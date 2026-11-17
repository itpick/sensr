//! Gateway monitoring and failover on the box (OPNsense dpinger +
//! `gateway_watcher.php`): every gateway of the applied document, plus the
//! dynamic gateways OPNsense creates by itself (`WAN_DHCP`, `WAN_DHCP6`), is
//! probed by `sensr-monitor`; status changes move
//!
//! - gateway-group policy tables to the lowest tier with a usable member
//!   (`ip route replace default … table <t>`), and
//! - with "default gateway switching" on, the main default route to the
//!   next candidate (an extra `metric 10` default route while failed over;
//!   networkd's own route stays and takes over again when it is removed).
//!
//! Never a ruleset reload: policy routing marks stay, only routes move.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sensr_apply::cmd::{Cmd, Runner};
use sensr_monitor::{
    DefaultCandidate, Family, GatewayConfig, GroupMember, IcmpFactory, Monitor, MonitorSettings,
    Status, Trigger, select_default_gateway, select_group,
};
use sensr_rules::routing::TargetKind;
use sensr_schema::Document;
use sensr_schema::fields::IpFamily;
use sensr_schema::models::gateways::{GroupTrigger, MonitorThresholds};
use sensr_schema::models::interfaces::{InterfaceRole, Ipv4Config, Ipv6Config};
use serde::Serialize;

/// Metric of the default route sensr adds while failed over (below
/// networkd's DHCP route metric 100, so it wins while present).
pub const SWITCHED_METRIC: u32 = 10;
/// How often dynamic next hops are re-read and routes reconciled.
const POLL: Duration = Duration::from_secs(5);

/// A gateway as the monitor and the router see it.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EffectiveGateway {
    /// name (`WAN_DHCP` for an automatic one)
    pub name: String,
    /// logical interface
    pub interface: String,
    /// kernel device
    pub device: String,
    /// `inet` or `inet6`
    pub family: &'static str,
    /// configured next hop; `None`: learned (DHCP, RA)
    pub address: Option<IpAddr>,
    /// probe this instead of the next hop
    pub monitor_address: Option<IpAddr>,
    /// probed at all
    pub monitor: bool,
    /// default-route candidate
    pub default_route: bool,
    /// lower wins
    pub priority: u8,
    /// group share
    pub weight: u8,
    /// forced down
    pub force_down: bool,
    /// created automatically for a DHCP/RA interface
    pub dynamic: bool,
    #[serde(skip)]
    thresholds: MonitorThresholds,
}

fn fam(f: &str) -> Family {
    if f == "inet6" {
        Family::Inet6
    } else {
        Family::Inet
    }
}

/// Configured gateways plus OPNsense's automatic ones for interfaces with a
/// learned upstream (DHCP WAN, DHCPv6/SLAAC WAN) that have none configured.
pub fn effective_gateways(doc: &Document) -> Vec<EffectiveGateway> {
    let mut out = Vec::new();
    for g in doc.gateways.gateways.values().filter(|g| g.enabled) {
        let Some(i) = doc.interfaces.get(&g.interface) else {
            continue;
        };
        out.push(EffectiveGateway {
            name: g.name.to_string(),
            interface: g.interface.to_string(),
            device: i.device.to_string(),
            family: if g.family == IpFamily::Inet6 {
                "inet6"
            } else {
                "inet"
            },
            address: g.address,
            monitor_address: g.monitor_address,
            monitor: g.monitor,
            default_route: g.default_route,
            priority: g.priority,
            weight: g.weight,
            force_down: g.force_down,
            dynamic: false,
            thresholds: g.thresholds,
        });
    }
    let has = |out: &[EffectiveGateway], iface: &str, f: &str| {
        out.iter().any(|g| g.interface == iface && g.family == f)
    };
    let mut auto = Vec::new();
    for (id, i) in doc.interfaces.iter().filter(|(_, i)| i.enabled) {
        let up4 = matches!(
            i.ipv4,
            Ipv4Config::Dhcp {
                use_gateway: true,
                ..
            }
        );
        let up6 = matches!(i.ipv6, Ipv6Config::Dhcp6 { .. } | Ipv6Config::Slaac);
        for (learned, f, suffix) in [(up4, "inet", "DHCP"), (up6, "inet6", "DHCP6")] {
            if !learned || has(&out, id.as_str(), f) {
                continue;
            }
            auto.push(EffectiveGateway {
                name: format!("{}_{suffix}", id.as_str().to_ascii_uppercase()),
                interface: id.to_string(),
                device: i.device.to_string(),
                family: f,
                address: None,
                monitor_address: None,
                // upstream monitors its automatic gateways
                monitor: true,
                default_route: i.role == InterfaceRole::Wan && id.as_str() == "wan",
                priority: 254,
                weight: 1,
                force_down: false,
                dynamic: true,
                thresholds: MonitorThresholds::default(),
            });
        }
    }
    out.extend(auto);
    out
}

fn settings(t: &MonitorThresholds) -> MonitorSettings {
    let d = MonitorSettings::default();
    let ms =
        |v: Option<u32>, dflt: Duration| v.map_or(dflt, |x| Duration::from_millis(u64::from(x)));
    let s = |v: Option<u32>, dflt: Duration| v.map_or(dflt, |x| Duration::from_secs(u64::from(x)));
    MonitorSettings {
        latency_low: ms(t.latency_low, d.latency_low),
        latency_high: ms(t.latency_high, d.latency_high),
        loss_low: t.loss_low.map_or(d.loss_low, |x| x.min(100) as u8),
        loss_high: t.loss_high.map_or(d.loss_high, |x| x.min(100) as u8),
        interval: s(t.interval, d.interval),
        loss_interval: s(t.loss_interval, d.loss_interval),
        time_period: s(t.time_period, d.time_period),
        data_length: t.data_length.map_or(d.data_length, |x| x as usize),
        ..d
    }
}

/// `ip -j route show default` (or `-6`) → device → next hop.
pub fn parse_default_routes(json: &[u8]) -> BTreeMap<String, IpAddr> {
    #[derive(serde::Deserialize)]
    struct R {
        dst: Option<String>,
        gateway: Option<IpAddr>,
        dev: Option<String>,
        metric: Option<u32>,
    }
    let routes: Vec<R> = serde_json::from_slice(json).unwrap_or_default();
    let mut out = BTreeMap::new();
    for r in routes {
        // our own failover route is not a learned next hop
        if r.metric == Some(SWITCHED_METRIC) || r.dst.as_deref() != Some("default") {
            continue;
        }
        if let (Some(g), Some(d)) = (r.gateway, r.dev) {
            out.entry(d).or_insert(g);
        }
    }
    out
}

fn trigger(t: GroupTrigger) -> Trigger {
    match t {
        GroupTrigger::Down => Trigger::Down,
        GroupTrigger::DownLoss => Trigger::DownLoss,
        GroupTrigger::DownLatency => Trigger::DownLatency,
        GroupTrigger::DownLossLatency => Trigger::DownLossLatency,
    }
}

/// What the routes should be, given statuses and next hops.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RouteState {
    /// policy table → (gateway, device, next hop)
    pub tables: BTreeMap<u32, (String, String, IpAddr)>,
    /// per family: the failover default route while the configured default
    /// is not the chosen one
    pub switched: BTreeMap<&'static str, (String, String, IpAddr)>,
    /// group → active gateways
    pub groups: BTreeMap<String, Vec<String>>,
    /// per family: the chosen default gateway
    pub default: BTreeMap<&'static str, String>,
}

/// Decides routes from the document, statuses and next hops (pure).
pub fn plan_routes(
    doc: &Document,
    gws: &[EffectiveGateway],
    status: &BTreeMap<String, Status>,
    hops: &BTreeMap<String, IpAddr>,
) -> RouteState {
    let mut st = RouteState::default();
    let hop = |g: &EffectiveGateway| g.address.or_else(|| hops.get(&g.name).copied());
    let status_of = |n: &str| status.get(n).copied().unwrap_or(Status::Pending);
    let by_name: BTreeMap<&str, &EffectiveGateway> =
        gws.iter().map(|g| (g.name.as_str(), g)).collect();

    let routing = sensr_rules::document::compile(doc, &Default::default()).routing;
    for (name, t) in &routing.targets {
        let TargetKind::Group { members } = &t.kind else {
            continue;
        };
        let trig = doc
            .gateways
            .groups
            .values()
            .find(|g| g.name.as_str() == name)
            .map_or(Trigger::Down, |g| trigger(g.trigger));
        let ms: Vec<GroupMember<'_>> = members
            .iter()
            .filter_map(|(tier, m)| {
                let g = by_name.get(m.as_str())?;
                Some(GroupMember {
                    gateway: m.as_str(),
                    tier: *tier,
                    weight: g.weight,
                    status: if g.force_down {
                        Status::ForceDown
                    } else if g.monitor {
                        status_of(m)
                    } else {
                        Status::Online
                    },
                })
            })
            .collect();
        let sel = select_group(trig, &ms);
        st.groups.insert(
            name.clone(),
            sel.members.iter().map(|m| m.gateway.clone()).collect(),
        );
        if let Some(g) = sel
            .members
            .first()
            .and_then(|m| by_name.get(m.gateway.as_str()))
            && let Some(h) = hop(g)
        {
            st.tables
                .insert(t.table, (g.name.clone(), g.device.clone(), h));
        }
    }

    for f in ["inet", "inet6"] {
        let cands: Vec<DefaultCandidate<'_>> = gws
            .iter()
            .filter(|g| g.family == f)
            .map(|g| DefaultCandidate {
                name: g.name.as_str(),
                family: fam(f),
                enabled: true,
                default_route: g.default_route,
                priority: g.priority,
                has_address: hop(g).is_some(),
                force_down: g.force_down,
                status: if g.monitor {
                    status_of(&g.name)
                } else {
                    Status::Online
                },
            })
            .collect();
        let configured = select_default_gateway(&cands, fam(f), false);
        let chosen = select_default_gateway(&cands, fam(f), doc.gateways.switch_default);
        if let Some(c) = chosen {
            st.default.insert(f, c.to_owned());
        }
        if let (Some(c), true) = (chosen, chosen != configured)
            && let Some(g) = by_name.get(c)
            && let Some(h) = hop(g)
        {
            st.switched.insert(f, (g.name.clone(), g.device.clone(), h));
        }
    }
    st
}

/// Commands that move the routes from `old` to `new`.
pub fn route_commands(old: &RouteState, new: &RouteState) -> Vec<Cmd> {
    let mut v = Vec::new();
    let fam_flag = |h: &IpAddr| if h.is_ipv6() { "-6" } else { "-4" };
    for (table, (_, dev, hop)) in &new.tables {
        if old.tables.get(table).map(|(_, d, h)| (d, h)) != Some((dev, hop)) {
            v.push(Cmd::new("ip").args([
                fam_flag(hop).to_owned(),
                "route".into(),
                "replace".into(),
                "default".into(),
                "via".into(),
                hop.to_string(),
                "dev".into(),
                dev.clone(),
                "table".into(),
                table.to_string(),
            ]));
        }
    }
    for f in ["inet", "inet6"] {
        let flag = if f == "inet6" { "-6" } else { "-4" };
        match (old.switched.get(f), new.switched.get(f)) {
            (o, Some((_, dev, hop))) if o.map(|(_, d, h)| (d, h)) != Some((dev, hop)) => {
                v.push(Cmd::new("ip").args([
                    flag.to_owned(),
                    "route".into(),
                    "replace".into(),
                    "default".into(),
                    "via".into(),
                    hop.to_string(),
                    "dev".into(),
                    dev.clone(),
                    "metric".into(),
                    SWITCHED_METRIC.to_string(),
                ]));
            }
            (Some(_), None) => v.push(Cmd::new("ip").args([
                flag.to_owned(),
                "route".into(),
                "del".into(),
                "default".into(),
                "metric".into(),
                SWITCHED_METRIC.to_string(),
            ])),
            _ => {}
        }
    }
    v
}

/// Status of one gateway for the API and UI (System › Gateways).
#[derive(Clone, Debug, Serialize)]
pub struct GatewayStatus {
    /// configuration side
    #[serde(flatten)]
    pub gateway: EffectiveGateway,
    /// next hop in use
    pub next_hop: Option<IpAddr>,
    /// `online`, `delay`, `loss`, `delay_loss`, `down`, `force_down`, `pending`
    pub status: Status,
    /// OPNsense's word for it (`none`, `delay`, …)
    pub status_text: &'static str,
    /// average round trip
    pub latency_ms: Option<f64>,
    /// round-trip deviation
    pub stddev_ms: Option<f64>,
    /// loss over the time period
    pub loss_pct: Option<f64>,
    /// probe error, if the socket could not be used
    pub error: Option<String>,
    /// this gateway carries the default route of its family
    pub active_default: bool,
}

/// Everything the gateways page and widget show.
#[derive(Clone, Debug, Serialize)]
pub struct GatewaysView {
    /// gateways
    pub gateways: Vec<GatewayStatus>,
    /// active members per group
    pub groups: BTreeMap<String, Vec<String>>,
    /// default gateway switching on
    pub switch_default: bool,
}

struct Shared {
    doc: Option<Document>,
    gws: Vec<EffectiveGateway>,
    hops: BTreeMap<String, IpAddr>,
    routes: RouteState,
}

/// The running monitor plus route reconciliation.
pub struct GatewayService {
    monitor: Monitor<IcmpFactory>,
    runner: Arc<dyn Runner>,
    handle: tokio::runtime::Handle,
    shared: Mutex<Shared>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl GatewayService {
    /// Starts on the current tokio runtime; reconciles every 5 s.
    pub fn start(runner: Arc<dyn Runner>) -> Option<Arc<GatewayService>> {
        let handle = tokio::runtime::Handle::try_current().ok()?;
        let svc = Arc::new(GatewayService {
            monitor: {
                let _g = handle.enter();
                Monitor::icmp()
            },
            runner,
            handle,
            shared: Mutex::new(Shared {
                doc: None,
                gws: Vec::new(),
                hops: BTreeMap::new(),
                routes: RouteState::default(),
            }),
        });
        let s = Arc::clone(&svc);
        let spawned = std::thread::Builder::new()
            .name("sensr-gateways".into())
            .spawn(move || {
                loop {
                    s.tick();
                    std::thread::sleep(POLL);
                }
            });
        if let Err(e) = spawned {
            tracing::error!(error = %e, "gateway monitor not started");
        }
        Some(svc)
    }

    /// After an apply: the gateways of `doc` replace the monitored set.
    pub fn applied(&self, doc: &Document) {
        let gws = effective_gateways(doc);
        let _g = self.handle.enter();
        let mut sh = lock(&self.shared);
        for old in &sh.gws {
            if !gws.iter().any(|g| g.name == old.name) {
                let _ = self.monitor.remove(&old.name);
            }
        }
        for g in &gws {
            let target = g
                .monitor_address
                .or(g.address)
                .or_else(|| sh.hops.get(&g.name).copied());
            let cfg = GatewayConfig {
                name: g.name.clone(),
                family: fam(g.family),
                device: Some(g.device.clone()),
                source: None,
                target,
                monitor: g.monitor,
                force_down: g.force_down,
                settings: settings(&g.thresholds),
            };
            if let Err(e) = self.monitor.upsert(cfg) {
                tracing::warn!(gateway = %g.name, error = %e, "gateway not monitored");
            }
        }
        sh.gws = gws;
        sh.doc = Some(doc.clone());
        // networkd re-installs the tier-1 tables on apply
        sh.routes.tables.clear();
    }

    fn read_hops(&self) -> BTreeMap<String, IpAddr> {
        let mut by_dev = BTreeMap::new();
        for flag in ["-4", "-6"] {
            if let Ok(o) = self.runner.run(
                &Cmd::new("ip").args(["-j", flag, "route", "show", "default"]),
                None,
            ) && o.success()
            {
                for (d, h) in parse_default_routes(&o.stdout) {
                    by_dev.entry((d, h.is_ipv6())).or_insert(h);
                }
            }
        }
        let sh = lock(&self.shared);
        sh.gws
            .iter()
            .filter(|g| g.address.is_none())
            .filter_map(|g| {
                let h = by_dev.get(&(g.device.clone(), g.family == "inet6"))?;
                Some((g.name.clone(), *h))
            })
            .collect()
    }

    /// Re-read dynamic next hops, retarget probes, reconcile routes.
    pub fn tick(&self) {
        if lock(&self.shared).doc.is_none() {
            return;
        }
        let hops = self.read_hops();
        let _g = self.handle.enter();
        let mut sh = lock(&self.shared);
        for g in sh
            .gws
            .iter()
            .filter(|g| g.address.is_none() && g.monitor_address.is_none())
        {
            if sh.hops.get(&g.name) != hops.get(&g.name) {
                let _ = self.monitor.set_target(&g.name, hops.get(&g.name).copied());
            }
        }
        sh.hops = hops;
        let snap = self.monitor.snapshot();
        let status: BTreeMap<String, Status> = snap
            .gateways
            .iter()
            .map(|(k, v)| (k.clone(), v.status))
            .collect();
        let Some(doc) = sh.doc.as_ref() else { return };
        let new = plan_routes(doc, &sh.gws, &status, &sh.hops);
        for c in route_commands(&sh.routes, &new) {
            match self.runner.run(&c, None) {
                Ok(o) if o.success() => tracing::info!(cmd = %c.display(), "gateway route changed"),
                Ok(o) => {
                    tracing::warn!(cmd = %c.display(), error = %o.stderr_text(), "gateway route change failed")
                }
                Err(e) => {
                    tracing::warn!(cmd = %c.display(), error = %e, "gateway route change failed")
                }
            }
        }
        if new.default != sh.routes.default {
            tracing::warn!(from = ?sh.routes.default, to = ?new.default, "default gateway changed");
        }
        sh.routes = new;
    }

    /// The gateways page / widget data.
    pub fn view(&self) -> GatewaysView {
        let snap = self.monitor.snapshot();
        let sh = lock(&self.shared);
        let gateways = sh
            .gws
            .iter()
            .map(|g| {
                let s = snap.get(&g.name);
                let status = s.map_or(Status::Pending, |s| s.status);
                GatewayStatus {
                    next_hop: g.address.or_else(|| sh.hops.get(&g.name).copied()),
                    status,
                    status_text: status.opnsense_str(),
                    latency_ms: s.and_then(|s| s.latency_ms),
                    stddev_ms: s.and_then(|s| s.stddev_ms),
                    loss_pct: s.and_then(|s| s.loss_pct),
                    error: s.and_then(|s| s.error.clone()),
                    active_default: sh.routes.default.get(g.family) == Some(&g.name),
                    gateway: g.clone(),
                }
            })
            .collect();
        GatewaysView {
            gateways,
            groups: sh.routes.groups.clone(),
            switch_default: sh.doc.as_ref().is_some_and(|d| d.gateways.switch_default),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn multiwan() -> Document {
        serde_json::from_str(include_str!(
            "../../sensr-import-opnsense/tests/golden/multiwan.sensr.json"
        ))
        .unwrap()
    }

    fn home_router() -> Document {
        serde_json::from_str(include_str!(
            "../../sensr-import-opnsense/tests/golden/home-router.sensr.json"
        ))
        .unwrap()
    }

    #[test]
    fn automatic_dhcp_gateways_like_opnsense() {
        let gws = effective_gateways(&home_router());
        let wan6 = gws
            .iter()
            .find(|g| g.name == "WAN_DHCP6")
            .expect("WAN_DHCP6");
        assert!(wan6.dynamic && wan6.monitor && wan6.default_route);
        // the configured v4 gateway on wan replaces WAN_DHCP
        assert_eq!(
            gws.iter()
                .filter(|g| g.interface == "wan" && g.family == "inet")
                .count(),
            1
        );
    }

    #[test]
    fn default_routes_parse_and_skip_our_failover_route() {
        let j = br#"[{"dst":"default","gateway":"192.0.2.1","dev":"igc0","protocol":"dhcp","metric":100},
                    {"dst":"default","gateway":"198.51.100.1","dev":"igc2","metric":10}]"#;
        let m = parse_default_routes(j);
        assert_eq!(m.len(), 1);
        assert_eq!(m["igc0"].to_string(), "192.0.2.1");
    }

    fn statuses(v: &[(&str, Status)]) -> BTreeMap<String, Status> {
        v.iter().map(|(k, s)| ((*k).to_owned(), *s)).collect()
    }

    #[test]
    fn group_fails_over_to_tier_two_and_back() {
        let doc = multiwan();
        let gws = effective_gateways(&doc);
        let names: Vec<&str> = gws.iter().map(|g| g.name.as_str()).collect();
        let routing = sensr_rules::document::compile(&doc, &Default::default()).routing;
        let (gname, t) = routing
            .targets
            .iter()
            .find(|(_, t)| matches!(t.kind, TargetKind::Group { .. }))
            .expect("a group");
        let TargetKind::Group { members } = &t.kind else {
            unreachable!()
        };
        let tier1 = members.iter().min_by_key(|(t, _)| *t).unwrap().1.clone();
        let tier2 = members.iter().max_by_key(|(t, _)| *t).unwrap().1.clone();
        assert_ne!(tier1, tier2, "{members:?}");
        let mut hops = BTreeMap::new();
        for g in &gws {
            hops.insert(g.name.clone(), "192.0.2.254".parse().unwrap());
        }
        let all_up: Vec<(&str, Status)> = names.iter().map(|n| (*n, Status::Online)).collect();
        let up = plan_routes(&doc, &gws, &statuses(&all_up), &hops);
        assert_eq!(up.groups[gname], vec![tier1.clone()]);
        let mut down = all_up.clone();
        for d in down.iter_mut().filter(|(n, _)| *n == tier1) {
            d.1 = Status::Down;
        }
        let failed = plan_routes(&doc, &gws, &statuses(&down), &hops);
        assert_eq!(failed.groups[gname], vec![tier2.clone()]);
        let cmds: Vec<String> = route_commands(&up, &failed)
            .iter()
            .map(|c| c.display())
            .collect();
        assert!(
            cmds.iter()
                .any(|c| c.contains(&format!("'table' '{}'", t.table))),
            "{cmds:?}"
        );
        // and back: tier 1 again
        let back = plan_routes(&doc, &gws, &statuses(&all_up), &hops);
        assert_eq!(back.groups[gname], vec![tier1]);
        assert!(!route_commands(&failed, &back).is_empty());
        // unchanged: no commands
        assert!(route_commands(&back, &back).is_empty());
    }

    #[test]
    fn default_switching_adds_and_removes_the_failover_route() {
        let mut doc = multiwan();
        doc.gateways.switch_default = true;
        let gws = effective_gateways(&doc);
        let v4: Vec<&EffectiveGateway> = gws.iter().filter(|g| g.family == "inet").collect();
        assert!(v4.len() >= 2, "{gws:?}");
        let hops: BTreeMap<String, IpAddr> = gws
            .iter()
            .map(|g| (g.name.clone(), "192.0.2.254".parse().unwrap()))
            .collect();
        let up_all: Vec<(&str, Status)> = gws
            .iter()
            .map(|g| (g.name.as_str(), Status::Online))
            .collect();
        let up = plan_routes(&doc, &gws, &statuses(&up_all), &hops);
        assert!(up.switched.is_empty());
        let first = up.default["inet"].clone();
        let mut down = up_all.clone();
        for d in down.iter_mut().filter(|(n, _)| *n == first) {
            d.1 = Status::Down;
        }
        let failed = plan_routes(&doc, &gws, &statuses(&down), &hops);
        assert_ne!(failed.default["inet"], first);
        let add: Vec<String> = route_commands(&up, &failed)
            .iter()
            .map(|c| c.display())
            .collect();
        assert!(
            add.iter()
                .any(|c| c.contains("'metric' '10'") && c.contains("replace")),
            "{add:?}"
        );
        let del: Vec<String> = route_commands(&failed, &up)
            .iter()
            .map(|c| c.display())
            .collect();
        assert!(del.iter().any(|c| c.contains("'del'")), "{del:?}");
        // switching off: the configured default stays although it is down
        doc.gateways.switch_default = false;
        let stay = plan_routes(&doc, &gws, &statuses(&down), &hops);
        assert_eq!(stay.default["inet"], first);
        assert!(stay.switched.is_empty());
    }
}
