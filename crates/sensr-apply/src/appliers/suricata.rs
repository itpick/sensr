//! Suricata: `suricata.yaml` and its companions rendered from the typed
//! `ids` section, plus the nftables queue table for prevent mode.
//!
//! Files (all in `/run/sensr/suricata`):
//!
//! | file | read by | change means |
//! |---|---|---|
//! | `suricata.yaml` | `sensr-suricata.service` | restart (capture setup) |
//! | `suricata.args` | the unit's start script | restart (`--af-packet` or `-q N…`) |
//! | `vars.yaml` | included by `suricata.yaml` | rule reload: HOME_NET follows addresses |
//! | `threshold.config`, `local.rules` | Suricata | rule reload |
//! | `update.args`, `{enable,disable,drop,modify}.conf` | `sensr-suricata-update.service` | a path unit runs the update, which reloads Suricata |
//! | `ips.nft.json` | the engine (`nft -j -f`) | the `inet sensr_ips` table is replaced |
//!
//! Upstream counterparts: `service/templates/OPNsense/IDS/{suricata.yaml,
//! OPNsense.rules, rule-policies.config}` and `scripts/suricata/
//! {rule-updater.py,installRules.py}`; rule fetching and policy application
//! is `suricata-update`'s job here.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;
use sensr_rules::ir::IfAddr;
use sensr_schema::Document;
use sensr_schema::fields::DeviceName;
use sensr_schema::models::ids::{
    DetectProfile, IdsMode, PatternMatcher, PolicyAction, RuleAction, RuleSource, TrackBy,
    UserRuleAction,
};
use sensr_schema::models::interfaces::{InterfaceRole, Ipv4Config, Ipv6Config};
use serde::Serialize;

use crate::templates::{Module, Rendered, TemplateError, Templates};

/// Live directory of the rendered files.
pub const DIR: &str = "run/sensr/suricata";
/// The engine.
pub const UNIT: &str = "sensr-suricata.service";
/// Rule downloads (started by a path unit when `update.args` changes, and
/// daily by a timer).
pub const UPDATE_UNIT: &str = "sensr-suricata-update.service";
/// Reloads the engine's rules (a oneshot: `systemctl reload` of [`UNIT`]
/// when it runs), for files Suricata re-reads on a rule reload.
pub const RELOAD_UNIT: &str = "sensr-suricata-reload.service";
/// Starts [`UPDATE_UNIT`] without waiting for the download (a oneshot
/// running `systemctl start --no-block`).
pub const TRIGGER_UNIT: &str = "sensr-suricata-update-trigger.service";
/// The daily update timer.
pub const TIMER_UNIT: &str = "sensr-suricata-update.timer";
/// The timer's schedule, as a runtime drop-in.
pub const TIMER_DROPIN: &str = "/run/systemd/system/sensr-suricata-update.timer.d/50-sensr.conf";
/// Units the engine stops when IDS is switched off.
pub const OWNED_UNITS: &[&str] = &[UNIT, TIMER_UNIT];
/// The nftables table of prevent mode.
pub const IPS_TABLE: &str = "sensr_ips";
/// The queue table, as a plan file (the engine loads it with `nft -j -f`).
pub const IPS_NFT: &str = "ips.nft.json";
/// Packet/conntrack mark bit for flows Suricata has stopped inspecting
/// (outside `sensr-rules`' policy-routing bits, see `sensr_rules::routing`).
pub const BYPASS_MARK: u32 = 0x0100_0000;
/// Where suricata-update writes rules (one file per source file).
pub const RULE_DIR: &str = "/var/lib/suricata/rules";
/// Suricata's state (rule-group cache).
pub const STATE_DIR: &str = "/var/lib/suricata";
/// eve.json and stats.
pub const LOG_DIR: &str = "/var/log/suricata";
/// suricatasc socket.
pub const SOCKET: &str = "/run/suricata/suricata-command.socket";
/// nft base-chain priority of the queue: after the filter table (0), so
/// only traffic the firewall passes is inspected.
pub const QUEUE_PRIORITY: i32 = 10;

/// One capture interface (detect mode).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capture {
    /// Kernel device.
    pub device: DeviceName,
    /// af-packet worker threads.
    pub threads: u8,
    /// af-packet fanout group.
    pub cluster_id: u16,
}

/// suricata-update modification lists.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Confs {
    /// `enable.conf` lines.
    pub enable: Vec<String>,
    /// `disable.conf` lines.
    pub disable: Vec<String>,
    /// `drop.conf` lines.
    pub drop: Vec<String>,
    /// `modify.conf` lines.
    pub modify: Vec<String>,
}

/// A suppression line's parts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuppressLine {
    /// Generator id.
    pub gid: u32,
    /// Signature id.
    pub sid: u32,
    /// `by_src` / `by_dst` / `by_either`.
    pub track: Option<&'static str>,
    /// The address or network.
    pub ip: Option<String>,
    /// Comment.
    pub description: Option<String>,
}

/// The resolved IDS input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuricataModel {
    /// Detect or prevent.
    pub mode: IdsMode,
    /// Capture interfaces (detect mode; in prevent mode the queue's
    /// interfaces).
    pub capture: Vec<Capture>,
    /// Promiscuous capture.
    pub promiscuous: bool,
    /// `$HOME_NET`.
    pub home_net: Vec<IpNet>,
    /// Rules files to load (`None`: all).
    pub rule_files: Option<Vec<String>>,
    /// Rule sources.
    pub sources: Vec<RuleSource>,
    /// Active suppressions.
    pub suppressions: Vec<SuppressLine>,
    /// Include the default suppression list.
    pub default_suppressions: bool,
    /// User rules, rendered.
    pub local_rules: Vec<String>,
    /// suricata-update lists.
    pub conf: Confs,
    /// Queues (prevent mode): first and count.
    pub queues: (u16, u16),
    /// Fail open.
    pub fail_open: bool,
    /// Midstream pickup.
    pub midstream: bool,
    /// af-packet ring size.
    pub ring_size: u32,
    /// Worker CPU set (`"1-3"`), when pinned.
    pub worker_cpus: Option<String>,
    /// Detection profile.
    pub detect_profile: DetectProfile,
    /// Pattern matcher.
    pub mpm: Option<PatternMatcher>,
    /// Default packet size.
    pub default_packet_size: Option<u16>,
    /// Log payloads.
    pub payload: bool,
    /// Log HTTP.
    pub http: bool,
    /// Log TLS.
    pub tls: bool,
    /// Alerts to syslog.
    pub syslog: bool,
}

/// Model errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SuricataError {
    /// An IDS interface id with no assignment.
    #[error("ids.interfaces: unknown interface {0}")]
    UnknownInterface(String),
}

/// HOME_NET: the configured networks plus, with `home_net_auto`, every
/// interface's network and every WAN address (as a host route: a WAN's ISP
/// subnet holds other customers). `addrs` are the live addresses
/// (`Engine::current_addrs`), so a DHCP WAN's lease is included and
/// followed.
pub fn home_net(doc: &Document, addrs: &BTreeMap<String, Vec<IfAddr>>) -> Vec<IpNet> {
    let ids = &doc.ids;
    let mut nets: Vec<IpNet> = ids.home_net.clone();
    if ids.home_net_auto {
        for (id, i) in doc.interfaces.iter().filter(|(_, i)| i.enabled) {
            let wan = i.role == InterfaceRole::Wan;
            let mut own: Vec<IfAddr> = Vec::new();
            if let Ipv4Config::Static { address, .. } = &i.ipv4 {
                own.push(IfAddr {
                    addr: IpAddr::V4(address.addr()),
                    prefix_len: address.prefix_len(),
                });
            }
            if let Ipv6Config::Static { address, .. } = &i.ipv6 {
                own.push(IfAddr {
                    addr: IpAddr::V6(address.addr()),
                    prefix_len: address.prefix_len(),
                });
            }
            own.extend(addrs.get(id.as_str()).into_iter().flatten().cloned());
            for a in own {
                let net = if wan {
                    Some(IpNet::from(a.addr))
                } else {
                    a.network()
                };
                nets.extend(net);
            }
        }
    }
    IpNet::aggregate(&nets)
}

fn quote_msg(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '"' | ';') {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

fn cpu_count(cpus: usize) -> u16 {
    u16::try_from(cpus.max(1)).unwrap_or(u16::MAX)
}

impl SuricataModel {
    /// The model for `doc` (`None` when IDS is off). `cpus` is the number of
    /// CPUs the box has: workers default to all but CPU 0, where a Pi 5
    /// handles every NIC interrupt.
    pub fn from_document(
        doc: &Document,
        addrs: &BTreeMap<String, Vec<IfAddr>>,
        cpus: usize,
    ) -> Result<Option<SuricataModel>, SuricataError> {
        let ids = &doc.ids;
        if !ids.enabled {
            return Ok(None);
        }
        let devices = ids
            .interfaces
            .iter()
            .map(|i| {
                doc.interfaces
                    .get(i)
                    .map(|x| x.device.clone())
                    .ok_or_else(|| SuricataError::UnknownInterface(i.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let cpus = cpu_count(cpus);
        let spare = cpus.saturating_sub(1).max(1);
        let total = ids.tuning.workers.map(u16::from).unwrap_or(spare).max(1);
        let n = u16::try_from(devices.len().max(1)).unwrap_or(1);
        let per = u8::try_from((total / n).max(1)).unwrap_or(u8::MAX);
        let capture = devices
            .into_iter()
            .enumerate()
            .map(|(k, device)| Capture {
                device,
                threads: per,
                cluster_id: 99 - u16::try_from(k).unwrap_or(0),
            })
            .collect();
        let worker_cpus = (ids.tuning.pin_workers && cpus >= 3).then(|| format!("1-{}", cpus - 1));

        let suppressions = ids
            .active_suppressions()
            .into_iter()
            .map(|s| {
                let (track, ip) = match &s.track {
                    Some(t) => (
                        Some(match t.by {
                            TrackBy::Src => "by_src",
                            TrackBy::Dst => "by_dst",
                            TrackBy::Either => "by_either",
                        }),
                        Some(t.net.to_string()),
                    ),
                    None => (None, None),
                };
                SuppressLine {
                    gid: s.gid,
                    sid: s.sid,
                    track,
                    ip,
                    description: s.description.map(|d| d.to_string()),
                }
            })
            .collect();

        let local_rules = ids
            .user_rules
            .values()
            .filter(|r| r.enabled)
            .enumerate()
            .map(|(k, r)| {
                let action = match r.action {
                    UserRuleAction::Alert => "alert",
                    UserRuleAction::Drop => "drop",
                    UserRuleAction::Pass => "pass",
                };
                let proto = if r.fingerprint.is_some() { "tls" } else { "ip" };
                let net = |n: &Option<IpNet>| n.map_or("any".to_owned(), |n| n.to_string());
                let mut opts = format!("msg:\"{}\";", quote_msg(r.description.as_str()));
                if r.bypass {
                    opts.push_str(" bypass;");
                }
                if let Some(f) = &r.fingerprint {
                    opts.push_str(&format!(
                        " tls.cert_fingerprint; content:\"{}\";",
                        f.to_ascii_lowercase()
                    ));
                }
                // upstream numbers user rules down from the top of the sid space
                let sid = u32::MAX - u32::try_from(k + 1).unwrap_or(0);
                format!(
                    "{action} {proto} {} any -> {} any ({opts} sid:{sid}; rev:1;)",
                    net(&r.source),
                    net(&r.destination)
                )
            })
            .collect();

        Ok(Some(SuricataModel {
            mode: ids.mode,
            capture,
            promiscuous: ids.promiscuous,
            home_net: home_net(doc, addrs),
            rule_files: ids
                .loaded_files()
                .map(|v| v.iter().map(|f| f.to_string()).collect()),
            sources: ids.sources.clone(),
            suppressions,
            default_suppressions: ids.default_suppressions,
            local_rules,
            conf: confs(doc),
            queues: (ids.ips.queue, total),
            fail_open: ids.ips.fail_open,
            midstream: ids.ips.midstream,
            ring_size: ids.tuning.ring_size.unwrap_or(16_384),
            worker_cpus,
            detect_profile: ids.tuning.detect_profile,
            mpm: ids.tuning.pattern_matcher,
            default_packet_size: ids.tuning.default_packet_size,
            payload: ids.logging.payload,
            http: ids.logging.http,
            tls: ids.logging.tls,
            syslog: ids.logging.syslog,
        }))
    }

    fn view(&self) -> View<'_> {
        let prevent = self.mode == IdsMode::Prevent;
        let mut args = vec![
            "-c".to_owned(),
            format!("/{DIR}/suricata.yaml"),
            "--pidfile".to_owned(),
            "/run/suricata/suricata.pid".to_owned(),
            // Suricata 8 ignores default-log-dir from the yaml when the
            // process runs from another working directory; -l is the only
            // thing that redirects eve.json (to the unit's LogsDirectory).
            "-l".to_owned(),
            LOG_DIR.to_owned(),
        ];
        if prevent {
            for q in self.queues.0..self.queues.0.saturating_add(self.queues.1) {
                args.push("-q".to_owned());
                args.push(q.to_string());
            }
        } else {
            args.push("--af-packet".to_owned());
        }
        let mut update_args = vec![
            "--suricata-conf".to_owned(),
            format!("/{DIR}/suricata.yaml"),
            "--data-dir".to_owned(),
            STATE_DIR.to_owned(),
            "--output".to_owned(),
            RULE_DIR.to_owned(),
            // one file per ruleset, so `rule-files` selects them as upstream does
            "--no-merge".to_owned(),
            "--no-reload".to_owned(),
            "--no-test".to_owned(),
            // Without this a failed download exits 0 and keeps the store's
            // distribution rules, so a fetch that raced the WAN at boot
            // would go unnoticed until the next day. The unit's
            // Restart=on-failure retries instead.
            "--fail".to_owned(),
            "--enable-conf".to_owned(),
            format!("/{DIR}/enable.conf"),
            "--disable-conf".to_owned(),
            format!("/{DIR}/disable.conf"),
            "--drop-conf".to_owned(),
            format!("/{DIR}/drop.conf"),
            "--modify-conf".to_owned(),
            format!("/{DIR}/modify.conf"),
        ];
        for s in &self.sources {
            match s {
                RuleSource::EtOpen => update_args.push("--etopen".to_owned()),
                RuleSource::Url { url } => {
                    update_args.push("--url".to_owned());
                    update_args.push(url.as_str().to_owned());
                }
            }
        }
        View {
            mode: if prevent { "prevent" } else { "detect" },
            prevent,
            dir: format!("/{DIR}"),
            log_dir: LOG_DIR,
            rule_dir: RULE_DIR,
            state_dir: STATE_DIR,
            socket: SOCKET,
            home_net: format!(
                "[{}]",
                self.home_net
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            rule_files: self
                .rule_files
                .clone()
                .unwrap_or_else(|| vec!["*.rules".to_owned()]),
            capture: &self.capture,
            ring_size: self.ring_size,
            yes: Yes {
                payload: self.payload,
                promiscuous: self.promiscuous,
                fail_open: self.fail_open,
            },
            http: self.http,
            tls: self.tls,
            syslog: self.syslog,
            bypass_mark: format!("{BYPASS_MARK:#010x}"),
            exception_policy: if self.fail_open { "ignore" } else { "auto" },
            host_mode: if prevent { "router" } else { "sniffer-only" },
            default_packet_size: self.default_packet_size,
            midstream: self.midstream,
            detect_profile: match self.detect_profile {
                DetectProfile::Low => "low",
                DetectProfile::Medium => "medium",
                DetectProfile::High => "high",
            },
            mpm: match self.mpm {
                None => "auto",
                Some(PatternMatcher::Ac) => "ac",
                Some(PatternMatcher::AcKs) => "ac-ks",
                Some(PatternMatcher::Hs) => "hs",
            },
            worker_cpus: self.worker_cpus.as_deref(),
            suppressions: &self.suppressions,
            default_suppressions: self.default_suppressions,
            local_rules: &self.local_rules,
            conf: &self.conf,
            args,
            update_args,
        }
    }

    /// Render every file of the module.
    pub fn render(&self, templates: &Templates) -> Result<Vec<Rendered>, TemplateError> {
        templates.render("suricata", &Ctx { s: self.view() })
    }

    /// The template context (for the registry's fixture tests).
    pub fn context(&self) -> impl Serialize + '_ {
        Ctx { s: self.view() }
    }

    /// The prevent-mode queue table: forwarded packets in or out of the
    /// inspected interfaces go to Suricata, with `bypass` (fail-open) unless
    /// turned off. Connections Suricata marked as bypassed are no longer
    /// queued. Detect mode gets the table's removal.
    pub fn ips_ruleset(&self) -> String {
        if self.mode != IdsMode::Prevent {
            return ips_removal();
        }
        let t = IPS_TABLE;
        let devices: Vec<&str> = self.capture.iter().map(|c| c.device.as_str()).collect();
        let set = serde_json::json!({ "set": devices });
        let (first, count) = self.queues;
        let num = if count > 1 {
            serde_json::json!({ "range": [first, first + count - 1] })
        } else {
            serde_json::json!(first)
        };
        let mut flags = Vec::new();
        if self.fail_open {
            flags.push("bypass");
        }
        if count > 1 {
            flags.push("fanout");
        }
        let queue = serde_json::json!({ "queue": { "num": num, "flags": flags } });
        let bit = serde_json::json!({ "&": [{ "ct": { "key": "mark" } }, BYPASS_MARK] });
        let meta_bit = serde_json::json!({ "&": [{ "meta": { "key": "mark" } }, BYPASS_MARK] });
        let rule = |chain: &str, expr: serde_json::Value| {
            serde_json::json!({ "add": { "rule": {
                "family": "inet", "table": t, "chain": chain, "expr": expr } } })
        };
        let chain = |name: &str, prio: i32| {
            serde_json::json!({ "add": { "chain": {
                "family": "inet", "table": t, "name": name, "type": "filter",
                "hook": "forward", "prio": prio, "policy": "accept" } } })
        };
        let table = serde_json::json!({ "table": { "family": "inet", "name": t } });
        let doc = serde_json::json!({ "nftables": [
            { "add": table.clone() },
            { "delete": table.clone() },
            { "add": table },
            chain("queue", QUEUE_PRIORITY),
            rule("queue", serde_json::json!([
                { "match": { "op": "==", "left": bit, "right": BYPASS_MARK } },
                { "accept": null }
            ])),
            rule("queue", serde_json::json!([
                { "match": { "op": "==", "left": { "meta": { "key": "iifname" } }, "right": set.clone() } },
                queue.clone()
            ])),
            rule("queue", serde_json::json!([
                { "match": { "op": "==", "left": { "meta": { "key": "oifname" } }, "right": set } },
                queue
            ])),
            // the verdict's mark lives on the packet only: keep it on the
            // connection so its next packets skip the queue
            chain("bypass", QUEUE_PRIORITY + 1),
            rule("bypass", serde_json::json!([
                { "match": { "op": "==", "left": meta_bit, "right": BYPASS_MARK } },
                { "mangle": { "key": { "ct": { "key": "mark" } },
                  "value": { "|": [{ "ct": { "key": "mark" } }, BYPASS_MARK] } } }
            ])),
        ]});
        doc.to_string()
    }
}

/// Removes the queue table if present (add + delete never fails).
pub fn ips_removal() -> String {
    let table = serde_json::json!({ "table": { "family": "inet", "name": IPS_TABLE } });
    serde_json::json!({ "nftables": [ { "add": table.clone() }, { "delete": table } ] }).to_string()
}

/// Policies and overrides as suricata-update lists. Policies apply in
/// priority order; per-sid overrides come last and win.
fn confs(doc: &Document) -> Confs {
    let ids = &doc.ids;
    let mut c = Confs::default();
    let mut policies: Vec<_> = ids.policies.values().filter(|p| p.enabled).collect();
    policies.sort_by_key(|p| p.priority);
    for p in policies {
        // a policy names rulesets or metadata (validation rejects both);
        // neither means every rule
        let matchers: Vec<String> = if !p.rulesets.is_empty() {
            p.rulesets.iter().map(|f| format!("group:{f}")).collect()
        } else if !p.metadata.is_empty() {
            p.metadata
                .iter()
                .map(|m| format!("metadata: {} {}", m.key, m.value))
                .collect()
        } else {
            vec!["re:.".to_owned()]
        };
        match p.action {
            PolicyAction::Default => {}
            PolicyAction::Alert => c.modify.extend(
                matchers
                    .iter()
                    .map(|m| format!("{m} \"^drop \" \"alert \"")),
            ),
            PolicyAction::Drop => c.drop.extend(matchers),
            PolicyAction::Disable => c.disable.extend(matchers),
        }
    }
    for o in &ids.rule_overrides {
        if o.enabled {
            c.enable.push(o.sid.to_string());
        } else {
            c.disable.push(o.sid.to_string());
        }
        match o.action {
            RuleAction::Drop => c.drop.push(o.sid.to_string()),
            RuleAction::Alert => c.modify.push(format!("{} \"^drop \" \"alert \"", o.sid)),
        }
    }
    c
}

#[derive(Serialize)]
struct Yes {
    payload: bool,
    promiscuous: bool,
    fail_open: bool,
}

#[derive(Serialize)]
struct View<'a> {
    mode: &'static str,
    prevent: bool,
    dir: String,
    log_dir: &'static str,
    rule_dir: &'static str,
    state_dir: &'static str,
    socket: &'static str,
    home_net: String,
    rule_files: Vec<String>,
    capture: &'a [Capture],
    ring_size: u32,
    yes: Yes,
    http: bool,
    tls: bool,
    syslog: bool,
    bypass_mark: String,
    exception_policy: &'static str,
    host_mode: &'static str,
    default_packet_size: Option<u16>,
    midstream: bool,
    detect_profile: &'static str,
    mpm: &'static str,
    worker_cpus: Option<&'a str>,
    suppressions: &'a [SuppressLine],
    default_suppressions: bool,
    local_rules: &'a [String],
    conf: &'a Confs,
    args: Vec<String>,
    update_args: Vec<String>,
}

#[derive(Serialize)]
struct Ctx<'a> {
    s: View<'a>,
}

/// The `suricata` template module.
pub const MODULE: Module = Module {
    name: "suricata",
    dir: DIR,
    templates: &[
        (
            "suricata.yaml",
            include_str!("../../templates/suricata/suricata.yaml"),
        ),
        (
            "vars.yaml",
            include_str!("../../templates/suricata/vars.yaml"),
        ),
        (
            "threshold.config",
            include_str!("../../templates/suricata/threshold.config"),
        ),
        (
            "local.rules",
            include_str!("../../templates/suricata/local.rules"),
        ),
        (
            "suricata.args",
            include_str!("../../templates/suricata/suricata.args"),
        ),
        (
            "update.args",
            include_str!("../../templates/suricata/update.args"),
        ),
        (
            "enable.conf",
            include_str!("../../templates/suricata/enable.conf"),
        ),
        (
            "disable.conf",
            include_str!("../../templates/suricata/disable.conf"),
        ),
        (
            "drop.conf",
            include_str!("../../templates/suricata/drop.conf"),
        ),
        (
            "modify.conf",
            include_str!("../../templates/suricata/modify.conf"),
        ),
    ],
    targets: include_str!("../../templates/suricata/TARGETS"),
};

/// The update timer's schedule (local time).
pub fn timer_dropin(u: &sensr_schema::models::ids::RuleUpdates) -> String {
    format!(
        "# Generated by sensr (ids.updates); do not edit.\n[Timer]\nOnCalendar=\nOnCalendar=*-*-* {:02}:{:02}:00\nRandomizedDelaySec=10min\nPersistent=true\n",
        u.hour, u.minute
    )
}

/// Which unit action a changed file needs.
pub fn action_for(file: &str) -> Option<crate::plan::UnitAction> {
    use crate::plan::UnitAction;
    match file {
        "suricata.yaml" | "suricata.args" => Some(UnitAction::Restart),
        "vars.yaml" | "threshold.config" | "local.rules" => Some(UnitAction::Reload),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sensr_schema::models::ids::{
        IdsPolicy, MetadataMatch, RuleOverride, SuppressTrack, Suppression, UserRule,
    };

    fn doc() -> Document {
        serde_json::from_str(include_str!(
            "../../../sensr-import-opnsense/tests/golden/home-router.sensr.json"
        ))
        .unwrap()
    }

    fn wan_lease() -> BTreeMap<String, Vec<IfAddr>> {
        BTreeMap::from([(
            "wan".to_owned(),
            vec![IfAddr {
                addr: "203.0.113.77".parse().unwrap(),
                prefix_len: 22,
            }],
        )])
    }

    pub(crate) fn model() -> SuricataModel {
        let mut d = doc();
        d.ids.enabled = true;
        SuricataModel::from_document(&d, &wan_lease(), 4)
            .unwrap()
            .unwrap()
    }

    fn render(m: &SuricataModel) -> BTreeMap<String, String> {
        let mut t = Templates::empty();
        t.register(MODULE).unwrap();
        m.render(&t)
            .unwrap()
            .into_iter()
            .map(|r| (r.dest.display().to_string(), r.contents))
            .collect()
    }

    #[test]
    fn home_net_has_the_wan_lease_and_lan_networks() {
        let m = model();
        let h: Vec<String> = m.home_net.iter().map(ToString::to_string).collect();
        assert!(h.contains(&"203.0.113.77/32".to_owned()), "{h:?}");
        assert!(h.contains(&"192.168.0.0/16".to_owned()), "{h:?}");
        // without auto, only the configured networks
        let mut d = doc();
        d.ids.enabled = true;
        d.ids.home_net_auto = false;
        let h = home_net(&d, &wan_lease());
        assert_eq!(h.len(), 3);
        // a new lease changes HOME_NET (and nothing else of the yaml)
        let mut other = wan_lease();
        other.get_mut("wan").unwrap()[0].addr = "198.51.100.9".parse().unwrap();
        d.ids.home_net_auto = true;
        let m2 = SuricataModel::from_document(&d, &other, 4)
            .unwrap()
            .unwrap();
        let (a, b) = (render(&model()), render(&m2));
        assert_ne!(a["vars.yaml"], b["vars.yaml"]);
        assert_eq!(a["suricata.yaml"], b["suricata.yaml"]);
    }

    #[test]
    fn detect_mode_golden() {
        let files = render(&model());
        insta::assert_snapshot!("suricata_detect_yaml", files["suricata.yaml"]);
        insta::assert_snapshot!("suricata_detect_vars", files["vars.yaml"]);
        insta::assert_snapshot!("suricata_threshold", files["threshold.config"]);
        insta::assert_snapshot!("suricata_detect_args", files["suricata.args"]);
        insta::assert_snapshot!("suricata_update_args", files["update.args"]);
        assert!(files["threshold.config"].contains("sig_id 2016149"));
        assert!(files["suricata.yaml"].contains("af-packet"));
        assert!(files["suricata.yaml"].contains("cpu: [ \"1-3\" ]"));
        assert!(model().ips_ruleset().contains("delete"));
    }

    #[test]
    fn prevent_mode_golden_and_queue_table() {
        let mut d = doc();
        d.ids.enabled = true;
        d.ids.mode = IdsMode::Prevent;
        let m = SuricataModel::from_document(&d, &wan_lease(), 4)
            .unwrap()
            .unwrap();
        let files = render(&m);
        let y = &files["suricata.yaml"];
        assert!(y.contains("nfq:") && !y.contains("af-packet:"), "{y}");
        assert!(y.contains("midstream: true") && y.contains("fail-open: true"));
        assert!(y.contains("exception-policy: \"ignore\""));
        insta::assert_snapshot!("suricata_prevent_args", files["suricata.args"]);
        let nft: serde_json::Value = serde_json::from_str(&m.ips_ruleset()).unwrap();
        insta::assert_snapshot!(
            "suricata_ips_nft",
            serde_json::to_string_pretty(&nft).unwrap()
        );
        let text = nft.to_string();
        assert!(text.contains(r#""flags":["bypass","fanout"]"#), "{text}");
        assert!(text.contains(r#""range":[0,2]"#), "{text}");
    }

    #[test]
    fn user_rules_policies_and_overrides() {
        let mut d = doc();
        d.ids.enabled = true;
        d.ids.user_rules.push(UserRule {
            enabled: true,
            source: Some("192.168.1.0/22".parse().unwrap()),
            destination: None,
            fingerprint: None,
            action: UserRuleAction::Pass,
            bypass: true,
            description: "LAN \"backup\"; bulk".parse().unwrap(),
        });
        d.ids.user_rules.push(UserRule {
            enabled: true,
            source: None,
            destination: None,
            fingerprint: Some((0..20).map(|_| "AB").collect::<Vec<_>>().join(":")),
            action: UserRuleAction::Drop,
            bypass: false,
            description: "bad cert".parse().unwrap(),
        });
        d.ids.policies.push(IdsPolicy {
            enabled: true,
            priority: 1,
            rulesets: vec!["emerging-scan.rules".parse().unwrap()],
            metadata: vec![],
            action: PolicyAction::Drop,
            description: None,
        });
        d.ids.policies.push(IdsPolicy {
            enabled: true,
            priority: 0,
            rulesets: vec![],
            metadata: vec![MetadataMatch {
                key: "signature_severity".into(),
                value: "Informational".into(),
            }],
            action: PolicyAction::Disable,
            description: None,
        });
        d.ids.rule_overrides.push(RuleOverride {
            sid: 2024897,
            enabled: false,
            action: RuleAction::Alert,
        });
        d.ids.suppressions.push(Suppression {
            enabled: true,
            gid: 1,
            sid: 2047702,
            track: Some(SuppressTrack {
                by: TrackBy::Src,
                net: "192.168.1.20/32".parse().unwrap(),
            }),
            description: None,
        });
        let m = SuricataModel::from_document(&d, &wan_lease(), 4)
            .unwrap()
            .unwrap();
        let f = render(&m);
        insta::assert_snapshot!("suricata_local_rules", f["local.rules"]);
        assert!(f["local.rules"].contains(r#"msg:"LAN \"backup\"\; bulk"; bypass;"#));
        assert!(f["local.rules"].contains("sid:4294967294;"));
        assert!(f["drop.conf"].contains("group:emerging-scan.rules"));
        assert!(f["disable.conf"].contains("metadata: signature_severity Informational"));
        assert!(f["disable.conf"].contains("2024897"));
        assert!(f["threshold.config"].contains("track by_src, ip 192.168.1.20/32"));
    }

    #[test]
    fn workers_follow_cpus_and_interfaces() {
        let mut d = doc();
        d.ids.enabled = true;
        d.ids.interfaces = vec!["lan".parse().unwrap(), "wan".parse().unwrap()];
        let m = SuricataModel::from_document(&d, &wan_lease(), 4)
            .unwrap()
            .unwrap();
        assert_eq!(m.capture.len(), 2);
        assert!(m.capture.iter().all(|c| c.threads == 1));
        assert_ne!(m.capture[0].cluster_id, m.capture[1].cluster_id);
        let one = SuricataModel::from_document(&d, &wan_lease(), 1)
            .unwrap()
            .unwrap();
        assert!(one.worker_cpus.is_none());
        d.ids.enabled = false;
        assert!(
            SuricataModel::from_document(&d, &wan_lease(), 4)
                .unwrap()
                .is_none()
        );
    }

    /// `suricata -T` on the rendered config when Suricata is installed
    /// (nixtop: `nix shell nixpkgs#suricata -c cargo test -p sensr-apply suricata`).
    #[test]
    fn real_suricata_accepts_the_config() {
        use crate::cmd::{Cmd, Runner, SystemRunner};
        if !SystemRunner.has_program("suricata") {
            eprintln!("note: suricata not installed; skipping");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        for mode in [IdsMode::Detect, IdsMode::Prevent] {
            let mut d = doc();
            d.ids.enabled = true;
            d.ids.mode = mode;
            let m = SuricataModel::from_document(&d, &wan_lease(), 4)
                .unwrap()
                .unwrap();
            let rules = p.join("rules");
            std::fs::create_dir_all(&rules).unwrap();
            for f in m.rule_files.iter().flatten() {
                std::fs::write(rules.join(f), "").unwrap();
            }
            std::fs::write(
                rules.join("emerging-attack_response.rules"),
                "alert http any any -> any any (msg:\"GPL ATTACK_RESPONSE id check returned root\"; content:\"uid=0|28|root|29|\"; classtype:bad-unknown; sid:2100498; rev:7;)\n",
            )
            .unwrap();
            // the package root: <root>/bin/suricata -> <root>/etc/suricata
            let share = std::env::var_os("PATH")
                .into_iter()
                .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
                .map(|d| d.join("suricata"))
                .find(|b| b.is_file())
                .and_then(|b| std::fs::canonicalize(b).ok())
                .and_then(|b| b.parent()?.parent().map(|r| r.display().to_string()))
                .unwrap_or_default();
            for f in ["classification.config", "reference.config"] {
                let _ = std::fs::copy(format!("{share}/etc/suricata/{f}"), rules.join(f));
            }
            for (name, text) in render(&m) {
                let text = text
                    .replace(&format!("/{DIR}"), &p.display().to_string())
                    .replace(RULE_DIR, &rules.display().to_string())
                    .replace(STATE_DIR, &p.display().to_string())
                    .replace(LOG_DIR, &p.display().to_string());
                std::fs::write(p.join(name), text).unwrap();
            }
            let out = SystemRunner
                .run(
                    &Cmd::new("suricata")
                        .args(["-T", "-c"])
                        .arg(p.join("suricata.yaml"))
                        .args(["-l"])
                        .arg(p),
                    None,
                )
                .unwrap();
            assert!(
                out.success(),
                "suricata -T ({mode:?}): {}{}",
                String::from_utf8_lossy(&out.stdout),
                out.stderr_text()
            );
        }
    }
}
