//! The real apply pipeline for the routing slice: [`sensr_apply::engine`]
//! (networkd links, the `sensr-rules` nft ruleset, Kea, Unbound, WireGuard,
//! sysctls, qdiscs) behind the agent's [`Applier`] boundary.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use std::path::PathBuf;

use sensr_apply::cmd::{Cmd, Runner, SystemRunner};
use sensr_apply::engine::{Engine, EngineError, EngineOptions, Prepared};
use sensr_apply::plan::UnitAction;
use sensr_feeds::http::HttpFetcher;
use sensr_feeds::{Feeds, NeighbourFn, SystemResolver};
use sensr_ipc::{FileDiff, PlanView, ServiceAction, ServiceChange, ValidationIssue};
use sensr_rules::document::Runtime;
use sensr_rules::host_modes::HostModeSets;
use sensr_rules::ir::IfAddr;
use sensr_schema::Document;
use sensr_schema::fields::MacAddr;
use serde_json::Value;

use crate::applier::{Applier, ApplyError};
use crate::diff::unified_text;

/// The applied document and the link addresses its ruleset knows.
type Applied = Option<(Document, BTreeMap<String, Vec<IfAddr>>)>;

/// Applies documents to the host through [`Engine`].
pub struct SliceApplier {
    engine: Arc<Mutex<Engine>>,
    applied: Arc<Mutex<Applied>>,
    watch: Option<Duration>,
    watching: bool,
    feeds: Option<Arc<Feeds>>,
    refreshing: bool,
    gateways: Option<Arc<crate::gateways::GatewayService>>,
    pd: Option<Arc<crate::pd::PdService>>,
    hosts: Option<Arc<crate::hosts::HostCollector>>,
    /// The neighbour table and active leases (`(mac, address)`), for MAC
    /// aliases and the locked hosts' addresses.
    neighbours: Option<Arc<NeighbourFn>>,
    /// The host-mode sets last pushed to the ruleset.
    host_modes: Arc<Mutex<HostModeSets>>,
}

/// How often link addresses are compared with the ruleset's sets.
const ADDRESS_POLL: Duration = Duration::from_secs(2);
/// How often alias feeds are checked for due refreshes (each feed keeps its
/// own schedule; this is only the tick).
const FEED_TICK: Duration = Duration::from_secs(10);

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // a panic mid-apply leaves nothing half-held worth protecting
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl SliceApplier {
    /// On the host (`/`, real commands), following address changes; alias
    /// feeds (URL tables, GeoIP, ASN, host names, MACs) are kept under
    /// `feeds_dir` when given.
    pub fn system_with_feeds(feeds_dir: Option<PathBuf>) -> Result<SliceApplier, EngineError> {
        let mut a = Self::system()?;
        if let Some(state) = feeds_dir.as_ref().and_then(|d| d.parent()) {
            let pd = crate::pd::PdService::new(Arc::new(SystemRunner), "/", state.join("pd"));
            pd.start();
            a.pd = Some(pd);
            let hosts = crate::hosts::HostCollector::new(
                crate::hosts::HostStore::new(state.join("hosts.json")),
                Arc::new(host_sources(Arc::new(SystemRunner))),
            );
            hosts.start();
            a.hosts = Some(hosts);
        }
        if let Some(dir) = feeds_dir {
            let runner: Arc<dyn Runner> = Arc::new(SystemRunner);
            let neighbours: Arc<NeighbourFn> = Arc::new(move || {
                let mut table = runner
                    .run(&Cmd::new("ip").args(["-j", "neigh", "show"]), None)
                    .map(|o| sensr_feeds::neigh::parse_ip_neigh_json(&o.stdout))
                    .unwrap_or_default();
                // A just-leased device has no neighbour entry yet (nothing
                // has made the box ARP it), so a MAC alias would miss it.
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                table.extend(sensr_feeds::neigh::read_kea_leases(
                    std::path::Path::new(sensr_apply::appliers::kea::LEASE_FILE),
                    now,
                ));
                table
            });
            a.neighbours = Some(Arc::clone(&neighbours));
            a.feeds = Some(Arc::new(Feeds::new(
                dir,
                Arc::new(HttpFetcher::default()),
                Arc::new(SystemResolver),
                neighbours,
            )));
        }
        Ok(a)
    }

    /// With an explicit feed store (tests).
    pub fn with_feeds(mut self, feeds: Arc<Feeds>) -> SliceApplier {
        self.feeds = Some(feeds);
        self
    }

    /// With an explicit neighbour table (tests).
    pub fn with_neighbours(mut self, neighbours: Arc<NeighbourFn>) -> SliceApplier {
        self.neighbours = Some(neighbours);
        self
    }

    /// Alias feed status of the applied document (API, UI).
    pub fn alias_status(&self) -> Vec<sensr_feeds::AliasStatus> {
        let (Some(f), Some((doc, _))) = (&self.feeds, lock(&self.applied).as_ref().cloned()) else {
            return Vec::new();
        };
        f.status(&doc, unix_now())
    }

    /// On the host (`/`, real commands), following address changes.
    pub fn system() -> Result<SliceApplier, EngineError> {
        let opts = EngineOptions {
            // under /run/sensr (0755): networkd must reach the WireGuard
            // keys, which /var/lib/sensr (0700) would hide
            secrets: sensr_apply::appliers::convert::SecretsDir("/run/sensr/secrets".into()),
            ..EngineOptions::default()
        };
        let mut a = Self::new(opts, Arc::new(SystemRunner))?;
        a.watch = Some(ADDRESS_POLL);
        a.gateways = crate::gateways::GatewayService::start(Arc::new(SystemRunner));
        Ok(a)
    }

    /// With explicit options and runner, without the address watcher (tests).
    pub fn new(opts: EngineOptions, runner: Arc<dyn Runner>) -> Result<SliceApplier, EngineError> {
        Ok(SliceApplier {
            engine: Arc::new(Mutex::new(Engine::new(opts, runner)?)),
            applied: Arc::new(Mutex::new(None)),
            watch: None,
            watching: false,
            feeds: None,
            refreshing: false,
            gateways: None,
            pd: None,
            hosts: None,
            neighbours: None,
            host_modes: Arc::new(Mutex::new(HostModeSets::default())),
        })
    }

    /// Feeds refresh on their own schedules; changed aliases reach the
    /// ruleset as one set transaction each tick, never as a reload. The
    /// locked hosts' addresses follow the neighbour table on the same tick.
    fn start_refresher(&mut self) {
        if self.refreshing || (self.feeds.is_none() && self.neighbours.is_none()) {
            return;
        }
        if self.watch.is_none() {
            // tests drive refresh() themselves
            return;
        }
        self.refreshing = true;
        let feeds = self.feeds.clone();
        let neighbours = self.neighbours.clone();
        let engine = Arc::clone(&self.engine);
        let applied = Arc::clone(&self.applied);
        let host_modes = Arc::clone(&self.host_modes);
        std::thread::Builder::new()
            .name("sensr-alias-feeds".into())
            .spawn(move || {
                loop {
                    let doc = lock(&applied).as_ref().map(|(d, _)| d.clone());
                    if let (Some(feeds), Some(doc)) = (&feeds, doc) {
                        refresh_once(feeds, &engine, &doc, unix_now());
                    }
                    if let Some(n) = &neighbours {
                        refresh_host_modes(n.as_ref(), &engine, &host_modes);
                    }
                    std::thread::sleep(FEED_TICK);
                }
            })
            .map(|_| ())
            .unwrap_or_else(|e| tracing::error!(error = %e, "alias feed refresher not started"));
    }

    fn engine(&self) -> std::sync::MutexGuard<'_, Engine> {
        lock(&self.engine)
    }

    /// Links get their addresses after the apply (DHCP, SLAAC, tracked
    /// prefixes) and keep changing them; the ruleset's interface sets follow
    /// without a re-render.
    fn start_watcher(&mut self) {
        let (Some(every), false) = (self.watch, self.watching) else {
            return;
        };
        self.watching = true;
        let engine = Arc::clone(&self.engine);
        let applied = Arc::clone(&self.applied);
        std::thread::Builder::new()
            .name("sensr-addr-watch".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(every);
                    let mut cur = lock(&applied);
                    let Some((doc, known)) = cur.as_mut() else {
                        continue;
                    };
                    let e = lock(&engine);
                    let Ok(now) = e.current_addrs(doc) else {
                        continue;
                    };
                    if now == *known {
                        continue;
                    }
                    // HOME_NET holds the WAN's lease: follow it
                    match e.update_ids_home_net(doc, &now) {
                        Ok(true) => tracing::info!("IDS HOME_NET updated"),
                        Ok(false) => {}
                        Err(err) => tracing::warn!(error = %err, "updating IDS HOME_NET"),
                    }
                    match e.update_interface_sets(doc, &now) {
                        Ok(()) => {
                            tracing::info!(addresses = ?now, "interface sets updated");
                            *known = now;
                        }
                        Err(err) => tracing::warn!(error = %err, "updating interface sets"),
                    }
                }
            })
            .map(|_| ())
            .unwrap_or_else(|e| tracing::error!(error = %e, "address watcher not started"));
    }
}

/// One refresh tick: fetch what is due, push what changed.
pub fn refresh_once(feeds: &Feeds, engine: &Mutex<Engine>, doc: &Document, now: u64) {
    let r = feeds.refresh(doc, now);
    for f in &r.fetches {
        tracing::info!(url = %f.url, outcome = %f.outcome, bytes = f.bytes, ms = f.millis as u64, "alias feed fetched");
    }
    if r.updates.is_empty() {
        return;
    }
    let names: Vec<&str> = r.updates.iter().map(|(n, _)| n.as_str()).collect();
    let t0 = std::time::Instant::now();
    match lock(engine).update_alias_sets(&r.updates) {
        Ok(()) => {
            tracing::info!(aliases = ?names, ms = t0.elapsed().as_millis() as u64, "alias sets updated")
        }
        Err(e) => {
            tracing::warn!(error = %e, aliases = ?names, "alias set update failed; retrying next tick");
            feeds.reset();
        }
    }
}

/// `sets`' MACs with the addresses `table` holds for them: the locked
/// hosts' current IPv4 and IPv6 addresses.
fn with_locked(sets: &HostModeSets, table: &[(String, std::net::IpAddr)]) -> HostModeSets {
    use std::collections::BTreeSet;
    use std::net::IpAddr;
    let locked: BTreeSet<MacAddr> = sets
        .isolated
        .iter()
        .chain(&sets.quarantine)
        .copied()
        .collect();
    let (mut v4, mut v6) = (BTreeSet::new(), BTreeSet::new());
    for (mac, ip) in table {
        if !mac.parse().is_ok_and(|m: MacAddr| locked.contains(&m)) {
            continue;
        }
        match ip {
            IpAddr::V4(a) => v4.insert(*a),
            IpAddr::V6(a) => v6.insert(*a),
        };
    }
    HostModeSets {
        isolated: sets.isolated.clone(),
        quarantine: sets.quarantine.clone(),
        locked_v4: v4.into_iter().collect(),
        locked_v6: v6.into_iter().collect(),
    }
}

/// The addresses whose established flows must be cut when `prev` becomes
/// `next`: those new to the locked set, and those of a host that entered a
/// mode or moved Isolated to Quarantine. Leaving a mode, or Quarantine to
/// Isolated, cuts nothing.
fn newly_locked(
    prev: &HostModeSets,
    next: &HostModeSets,
    table: &[(String, std::net::IpAddr)],
) -> Vec<std::net::IpAddr> {
    use std::collections::BTreeSet;
    use std::net::IpAddr;
    let was_locked = |m: &MacAddr| prev.isolated.contains(m) || prev.quarantine.contains(m);
    let tightened: BTreeSet<MacAddr> = next
        .isolated
        .iter()
        .filter(|m| !was_locked(m))
        .chain(
            next.quarantine
                .iter()
                .filter(|m| !was_locked(m) || prev.isolated.contains(m)),
        )
        .copied()
        .collect();
    let known: BTreeSet<IpAddr> = prev
        .locked_v4
        .iter()
        .map(|a| IpAddr::V4(*a))
        .chain(prev.locked_v6.iter().map(|a| IpAddr::V6(*a)))
        .collect();
    let mut out: BTreeSet<IpAddr> = next
        .locked_v4
        .iter()
        .map(|a| IpAddr::V4(*a))
        .chain(next.locked_v6.iter().map(|a| IpAddr::V6(*a)))
        .filter(|a| !known.contains(a))
        .collect();
    for (mac, ip) in table {
        if mac.parse().is_ok_and(|m: MacAddr| tightened.contains(&m)) {
            out.insert(*ip);
        }
    }
    out.into_iter().collect()
}

/// Cuts `addrs`' established flows; a failure is logged, never fatal.
fn cut(engine: &Engine, addrs: &[std::net::IpAddr]) {
    if addrs.is_empty() {
        return;
    }
    match engine.cut_host(addrs) {
        Ok(()) => tracing::info!(?addrs, "cut existing connections of locked hosts"),
        Err(e) => tracing::warn!(error = %e, "cutting connections of locked hosts failed"),
    }
}

/// One host-mode tick: re-reads the locked hosts' addresses and pushes the
/// sets when they changed (a new lease, a released one). Nothing when no
/// host is in a mode, since the ruleset then declares none of the sets.
pub fn refresh_host_modes(
    neighbours: &NeighbourFn,
    engine: &Mutex<Engine>,
    pushed: &Mutex<HostModeSets>,
) {
    if lock(pushed).is_empty() {
        return;
    }
    // outside the locks: this runs `ip` and reads Kea's files
    let table = neighbours();
    let mut pushed = lock(pushed);
    if pushed.is_empty() {
        return;
    }
    let next = with_locked(&pushed, &table);
    if next == *pushed {
        return;
    }
    let engine = lock(engine);
    match engine.update_host_mode_sets(&next) {
        Ok(()) => {
            tracing::info!(v4 = ?next.locked_v4, v6 = ?next.locked_v6, "locked host addresses updated");
            // a locked host's new address may already hold an open flow
            cut(&engine, &newly_locked(&pushed, &next, &table));
            *pushed = next;
        }
        Err(e) => tracing::warn!(error = %e, "host-mode set update failed; retrying next tick"),
    }
}

fn issue(path: &str, message: impl Into<String>) -> ValidationIssue {
    let mut message = message.into();
    if !message.ends_with('.') {
        message.push('.');
    }
    ValidationIssue {
        path: path.to_owned(),
        message,
    }
}

/// Validates a document before it reaches the engine (the store validated
/// it on commit; this guards boot applies of revisions written by an older
/// build).
fn document(doc: &Document) -> Result<&Document, ApplyError> {
    let v = doc.validate();
    if !v.is_empty() {
        tracing::warn!(issues = ?v, "document does not validate");
        return Err(ApplyError::Invalid(
            v.iter()
                .flat_map(|(path, errs)| {
                    errs.iter()
                        .map(move |e| issue(&path.to_string(), e.message.clone()))
                })
                .collect(),
        ));
    }
    Ok(doc)
}

fn prepare(
    engine: &Engine,
    doc: &Document,
    feeds: Option<&Feeds>,
) -> Result<(Prepared, BTreeMap<String, Vec<IfAddr>>), EngineError> {
    // what DHCP/SLAAC gave the links right now; sets follow later changes
    let addrs = engine.current_addrs(doc).unwrap_or_default();
    let sources = feeds.map(Feeds::sources);
    let p = engine.prepare(
        doc,
        &Runtime {
            addrs: addrs.clone(),
            sources: sources
                .as_ref()
                .map(|s| s as &dyn sensr_rules::alias::Sources),
        },
    )?;
    Ok((p, addrs))
}

fn rejected(e: EngineError) -> ApplyError {
    tracing::warn!(error = %e, "apply engine");
    match e {
        EngineError::Rejected { backend, message } => {
            ApplyError::Invalid(vec![issue(backend, message.trim().to_owned())])
        }
        other => ApplyError::Failed(other.to_string()),
    }
}

impl Applier for SliceApplier {
    fn plan(&self, running: Option<&Document>, next: &Document) -> Result<PlanView, ApplyError> {
        let doc = document(next)?;
        let engine = self.engine();
        let (p, _) = prepare(&engine, doc, self.feeds.as_deref()).map_err(rejected)?;
        engine.check(&p).map_err(rejected)?;
        let delta = engine.delta(&p);
        let old_ruleset = match running.map(document) {
            Some(Ok(old)) => prepare(&engine, old, self.feeds.as_deref())
                .map(|(o, _)| String::from_utf8_lossy(&o.ruleset).into_owned())
                .unwrap_or_default(),
            _ => String::new(),
        };
        let nft = if delta.nft.is_some() {
            unified_text(
                &pretty(&old_ruleset),
                &pretty(&String::from_utf8_lossy(&p.ruleset)),
                "running",
                "planned",
            )
        } else {
            String::new()
        };
        let net = delta
            .files
            .keys()
            .filter(|f| f.starts_with("/run/systemd/network"))
            .map(|f| format!("write {}", f.display()))
            .chain(
                delta
                    .remove_files
                    .iter()
                    .filter(|f| f.starts_with("/run/systemd/network"))
                    .map(|f| format!("remove {}", f.display())),
            )
            .collect();
        let services = delta
            .units
            .iter()
            .map(|(unit, spec)| ServiceChange {
                unit: unit.clone(),
                action: match spec.action {
                    UnitAction::Reload => ServiceAction::Reload,
                    UnitAction::Restart => ServiceAction::Restart,
                },
                files: spec
                    .inputs
                    .iter()
                    .filter_map(|path| {
                        let f = delta.files.get(path)?;
                        Some(FileDiff {
                            path: path.display().to_string(),
                            unified: unified_text(
                                "",
                                &String::from_utf8_lossy(&f.contents),
                                "running",
                                "planned",
                            ),
                        })
                    })
                    .collect(),
            })
            .collect();
        Ok(PlanView { nft, net, services })
    }

    fn runtime(&self, section: sensr_ipc::RuntimeSection) -> Option<Value> {
        match section {
            sensr_ipc::RuntimeSection::Gateways => self.gateways_view(),
            sensr_ipc::RuntimeSection::Aliases => serde_json::to_value(self.alias_status()).ok(),
            sensr_ipc::RuntimeSection::Ipv6 => self
                .pd
                .as_ref()
                .and_then(|p| serde_json::to_value(p.view(unix_now())).ok()),
            sensr_ipc::RuntimeSection::Hosts => self.hosts.as_ref().map(|h| h.view(unix_now())),
        }
    }

    fn forget_host(&mut self, key: &str) -> Result<bool, ApplyError> {
        Ok(self.hosts.as_ref().is_some_and(|h| h.forget(key)))
    }

    fn client_mac(&self, ip: std::net::IpAddr) -> Option<String> {
        self.hosts.as_ref()?.mac_for_ip(ip)
    }

    fn apply(&mut self, _running: Option<&Document>, next: &Document) -> Result<(), ApplyError> {
        let doc = document(next)?.clone();
        // before the engine, as in the refresher: no tick pushes stale sets
        // between the reload and the push below
        let mut pushed = lock(&self.host_modes);
        let mut engine = self.engine();
        let (p, addrs) = prepare(&engine, &doc, self.feeds.as_deref()).map_err(rejected)?;
        let rendered = p.aliases.clone();
        let host_modes = p.host_modes.clone();
        for w in &p.warnings {
            tracing::warn!(rule = %w, "firewall rule degraded");
        }
        if !p.alias_failed.is_empty() {
            tracing::warn!(aliases = ?p.alias_failed, "aliases kept their previous contents");
        }
        let report = engine.commit(p).map_err(rejected)?;
        tracing::info!(
            commands = report.commands.len(),
            files = report.files.len(),
            nft = report.nft_loaded,
            "applied"
        );
        // A full ruleset declares the locked hosts' address sets empty:
        // fill them now, not on the next tick.
        let table = self.neighbours.as_ref().map(|n| n()).unwrap_or_default();
        let sets = with_locked(&host_modes, &table);
        // cut whether or not the push worked: the ruleset holds the MACs
        cut(&engine, &newly_locked(&pushed, &sets, &table));
        match engine.update_host_mode_sets(&sets) {
            Ok(()) => *pushed = sets,
            Err(e) => {
                tracing::warn!(error = %e, "host-mode set update failed; retrying next tick");
                // the ruleset holds the MACs only; the tick fills the rest
                *pushed = with_locked(&host_modes, &[]);
            }
        }
        drop(engine);
        drop(pushed);
        if let Some(f) = &self.feeds {
            f.applied(rendered);
        }
        if let Some(g) = &self.gateways {
            g.applied(&doc);
        }
        if let Some(p) = &self.pd {
            p.applied(&doc);
        }
        if let Some(h) = &self.hosts {
            h.set_document(&doc);
        }
        *lock(&self.applied) = Some((doc, addrs));
        self.start_watcher();
        self.start_refresher();
        Ok(())
    }
}

impl Drop for SliceApplier {
    fn drop(&mut self) {
        // clean shutdown: keep the last `last_seen`s the throttle held back
        if let Some(h) = &self.hosts {
            h.shutdown();
        }
    }
}

/// The host inventory's inputs: `ip -j neigh show` and Kea's lease files.
fn host_sources(
    runner: Arc<dyn Runner>,
) -> impl Fn() -> (
    Vec<sensr_feeds::neigh::NeighEntry>,
    Vec<sensr_feeds::neigh::KeaLease>,
) + Send
+ Sync
+ 'static {
    move || {
        let neigh = runner
            .run(&Cmd::new("ip").args(["-j", "neigh", "show"]), None)
            .map(|o| sensr_feeds::neigh::parse_ip_neigh_entries(&o.stdout))
            .unwrap_or_default();
        let leases = sensr_feeds::neigh::read_kea_lease_records(
            std::path::Path::new(sensr_apply::appliers::kea::LEASE_FILE),
            unix_now(),
        );
        (neigh, leases)
    }
}

impl SliceApplier {
    /// Gateway monitor view (System › Gateways, dashboard widget).
    pub fn gateways_view(&self) -> Option<Value> {
        let g = self.gateways.as_ref()?;
        serde_json::to_value(g.view()).ok()
    }
}

/// One nft command per line, for a readable ruleset diff.
fn pretty(json: &str) -> String {
    let v: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    v.get("nftables")
        .and_then(Value::as_array)
        .map(|cmds| {
            cmds.iter()
                .map(|c| c.to_string() + "\n")
                .collect::<String>()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensr_apply::cmd::FakeRunner;

    fn home_router() -> Document {
        serde_json::from_str(include_str!(
            "../../sensr-import-opnsense/tests/golden/home-router.sensr.json"
        ))
        .unwrap()
    }

    #[test]
    fn plans_and_applies_the_home_router() {
        let root = tempfile::tempdir().unwrap();
        let mut keys: Vec<String> = sensr_apply::appliers::sysctl::SysctlModel::default()
            .to_map()
            .unwrap()
            .into_keys()
            .collect();
        keys.push("net.core.default_qdisc".into());
        keys.push("kernel.hostname".into());
        for k in keys {
            let p = root.path().join("proc/sys").join(k.replace('.', "/"));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "0\n").unwrap();
        }
        let runner = Arc::new(FakeRunner::new());
        let mut a = SliceApplier::new(
            EngineOptions {
                root: root.path().to_owned(),
                ..EngineOptions::default()
            },
            runner.clone(),
        )
        .unwrap();
        let doc = home_router();
        let plan = a.plan(None, &doc).unwrap();
        assert!(!plan.nft.is_empty());
        assert!(
            plan.services
                .iter()
                .any(|s| s.unit == "sensr-kea-dhcp4.service")
        );
        a.apply(None, &doc).unwrap();
        assert!(
            runner
                .call_lines()
                .iter()
                .any(|l| l.starts_with("nft '-j'"))
        );
        assert!(a.plan(Some(&doc), &doc).unwrap().is_empty());
    }

    struct OneList;
    impl sensr_feeds::http::Fetcher for OneList {
        fn get(
            &self,
            url: &str,
            _: &sensr_rules::alias::Auth,
            _: &sensr_feeds::http::Conditional,
        ) -> Result<sensr_feeds::http::Fetched, sensr_feeds::http::HttpError> {
            if url.ends_with("/blocklist.txt") {
                Ok(sensr_feeds::http::Fetched::Body {
                    bytes: b"198.51.100.0/24\n".to_vec(),
                    conditional: Default::default(),
                })
            } else {
                Err(sensr_feeds::http::HttpError("unreachable".into()))
            }
        }
    }

    #[test]
    fn alias_refresh_pushes_a_set_update_not_a_reload() {
        let root = tempfile::tempdir().unwrap();
        for k in sensr_apply::appliers::sysctl::SysctlModel::default()
            .to_map()
            .unwrap()
            .into_keys()
            .chain(["net.core.default_qdisc".into(), "kernel.hostname".into()])
        {
            let p = root.path().join("proc/sys").join(k.replace('.', "/"));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "0\n").unwrap();
        }
        let runner = Arc::new(FakeRunner::new());
        let feeds = Arc::new(Feeds::new(
            root.path().join("aliases"),
            Arc::new(OneList),
            Arc::new(SystemResolver),
            Arc::new(Vec::new),
        ));
        let mut a = SliceApplier::new(
            EngineOptions {
                root: root.path().to_owned(),
                ..EngineOptions::default()
            },
            runner.clone(),
        )
        .unwrap()
        .with_feeds(feeds.clone());
        let doc = home_router();
        a.apply(None, &doc).unwrap();
        let loads = |r: &FakeRunner| {
            r.call_lines()
                .iter()
                .filter(|l| l.starts_with("nft '-j'"))
                .count()
        };
        let before = loads(&runner);
        let typed: Document = doc.clone();
        refresh_once(&feeds, &a.engine, &typed, 1_000);
        // BLOCKLIST arrived: one more transaction, a set update
        assert_eq!(loads(&runner), before + 1);
        let st = a.alias_status();
        let bl = st.iter().find(|s| s.name == "BLOCKLIST").unwrap();
        assert_eq!(bl.entries, 1);
        assert!(bl.error.is_none());
        let drop = st.iter().find(|s| s.name == "DROP_FEED").unwrap();
        assert!(drop.error.as_deref().unwrap().contains("unreachable"));
        // nothing due: nothing pushed
        refresh_once(&feeds, &a.engine, &typed, 1_005);
        assert_eq!(loads(&runner), before + 1);
    }

    #[test]
    fn invalid_documents_are_rejected_with_paths() {
        use sensr_schema::PathAccess;
        let a = SliceApplier::new(EngineOptions::default(), Arc::new(FakeRunner::new())).unwrap();
        let mut doc = Document::factory();
        // DHCP on an interface that is not assigned
        doc.set_by_path("dhcpv4.interfaces", serde_json::json!(["opt9"]))
            .unwrap();
        assert!(!doc.validate().is_empty());
        let err = a.plan(None, &doc).unwrap_err();
        assert!(matches!(err, ApplyError::Invalid(_)), "{err:?}");
    }

    fn fake_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        for k in sensr_apply::appliers::sysctl::SysctlModel::default()
            .to_map()
            .unwrap()
            .into_keys()
            .chain(["net.core.default_qdisc".into(), "kernel.hostname".into()])
        {
            let p = root.path().join("proc/sys").join(k.replace('.', "/"));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "0\n").unwrap();
        }
        // locked hosts turn ICMP redirects off per internal link
        for i in crate::hosts::internal_interfaces(&home_router()) {
            let p = root
                .path()
                .join(format!("proc/sys/net/ipv4/conf/{}", i.device));
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("send_redirects"), "1\n").unwrap();
        }
        root
    }

    type Table = Arc<Mutex<Vec<(String, std::net::IpAddr)>>>;

    fn moded_applier(root: &tempfile::TempDir) -> (SliceApplier, Arc<FakeRunner>, Table) {
        let runner = Arc::new(FakeRunner::new());
        let table: Table = Arc::new(Mutex::new(Vec::new()));
        let t = Arc::clone(&table);
        let a = SliceApplier::new(
            EngineOptions {
                root: root.path().to_owned(),
                ..EngineOptions::default()
            },
            runner.clone(),
        )
        .unwrap()
        .with_neighbours(Arc::new(move || lock(&t).clone()));
        (a, runner, table)
    }

    /// The nft transactions so far, as text.
    fn nft_loads(r: &FakeRunner) -> Vec<String> {
        r.calls()
            .iter()
            .filter(|c| c.cmd.display() == "nft '-j' '-f' '-'")
            .map(|c| String::from_utf8_lossy(c.stdin.as_deref().unwrap_or_default()).into_owned())
            .collect()
    }

    const LOCKED: &str = "02:00:5e:10:00:99";

    fn quarantined() -> Document {
        use sensr_schema::PathAccess;
        let mut doc = home_router();
        doc.set_by_path(
            "firewall.host_modes.6d0de000-0000-4000-8000-000000000001",
            serde_json::json!({"mac": LOCKED, "mode": "quarantine"}),
        )
        .unwrap();
        doc
    }

    #[test]
    fn no_host_mode_push_without_modes() {
        let root = fake_root();
        let (mut a, runner, table) = moded_applier(&root);
        lock(&table).push((LOCKED.into(), "192.168.1.20".parse().unwrap()));
        a.apply(None, &home_router()).unwrap();
        let loads = nft_loads(&runner);
        assert!(
            loads.iter().all(|l| !l.contains("host_locked")),
            "no host-mode sets are declared, so none may be pushed"
        );
        let n = runner.calls().len();
        refresh_host_modes(a.neighbours.as_deref().unwrap(), &a.engine, &a.host_modes);
        assert_eq!(runner.calls().len(), n, "the tick pushes nothing either");
    }

    #[test]
    fn locked_addresses_are_pushed_after_every_apply_and_follow_the_table() {
        let root = fake_root();
        let (mut a, runner, table) = moded_applier(&root);
        lock(&table).extend([
            (LOCKED.to_uppercase(), "192.168.1.20".parse().unwrap()),
            (LOCKED.into(), "fd00::20".parse().unwrap()),
            ("02:00:5e:10:00:0a".into(), "192.168.1.10".parse().unwrap()),
        ]);
        let doc = quarantined();
        a.apply(None, &doc).unwrap();
        let loads = nft_loads(&runner);
        let last = loads.last().unwrap();
        assert!(
            last.contains("host_locked_v4") && last.contains("192.168.1.20"),
            "{last}"
        );
        assert!(last.contains("fd00::20"), "{last}");
        assert!(
            !last.contains("192.168.1.10"),
            "a Normal host is not locked"
        );
        // a re-apply of the same document reloads nothing but still pushes
        a.apply(Some(&doc), &doc).unwrap();
        let again = nft_loads(&runner);
        assert!(again.len() > loads.len());
        assert!(again.last().unwrap().contains("192.168.1.20"));

        let tick = |a: &SliceApplier| {
            refresh_host_modes(a.neighbours.as_deref().unwrap(), &a.engine, &a.host_modes)
        };
        // nothing changed: nothing pushed
        let n = nft_loads(&runner).len();
        tick(&a);
        assert_eq!(nft_loads(&runner).len(), n);
        // a new lease is covered on the next tick, the old address drops out
        lock(&table)[0].1 = "192.168.1.21".parse().unwrap();
        tick(&a);
        let loads = nft_loads(&runner);
        assert_eq!(loads.len(), n + 1);
        let last = loads.last().unwrap();
        assert!(
            last.contains("192.168.1.21") && !last.contains("192.168.1.20"),
            "{last}"
        );
        // released: the set empties
        lock(&table).clear();
        tick(&a);
        let loads = nft_loads(&runner);
        assert_eq!(loads.len(), n + 2);
        assert!(!loads.last().unwrap().contains("192.168.1.21"));

        // back to no modes: the next tick pushes nothing
        a.apply(Some(&doc), &home_router()).unwrap();
        lock(&table).push((LOCKED.into(), "192.168.1.22".parse().unwrap()));
        let n = runner.calls().len();
        tick(&a);
        assert_eq!(runner.calls().len(), n);
    }

    #[test]
    fn apply_cuts_newly_locked_hosts() {
        use sensr_schema::PathAccess;
        let root = fake_root();
        let (mut a, runner, table) = moded_applier(&root);
        lock(&table).push((LOCKED.into(), "192.168.1.20".parse().unwrap()));
        let conntrack = |r: &FakeRunner| -> Vec<String> {
            r.call_lines()
                .into_iter()
                .filter(|l| l.starts_with("conntrack"))
                .collect()
        };
        a.apply(None, &home_router()).unwrap();
        assert!(conntrack(&runner).is_empty(), "no mode, no cut");

        let doc = quarantined();
        a.apply(Some(&home_router()), &doc).unwrap();
        assert_eq!(
            conntrack(&runner),
            [
                "conntrack '-D' '-s' '192.168.1.20'",
                "conntrack '-D' '-d' '192.168.1.20'"
            ]
        );
        a.apply(Some(&doc), &doc).unwrap();
        assert_eq!(conntrack(&runner).len(), 2, "re-applying cuts nothing");

        // the tick finds a new lease: that address is cut too
        lock(&table)[0].1 = "192.168.1.21".parse().unwrap();
        refresh_host_modes(a.neighbours.as_deref().unwrap(), &a.engine, &a.host_modes);
        let c = conntrack(&runner);
        assert_eq!(c.len(), 4, "{c:?}");
        assert!(c[2].contains("192.168.1.21"));

        // Quarantine -> Isolated and leaving a mode cut nothing
        let mut iso = doc.clone();
        iso.set_by_path(
            "firewall.host_modes.6d0de000-0000-4000-8000-000000000001.mode",
            serde_json::json!("isolated"),
        )
        .unwrap();
        a.apply(Some(&doc), &iso).unwrap();
        a.apply(Some(&iso), &home_router()).unwrap();
        assert_eq!(conntrack(&runner).len(), 4);

        // Isolated -> Quarantine cuts
        a.apply(Some(&home_router()), &iso).unwrap();
        let n = conntrack(&runner).len();
        a.apply(Some(&iso), &doc).unwrap();
        assert_eq!(conntrack(&runner).len(), n + 2);
    }
}
