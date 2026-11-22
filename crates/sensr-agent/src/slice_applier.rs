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
use sensr_feeds::{Feeds, SystemResolver};
use sensr_ipc::{FileDiff, PlanView, ServiceAction, ServiceChange, ValidationIssue};
use sensr_rules::document::Runtime;
use sensr_rules::ir::IfAddr;
use sensr_schema::Document;
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
            let neighbours = move || {
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
            };
            a.feeds = Some(Arc::new(Feeds::new(
                dir,
                Arc::new(HttpFetcher::default()),
                Arc::new(SystemResolver),
                Arc::new(neighbours),
            )));
        }
        Ok(a)
    }

    /// With an explicit feed store (tests).
    pub fn with_feeds(mut self, feeds: Arc<Feeds>) -> SliceApplier {
        self.feeds = Some(feeds);
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
        })
    }

    /// Feeds refresh on their own schedules; changed aliases reach the
    /// ruleset as one set transaction each tick, never as a reload.
    fn start_refresher(&mut self) {
        let (Some(feeds), false) = (self.feeds.clone(), self.refreshing) else {
            return;
        };
        if self.watch.is_none() {
            // tests drive refresh() themselves
            return;
        }
        self.refreshing = true;
        let engine = Arc::clone(&self.engine);
        let applied = Arc::clone(&self.applied);
        std::thread::Builder::new()
            .name("sensr-alias-feeds".into())
            .spawn(move || {
                loop {
                    let doc = lock(&applied).as_ref().map(|(d, _)| d.clone());
                    if let Some(doc) = doc {
                        refresh_once(&feeds, &engine, &doc, unix_now());
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

    fn apply(&mut self, _running: Option<&Document>, next: &Document) -> Result<(), ApplyError> {
        let doc = document(next)?.clone();
        let mut engine = self.engine();
        let (p, addrs) = prepare(&engine, &doc, self.feeds.as_deref()).map_err(rejected)?;
        let rendered = p.aliases.clone();
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
        drop(engine);
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
}
