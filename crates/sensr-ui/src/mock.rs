//! In-memory [`Backend`] with a realistic small-office config, used by the dev server and the
//! tests until sensr-api's routes land.

use crate::adapt::REDACTED;
use crate::api::*;
use crate::form::{get_path, set_path};
use crate::runtime::RuntimeSection;
use futures::future::{BoxFuture, FutureExt};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Commit {
    rev: Revision,
    doc: Value,
}

struct State {
    history: Vec<Commit>,
    staged: Value,
    confirm: Option<ConfirmWindow>,
    /// Revision to return to if the confirm window lapses.
    confirm_fallback: Option<u64>,
    sessions: HashMap<String, String>,
    next_token: u64,
    clock: Box<dyn Fn() -> u64 + Send>,
    /// Host keys dropped with Forget.
    forgotten: std::collections::HashSet<String>,
    /// Port scans queued through [`Backend::portscan`] (the mock never runs them).
    scan_queue: Vec<sensr_scan::proto::QueuedJob>,
    /// Job ids cancelled through [`Backend::portscan`].
    scans_cancelled: std::collections::HashSet<u64>,
}

impl State {
    fn head(&self) -> &Commit {
        self.history.last().expect("history is never empty")
    }

    /// Lapses an expired confirm window: the box rolls back on its own.
    fn tick(&mut self) {
        if let (Some(w), Some(back)) = (&self.confirm, self.confirm_fallback)
            && (self.clock)() >= w.deadline
        {
            let doc = self.doc_at(back).cloned().unwrap_or(Value::Null);
            self.confirm = None;
            self.confirm_fallback = None;
            self.push(
                "system",
                &format!("Automatic rollback to revision {back}: change not confirmed in time"),
                doc,
            );
        }
    }

    fn doc_at(&self, id: u64) -> Option<&Value> {
        self.history.iter().find(|c| c.rev.id == id).map(|c| &c.doc)
    }

    fn push(&mut self, user: &str, message: &str, doc: Value) -> Revision {
        let rev = Revision {
            id: self.head().rev.id + 1,
            time: (self.clock)(),
            user: user.to_owned(),
            message: message.to_owned(),
        };
        self.staged = doc.clone();
        self.history.push(Commit {
            rev: rev.clone(),
            doc,
        });
        rev
    }

    fn changed(&self) -> Vec<String> {
        let head = &self.head().doc;
        let mut keys: Vec<String> = match (&self.staged, head) {
            (Value::Object(a), Value::Object(b)) => a
                .keys()
                .chain(b.keys())
                .filter(|k| a.get(*k) != b.get(*k))
                .cloned()
                .collect(),
            _ => vec![],
        };
        keys.sort();
        keys.dedup();
        keys
    }
}

/// The mock backend.
pub struct MockBackend {
    state: Mutex<State>,
    /// Accepted credentials.
    users: Vec<(String, String)>,
    /// Where the traffic and alert databases are (see [`seed_insight`]).
    insight_dir: Option<std::path::PathBuf>,
    /// The caller's privileges, checked against the built-in registry; `None` is root.
    privileges: Option<Vec<String>>,
    /// The dnstap feed reads as stale (lookups only, no minutes).
    stale_feed: bool,
    /// Where the port scan database is (see [`seed_scans`]).
    scan_dir: Option<std::path::PathBuf>,
    /// The port scanner's socket cannot be reached.
    scanner_down: bool,
    /// Every start request the daemon was sent, oldest first.
    scan_requests: std::sync::Arc<Mutex<Vec<sensr_scan::proto::StartReq>>>,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBackend {
    /// A mock seeded with [`seed`] and the user `root` / `sensr`.
    pub fn new() -> Self {
        Self::with_clock(Box::new(now))
    }

    /// Like [`MockBackend::new`] with an injectable clock (seconds since the epoch).
    pub fn with_clock(clock: Box<dyn Fn() -> u64 + Send>) -> Self {
        let t = clock();
        let doc = seed();
        let first = Commit {
            rev: Revision {
                id: 1,
                time: t.saturating_sub(86_400 * 3),
                user: "root".into(),
                message: "Imported config.xml from OPNsense 26.1".into(),
            },
            doc: doc.clone(),
        };
        let mut second_doc = doc.clone();
        set_path(
            &mut second_doc,
            "system.timezone",
            json!("Europe/Amsterdam"),
        );
        let second = Commit {
            rev: Revision {
                id: 2,
                time: t.saturating_sub(3_600 * 5),
                user: "root".into(),
                message: "system".into(),
            },
            doc: second_doc.clone(),
        };
        Self {
            state: Mutex::new(State {
                history: vec![first, second],
                staged: second_doc,
                confirm: None,
                confirm_fallback: None,
                sessions: HashMap::new(),
                next_token: 1,
                clock,
                forgotten: Default::default(),
                scan_queue: Vec::new(),
                scans_cancelled: Default::default(),
            }),
            users: vec![("root".into(), "sensr".into())],
            insight_dir: None,
            privileges: None,
            stale_feed: false,
            scan_dir: None,
            scanner_down: false,
            scan_requests: Default::default(),
        }
    }

    /// The start requests sent to the port scanner (shared: read it after the mock is
    /// moved into a handle).
    #[must_use]
    pub fn scan_requests(&self) -> std::sync::Arc<Mutex<Vec<sensr_scan::proto::StartReq>>> {
        std::sync::Arc::clone(&self.scan_requests)
    }

    /// Reads port scans from `dir` instead of the daemon's directory.
    #[must_use]
    pub fn with_scan_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.scan_dir = Some(dir.into());
        self
    }

    /// The port scanner's control socket cannot be reached.
    #[must_use]
    pub fn with_scanner_down(mut self) -> Self {
        self.scanner_down = true;
        self
    }

    /// The daemon's answer: refusals as sensr-scan gives them (public targets, bad or
    /// too large ones, a device on the config's `portscan.exclude` list without
    /// `confirm`), jobs queued in memory, and the seeded database's running range job
    /// reported running with fixed progress.
    fn scan_reply(&self, req: sensr_scan::proto::Request) -> sensr_scan::proto::Reply {
        use sensr_scan::config::Exclude;
        use sensr_scan::proto::{
            JobKind, JobProgress, QueuedJob, Refusal, Reply, Request, StatusView,
        };
        match req {
            Request::Start(r) => {
                self.scan_requests
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(r.clone());
                let exclude = self.with(|s| {
                    s.head().doc["portscan"]["exclude"]
                        .as_object()
                        .map(|m| {
                            m.values()
                                .filter_map(|e| e["target"].as_str())
                                .map(|t| match t.parse() {
                                    Ok(ip) => Exclude::Addr(ip),
                                    Err(_) => Exclude::Mac(t.to_owned()),
                                })
                                .collect()
                        })
                        .unwrap_or_default()
                });
                let cfg = sensr_scan::config::Config {
                    enabled: true,
                    auto_scan_new: false,
                    pace: sensr_scan::config::Pace::Gentle,
                    history: 10,
                    max_range: 4096,
                    exclude,
                    local: vec![],
                    router: vec![],
                };
                let parsed = sensr_scan::target::parse(&r.target).map_err(Refusal::Invalid);
                let checked = parsed
                    .clone()
                    .and_then(|t| sensr_scan::target::check(&t, &cfg, r.public_ok));
                if let Err(reason) = checked {
                    return Reply::Refused { reason };
                }
                if let Ok(sensr_scan::target::Target::One(ip)) = parsed
                    && r.kind == JobKind::Device
                    && !r.confirm
                    && cfg.excludes(ip, r.mac.as_deref())
                {
                    return Reply::Refused {
                        reason: Refusal::Excluded,
                    };
                }
                self.with(|s| {
                    if let Some(q) = s.scan_queue.iter().find(|q| q.target == r.target) {
                        return Reply::Started { job_id: q.job_id };
                    }
                    let job_id = 1_000 + s.scan_queue.len() as u64 + s.scans_cancelled.len() as u64;
                    s.scan_queue.push(QueuedJob {
                        job_id,
                        kind: r.kind,
                        target: r.target.clone(),
                        mac: r.mac.clone(),
                    });
                    Reply::Started { job_id }
                })
            }
            Request::Cancel { job_id } => self.with(|s| {
                s.scan_queue.retain(|q| q.job_id != job_id);
                s.scans_cancelled.insert(job_id);
                Reply::Ok
            }),
            Request::Status => {
                let running = self
                    .scan_dir
                    .as_ref()
                    .map(|d| d.join(sensr_scan::config::DB))
                    .filter(|p| p.exists())
                    .and_then(|p| sensr_scan::store::Store::open_ro(&p).ok())
                    .and_then(|st| st.jobs(JobKind::Range, 50).ok())
                    .and_then(|jobs| jobs.into_iter().find(|j| j.status == "running"))
                    .map(|j| u64::try_from(j.id).unwrap_or(0))
                    .filter(|id| self.with(|s| !s.scans_cancelled.contains(id)))
                    .map(|job_id| JobProgress {
                        job_id,
                        kind: JobKind::Range,
                        target: SCAN_RUNNING.to_owned(),
                        mac: None,
                        alive: Some(12),
                        address_n: 3,
                        address_total: 12,
                        tcp_done: 41_200,
                        udp_done: 310,
                    });
                Reply::Status(StatusView {
                    running,
                    queue: self.with(|s| s.scan_queue.clone()),
                })
            }
            Request::Known { .. } => Reply::Ok,
        }
    }

    /// The DNS activity feed reads as stale: hosts keep their lookups, but there are no
    /// minutes and the page shows the banner.
    #[must_use]
    pub fn with_stale_feed(mut self) -> Self {
        self.stale_feed = true;
        self
    }

    /// Reads the traffic and alert databases from `dir` instead of the daemon's directory.
    #[must_use]
    pub fn with_insight_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.insight_dir = Some(dir.into());
        self
    }

    /// Acts as a caller holding only `privileges` (names from
    /// [`sensr_auth::acl::Registry::builtin`]), e.g. `["page-all", "user-config-readonly"]`
    /// for a read-only administrator.
    #[must_use]
    pub fn with_privileges(mut self, privileges: &[&str]) -> Self {
        self.privileges = Some(privileges.iter().map(|p| (*p).to_owned()).collect());
        self
    }

    fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.tick();
        f(&mut s)
    }
}

fn ready<'a, T: Send + 'a>(v: T) -> BoxFuture<'a, T> {
    futures::future::ready(v).boxed()
}

fn diff_lines(a: &Value, b: &Value) -> Vec<DiffLine> {
    let a = serde_json::to_string_pretty(a).unwrap_or_default();
    let b = serde_json::to_string_pretty(b).unwrap_or_default();
    let diff = similar::TextDiff::from_lines(&a, &b);
    let mut out = Vec::new();
    for group in diff.grouped_ops(3) {
        if !out.is_empty() {
            out.push(DiffLine {
                kind: DiffKind::Context,
                text: "…".into(),
            });
        }
        for op in group {
            for change in diff.iter_changes(&op) {
                let kind = match change.tag() {
                    similar::ChangeTag::Equal => DiffKind::Context,
                    similar::ChangeTag::Insert => DiffKind::Added,
                    similar::ChangeTag::Delete => DiffKind::Removed,
                };
                out.push(DiffLine {
                    kind,
                    text: change.value().trim_end_matches('\n').to_owned(),
                });
            }
        }
    }
    out
}

impl Backend for MockBackend {
    fn get<'a>(&'a self, path: &'a str) -> BoxFuture<'a, ApiResult<Value>> {
        ready(self.with(|s| {
            let mut v = if path.is_empty() {
                s.staged.clone()
            } else {
                get_path(&s.staged, path).cloned().unwrap_or(Value::Null)
            };
            redact(&mut v);
            Ok(v)
        }))
    }

    fn set<'a>(&'a self, path: &'a str, value: Value) -> BoxFuture<'a, ApiResult<()>> {
        ready(self.with(|s| {
            if path.is_empty() {
                return Err(ApiError::Conflict(
                    "refusing to replace the whole document".into(),
                ));
            }
            let mut value = value;
            if let Some(old) = get_path(&s.staged, path) {
                unredact(&mut value, old);
            }
            let mut candidate = s.staged.clone();
            set_path(&mut candidate, path, value);
            validate(&candidate).map_err(ApiError::Validation)?;
            s.staged = candidate;
            Ok(())
        }))
    }

    fn pending(&self) -> BoxFuture<'_, ApiResult<Pending>> {
        ready(self.with(|s| {
            Ok(Pending {
                changed: s.changed(),
                confirm: s.confirm.clone(),
                now: (s.clock)(),
                alert: None,
            })
        }))
    }

    fn commit<'a>(
        &'a self,
        user: &'a str,
        message: &'a str,
        confirm_secs: Option<u32>,
    ) -> BoxFuture<'a, ApiResult<Revision>> {
        ready(self.with(|s| {
            if s.changed().is_empty() {
                return Err(ApiError::Conflict("nothing to apply".into()));
            }
            let before = s.head().rev.id;
            let message = if message.is_empty() {
                s.changed().join(", ")
            } else {
                message.to_owned()
            };
            let doc = s.staged.clone();
            let rev = s.push(user, &message, doc);
            match confirm_secs {
                Some(secs) => {
                    s.confirm = Some(ConfirmWindow {
                        revision: rev.id,
                        deadline: (s.clock)() + u64::from(secs),
                    });
                    s.confirm_fallback = Some(before);
                }
                None => {
                    s.confirm = None;
                    s.confirm_fallback = None;
                }
            }
            Ok(rev)
        }))
    }

    fn confirm(&self) -> BoxFuture<'_, ApiResult<()>> {
        ready(self.with(|s| {
            if s.confirm.take().is_none() {
                return Err(ApiError::Conflict("no change awaits confirmation".into()));
            }
            s.confirm_fallback = None;
            Ok(())
        }))
    }

    fn discard(&self) -> BoxFuture<'_, ApiResult<()>> {
        ready(self.with(|s| {
            s.staged = s.head().doc.clone();
            Ok(())
        }))
    }

    fn rollback<'a>(&'a self, user: &'a str, to: u64) -> BoxFuture<'a, ApiResult<Revision>> {
        ready(self.with(|s| {
            let doc = s
                .doc_at(to)
                .cloned()
                .ok_or_else(|| ApiError::NotFound(format!("revision {to}")))?;
            s.confirm = None;
            s.confirm_fallback = None;
            Ok(s.push(user, &format!("Rollback to revision {to}"), doc))
        }))
    }

    fn history(&self) -> BoxFuture<'_, ApiResult<Vec<Revision>>> {
        ready(self.with(|s| Ok(s.history.iter().rev().map(|c| c.rev.clone()).collect())))
    }

    fn diff(&self, from: u64, to: Option<u64>) -> BoxFuture<'_, ApiResult<Vec<DiffLine>>> {
        ready(self.with(|s| {
            let a = s
                .doc_at(from)
                .ok_or_else(|| ApiError::NotFound(format!("revision {from}")))?;
            let b = match to {
                Some(t) => s
                    .doc_at(t)
                    .ok_or_else(|| ApiError::NotFound(format!("revision {t}")))?,
                None => &s.staged,
            };
            Ok(diff_lines(a, b))
        }))
    }

    fn status(&self) -> BoxFuture<'_, ApiResult<SystemStatus>> {
        ready(self.with(|s| Ok(simulated_status(&s.staged, (s.clock)()))))
    }

    fn nics(&self) -> BoxFuture<'_, ApiResult<Vec<crate::api::NetworkCard>>> {
        let cards = crate::models::DEVICES
            .iter()
            .filter_map(|(name, label)| {
                let mac = label.split_once('(')?.1.trim_end_matches(')');
                mac.contains(':').then(|| crate::api::NetworkCard {
                    name: (*name).to_owned(),
                    mac: mac.to_owned(),
                    driver: Some("virtio_net".into()),
                    bus: None,
                    link: Some((true, Some(1000))),
                    assigned: None,
                })
            })
            .collect();
        ready(Ok(cards))
    }

    fn runtime(&self, section: RuntimeSection) -> BoxFuture<'_, ApiResult<Value>> {
        ready(self.with(|s| {
            let t = (s.clock)();
            Ok(match section {
                RuntimeSection::Gateways => simulated_gateways(t),
                RuntimeSection::Aliases => simulated_feeds(&s.staged, t),
                RuntimeSection::Ipv6 => simulated_pd(&s.staged, t),
                RuntimeSection::Hosts => {
                    let mut hosts: Vec<Value> = simulated_hosts(t)
                        .into_iter()
                        .filter(|h| !s.forgotten.contains(h["key"].as_str().unwrap_or_default()))
                        .collect();
                    // the applied document's owner labels and modes, as the agent reports them
                    apply_host_labels(&mut hosts, &s.head().doc);
                    // the figures come from the insight database: only for callers who may read it
                    if self.may_access("/api/v1/insight/top") {
                        for h in &mut hosts {
                            apply_mock_mix(h, self.stale_feed);
                        }
                    }
                    let modes = host_modes(&s.head().doc);
                    let mut interfaces = std::collections::BTreeSet::new();
                    for h in &mut hosts {
                        if let Some(mode) = h["mac"].as_str().and_then(|m| modes.get(m)) {
                            h["mode"] = json!(mode);
                            interfaces
                                .insert(h["interface"].as_str().unwrap_or_default().to_owned());
                        }
                    }
                    let intercept = json!({
                        "active": !interfaces.is_empty(),
                        "interfaces": interfaces,
                        "error": null,
                    });
                    json!({ "now": t, "hosts": hosts, "intercept": intercept })
                }
            })
        }))
    }

    fn host_activity(
        &self,
        mac: String,
        range: String,
        page: u32,
    ) -> BoxFuture<'_, ApiResult<HostActivityView>> {
        if !self.may_access("/api/v1/insight/top") || !self.may_access("/api/v1/hosts") {
            return ready(Err(ApiError::Unauthorized));
        }
        ready(self.with(|s| {
            if !matches!(range.as_str(), "today" | "7d") {
                return Err(ApiError::Validation(vec![FieldError::new(
                    "range",
                    "Range is today or 7d.",
                )]));
            }
            let t = (s.clock)();
            let host = simulated_hosts(t)
                .into_iter()
                .find(|h| {
                    h["mac"]
                        .as_str()
                        .is_some_and(|m| m.eq_ignore_ascii_case(&mac))
                })
                .filter(|h| !s.forgotten.contains(h["key"].as_str().unwrap_or_default()))
                .ok_or_else(|| ApiError::NotFound("no such host".into()))?;
            let mut v = simulated_activity(&host, &range, page, t, self.stale_feed);
            // the applied overrides re-attribute names, as the daemon's catalogue does
            apply_mock_overrides(&mut v, &s.head().doc);
            Ok(v)
        }))
    }

    fn forget_host(&self, key: String) -> BoxFuture<'_, ApiResult<()>> {
        ready(self.with(|s| {
            let t = (s.clock)();
            let forgettable = simulated_hosts(t).iter().any(|h| {
                h["key"] == key.as_str()
                    && !h["sources"]
                        .as_array()
                        .is_some_and(|v| v.iter().any(|x| x == "reserved"))
            });
            if forgettable && s.forgotten.insert(key) {
                Ok(())
            } else {
                Err(ApiError::Conflict("host is reserved or unknown".into()))
            }
        }))
    }

    fn set_host_label(
        &self,
        mac: String,
        kind: Option<String>,
        maker: Option<String>,
    ) -> BoxFuture<'_, ApiResult<String>> {
        if self.read_only() {
            return ready(Err(ApiError::Unauthorized));
        }
        let mac = mac.to_ascii_lowercase();
        let kind = kind.filter(|k| !k.is_empty());
        if let Some(k) = &kind
            && !crate::runtime::HOST_KINDS.iter().any(|(n, ..)| n == k)
        {
            return ready(Err(ApiError::Validation(vec![FieldError::new(
                "kind",
                format!("Unknown type {k:?}."),
            )])));
        }
        let maker = maker.map(|m| m.trim().to_owned()).filter(|m| !m.is_empty());
        let message = format!(
            "set host label {mac} → {}/{}",
            kind.as_deref().unwrap_or("auto"),
            maker.as_deref().unwrap_or("auto")
        );
        // Like the agent (and set_host_mode): commit at once unless something is staged.
        ready(self.with(|s| {
            let dirty = !s.changed().is_empty() || s.confirm.is_some();
            let mut doc = s.staged.clone();
            let root = doc
                .as_object_mut()
                .ok_or_else(|| ApiError::Backend("no document".into()))?;
            let hosts = root.entry("hosts").or_insert_with(|| json!({}));
            let entries = hosts
                .as_object_mut()
                .map(|h| h.entry("labels").or_insert_with(|| json!({})))
                .and_then(Value::as_object_mut)
                .ok_or_else(|| ApiError::Backend("no hosts section".into()))?;
            let id = entries
                .iter()
                .find(|(_, l)| l["mac"].as_str() == Some(mac.as_str()))
                .map(|(id, _)| id.clone());
            if kind.is_none() && maker.is_none() {
                if let Some(id) = id {
                    entries.remove(&id);
                }
            } else {
                let id = id
                    .unwrap_or_else(|| format!("6d1abe10-0000-4000-8000-{}", mac.replace(':', "")));
                let mut l = json!({"enabled": true, "mac": mac});
                if let Some(k) = &kind {
                    l["kind"] = json!(k);
                }
                if let Some(m) = &maker {
                    l["maker"] = json!(m);
                }
                entries.insert(id, l);
            }
            if hosts.as_object().is_some_and(|h| {
                h.get("labels")
                    .and_then(Value::as_object)
                    .is_some_and(|l| l.is_empty())
                    && h.len() == 1
            }) {
                root.remove("hosts");
            }
            validate(&doc).map_err(ApiError::Validation)?;
            if dirty {
                s.staged = doc;
                return Ok("staged".to_owned());
            }
            if doc != s.head().doc {
                s.push("root", &message, doc);
            }
            Ok("applied".to_owned())
        }))
    }

    fn set_host_mode(
        &self,
        mac: String,
        mode: Option<String>,
        remote: Option<std::net::IpAddr>,
    ) -> BoxFuture<'_, ApiResult<String>> {
        let _ = remote;
        if self.read_only() {
            return ready(Err(ApiError::Unauthorized));
        }
        let mac = mac.to_ascii_lowercase();
        let mode = match mode.as_deref() {
            None | Some("normal") => None,
            Some(m @ ("isolated" | "quarantine")) => Some(m.to_owned()),
            Some(other) => {
                return ready(Err(ApiError::Backend(format!(
                    "unknown host mode {other:?}"
                ))));
            }
        };
        if mode.as_deref() == Some("quarantine") && mac == MOCK_CLIENT_MAC {
            return ready(Err(ApiError::Conflict(
                crate::actions::SELF_QUARANTINE.to_owned(),
            )));
        }
        let message = format!(
            "set host mode {mac} → {}",
            mode.as_deref().unwrap_or("normal")
        );
        // Like the agent: commit at once unless other changes are staged or a commit
        // awaits confirmation, then stage beside them.
        ready(self.with(|s| {
            let dirty = !s.changed().is_empty() || s.confirm.is_some();
            let mut doc = s.staged.clone();
            let entries = doc
                .pointer_mut("/firewall")
                .and_then(Value::as_object_mut)
                .map(|f| f.entry("host_modes").or_insert_with(|| json!({})))
                .and_then(Value::as_object_mut)
                .ok_or_else(|| ApiError::Backend("no firewall section".into()))?;
            let id = entries
                .iter()
                .find(|(_, h)| h["mac"].as_str() == Some(mac.as_str()))
                .map(|(id, _)| id.clone());
            match (mode, id) {
                (None, Some(id)) => {
                    entries.remove(&id);
                }
                (None, None) => {}
                (Some(m), id) => {
                    let id = id.unwrap_or_else(|| {
                        format!("6d0de000-0000-4000-8000-{}", mac.replace(':', ""))
                    });
                    entries.insert(id, json!({"enabled": true, "mac": mac, "mode": m}));
                }
            }
            if dirty {
                s.staged = doc;
                return Ok("staged".to_owned());
            }
            if doc != s.head().doc {
                s.push("root", &message, doc);
            }
            Ok("applied".to_owned())
        }))
    }

    fn set_service_override(
        &self,
        suffix: String,
        service: Option<String>,
        category: Option<String>,
    ) -> BoxFuture<'_, ApiResult<String>> {
        if self.read_only() || !self.may_access("/api/v1/insight/service-override") {
            return ready(Err(ApiError::Unauthorized));
        }
        let suffix = suffix.trim().trim_end_matches('.').to_ascii_lowercase();
        let service = service.map(|s| s.trim().to_owned());
        let category = category.filter(|c| !c.is_empty());
        if let Some(c) = &category
            && !crate::runtime::CATEGORIES.iter().any(|(k, _)| k == c)
        {
            return ready(Err(ApiError::Validation(vec![FieldError::new(
                "category",
                format!("Unknown category {c:?}."),
            )])));
        }
        if service.is_some() != category.is_some() {
            return ready(Err(ApiError::Backend(
                "give both a service and a category, or neither".into(),
            )));
        }
        let message = match (&service, &category) {
            (Some(sv), Some(c)) => format!("set service override {suffix} → {sv}/{c}"),
            _ => format!("remove service override {suffix}"),
        };
        // Like the agent: commit at once unless something is staged.
        ready(self.with(|s| {
            let dirty = !s.changed().is_empty() || s.confirm.is_some();
            let mut doc = s.staged.clone();
            let root = doc
                .as_object_mut()
                .ok_or_else(|| ApiError::Backend("no document".into()))?;
            let insight = root.entry("insight").or_insert_with(|| json!({}));
            let dns = insight
                .as_object_mut()
                .map(|i| i.entry("dns").or_insert_with(|| json!({})))
                .ok_or_else(|| ApiError::Backend("no insight section".into()))?;
            let entries = dns
                .as_object_mut()
                .map(|d| d.entry("service_overrides").or_insert_with(|| json!({})))
                .and_then(Value::as_object_mut)
                .ok_or_else(|| ApiError::Backend("no dns section".into()))?;
            let id = entries
                .iter()
                .find(|(_, o)| o["suffix"].as_str() == Some(suffix.as_str()))
                .map(|(id, _)| id.clone());
            match (service, category) {
                (Some(service), Some(category)) => {
                    let id = id.unwrap_or_else(|| {
                        format!("5e7f0000-0000-4000-8000-{:012x}", entries.len() + 1)
                    });
                    entries.insert(
                        id,
                        json!({"enabled": true, "suffix": suffix, "service": service, "category": category}),
                    );
                }
                _ => {
                    if let Some(id) = id {
                        entries.remove(&id);
                    }
                }
            }
            validate(&doc).map_err(ApiError::Validation)?;
            if dirty {
                s.staged = doc;
                return Ok("staged".to_owned());
            }
            if doc != s.head().doc {
                s.push("root", &message, doc);
            }
            Ok("applied".to_owned())
        }))
    }

    fn may_access(&self, url: &str) -> bool {
        self.privileges.as_ref().is_none_or(|p| {
            sensr_auth::acl::Registry::builtin().grants(p.iter().map(String::as_str), url)
        })
    }

    fn read_only(&self) -> bool {
        self.privileges
            .as_ref()
            .is_some_and(|p| p.iter().any(|p| p == sensr_auth::acl::CONFIG_READONLY))
    }

    fn dns_stats(&self) -> BoxFuture<'_, ApiResult<DnsStats>> {
        ready(Ok(simulated_dns_stats()))
    }
    fn dhcp_leases(&self) -> BoxFuture<'_, ApiResult<Vec<DhcpLease>>> {
        ready(Ok(simulated_leases()))
    }
    fn scan_dir(&self) -> std::path::PathBuf {
        self.scan_dir.clone().unwrap_or_else(|| {
            std::env::var_os("SENSR_SCAN_DIR").map_or_else(
                || std::path::PathBuf::from(sensr_scan::config::DB_DIR),
                std::path::PathBuf::from,
            )
        })
    }
    fn portscan(
        &self,
        req: sensr_scan::proto::Request,
    ) -> BoxFuture<'_, ApiResult<sensr_scan::proto::Reply>> {
        if self.scanner_down {
            return ready(Err(ApiError::Backend(
                crate::portscan::NOT_RUNNING.to_owned(),
            )));
        }
        ready(Ok(self.scan_reply(req)))
    }
    fn insight_dir(&self) -> std::path::PathBuf {
        self.insight_dir.clone().unwrap_or_else(|| {
            std::env::var_os("SENSR_INSIGHT_DIR").map_or_else(
                || std::path::PathBuf::from(sensr_flow::config::DB_DIR),
                std::path::PathBuf::from,
            )
        })
    }
}

/// Re-attributes the domains of a mock activity page by the enabled service overrides
/// of `doc` (the longest matching suffix wins).
fn apply_mock_overrides(v: &mut HostActivityView, doc: &Value) {
    let overrides: Vec<(&str, &str, &str)> = doc
        .pointer("/insight/dns/service_overrides")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|m| m.values())
        .filter(|o| o["enabled"].as_bool().unwrap_or(true))
        .filter_map(|o| {
            Some((
                o["suffix"].as_str()?,
                o["service"].as_str()?,
                o["category"].as_str()?,
            ))
        })
        .collect();
    for d in &mut v.domains {
        let best = overrides
            .iter()
            .filter(|(sfx, ..)| {
                d.qname == *sfx
                    || d.qname
                        .strip_suffix(sfx)
                        .is_some_and(|head| head.ends_with('.'))
            })
            .max_by_key(|(sfx, ..)| sfx.len());
        if let Some((_, service, category)) = best {
            d.service = (*service).to_owned();
            d.category = (*category).to_owned();
        }
    }
}

/// Enabled host modes of `doc`: MAC → `isolated` / `quarantine`.
pub fn host_modes(doc: &Value) -> std::collections::BTreeMap<String, String> {
    doc.pointer("/firewall/host_modes")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|m| m.values())
        .filter(|h| h["enabled"].as_bool().unwrap_or(true))
        .filter_map(|h| {
            Some((
                h["mac"].as_str()?.to_ascii_lowercase(),
                h["mode"].as_str()?.to_owned(),
            ))
        })
        .collect()
}

/// Lays the enabled owner labels of `doc` over the guessed `label` of each host, as
/// the agent does: a set field wins, with confidence `high` and the reason `Set by you`
/// ahead of the guessed ones.
pub fn apply_host_labels(hosts: &mut [Value], doc: &Value) {
    let Some(labels) = doc.pointer("/hosts/labels").and_then(Value::as_object) else {
        return;
    };
    for l in labels
        .values()
        .filter(|l| l["enabled"].as_bool().unwrap_or(true))
    {
        let Some(mac) = l["mac"].as_str().map(str::to_ascii_lowercase) else {
            continue;
        };
        // an override for a host not in the inventory is kept but not rendered
        let Some(h) = hosts.iter_mut().find(|h| h["mac"] == mac.as_str()) else {
            continue;
        };
        let label = &mut h["label"];
        let mut owner = false;
        for field in ["kind", "maker"] {
            if let Some(v) = l.get(field).filter(|v| v.is_string()) {
                label[field] = v.clone();
                owner = true;
            }
        }
        if owner {
            label["confidence"] = json!("high");
            label["by"] = json!("owner");
            let mut reasons = vec![json!("Set by you")];
            if let Some(guessed) = label["reasons"].as_array() {
                reasons.extend(guessed.iter().filter(|r| *r != "Set by you").cloned());
            }
            label["reasons"] = Value::Array(reasons);
        }
    }
}

/// The MAC of the device the mock pretends every request comes from (`device-01`):
/// quarantining it is refused, as the agent refuses the caller's own device.
pub const MOCK_CLIENT_MAC: &str = "02:00:00:00:00:01";

/// The host inventory as the agent would report it at `now`, sorted the agent's way
/// (online first, then most recently seen): 25 hosts on LAN and LAN2 with one of each
/// kind the dashboard card renders. `nas` is the seeded reservation and `bench-pi` the
/// seeded active lease (see [`simulated_leases`]).
pub fn simulated_hosts(now: u64) -> Vec<Value> {
    let mut hosts = vec![
        // Reserved, leased and answering.
        json!({"key": "52:54:00:aa:bb:01", "mac": "52:54:00:aa:bb:01", "name": "nas",
               "reserved_name": "nas", "lease_hostname": "nas",
               "interface": "lan", "interface_name": "LAN", "ipv4": "192.168.1.20",
               "ipv6": ["2001:db8:42:1::20"], "sources": ["reserved", "lease", "neighbour"],
               "lease": {"state": "active", "expires": now + 3_600},
               "first_seen": now - 86_400 * 30, "last_seen": now - 5, "online": true}),
        // Dynamic lease.
        json!({"key": "b8:27:eb:7d:4e:25", "mac": "b8:27:eb:7d:4e:25", "name": "bench-pi",
               "lease_hostname": "bench-pi", "interface": "lan", "interface_name": "LAN",
               "ipv4": "192.168.1.112", "sources": ["lease", "neighbour"],
               "lease": {"state": "active", "expires": now + 1_800},
               "first_seen": now - 86_400 * 2, "last_seen": now - 12, "online": true}),
        // Only seen in the neighbour table: no name.
        json!({"key": "7c:78:b2:10:9e:41", "mac": "7c:78:b2:10:9e:41",
               "interface": "opt1", "interface_name": "LAN2", "ipv4": "192.168.72.40",
               "ipv6": ["fe80::7e78:b2ff:fe10:9e41"], "sources": ["neighbour"],
               "first_seen": now - 3_600, "last_seen": now - 20, "online": true}),
        // Gone two hours ago.
        json!({"key": "00:14:78:38:a5:fc", "mac": "00:14:78:38:a5:fc", "name": "old-router",
               "lease_hostname": "old-router", "interface": "opt1", "interface_name": "LAN2",
               "ipv4": "192.168.72.2", "sources": ["lease"],
               "lease": {"state": "expired", "expires": now - 3_600},
               "first_seen": now - 86_400 * 9, "last_seen": now - 7_200, "online": false}),
        // Reserved but never on the network.
        json!({"key": "00:1b:a9:44:02:7c", "mac": "00:1b:a9:44:02:7c", "name": "printer",
               "reserved_name": "printer", "interface": "lan", "interface_name": "LAN",
               "ipv4": "192.168.1.30", "sources": ["reserved"],
               "first_seen": now - 86_400 * 4, "online": false}),
    ];
    // Devices with DNS activity (see [`MOCK_ACTIVITY`]).
    hosts.push(
        json!({"key": KID_TABLET, "mac": KID_TABLET, "name": "kid-tablet",
           "lease_hostname": "kid-tablet", "interface": "lan", "interface_name": "LAN",
           "ipv4": "192.168.1.61", "sources": ["lease", "neighbour"],
           "lease": {"state": "active", "expires": now + 3_600},
           "first_seen": now.saturating_sub(86_400 * 60), "last_seen": now - 4, "online": true}),
    );
    hosts.push(json!({"key": LAPTOP, "mac": LAPTOP, "name": "laptop",
           "lease_hostname": "laptop", "interface": "lan", "interface_name": "LAN",
           "ipv4": "192.168.1.62", "sources": ["lease", "neighbour"],
           "lease": {"state": "active", "expires": now + 3_600},
           "first_seen": now.saturating_sub(86_400 * 200), "last_seen": now - 9, "online": true}));
    // (Eighteen of these: with the two above the inventory stays at 25 devices.)
    for i in 1..=18u64 {
        let (iface, name, net) = if i % 3 == 0 {
            ("opt1", "LAN2", "192.168.72")
        } else {
            ("lan", "LAN", "192.168.1")
        };
        hosts.push(json!({
            "key": format!("02:00:00:00:00:{i:02x}"), "mac": format!("02:00:00:00:00:{i:02x}"),
            "name": format!("device-{i:02}"), "lease_hostname": format!("device-{i:02}"),
            "interface": iface, "interface_name": name, "ipv4": format!("{net}.{}", 100 + i),
            "sources": ["lease", "neighbour"],
            "lease": {"state": "active", "expires": now + 3_600},
            "first_seen": now - 86_400, "last_seen": now - 30 - i, "online": true,
        }));
    }
    // What the agent's classifier makes of these MACs and names (only reasons it
    // produces); the printer's owner label comes from the seeded document, see
    // [`apply_host_labels`].
    for h in &mut hosts {
        let mac = h["mac"].as_str().unwrap_or_default();
        let (maker, kind, confidence, reasons): (Option<&str>, _, _, &[&str]) = match mac {
            "52:54:00:aa:bb:01" => (
                Some("QEMU/KVM"),
                "virtual",
                "high",
                &["MAC maker: QEMU/KVM"],
            ),
            "b8:27:eb:7d:4e:25" => (
                Some("Raspberry Pi"),
                "server",
                "low",
                &["MAC maker: Raspberry Pi"],
            ),
            "7c:78:b2:10:9e:41" => (Some("Wyze"), "camera", "medium", &["MAC maker: Wyze"]),
            KID_TABLET => (
                Some("Samsung"),
                "tablet",
                "medium",
                &["MAC maker: Samsung", "Host name: kid-tablet"],
            ),
            LAPTOP => (
                Some("Apple"),
                "computer",
                "medium",
                &["MAC maker: Apple", "Host name: laptop"],
            ),
            "00:14:78:38:a5:fc" => (
                Some("TP-Link"),
                "network",
                "medium",
                &["MAC maker: TP-Link"],
            ),
            "00:1b:a9:44:02:7c" => (
                Some("Brother industries"),
                "printer",
                "medium",
                &["MAC maker: Brother industries"],
            ),
            _ => (
                Some("Private MAC"),
                "phone",
                "low",
                &["Randomised address (phones, tablets and laptops do this)"],
            ),
        };
        h["label"] = json!({"maker": maker, "kind": kind, "confidence": confidence,
                            "reasons": reasons, "by": "auto"});
    }
    hosts.sort_by_key(|h| {
        (
            !h["online"].as_bool().unwrap_or(false),
            std::cmp::Reverse(h["last_seen"].as_u64()),
        )
    });
    hosts
}

const KID_TABLET: &str = "e2:5b:7a:31:90:c4";
const LAPTOP: &str = "3c:22:fb:81:4d:0a";
/// The Wyze camera of [`simulated_hosts`]: only lookups, no screen time.
const CAMERA: &str = "7c:78:b2:10:9e:41";

/// `(service, category key, minutes today)`.
type MockService = (&'static str, &'static str, u32);
/// `(name, lookups, service, category key, new, blocked)`.
type MockDomain = (&'static str, u64, &'static str, &'static str, bool, bool);

/// What a mock device did: today's minutes per service, how the other six days compare
/// (tenths of today), the hours of the day it is active (hour, share in percent), the
/// names it looked up and its 24 h lookups per category.
struct MockActivity {
    mac: &'static str,
    today: &'static [MockService],
    prior_days: [u32; 6],
    hours: &'static [(u8, u32)],
    domains: &'static [MockDomain],
    mix: &'static [(&'static str, u32)],
}

/// The seeded activity, matching the owner-approved mockup.
const MOCK_ACTIVITY: &[MockActivity] = &[
    MockActivity {
        mac: KID_TABLET,
        today: &[
            ("YouTube", "video", 82),
            ("Roblox", "games", 48),
            ("YouTube Kids", "video", 13),
            ("TikTok", "social", 14),
            ("Discord", "messaging", 6),
            ("Minecraft", "games", 4),
        ],
        prior_days: [8, 11, 6, 9, 13, 12],
        hours: &[(15, 20), (16, 25), (17, 20), (19, 20), (20, 15)],
        domains: &[
            (
                "rr3---sn-4g5e6nsz.googlevideo.com",
                412,
                "YouTube",
                "video",
                false,
                false,
            ),
            ("www.youtube.com", 188, "YouTube", "video", false, false),
            ("apis.roblox.com", 164, "Roblox", "games", false, false),
            ("gamejoin.roblox.com", 61, "Roblox", "games", false, false),
            ("v16m.tiktokcdn.com", 133, "TikTok", "social", false, false),
            ("www.tiktok.com", 57, "TikTok", "social", false, false),
            ("ads.tiktok.com", 49, "TikTok", "ads_tracking", false, true),
            (
                "kids.youtube.com",
                41,
                "YouTube Kids",
                "video",
                false,
                false,
            ),
            (
                "gateway.discord.gg",
                38,
                "Discord",
                "messaging",
                false,
                false,
            ),
            (
                "sessionserver.mojang.com",
                12,
                "Minecraft",
                "games",
                false,
                false,
            ),
            ("time.android.com", 9, "Google", "system", false, false),
            (
                "some-new-game-cdn.net",
                6,
                "some-new-game-cdn.net",
                "other",
                true,
                false,
            ),
        ],
        mix: &[
            ("video", 640),
            ("social", 190),
            ("games", 225),
            ("messaging", 38),
            ("system", 44),
            ("ads_tracking", 49),
            ("other", 6),
        ],
    },
    MockActivity {
        mac: CAMERA,
        today: &[],
        prior_days: [10; 6],
        hours: &[],
        domains: &[
            ("api.wyzecam.com", 312, "Wyze", "smart_home", false, false),
            (
                "p2p-relay-eu-3.wyze.com",
                140,
                "Wyze",
                "smart_home",
                false,
                false,
            ),
            ("time.android.com", 96, "Google", "system", false, false),
            (
                "telemetry.iot-analytics.net",
                14,
                "iot-analytics.net",
                "ads_tracking",
                false,
                true,
            ),
            (
                "firmware-cdn-07.iotvendor.net",
                3,
                "iotvendor.net",
                "other",
                true,
                false,
            ),
        ],
        mix: &[
            ("smart_home", 452),
            ("system", 96),
            ("ads_tracking", 14),
            ("other", 3),
        ],
    },
    MockActivity {
        mac: LAPTOP,
        today: &[
            ("Netflix", "video", 41),
            ("Slack", "messaging", 118),
            ("GitHub", "other", 64),
            ("Spotify", "music", 90),
            ("Khan Academy", "education", 25),
        ],
        prior_days: [9, 10, 4, 3, 8, 7],
        hours: &[
            (9, 15),
            (10, 15),
            (11, 12),
            (13, 12),
            (14, 12),
            (15, 12),
            (16, 12),
            (21, 10),
        ],
        domains: &[
            ("api.github.com", 540, "GitHub", "other", false, false),
            ("slack-edge.com", 310, "Slack", "messaging", false, false),
            ("gateway.icloud.com", 260, "Apple", "system", false, false),
            (
                "audio-ak-spotify-com.akamaized.net",
                150,
                "Spotify",
                "music",
                false,
                false,
            ),
            ("www.amazon.com", 30, "Amazon", "shopping", false, false),
            (
                "pixel.adsafeprotected.com",
                95,
                "adsafeprotected.com",
                "ads_tracking",
                false,
                true,
            ),
            (
                "www.khanacademy.org",
                25,
                "Khan Academy",
                "education",
                false,
                false,
            ),
            (
                "occ-0-1.nflxvideo.net",
                120,
                "Netflix",
                "video",
                false,
                false,
            ),
        ],
        mix: &[
            ("video", 120),
            ("social", 80),
            ("messaging", 310),
            ("music", 150),
            ("education", 25),
            ("shopping", 30),
            ("system", 260),
            ("ads_tracking", 95),
            ("other", 540),
        ],
    },
];

/// Screen-time categories of the mock (everything but system and ads).
fn mock_screen_time(category: &str) -> bool {
    !matches!(category, "system" | "ads_tracking")
}

/// Today's screen-time minutes of a mock device (`None`: no services).
fn mock_today_minutes(a: &MockActivity) -> Option<u32> {
    let m: u32 = a
        .today
        .iter()
        .filter(|s| mock_screen_time(s.1))
        .map(|s| s.2)
        .sum();
    (m > 0).then_some(m)
}

/// Sets a host row's `today_minutes` and `dns_mix` when the mock has activity for it; a
/// stale feed has no minutes.
fn apply_mock_mix(h: &mut Value, stale: bool) {
    let Some(a) = MOCK_ACTIVITY
        .iter()
        .find(|a| h["mac"].as_str() == Some(a.mac))
    else {
        return;
    };
    h["dns_mix"] = json!(a.mix);
    if !stale && let Some(m) = mock_today_minutes(a) {
        h["today_minutes"] = json!(m);
    }
}

/// The activity page of a mock device (an empty one for hosts without seeded activity).
/// `host` is its row in [`simulated_hosts`].
pub fn simulated_activity(
    host: &Value,
    range: &str,
    page: u32,
    now: u64,
    stale: bool,
) -> HostActivityView {
    const DAY: i64 = 86_400;
    let now = i64::try_from(now).unwrap_or(0);
    let today_start = now - now.rem_euclid(DAY);
    let week = range == "7d";
    let mut v = HostActivityView {
        mac: host["mac"].as_str().unwrap_or_default().to_owned(),
        name: host["name"].as_str().map(str::to_owned),
        label: serde_json::from_value(host["label"].clone()).ok(),
        ipv4: host["ipv4"].as_str().map(str::to_owned),
        ipv6: host["ipv6"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| a.as_str().map(str::to_owned))
            .collect(),
        mode: host["mode"].as_str().map(str::to_owned),
        last_seen: host["last_seen"].as_u64(),
        online: host["online"].as_bool().unwrap_or(false),
        range: range.to_owned(),
        from: if week {
            today_start - 6 * DAY
        } else {
            today_start
        },
        to: today_start + DAY,
        utc_offset: 0,
        available: true,
        feed_stale: stale,
        last_frame: stale.then_some(now - 3_600),
        page,
        per_page: 100,
        ..HostActivityView::default()
    };
    let Some(a) = MOCK_ACTIVITY.iter().find(|a| a.mac == v.mac) else {
        return v;
    };
    // `scale` tenths of today: 10 is today itself.
    let day_factors: Vec<(i64, u32)> = if week {
        std::iter::once((0, 10))
            .chain(
                a.prior_days
                    .iter()
                    .enumerate()
                    .map(|(i, f)| (-(i as i64) - 1, *f)),
            )
            .collect()
    } else {
        vec![(0, 10)]
    };
    let total_factor: u32 = day_factors.iter().map(|f| f.1).sum();
    if !stale {
        let mut services: Vec<ActivityService> = a
            .today
            .iter()
            .map(|(service, category, m)| ActivityService {
                service: (*service).to_owned(),
                category: (*category).to_owned(),
                minutes: (m * total_factor).div_ceil(10).max(1),
            })
            .collect();
        services.sort_by(|x, y| y.minutes.cmp(&x.minutes).then(x.service.cmp(&y.service)));
        let mut cats: std::collections::BTreeMap<&str, u32> = Default::default();
        for s in &services {
            *cats.entry(s.category.as_str()).or_default() += s.minutes;
        }
        let mut categories: Vec<ActivityCategory> = cats
            .iter()
            .map(|(c, m)| ActivityCategory {
                category: (*c).to_owned(),
                minutes: *m,
            })
            .collect();
        categories.sort_by(|x, y| y.minutes.cmp(&x.minutes).then(x.category.cmp(&y.category)));
        let today_total = mock_today_minutes(a).unwrap_or(0);
        for (offset, factor) in day_factors {
            let day = (today_start / DAY) + offset;
            let total = (today_total * factor).div_ceil(10);
            // shares of the day's total; the last hour takes the rounding remainder, so
            // the cells add up to the day
            let mut left = total;
            for (i, (hour, share)) in a.hours.iter().enumerate() {
                let m = if i + 1 == a.hours.len() {
                    left
                } else {
                    (total * share / 100).min(left)
                };
                left -= m;
                v.timeline.push(ActivityCell {
                    day,
                    hour: *hour,
                    minutes: m,
                });
            }
        }
        v.timeline.sort_by_key(|c| (c.day, c.hour));
        v.screen_time = v.timeline.iter().map(|c| c.minutes).sum();
        v.services = services;
        v.categories = categories;
    }
    let mut domains: Vec<ActivityDomain> = a
        .domains
        .iter()
        .map(
            |(qname, count, service, category, new, blocked)| ActivityDomain {
                qname: (*qname).to_owned(),
                count: if week { count * 6 } else { *count },
                first_seen: if *new { now - 3_600 } else { now - 86_400 * 20 },
                last_seen: now - 60,
                service: (*service).to_owned(),
                category: (*category).to_owned(),
                new: *new,
                blocked: *blocked,
            },
        )
        .collect();
    // Over a week the tablet looks up a long tail of one-off names, enough for a second
    // page of domains.
    if week && a.mac == KID_TABLET {
        domains.extend((0..MOCK_TAIL).map(|i| ActivityDomain {
            qname: format!("edge-{i:03}.tail-cdn.net"),
            count: 1,
            first_seen: now - 86_400 * 3,
            last_seen: now - 86_400 * 3,
            service: "tail-cdn.net".to_owned(),
            category: "other".to_owned(),
            new: false,
            blocked: false,
        }));
    }
    v.domains_total = u32::try_from(domains.len()).unwrap_or(u32::MAX);
    let per_page = v.per_page.max(1) as usize;
    v.domains = domains
        .into_iter()
        .skip((page as usize).saturating_mul(per_page))
        .take(per_page)
        .collect();
    v
}

/// One-off names in the tablet's 7-day domains after the seeded ones.
const MOCK_TAIL: usize = 120;

/// Leases for the seeded DHCP server on 192.168.1.0/24: a client of each kind the page
/// has to render. The first is the seeded `nas` reservation (192.168.1.20,
/// `52:54:00:aa:bb:01`), so a real recomputation of `reserved` agrees with it.
pub fn simulated_leases() -> Vec<DhcpLease> {
    let now = now();
    vec![
        DhcpLease {
            address: "192.168.1.20".into(),
            mac: Some("52:54:00:aa:bb:01".into()),
            client_id: None,
            hostname: "nas".into(),
            subnet_id: 1,
            expire: now + 3_600,
            state: LeaseState::Active,
            reserved: true,
        },
        DhcpLease {
            address: "192.168.1.112".into(),
            mac: Some("b8:27:eb:7d:4e:25".into()),
            client_id: None,
            hostname: "bench-pi".into(),
            subnet_id: 1,
            expire: now + 1_800,
            state: LeaseState::Active,
            reserved: false,
        },
        DhcpLease {
            address: "192.168.1.131".into(),
            mac: None,
            client_id: Some("01:9c:bf:0d:01:2d:96".into()),
            hostname: "phone".into(),
            subnet_id: 1,
            expire: now + 900,
            state: LeaseState::Active,
            reserved: false,
        },
        DhcpLease {
            address: "192.168.1.142".into(),
            mac: Some("50:a1:32:3d:42:24".into()),
            client_id: None,
            hostname: "laptop".into(),
            subnet_id: 1,
            expire: now - 600,
            state: LeaseState::Expired,
            reserved: false,
        },
    ]
}

/// What sensr-dns would report for the seeded blocklist policies.
pub fn simulated_dns_stats() -> DnsStats {
    let src = |url: &str, entries: u64, from_cache: bool, error: Option<&str>| DnsblSource {
        url: url.into(),
        entries,
        fetched: Some("2026-11-16T03:00:12Z".into()),
        from_cache,
        error: error.map(str::to_owned),
    };
    let hagezi = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/";
    DnsStats {
        blocklists: Some(DnsblStatus {
            updated: "2026-11-16T03:00:15Z".into(),
            duration_ms: 3_412,
            names: 412_731,
            policies: vec![
                DnsblPolicy {
                    id: "e2000000-0000-4000-a000-000000000001".into(),
                    description: "Default".into(),
                    names: 238_904,
                    sources: vec![
                        src(&format!("{hagezi}pro.txt"), 189_377, false, None),
                        src("https://small.oisd.nl/domainswild", 56_120, true, None),
                    ],
                },
                DnsblPolicy {
                    id: "e2000000-0000-4000-a000-000000000002".into(),
                    description: "Kids".into(),
                    names: 173_828,
                    sources: vec![
                        src(&format!("{hagezi}gambling.txt"), 173_827, false, None),
                        src(
                            "https://nsfw.oisd.nl/domainswild",
                            0,
                            true,
                            Some("HTTP 503 Service Unavailable; kept the cached copy"),
                        ),
                    ],
                },
            ],
        }),
        unbound: Some(UnboundCounters {
            at: "2026-11-16T09:41:00Z".into(),
            queries: 1_284_377,
            cache_hits: 1_002_115,
            nxdomain: 58_230,
            uptime_seconds: 86_400.0 * 3.0 + 7_260.0,
            log_queries: true,
            top_domains: vec![
                DnsHit {
                    name: "connectivity-check.ubuntu.com.".into(),
                    count: 18_421,
                },
                DnsHit {
                    name: "www.google.com.".into(),
                    count: 9_004,
                },
                DnsHit {
                    name: "api.github.com.".into(),
                    count: 6_213,
                },
                DnsHit {
                    name: "gateway.icloud.com.".into(),
                    count: 4_882,
                },
                DnsHit {
                    name: "time.cloudflare.com.".into(),
                    count: 3_119,
                },
            ],
            top_clients: vec![
                DnsHit {
                    name: "192.168.1.23".into(),
                    count: 31_882,
                },
                DnsHit {
                    name: "192.168.1.42".into(),
                    count: 12_440,
                },
                DnsHit {
                    name: "2001:db8:1::7".into(),
                    count: 5_019,
                },
            ],
            recent: vec![
                RecentQuery {
                    at: "2026-11-16T09:40:58Z".into(),
                    client: "192.168.1.23".into(),
                    name: "api.github.com.".into(),
                    kind: "HTTPS".into(),
                },
                RecentQuery {
                    at: "2026-11-16T09:40:55Z".into(),
                    client: "192.168.1.42".into(),
                    name: "www.google.com.".into(),
                    kind: "A".into(),
                },
                RecentQuery {
                    at: "2026-11-16T09:40:52Z".into(),
                    client: "2001:db8:1::7".into(),
                    name: "gateway.icloud.com.".into(),
                    kind: "AAAA".into(),
                },
            ],
            logged_queries: 1_204_882,
        }),
        problems: vec![],
    }
}

/// Sessions over a shared [`MockBackend`]; every session edits the same document.
pub struct MockSessions(pub std::sync::Arc<MockBackend>);

impl Sessions for MockSessions {
    fn login<'a>(
        &'a self,
        user: &'a str,
        password: &'a str,
        _otp: Option<&'a str>,
    ) -> BoxFuture<'a, ApiResult<String>> {
        let ok = self.0.users.iter().any(|(u, p)| u == user && p == password);
        ready(self.0.with(|s| {
            if !ok {
                return Err(ApiError::Unauthorized);
            }
            let token = format!(
                "mock-{}-{:x}",
                s.next_token,
                (s.clock)().wrapping_mul(2_654_435_761)
            );
            s.next_token += 1;
            s.sessions.insert(token.clone(), user.to_owned());
            Ok(token)
        }))
    }

    fn open<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Option<Session>> {
        let user = self.0.with(|s| s.sessions.get(token).cloned());
        ready(user.map(|user| Session {
            user,
            backend: self.0.clone(),
        }))
    }

    fn logout<'a>(&'a self, token: &'a str) -> BoxFuture<'a, ()> {
        self.0.with(|s| s.sessions.remove(token));
        ready(())
    }
}

/// Smooth, deterministic pseudo-load so screenshots are stable within a minute.
fn wave(t: u64, period: u64, phase: u64) -> f64 {
    let x = ((t + phase) % period) as f64 / period as f64 * std::f64::consts::TAU;
    (x.sin() + 1.0) / 2.0
}

/// The agent's gateway view (sensr-agent `GatewaysView`): the automatic WAN gateways, healthy,
/// plus a static backup that is slow, so every badge colour shows up.
fn simulated_gateways(t: u64) -> Value {
    json!({
        "gateways": [
            {"name": "WAN_DHCP", "interface": "wan", "device": "eth0", "family": "inet",
             "address": null, "monitor_address": null, "monitor": true, "default_route": true,
             "priority": 255, "weight": 1, "force_down": false, "dynamic": true,
             "next_hop": "203.0.113.1", "status": "online", "status_text": "none",
             "latency_ms": 7.5 + wave(t, 20, 3) * 2.0, "stddev_ms": 0.4 + wave(t, 15, 1) * 0.3,
             "loss_pct": 0.0, "error": null, "active_default": true},
            {"name": "WAN_DHCP6", "interface": "wan", "device": "eth0", "family": "inet6",
             "address": null, "monitor_address": null, "monitor": true, "default_route": true,
             "priority": 255, "weight": 1, "force_down": false, "dynamic": true,
             "next_hop": "fe80::1", "status": "online", "status_text": "none",
             "latency_ms": 8.1 + wave(t, 25, 1) * 2.5, "stddev_ms": 0.6, "loss_pct": 0.0,
             "error": null, "active_default": true},
            {"name": "BACKUP_GW", "interface": "wan", "device": "eth0", "family": "inet",
             "address": "198.51.100.1", "monitor_address": "198.51.100.53", "monitor": true,
             "default_route": true, "priority": 200, "weight": 1, "force_down": false,
             "dynamic": false, "next_hop": "198.51.100.1", "status": "delay", "status_text": "delay",
             "latency_ms": 480.0 + wave(t, 30, 7) * 60.0, "stddev_ms": 35.2, "loss_pct": 2.0,
             "error": null, "active_default": false}
        ],
        "groups": {"WAN_FAILOVER": ["WAN_DHCP"]},
        "switch_default": true
    })
}

/// The feed status (sensr-feeds `AliasStatus`) for every URL, URL table, GeoIP and ASN alias.
/// URLs on the reserved `.invalid` TLD fail, to show the error state.
fn simulated_feeds(doc: &Value, t: u64) -> Value {
    let aliases = get_path(doc, "firewall.aliases")
        .and_then(Value::as_object)
        .into_iter()
        .flatten();
    let list: Vec<Value> = aliases
        .filter_map(|(_, a)| {
            let kind = get_path(a, "content.type")?.as_str()?.to_owned();
            if !matches!(kind.as_str(), "url" | "url_table" | "geo_ip" | "asn") {
                return None;
            }
            let name = get_path(a, "name")?.as_str()?.to_owned();
            let content = get_path(a, "content").map(Value::to_string).unwrap_or_default();
            let failing = content.contains(".invalid");
            // Stable per alias, so the counts do not jump between refreshes.
            let entries = 200 + content.bytes().map(u64::from).sum::<u64>() % 1800;
            Some(json!({
                "name": name,
                "kind": kind,
                "entries": if failing { 0 } else { entries },
                "updated_at": (!failing).then(|| t.saturating_sub(1_800)),
                "error": failing.then_some("fetch failed: dns error: failed to lookup address information"),
                "next_check": t + 1_800,
                "attribution": (kind == "geo_ip")
                    .then_some("IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0"),
            }))
        })
        .collect();
    Value::Array(list)
}

/// Prefix delegation (sensr-agent `PdView`) for each DHCPv6 uplink with a requested prefix,
/// handing one /64 to every interface that tracks it. One older prefix is being phased out.
fn simulated_pd(doc: &Value, t: u64) -> Value {
    let ifaces = doc.get("interfaces").and_then(Value::as_object);
    let list: Vec<Value> = ifaces
        .into_iter()
        .flatten()
        .filter(|(_, i)| {
            get_path(i, "ipv6.mode").and_then(Value::as_str) == Some("dhcp6")
                && get_path(i, "ipv6.prefix_delegation_len").is_some()
        })
        .map(|(up, _)| {
            let lans: Vec<&String> = ifaces
                .into_iter()
                .flatten()
                .filter(|(_, i)| {
                    get_path(i, "ipv6.mode").and_then(Value::as_str) == Some("track")
                        && get_path(i, "ipv6.interface").and_then(Value::as_str) == Some(up)
                })
                .map(|(id, _)| id)
                .collect();
            let advertised: serde_json::Map<String, Value> = lans
                .iter()
                .enumerate()
                .map(|(n, id)| {
                    let n = n + 1;
                    (
                        (*id).clone(),
                        json!([
                            {"prefix": format!("2001:db8:42:{n:x}::/64"),
                             "preferred_lifetime_secs": 1_800, "valid_lifetime_secs": 5_400,
                             "deprecated": false},
                            {"prefix": format!("2001:db8:17:{n:x}::/64"),
                             "preferred_lifetime_secs": 0, "valid_lifetime_secs": 3_600,
                             "deprecated": true}
                        ]),
                    )
                })
                .collect();
            json!({
                "interface": up,
                "state": {
                    "current": {"prefix": "2001:db8:42::/56", "preferred_until": t + 1_800,
                                "valid_until": t + 5_400, "iaid": 1,
                                "obtained_at": t.saturating_sub(86_400), "renewed_at": t.saturating_sub(1_800)},
                    "confirmed": true,
                    "stale": [{"prefix": "2001:db8:17::/56", "stale_since": t.saturating_sub(3_600),
                               "deprecate_until": t + 3_600}],
                    "last_now": t
                },
                "advertised": advertised,
            })
        })
        .collect();
    Value::Array(list)
}

fn simulated_status(doc: &Value, t: u64) -> SystemStatus {
    let text = |p: &str, d: &str| {
        get_path(doc, p)
            .and_then(Value::as_str)
            .unwrap_or(d)
            .to_owned()
    };
    let hostname = format!(
        "{}.{}",
        text("system.hostname", "sensr"),
        text("system.domain", "internal")
    );
    let ifaces: Vec<(String, Value)> = doc
        .get("interfaces")
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    let interfaces: Vec<InterfaceStatus> = ifaces
        .iter()
        .enumerate()
        .map(|(i, (id, v))| {
            let s = |k: &str| {
                get_path(v, k)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let phase = i as u64 * 17;
            let scale = if id == "wan" { 180e6 } else { 60e6 };
            InterfaceStatus {
                name: if s("description").is_empty() {
                    id.to_uppercase()
                } else {
                    s("description")
                },
                device: s("device"),
                up: v.get("enabled").and_then(Value::as_bool).unwrap_or(true),
                speed_mbps: (!s("device").starts_with("wg")).then_some(1000),
                ipv4: match s("ipv4.mode").as_str() {
                    "static" => Some(s("ipv4.address")),
                    "dhcp" => Some("203.0.113.24/24".to_owned()),
                    _ => None,
                },
                ipv6: match s("ipv6.mode").as_str() {
                    "static" => Some(s("ipv6.address")),
                    "dhcp6" => Some("2001:db8:42::1/64".to_owned()),
                    "track" => Some("2001:db8:42:1::1/64".to_owned()),
                    _ => None,
                },
                rx_bps: (wave(t, 60, phase) * scale) as u64,
                tx_bps: (wave(t, 45, phase + 9) * scale * 0.3) as u64,
            }
        })
        .collect();
    let traffic = interfaces
        .iter()
        .enumerate()
        .filter(|(_, i)| i.up)
        .map(|(i, iface)| {
            let phase = i as u64 * 17;
            let scale = if iface.name == "WAN" { 180e6 } else { 60e6 };
            // The newest sample equals the rate the interfaces table shows.
            let samples = |period, ph, k: f64| {
                (0..60u64)
                    .map(|s| (wave(t.saturating_sub(59 - s), period, ph) * scale * k) as u64)
                    .collect()
            };
            TrafficSeries {
                name: iface.name.clone(),
                rx: samples(60, phase, 1.0),
                tx: samples(45, phase + 9, 0.3),
                ts: (0..60).map(|s| t as i64 - 59 + s).collect(),
            }
        })
        .collect();
    SystemStatus {
        hostname,
        version: concat!("sensr ", env!("CARGO_PKG_VERSION"), " (mock)").to_owned(),
        kernel: "Linux 6.18.4 (NixOS 26.05)".into(),
        cpu_model: "Intel(R) N100 (4 cores)".into(),
        uptime_secs: 3 * 86_400 + 4 * 3_600 + 12 * 60 + (t % 60),
        cpu_pct: (4.0 + wave(t, 30, 0) * 22.0) as f32,
        load: [0.42, 0.37, 0.31],
        mem_used: 1_310_000_000 + (wave(t, 90, 5) * 120_000_000.0) as u64,
        mem_total: 8_000_000_000,
        interfaces,
        gateways: Vec::new(),
        traffic,
        history: None,
    }
}

/// The range the seeded database has a scan running of.
pub const SCAN_RUNNING: &str = "192.168.72.0/24";

/// Writes a small port scan database (`scans.db`) into `dir` through sensr-scan's own
/// store: device scans finishing at `at` (Unix seconds) and a week earlier for some of
/// the mock's hosts (nas, bench-pi with a newly opened port, the camera with a partial
/// scan, the printer that did not answer, device-01 with many ports), a finished range
/// scan and a running one ([`SCAN_RUNNING`]).
///
/// # Errors
/// Any SQLite error.
pub fn seed_scans(dir: &std::path::Path, at: i64) -> Result<(), String> {
    use sensr_scan::proto::JobKind;
    use sensr_scan::types::{Ident, PortRow, PortState, Proto, ScanStatus};
    const WEEK: i64 = 7 * 86_400;
    let path = dir.join(sensr_scan::config::DB);
    let _ = std::fs::remove_file(&path);
    let s = sensr_scan::store::Store::open(&path).map_err(|e| e.to_string())?;
    let port = |proto, port, state, service: &str, ident: Ident| PortRow {
        proto,
        port,
        state,
        service: Some(service.to_owned()),
        ident,
    };
    let said = |product: Option<&str>, version: Option<&str>, title: Option<&str>| Ident {
        product: product.map(str::to_owned),
        version: version.map(str::to_owned),
        title: title.map(str::to_owned),
        ..Ident::default()
    };
    let open = PortState::Open;
    // the greeting only: no product, so the line shows no label for it
    let ssh = |v: &str| {
        port(
            Proto::Tcp,
            22,
            open,
            "ssh",
            Ident {
                banner: Some(format!("SSH-2.0-OpenSSH_{v}")),
                ..Ident::default()
            },
        )
    };
    let nas = vec![
        ssh("9.6"),
        port(
            Proto::Tcp,
            80,
            open,
            "http",
            said(Some("nginx"), None, Some("Synology")),
        ),
        port(Proto::Udp, 53, open, "domain", Ident::default()),
    ];
    let pi_then = vec![ssh("9.2p1")];
    let mut pi_now = pi_then.clone();
    pi_now.push(port(
        Proto::Tcp,
        3389,
        open,
        "ms-wbt-server",
        said(None, None, None),
    ));
    let camera = vec![
        port(
            Proto::Tcp,
            554,
            open,
            "rtsp",
            Ident {
                banner: Some("RTSP/1.0 200 OK".into()),
                ..Ident::default()
            },
        ),
        port(
            Proto::Udp,
            1900,
            PortState::OpenFiltered,
            "ssdp",
            Ident::default(),
        ),
    ];
    let busy: Vec<PortRow> = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 8080]
        .into_iter()
        .map(|p| port(Proto::Tcp, p, open, "svc", Ident::default()))
        .collect();
    type Scan<'a> = (&'a str, &'a str, i64, ScanStatus, &'a [PortRow]);
    let scans: [Scan<'_>; 7] = [
        (
            "52:54:00:aa:bb:01",
            "192.168.1.20",
            at - WEEK,
            ScanStatus::Partial,
            &nas[..1],
        ),
        (
            "52:54:00:aa:bb:01",
            "192.168.1.20",
            at,
            ScanStatus::Complete,
            &nas,
        ),
        (
            "b8:27:eb:7d:4e:25",
            "192.168.1.112",
            at - WEEK,
            ScanStatus::Complete,
            &pi_then,
        ),
        (
            "b8:27:eb:7d:4e:25",
            "192.168.1.112",
            at,
            ScanStatus::Complete,
            &pi_now,
        ),
        (
            "7c:78:b2:10:9e:41",
            "192.168.72.40",
            at,
            ScanStatus::Partial,
            &camera,
        ),
        (
            "00:1b:a9:44:02:7c",
            "192.168.1.30",
            at,
            ScanStatus::Failed,
            &[],
        ),
        (
            "02:00:00:00:00:01",
            "192.168.1.101",
            at,
            ScanStatus::Complete,
            &busy,
        ),
    ];
    let err = |e: &dyn std::fmt::Display| e.to_string();
    for (mac, ip, t, status, ports) in scans {
        let job = s
            .begin_job(JobKind::Device, ip, Some(mac), false, false)
            .map_err(|e| err(&e))?;
        let addr = ip.parse().map_err(|e| err(&e))?;
        s.write_scan(job, addr, Some(mac), t - 600, t, status, false, ports)
            .map_err(|e| err(&e))?;
        let end = if status == ScanStatus::Failed {
            "failed"
        } else {
            "complete"
        };
        s.end_job(job, end, &[]).map_err(|e| err(&e))?;
    }
    // A finished range scan of addresses outside the inventory, and a running one.
    let job = s
        .begin_job(JobKind::Range, "192.168.1.0/24", None, false, false)
        .map_err(|e| err(&e))?;
    let printer = [port(
        Proto::Tcp,
        80,
        open,
        "http",
        said(None, None, Some("Printer setup")),
    )];
    for (ip, ports) in [("192.168.1.50", &printer[..]), ("192.168.1.51", &[][..])] {
        let addr = ip.parse().map_err(|e| err(&e))?;
        s.write_scan(
            job,
            addr,
            None,
            at - 2 * 86_400,
            at - 2 * 86_400 + 300,
            ScanStatus::Complete,
            false,
            ports,
        )
        .map_err(|e| err(&e))?;
    }
    s.end_job(job, "complete", &[]).map_err(|e| err(&e))?;
    s.begin_job(JobKind::Range, SCAN_RUNNING, None, false, false)
        .map_err(|e| err(&e))?;
    Ok(())
}

/// Writes a small traffic database (`flows.db`: hosts, services, remotes and interfaces over
/// the last year, live interface samples for the last hour) and alert database (`alerts.db`)
/// into `dir`, through the same store code sensr-insight writes with. Deterministic for a
/// given `now` (Unix seconds).
pub fn seed_insight(dir: &std::path::Path, now: i64) -> sensr_flow::store::Result<()> {
    use sensr_flow::config::{ALERTS_DB, FLOWS_DB};
    use sensr_flow::eve::{Alert, AlertStore, Event};
    use sensr_flow::store::{Batch, DAY, FlowStore, HOUR, MINUTE, RowKind, SAMPLE, Totals};

    let _ = std::fs::remove_file(dir.join(FLOWS_DB));
    let _ = std::fs::remove_file(dir.join(ALERTS_DB));
    // (local host, share of the traffic, its services as (key, share)).
    type HostSpec = (&'static str, f64, &'static [(&'static str, f64)]);
    const HOSTS: &[HostSpec] = &[
        (
            "192.168.1.20",
            0.38,
            &[("tcp/443", 0.7), ("tcp/22", 0.05), ("udp/51820", 0.25)],
        ),
        (
            "192.168.1.100",
            0.27,
            &[
                ("tcp/443", 0.55),
                ("udp/443", 0.35),
                ("udp/53", 0.02),
                ("udp/3478", 0.08),
            ],
        ),
        (
            "192.168.1.101",
            0.18,
            &[("tcp/443", 0.6), ("udp/443", 0.3), ("tcp/993", 0.1)],
        ),
        ("10.10.0.2", 0.09, &[("tcp/443", 0.8), ("udp/53", 0.2)]),
        (
            "192.168.1.30",
            0.05,
            &[("tcp/25565", 0.9), ("udp/123", 0.1)],
        ),
        ("192.168.1.21", 0.03, &[("tcp/80", 0.4), ("tcp/443", 0.6)]),
    ];
    const REMOTES: &[(&str, f64)] = &[
        ("203.0.113.80", 0.31),
        ("198.51.100.7", 0.22),
        ("2001:db8:cafe::443", 0.14),
        ("192.0.2.44", 0.11),
        ("198.51.100.200", 0.08),
        ("203.0.113.9", 0.06),
        ("192.0.2.180", 0.05),
        ("198.51.100.53", 0.03),
    ];
    // Bytes per second at the busiest hour of the day.
    const PEAK: f64 = 6.0e6;
    let wave = |t: i64, period: i64, phase: i64| {
        let x = (t + phase).rem_euclid(period) as f64 / period as f64 * std::f64::consts::TAU;
        (x.sin() + 1.0) / 2.0
    };
    // Daily rhythm plus slower weekly swing, never quite idle.
    let level = |t: i64| PEAK * (0.12 + 0.6 * wave(t, DAY, -6 * HOUR) + 0.28 * wave(t, 7 * DAY, 0));
    let tot = |bytes: f64, up_share: f64| {
        let down = (bytes * (1.0 - up_share)) as u64;
        let up = (bytes * up_share) as u64;
        Totals {
            up,
            down,
            up_packets: up / 900 + 1,
            down_packets: down / 1300 + 1,
        }
    };
    let batch = |t: i64, secs: i64| {
        let total = level(t) * secs as f64;
        let mut b = Batch::default();
        for (i, (host, share, apps)) in HOSTS.iter().enumerate() {
            let jitter = 0.75 + 0.5 * wave(t, 5 * HOUR + i as i64 * 1_337, i as i64 * 977);
            let bytes = total * share * jitter;
            b.rows.insert(
                (RowKind::Host, (*host).into(), String::new()),
                tot(bytes, 0.18),
            );
            for (app, s) in *apps {
                b.rows.insert(
                    (RowKind::App, (*app).into(), (*host).into()),
                    tot(bytes * s, 0.18),
                );
            }
        }
        for (remote, share) in REMOTES {
            b.rows.insert(
                (RowKind::Remote, (*remote).into(), String::new()),
                tot(total * share, 0.18),
            );
        }
        // Forwarded traffic crosses the WAN and one inside interface.
        for (iface, share) in [("wan", 1.0), ("lan", 0.88), ("opt1", 0.12)] {
            b.add_iface(
                iface,
                (total * share * 0.82) as u64,
                (total * share * 0.18) as u64,
            );
        }
        b
    };

    let mut flows = FlowStore::open(&dir.join(FLOWS_DB))?;
    let floor = |t: i64, r: i64| t - t.rem_euclid(r);
    // Each write lands in the minute, hour and day buckets, so the oldest data goes in
    // a day at a time, then an hour at a time, and the last two hours a minute at a time:
    // every range sees complete buckets at its own resolution.
    let recent_hours = floor(now, HOUR) - 2 * HOUR;
    let hourly_from = floor(now, DAY) - 31 * DAY;
    let mut t = floor(now, DAY) - 365 * DAY;
    while t < hourly_from {
        flows.write_minute(t, &batch(t, DAY))?;
        t += DAY;
    }
    while t < recent_hours {
        flows.write_minute(t, &batch(t, HOUR))?;
        t += HOUR;
    }
    while t < floor(now, MINUTE) {
        flows.write_minute(t, &batch(t, MINUTE))?;
        t += MINUTE;
    }
    let mut t = floor(now, SAMPLE) - HOUR;
    while t < now {
        let live = (0.6 + 0.4 * wave(t, 120, 0)) * level(t) * SAMPLE as f64;
        let mut b = Batch::default();
        for (iface, share) in [("wan", 1.0), ("lan", 0.88), ("opt1", 0.12)] {
            b.add_iface(
                iface,
                (live * share * 0.82) as u64,
                (live * share * 0.18) as u64,
            );
        }
        flows.write_samples(t, &b)?;
        t += SAMPLE;
    }

    // (sid, signature, category, severity, proto, src, src port, dst, dst port, how many).
    type Spec = (
        u32,
        &'static str,
        &'static str,
        u8,
        &'static str,
        &'static str,
        u16,
        &'static str,
        u16,
        u32,
    );
    const ALERTS: &[Spec] = &[
        (
            2001219,
            "ET SCAN Potential SSH Scan",
            "Attempted Information Leak",
            2,
            "TCP",
            "198.51.100.23",
            51544,
            "203.0.113.24",
            22,
            14,
        ),
        (
            2402000,
            "ET DROP Dshield Block Listed Source group 1",
            "Misc Attack",
            2,
            "TCP",
            "192.0.2.77",
            40112,
            "203.0.113.24",
            443,
            11,
        ),
        (
            2027757,
            "ET DNS Query for .to TLD",
            "Potentially Bad Traffic",
            2,
            "UDP",
            "192.168.1.101",
            53211,
            "192.168.1.1",
            53,
            9,
        ),
        (
            2013504,
            "ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management",
            "Not Suspicious Traffic",
            3,
            "TCP",
            "192.168.1.20",
            38812,
            "198.51.100.7",
            80,
            8,
        ),
        (
            2028371,
            "ET JA3 Hash - Possible Malware - Fake Firefox Font Update",
            "Unknown Traffic",
            3,
            "TCP",
            "192.168.1.100",
            50433,
            "203.0.113.80",
            443,
            6,
        ),
        (
            2047122,
            "ET INFO Observed DNS Query to .cloud TLD",
            "Potentially Bad Traffic",
            2,
            "UDP",
            "192.168.1.100",
            61552,
            "192.168.1.1",
            53,
            5,
        ),
        (
            2210045,
            "SURICATA STREAM Packet with invalid ack",
            "Generic Protocol Command Decode",
            3,
            "TCP",
            "203.0.113.80",
            443,
            "192.168.1.101",
            50122,
            4,
        ),
        (
            2019401,
            "ET POLICY Vulnerable Java Version 1.8.x Detected",
            "Potential Corporate Privacy Violation",
            1,
            "TCP",
            "192.168.1.30",
            44210,
            "192.0.2.44",
            80,
            3,
        ),
    ];
    let mut events = Vec::new();
    let mut n = 0i64;
    for (sid, sig, cat, sev, proto, src, sport, dst, dport, count) in ALERTS {
        for k in 0..*count {
            n += 1;
            // Spread over the last day, newest a minute ago.
            let ts = (now - 60 - (n * 7_919 + i64::from(k) * 3_331) % DAY) * 1000;
            events.push(Event::Alert(Box::new(Alert {
                id: 0,
                ts,
                gid: 1,
                sid: *sid,
                rev: 3,
                signature: (*sig).into(),
                category: (*cat).into(),
                severity: *sev,
                action: "allowed".into(),
                proto: (*proto).into(),
                src_ip: (*src).into(),
                src_port: Some(*sport + k as u16),
                dest_ip: (*dst).into(),
                dest_port: Some(*dport),
                iface: if dst.starts_with("192.168.") || src.starts_with("192.168.") {
                    "eth1".into()
                } else {
                    "eth0".into()
                },
                app_proto: String::new(),
                raw: "{}".into(),
            })));
        }
    }
    let mut alerts = AlertStore::open(&dir.join(ALERTS_DB))?;
    alerts.write(&events, None)
}

/// The seeded document (sensr-schema shape): the factory default plus aliases, rules, NAT,
/// DHCP reservations, host overrides and a WireGuard road-warrior setup.
pub fn seed() -> Value {
    json!({
        "schema_version": "0.1.0",
        "system": {
            "hostname": "sensr",
            "domain": "home.arpa",
            "dns_servers": ["9.9.9.9", "2620:fe::fe"],
            "dns_allow_override": true,
            "timezone": "Etc/UTC",
            "ipv6_allow": true
        },
        "interfaces": {
            "wan": {"enabled": true, "role": "wan", "description": "WAN", "device": "eth0",
                    "ipv4": {"mode": "dhcp"}, "ipv6": {"mode": "dhcp6", "prefix_delegation_len": 64},
                    "block_private": true, "block_bogons": true},
            "lan": {"enabled": true, "role": "lan", "description": "LAN", "device": "eth1",
                    "ipv4": {"mode": "static", "address": "192.168.1.1/24"},
                    "ipv6": {"mode": "track", "interface": "wan"}},
            "opt1": {"enabled": true, "role": "other", "description": "WireGuard", "device": "wg0", "mtu": 1420,
                     "ipv4": {"mode": "static", "address": "10.10.0.1/24"}, "ipv6": {"mode": "none"}}
        },
        "hosts": {
            "labels": {
                "6d1abe10-0000-4000-8000-001ba944027c": {"enabled": true,
                    "mac": "00:1b:a9:44:02:7c", "kind": "printer", "maker": "Brother"}
            }
        },
        "firewall": {
            "host_modes": {
                "6d0de000-0000-4000-8000-020000000002": {"enabled": true,
                    "mac": "02:00:00:00:00:02", "mode": "isolated"},
                "6d0de000-0000-4000-8000-020000000005": {"enabled": true,
                    "mac": "02:00:00:00:00:05", "mode": "quarantine",
                    "description": "Unknown device"}
            },
            "aliases": {
                "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a01": {"enabled": true, "name": "rfc1918",
                    "content": {"type": "network", "entries": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]},
                    "description": "Private networks"},
                "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a02": {"enabled": true, "name": "web_ports",
                    "content": {"type": "port", "entries": ["80", "443", "8080-8090"]}, "description": "HTTP(S)"},
                "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a03": {"enabled": true, "name": "nas",
                    "content": {"type": "host", "entries": ["192.168.1.20"]}, "description": "File server"},
                "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a04": {"enabled": false, "name": "spamhaus_drop",
                    "content": {"type": "url_table", "url": "https://www.spamhaus.org/drop/drop.txt"},
                    "description": "Spamhaus DROP"},
                "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a05": {"enabled": true, "name": "admins",
                    "content": {"type": "host", "entries": ["192.168.1.10", "192.168.1.11"]},
                    "description": "Admin workstations"},
                "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a06": {"enabled": true, "name": "cameras",
                    "content": {"type": "mac", "addresses": ["b8:27:eb:7d:4e:25", "50:a1:32:3d:42:24"]},
                    "description": "Guest and IoT cameras"}
            },
            "isolation": {
                "e0000000-0000-4000-a000-000000000001": {"enabled": true, "interface": "lan",
                    "source": {"net": "alias:cameras"}, "description": "Cameras see the router only"}
            },
            "rules": {
                "00000000-0000-0000-0000-00005e450001": {"sequence": 1, "action": "pass", "interfaces": ["lan"],
                    "ip_protocol": "inet", "source": {"net": "net:lan"}, "description": "Default allow LAN to any rule"},
                "00000000-0000-0000-0000-00005e450002": {"sequence": 11, "action": "pass", "interfaces": ["lan"],
                    "ip_protocol": "inet6", "source": {"net": "net:lan"}, "description": "Default allow LAN IPv6 to any rule"},
                "a1e1c6f0-1d6e-4b1e-8f00-000000000003": {"sequence": 21, "action": "block", "interfaces": ["lan"],
                    "protocol": "tcp", "source": {"net": "net:lan"}, "destination": {"net": "any", "port": "25"},
                    "log": true, "description": "No direct SMTP"},
                "a1e1c6f0-1d6e-4b1e-8f00-000000000004": {"sequence": 31, "action": "pass", "interfaces": ["wan"],
                    "protocol": "udp", "destination": {"net": "addr:wan", "port": "51820"}, "description": "WireGuard"},
                "a1e1c6f0-1d6e-4b1e-8f00-000000000005": {"sequence": 41, "action": "pass", "interfaces": ["wan"],
                    "protocol": "tcp", "destination": {"net": "alias:nas", "port": "alias:web_ports"},
                    "description": "NAT: web to NAS"},
                "a1e1c6f0-1d6e-4b1e-8f00-000000000006": {"sequence": 51, "action": "pass", "interfaces": ["opt1"],
                    "source": {"net": "10.10.0.0/24"}, "destination": {"net": "alias:rfc1918"},
                    "description": "Road warriors to LAN"},
                "a1e1c6f0-1d6e-4b1e-8f00-000000000007": {"enabled": false, "sequence": 61, "action": "block",
                    "quick": false, "interfaces": [], "ip_protocol": "inet46",
                    "source": {"net": "alias:spamhaus_drop"}, "log": true, "description": "Drop listed networks"}
            }
        },
        "nat": {
            "outbound": {
                "mode": "hybrid",
                "rules": {
                    "c0ffee00-0000-4000-a000-000000000001": {"interface": "wan", "source": {"net": "10.10.0.0/24"},
                        "description": "WireGuard clients out"}
                }
            },
            "port_forwards": {
                "d0d0d0d0-0000-4000-a000-000000000001": {"interfaces": ["wan"], "protocol": "tcp",
                    "destination": {"net": "addr:wan", "port": "443"}, "target": "192.168.1.20", "target_port": "443",
                    "description": "NAS HTTPS"},
                "d0d0d0d0-0000-4000-a000-000000000002": {"enabled": false, "sequence": 2, "interfaces": ["wan"],
                    "protocol": "tcp/udp", "destination": {"net": "addr:wan", "port": "25565"},
                    "target": "192.168.1.30", "description": "Game server"}
            }
        },
        "dhcpv4": {
            "enabled": true,
            "interfaces": ["lan"],
            "subnets": {
                "00000000-0000-0000-0000-00005e450003": {"subnet": "192.168.1.0/24", "interface": "lan",
                    "pools": ["192.168.1.100-192.168.1.199", "192.168.1.220-192.168.1.239"],
                    "options": {"domain_name": "home.arpa"}}
            },
            "reservations": {
                "f0000000-0000-4000-a000-000000000001": {"subnet": "00000000-0000-0000-0000-00005e450003",
                    "client": {"hw_address": "52:54:00:aa:bb:01"}, "ip_address": "192.168.1.20",
                    "hostname": "nas", "description": "File server"},
                "f0000000-0000-4000-a000-000000000002": {"subnet": "00000000-0000-0000-0000-00005e450003",
                    "client": {"hw_address": "52:54:00:aa:bb:02"}, "ip_address": "192.168.1.21",
                    "hostname": "printer", "description": "Office printer"}
            }
        },
        "dns": {
            "enabled": true, "port": "53", "dnssec": true, "register_dhcp_leases": true,
            "register_dhcp_static": true, "local_zone_type": "transparent",
            "host_overrides": {
                "b0000000-0000-4000-a000-000000000001": {"hostname": "nas", "domain": "home.arpa",
                    "record": {"rr": "A", "address": "192.168.1.20"}, "description": "NAS"},
                "b0000000-0000-4000-a000-000000000002": {"hostname": "*", "domain": "lab.home.arpa",
                    "record": {"rr": "A", "address": "192.168.1.40"}, "ttl": 300, "ptr": false,
                    "description": "Lab wildcard"}
            },
            "statistics": true,
            "forwarding": {
                "servers": {
                    "e0000000-0000-4000-a000-000000000001": {"domain": "corp.example", "address": "10.20.0.53",
                        "description": "Office DNS"},
                    "e0000000-0000-4000-a000-000000000002": {"address": "9.9.9.9", "port": "853",
                        "tls_name": "dns.quad9.net", "description": "Quad9 over TLS"}
                }
            },
            "access": {
                "default_action": "allow",
                "lists": {
                    "e1000000-0000-4000-a000-000000000001": {"name": "road_warriors", "action": "allow",
                        "networks": ["10.10.0.0/24"], "description": "WireGuard clients"},
                    "e1000000-0000-4000-a000-000000000002": {"enabled": false, "name": "lab", "action": "refuse",
                        "networks": ["192.168.50.0/24"]}
                }
            },
            "tuning": {"prefetch": true, "msg_cache_size": "8m", "log_verbosity": 2},
            "blocklists": {
                "e2000000-0000-4000-a000-000000000001": {"description": "Default",
                    "lists": ["hagezi-pro", "oisd-small"], "allow": ["*.microsoft.com"],
                    "refresh_seconds": 72000},
                "e2000000-0000-4000-a000-000000000002": {"description": "Kids",
                    "lists": ["hagezi-gambling", "oisd-nsfw"], "block_subtrees": ["tiktok.com"],
                    "source_nets": ["192.168.1.128/25"], "answer": {"mode": "nxdomain"},
                    "refresh_seconds": 86400}
            }
        },
        "wireguard": {
            "enabled": true,
            "servers": {
                "90000000-0000-4000-a000-000000000001": {"name": "wg0", "instance": 0,
                    "public_key": "pf9Z1Xx2TJUy0rzvQFkWsWTfNszIHhUyU0PazG/IQyc=",
                    "private_key": "RFdSBMFhe6alos1D62jnPf1MOxQSfI4eWjqrjHdkgtI=",
                    "listen_port": "51820", "mtu": 1420, "tunnel_addresses": ["10.10.0.1/24"],
                    "peers": ["91000000-0000-4000-a000-000000000001", "91000000-0000-4000-a000-000000000002"]}
            },
            "peers": {
                "91000000-0000-4000-a000-000000000001": {"name": "laptop",
                    "public_key": "SgF/lLNYzsAh3k/TS8exPiMtwhP8i24yYk9rXVhvOI4=",
                    "allowed_ips": ["10.10.0.2/32"], "keepalive": 25},
                "91000000-0000-4000-a000-000000000002": {"name": "phone",
                    "public_key": "QI/cUp+b5XkhrNjwkflNQD3lZZ1tzY6kr9E3dj+KyDw=",
                    "allowed_ips": ["10.10.0.3/32"], "keepalive": 25}
            }
        },
        "portscan": {
            "exclude": {
                "5c000000-0000-4000-a000-000000000001": {"target": "00:14:78:38:a5:fc",
                    "description": "Old router: reboots when scanned"}
            }
        },
        "ids": {
            "enabled": true,
            "interfaces": ["wan"],
            "suppressions": {
                "e1000000-0000-4000-a000-000000000001": {"gid": 1, "sid": 2013504,
                    "description": "APT updates from the NAS"},
                "e1000000-0000-4000-a000-000000000002": {"enabled": false, "gid": 1, "sid": 2027757,
                    "track": {"by": "src", "net": "192.168.1.101/32"}, "description": "Laptop .to lookups"}
            },
            "user_rules": {
                "e2000000-0000-4000-a000-000000000001": {"source": "192.168.1.30/32",
                    "action": "pass", "bypass": true, "description": "Game server: no inspection"}
            }
        }
    })
}

/// Field names whose values are secrets (sensr-schema `Secret<T>`).
const SECRET_KEYS: &[&str] = &[
    "private_key",
    "preshared_key",
    "password_hash",
    "secret_hash",
];

/// Replaces secrets with [`REDACTED`], as the API does in responses.
fn redact(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if SECRET_KEYS.contains(&k.as_str()) && x.is_string() {
                    *x = Value::String(REDACTED.into());
                } else {
                    redact(x);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(redact),
        _ => {}
    }
}

/// Puts stored secrets back where a write sent [`REDACTED`] ("unchanged").
fn unredact(new: &mut Value, old: &Value) {
    match new {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if x.as_str() == Some(REDACTED) {
                    if let Some(prev) = old.get(k) {
                        *x = prev.clone();
                    }
                } else if let Some(prev) = old.get(k) {
                    unredact(x, prev);
                }
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter_mut().enumerate() {
                if let Some(prev) = old.get(i) {
                    unredact(x, prev);
                }
            }
        }
        _ => {}
    }
}

/// Validates a whole document the way the agent does: typed parse, then cross-checks.
pub fn validate(doc: &Value) -> Result<(), Vec<FieldError>> {
    let typed: sensr_schema::Document = serde_path_to_error::deserialize(doc).map_err(|e| {
        let path = e.path().to_string();
        let msg = e.inner().to_string();
        vec![FieldError::new(
            if path == "." { String::new() } else { path },
            msg,
        )]
    })?;
    let v = typed.validate();
    if v.is_ok() {
        return Ok(());
    }
    Err(v
        .iter()
        .flat_map(|(p, errs)| {
            errs.iter()
                .map(move |e| FieldError::new(p.to_string(), e.message.clone()))
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn activity(mock: &MockBackend, mac: &str, range: &str) -> ApiResult<HostActivityView> {
        block(mock.host_activity(mac.into(), range.into(), 0))
    }

    #[test]
    fn mock_service_override_reattributes_domains() {
        let m = MockBackend::new();
        let set = |sv: Option<&str>, c: Option<&str>| {
            block(m.set_service_override(
                " Some-New-Game-CDN.net ".into(),
                sv.map(Into::into),
                c.map(Into::into),
            ))
        };
        assert_eq!(set(Some("Fortnite"), Some("games")).unwrap(), "applied");
        let v = activity(&m, KID_TABLET, "today").unwrap();
        let d = v
            .domains
            .iter()
            .find(|d| d.qname == "some-new-game-cdn.net")
            .unwrap();
        assert_eq!(
            (d.service.as_str(), d.category.as_str()),
            ("Fortnite", "games")
        );
        assert!(matches!(
            set(Some("X"), Some("toaster")),
            Err(ApiError::Validation(_))
        ));
        assert_eq!(set(None, None).unwrap(), "applied");
        let v = activity(&m, KID_TABLET, "today").unwrap();
        assert!(v.domains.iter().all(|d| d.service != "Fortnite"));
    }

    #[test]
    fn mock_kid_tablet_matches_the_mockup() {
        let m = MockBackend::new();
        let v = activity(&m, KID_TABLET, "today").unwrap();
        let mins = |svc: &str| {
            v.services
                .iter()
                .find(|s| s.service == svc)
                .unwrap()
                .minutes
        };
        assert_eq!(
            [
                "YouTube",
                "Roblox",
                "YouTube Kids",
                "TikTok",
                "Discord",
                "Minecraft"
            ]
            .map(mins),
            [82, 48, 13, 14, 6, 4]
        );
        assert_eq!(v.screen_time, 167);
        assert_eq!(v.timeline.iter().map(|c| c.minutes).sum::<u32>(), 167);
        assert_eq!(v.categories[0].category, "video");
        let d = |n: &str| v.domains.iter().find(|d| d.qname == n).unwrap();
        assert!(d("ads.tiktok.com").blocked);
        assert!(d("some-new-game-cdn.net").new);
        assert!(!v.feed_stale && v.available);
        let week = activity(&m, KID_TABLET, "7d").unwrap();
        assert!(week.screen_time > 4 * v.screen_time);
        let days: std::collections::BTreeSet<_> = week.timeline.iter().map(|c| c.day).collect();
        assert_eq!(days.len(), 7);
        assert!(week.timeline.iter().any(|c| c.hour == 16));
        assert_eq!(week.page, 0);
        assert_eq!(week.domains.len(), 100);
        assert_eq!(week.domains_total, 132);
        let second = block(m.host_activity(KID_TABLET.into(), "7d".into(), 1)).unwrap();
        assert_eq!((second.page, second.domains.len()), (1, 32));
        assert!(
            second
                .domains
                .iter()
                .all(|d| d.qname.ends_with(".tail-cdn.net"))
        );
        assert!(
            block(m.host_activity(KID_TABLET.into(), "7d".into(), 2))
                .unwrap()
                .domains
                .is_empty()
        );
        assert_eq!(v.domains_total, 12);
    }

    #[test]
    fn mock_camera_has_only_domains() {
        let m = MockBackend::new();
        let v = activity(&m, CAMERA, "today").unwrap();
        assert!(v.services.is_empty() && v.timeline.is_empty() && v.screen_time == 0);
        assert!(v.domains.iter().any(|d| d.blocked));
        assert!(v.domains.iter().any(|d| d.new));
        assert!(v.domains.iter().any(|d| d.category == "smart_home"));
    }

    #[test]
    fn mock_stale_feed_keeps_lookups_but_no_minutes() {
        let m = MockBackend::new().with_stale_feed();
        let v = activity(&m, KID_TABLET, "today").unwrap();
        assert!(v.feed_stale && v.last_frame.is_some());
        assert!(v.services.is_empty() && v.timeline.is_empty());
        assert!(!v.domains.is_empty());
        let hosts: crate::runtime::HostList =
            crate::runtime::parse(block(m.runtime(RuntimeSection::Hosts)).unwrap());
        let kid = hosts
            .hosts
            .iter()
            .find(|h| h.mac.as_deref() == Some(KID_TABLET))
            .unwrap();
        assert_eq!(kid.today_minutes, None);
        assert!(!kid.dns_mix.is_empty());
    }

    #[test]
    fn mock_activity_errors_and_hosts_rows() {
        let m = MockBackend::new();
        assert!(matches!(
            activity(&m, KID_TABLET, "1y"),
            Err(ApiError::Validation(_))
        ));
        assert!(matches!(
            activity(&m, "00:00:00:00:00:00", "today"),
            Err(ApiError::NotFound(_))
        ));
        let hosts: crate::runtime::HostList =
            crate::runtime::parse(block(m.runtime(RuntimeSection::Hosts)).unwrap());
        let row = |mac: &str| {
            hosts
                .hosts
                .iter()
                .find(|h| h.mac.as_deref() == Some(mac))
                .unwrap()
        };
        assert_eq!(row(KID_TABLET).today_minutes, Some(167));
        assert_eq!(row(KID_TABLET).dns_mix[0], ("video".to_owned(), 640));
        assert_eq!(row(CAMERA).today_minutes, None);
        assert!(row(CAMERA).dns_mix.iter().any(|c| c.0 == "smart_home"));
        assert!(row(LAPTOP).dns_mix.len() >= 8, "a mixed day");
        assert!(row("02:00:00:00:00:01").dns_mix.is_empty());
        // the laptop's hours add up to its headline, for every range
        for range in ["today", "7d"] {
            let l = activity(&m, LAPTOP, range).unwrap();
            assert_eq!(
                l.timeline.iter().map(|c| c.minutes).sum::<u32>(),
                l.screen_time
            );
            assert!(l.timeline.iter().all(|c| c.minutes <= 60));
        }
        assert_eq!(activity(&m, LAPTOP, "today").unwrap().screen_time, 338);
        assert_eq!(row(LAPTOP).today_minutes, Some(338));
        // without the insight privilege the card gets no figures and the page is refused
        let blind = MockBackend::new().with_privileges(&["page-sensr-hosts"]);
        let hosts: crate::runtime::HostList =
            crate::runtime::parse(block(blind.runtime(RuntimeSection::Hosts)).unwrap());
        assert!(
            hosts
                .hosts
                .iter()
                .all(|h| h.dns_mix.is_empty() && h.today_minutes.is_none())
        );
        assert!(matches!(
            activity(&blind, KID_TABLET, "today"),
            Err(ApiError::Unauthorized)
        ));
        // every mix key is a known category
        for h in &hosts.hosts {
            for (k, _) in &h.dns_mix {
                assert!(crate::runtime::CATEGORIES.iter().any(|c| c.0 == k), "{k}");
            }
        }
    }

    fn block<T>(f: BoxFuture<'_, T>) -> T {
        futures::executor::block_on(f)
    }

    fn mock_with_clock() -> (MockBackend, Arc<AtomicU64>) {
        let t = Arc::new(AtomicU64::new(1_000_000));
        let c = t.clone();
        (
            MockBackend::with_clock(Box::new(move || c.load(Ordering::SeqCst))),
            t,
        )
    }

    #[test]
    fn set_stages_and_commit_applies() {
        let (m, _) = mock_with_clock();
        block(m.set("system.hostname", json!("fw"))).unwrap();
        assert_eq!(block(m.pending()).unwrap().changed, ["system"]);
        let rev = block(m.commit("root", "rename", None)).unwrap();
        assert_eq!(rev.id, 3);
        assert!(!block(m.pending()).unwrap().dirty());
        assert_eq!(block(m.get("system.hostname")).unwrap(), json!("fw"));
        let diff = block(m.diff(2, Some(3))).unwrap();
        assert!(
            diff.iter()
                .any(|l| l.kind == DiffKind::Added && l.text.contains("\"fw\""))
        );
        assert!(
            diff.iter()
                .any(|l| l.kind == DiffKind::Removed && l.text.contains("\"sensr\""))
        );
    }

    #[test]
    fn unconfirmed_commit_rolls_back_after_deadline() {
        let (m, t) = mock_with_clock();
        block(m.set("system.hostname", json!("fw"))).unwrap();
        block(m.commit("root", "risky", Some(60))).unwrap();
        assert!(block(m.pending()).unwrap().confirm.is_some());
        t.fetch_add(61, Ordering::SeqCst);
        let p = block(m.pending()).unwrap();
        assert!(p.confirm.is_none());
        assert_eq!(block(m.get("system.hostname")).unwrap(), json!("sensr"));
        assert!(
            block(m.history()).unwrap()[0]
                .message
                .starts_with("Automatic rollback")
        );
    }

    #[test]
    fn confirmed_commit_stays() {
        let (m, t) = mock_with_clock();
        block(m.set("system.hostname", json!("fw"))).unwrap();
        block(m.commit("root", "risky", Some(60))).unwrap();
        block(m.confirm()).unwrap();
        t.fetch_add(120, Ordering::SeqCst);
        assert_eq!(block(m.get("system.hostname")).unwrap(), json!("fw"));
        assert_eq!(
            block(m.confirm()),
            Err(ApiError::Conflict("no change awaits confirmation".into()))
        );
    }

    #[test]
    fn rollback_and_discard() {
        let (m, _) = mock_with_clock();
        let r = block(m.rollback("root", 1)).unwrap();
        assert_eq!(r.id, 3);
        assert_eq!(block(m.get("system.timezone")).unwrap(), json!("Etc/UTC"));
        block(m.set("system.timezone", json!("Asia/Tokyo"))).unwrap();
        block(m.discard()).unwrap();
        assert!(!block(m.pending()).unwrap().dirty());
        assert!(matches!(
            block(m.rollback("root", 99)),
            Err(ApiError::NotFound(_))
        ));
    }

    #[test]
    fn sessions() {
        let (m, _) = mock_with_clock();
        let m = MockSessions(Arc::new(m));
        assert_eq!(
            block(m.login("root", "nope", None)),
            Err(ApiError::Unauthorized)
        );
        let tok = block(m.login("root", "sensr", None)).unwrap();
        assert_eq!(block(m.open(&tok)).map(|s| s.user).as_deref(), Some("root"));
        block(m.logout(&tok));
        assert!(block(m.open(&tok)).is_none());
    }

    #[test]
    fn seed_is_a_valid_schema_document() {
        validate(&seed()).unwrap();
    }

    #[test]
    fn invalid_writes_are_rejected_with_schema_paths() {
        let (m, _) = mock_with_clock();
        let err = block(m.set("system.hostname", json!("not a host"))).unwrap_err();
        let ApiError::Validation(errs) = err else {
            panic!("{err:?}")
        };
        assert_eq!(errs[0].path, "system.hostname", "{errs:?}");
        assert!(!block(m.pending()).unwrap().dirty(), "nothing staged");
    }

    #[test]
    fn secrets_are_redacted_and_kept() {
        let (m, _) = mock_with_clock();
        let servers = block(m.get("wireguard.servers")).unwrap();
        let (k, srv) = servers.as_object().unwrap().iter().next().unwrap();
        assert_eq!(srv["private_key"], REDACTED);
        let mut changed = srv.clone();
        changed["mtu"] = json!(1400);
        block(m.set(&format!("wireguard.servers.{k}"), changed)).unwrap();
        let state = m.state.lock().unwrap();
        let stored =
            get_path(&state.staged, &format!("wireguard.servers.{k}.private_key")).unwrap();
        assert_ne!(stored, REDACTED, "a redacted write keeps the stored secret");
    }

    #[test]
    fn seed_rows_round_trip_through_views() {
        use crate::models::*;
        let doc = seed();
        for g in [
            GridId::Assignments,
            GridId::Aliases,
            GridId::FilterRules,
            GridId::SourceNat,
            GridId::PortForwards,
            GridId::DhcpRanges,
            GridId::StaticMaps,
            GridId::HostOverrides,
            GridId::AccessLists,
            GridId::Forwarders,
            GridId::Blocklists,
            GridId::WgInstances,
            GridId::WgPeers,
            GridId::IdsSuppressions,
            GridId::IdsUserRules,
            GridId::PortscanExcludes,
        ] {
            let scope = g.scope(&None);
            let store = crate::adapt::store(g, &scope, &doc);
            let (crate::adapt::Store::Map(p) | crate::adapt::Store::Array(p)) = &store;
            let items: Vec<Value> = match get_path(&doc, p).unwrap() {
                Value::Object(m) => m.values().cloned().collect(),
                Value::Array(a) => a.clone(),
                _ => unreachable!(),
            };
            assert!(!items.is_empty(), "{g:?}");
            for item in items
                .iter()
                .filter(|i| crate::adapt::in_scope(g, &scope, &doc, i))
            {
                let mut view = crate::adapt::to_view(g, &doc, item);
                view[g.meta().key] = json!("existing");
                let inputs = crate::form::to_inputs(g.meta().fields, &view);
                let parsed = g
                    .apply(&view, &inputs)
                    .unwrap_or_else(|e| panic!("{g:?} {view}: {e:?}"));
                let back = crate::adapt::from_view(g, &doc, &scope, Some(item), &parsed);
                // Unchanged views write back the same item (secrets come back as "keep").
                let mut expect = item.clone();
                redact(&mut expect);
                let mut got = back.clone();
                redact(&mut got);
                assert_eq!(strip_defaults(&got), strip_defaults(&expect), "{g:?}");
            }
        }
        for f in [
            FormId::SystemGeneral,
            FormId::Interface,
            FormId::SourceNatMode,
            FormId::DhcpSettings,
            FormId::UnboundGeneral,
            FormId::UnboundAdvanced,
            FormId::UnboundServeExpired,
            FormId::UnboundLogging,
            FormId::UnboundCache,
            FormId::UnboundAclDefault,
            FormId::UnboundForwarding,
            FormId::IdsSettings,
            FormId::PortscanSettings,
        ] {
            let scope = f.scope(&None);
            let view = crate::adapt::form_to_view(f, &doc, &scope).unwrap();
            let parsed = f
                .apply(&view, &crate::form::to_inputs(f.fields(), &view))
                .unwrap_or_else(|e| panic!("{f:?}: {e:?}"));
            let mut d = doc.clone();
            crate::adapt::form_from_view(f, &mut d, &scope, &parsed).unwrap();
            validate(&d).unwrap_or_else(|e| panic!("{f:?}: {e:?}"));
        }
    }

    /// Drops keys whose value equals the schema default the view writes explicitly.
    fn strip_defaults(v: &Value) -> Value {
        let defaults = [
            ("enabled", json!(true)),
            ("not", json!(false)),
            ("quick", json!(true)),
            ("log", json!(false)),
            ("no_nat", json!(false)),
            ("disable_routes", json!(false)),
            ("ptr", json!(true)),
            ("block_private", json!(false)),
            ("block_bogons", json!(false)),
            ("tunnel_addresses", json!([])),
            ("dns", json!([])),
            ("direction", json!("")),
            ("direction", json!("in")),
            ("ip_protocol", json!("inet")),
            ("protocol", json!("any")),
            ("action", json!("pass")),
            ("ip_protocol", json!("")),
            ("protocol", json!("")),
            ("action", json!("")),
        ];
        match v {
            Value::Object(m) => Value::Object(
                m.iter()
                    .filter(|(k, x)| !defaults.iter().any(|(dk, dv)| dk == k && dv == *x))
                    .filter(|(k, x)| !(k.as_str() == "net" && x.as_str() == Some("any")))
                    .map(|(k, x)| (k.clone(), strip_defaults(x)))
                    .filter(|(_, x)| x.as_object().is_none_or(|o| !o.is_empty()))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    #[test]
    fn status_reflects_config() {
        let (m, _) = mock_with_clock();
        let s = block(m.status()).unwrap();
        assert_eq!(s.hostname, "sensr.home.arpa");
        assert_eq!(s.interfaces.len(), 3);
        assert_eq!(s.interfaces[1].ipv4.as_deref(), Some("192.168.1.1/24"));
        assert_eq!(s.traffic[0].rx.len(), 60);
    }

    #[test]
    fn runtime_views_parse_into_the_ui_types() {
        use crate::runtime::{AliasFeed, GatewayState, GatewaysView, PdUplink, parse};
        let (m, _) = mock_with_clock();
        let gw: GatewaysView = parse(block(m.runtime(RuntimeSection::Gateways)).unwrap());
        assert_eq!(gw.gateways.len(), 3);
        assert!(gw.gateways.iter().any(|g| g.status == GatewayState::Delay));
        assert_eq!(gw.groups["WAN_FAILOVER"], ["WAN_DHCP"]);

        // Feed aliases only, and the GeoIP one carries the DB-IP attribution.
        block(m.set(
            "firewall.aliases.6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a99",
            json!({"enabled": true, "name": "geo", "content": {"type": "geo_ip", "countries": ["NL"]}}),
        ))
        .unwrap();
        let feeds: Vec<AliasFeed> = parse(block(m.runtime(RuntimeSection::Aliases)).unwrap());
        let names: Vec<&str> = feeds.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(names.contains(&"spamhaus_drop") && names.contains(&"geo"));
        let geo = feeds.iter().find(|f| f.name == "geo").unwrap();
        assert!(geo.attribution.as_deref().unwrap().contains("DB-IP"));
        assert!(geo.entries > 0 && geo.updated_at.is_some());

        let pd: Vec<PdUplink> = parse(block(m.runtime(RuntimeSection::Ipv6)).unwrap());
        assert_eq!(pd.len(), 1);
        assert_eq!(pd[0].interface, "wan");
        assert_eq!(pd[0].advertised["lan"].len(), 2);
        assert!(pd[0].advertised["lan"].iter().any(|a| a.deprecated));
    }
}
