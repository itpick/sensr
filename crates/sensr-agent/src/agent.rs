//! The agent core: candidate/commit/apply, commit-confirm with automatic
//! rollback, peer trust, and the [`Handler`] that serves `sensr-ipc`.
//!
//! Model (docs/PLAN.md §2.4):
//! - `set`/`delete`/`load` edit one shared *candidate* (head + staged edits).
//! - `commit` plans the candidate (every checker runs; a rejection stores
//!   nothing), stores it as a new revision, then applies it. With
//!   `confirm_secs` the apply is provisional: unless `confirm` arrives in
//!   time, the last confirmed revision is committed again and re-applied.
//! - `rollback` commits an earlier revision's document as a new revision, so
//!   history only grows (03 §4.8 "restore then commit yields a new revision").
//! - The applied revision and any pending confirm are persisted; an agent
//!   that starts with a confirm still pending rolls back at once, because a
//!   reboot during a provisional change is the case the timer exists for.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensr_ipc::server::{Handler, PeerCred, Reply};
use sensr_ipc::{
    AuthMethod, CommitOutcome, ErrorKind, Event, IpcError, Op, PendingConfirm, Principal, Request,
    Response, RevisionId, Source, Status, StreamItem,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{Mutex, Notify, broadcast, mpsc, watch};

use crate::applier::{Applier, ApplyError};
use crate::redact;
use crate::store::{ConfigStore, NewRevision, StoreError, now_ms, write_atomic};

/// Agent policy knobs.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Peers (besides root) whose claimed principal is trusted, e.g. the
    /// `sensr-api` service user.
    pub trusted_uids: Vec<u32>,
    /// Peer groups whose claimed principal is trusted.
    pub trusted_gids: Vec<u32>,
    /// Where the applied revision and pending confirm are persisted.
    pub state_file: Option<PathBuf>,
    /// Longest confirm window accepted.
    pub max_confirm: Duration,
    /// Delay before retrying a rollback whose apply failed.
    pub rollback_retry: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            trusted_uids: Vec::new(),
            trusted_gids: Vec::new(),
            state_file: None,
            max_confirm: Duration::from_secs(24 * 3600),
            rollback_retry: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Persisted {
    applied: Option<RevisionId>,
    pending: Option<PendingConfirm>,
}

struct Inner<S, A> {
    store: S,
    applier: A,
    candidate: Option<Value>,
    applied: Option<RevisionId>,
    applied_doc: Option<Value>,
    pending: Option<PendingConfirm>,
    last_apply_error: Option<String>,
}

/// The agent. Cheap to share: wrap in an [`Arc`].
pub struct Agent<S, A> {
    inner: Mutex<Inner<S, A>>,
    events: broadcast::Sender<Event>,
    confirm_changed: Notify,
    started: Instant,
    settings: Settings,
}

fn empty() -> Value {
    Value::Object(Default::default())
}

fn internal(e: StoreError) -> IpcError {
    IpcError::new(ErrorKind::Internal, e.to_string())
}

fn err(kind: ErrorKind, msg: impl Into<String>) -> IpcError {
    IpcError::new(kind, msg)
}

/// The agent's own principal, used for boot applies and timeouts.
pub fn system_principal() -> Principal {
    Principal {
        user: "sensr-agent".into(),
        via: AuthMethod::System,
        impersonated_by: None,
        readonly: false,
    }
}

/// Looks a uid up in `/etc/passwd` (no NSS: the agent only needs local
/// system accounts).
fn unix_user_name(uid: u32) -> String {
    std::fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|passwd| {
            passwd.lines().find_map(|line| {
                let mut f = line.split(':');
                let name = f.next()?;
                let id: u32 = f.nth(1)?.parse().ok()?;
                (id == uid).then(|| name.to_owned())
            })
        })
        .unwrap_or_else(|| format!("uid{uid}"))
}

impl<S: ConfigStore, A: Applier> Agent<S, A> {
    /// Builds the agent, restoring persisted apply/confirm state.
    pub fn new(store: S, applier: A, settings: Settings) -> Result<Arc<Self>, IpcError> {
        let persisted: Persisted = match &settings.state_file {
            Some(path) => match std::fs::read(path) {
                Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| {
                    err(
                        ErrorKind::Internal,
                        format!("corrupt state file {}: {e}", path.display()),
                    )
                })?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Persisted::default(),
                Err(e) => return Err(err(ErrorKind::Internal, e.to_string())),
            },
            None => Persisted::default(),
        };
        let applied_doc = match persisted.applied {
            Some(id) => store.get(id).map_err(internal)?.map(|r| r.document),
            None => None,
        };
        let (events, _) = broadcast::channel(64);
        Ok(Arc::new(Self {
            inner: Mutex::new(Inner {
                store,
                applier,
                candidate: None,
                applied: persisted.applied.filter(|_| applied_doc.is_some()),
                applied_doc,
                pending: persisted.pending,
                last_apply_error: None,
            }),
            events,
            confirm_changed: Notify::new(),
            started: Instant::now(),
            settings,
        }))
    }

    /// Boot path = apply path (§2.4 step 5): roll back a confirm left
    /// pending by a previous run, else apply head in full.
    pub async fn boot(&self) -> Result<(), IpcError> {
        {
            let mut inner = self.inner.lock().await;
            match inner.pending.as_mut() {
                None => return self.reconcile(&mut inner).await,
                Some(p) => {
                    tracing::warn!(
                        revision = p.revision,
                        rollback_to = p.rollback_to,
                        "commit-confirm was pending at startup; rolling back"
                    );
                    p.deadline_ms = p.deadline_ms.min(now_ms());
                }
            }
        }
        // A failed rollback stays pending and the timer retries it.
        self.expire_pending().await;
        Ok(())
    }

    /// Re-applies head from scratch (boot and `SIGHUP`).
    pub async fn reload(&self) -> Result<(), IpcError> {
        let mut inner = self.inner.lock().await;
        self.reconcile(&mut inner).await
    }

    async fn reconcile(&self, inner: &mut Inner<S, A>) -> Result<(), IpcError> {
        let Some(head) = inner.store.head().map_err(internal)? else {
            return Ok(());
        };
        // `running: None` forces every backend to be rendered and checked.
        inner
            .applier
            .plan(None, &head.document)
            .map_err(apply_error)?;
        match inner.applier.apply(None, &head.document) {
            Ok(()) => {
                inner.applied = Some(head.info.id);
                inner.applied_doc = Some(head.document);
                inner.last_apply_error = None;
                let _ = self.events.send(Event::Applied(head.info.id));
                self.persist(inner);
                Ok(())
            }
            Err(e) => {
                inner.last_apply_error = Some(e.to_string());
                Err(apply_error(e))
            }
        }
    }

    fn persist(&self, inner: &Inner<S, A>) {
        let Some(path) = &self.settings.state_file else {
            return;
        };
        let state = Persisted {
            applied: inner.applied,
            pending: inner.pending.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&state).unwrap_or_default();
        if let Err(e) = write_atomic(path, &bytes) {
            tracing::error!(error = %e, path = %path.display(), "cannot persist agent state");
        }
    }

    /// Decides which principal a request really runs as.
    ///
    /// Root and configured trusted peers (the API service) may act for the
    /// principal they authenticated. Anyone else who can reach the socket is
    /// pinned to their own Unix identity, read-only. A Unix principal always
    /// takes its name from the peer uid; when root acts on behalf of a
    /// different claimed user (sudo), that user is recorded as
    /// `impersonated_by`.
    pub fn resolve_principal(&self, peer: PeerCred, claimed: Principal) -> Principal {
        let trusted = peer.uid == 0
            || self.settings.trusted_uids.contains(&peer.uid)
            || self.settings.trusted_gids.contains(&peer.gid);
        if !trusted {
            return Principal {
                user: unix_user_name(peer.uid),
                via: AuthMethod::Unix { uid: peer.uid },
                impersonated_by: None,
                readonly: true,
            };
        }
        match claimed.via {
            AuthMethod::Unix { .. } => {
                let user = unix_user_name(peer.uid);
                let impersonated_by = (claimed.user != user && !claimed.user.is_empty())
                    .then_some(claimed.user)
                    .or(claimed.impersonated_by);
                Principal {
                    user,
                    via: AuthMethod::Unix { uid: peer.uid },
                    impersonated_by,
                    readonly: claimed.readonly,
                }
            }
            // Only the agent itself acts as System.
            AuthMethod::System => Principal {
                readonly: true,
                ..claimed
            },
            _ => claimed,
        }
    }

    fn is_trusted_peer(&self, peer: PeerCred) -> bool {
        peer.uid == 0
            || self.settings.trusted_uids.contains(&peer.uid)
            || self.settings.trusted_gids.contains(&peer.gid)
    }

    fn resolve(&self, inner: &Inner<S, A>, source: Source) -> Result<Value, IpcError> {
        let head = || -> Result<Value, IpcError> {
            Ok(inner
                .store
                .head()
                .map_err(internal)?
                .map_or_else(empty, |r| r.document))
        };
        match source {
            Source::Candidate => match &inner.candidate {
                Some(c) => Ok(c.clone()),
                None => head(),
            },
            Source::Head => head(),
            Source::Applied => Ok(inner.applied_doc.clone().unwrap_or_else(empty)),
            Source::Revision(id) => inner
                .store
                .get(id)
                .map_err(internal)?
                .map(|r| r.document)
                .ok_or_else(|| err(ErrorKind::NotFound, format!("no revision {id}"))),
        }
    }

    fn candidate_mut<'a>(&self, inner: &'a mut Inner<S, A>) -> Result<&'a mut Value, IpcError> {
        if inner.candidate.is_none() {
            let head = self.resolve(inner, Source::Head)?;
            inner.candidate = Some(head);
        }
        Ok(inner.candidate.get_or_insert_with(empty))
    }

    fn dirty(&self, inner: &Inner<S, A>) -> Result<bool, IpcError> {
        match &inner.candidate {
            None => Ok(false),
            Some(c) => Ok(*c != self.resolve(inner, Source::Head)?),
        }
    }

    /// Plan → store → apply one document. Never leaves the host on a
    /// half-applied revision: a failed apply re-applies what was running.
    async fn commit_doc(
        &self,
        inner: &mut Inner<S, A>,
        doc: Value,
        principal: &Principal,
        description: String,
    ) -> Result<sensr_ipc::RevisionInfo, IpcError> {
        inner
            .applier
            .plan(inner.applied_doc.as_ref(), &doc)
            .map_err(apply_error)?;
        let info = inner
            .store
            .commit(NewRevision {
                document: doc.clone(),
                username: principal.revision_username(),
                description,
                impersonated_by: principal.impersonated_by.clone(),
            })
            .map_err(internal)?;
        let _ = self.events.send(Event::RevisionCommitted(info.clone()));
        inner.candidate = None;
        let running = inner.applied_doc.clone();
        match inner.applier.apply(running.as_ref(), &doc) {
            Ok(()) => {
                inner.applied = Some(info.id);
                inner.applied_doc = Some(doc);
                inner.last_apply_error = None;
                let _ = self.events.send(Event::Applied(info.id));
                self.persist(inner);
                Ok(info)
            }
            Err(e) => {
                let msg = format!("revision {} stored but not applied: {e}", info.id);
                inner.last_apply_error = Some(msg.clone());
                if let Some(prev) = &running
                    && let Err(again) = inner.applier.apply(Some(&doc), prev)
                {
                    tracing::error!(error = %again, "re-applying the previous revision also failed");
                }
                self.persist(inner);
                Err(err(ErrorKind::ApplyFailed, msg))
            }
        }
    }

    /// Commits an earlier revision's document again, superseding any
    /// pending confirm.
    async fn restore(
        &self,
        inner: &mut Inner<S, A>,
        target: RevisionId,
        principal: &Principal,
        description: String,
    ) -> Result<sensr_ipc::RevisionInfo, IpcError> {
        let doc = self.resolve(inner, Source::Revision(target))?;
        let info = self.commit_doc(inner, doc, principal, description).await?;
        if inner.pending.take().is_some() {
            self.persist(inner);
            self.confirm_changed.notify_one();
        }
        Ok(info)
    }

    /// Rolls back an expired provisional commit. Returns the instant to
    /// check again (next deadline), if any.
    async fn expire_pending(&self) -> Option<i64> {
        let mut inner = self.inner.lock().await;
        let p = inner.pending.clone()?;
        if now_ms() < p.deadline_ms {
            return Some(p.deadline_ms);
        }
        let desc = format!(
            "commit-confirm timeout: revision {} not confirmed, restoring revision {}",
            p.revision, p.rollback_to
        );
        match self
            .restore(&mut inner, p.rollback_to, &system_principal(), desc)
            .await
        {
            Ok(restored) => {
                tracing::warn!(
                    abandoned = p.revision,
                    restored = restored.id,
                    "commit-confirm timed out; rolled back"
                );
                inner.pending = None;
                self.persist(&inner);
                let _ = self.events.send(Event::RolledBack {
                    abandoned: p.revision,
                    restored,
                });
                None
            }
            Err(e) => {
                tracing::error!(error = %e, "commit-confirm rollback failed; retrying");
                let retry = now_ms() + self.settings.rollback_retry.as_millis() as i64;
                inner.pending = Some(PendingConfirm {
                    deadline_ms: retry,
                    ..p
                });
                self.persist(&inner);
                Some(retry)
            }
        }
    }

    /// Drives the commit-confirm deadline until `shutdown`.
    pub async fn run_confirm_timer(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        loop {
            let deadline = self
                .inner
                .lock()
                .await
                .pending
                .as_ref()
                .map(|p| p.deadline_ms);
            let sleep = match deadline {
                Some(d) => Duration::from_millis((d - now_ms()).max(0) as u64),
                None => Duration::from_secs(3600),
            };
            tokio::select! {
                _ = tokio::time::sleep(sleep), if deadline.is_some() => {
                    self.expire_pending().await;
                }
                _ = tokio::time::sleep(sleep), if deadline.is_none() => {}
                _ = self.confirm_changed.notified() => {}
                _ = stopped(&mut shutdown) => return,
            }
        }
    }

    /// Serves one operation for an already-resolved principal.
    pub async fn execute(&self, principal: &Principal, op: Op) -> Result<Response, IpcError> {
        if op.is_write() && principal.readonly {
            return Err(err(
                ErrorKind::Forbidden,
                format!("{} may not change the configuration", principal.user),
            ));
        }
        let mut inner = self.inner.lock().await;
        let inner = &mut *inner;
        match op {
            Op::Ping => Ok(Response::Pong),
            Op::Status => {
                let head = inner.store.head().map_err(internal)?.map(|r| r.info);
                Ok(Response::Status(Box::new(Status {
                    agent_version: env!("CARGO_PKG_VERSION").into(),
                    protocol: sensr_ipc::PROTOCOL_VERSION,
                    uptime_secs: self.started.elapsed().as_secs(),
                    head,
                    applied: inner.applied,
                    candidate_dirty: self.dirty(inner)?,
                    pending_confirm: inner.pending.clone(),
                    last_apply_error: inner.last_apply_error.clone(),
                })))
            }
            Op::ConfigGet { path, source } => {
                let doc = self.resolve(inner, source)?;
                let value = path.lookup(&doc).map(|v| {
                    if redact::is_secret_path(&path) {
                        redact::redacted(&serde_json::json!({"secret": v}))["secret"].take()
                    } else {
                        redact::redacted(v)
                    }
                });
                Ok(Response::Value(value))
            }
            Op::ConfigSet { path, mut value } => {
                let cand = self.candidate_mut(inner)?;
                let old = path.lookup(cand).cloned();
                if redact::is_secret_path(&path) && redact::is_masked(&value) {
                    // Writing back the placeholder means "unchanged".
                    return Ok(Response::Staged {
                        dirty: self.dirty(inner)?,
                    });
                }
                redact::restore(&mut value, old.as_ref());
                path.assign(cand, value)
                    .map_err(|e| err(ErrorKind::BadRequest, e.to_string()))?;
                Ok(Response::Staged {
                    dirty: self.dirty(inner)?,
                })
            }
            Op::ConfigDelete { path } => {
                let cand = self.candidate_mut(inner)?;
                if path.is_root() {
                    *cand = empty();
                } else if path.remove(cand).is_none() {
                    return Err(err(ErrorKind::NotFound, format!("{path} does not exist")));
                }
                Ok(Response::Staged {
                    dirty: self.dirty(inner)?,
                })
            }
            Op::ConfigLoad { mut document } => {
                if !document.is_object() {
                    return Err(err(
                        ErrorKind::BadRequest,
                        "a config document must be a JSON object",
                    ));
                }
                let current = self.resolve(inner, Source::Candidate)?;
                redact::restore(&mut document, Some(&current));
                inner.candidate = Some(document);
                Ok(Response::Staged {
                    dirty: self.dirty(inner)?,
                })
            }
            Op::ConfigDiscard => {
                inner.candidate = None;
                Ok(Response::Staged { dirty: false })
            }
            Op::ConfigCommit {
                description,
                confirm_secs,
            } => {
                self.commit(inner, principal, description, confirm_secs)
                    .await
            }
            Op::ConfigConfirm => {
                let p = inner.pending.take().ok_or_else(|| {
                    err(ErrorKind::Conflict, "no commit is waiting for confirmation")
                })?;
                self.persist(inner);
                self.confirm_changed.notify_one();
                let _ = self.events.send(Event::Confirmed(p.revision));
                Ok(Response::Confirmed(p.revision))
            }
            Op::ConfigRollback { to } => {
                let head = inner
                    .store
                    .head()
                    .map_err(internal)?
                    .ok_or_else(|| err(ErrorKind::NotFound, "no revisions to roll back"))?;
                let target = match to {
                    Some(t) => t,
                    None => head
                        .info
                        .parent
                        .ok_or_else(|| err(ErrorKind::NotFound, "head has no earlier revision"))?,
                };
                let desc = format!("rollback to revision {target}");
                let revision = self.restore(inner, target, principal, desc).await?;
                Ok(Response::Committed(Box::new(CommitOutcome {
                    revision,
                    pending_confirm: None,
                })))
            }
            Op::ConfigHistory { limit } => Ok(Response::History(
                inner
                    .store
                    .history(limit.unwrap_or(50) as usize)
                    .map_err(internal)?,
            )),
            Op::ConfigDiff { from, to } => {
                let a = redact::redacted(&self.resolve(inner, from)?);
                let b = redact::redacted(&self.resolve(inner, to)?);
                Ok(Response::Diff(crate::diff::diff(
                    &a,
                    &b,
                    &label(from),
                    &label(to),
                )))
            }
            Op::ApplyDryRun { source } => {
                let next = self.resolve(inner, source)?;
                inner
                    .applier
                    .plan(inner.applied_doc.as_ref(), &next)
                    .map(Response::Plan)
                    .map_err(apply_error)
            }
            Op::Authenticate {
                credential,
                remote_addr,
            } => {
                let head = self.resolve(inner, Source::Head)?;
                crate::auth::authenticate(&head, &credential, remote_addr)
                    .map(Response::Authenticated)
                    .ok_or_else(|| err(ErrorKind::Unauthenticated, "invalid credentials"))
            }
            Op::Subscribe => Err(err(ErrorKind::BadRequest, "subscribe opens a stream")),
        }
    }

    async fn commit(
        &self,
        inner: &mut Inner<S, A>,
        principal: &Principal,
        description: Option<String>,
        confirm_secs: Option<u32>,
    ) -> Result<Response, IpcError> {
        let window = confirm_secs.map(|s| Duration::from_secs(u64::from(s)));
        if let Some(w) = window {
            if w.is_zero() || w > self.settings.max_confirm {
                return Err(err(
                    ErrorKind::BadRequest,
                    format!(
                        "confirm window must be 1..={} seconds",
                        self.settings.max_confirm.as_secs()
                    ),
                ));
            }
            if inner.applied.is_none() {
                return Err(err(
                    ErrorKind::Conflict,
                    "commit-confirm needs a previously applied revision to fall back to",
                ));
            }
        }
        if !self.dirty(inner)? {
            return Err(err(ErrorKind::Conflict, "nothing to commit"));
        }
        let doc = inner.candidate.clone().unwrap_or_else(empty);
        // Fall back to the last *confirmed* revision: a pending one was never
        // shown to keep management reachable.
        let known_good = inner
            .pending
            .as_ref()
            .map(|p| p.rollback_to)
            .or(inner.applied);
        let description = description.unwrap_or_else(|| "sensr config commit".into());
        let revision = self.commit_doc(inner, doc, principal, description).await?;
        let pending_confirm = match (window, known_good) {
            (Some(w), Some(rollback_to)) => {
                let p = PendingConfirm {
                    revision: revision.id,
                    rollback_to,
                    deadline_ms: now_ms() + w.as_millis() as i64,
                };
                inner.pending = Some(p.clone());
                self.persist(inner);
                self.confirm_changed.notify_one();
                Some(p)
            }
            _ => {
                // A plain commit on top of a provisional one confirms nothing;
                // the old deadline still stands.
                inner.pending.clone()
            }
        };
        Ok(Response::Committed(Box::new(CommitOutcome {
            revision,
            pending_confirm,
        })))
    }

    /// Completes once the agent state lock can be taken (watchdog probe).
    pub async fn health(&self) {
        drop(self.inner.lock().await);
    }

    /// A new subscription to agent events.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }
}

fn label(s: Source) -> String {
    match s {
        Source::Candidate => "candidate".into(),
        Source::Head => "head".into(),
        Source::Applied => "applied".into(),
        Source::Revision(id) => format!("revision {id}"),
    }
}

fn apply_error(e: ApplyError) -> IpcError {
    match e {
        ApplyError::Invalid(validations) => IpcError {
            kind: ErrorKind::Validation,
            message: "the configuration was rejected; nothing was changed".into(),
            validations,
        },
        ApplyError::Failed(m) => err(ErrorKind::ApplyFailed, m),
    }
}

impl<S: ConfigStore, A: Applier> Handler for Agent<S, A> {
    async fn handle(&self, peer: PeerCred, req: Request) -> Reply {
        if matches!(req.op, Op::Authenticate { .. }) && !self.is_trusted_peer(peer) {
            return Response::Error(err(
                ErrorKind::Forbidden,
                "authentication is reserved for sensr-api",
            ))
            .into();
        }
        let principal = self.resolve_principal(peer, req.principal);
        if matches!(req.op, Op::Subscribe) {
            let mut events = self.subscribe();
            let (tx, rx) = mpsc::channel(16);
            tokio::spawn(async move {
                loop {
                    let item = match events.recv().await {
                        Ok(ev) => StreamItem::Event(ev),
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            StreamItem::Line(format!("{n} events dropped"))
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    };
                    if tx.send(item).await.is_err() {
                        break;
                    }
                }
            });
            return Reply::Stream(rx);
        }
        let op_name = op_name(&req.op);
        let result = self.execute(&principal, req.op).await;
        if let Err(e) = &result {
            tracing::debug!(op = op_name, user = %principal.user, kind = ?e.kind, "request failed: {}", e.message);
        }
        result.into()
    }
}

fn op_name(op: &Op) -> &'static str {
    match op {
        Op::Ping => "ping",
        Op::Status => "status",
        Op::ConfigGet { .. } => "config.get",
        Op::ConfigSet { .. } => "config.set",
        Op::ConfigDelete { .. } => "config.delete",
        Op::ConfigLoad { .. } => "config.load",
        Op::ConfigDiscard => "config.discard",
        Op::ConfigCommit { .. } => "config.commit",
        Op::ConfigConfirm => "config.confirm",
        Op::ConfigRollback { .. } => "config.rollback",
        Op::ConfigHistory { .. } => "config.history",
        Op::ConfigDiff { .. } => "config.diff",
        Op::ApplyDryRun { .. } => "apply.dry_run",
        Op::Authenticate { .. } => "authenticate",
        Op::Subscribe => "subscribe",
    }
}

async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|s| *s).await;
}
