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
//! - The applied revision and any pending confirm live in the
//!   `sensr-config` store next to the revisions, so they survive restarts
//!   with them; an agent that starts with a confirm still pending rolls back
//!   at once, because a reboot during a provisional change is the case the
//!   timer exists for.
//! - Every edit is decoded into the typed `sensr-schema` document, so the
//!   candidate always fits the schema, and an edit that introduces a
//!   validation problem is refused before anything is staged.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensr_config::{CommitMeta, CommitOutcome as StoreOutcome, ConfirmState, Store, StoreError};
use sensr_ipc::server::{Handler, PeerCred, Reply};
use sensr_ipc::{
    AuthMethod, CommitOutcome, ErrorKind, Event, IpcError, Op, PendingConfirm, Principal, Request,
    Response, RevisionId, RevisionInfo, Source, Status, StreamItem, ValidationIssue,
};
use sensr_schema::Document;
use serde_json::Value;
use tokio::sync::{Mutex, Notify, broadcast, mpsc, watch};

use crate::applier::{Applier, ApplyError};
use crate::redact::{self, View};
use crate::store::{from_ipc, info_of, issues, now_ms, to_ipc};

/// Agent policy knobs.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Peers (besides root) whose claimed principal is trusted, e.g. the
    /// `sensr-api` service user.
    pub trusted_uids: Vec<u32>,
    /// Peer groups whose claimed principal is trusted.
    pub trusted_gids: Vec<u32>,
    /// Longest confirm window accepted.
    pub max_confirm: Duration,
    /// Delay before retrying a rollback whose apply failed.
    pub rollback_retry: Duration,
    /// Where the web GUI's local CA and certificate live; `None` keeps them
    /// in memory (tests).
    pub tls_dir: Option<std::path::PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            trusted_uids: Vec::new(),
            trusted_gids: Vec::new(),
            max_confirm: Duration::from_secs(24 * 3600),
            rollback_retry: Duration::from_secs(5),
            tls_dir: None,
        }
    }
}

struct Inner<A> {
    store: Store,
    applier: A,
    /// The store's head, cached: every read and `dirty` check needs it.
    head: (RevisionId, Document),
    /// Head plus staged edits; `None` when nothing is staged.
    candidate: Option<Document>,
    /// Masked JSON of `head` and `candidate`, kept with them: reads are the
    /// hot path and masking walks the whole document.
    head_masked: Value,
    candidate_masked: Option<Value>,
    /// What the host runs. The id is also recorded in the store
    /// (`mark_applied`); the document is kept for planning.
    applied: Option<(RevisionId, Document)>,
    last_apply_error: Option<String>,
}

impl<A> Inner<A> {
    fn set_candidate(&mut self, doc: Option<Document>) {
        self.candidate_masked = doc.as_ref().map(redact::masked);
        self.candidate = doc;
    }
}

/// The agent. Cheap to share: wrap in an [`Arc`].
pub struct Agent<A> {
    inner: Mutex<Inner<A>>,
    events: broadcast::Sender<Event>,
    confirm_changed: Notify,
    started: Instant,
    settings: Settings,
    tls: crate::tls::LocalCa,
}

fn internal(e: StoreError) -> IpcError {
    match e {
        StoreError::Invalid(v) => validation(issues(&v)),
        StoreError::NotFound(id) => err(ErrorKind::NotFound, format!("no revision {id}")),
        other => IpcError::new(ErrorKind::Internal, other.to_string()),
    }
}

fn validation(validations: Vec<ValidationIssue>) -> IpcError {
    IpcError {
        kind: ErrorKind::Validation,
        message: "the configuration was rejected; nothing was changed".into(),
        validations,
    }
}

fn err(kind: ErrorKind, msg: impl Into<String>) -> IpcError {
    IpcError::new(kind, msg)
}

fn ipc_pending(c: ConfirmState) -> PendingConfirm {
    PendingConfirm {
        revision: to_ipc(c.pending),
        rollback_to: to_ipc(c.rollback_to),
        deadline_ms: c.deadline_ms,
    }
}

/// Decodes a JSON document into the schema, naming the offending path.
pub fn decode(v: &Value) -> Result<Document, IpcError> {
    serde_path_to_error::deserialize(v.clone()).map_err(|e| {
        let path = e.path().to_string();
        validation(vec![ValidationIssue {
            path: if path == "." { String::new() } else { path },
            message: format!("{}.", e.inner()),
        }])
    })
}

/// Validation problems as comparable `(path, message)` pairs.
fn problems(doc: &Document) -> BTreeSet<(String, String)> {
    issues(&doc.validate())
        .into_iter()
        .map(|i| (i.path, i.message))
        .collect()
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

/// The `Groups:` line of `/proc/<pid>/status` (empty off Linux or when the
/// process is gone). The peer cannot change it under us without exec'ing,
/// and the connection was opened by that process.
fn supplementary_groups(pid: i32) -> Vec<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|l| l.strip_prefix("Groups:"))
                .map(|g| {
                    g.split_whitespace()
                        .filter_map(|n| n.parse().ok())
                        .collect()
                })
        })
        .unwrap_or_default()
}

/// Resolves a group name in `/etc/group`.
pub fn group_id(name: &str) -> Option<u32> {
    std::fs::read_to_string("/etc/group")
        .ok()?
        .lines()
        .find_map(|line| {
            let mut f = line.split(':');
            (f.next()? == name).then_some(())?;
            f.nth(1)?.parse().ok()
        })
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

/// How a revision is written: the store call that produces it.
enum Write {
    /// A candidate commit.
    Commit(Box<Document>),
    /// Revision `n`'s content made current again.
    Restore(RevisionId),
    /// The pending commit-confirm abandoned.
    Rollback,
}

impl<A: Applier> Agent<A> {
    /// Builds the agent over `store`, restoring the applied revision it
    /// records.
    pub fn new(store: Store, applier: A, settings: Settings) -> Result<Arc<Self>, IpcError> {
        let head = store.head().map_err(internal)?;
        let applied = match store.applied().map_err(internal)? {
            Some(id) => match store.get(id) {
                Ok(r) => Some((to_ipc(id), r.document)),
                Err(StoreError::NotFound(_)) => None,
                Err(e) => return Err(internal(e)),
            },
            None => None,
        };
        let (events, _) = broadcast::channel(64);
        Ok(Arc::new(Self {
            inner: Mutex::new(Inner {
                head_masked: redact::masked(&head.document),
                candidate_masked: None,
                head: (to_ipc(head.meta.id), head.document),
                store,
                applier,
                candidate: None,
                applied,
                last_apply_error: None,
            }),
            events,
            confirm_changed: Notify::new(),
            started: Instant::now(),
            tls: crate::tls::LocalCa::new(settings.tls_dir.clone()),
            settings,
        }))
    }

    /// Boot path = apply path (§2.4 step 5): roll back a confirm left
    /// pending by a previous run, else apply head in full.
    pub async fn boot(&self) -> Result<(), IpcError> {
        {
            // First boot creates the web GUI's CA and certificate, so they
            // exist before sensr-api asks.
            let inner = self.inner.lock().await;
            if let Err(e) = self.tls.ensure(&inner.head.1) {
                tracing::error!(error = %e, "creating the web GUI certificate");
            }
        }
        {
            let mut inner = self.inner.lock().await;
            match inner.store.pending_confirm().map_err(internal)? {
                None => return self.reconcile(&mut inner).await,
                Some(p) => tracing::warn!(
                    revision = %p.pending,
                    rollback_to = %p.rollback_to,
                    "commit-confirm was pending at startup; rolling back"
                ),
            }
        }
        // A failed rollback stays pending and the timer retries it.
        self.expire_pending(true).await;
        Ok(())
    }

    /// Re-applies head from scratch (boot and `SIGHUP`).
    pub async fn reload(&self) -> Result<(), IpcError> {
        let mut inner = self.inner.lock().await;
        self.reconcile(&mut inner).await
    }

    async fn reconcile(&self, inner: &mut Inner<A>) -> Result<(), IpcError> {
        let (id, head) = inner.head.clone();
        // `running: None` forces every backend to be rendered and checked.
        inner.applier.plan(None, &head).map_err(apply_error)?;
        match inner.applier.apply(None, &head) {
            Ok(()) => {
                // A pending confirm (SIGHUP during the window) keeps its deadline.
                let pending = inner.store.pending_confirm().map_err(internal)?;
                self.mark_applied(inner, id, head, pending)?;
                inner.last_apply_error = None;
                let _ = self.events.send(Event::Applied(id));
                Ok(())
            }
            Err(e) => {
                inner.last_apply_error = Some(e.to_string());
                Err(apply_error(e))
            }
        }
    }

    fn mark_applied(
        &self,
        inner: &mut Inner<A>,
        id: RevisionId,
        doc: Document,
        confirm: Option<ConfirmState>,
    ) -> Result<(), IpcError> {
        let rev = from_ipc(id).ok_or_else(|| err(ErrorKind::Internal, "revision out of range"))?;
        inner
            .store
            .mark_applied(rev, confirm, "sensr-agent")
            .map_err(internal)?;
        inner.applied = Some((id, doc));
        Ok(())
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
        if !self.is_trusted_peer(peer) {
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

    /// Root, a trusted uid, or a process whose primary or supplementary
    /// groups include a trusted gid. `SO_PEERCRED` only reports the primary
    /// gid; supplementary groups (how the `DynamicUser` API is marked) come
    /// from `/proc/<pid>/status`.
    pub fn is_trusted_peer(&self, peer: PeerCred) -> bool {
        if peer.uid == 0
            || self.settings.trusted_uids.contains(&peer.uid)
            || self.settings.trusted_gids.contains(&peer.gid)
        {
            return true;
        }
        if self.settings.trusted_gids.is_empty() {
            return false;
        }
        peer.pid.map(supplementary_groups).is_some_and(|groups| {
            groups
                .iter()
                .any(|g| self.settings.trusted_gids.contains(g))
        })
    }

    /// The document `source` names; `Ok(None)` for `applied` before the
    /// first apply.
    fn resolve(&self, inner: &Inner<A>, source: Source) -> Result<Option<Document>, IpcError> {
        Ok(Some(match source {
            Source::Candidate => inner
                .candidate
                .clone()
                .unwrap_or_else(|| inner.head.1.clone()),
            Source::Head => inner.head.1.clone(),
            Source::Applied => match &inner.applied {
                Some((_, d)) => d.clone(),
                None => return Ok(None),
            },
            Source::Revision(id) => {
                let rev = from_ipc(id)
                    .ok_or_else(|| err(ErrorKind::NotFound, format!("no revision {id}")))?;
                inner.store.get(rev).map_err(internal)?.document
            }
        }))
    }

    /// The masked JSON view of `source` (an empty object for `applied`
    /// before the first apply).
    fn masked(&self, inner: &Inner<A>, source: Source) -> Result<Value, IpcError> {
        match source {
            Source::Head => return Ok(inner.head_masked.clone()),
            Source::Candidate => {
                return Ok(inner
                    .candidate_masked
                    .clone()
                    .unwrap_or_else(|| inner.head_masked.clone()));
            }
            _ => {}
        }
        Ok(self
            .resolve(inner, source)?
            .map_or_else(|| Value::Object(Default::default()), |d| redact::masked(&d)))
    }

    fn dirty(inner: &Inner<A>) -> bool {
        inner.candidate.as_ref().is_some_and(|c| *c != inner.head.1)
    }

    /// Applies an edit of the candidate's JSON. The result must fit the
    /// schema, and the edit may not introduce validation problems the
    /// candidate did not already have (a duplicate alias name, a rule
    /// pointing at a missing alias); otherwise nothing is staged.
    fn edit(
        &self,
        inner: &mut Inner<A>,
        change: impl FnOnce(&mut Value) -> Result<(), IpcError>,
    ) -> Result<Response, IpcError> {
        let base = inner
            .candidate
            .clone()
            .unwrap_or_else(|| inner.head.1.clone());
        let old = View::of(&base);
        let mut v = old.value.clone();
        change(&mut v)?;
        redact::restore(&mut v, &old);
        let mut doc = decode(&v)?;
        if redact::drop_unbacked(&mut v, &doc) {
            doc = decode(&v)?;
        }
        let before = problems(&base);
        let introduced: Vec<ValidationIssue> = problems(&doc)
            .into_iter()
            .filter(|p| !before.contains(p))
            .map(|(path, message)| ValidationIssue { path, message })
            .collect();
        if !introduced.is_empty() {
            return Err(validation(introduced));
        }
        inner.set_candidate(Some(doc));
        Ok(Response::Staged {
            dirty: Self::dirty(inner),
        })
    }

    /// Plan → store → apply one revision. Never leaves the host on a
    /// half-applied revision: a failed apply re-applies what was running.
    /// `confirm` builds the commit-confirm state for the stored revision.
    async fn commit_doc(
        &self,
        inner: &mut Inner<A>,
        write: Write,
        meta: CommitMeta,
        confirm: impl FnOnce(RevisionId) -> Option<ConfirmState>,
    ) -> Result<RevisionInfo, IpcError> {
        let next = match &write {
            Write::Commit(doc) => (**doc).clone(),
            Write::Restore(id) => self
                .resolve(inner, Source::Revision(*id))?
                .unwrap_or_default(),
            Write::Rollback => {
                let p = inner
                    .store
                    .pending_confirm()
                    .map_err(internal)?
                    .ok_or_else(|| err(ErrorKind::Conflict, "no commit is waiting"))?;
                inner.store.get(p.rollback_to).map_err(internal)?.document
            }
        };
        let running = inner.applied.as_ref().map(|(_, d)| d.clone());
        inner
            .applier
            .plan(running.as_ref(), &next)
            .map_err(apply_error)?;
        let outcome = match write {
            Write::Commit(doc) => inner.store.commit(&doc, meta),
            Write::Restore(id) => match from_ipc(id) {
                Some(rev) => inner.store.restore(rev, meta),
                None => return Err(err(ErrorKind::NotFound, format!("no revision {id}"))),
            },
            Write::Rollback => match inner.store.rollback_with(meta) {
                Ok(Some(o)) => Ok(o),
                Ok(None) => return Err(err(ErrorKind::Conflict, "no commit is waiting")),
                Err(e) => Err(e),
            },
        }
        .map_err(internal)?;
        let meta = match outcome {
            StoreOutcome::Committed(m) => m,
            StoreOutcome::Unchanged(_) => {
                return Err(err(ErrorKind::Conflict, "nothing to commit"));
            }
        };
        let info = info_of(&meta);
        inner.head_masked = redact::masked(&next);
        inner.head = (info.id, next.clone());
        let _ = self.events.send(Event::RevisionCommitted(info.clone()));
        inner.set_candidate(None);
        match inner.applier.apply(running.as_ref(), &next) {
            Ok(()) => {
                self.mark_applied(inner, info.id, next, confirm(info.id))?;
                inner.last_apply_error = None;
                let _ = self.events.send(Event::Applied(info.id));
                Ok(info)
            }
            Err(e) => {
                let msg = format!("revision {} stored but not applied: {e}", info.id);
                inner.last_apply_error = Some(msg.clone());
                if let Some(prev) = &running
                    && let Err(again) = inner.applier.apply(Some(&next), prev)
                {
                    tracing::error!(error = %again, "re-applying the previous revision also failed");
                }
                Err(err(ErrorKind::ApplyFailed, msg))
            }
        }
    }

    /// Rolls back an expired provisional commit. Returns the instant to
    /// check again (next deadline), if any.
    async fn expire_pending(&self, at_startup: bool) -> Option<i64> {
        let mut inner = self.inner.lock().await;
        let p = match inner.store.pending_confirm() {
            Ok(p) => p?,
            Err(e) => {
                tracing::error!(error = %e, "reading the pending confirm");
                return Some(now_ms() + self.settings.rollback_retry.as_millis() as i64);
            }
        };
        if !at_startup && now_ms() < p.deadline_ms {
            return Some(p.deadline_ms);
        }
        let desc = if at_startup {
            format!(
                "commit-confirm: agent restarted before revision {} was confirmed, restoring revision {}",
                p.pending, p.rollback_to
            )
        } else {
            format!(
                "commit-confirm timeout: revision {} not confirmed, restoring revision {}",
                p.pending, p.rollback_to
            )
        };
        let meta = CommitMeta::new(system_principal().revision_username(), desc);
        match self
            .commit_doc(&mut inner, Write::Rollback, meta, |_| None)
            .await
        {
            Ok(restored) => {
                tracing::warn!(
                    abandoned = %p.pending,
                    restored = restored.id,
                    "commit-confirm timed out; rolled back"
                );
                let _ = self.events.send(Event::RolledBack {
                    abandoned: to_ipc(p.pending),
                    restored,
                });
                None
            }
            Err(e) => {
                tracing::error!(error = %e, "commit-confirm rollback failed; retrying");
                let retry = now_ms() + self.settings.rollback_retry.as_millis() as i64;
                let again = ConfirmState {
                    deadline_ms: retry,
                    ..p
                };
                // The rollback revision may be stored but not applied; the
                // host still runs the provisional one, so record that with
                // the retry deadline.
                let applied = inner
                    .applied
                    .as_ref()
                    .and_then(|(id, _)| from_ipc(*id))
                    .unwrap_or(p.pending);
                if let Err(e) = inner
                    .store
                    .mark_applied(applied, Some(again), "sensr-agent")
                {
                    tracing::error!(error = %e, "recording the rollback retry");
                }
                Some(retry)
            }
        }
    }

    /// Drives the commit-confirm deadline until `shutdown`.
    pub async fn run_confirm_timer(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        loop {
            let deadline = {
                let inner = self.inner.lock().await;
                inner
                    .store
                    .pending_confirm()
                    .ok()
                    .flatten()
                    .map(|p| p.deadline_ms)
            };
            let sleep = match deadline {
                Some(d) => Duration::from_millis((d - now_ms()).max(0) as u64),
                None => Duration::from_secs(3600),
            };
            tokio::select! {
                _ = tokio::time::sleep(sleep), if deadline.is_some() => {
                    self.expire_pending(false).await;
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
                let head = inner
                    .store
                    .history(1, None)
                    .map_err(internal)?
                    .first()
                    .map(info_of);
                Ok(Response::Status(Box::new(Status {
                    agent_version: env!("CARGO_PKG_VERSION").into(),
                    protocol: sensr_ipc::PROTOCOL_VERSION,
                    uptime_secs: self.started.elapsed().as_secs(),
                    head,
                    applied: inner.applied.as_ref().map(|(id, _)| *id),
                    candidate_dirty: Self::dirty(inner),
                    pending_confirm: inner
                        .store
                        .pending_confirm()
                        .map_err(internal)?
                        .map(ipc_pending),
                    last_apply_error: inner.last_apply_error.clone(),
                })))
            }
            Op::ConfigGet { path, source } => {
                let doc = self.masked(inner, source)?;
                Ok(Response::Value(path.lookup(&doc).cloned()))
            }
            Op::ConfigSet { path, value } => self.edit(inner, |v| {
                path.assign(v, value)
                    .map_err(|e| err(ErrorKind::BadRequest, e.to_string()))
            }),
            Op::ConfigDelete { path } => {
                if path.is_root() {
                    return Err(err(
                        ErrorKind::BadRequest,
                        "the document root cannot be deleted; load or discard instead",
                    ));
                }
                self.edit(inner, |v| match path.remove(v) {
                    Some(_) => Ok(()),
                    None => Err(err(ErrorKind::NotFound, format!("{path} does not exist"))),
                })
            }
            Op::ConfigLoad { document } => {
                if !document.is_object() {
                    return Err(err(
                        ErrorKind::BadRequest,
                        "a config document must be a JSON object",
                    ));
                }
                // A whole document replaces the candidate; problems it
                // brings along are reported at commit.
                let current =
                    View::of(&self.resolve(inner, Source::Candidate)?.unwrap_or_default());
                let mut v = document;
                redact::restore(&mut v, &current);
                let mut doc = decode(&v)?;
                if redact::drop_unbacked(&mut v, &doc) {
                    doc = decode(&v)?;
                }
                inner.set_candidate(Some(doc));
                Ok(Response::Staged {
                    dirty: Self::dirty(inner),
                })
            }
            Op::ConfigDiscard => {
                inner.set_candidate(None);
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
                let rev = inner
                    .store
                    .confirm(&principal.revision_username())
                    .map_err(internal)?
                    .ok_or_else(|| {
                        err(ErrorKind::Conflict, "no commit is waiting for confirmation")
                    })?;
                self.confirm_changed.notify_one();
                let _ = self.events.send(Event::Confirmed(to_ipc(rev)));
                Ok(Response::Confirmed(to_ipc(rev)))
            }
            Op::ConfigRollback { to } => {
                let head = inner.store.history(1, None).map_err(internal)?;
                let target = match to {
                    Some(t) => t,
                    None => head
                        .first()
                        .and_then(|h| h.parent)
                        .map(to_ipc)
                        .ok_or_else(|| err(ErrorKind::NotFound, "head has no earlier revision"))?,
                };
                let had_pending = inner.store.pending_confirm().map_err(internal)?.is_some();
                let meta = meta_of(principal, format!("rollback to revision {target}"));
                // A restore supersedes any pending confirm.
                let revision = self
                    .commit_doc(inner, Write::Restore(target), meta, |_| None)
                    .await?;
                if had_pending {
                    self.confirm_changed.notify_one();
                }
                Ok(Response::Committed(Box::new(CommitOutcome {
                    revision,
                    pending_confirm: None,
                })))
            }
            Op::ConfigHistory { limit } => Ok(Response::History(
                inner
                    .store
                    .history(limit.unwrap_or(50) as usize, None)
                    .map_err(internal)?
                    .iter()
                    .map(info_of)
                    .collect(),
            )),
            Op::ConfigDiff { from, to } => {
                let a = self.masked(inner, from)?;
                let b = self.masked(inner, to)?;
                Ok(Response::Diff(crate::diff::diff(
                    &a,
                    &b,
                    &label(from),
                    &label(to),
                )))
            }
            Op::ApplyDryRun { source } => {
                let next = self.resolve(inner, source)?.unwrap_or_default();
                let running = inner.applied.as_ref().map(|(_, d)| d);
                inner
                    .applier
                    .plan(running, &next)
                    .map(Response::Plan)
                    .map_err(apply_error)
            }
            Op::Authenticate {
                credential,
                remote_addr,
            } => {
                let head = View::of(&inner.head.1).value;
                crate::auth::authenticate(&head, &credential, remote_addr)
                    .map(Response::Authenticated)
                    .ok_or_else(|| err(ErrorKind::Unauthenticated, "invalid credentials"))
            }
            Op::Subscribe => Err(err(ErrorKind::BadRequest, "subscribe opens a stream")),
            Op::WebListener => {
                // What runs, not what is staged: the listener moves when a
                // change is applied.
                let doc = inner.applied.as_ref().map_or(&inner.head.1, |(_, d)| d);
                self.tls
                    .listener(doc)
                    .map(|l| Response::WebListener(Box::new(l)))
                    .map_err(|e| err(ErrorKind::Internal, e.to_string()))
            }
            Op::Runtime { section } => Ok(Response::Value(inner.applier.runtime(section))),
        }
    }

    async fn commit(
        &self,
        inner: &mut Inner<A>,
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
        let Some(doc) = inner.candidate.clone().filter(|_| Self::dirty(inner)) else {
            return Err(err(ErrorKind::Conflict, "nothing to commit"));
        };
        let pending = inner.store.pending_confirm().map_err(internal)?;
        // Fall back to the last *confirmed* revision: a pending one was never
        // shown to keep management reachable.
        let known_good = pending
            .map(|p| p.rollback_to)
            .or_else(|| inner.applied.as_ref().and_then(|(id, _)| from_ipc(*id)));
        let description = description.unwrap_or_else(|| "sensr config commit".into());
        let revision = self
            .commit_doc(
                inner,
                Write::Commit(Box::new(doc)),
                meta_of(principal, description),
                |id| match (window, known_good) {
                    (Some(w), Some(rollback_to)) => Some(ConfirmState {
                        pending: from_ipc(id)?,
                        rollback_to,
                        deadline_ms: now_ms() + w.as_millis() as i64,
                    }),
                    // A plain commit on top of a provisional one confirms
                    // nothing; the old deadline still stands.
                    _ => pending,
                },
            )
            .await?;
        let pending_confirm = inner.store.pending_confirm().map_err(internal)?;
        if window.is_some() {
            self.confirm_changed.notify_one();
        }
        Ok(Response::Committed(Box::new(CommitOutcome {
            revision,
            pending_confirm: pending_confirm.map(ipc_pending),
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

fn meta_of(principal: &Principal, description: String) -> CommitMeta {
    CommitMeta {
        username: principal.revision_username(),
        description,
        impersonated_by: principal.impersonated_by.clone(),
        user_apitoken: match &principal.via {
            AuthMethod::ApiKey { key } => Some(key.clone()),
            _ => None,
        },
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
        ApplyError::Invalid(validations) => validation(validations),
        ApplyError::Failed(m) => err(ErrorKind::ApplyFailed, m),
    }
}

impl<A: Applier> Handler for Agent<A> {
    async fn handle(&self, peer: PeerCred, req: Request) -> Reply {
        if matches!(req.op, Op::Authenticate { .. }) && !self.is_trusted_peer(peer) {
            return Response::Error(err(
                ErrorKind::Forbidden,
                "authentication is reserved for sensr-api",
            ))
            .into();
        }
        if matches!(req.op, Op::WebListener) && !self.is_trusted_peer(peer) {
            return Response::Error(err(
                ErrorKind::Forbidden,
                "the web GUI key is reserved for sensr-api",
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
        Op::WebListener => "web_listener",
        Op::Runtime { .. } => "runtime",
    }
}

async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|s| *s).await;
}
