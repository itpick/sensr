//! The typed request/response vocabulary spoken between clients
//! (`sensr-api`, the `sensr` CLI) and `sensr-agent`.
//!
//! Documents travel as JSON values: JSON is sensr's config interchange format
//! (docs/PLAN.md §2.1), so the IPC layer stays independent of the typed
//! `Document` in `sensr-config` and of schema versions.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::path::ConfigPath;

/// Identifies a stored config revision. Revisions are numbered from 1 in
/// commit order and never reused.
pub type RevisionId = u64;

/// Who a request is made on behalf of. The agent records it in revision
/// metadata (OPNsense-compatible `username` / `impersonated_by` /
/// `user_apitoken`) and re-checks it against the peer's socket credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// Login name (`root`, `admin`, …).
    pub user: String,
    /// How the principal was authenticated.
    pub via: AuthMethod,
    /// The operator acting through this principal, if any.
    pub impersonated_by: Option<String>,
    /// Holds OPNsense's `user-config-readonly` privilege: may read, never write.
    pub readonly: bool,
}

impl Principal {
    /// A principal for a local Unix user talking to the socket directly.
    pub fn unix(user: impl Into<String>, uid: u32) -> Self {
        Self {
            user: user.into(),
            via: AuthMethod::Unix { uid },
            impersonated_by: None,
            readonly: false,
        }
    }

    /// The OPNsense revision `username` string, e.g. `root@unix` or
    /// `admin@api`.
    pub fn revision_username(&self) -> String {
        let via = match self.via {
            AuthMethod::Unix { .. } => "unix",
            AuthMethod::Password => "ui",
            AuthMethod::ApiKey { .. } => "api",
            AuthMethod::System => "system",
        };
        format!("{}@{via}", self.user)
    }
}

/// How a [`Principal`] proved its identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    /// Local socket peer; identity taken from `SO_PEERCRED`.
    Unix {
        /// Peer uid as reported by the kernel.
        uid: u32,
    },
    /// Username + password checked by the agent.
    Password,
    /// OPNsense-style `key:secret` API key.
    ApiKey {
        /// The public key half (never the secret).
        key: String,
    },
    /// The agent itself (boot apply, confirm-timeout rollback).
    System,
}

/// One request frame body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    /// On whose behalf.
    pub principal: Principal,
    /// What to do.
    pub op: Op,
}

/// Which document a read addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Source {
    /// The staged candidate (head plus uncommitted `set`s); equals head when
    /// nothing is staged.
    #[default]
    Candidate,
    /// The newest committed revision.
    Head,
    /// The revision the running system was last applied from.
    Applied,
    /// A specific stored revision.
    Revision(RevisionId),
}

/// A credential presented to [`Op::Authenticate`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Credential {
    /// Local user password.
    Password {
        /// Login name.
        user: String,
        /// Clear-text password (only ever inside the local socket).
        password: String,
    },
    /// OPNsense-style API key pair.
    ApiKey {
        /// Public key.
        key: String,
        /// Secret.
        secret: String,
    },
}

impl std::fmt::Debug for Credential {
    // Secrets must never reach a log line through `{:?}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password { user, .. } => write!(f, "Password {{ user: {user:?}, .. }}"),
            Self::ApiKey { key, .. } => write!(f, "ApiKey {{ key: {key:?}, .. }}"),
        }
    }
}

/// The operations the agent serves.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Op {
    /// Liveness probe.
    Ping,
    /// Agent, store and commit-confirm state.
    Status,
    /// Read the value at `path` in `source`.
    ConfigGet {
        /// Where.
        path: ConfigPath,
        /// Which document.
        source: Source,
    },
    /// Stage `value` at `path` in the candidate.
    ConfigSet {
        /// Where.
        path: ConfigPath,
        /// The new value.
        value: Value,
    },
    /// Stage removal of `path` from the candidate.
    ConfigDelete {
        /// Where.
        path: ConfigPath,
    },
    /// Replace the whole candidate (import, restore from file).
    ConfigLoad {
        /// The new candidate document.
        document: Value,
    },
    /// Throw away staged changes.
    ConfigDiscard,
    /// Store the candidate as a new revision and apply it. With `confirm`,
    /// the apply is provisional and reverts unless confirmed in time.
    ConfigCommit {
        /// Revision description (OPNsense `revision/description`).
        description: Option<String>,
        /// Seconds to wait for [`Op::ConfigConfirm`] before rolling back.
        confirm_secs: Option<u32>,
    },
    /// Make a provisional commit permanent.
    ConfigConfirm,
    /// Re-apply an earlier revision as a new revision. With `to: None`, the
    /// parent of the current head.
    ConfigRollback {
        /// Target revision.
        to: Option<RevisionId>,
    },
    /// Newest-first revision list.
    ConfigHistory {
        /// At most this many entries.
        limit: Option<u32>,
    },
    /// Differences between two documents.
    ConfigDiff {
        /// Old side.
        from: Source,
        /// New side.
        to: Source,
    },
    /// Plan the apply of `source` against what is running, without touching
    /// the system.
    ApplyDryRun {
        /// What would be applied.
        source: Source,
    },
    /// Verify a credential against the local user database.
    Authenticate {
        /// What was presented.
        credential: Credential,
        /// The client's address as seen by the API, for group
        /// `source_networks` restrictions.
        #[serde(default)]
        remote_addr: Option<std::net::IpAddr>,
    },
    /// Stream [`Event`]s until cancelled.
    Subscribe,
}

impl Op {
    /// True for operations that change state and so require a principal
    /// without the read-only privilege.
    pub fn is_write(&self) -> bool {
        matches!(
            self,
            Op::ConfigSet { .. }
                | Op::ConfigDelete { .. }
                | Op::ConfigLoad { .. }
                | Op::ConfigDiscard
                | Op::ConfigCommit { .. }
                | Op::ConfigConfirm
                | Op::ConfigRollback { .. }
        )
    }
}

/// Revision metadata (OPNsense `<revision>` element plus sensr fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionInfo {
    /// Revision number.
    pub id: RevisionId,
    /// The revision this one was derived from.
    pub parent: Option<RevisionId>,
    /// Content hash of the canonical document (hex).
    pub hash: String,
    /// OPNsense-style `user@via` string.
    pub username: String,
    /// Commit time, milliseconds since the Unix epoch.
    pub time_ms: i64,
    /// Free-text description.
    pub description: String,
    /// Operator acting through `username`, if any.
    pub impersonated_by: Option<String>,
}

/// One changed leaf or subtree between two documents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Change {
    /// Where.
    pub path: ConfigPath,
    /// Old value, absent when added.
    pub before: Option<Value>,
    /// New value, absent when removed.
    pub after: Option<Value>,
}

/// Structured and textual differences between two documents.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Diff {
    /// Changed paths, in document order.
    pub changes: Vec<Change>,
    /// Unified diff of the pretty-printed canonical JSON.
    pub unified: String,
}

/// What a service unit will do during an apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceAction {
    /// Start a unit that was not running.
    Start,
    /// Stop a unit that is no longer configured.
    Stop,
    /// Reload in place (`ExecReload`).
    Reload,
    /// Full restart.
    Restart,
}

/// A planned change to one wrapped daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceChange {
    /// systemd unit name, e.g. `kea-dhcp4-server.service`.
    pub unit: String,
    /// What happens to it.
    pub action: ServiceAction,
    /// Rendered config files that changed, with unified diffs.
    pub files: Vec<FileDiff>,
}

/// A unified diff of one rendered file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDiff {
    /// Target path, e.g. `/run/sensr/kea/kea-dhcp4.conf`.
    pub path: String,
    /// Unified diff text (empty when unchanged).
    pub unified: String,
}

/// The dry-run result: what an apply would change.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PlanView {
    /// Unified diff of the nftables ruleset (running vs planned).
    pub nft: String,
    /// Network operations in execution order, one line each.
    pub net: Vec<String>,
    /// Service changes.
    pub services: Vec<ServiceChange>,
}

impl PlanView {
    /// True when applying would change nothing.
    pub fn is_empty(&self) -> bool {
        self.nft.is_empty() && self.net.is_empty() && self.services.is_empty()
    }
}

/// A provisional commit waiting for confirmation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingConfirm {
    /// The provisional revision.
    pub revision: RevisionId,
    /// What is re-applied on timeout.
    pub rollback_to: RevisionId,
    /// Deadline, milliseconds since the Unix epoch.
    pub deadline_ms: i64,
}

/// Agent status snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// `sensr-agent` crate version.
    pub agent_version: String,
    /// IPC protocol version the agent speaks.
    pub protocol: u16,
    /// Seconds since the agent started.
    pub uptime_secs: u64,
    /// Newest committed revision.
    pub head: Option<RevisionInfo>,
    /// Revision the running system was applied from.
    pub applied: Option<RevisionId>,
    /// True when the candidate differs from head.
    pub candidate_dirty: bool,
    /// Outstanding commit-confirm, if any.
    pub pending_confirm: Option<PendingConfirm>,
    /// Message of the last failed apply, cleared by the next success.
    pub last_apply_error: Option<String>,
}

/// Outcome of a commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitOutcome {
    /// The new revision.
    pub revision: RevisionInfo,
    /// Present when the commit is provisional.
    pub pending_confirm: Option<PendingConfirm>,
}

/// A successfully authenticated identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthInfo {
    /// Login name.
    pub user: String,
    /// Numeric user id from the config document.
    pub uid: u32,
    /// Group names the user belongs to.
    pub groups: Vec<String>,
    /// Effective privilege names (user and group privileges, deduplicated).
    pub privileges: Vec<String>,
}

/// Asynchronous notifications delivered on a [`Op::Subscribe`] stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    /// A new revision was stored.
    RevisionCommitted(RevisionInfo),
    /// A revision was applied to the running system.
    Applied(RevisionId),
    /// A provisional commit was confirmed.
    Confirmed(RevisionId),
    /// A provisional commit timed out and was rolled back.
    RolledBack {
        /// The revision that was abandoned.
        abandoned: RevisionId,
        /// The new revision that restores the previous state.
        restored: RevisionInfo,
    },
}

/// Field-level validation failure (OPNsense `validations` map entry).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationIssue {
    /// Dotted path of the offending field.
    pub path: String,
    /// Human-readable message (ends with a period, T-0361).
    pub message: String,
}

/// Machine-readable error class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorKind {
    /// The frame or request could not be decoded.
    BadRequest,
    /// Client and agent speak incompatible protocol versions.
    VersionMismatch,
    /// Credentials missing or wrong.
    Unauthenticated,
    /// Principal lacks the privilege.
    Forbidden,
    /// Path, revision or object does not exist.
    NotFound,
    /// The candidate failed validation.
    Validation,
    /// The request conflicts with current state (e.g. nothing to commit,
    /// nothing to confirm, a confirm already pending).
    Conflict,
    /// The apply pipeline failed; the previous state stays in force.
    ApplyFailed,
    /// A bug or I/O failure in the agent.
    Internal,
}

/// An error returned by the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{kind:?}: {message}")]
pub struct IpcError {
    /// Class.
    pub kind: ErrorKind,
    /// Human-readable message.
    pub message: String,
    /// Per-field validation messages, for [`ErrorKind::Validation`].
    pub validations: Vec<ValidationIssue>,
}

impl IpcError {
    /// An error without field details.
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            validations: Vec::new(),
        }
    }
}

/// One response frame body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Response {
    /// Reply to [`Op::Ping`].
    Pong,
    /// Reply to [`Op::Status`].
    Status(Box<Status>),
    /// A document or subtree; `None` when the path is absent.
    Value(Option<Value>),
    /// The candidate changed; `dirty` tells whether it now differs from head.
    Staged {
        /// Candidate differs from head.
        dirty: bool,
    },
    /// Reply to [`Op::ConfigCommit`] and [`Op::ConfigRollback`].
    Committed(Box<CommitOutcome>),
    /// Reply to [`Op::ConfigConfirm`].
    Confirmed(RevisionId),
    /// Reply to [`Op::ConfigHistory`].
    History(Vec<RevisionInfo>),
    /// Reply to [`Op::ConfigDiff`].
    Diff(Diff),
    /// Reply to [`Op::ApplyDryRun`].
    Plan(PlanView),
    /// Reply to [`Op::Authenticate`].
    Authenticated(AuthInfo),
    /// The request opened a stream; items follow as stream frames.
    StreamOpened,
    /// The request failed.
    Error(IpcError),
}
