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
            AuthMethod::External { .. } => "oidc",
            AuthMethod::Passkey => "passkey",
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
    /// An external identity (OpenID Connect), after the ID token was checked.
    External {
        /// Provider object id.
        provider: String,
    },
    /// A WebAuthn assertion the API checked against the stored passkey.
    Passkey,
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
        /// TOTP code, when the account has two-factor login enabled. Old
        /// clients may instead append it to `password`, as OPNsense does.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        otp: Option<String>,
    },
    /// OPNsense-style API key pair.
    ApiKey {
        /// Public key.
        key: String,
        /// Secret.
        secret: String,
    },
    /// A local account whose passkey assertion the API verified. The agent
    /// only resolves the account, its groups and its privileges.
    Passkey {
        /// Login name.
        user: String,
    },
    /// An identity an OpenID Connect provider authenticated for us. The API
    /// has already validated the ID token; the agent applies the provider's
    /// claim→group mapping from the configuration.
    External {
        /// Provider object id in `system.oidc.providers`.
        provider: String,
        /// Verified ID-token claims (boxed: the request frame stays small).
        claims: Box<serde_json::Value>,
    },
}

impl std::fmt::Debug for Credential {
    // Secrets must never reach a log line through `{:?}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password { user, .. } => write!(f, "Password {{ user: {user:?}, .. }}"),
            Self::ApiKey { key, .. } => write!(f, "ApiKey {{ key: {key:?}, .. }}"),
            Self::Passkey { user } => write!(f, "Passkey {{ user: {user:?} }}"),
            Self::External { provider, .. } => {
                write!(f, "External {{ provider: {provider:?} }}")
            }
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
    /// The web GUI listener and its TLS material (trusted peers only: the
    /// reply carries a private key).
    WebListener,
    /// The network cards on the host, with the interface each one carries.
    Nics,
    /// Bind interfaces to NICs by MAC in the candidate (Interfaces ›
    /// Assignments): each interface gets `match_mac` and, when its device
    /// name is one the kernel or udev could also hand out, a stable name.
    InterfacesAssign {
        /// What goes where.
        assignments: Vec<Assignment>,
    },
    /// Run-time state of a subsystem (never part of the configuration):
    /// answered with [`Response::Value`].
    Runtime {
        /// Which subsystem.
        section: RuntimeSection,
    },
    /// Drop an unreserved host from the inventory (Hosts › Forget). It
    /// reappears on the next poll if it is still on the network.
    HostForget {
        /// The host key: the lowercase MAC, else `id:<client id>`.
        key: String,
    },
    /// Put a host in a mode, or back to Normal (Hosts › Mode): writes or
    /// removes its `firewall.host_modes` entry. Commits and applies at once
    /// when nothing else is staged and no commit awaits confirmation;
    /// otherwise only stages. Answered with [`Response::Value`]
    /// `{"result": "applied" | "staged"}`.
    HostModeSet {
        /// The host's MAC address.
        mac: String,
        /// The new mode; `None` is Normal (the entry is removed).
        mode: Option<HostModeMode>,
        /// The client's address as seen by the API: quarantining the device
        /// the request comes from is refused.
        #[serde(default)]
        remote_addr: Option<std::net::IpAddr>,
    },
    /// Set what a host is called (Hosts › Label): writes or removes its
    /// `hosts.labels` entry. Both fields `None` removes it. Commits and
    /// applies at once when nothing else is staged and no commit awaits
    /// confirmation; otherwise only stages. Answered with
    /// [`Response::Value`] `{"result": "applied" | "staged"}`.
    HostLabelSet {
        /// The host's MAC address.
        mac: String,
        /// The owner's kind, replacing the guess; `None` keeps the guess.
        #[serde(default)]
        kind: Option<sensr_schema::models::hosts::HostKind>,
        /// The owner's maker, replacing the guess (trimmed; blank is `None`).
        #[serde(default)]
        maker: Option<String>,
    },
}

/// A host mode other than Normal, for [`Op::HostModeSet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostModeMode {
    /// Reaches the router and the internet but no other local host.
    Isolated,
    /// Reaches only the router's DHCP, DNS and NTP.
    Quarantine,
}

/// Subsystems with run-time state the UI shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuntimeSection {
    /// Gateway monitor: status, latency, loss, active group members.
    Gateways,
    /// Alias feeds: entries, last update, errors.
    Aliases,
    /// IPv6 prefix delegation: delegated prefix, lifetimes, per-LAN prefixes.
    Ipv6,
    /// Host inventory: every device seen on an internal network.
    Hosts,
}

/// One interface-to-NIC binding for [`Op::InterfacesAssign`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assignment {
    /// Interface id (`wan`, `lan`, `opt1`); created when missing.
    pub interface: String,
    /// The NIC: its MAC address or its current kernel name.
    pub nic: String,
}

/// A network card found on the host (sysfs), for assignment pages and
/// `sensr interfaces`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nic {
    /// Current kernel name.
    pub name: String,
    /// Current MAC address.
    pub mac: String,
    /// Burnt-in MAC when it differs from `mac` (spoofed); what pins match.
    #[serde(default)]
    pub permanent_mac: Option<String>,
    /// Kernel driver (`igc`, `r8152`, `virtio_net`).
    #[serde(default)]
    pub driver: Option<String>,
    /// Bus the card sits on (`pci`, `usb`, `platform`, ...).
    #[serde(default)]
    pub bus: Option<String>,
    /// Where on that bus (`0000:01:00.0`, `2-1:1.0`): changes when the card
    /// moves, which is exactly what pins must not depend on.
    #[serde(default)]
    pub bus_path: Option<String>,
    /// Negotiated speed in Mbit/s while the link is up.
    #[serde(default)]
    pub speed_mbps: Option<u32>,
    /// Carrier detected.
    #[serde(default)]
    pub carrier: Option<bool>,
    /// Kernel operational state (`up`, `down`, `dormant`, ...).
    pub operstate: String,
    /// The interface id this card carries, if assigned.
    #[serde(default)]
    pub assigned: Option<String>,
}

impl Nic {
    /// The MAC a pin matches: the permanent one when known.
    pub fn pin_mac(&self) -> &str {
        self.permanent_mac.as_deref().unwrap_or(&self.mac)
    }
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
                | Op::InterfacesAssign { .. }
                | Op::HostForget { .. }
                | Op::HostModeSet { .. }
                | Op::HostLabelSet { .. }
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
    /// What went wrong with the first-boot seed folder (an import that did
    /// not validate, a partial import), so the UI can say so.
    #[serde(default)]
    pub seed_error: Option<String>,
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
    /// Reply to [`Op::WebListener`].
    WebListener(Box<WebListener>),
    /// Reply to [`Op::Nics`].
    Nics(Vec<Nic>),
    /// The request failed.
    Error(IpcError),
}

/// Where and how sensr-api serves the web GUI (from `system.webgui` of the
/// applied document), with the certificate to present.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebListener {
    /// TLS; `false` serves plain HTTP.
    pub https: bool,
    /// The GUI port.
    pub port: u16,
    /// A plain-HTTP listener that redirects to HTTPS, when enabled.
    pub redirect_port: Option<u16>,
    /// Kernel devices to listen on (`lo` included); empty means all.
    pub devices: Vec<String>,
    /// PEM certificate chain, leaf first.
    pub cert_chain_pem: String,
    /// PEM private key of the leaf.
    pub key_pem: String,
    /// PEM of the local CA that signed a generated certificate, for
    /// clients to trust; `None` for a trust-store certificate.
    pub ca_pem: Option<String>,
    /// Where the certificate comes from (`generated` or the trust-store
    /// certificate's description).
    pub certificate: String,
}

impl std::fmt::Debug for WebListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebListener")
            .field("https", &self.https)
            .field("port", &self.port)
            .field("redirect_port", &self.redirect_port)
            .field("devices", &self.devices)
            .field("certificate", &self.certificate)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_forget_is_write() {
        assert!(Op::HostForget { key: "x".into() }.is_write());
        assert!(
            !Op::Runtime {
                section: RuntimeSection::Hosts
            }
            .is_write()
        );
    }

    #[test]
    fn host_mode_set_is_write() {
        assert!(
            Op::HostModeSet {
                mac: "x".into(),
                mode: None,
                remote_addr: None
            }
            .is_write()
        );
        let v = serde_json::to_value(Some(HostModeMode::Quarantine)).unwrap();
        assert_eq!(v, serde_json::json!("quarantine"));
    }

    #[test]
    fn host_label_set_is_write() {
        assert!(
            Op::HostLabelSet {
                mac: "x".into(),
                kind: None,
                maker: None
            }
            .is_write()
        );
    }
}
