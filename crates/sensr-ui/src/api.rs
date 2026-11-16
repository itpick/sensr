//! The UI's view of the sensr API: wire types shared with the browser, and (server side) the
//! [`Backend`] trait the pages are written against.
//!
//! The trait mirrors the sensr-api REST surface (config get/set/commit/history/diff plus status
//! and sessions) so the mock in [`crate::mock`] and the HTTP client can be swapped without the
//! pages noticing.

use serde::{Deserialize, Serialize};

/// A validation message attached to a field path (dot-separated, relative to the edited model).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldError {
    /// Field path, e.g. `content` or `ipv4.address`. Empty for errors not tied to one field.
    pub path: String,
    /// Human-readable message shown under the field.
    pub message: String,
}

impl FieldError {
    /// Builds an error for `path`.
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

/// Errors a backend call can return.
#[derive(Debug, Clone, PartialEq, thiserror::Error, Serialize, Deserialize)]
pub enum ApiError {
    /// The submitted value was rejected; one message per field path.
    #[error("validation failed")]
    Validation(Vec<FieldError>),
    /// The path, revision or object does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// Bad credentials or no valid session.
    #[error("unauthorized")]
    Unauthorized,
    /// The operation is not possible in the current state (e.g. confirm with nothing pending).
    #[error("conflict: {0}")]
    Conflict(String),
    /// Transport or backend failure.
    #[error("backend error: {0}")]
    Backend(String),
}

/// Result alias for backend calls.
pub type ApiResult<T> = Result<T, ApiError>;

/// One committed configuration revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revision {
    /// Monotonic revision number.
    pub id: u64,
    /// Commit time, seconds since the Unix epoch.
    pub time: u64,
    /// Who committed it.
    pub user: String,
    /// Commit message.
    pub message: String,
}

/// A commit that rolls back automatically unless confirmed before the deadline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmWindow {
    /// The revision awaiting confirmation.
    pub revision: u64,
    /// Rollback deadline, seconds since the Unix epoch.
    pub deadline: u64,
}

/// Staged-but-uncommitted state, which drives the "Apply" banner.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    /// Top-level config paths with staged changes.
    pub changed: Vec<String>,
    /// Set while a commit-confirm window is open.
    pub confirm: Option<ConfirmWindow>,
    /// Server time when this was produced, so the browser can count down without clock skew.
    pub now: u64,
}

impl Pending {
    /// True when there is something to apply.
    pub fn dirty(&self) -> bool {
        !self.changed.is_empty()
    }
}

/// Kind of a line in a revision diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffKind {
    /// Present in both.
    Context,
    /// Only in the newer side.
    Added,
    /// Only in the older side.
    Removed,
}

/// One line of a unified diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffLine {
    /// Added, removed or unchanged.
    pub kind: DiffKind,
    /// The line, without its newline.
    pub text: String,
}

/// Link state of an interface as shown on the dashboard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InterfaceStatus {
    /// Assignment name, e.g. `WAN`.
    pub name: String,
    /// Kernel device, e.g. `eth0`.
    pub device: String,
    /// Carrier up.
    pub up: bool,
    /// Link speed in Mbit/s, if known.
    pub speed_mbps: Option<u32>,
    /// Primary IPv4 address with prefix.
    pub ipv4: Option<String>,
    /// Primary global IPv6 address with prefix.
    pub ipv6: Option<String>,
    /// Receive rate, bits/s.
    pub rx_bps: u64,
    /// Transmit rate, bits/s.
    pub tx_bps: u64,
}

/// Gateway health as monitored by the routing layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatewayHealth {
    /// Probes answer within thresholds.
    Online,
    /// Latency or loss above the warning threshold.
    Degraded,
    /// No answers.
    Down,
}

/// One monitored gateway.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GatewayStatus {
    /// Gateway name, e.g. `WAN_DHCP`.
    pub name: String,
    /// Interface it belongs to.
    pub interface: String,
    /// Gateway address.
    pub address: String,
    /// Round-trip time in milliseconds.
    pub rtt_ms: f32,
    /// Packet loss in percent.
    pub loss_pct: f32,
    /// Health classification.
    pub health: GatewayHealth,
}

/// A traffic sample for one interface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrafficSeries {
    /// Interface name.
    pub name: String,
    /// Receive rates, oldest first, bits/s.
    pub rx: Vec<u64>,
    /// Transmit rates, oldest first, bits/s.
    pub tx: Vec<u64>,
}

/// Everything the dashboard shows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemStatus {
    /// Hostname.domain.
    pub hostname: String,
    /// sensr version string.
    pub version: String,
    /// Kernel version.
    pub kernel: String,
    /// CPU model.
    pub cpu_model: String,
    /// Uptime in seconds.
    pub uptime_secs: u64,
    /// CPU usage, 0..=100.
    pub cpu_pct: f32,
    /// 1, 5 and 15 minute load averages.
    pub load: [f32; 3],
    /// Used memory in bytes.
    pub mem_used: u64,
    /// Total memory in bytes.
    pub mem_total: u64,
    /// Interfaces, in assignment order.
    pub interfaces: Vec<InterfaceStatus>,
    /// Gateways.
    pub gateways: Vec<GatewayStatus>,
    /// Recent traffic per interface.
    pub traffic: Vec<TrafficSeries>,
}

#[cfg(feature = "ssr")]
pub use server::*;

#[cfg(feature = "ssr")]
mod server {
    use super::*;
    use futures::future::BoxFuture;
    use serde_json::Value;
    use std::sync::Arc;

    /// The operations the UI needs from sensr-api.
    ///
    /// Paths are dot-separated object keys into the config document (`firewall.alias`).
    /// `set` stages a change; nothing takes effect until `commit`.
    pub trait Backend: Send + Sync + 'static {
        /// Reads the staged value at `path` (committed value if nothing is staged).
        fn get<'a>(&'a self, path: &'a str) -> BoxFuture<'a, ApiResult<Value>>;
        /// Stages `value` at `path`.
        fn set<'a>(&'a self, path: &'a str, value: Value) -> BoxFuture<'a, ApiResult<()>>;
        /// What is staged and whether a confirm window is open.
        fn pending(&self) -> BoxFuture<'_, ApiResult<Pending>>;
        /// Commits the staged document. With `confirm_secs`, the commit rolls back on its own
        /// unless [`Backend::confirm`] is called in time.
        fn commit<'a>(
            &'a self,
            user: &'a str,
            message: &'a str,
            confirm_secs: Option<u32>,
        ) -> BoxFuture<'a, ApiResult<Revision>>;
        /// Keeps a commit made with a confirm window.
        fn confirm(&self) -> BoxFuture<'_, ApiResult<()>>;
        /// Drops all staged changes.
        fn discard(&self) -> BoxFuture<'_, ApiResult<()>>;
        /// Commits a new revision whose content equals revision `to`.
        fn rollback<'a>(&'a self, user: &'a str, to: u64) -> BoxFuture<'a, ApiResult<Revision>>;
        /// All revisions, newest first.
        fn history(&self) -> BoxFuture<'_, ApiResult<Vec<Revision>>>;
        /// Diff between two revisions; `to = None` means the staged document.
        fn diff(&self, from: u64, to: Option<u64>) -> BoxFuture<'_, ApiResult<Vec<DiffLine>>>;
        /// Live status for the dashboard.
        fn status(&self) -> BoxFuture<'_, ApiResult<SystemStatus>>;
    }

    /// A backend bound to one signed-in user (their identity and privileges travel with
    /// every call, so the agent enforces ACLs, not the UI).
    pub type BackendHandle = Arc<dyn Backend>;

    /// A signed-in session.
    #[derive(Clone)]
    pub struct Session {
        /// Login name.
        pub user: String,
        /// The backend acting as that user.
        pub backend: BackendHandle,
    }

    /// Logins and session tokens. sensr-api implements this over its session table; the
    /// mock keeps its own.
    pub trait Sessions: Send + Sync + 'static {
        /// Checks credentials and opens a session, returning its token.
        fn login<'a>(
            &'a self,
            user: &'a str,
            password: &'a str,
        ) -> BoxFuture<'a, ApiResult<String>>;
        /// The session behind `token`, if it is valid.
        fn open<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Option<Session>>;
        /// Ends session `token`.
        fn logout<'a>(&'a self, token: &'a str) -> BoxFuture<'a, ()>;
    }

    /// Shared handle the server finds in Leptos context.
    pub type SessionsHandle = Arc<dyn Sessions>;
}
