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
    /// A problem the operator must know about on every page (a first-boot
    /// seed that did not import).
    #[serde(default)]
    pub alert: Option<String>,
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

/// A network card on the host (Interfaces › Assignments).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCard {
    /// Current kernel name.
    pub name: String,
    /// The MAC an assignment binds to.
    pub mac: String,
    /// Kernel driver.
    pub driver: Option<String>,
    /// Bus and position (`pci 0000:01:00.0`, `usb 2-1:1.0`).
    pub bus: Option<String>,
    /// Link up, with speed in Mbit/s when known.
    pub link: Option<(bool, Option<u32>)>,
    /// Interface the card carries.
    pub assigned: Option<String>,
}

impl NetworkCard {
    /// The label in the device list: `enp1s0 (52:54:00:aa:00:01, igc, up 1000M)`.
    pub fn label(&self) -> String {
        let mut parts = vec![self.mac.clone()];
        parts.extend(self.driver.clone());
        match self.link {
            Some((true, Some(s))) => parts.push(format!("up {s}M")),
            Some((true, None)) => parts.push("up".into()),
            Some((false, _)) => parts.push("no carrier".into()),
            None => {}
        }
        if let Some(b) = &self.bus {
            parts.push(b.clone());
        }
        format!("{} ({})", self.name, parts.join(", "))
    }
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
    /// All interfaces together from the traffic database (Reporting › Insight), when
    /// sensr-insight has written one.
    #[serde(default)]
    pub history: Option<TrafficHistory>,
}

/// One bucket of a traffic series (bytes in the bucket, not a rate).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficPoint {
    /// Bucket start, seconds since the Unix epoch.
    pub ts: i64,
    /// Bucket length in seconds.
    pub res: i64,
    /// Bytes sent (out of the interface, or by the local host).
    pub up: u64,
    /// Bytes received.
    pub down: u64,
}

impl TrafficPoint {
    /// Average receive rate over the bucket, bits/s.
    pub fn down_bps(&self) -> u64 {
        self.down.saturating_mul(8) / self.res.max(1).unsigned_abs()
    }
    /// Average send rate over the bucket, bits/s.
    pub fn up_bps(&self) -> u64 {
        self.up.saturating_mul(8) / self.res.max(1).unsigned_abs()
    }
}

/// The dashboard traffic graph: every interface summed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficHistory {
    /// The last ten minutes of 10 s samples.
    pub live: Vec<TrafficPoint>,
    /// The last hour at one minute.
    pub hour: Vec<TrafficPoint>,
}

/// A ranked row of Reporting › Insight (a host, service, remote or interface).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficRow {
    /// Address, `proto/port`, or interface id.
    pub key: String,
    /// What to show (the interface's description, a service name); empty to show the key.
    pub label: String,
    /// Bytes sent.
    pub up: u64,
    /// Bytes received.
    pub down: u64,
    /// Packets sent.
    pub up_packets: u64,
    /// Packets received.
    pub down_packets: u64,
}

impl TrafficRow {
    /// Bytes both ways.
    pub fn total(&self) -> u64 {
        self.up.saturating_add(self.down)
    }
}

/// Reporting › Insight for one time range (and optionally one local host).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsightReport {
    /// The traffic database exists.
    pub available: bool,
    /// Range start, seconds since the Unix epoch.
    pub from: i64,
    /// Range end.
    pub to: i64,
    /// Bucket length the range is shown at, seconds.
    pub resolution: i64,
    /// Top local hosts.
    pub hosts: Vec<TrafficRow>,
    /// Top services (of the selected host, or of every host).
    pub apps: Vec<TrafficRow>,
    /// Top remote addresses.
    pub remotes: Vec<TrafficRow>,
    /// Interface totals.
    pub ifaces: Vec<TrafficRow>,
    /// Traffic over time: the selected host's, or every interface's.
    pub series: Vec<TrafficPoint>,
}

/// Reporting › Insight time ranges: query value, label, length in seconds.
pub const INSIGHT_RANGES: &[(&str, &str, i64)] = &[
    ("2h", "2 hours", 2 * 3_600),
    ("24h", "24 hours", 86_400),
    ("7d", "7 days", 7 * 86_400),
    ("31d", "31 days", 31 * 86_400),
    ("1y", "1 year", 365 * 86_400),
];

/// The range named `q`, or 24 hours.
pub fn insight_range(q: &str) -> (&'static str, &'static str, i64) {
    INSIGHT_RANGES
        .iter()
        .copied()
        .find(|(k, _, _)| *k == q)
        .unwrap_or(INSIGHT_RANGES[1])
}

/// One IDS alert (Services › Intrusion Detection › Alerts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRow {
    /// Database id.
    pub id: i64,
    /// Time, milliseconds since the Unix epoch.
    pub ts: i64,
    /// Generator id.
    pub gid: u32,
    /// Signature id.
    pub sid: u32,
    /// Signature message.
    pub signature: String,
    /// Classification.
    pub category: String,
    /// Severity, 1 (high) to 4.
    pub severity: u8,
    /// `allowed` or `blocked`.
    pub action: String,
    /// Transport protocol.
    pub proto: String,
    /// Source address.
    pub src_ip: String,
    /// Source port.
    pub src_port: Option<u16>,
    /// Destination address.
    pub dest_ip: String,
    /// Destination port.
    pub dest_port: Option<u16>,
    /// Interface (kernel device).
    pub iface: String,
    /// An active (or staged) suppression already silences it.
    pub suppressed: bool,
}

/// One page of alerts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertPage {
    /// The alert database exists.
    pub available: bool,
    /// Alerts on this page, newest first.
    pub rows: Vec<AlertRow>,
    /// Alerts matching the filter.
    pub total: u64,
    /// Zero-based page.
    pub page: u32,
    /// Alerts per page.
    pub per_page: u32,
}

/// One downloaded list of a blocklist policy, as of the last refresh.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsblSource {
    /// Where it was fetched from.
    pub url: String,
    /// Names it contributed.
    pub entries: u64,
    /// When it was last downloaded (RFC 3339); `None` if never.
    pub fetched: Option<String>,
    /// Served from the local cache instead of downloaded this time.
    pub from_cache: bool,
    /// Why the last download failed, if it did.
    pub error: Option<String>,
}

/// One blocklist policy as compiled by the last refresh.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsblPolicy {
    /// The policy's UUID in `dns.blocklists`.
    pub id: String,
    /// Its description.
    pub description: String,
    /// Distinct names it blocks.
    pub names: u64,
    /// Its lists.
    pub sources: Vec<DnsblSource>,
}

/// What the last blocklist refresh produced (`status.json` of sensr-dns).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsblStatus {
    /// When the refresh finished (RFC 3339).
    pub updated: String,
    /// How long it took.
    pub duration_ms: u64,
    /// Names in force across all policies.
    pub names: u64,
    /// Per policy.
    pub policies: Vec<DnsblPolicy>,
}

/// Unbound's own counters (`unbound-control stats`, sampled every minute).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UnboundCounters {
    /// When they were sampled (RFC 3339).
    pub at: String,
    /// Queries answered.
    pub queries: u64,
    /// Answered from the cache.
    pub cache_hits: u64,
    /// Answered NXDOMAIN.
    pub nxdomain: u64,
    /// Resolver uptime.
    pub uptime_seconds: f64,
}

/// Everything the blocklist page shows about the running resolver. `None` means the file
/// has not been written yet.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DnsStats {
    /// Last blocklist refresh.
    pub blocklists: Option<DnsblStatus>,
    /// Resolver counters.
    pub unbound: Option<UnboundCounters>,
    /// Files that exist but could not be read.
    pub problems: Vec<String>,
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
        /// The host's network cards.
        fn nics(&self) -> BoxFuture<'_, ApiResult<Vec<NetworkCard>>>;
        /// Blocklist and resolver statistics. The default reads the files sensr-dns and the
        /// stats timer write on this host (see [`crate::dnsstats`]).
        fn dns_stats(&self) -> BoxFuture<'_, ApiResult<DnsStats>> {
            Box::pin(async { Ok(crate::dnsstats::DnsStatsPaths::from_env().read()) })
        }
        /// Run-time state of one subsystem as the agent reports it (`null` when the
        /// subsystem is not running). Parse with [`crate::runtime::parse`].
        fn runtime(
            &self,
            section: crate::runtime::RuntimeSection,
        ) -> BoxFuture<'_, ApiResult<Value>>;
        /// Whether the caller's privileges cover `url` (an API path such as
        /// `/api/v1/ids/alerts`). Data the UI reads itself (the traffic and alert databases)
        /// is checked against the same ACL entries as the REST routes serving it.
        fn may_access(&self, url: &str) -> bool {
            let _ = url;
            true
        }
        /// Directory holding sensr-insight's `flows.db` and `alerts.db`: `SENSR_INSIGHT_DIR`
        /// when set (as for sensr-api), else the daemon's default.
        fn insight_dir(&self) -> std::path::PathBuf {
            std::env::var_os("SENSR_INSIGHT_DIR").map_or_else(
                || std::path::PathBuf::from(sensr_flow::config::DB_DIR),
                std::path::PathBuf::from,
            )
        }
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
