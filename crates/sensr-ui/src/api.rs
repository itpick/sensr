//! The UI's view of the sensr API: wire types shared with the browser, and (server side) the
//! [`Backend`] trait the pages are written against.
//!
//! The trait mirrors the sensr-api REST surface (config get/set/commit/history/diff plus status,
//! run-time views and sessions) so the mock in [`crate::mock`] and the HTTP client can be
//! swapped without the pages noticing.

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

/// One OpenID Connect provider offered on the login page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginProvider {
    /// Object id.
    pub id: String,
    /// Button text.
    pub name: String,
    /// Where the login page sends the browser, for example
    /// `/ui/oidc/start/{id}` or `/ui/saml/start/{id}`.
    pub start: String,
}

/// What the browser should do to reach the identity provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoginStart {
    /// Follow this URL (HTTP-Redirect binding).
    Redirect(String),
    /// POST these hidden fields to this URL (HTTP-POST binding).
    Form {
        /// Form action.
        action: String,
        /// Hidden fields, in order.
        fields: Vec<(String, String)>,
    },
}

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
    /// Set when the commit is provisional (the caller asked, or the agent
    /// imposed a window): the revision rolls back unless confirmed.
    #[serde(default)]
    pub confirm: Option<ConfirmWindow>,
    /// Why the agent imposed a confirm window the caller did not ask for.
    #[serde(default)]
    pub confirm_reason: Option<String>,
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
    /// Problems the operator must know about on every page (a first-boot
    /// seed that did not import, a daemon the boot apply held back), one
    /// `Label: message` per line.
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
    /// When each sample was taken, seconds since the Unix epoch.
    #[serde(default)]
    pub ts: Vec<i64>,
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
    /// Gateways, from the gateway monitor's run-time view (filled by the dashboard's
    /// server function, so backends leave it empty).
    #[serde(default)]
    pub gateways: Vec<crate::runtime::GatewayRow>,
    /// Recent traffic per interface.
    pub traffic: Vec<TrafficSeries>,
    /// All interfaces together from the traffic database (Reporting › Insight), when
    /// sensr-insight has written one.
    #[serde(default)]
    pub history: Option<TrafficHistory>,
}

impl SystemStatus {
    /// The uplink's current IPv4 address without its prefix length (the public address
    /// when the ISP's gateway passes it through), or `None` while it holds none. The
    /// uplink is the interface assigned as WAN.
    pub fn wan_ipv4(&self) -> Option<&str> {
        self.interfaces
            .iter()
            .find(|i| i.name.eq_ignore_ascii_case("wan"))?
            .ipv4
            .as_deref()
            .map(|a| a.split_once('/').map_or(a, |(ip, _)| ip))
    }
}

#[cfg(test)]
mod wan_tests {
    use super::*;

    fn iface(name: &str, ipv4: Option<&str>) -> InterfaceStatus {
        InterfaceStatus {
            name: name.into(),
            device: "eth0".into(),
            up: true,
            speed_mbps: None,
            ipv4: ipv4.map(Into::into),
            ipv6: None,
            rx_bps: 0,
            tx_bps: 0,
        }
    }

    fn status(interfaces: Vec<InterfaceStatus>) -> SystemStatus {
        SystemStatus {
            hostname: String::new(),
            version: String::new(),
            kernel: String::new(),
            cpu_model: String::new(),
            uptime_secs: 0,
            cpu_pct: 0.0,
            load: [0.0; 3],
            mem_used: 0,
            mem_total: 0,
            interfaces,
            gateways: Vec::new(),
            traffic: Vec::new(),
            history: None,
        }
    }

    #[test]
    fn wan_ipv4_is_the_wan_interfaces_address_without_prefix() {
        let s = status(vec![
            iface("LAN", Some("192.168.1.1/24")),
            iface("WAN", Some("203.0.113.45/22")),
        ]);
        assert_eq!(s.wan_ipv4(), Some("203.0.113.45"));
    }

    #[test]
    fn wan_ipv4_is_none_without_a_wan_or_its_address() {
        assert_eq!(
            status(vec![iface("LAN", Some("192.168.1.1/24"))]).wan_ipv4(),
            None
        );
        assert_eq!(status(vec![iface("WAN", None)]).wan_ipv4(), None);
    }
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

/// A device's DNS activity page: its header (from the host inventory) and what it did over
/// a range (`today` or `7d`). Category fields are keys of [`crate::runtime::CATEGORIES`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostActivityView {
    /// MAC address, lowercase.
    pub mac: String,
    /// What the host is called.
    pub name: Option<String>,
    /// What the router thinks it is.
    pub label: Option<crate::runtime::HostLabelView>,
    /// IPv4 address.
    pub ipv4: Option<String>,
    /// IPv6 addresses.
    pub ipv6: Vec<String>,
    /// `isolated` or `quarantine`; `None` is Normal.
    pub mode: Option<String>,
    /// Last sighting, seconds since the epoch.
    pub last_seen: Option<u64>,
    /// Currently on the network.
    pub online: bool,
    /// `today` or `7d`.
    pub range: String,
    /// Start of the range (Unix seconds).
    pub from: i64,
    /// End of the range.
    pub to: i64,
    /// Router local time minus UTC, in seconds (what days and hours are in).
    pub utc_offset: i64,
    /// The insight database has DNS activity data at all.
    pub available: bool,
    /// The dnstap feed is stale: lookups only, no minutes.
    pub feed_stale: bool,
    /// Newest dnstap frame (Unix seconds).
    pub last_frame: Option<i64>,
    /// Screen-time minutes in the range.
    pub screen_time: u32,
    /// Minutes per service, largest first.
    pub services: Vec<ActivityService>,
    /// Minutes per category, largest first.
    pub categories: Vec<ActivityCategory>,
    /// Screen-time minutes per local hour.
    pub timeline: Vec<ActivityCell>,
    /// One page of looked-up names, most queried first.
    pub domains: Vec<ActivityDomain>,
    /// Names looked up in the range, over all pages.
    pub domains_total: u32,
    /// The page shown, from 0.
    pub page: u32,
    /// Names per page.
    pub per_page: u32,
}

/// Active minutes of one service.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ActivityService {
    /// Service name.
    pub service: String,
    /// Category key.
    pub category: String,
    /// Active minutes.
    pub minutes: u32,
}

/// Active minutes of one category.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ActivityCategory {
    /// Category key.
    pub category: String,
    /// Active minutes.
    pub minutes: u32,
}

/// One hour of the timeline.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ActivityCell {
    /// Local day, as days since 1970-01-01.
    pub day: i64,
    /// Local hour, 0-23.
    pub hour: u8,
    /// Screen-time minutes in it.
    pub minutes: u32,
}

/// One name a device looked up (untrusted text).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ActivityDomain {
    /// The name.
    pub qname: String,
    /// Lookups in the range.
    pub count: u64,
    /// First lookup ever kept (Unix seconds).
    pub first_seen: i64,
    /// Latest lookup.
    pub last_seen: i64,
    /// Its service.
    pub service: String,
    /// Category key.
    pub category: String,
    /// First seen within the last 24 hours.
    pub new: bool,
    /// Answered by a blocklist.
    pub blocked: bool,
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
    /// Whether query logging is on, so the page can explain an empty list.
    #[serde(default)]
    pub log_queries: bool,
    /// Most frequently queried names since the sampler started.
    #[serde(default)]
    pub top_domains: Vec<DnsHit>,
    /// Most active clients since the sampler started.
    #[serde(default)]
    pub top_clients: Vec<DnsHit>,
    /// The most recent queries, newest first.
    #[serde(default)]
    pub recent: Vec<RecentQuery>,
    /// Queries read from the query log since the sampler started.
    #[serde(default)]
    pub logged_queries: u64,
}

/// A name or client and how often it was seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsHit {
    /// Domain name (with its trailing dot) or client address.
    pub name: String,
    /// Queries counted.
    pub count: u64,
}

/// One logged query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentQuery {
    /// When the sampler saw it (RFC 3339).
    pub at: String,
    /// Client address.
    pub client: String,
    /// Queried name.
    pub name: String,
    /// Query type.
    pub kind: String,
}

/// What a lease record says about its own validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    /// Offered and not expired.
    Active,
    /// Past its expiry.
    Expired,
    /// Handed back by the client.
    Released,
    /// The client said the address was already in use.
    Declined,
    /// Reclaimed after an expiry.
    Reclaimed,
}

/// One DHCPv4 lease from Kea's memfile database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpLease {
    /// Address handed out.
    pub address: String,
    /// Client hardware address, when the lease has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Client identifier (option 61), hex, when the lease has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// Host name the client asked for or the router registered.
    #[serde(default)]
    pub hostname: String,
    /// Kea's subnet id for the lease.
    pub subnet_id: u32,
    /// Unix time the lease expires.
    pub expire: u64,
    /// State as recorded.
    pub state: LeaseState,
    /// Whether a static reservation already covers this client in the configuration.
    #[serde(default)]
    pub reserved: bool,
}

impl DhcpLease {
    /// Whether the lease is live right now.
    pub fn active(&self) -> bool {
        self.state == LeaseState::Active
    }
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
        /// DHCPv4 leases as Kea recorded them on this host. The default reads the lease
        /// files (see [`crate::leases`]).
        fn dhcp_leases(&self) -> BoxFuture<'_, ApiResult<Vec<DhcpLease>>> {
            Box::pin(async { Ok(crate::leases::read_now()) })
        }
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
        /// Directory holding sensr-scan's `scans.db`: `SENSR_SCAN_DIR` when set (as for
        /// sensr-api), else the daemon's default.
        fn scan_dir(&self) -> std::path::PathBuf {
            std::env::var_os("SENSR_SCAN_DIR").map_or_else(
                || std::path::PathBuf::from(sensr_scan::config::DB_DIR),
                std::path::PathBuf::from,
            )
        }
        /// sensr-scan's control socket: `SENSR_SCAN_SOCKET` when set, else the daemon's
        /// default.
        fn scan_socket(&self) -> std::path::PathBuf {
            std::env::var_os("SENSR_SCAN_SOCKET").map_or_else(
                || std::path::PathBuf::from(sensr_scan::config::SOCKET),
                std::path::PathBuf::from,
            )
        }
        /// Sends one request to sensr-scan's control socket ([`Backend::scan_socket`]). A
        /// socket that cannot be used is [`ApiError::Backend`] with
        /// [`crate::portscan::NOT_RUNNING`] (the cause is logged). The caller checks the
        /// port scanner privileges.
        fn portscan(
            &self,
            req: sensr_scan::proto::Request,
        ) -> BoxFuture<'_, ApiResult<sensr_scan::proto::Reply>> {
            let sock = self.scan_socket();
            Box::pin(async move {
                let run = move || sensr_scan::client::send(&sock, &req);
                // Off the async threads when there is a runtime (not in the component tests).
                let r = if tokio::runtime::Handle::try_current().is_ok() {
                    tokio::task::spawn_blocking(run)
                        .await
                        .map_err(|e| ApiError::Backend(e.to_string()))?
                } else {
                    run()
                };
                r.map_err(|e| {
                    tracing::warn!(error = %e, "sensr-scan control socket");
                    ApiError::Backend(crate::portscan::NOT_RUNNING.to_owned())
                })
            })
        }
        /// Run-time state of one subsystem as the agent reports it (`null` when the
        /// subsystem is not running). Parse with [`crate::runtime::parse`].
        fn runtime(
            &self,
            section: crate::runtime::RuntimeSection,
        ) -> BoxFuture<'_, ApiResult<Value>>;
        /// One device's DNS activity over `range` (`today` or `7d`), domains page `page` from
        /// 0. The caller needs the hosts and insight privileges; an unknown MAC is
        /// [`ApiError::NotFound`], a bad range [`ApiError::Validation`].
        fn host_activity(
            &self,
            mac: String,
            range: String,
            page: u32,
        ) -> BoxFuture<'_, ApiResult<HostActivityView>>;
        /// Drops an unreserved host from the inventory (`key` as in
        /// [`crate::runtime::HostRow::key`]); it comes back if it is still on the network.
        fn forget_host(&self, key: String) -> BoxFuture<'_, ApiResult<()>>;
        /// Puts the host with `mac` in `mode` (`isolated`, `quarantine`; `None` or
        /// `normal` for Normal). `remote` is the client's address: quarantining the
        /// device the request comes from is refused ([`ApiError::Conflict`]). Returns
        /// `applied` when it took effect at once, `staged` when it waits for Apply.
        fn set_host_mode(
            &self,
            mac: String,
            mode: Option<String>,
            remote: Option<std::net::IpAddr>,
        ) -> BoxFuture<'_, ApiResult<String>>;
        /// Sets what a host is called (`hosts.labels`): `kind` is a kind name
        /// (`camera`, `smart_home`, ...), `maker` free text; both `None` clears the
        /// label. Returns `applied` when it took effect at once, `staged` when it
        /// waits for Apply.
        fn set_host_label(
            &self,
            mac: String,
            kind: Option<String>,
            maker: Option<String>,
        ) -> BoxFuture<'_, ApiResult<String>>;
        /// Sets what the domain `suffix` counts as on the DNS activity page
        /// (`insight.dns.service_overrides`): `service` a name, `category` a
        /// [`crate::runtime::CATEGORIES`] key; both `None` removes the override. Returns
        /// `applied` when it took effect at once, `staged` when it waits for Apply.
        fn set_service_override(
            &self,
            suffix: String,
            service: Option<String>,
            category: Option<String>,
        ) -> BoxFuture<'_, ApiResult<String>>;
        /// The caller may read but not change anything (`user-config-readonly`), so the
        /// UI hides actions that would be refused.
        fn read_only(&self) -> bool {
            false
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
            otp: Option<&'a str>,
        ) -> BoxFuture<'a, ApiResult<String>>;
        /// The session behind `token`, if it is valid.
        fn open<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Option<Session>>;
        /// Ends session `token`.
        fn logout<'a>(&'a self, token: &'a str) -> BoxFuture<'a, ()>;
        /// OpenID Connect providers offered on the login page.
        fn oidc_providers(&self) -> BoxFuture<'_, Vec<LoginProvider>> {
            Box::pin(async { Vec::new() })
        }
        /// Starts an authorization; returns the provider URL to send the browser to.
        fn oidc_start<'a>(
            &'a self,
            provider: &'a str,
            callback: &'a str,
        ) -> BoxFuture<'a, ApiResult<String>> {
            let _ = (provider, callback);
            Box::pin(async { Err(ApiError::Unauthorized) })
        }
        /// Completes an authorization and returns the new session token.
        fn oidc_finish<'a>(
            &'a self,
            params: &'a std::collections::HashMap<String, String>,
            remote: Option<std::net::IpAddr>,
        ) -> BoxFuture<'a, ApiResult<String>> {
            let _ = (params, remote);
            Box::pin(async { Err(ApiError::Unauthorized) })
        }
        /// SAML providers offered on the login page.
        fn saml_providers(&self) -> BoxFuture<'_, Vec<LoginProvider>> {
            Box::pin(async { Vec::new() })
        }
        /// Starts a SAML authorization.
        fn saml_start<'a>(
            &'a self,
            provider: &'a str,
            base: &'a str,
        ) -> BoxFuture<'a, ApiResult<LoginStart>> {
            let _ = (provider, base);
            Box::pin(async { Err(ApiError::Unauthorized) })
        }
        /// Completes a SAML authorization and returns the new session token.
        fn saml_finish<'a>(
            &'a self,
            provider: &'a str,
            fields: &'a std::collections::HashMap<String, String>,
            base: &'a str,
            remote: Option<std::net::IpAddr>,
        ) -> BoxFuture<'a, ApiResult<String>> {
            let _ = (provider, fields, base, remote);
            Box::pin(async { Err(ApiError::Unauthorized) })
        }
        /// The service provider metadata for `provider`.
        fn saml_metadata<'a>(
            &'a self,
            provider: &'a str,
            base: &'a str,
        ) -> BoxFuture<'a, ApiResult<String>> {
            let _ = (provider, base);
            Box::pin(async { Err(ApiError::Unauthorized) })
        }
        /// Starts passkey registration; returns `{state, options}`.
        fn passkey_register_start<'a>(
            &'a self,
            user: &'a str,
            user_uuid: &'a str,
            base: &'a str,
            exclude: &'a [String],
        ) -> BoxFuture<'a, ApiResult<serde_json::Value>> {
            let _ = (user, user_uuid, base, exclude);
            Box::pin(async { Err(ApiError::Unauthorized) })
        }
        /// Verifies a registration and returns the credential to store.
        fn passkey_register_finish<'a>(
            &'a self,
            user_uuid: &'a str,
            state: &'a str,
            credential: &'a serde_json::Value,
            base: &'a str,
        ) -> BoxFuture<'a, ApiResult<serde_json::Value>> {
            let _ = (user_uuid, state, credential, base);
            Box::pin(async { Err(ApiError::Unauthorized) })
        }
        /// Starts a passkey login; returns `{state, options}`.
        fn passkey_login_start<'a>(
            &'a self,
            base: &'a str,
        ) -> BoxFuture<'a, ApiResult<serde_json::Value>> {
            let _ = base;
            Box::pin(async { Err(ApiError::Unauthorized) })
        }
        /// Verifies a passkey login and returns the new session token.
        fn passkey_login_finish<'a>(
            &'a self,
            state: &'a str,
            credential: &'a serde_json::Value,
            base: &'a str,
            remote: Option<std::net::IpAddr>,
        ) -> BoxFuture<'a, ApiResult<String>> {
            let _ = (state, credential, base, remote);
            Box::pin(async { Err(ApiError::Unauthorized) })
        }
    }

    /// Shared handle the server finds in Leptos context.
    pub type SessionsHandle = Arc<dyn Sessions>;
}
