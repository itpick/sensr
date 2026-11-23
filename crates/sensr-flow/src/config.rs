//! What the agent renders for `sensr-insight` (`/run/sensr/insight/insight.json`).

use std::path::{Path, PathBuf};

use sensr_schema::models::insight::ServiceOverride;
use serde::{Deserialize, Serialize};

/// Where the agent writes the daemon's configuration.
pub const CONFIG_PATH: &str = "/run/sensr/insight/insight.json";
/// The daemon's databases (`flows.db`, `alerts.db`).
pub const DB_DIR: &str = "/var/lib/sensr-insight";
/// Flow database file name.
pub const FLOWS_DB: &str = "flows.db";
/// Alert database file name.
pub const ALERTS_DB: &str = "alerts.db";
/// The unix socket the daemon reads Unbound's dnstap stream from
/// (Unbound's `dnstap-socket-path`).
pub const DNSTAP_SOCKET: &str = "/run/sensr-insight/dnstap.sock";
/// The group of the dnstap socket: Unbound's and the daemon's users are
/// members, nobody else.
pub const DNSTAP_GROUP: &str = "sensr-dnstap";
/// The DNS feed's status file, in [`DB_DIR`] ([`DnsStatus`]).
pub const DNS_STATUS: &str = "dns-status.json";

/// The daemon's configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Traffic accounting (`None`: off).
    #[serde(default)]
    pub flows: Option<FlowConfig>,
    /// IDS alert storage (`None`: off).
    #[serde(default)]
    pub ids: Option<IdsConfig>,
}

/// An interface the daemon reports on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Iface {
    /// Logical name (`lan`, `wan`, `opt1`).
    pub name: String,
    /// Kernel device.
    pub device: String,
    /// Its hosts are accounted ("local").
    pub local: bool,
}

/// Retention per resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    /// Hours of 1-minute buckets.
    pub minute_hours: u32,
    /// Days of 1-hour buckets.
    pub hour_days: u32,
    /// Days of 1-day buckets.
    pub day_days: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            minute_hours: 48,
            hour_days: 62,
            day_days: 730,
        }
    }
}

/// Traffic accounting settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowConfig {
    /// Seconds between counter reads.
    pub sample_seconds: u32,
    /// Size of each kernel set.
    pub max_entries: u32,
    /// Every interface (rates for all, hosts behind the local ones).
    pub interfaces: Vec<Iface>,
    /// History.
    #[serde(default)]
    pub retention: Retention,
    /// Per-host DNS activity from Unbound's dnstap feed (`None`: off).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,
}

/// Per-host DNS activity settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// The dnstap socket to create and listen on.
    pub socket: PathBuf,
    /// Owner corrections of the service catalogue (enabled ones apply).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service_overrides: Vec<ServiceOverride>,
    /// Unbound's query log, read for lookups only while the dnstap feed is
    /// stale (`None`: query logging is off).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_log: Option<PathBuf>,
    /// Unbound's unit: the feed is stale only while it is active.
    #[serde(default = "unbound_unit")]
    pub unbound_unit: String,
}

fn unbound_unit() -> String {
    "sensr-unbound.service".into()
}

impl DnsConfig {
    /// The defaults for `socket`, with no overrides and no query log.
    pub fn new(socket: impl Into<PathBuf>) -> DnsConfig {
        DnsConfig {
            socket: socket.into(),
            service_overrides: Vec::new(),
            query_log: None,
            unbound_unit: unbound_unit(),
        }
    }
}

/// What the daemon reports about the dnstap feed ([`DNS_STATUS`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsStatus {
    /// No dnstap frames for 5 minutes while Unbound is active: lookups come
    /// from the query log, if any, and there are no service minutes.
    pub dns_feed_stale: bool,
    /// Unix seconds of the newest frame (`None`: none since the start).
    #[serde(default)]
    pub last_frame: Option<i64>,
}

impl DnsStatus {
    /// The status in database directory `dir`; a missing or damaged file
    /// reads as not stale.
    pub fn read(dir: &Path) -> DnsStatus {
        std::fs::read(dir.join(DNS_STATUS))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
}

/// IDS alert storage settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdsConfig {
    /// Suricata's eve.json.
    pub eve: PathBuf,
    /// Days of alerts kept.
    pub retention_days: u32,
    /// Most alerts kept.
    pub max_alerts: u64,
}
