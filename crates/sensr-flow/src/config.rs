//! What the agent renders for `sensr-insight` (`/run/sensr/insight/insight.json`).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Where the agent writes the daemon's configuration.
pub const CONFIG_PATH: &str = "/run/sensr/insight/insight.json";
/// The daemon's databases (`flows.db`, `alerts.db`).
pub const DB_DIR: &str = "/var/lib/sensr-insight";
/// Flow database file name.
pub const FLOWS_DB: &str = "flows.db";
/// Alert database file name.
pub const ALERTS_DB: &str = "alerts.db";

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
