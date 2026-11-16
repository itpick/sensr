//! Gateway monitor: the sensr counterpart of OPNsense's dpinger instances
//! plus the gateway watcher that turns their numbers into a status.
//!
//! The crate is layered so that every decision is a pure function that tests
//! drive with synthetic time:
//!
//! - [`MonitorSettings`]: per-gateway probe timing and thresholds with the
//!   OPNsense defaults.
//! - [`ProbeWindow`]: the probe history of one target, reduced to a
//!   [`Sample`] (average latency, standard deviation, loss) over the time
//!   period.
//! - [`evaluate`]: sample and thresholds to a [`Status`], exactly the way
//!   OPNsense maps dpinger output (`none`, `delay`, `loss`, `delay+loss`,
//!   `down`, `force_down`).
//! - [`select_group`] and [`select_default_gateway`]: which gateways carry
//!   traffic given their statuses.
//! - [`Prober`] / [`ProberFactory`]: the probe transport, with
//!   [`IcmpFactory`] (ICMP / ICMPv6 echo over raw or ping sockets) as the real
//!   implementation.
//! - [`Monitor`]: the tokio driver that runs one probe loop per gateway and
//!   publishes [`Snapshot`]s and [`StatusChanged`] events.
//!
//! Behaviour derived from upstream, and where sensr deviates, is documented
//! in `docs/monitor.md` next to this crate.

mod default_gw;
mod group;
#[cfg(unix)]
mod icmp;
mod monitor;
pub mod packet;
mod prober;
mod settings;
mod stats;
mod status;

use serde::{Deserialize, Serialize};

pub use default_gw::{DefaultCandidate, select_default_gateway};
pub use group::{ActiveMember, GroupMember, GroupSelection, Trigger, select_group};
#[cfg(unix)]
pub use icmp::{IcmpFactory, IcmpProber, SocketKind};
pub use monitor::{GatewayConfig, GatewayState, Monitor, MonitorError, Snapshot, StatusChanged};
pub use prober::{ProbeSpec, Prober, ProberFactory, Reply};
pub use settings::{MonitorSettings, SettingsError};
pub use stats::{ProbeWindow, Sample};
pub use status::{Status, evaluate};

/// Address family of a gateway (OPNsense `ipprotocol`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    /// IPv4 (`inet`).
    Inet,
    /// IPv6 (`inet6`).
    Inet6,
}

impl Family {
    /// The family of `addr`.
    pub fn of(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(_) => Self::Inet,
            std::net::IpAddr::V6(_) => Self::Inet6,
        }
    }
}
