//! What the agent renders for `sensr-scan` (`/run/sensr/portscan/portscan.json`).

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Where the agent writes the daemon's configuration.
pub const CONFIG_PATH: &str = "/run/sensr/portscan/portscan.json";
/// The daemon's state directory.
pub const DB_DIR: &str = "/var/lib/sensr-scan";
/// Scan result database file name, in [`DB_DIR`].
pub const DB: &str = "scans.db";
/// The unix socket the daemon serves [`crate::proto`] on.
pub const SOCKET: &str = "/run/sensr-scan/scan.sock";

/// The daemon's configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Scanning allowed at all.
    pub enabled: bool,
    /// Scan newly seen devices automatically.
    pub auto_scan_new: bool,
    /// How hard to scan.
    pub pace: Pace,
    /// Scan results kept per target.
    pub history: u16,
    /// Largest range (addresses) accepted without refusal.
    pub max_range: u32,
    /// Devices never scanned.
    pub exclude: Vec<Exclude>,
    /// Networks that count as local (besides the private ranges).
    pub local: Vec<IpNet>,
    /// The router's own addresses, never scanned.
    pub router: Vec<IpAddr>,
}

impl Config {
    /// Whether the device at `ip` (with `mac`, if known) is on the exclude
    /// list. MACs compare case-insensitively.
    #[must_use]
    pub fn excludes(&self, ip: IpAddr, mac: Option<&str>) -> bool {
        self.exclude.iter().any(|e| match e {
            Exclude::Mac(m) => mac.is_some_and(|x| x.eq_ignore_ascii_case(m)),
            Exclude::Addr(a) => *a == ip,
        })
    }
}

/// Scan speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pace {
    /// Quiet: for small or fragile networks. What the router ships with.
    Gentle,
    /// Faster, for networks that can take it.
    Normal,
    /// As fast as is polite.
    Fast,
}

/// The limits a [`Pace`] stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaceLimits {
    /// Connection attempts started per second.
    pub connects_per_sec: u32,
    /// Attempts outstanding at once.
    pub in_flight: u16,
}

impl Pace {
    /// The rate limits for this pace.
    #[must_use]
    pub fn limits(self) -> PaceLimits {
        let (connects_per_sec, in_flight) = match self {
            Self::Gentle => (200, 64),
            Self::Normal => (1000, 256),
            Self::Fast => (5000, 512),
        };
        PaceLimits {
            connects_per_sec,
            in_flight,
        }
    }
}

/// A device excluded from scanning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exclude {
    /// By MAC address.
    Mac(String),
    /// By IP address.
    Addr(IpAddr),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gentle_limits_are_200_and_64() {
        let l = Pace::Gentle.limits();
        assert_eq!((l.connects_per_sec, l.in_flight), (200, 64));
    }

    #[test]
    fn paces_get_faster() {
        let (g, n, f) = (
            Pace::Gentle.limits(),
            Pace::Normal.limits(),
            Pace::Fast.limits(),
        );
        assert!(g.connects_per_sec < n.connects_per_sec && n.connects_per_sec < f.connects_per_sec);
        assert!(g.in_flight < n.in_flight && n.in_flight < f.in_flight);
    }

    #[test]
    fn excludes_by_address_or_mac() {
        let cfg = Config {
            enabled: true,
            auto_scan_new: true,
            pace: Pace::Gentle,
            history: 10,
            max_range: 4096,
            exclude: vec![
                Exclude::Mac("AA:BB:CC:DD:EE:FF".into()),
                Exclude::Addr("192.168.1.9".parse().unwrap()),
            ],
            local: vec![],
            router: vec![],
        };
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(cfg.excludes(ip("192.168.1.9"), None));
        assert!(cfg.excludes(ip("192.168.1.5"), Some("aa:bb:cc:dd:ee:ff")));
        assert!(!cfg.excludes(ip("192.168.1.5"), Some("aa:bb:cc:dd:ee:00")));
        assert!(!cfg.excludes(ip("192.168.1.5"), None));
    }

    #[test]
    fn config_round_trips_and_rejects_unknown_fields() {
        let cfg = Config {
            enabled: true,
            auto_scan_new: false,
            pace: Pace::Normal,
            history: 10,
            max_range: 4096,
            exclude: vec![
                Exclude::Mac("aa:bb:cc:dd:ee:ff".into()),
                Exclude::Addr("192.168.1.9".parse().unwrap()),
            ],
            local: vec!["10.9.0.0/16".parse().unwrap()],
            router: vec!["192.168.1.1".parse().unwrap()],
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains(r#""pace":"normal""#));
        assert_eq!(serde_json::from_str::<Config>(&json).unwrap(), cfg);

        let bad = json.replacen('{', r#"{"bogus":1,"#, 1);
        assert!(serde_json::from_str::<Config>(&bad).is_err());
    }
}
