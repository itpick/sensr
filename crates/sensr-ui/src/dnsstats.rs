//! Blocklist and resolver statistics from the files sensr-dns writes on the firewall.
//!
//! Both are plain JSON, written atomically by their producers: the blocklist status after
//! every refresh, the Unbound counters by a timer once a minute. A missing file just means
//! "no data yet"; a file that does not parse is reported rather than shown as zeros.

use crate::api::{DnsStats, DnsblStatus, UnboundCounters};
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};

/// Default location of the blocklist refresh status.
pub const STATUS_PATH: &str = "/var/lib/sensr-dns/status.json";
/// Default location of the sampled Unbound counters.
pub const UNBOUND_STATS_PATH: &str = "/run/sensr-dns/unbound-stats.json";
/// Overrides [`STATUS_PATH`].
pub const STATUS_ENV: &str = "SENSR_DNS_STATUS";
/// Overrides [`UNBOUND_STATS_PATH`].
pub const UNBOUND_STATS_ENV: &str = "SENSR_DNS_UNBOUND_STATS";

/// Where to read the statistics from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsStatsPaths {
    /// Blocklist refresh status.
    pub status: PathBuf,
    /// Unbound counters.
    pub unbound: PathBuf,
}

impl Default for DnsStatsPaths {
    fn default() -> Self {
        Self {
            status: STATUS_PATH.into(),
            unbound: UNBOUND_STATS_PATH.into(),
        }
    }
}

fn read_json<T: DeserializeOwned>(path: &Path, problems: &mut Vec<String>) -> Option<T> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            problems.push(format!("{}: {e}", path.display()));
            return None;
        }
    };
    match serde_json::from_str(&text) {
        Ok(v) => Some(v),
        Err(e) => {
            problems.push(format!("{}: {e}", path.display()));
            None
        }
    }
}

impl DnsStatsPaths {
    /// The default paths, each overridable through its environment variable.
    pub fn from_env() -> Self {
        let d = Self::default();
        let var = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        Self {
            status: var(STATUS_ENV).unwrap_or(d.status),
            unbound: var(UNBOUND_STATS_ENV).unwrap_or(d.unbound),
        }
    }

    /// Reads both files.
    pub fn read(&self) -> DnsStats {
        let mut problems = Vec::new();
        let blocklists: Option<DnsblStatus> = read_json(&self.status, &mut problems);
        let unbound: Option<UnboundCounters> = read_json(&self.unbound, &mut problems);
        DnsStats {
            blocklists,
            unbound,
            problems,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_files_are_no_data_and_bad_files_are_reported() {
        let dir = std::env::temp_dir().join(format!("sensr-ui-dnsstats-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let paths = DnsStatsPaths {
            status: dir.join("status.json"),
            unbound: dir.join("unbound-stats.json"),
        };
        assert_eq!(paths.read(), DnsStats::default());

        std::fs::write(
            &paths.status,
            r#"{"updated":"2026-11-16T09:00:00Z","duration_ms":1234,"names":2,
               "policies":[{"id":"u1","description":"Default","names":2,
                 "sources":[{"url":"https://a/b","entries":2,"fetched":null,"from_cache":true,"error":"timed out"}]}]}"#,
        )
        .unwrap();
        std::fs::write(&paths.unbound, "{not json").unwrap();
        let s = paths.read();
        let b = s.blocklists.unwrap();
        assert_eq!((b.names, b.duration_ms), (2, 1234));
        let src = &b.policies[0].sources[0];
        assert_eq!(src.fetched, None);
        assert_eq!(src.error.as_deref(), Some("timed out"));
        assert!(s.unbound.is_none());
        assert_eq!(s.problems.len(), 1);
        assert!(s.problems[0].contains("unbound-stats.json"));

        std::fs::write(
            &paths.unbound,
            r#"{"at":"2026-11-16T09:01:00Z","queries":10,"cache_hits":4,"nxdomain":1,"uptime_seconds":61.5}"#,
        )
        .unwrap();
        let u = paths.read().unbound.unwrap();
        assert_eq!((u.queries, u.cache_hits, u.nxdomain), (10, 4, 1));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
