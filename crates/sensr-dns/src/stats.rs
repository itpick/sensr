//! Resolver counters for the web UI (`unbound-stats.json`).
//!
//! Unbound counts queries, cache hits and answers by rcode; it has no
//! counter for answers from a blocklist's local zones, so the UI shows the
//! blocklist's size and the resolver's totals, not a blocked-query count.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// `unbound-stats.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnboundStats {
    /// When sampled (RFC 3339).
    pub at: String,
    /// Queries since start.
    pub queries: u64,
    /// Of those, answered from cache (local data included).
    pub cache_hits: u64,
    /// NXDOMAIN answers (needs `extended-statistics`; 0 otherwise).
    pub nxdomain: u64,
    /// Resolver uptime.
    pub uptime_seconds: f64,
}

impl UnboundStats {
    /// From `stats_noreset` output.
    pub fn from_counters(c: &BTreeMap<String, f64>, at: String) -> Self {
        let n = |k: &str| c.get(k).copied().unwrap_or(0.0) as u64;
        Self {
            at,
            queries: n("total.num.queries"),
            cache_hits: n("total.num.cachehits"),
            nxdomain: n("num.answer.rcode.NXDOMAIN"),
            uptime_seconds: c.get("time.up").copied().unwrap_or(0.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::parse_stats;

    #[test]
    fn counters_map() {
        let c = parse_stats(
            "total.num.queries=10\ntotal.num.cachehits=9\nnum.answer.rcode.NXDOMAIN=1\ntime.up=1.5\n",
        );
        let s = UnboundStats::from_counters(&c, "t".into());
        assert_eq!((s.queries, s.cache_hits, s.nxdomain), (10, 9, 1));
        assert_eq!(s.uptime_seconds, 1.5);
    }
}
