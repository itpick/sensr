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
    /// Most frequently queried names since the sampler started.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub top_domains: Vec<DnsHit>,
    /// Most active clients since the sampler started.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub top_clients: Vec<DnsHit>,
    /// The most recent queries, newest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recent: Vec<RecentQuery>,
    /// Queries read from the query log since the sampler started.
    #[serde(default)]
    pub logged_queries: u64,
    /// Whether the sampler reads the query log (Unbound `log-queries`).
    #[serde(default)]
    pub log_queries: bool,
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
            top_domains: Vec::new(),
            top_clients: Vec::new(),
            recent: Vec::new(),
            logged_queries: 0,
            log_queries: false,
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
