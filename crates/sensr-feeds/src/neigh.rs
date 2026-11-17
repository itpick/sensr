//! The neighbour table for MAC aliases (`arpcache.py`): `ip -j neigh show`.

use std::net::IpAddr;

/// `(mac, address)` pairs of reachable/stale neighbours; failed and
/// incomplete entries have no MAC and are skipped.
pub fn parse_ip_neigh_json(json: &[u8]) -> Vec<(String, IpAddr)> {
    #[derive(serde::Deserialize)]
    struct Entry {
        dst: Option<IpAddr>,
        lladdr: Option<String>,
        #[serde(default)]
        state: Vec<String>,
    }
    let entries: Vec<Entry> = serde_json::from_slice(json).unwrap_or_default();
    entries
        .into_iter()
        .filter(|e| !e.state.iter().any(|s| s == "FAILED" || s == "INCOMPLETE"))
        .filter_map(|e| Some((e.lladdr?.to_ascii_lowercase(), e.dst?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reachable_and_stale_entries() {
        let j = br#"[
          {"dst":"192.168.1.10","dev":"igc1","lladdr":"02:00:5E:10:00:0A","state":["REACHABLE"]},
          {"dst":"192.168.1.11","dev":"igc1","state":["FAILED"]},
          {"dst":"fe80::1","dev":"igc1","lladdr":"02:00:5e:10:00:0b","router":null,"state":["STALE"]}
        ]"#;
        let v = parse_ip_neigh_json(j);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].0, "02:00:5e:10:00:0a");
        assert!(parse_ip_neigh_json(b"not json").is_empty());
    }
}
