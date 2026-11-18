//! Names for MAC aliases (`arpcache.py`): the neighbour table (`ip -j neigh
//! show`) and Kea's DHCPv4 leases.
//!
//! The leases matter on their own: a device that has just received its address
//! has not talked to the router yet, so there is no neighbour entry for it and
//! a rule "trusted MACs may reach the LAN" would drop its first packets until
//! something makes the box ARP it. OPNsense reads the DHCP lease file for the
//! same reason.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;

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

/// Active leased addresses from one Kea `lease4` CSV file, as `(mac,
/// address)`. Columns are located by the header line, as in
/// `sensr-dns`; records without a MAC are skipped, as are released and
/// expired ones.
pub fn parse_kea_lease_csv(text: &str, now: u64, into: &mut BTreeMap<IpAddr, String>) {
    let mut cols: BTreeMap<&str, usize> = BTreeMap::new();
    for line in text.lines() {
        if line.starts_with("address,") {
            cols = line
                .split(',')
                .enumerate()
                .map(|(i, f)| (f.trim(), i))
                .collect();
            continue;
        }
        let fields: Vec<&str> = line.split(',').collect();
        let get = |name: &str| cols.get(name).and_then(|&i| fields.get(i)).copied();
        let Some(address) = get("address").and_then(|a| a.trim().parse::<IpAddr>().ok()) else {
            continue;
        };
        let mac = get("hwaddr")
            .unwrap_or_default()
            .trim_matches('"')
            .to_ascii_lowercase();
        if mac.is_empty() {
            continue;
        }
        let num = |name: &str| get(name).and_then(|v| v.parse::<u64>().ok());
        let active = num("state").unwrap_or(0) == 0
            && num("valid_lifetime").unwrap_or(0) > 0
            && num("expire").unwrap_or(0) > now;
        if active {
            into.insert(address, mac);
        } else {
            into.remove(&address);
        }
    }
}

/// Leases from every file Kea's memfile backend may have written, in its load
/// order (`<file>.completed`, `.2`, `.1`, then `<file>`), as `(mac, address)`
/// pairs. A missing file is not an error.
pub fn read_kea_leases(base: &Path, now: u64) -> Vec<(String, IpAddr)> {
    let s = base.display().to_string();
    let mut leases = BTreeMap::new();
    for f in [
        format!("{s}.completed"),
        format!("{s}.2"),
        format!("{s}.1"),
        s.clone(),
    ] {
        if let Ok(text) = std::fs::read_to_string(&f) {
            parse_kea_lease_csv(&text, now, &mut leases);
        }
    }
    leases.into_iter().map(|(ip, mac)| (mac, ip)).collect()
}

#[cfg(test)]
mod lease_tests {
    use super::*;

    const HEADER: &str = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,\
                          fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id";

    #[test]
    fn active_leases_become_mac_addresses() {
        let text = format!(
            "{HEADER}\n\
             192.168.72.2,\"46:7E:11:F7:A6:1F\",\"01:46:7e:11:f7:a6:1f\",3600,2000000000,1,\
             0,0,trusted,0,,0\n\
             192.168.72.3,,\"01:aa\",3600,2000000000,1,0,0,nameless,0,,0\n"
        );
        let mut m = BTreeMap::new();
        parse_kea_lease_csv(&text, 1_700_000_000, &mut m);
        assert_eq!(
            m.into_iter().collect::<Vec<_>>(),
            vec![(
                "192.168.72.2".parse::<IpAddr>().unwrap(),
                "46:7e:11:f7:a6:1f".to_string()
            )]
        );
    }

    #[test]
    fn released_expired_and_rewritten_leases_are_not_offered() {
        let text = format!(
            "{HEADER}\n\
             10.0.0.2,02:00:00:00:00:02,x,0,2000000000,1,0,0,a,0,,0\n\
             10.0.0.3,02:00:00:00:00:03,x,3600,1000,1,0,0,b,0,,0\n\
             10.0.0.4,02:00:00:00:00:04,x,3600,2000000000,1,0,0,c,1,declined,0\n"
        );
        let mut m = BTreeMap::new();
        parse_kea_lease_csv(&text, 1_700_000_000, &mut m);
        assert!(m.is_empty());
    }

    #[test]
    fn missing_files_are_empty() {
        let d = tempfile::tempdir().unwrap();
        assert!(read_kea_leases(&d.path().join("dhcp4.leases"), 0).is_empty());
    }
}
