//! Names for MAC aliases (`arpcache.py`): the neighbour table (`ip -j neigh
//! show`) and Kea's DHCPv4 leases.
//!
//! The leases matter on their own: a device that has just received its address
//! has not talked to the router yet, so there is no neighbour entry for it and
//! a rule "trusted MACs may reach the LAN" would drop its first packets until
//! something makes the box ARP it. OPNsense reads the DHCP lease file for the
//! same reason.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
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
const HEADER: &str = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,\
                      fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id";

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
    for_each_kea_record(text, now, |lease| {
        let address = IpAddr::V4(lease.address);
        match (lease.active, lease.mac) {
            (_, None) => {}
            (true, Some(mac)) => {
                into.insert(address, mac);
            }
            (false, Some(_)) => {
                into.remove(&address);
            }
        }
    });
}

/// Leases from every file Kea's memfile backend may have written, in its load
/// order (`<file>.completed`, `.2`, `.1`, then `<file>`), as `(mac, address)`
/// pairs. A missing file is not an error.
pub fn read_kea_leases(base: &Path, now: u64) -> Vec<(String, IpAddr)> {
    let mut leases = BTreeMap::new();
    for f in kea_lease_files(base) {
        if let Ok(text) = std::fs::read_to_string(&f) {
            parse_kea_lease_csv(&text, now, &mut leases);
        }
    }
    leases.into_iter().map(|(ip, mac)| (mac, ip)).collect()
}

/// The files Kea's memfile backend may have written, in its load order.
fn kea_lease_files(base: &Path) -> [String; 4] {
    let s = base.display().to_string();
    [
        format!("{s}.completed"),
        format!("{s}.2"),
        format!("{s}.1"),
        s,
    ]
}

/// One neighbour-table entry that has a MAC: the address, the interface it was
/// seen on and the kernel's state words (`REACHABLE`, `STALE`, `DELAY`, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeighEntry {
    pub mac: String,
    pub ip: IpAddr,
    pub dev: String,
    pub state: Vec<String>,
}

/// Every neighbour with a MAC from `ip -j neigh show`, state kept as given.
/// Unlike [`parse_ip_neigh_json`] this does not judge the state; entries
/// without a MAC (failed, incomplete) are still skipped.
pub fn parse_ip_neigh_entries(json: &[u8]) -> Vec<NeighEntry> {
    #[derive(serde::Deserialize)]
    struct Entry {
        dst: Option<IpAddr>,
        #[serde(default)]
        dev: String,
        lladdr: Option<String>,
        #[serde(default)]
        state: Vec<String>,
    }
    let entries: Vec<Entry> = serde_json::from_slice(json).unwrap_or_default();
    entries
        .into_iter()
        .filter(|e| e.lladdr.as_deref().is_some_and(|m| !m.is_empty()))
        .filter_map(|e| {
            Some(NeighEntry {
                mac: e.lladdr?.to_ascii_lowercase(),
                ip: e.dst?,
                dev: e.dev,
                state: e.state,
            })
        })
        .collect()
}

/// A DHCPv4 lease as the newest Kea record describes it, whatever its state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeaLease {
    pub address: Ipv4Addr,
    pub mac: Option<String>,
    pub client_id: Option<String>,
    pub hostname: Option<String>,
    pub subnet_id: u32,
    pub expire: u64,
    /// State 0, a non-zero lifetime and an expiry still ahead of `now`.
    pub active: bool,
}

/// Every lease Kea knows, last record per address across the same files and
/// in the same order as [`read_kea_leases`], sorted by address. Released and
/// expired leases are kept with `active == false`. A missing file is not an
/// error.
pub fn read_kea_lease_records(base: &Path, now: u64) -> Vec<KeaLease> {
    let mut leases: BTreeMap<Ipv4Addr, KeaLease> = BTreeMap::new();
    for f in kea_lease_files(base) {
        if let Ok(text) = std::fs::read_to_string(&f) {
            for_each_kea_record(&text, now, |l| {
                leases.insert(l.address, l);
            });
        }
    }
    leases.into_values().collect()
}

/// Calls `f` for every record of one Kea CSV file, in file order. This is the
/// one place that knows the columns (located by the header line), the quoting
/// and the rule for a lease being active.
fn for_each_kea_record(text: &str, now: u64, mut f: impl FnMut(KeaLease)) {
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
        let Some(address) = get("address").and_then(|a| a.trim().parse::<Ipv4Addr>().ok()) else {
            continue;
        };
        let unquoted = |name: &str| {
            get(name)
                .map(|v| v.trim().trim_matches('"'))
                .filter(|v| !v.is_empty())
        };
        let num = |name: &str| get(name).and_then(|v| v.trim().parse::<u64>().ok());
        let lifetime = num("valid_lifetime").unwrap_or(0);
        let expire = num("expire").unwrap_or(0);
        f(KeaLease {
            address,
            mac: unquoted("hwaddr").map(str::to_ascii_lowercase),
            client_id: unquoted("client_id").map(str::to_ascii_lowercase),
            hostname: unquoted("hostname").map(str::to_owned),
            subnet_id: num("subnet_id")
                .and_then(|n| u32::try_from(n).ok())
                .unwrap_or(0),
            expire,
            active: num("state").unwrap_or(0) == 0 && lifetime > 0 && expire > now,
        });
    }
}

#[cfg(test)]
mod lease_tests {
    use super::*;

    #[test]
    fn active_leases_become_mac_addresses() {
        let text = format!(
            "{HEADER}\n\
             192.168.2.2,\"46:7E:11:F7:A6:1F\",\"01:46:7e:11:f7:a6:1f\",3600,2000000000,1,\
             0,0,trusted,0,,0\n\
             192.168.2.3,,\"01:aa\",3600,2000000000,1,0,0,nameless,0,,0\n"
        );
        let mut m = BTreeMap::new();
        parse_kea_lease_csv(&text, 1_700_000_000, &mut m);
        assert_eq!(
            m.into_iter().collect::<Vec<_>>(),
            vec![(
                "192.168.2.2".parse::<IpAddr>().unwrap(),
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

#[cfg(test)]
mod record_tests {
    use super::*;

    #[test]
    fn neigh_entries_keep_device_and_state() {
        let j = br#"[
          {"dst":"192.168.68.10","dev":"ue1","lladdr":"AA:BB:CC:00:00:01","state":["REACHABLE"]},
          {"dst":"192.168.68.11","dev":"ue1","state":["FAILED"]},
          {"dst":"fe80::1","dev":"ue0","lladdr":"aa:bb:cc:00:00:02","state":["STALE"]}
        ]"#;
        let v = parse_ip_neigh_entries(j);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].mac, "aa:bb:cc:00:00:01");
        assert_eq!(v[0].ip, "192.168.68.10".parse::<IpAddr>().unwrap());
        assert_eq!(v[0].dev, "ue1");
        assert_eq!(v[0].state, vec!["REACHABLE"]);
        assert_eq!(v[1].dev, "ue0");
        assert_eq!(v[1].state, vec!["STALE"]);
        assert!(parse_ip_neigh_entries(b"not json").is_empty());
    }

    #[test]
    fn lease_records_take_last_record_and_flag_active() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().join("dhcp4.leases");
        std::fs::write(
            &base,
            format!(
                "{HEADER}\n\
                 192.168.68.20,\"AA:BB:CC:00:00:20\",\"01:aa:bb:cc:00:00:20\",3600,1500,1,0,0,,0,,0\n\
                 192.168.68.20,\"AA:BB:CC:00:00:20\",\"01:aa:bb:cc:00:00:20\",3600,2000,1,0,0,tablet,0,,0\n\
                 192.168.68.21,\"aa:bb:cc:00:00:21\",,0,2000,1,0,0,old,0,,0\n"
            ),
        )
        .unwrap();
        let v = read_kea_lease_records(&base, 1000);
        assert_eq!(v.len(), 2);
        let a = &v[0];
        assert_eq!(
            a.address,
            "192.168.68.20".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert!(a.active);
        assert_eq!(a.hostname.as_deref(), Some("tablet"));
        assert_eq!(a.mac.as_deref(), Some("aa:bb:cc:00:00:20"));
        assert_eq!(a.client_id.as_deref(), Some("01:aa:bb:cc:00:00:20"));
        assert_eq!((a.subnet_id, a.expire), (1, 2000));
        let b = &v[1];
        assert!(!b.active);
        assert_eq!(b.client_id, None);
    }

    #[test]
    fn lease_records_missing_file_is_empty() {
        let d = tempfile::tempdir().unwrap();
        assert!(read_kea_lease_records(&d.path().join("dhcp4.leases"), 0).is_empty());
    }

    fn record(line: &str, now: u64) -> KeaLease {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().join("dhcp4.leases");
        std::fs::write(&base, format!("{HEADER}\n{line}\n")).unwrap();
        read_kea_lease_records(&base, now).remove(0)
    }

    #[test]
    fn declined_and_reclaimed_are_not_active() {
        assert!(!record("10.0.0.5,aa:bb:cc:00:00:05,,3600,2000,1,0,0,h,1,,0", 1000).active);
        assert!(!record("10.0.0.5,aa:bb:cc:00:00:05,,3600,2000,1,0,0,h,2,,0", 1000).active);
        assert!(record("10.0.0.5,aa:bb:cc:00:00:05,,3600,2000,1,0,0,h,0,,0", 1000).active);
    }

    #[test]
    fn expiry_must_be_after_now() {
        assert!(!record("10.0.0.6,aa:bb:cc:00:00:06,,3600,1000,1,0,0,h,0,,0", 1000).active);
        assert!(!record("10.0.0.6,aa:bb:cc:00:00:06,,3600,999,1,0,0,h,0,,0", 1000).active);
        assert!(record("10.0.0.6,aa:bb:cc:00:00:06,,3600,1001,1,0,0,h,0,,0", 1000).active);
    }

    #[test]
    fn client_id_is_lowercased() {
        let l = record(
            "10.0.0.7,AA:BB:CC:00:00:07,\"01:AA:BB:CC:00:00:07\",3600,2000,1,0,0,,0,,0",
            0,
        );
        assert_eq!(l.client_id.as_deref(), Some("01:aa:bb:cc:00:00:07"));
        assert_eq!(l.hostname, None);
    }

    #[test]
    fn missing_header_or_columns_do_not_panic() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().join("dhcp4.leases");
        std::fs::write(
            &base,
            "10.0.0.8,aa:bb:cc:00:00:08,,3600,2000,1,0,0,h,0,,0\n",
        )
        .unwrap();
        assert!(read_kea_lease_records(&base, 0).is_empty());
        std::fs::write(&base, "address,hwaddr\n10.0.0.9,aa:bb:cc:00:00:09\n").unwrap();
        let v = read_kea_lease_records(&base, 0);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].mac.as_deref(), Some("aa:bb:cc:00:00:09"));
        assert!(!v[0].active);
        assert_eq!(
            (v[0].subnet_id, v[0].expire, v[0].hostname.clone()),
            (0, 0, None)
        );
    }

    #[test]
    fn main_file_overrides_completed() {
        let d = tempfile::tempdir().unwrap();
        let base = d.path().join("dhcp4.leases");
        std::fs::write(
            d.path().join("dhcp4.leases.completed"),
            format!("{HEADER}\n10.0.0.10,aa:bb:cc:00:00:0a,,3600,9000,1,0,0,old,0,,0\n"),
        )
        .unwrap();
        std::fs::write(
            &base,
            format!("{HEADER}\n10.0.0.10,aa:bb:cc:00:00:0b,,3600,9000,1,0,0,new,0,,0\n"),
        )
        .unwrap();
        let v = read_kea_lease_records(&base, 1000);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].hostname.as_deref(), Some("new"));
        assert_eq!(v[0].mac.as_deref(), Some("aa:bb:cc:00:00:0b"));
    }

    #[test]
    fn neigh_entries_skip_empty_lladdr() {
        let j = br#"[{"dst":"10.0.0.1","dev":"x","lladdr":"","state":["STALE"]}]"#;
        assert!(parse_ip_neigh_entries(j).is_empty());
    }
}
