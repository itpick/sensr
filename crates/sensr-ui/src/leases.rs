//! DHCPv4 leases as Kea's memfile backend writes them.
//!
//! Kea appends every lease change to a CSV file and periodically compacts it, so the
//! current state is the last record per address across `<file>.completed`, `<file>.2`,
//! `<file>.1` and `<file>` (Kea's own load order). This is the same file sensr-dns reads
//! to register names and sensr-agent reads for MAC aliases; the columns are located by
//! the header line so a Kea upgrade that adds a column does not break the page.
//!
//! A missing file is not an error: a router whose DHCP server has never handed out a
//! lease simply has nothing to show.

use crate::api::{DhcpLease, LeaseState};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// Default location of the DHCPv4 lease file.
pub const LEASE_FILE: &str = "/var/lib/kea/dhcp4.leases";
/// Overrides [`LEASE_FILE`] (tests, the UI dev server).
pub const LEASE_ENV: &str = "SENSR_KEA_LEASE_FILE";

/// The files Kea's memfile backend may have written, in its load order.
fn lease_files(base: &Path) -> Vec<PathBuf> {
    let s = base.display().to_string();
    vec![
        PathBuf::from(format!("{s}.completed")),
        PathBuf::from(format!("{s}.2")),
        PathBuf::from(format!("{s}.1")),
        base.to_owned(),
    ]
}

fn state_of(state: u64, lifetime: u64, expire: u64, now: u64) -> LeaseState {
    match state {
        1 => LeaseState::Declined,
        2 => LeaseState::Reclaimed,
        _ if lifetime == 0 => LeaseState::Released,
        _ if expire <= now => LeaseState::Expired,
        _ => LeaseState::Active,
    }
}

/// Parses one CSV file into `into`, last record per address winning.
pub fn parse_csv(text: &str, now: u64, into: &mut BTreeMap<Ipv4Addr, DhcpLease>) {
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
        let Some(address) = get("address")
            .map(str::trim)
            .and_then(|a| a.parse::<Ipv4Addr>().ok())
        else {
            continue;
        };
        let text_of = |name: &str| {
            get(name)
                .map(|v| v.trim().trim_matches('"'))
                .filter(|v| !v.is_empty())
                .map(str::to_ascii_lowercase)
        };
        // A lease with neither a MAC nor a client id cannot be matched to a device, so it
        // is shown but cannot be turned into a reservation.
        let num = |name: &str| get(name).and_then(|v| v.trim().parse::<u64>().ok());
        let lifetime = num("valid_lifetime").unwrap_or(0);
        let expire = num("expire").unwrap_or(0);
        let state = state_of(num("state").unwrap_or(0), lifetime, expire, now);
        into.insert(
            address,
            DhcpLease {
                address: address.to_string(),
                mac: text_of("hwaddr"),
                client_id: text_of("client_id"),
                hostname: get("hostname")
                    .map(|v| v.trim().trim_matches('"').to_owned())
                    .unwrap_or_default(),
                subnet_id: num("subnet_id").unwrap_or(0) as u32,
                expire,
                state,
                reserved: false,
            },
        );
    }
}

/// Every lease Kea knows, newest state per address, sorted for display: live leases
/// first, then by address.
pub fn read_leases(base: &Path, now: u64) -> Vec<DhcpLease> {
    let mut leases = BTreeMap::new();
    for f in lease_files(base) {
        if let Ok(text) = std::fs::read_to_string(&f) {
            parse_csv(&text, now, &mut leases);
        }
    }
    let mut out: Vec<DhcpLease> = leases.into_values().collect();
    out.sort_by_key(|l| (!l.active(), l.address.clone()));
    out
}

/// Reads the leases from the configured path at the current time.
pub fn read_now() -> Vec<DhcpLease> {
    let path = std::env::var_os(LEASE_ENV).map_or_else(|| PathBuf::from(LEASE_FILE), PathBuf::from);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    read_leases(&path, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,\
                          fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id";

    #[test]
    fn live_expired_and_released_leases() {
        let text = format!(
            "{HEADER}\n\
             192.168.2.20,\"aa:bb:cc:dd:ee:01\",\"01:aa:bb:cc:dd:ee:01\",3600,2000,1,\
             0,0,laptop,0,,0\n\
             192.168.2.21,\"aa:bb:cc:dd:ee:02\",\"\",3600,1000,1,0,0,phone,0,,0\n\
             192.168.2.22,\"aa:bb:cc:dd:ee:03\",\"\",0,0,1,0,0,old,0,,0\n"
        );
        let mut map = BTreeMap::new();
        parse_csv(&text, 1500, &mut map);
        let v: Vec<_> = map.values().cloned().collect();
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].state, LeaseState::Active);
        assert_eq!(v[0].hostname, "laptop");
        assert_eq!(v[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:01"));
        assert_eq!(v[1].state, LeaseState::Expired);
        assert_eq!(v[2].state, LeaseState::Released);
    }

    #[test]
    fn client_id_only_and_last_record_wins() {
        let text = format!(
            "{HEADER}\n\
             192.168.2.30,,\"01:11:22:33:44:55\",3600,2000,1,0,0,,0,,0\n\
             192.168.2.30,\"aa:bb:cc:dd:ee:04\",\"\",3600,2000,1,0,0,desktop,0,,0\n"
        );
        let mut map = BTreeMap::new();
        parse_csv(&text, 0, &mut map);
        let lease = &map[&"192.168.2.30".parse().unwrap()];
        assert_eq!(lease.mac.as_deref(), Some("aa:bb:cc:dd:ee:04"));
        assert_eq!(lease.client_id, None);
        assert_eq!(lease.hostname, "desktop");
    }

    #[test]
    fn missing_file_is_empty() {
        let d = std::env::temp_dir().join("sensr-lease-missing");
        assert!(read_leases(&d.join("dhcp4.leases"), 0).is_empty());
    }

    #[test]
    fn compaction_files_are_read_in_load_order() {
        let d = std::env::temp_dir().join(format!("sensr-leases-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let base = d.join("dhcp4.leases");
        std::fs::write(
            d.join("dhcp4.leases.completed"),
            format!("{HEADER}\n192.168.2.40,\"aa:bb:cc:dd:ee:05\",\"\",3600,9000,1,0,0,one,0,,0\n"),
        )
        .unwrap();
        std::fs::write(
            &base,
            format!("{HEADER}\n192.168.2.40,\"aa:bb:cc:dd:ee:06\",\"\",3600,9000,1,0,0,two,0,,0\n"),
        )
        .unwrap();
        let v = read_leases(&base, 1000);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].hostname, "two");
        let _ = std::fs::remove_dir_all(&d);
    }
}
