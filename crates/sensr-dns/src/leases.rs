//! DHCP lease registration (OPNsense `unbound_watcher.py`, for Kea's
//! memfile instead of ISC dhcpd's lease file).
//!
//! Kea appends every lease change to its CSV lease file and periodically
//! compacts it (LFC: `<file>.2` holds the previous generation, `.completed`
//! the compacted one). The watcher reads them in Kea's own load order, keeps
//! the last record per address, and registers the active leases with a host
//! name as `host.domain` A + PTR: the subnet's domain, else the registration
//! domain, else the system domain (as OPNsense: per-range domain, then
//! `regdhcpdomain`, then the system domain). Names and addresses served
//! from static data (reservations, host overrides, the firewall itself) are
//! never replaced by a lease.
//!
//! Records go into an include file (read when Unbound starts or reloads)
//! and, as they change, into the running resolver with `local_datas` /
//! `local_datas_remove`.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use sensr_apply::appliers::dns_runtime::LeaseRuntime;
use sensr_schema::fields::Hostname;

use crate::control::{Control, ControlError};

/// One lease record from the CSV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// Address.
    pub address: Ipv4Addr,
    /// Client host name, as Kea stored it.
    pub hostname: String,
    /// Kea subnet id.
    pub subnet_id: u32,
    /// Unix time the lease expires.
    pub expire: u64,
    /// Lease lifetime; 0 for a released lease.
    pub valid_lifetime: u64,
    /// 0 default, 1 declined, 2 expired-reclaimed.
    pub state: u8,
}

impl Lease {
    fn active(&self, now: u64) -> bool {
        self.state == 0 && self.valid_lifetime > 0 && self.expire > now
    }
}

/// Parses Kea's `lease4` CSV (columns located by the header line), keeping
/// the last record per address.
pub fn parse_csv(text: &str, into: &mut BTreeMap<Ipv4Addr, Lease>) {
    let mut cols: HashMap<&str, usize> = HashMap::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split(',').collect();
        if line.starts_with("address,") {
            cols = fields.iter().enumerate().map(|(i, f)| (*f, i)).collect();
            continue;
        }
        let get = |name: &str| cols.get(name).and_then(|&i| fields.get(i)).copied();
        let Some(address) = get("address").and_then(|a| a.parse().ok()) else {
            continue;
        };
        let num = |name: &str| get(name).and_then(|v| v.parse::<u64>().ok());
        into.insert(
            address,
            Lease {
                address,
                hostname: get("hostname").unwrap_or_default().to_owned(),
                subnet_id: num("subnet_id").unwrap_or(0) as u32,
                expire: num("expire").unwrap_or(0),
                valid_lifetime: num("valid_lifetime").unwrap_or(0),
                state: num("state").unwrap_or(0) as u8,
            },
        );
    }
}

/// The files Kea's memfile backend uses, in its load order.
pub fn lease_files(base: &Path) -> Vec<PathBuf> {
    let s = base.display().to_string();
    vec![
        PathBuf::from(format!("{s}.completed")),
        PathBuf::from(format!("{s}.2")),
        PathBuf::from(format!("{s}.1")),
        base.to_owned(),
    ]
}

/// Every lease Kea knows.
pub fn read_leases(base: &Path) -> BTreeMap<Ipv4Addr, Lease> {
    let mut out = BTreeMap::new();
    for f in lease_files(base) {
        if let Ok(text) = fs::read_to_string(&f) {
            parse_csv(&text, &mut out);
        }
    }
    out
}

/// A change stamp for the lease files (size and mtime of each).
pub fn stamp(base: &Path) -> Vec<Option<(u64, std::time::SystemTime)>> {
    lease_files(base)
        .iter()
        .map(|f| {
            let m = fs::metadata(f).ok()?;
            Some((m.len(), m.modified().ok()?))
        })
        .collect()
}

/// Registered names: fqdn → address.
pub type Records = BTreeMap<String, Ipv4Addr>;

/// The names to register for `leases` at `now`.
pub fn records(cfg: &LeaseRuntime, leases: &BTreeMap<Ipv4Addr, Lease>, now: u64) -> Records {
    let domains: HashMap<u32, String> = cfg
        .subnets
        .iter()
        .map(|(id, d)| (*id, d.to_string()))
        .collect();
    let static_names: BTreeSet<&str> = cfg.static_names.iter().map(String::as_str).collect();
    let static_addrs: BTreeSet<IpAddr> = cfg.static_addresses.iter().copied().collect();
    // Newest lease first, so a name moving to a new address follows it.
    let mut active: Vec<&Lease> = leases.values().filter(|l| l.active(now)).collect();
    active.sort_by_key(|l| std::cmp::Reverse(l.expire));
    let mut out = Records::new();
    let mut used = BTreeSet::new();
    for l in active {
        // Kea may store a qualified name; the host part is what the client
        // asked for.
        let host = l
            .hostname
            .trim_end_matches('.')
            .split('.')
            .next()
            .unwrap_or_default();
        let Ok(host) = host.to_ascii_lowercase().parse::<Hostname>() else {
            if !l.hostname.is_empty() {
                tracing::warn!(
                    "lease {}: {:?} is not a valid host name, ignored",
                    l.address,
                    l.hostname
                );
            }
            continue;
        };
        let domain = domains
            .get(&l.subnet_id)
            .cloned()
            .unwrap_or_else(|| cfg.default_domain.to_string());
        let fqdn = format!("{host}.{}", domain.to_ascii_lowercase());
        if static_names.contains(fqdn.as_str())
            || static_addrs.contains(&IpAddr::V4(l.address))
            || out.contains_key(&fqdn)
            || !used.insert(l.address)
        {
            continue;
        }
        out.insert(fqdn, l.address);
    }
    out
}

fn reverse(a: Ipv4Addr) -> String {
    let o = a.octets();
    format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
}

/// The include file for `recs`.
pub fn render(recs: &Records) -> String {
    let mut out = String::from("# Registered DHCP leases; written by sensr-dns.\nserver:\n");
    for (name, a) in recs {
        let _ = writeln!(out, "  local-data: \"{name}. IN A {a}\"");
        let _ = writeln!(out, "  local-data-ptr: \"{a} {name}\"");
    }
    out
}

/// Pushes the difference between `old` and `new` into Unbound.
pub fn push(control: &Control<'_>, old: &Records, new: &Records) -> Result<usize, ControlError> {
    let mut remove = Vec::new();
    let mut add = Vec::new();
    for (name, a) in old {
        if new.get(name) != Some(a) {
            remove.push(format!("{name}."));
            remove.push(reverse(*a));
        }
    }
    for (name, a) in new {
        if old.get(name) != Some(a) {
            add.push(format!("{name}. IN A {a}"));
            add.push(format!("{} IN PTR {name}.", reverse(*a)));
        }
    }
    control.local_datas_remove(&remove)?;
    control.local_datas(&add)?;
    Ok(remove.len() + add.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensr_apply::cmd::FakeRunner;

    const HEADER: &str = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n";

    fn cfg() -> LeaseRuntime {
        LeaseRuntime {
            lease_file: "/var/lib/kea/dhcp4.leases".into(),
            default_domain: "home.arpa".parse().unwrap(),
            subnets: vec![(7, "iot.home.arpa".parse().unwrap())],
            static_names: vec!["nas.home.arpa".into()],
            static_addresses: vec!["192.168.1.10".parse().unwrap()],
        }
    }

    #[test]
    fn last_record_wins_and_only_active_named_leases_register() {
        let mut leases = BTreeMap::new();
        parse_csv(
            &format!(
                "{HEADER}192.168.1.100,52:54:00:00:00:01,,7200,5000,1,0,0,laptop,0,,0\n\
                 192.168.1.101,52:54:00:00:00:02,,7200,500,1,0,0,old-phone,0,,0\n\
                 192.168.1.102,52:54:00:00:00:03,,7200,5000,1,0,0,,0,,0\n\
                 192.168.1.103,52:54:00:00:00:04,,7200,5000,1,0,0,Bad_Name!,0,,0\n\
                 192.168.20.5,52:54:00:00:00:05,,7200,5000,7,0,0,thermostat.,0,,0\n\
                 192.168.1.104,52:54:00:00:00:06,,7200,5000,1,0,0,nas,0,,0\n\
                 192.168.1.10,52:54:00:00:00:07,,7200,5000,1,0,0,nas2,0,,0\n\
                 192.168.1.105,52:54:00:00:00:08,,7200,5000,1,0,0,tv,0,,0\n\
                 192.168.1.105,52:54:00:00:00:08,,0,5000,1,0,0,tv,0,,0\n"
            ),
            &mut leases,
        );
        let r = records(&cfg(), &leases, 1000);
        let got: Vec<(&str, String)> = r.iter().map(|(n, a)| (n.as_str(), a.to_string())).collect();
        assert_eq!(
            got,
            [
                ("laptop.home.arpa", "192.168.1.100".into()),
                ("thermostat.iot.home.arpa", "192.168.20.5".into()),
            ]
        );
        assert_eq!(
            render(&r),
            "# Registered DHCP leases; written by sensr-dns.\nserver:\n  local-data: \"laptop.home.arpa. IN A 192.168.1.100\"\n  local-data-ptr: \"192.168.1.100 laptop.home.arpa\"\n  local-data: \"thermostat.iot.home.arpa. IN A 192.168.20.5\"\n  local-data-ptr: \"192.168.20.5 thermostat.iot.home.arpa\"\n"
        );
    }

    #[test]
    fn rotated_files_load_in_kea_order() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("dhcp4.leases");
        fs::write(
            format!("{}.2", base.display()),
            format!("{HEADER}192.168.1.100,aa,,7200,5000,1,0,0,first,0,,0\n"),
        )
        .unwrap();
        fs::write(
            &base,
            format!("{HEADER}192.168.1.100,aa,,7200,6000,1,0,0,second,0,,0\n"),
        )
        .unwrap();
        let l = read_leases(&base);
        assert_eq!(l[&"192.168.1.100".parse().unwrap()].hostname, "second");
        assert_eq!(stamp(&base).iter().filter(|s| s.is_some()).count(), 2);
    }

    #[test]
    fn push_sends_only_changes() {
        let r = FakeRunner::new();
        let c = Control::new(&r, "/c.conf");
        let mut old = Records::new();
        old.insert("laptop.home.arpa".into(), "192.168.1.100".parse().unwrap());
        old.insert("tv.home.arpa".into(), "192.168.1.105".parse().unwrap());
        let mut new = old.clone();
        new.remove("tv.home.arpa");
        new.insert("phone.home.arpa".into(), "192.168.1.106".parse().unwrap());
        assert_eq!(push(&c, &old, &new).unwrap(), 4);
        let inputs: Vec<String> = r
            .calls()
            .iter()
            .map(|c| String::from_utf8_lossy(c.stdin.as_deref().unwrap()).into_owned())
            .collect();
        assert_eq!(
            inputs,
            [
                "tv.home.arpa.\n105.1.168.192.in-addr.arpa.\n",
                "phone.home.arpa. IN A 192.168.1.106\n106.1.168.192.in-addr.arpa. IN PTR phone.home.arpa.\n"
            ]
        );
    }
}
