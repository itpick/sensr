//! The host inventory: every device seen on an internal network, merged by
//! MAC from the neighbour table, Kea's leases and the configured
//! reservations (docs/superpowers/specs/2026-11-22-host-inventory-design.md).
//!
//! Pure model and merge; reading the inputs, persisting and serving the view
//! live elsewhere.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sensr_apply::appliers::convert::kea_subnet_id;
use sensr_feeds::neigh::{KeaLease, NeighEntry};
pub use sensr_rules::document::{InternalIf, internal_interfaces};
use sensr_schema::Document;
use sensr_schema::models::dhcp::ClientMatch;
use serde::{Deserialize, Serialize};

/// Hosts not seen for this long are pruned unless reserved (90 days).
pub const RETENTION_SECS: u64 = 7_776_000;
/// At most this many hosts are kept; the oldest unreserved go first.
pub const MAX_HOSTS: usize = 5_000;
/// A host seen this recently is online.
pub const ONLINE_SECS: u64 = 300;
/// IPv6 addresses kept per host, newest first.
const MAX_IPV6: usize = 4;
/// Neighbour states that mean the device is talking now (STALE lingers after
/// it leaves).
const ACTIVE_STATES: [&str; 3] = ["REACHABLE", "DELAY", "PROBE"];

/// One poll's inputs.
pub struct Snapshot {
    /// The kernel neighbour table.
    pub neigh: Vec<NeighEntry>,
    /// Kea's DHCPv4 leases.
    pub leases: Vec<KeaLease>,
    /// Reservations from the applied document.
    pub reservations: Vec<ReservationView>,
    /// The internal interfaces; neighbours elsewhere are ignored.
    pub internal: Vec<InternalIf>,
    /// Kea subnet id → interface id.
    pub subnet_iface: BTreeMap<u32, String>,
}

/// A DHCPv4 reservation as the inventory needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationView {
    /// The host key: the lowercase MAC, else `id:<client id>`.
    pub key: String,
    /// Lowercase MAC, for a hardware-address reservation.
    pub mac: Option<String>,
    /// Lowercase hex client id, for a client-id reservation.
    pub client_id: Option<String>,
    /// The fixed address.
    pub ip: Option<Ipv4Addr>,
    /// The reserved host name.
    pub hostname: Option<String>,
    /// The interface the reservation's subnet is served on.
    pub interface: Option<String>,
}

/// Where a host is known from.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    /// A DHCPv4 reservation names it.
    Reserved,
    /// It holds or held a Kea lease.
    Lease,
    /// It appeared in the neighbour table.
    Neighbour,
}

/// The host's current DHCPv4 lease.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct LeaseInfo {
    /// `active`.
    pub state: String,
    /// Expiry, Unix seconds.
    pub expires: u64,
}

/// One device. Serialises to the wire format minus the fields computed at
/// render (`online`, `interface_name`).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Host {
    /// The lowercase MAC, else `id:<client id>`.
    pub key: String,
    /// Lowercase MAC, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    /// Lowercase hex DHCP client id, once known; keeps a client-id
    /// reservation attached to this MAC row after the linking lease is gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// `reserved_name`, else `lease_hostname`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The reservation's host name.
    #[serde(default)]
    pub reserved_name: Option<String>,
    /// The host name the client sent with its lease.
    #[serde(default)]
    pub lease_hostname: Option<String>,
    /// Interface id where last seen.
    #[serde(default)]
    pub interface: Option<String>,
    /// Current or last known IPv4 address.
    #[serde(default)]
    pub ipv4: Option<Ipv4Addr>,
    /// Up to four IPv6 addresses, newest first.
    #[serde(default)]
    pub ipv6: Vec<Ipv6Addr>,
    /// Where the host is known from.
    #[serde(default)]
    pub sources: BTreeSet<Source>,
    /// The current lease, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<LeaseInfo>,
    /// When the row was created, Unix seconds.
    pub first_seen: u64,
    /// Last real activity, Unix seconds; `None` if never seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<u64>,
}

impl Host {
    fn new(key: String, now: u64) -> Self {
        Self {
            mac: (!key.starts_with("id:")).then(|| key.clone()),
            client_id: key.strip_prefix("id:").map(Into::into),
            key,
            name: None,
            reserved_name: None,
            lease_hostname: None,
            interface: None,
            ipv4: None,
            ipv6: Vec::new(),
            sources: BTreeSet::new(),
            lease: None,
            first_seen: now,
            last_seen: None,
        }
    }

    fn reserved(&self) -> bool {
        self.sources.contains(&Source::Reserved)
    }

    /// The prune clock: last activity, else creation.
    fn age_from(&self) -> u64 {
        self.last_seen.unwrap_or(self.first_seen)
    }

    fn add_ipv6(&mut self, a: Ipv6Addr) {
        self.ipv6.retain(|x| *x != a);
        self.ipv6.insert(0, a);
        if self.ipv6.iter().any(|a| !link_local(a)) {
            self.ipv6.retain(|a| !link_local(a));
        }
        self.ipv6.truncate(MAX_IPV6);
    }

    /// Takes in a row for the same device (an `id:` row now linked to a MAC).
    fn absorb(&mut self, other: Host) {
        self.first_seen = self.first_seen.min(other.first_seen);
        self.last_seen = self.last_seen.max(other.last_seen);
        self.sources.extend(other.sources);
        self.reserved_name = self.reserved_name.take().or(other.reserved_name);
        self.lease_hostname = self.lease_hostname.take().or(other.lease_hostname);
        self.interface = self.interface.take().or(other.interface);
        self.ipv4 = self.ipv4.or(other.ipv4);
        self.lease = self.lease.take().or(other.lease);
        self.client_id = self.client_id.take().or(other.client_id);
        let mine = std::mem::replace(&mut self.ipv6, other.ipv6);
        for a in mine.into_iter().rev() {
            self.add_ipv6(a);
        }
    }

    /// Equal apart from the fields that move without a structural change.
    fn same_structure(&self, other: &Host) -> bool {
        let strip = |h: &Host| Host {
            last_seen: None,
            lease: None,
            ..h.clone()
        };
        strip(self) == strip(other)
    }
}

fn link_local(a: &Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

fn client_key(cid: &str) -> String {
    format!("id:{cid}")
}

/// What an [`Inventory::observe`] changed.
#[derive(PartialEq, Debug)]
pub enum Change {
    /// Nothing.
    None,
    /// Only `last_seen` (and lease expiry) moved.
    Seen,
    /// A host was added or removed, or its name, addresses, interface or
    /// sources changed.
    Structural,
}

/// Kea subnet id → interface id: the subnet's own interface, else the
/// internal interface whose network contains it. Ids are Kea's
/// ([`kea_subnet_id`]).
pub fn subnet_ifaces(doc: &Document, internal: &[InternalIf]) -> BTreeMap<u32, String> {
    doc.dhcpv4
        .subnets
        .iter()
        .filter_map(|(uuid, s)| {
            let iface = match &s.interface {
                Some(i) => i.as_str().to_owned(),
                None => internal
                    .iter()
                    .find(|i| i.subnets.iter().any(|n| n.contains(&s.subnet)))?
                    .id
                    .clone(),
            };
            Some((kea_subnet_id(uuid), iface))
        })
        .collect()
}

/// The document's DHCPv4 reservations.
pub fn reservations(doc: &Document) -> Vec<ReservationView> {
    let ifaces = subnet_ifaces(doc, &internal_interfaces(doc));
    doc.dhcpv4
        .reservations
        .values()
        .map(|r| {
            let (key, mac, client_id) = match &r.client {
                ClientMatch::HwAddress(m) => (m.to_string(), Some(m.to_string()), None),
                ClientMatch::ClientId(c) => (client_key(&c.to_string()), None, Some(c.to_string())),
            };
            ReservationView {
                key,
                mac,
                client_id,
                ip: r.ip_address,
                hostname: r.hostname.as_ref().map(|h| h.to_string()),
                interface: ifaces.get(&kea_subnet_id(&r.subnet.id())).cloned(),
            }
        })
        .collect()
}

/// The in-memory inventory, keyed by [`Host::key`].
#[derive(Default)]
pub struct Inventory {
    hosts: BTreeMap<String, Host>,
    /// The previous poll's active lease expiries, by the lease's own client
    /// (MAC, else `id:<client id>`). Kept apart from the rows so forgetting
    /// or re-keying a row does not make an unchanged lease look renewed.
    expires: BTreeMap<String, u64>,
    /// Set after the first poll; until then lease expiries are only recorded,
    /// so leases existing at start-up are not mistaken for activity.
    primed: bool,
}

impl Inventory {
    /// An inventory loaded from storage.
    pub fn from_hosts(hosts: Vec<Host>) -> Self {
        Self {
            hosts: hosts.into_iter().map(|h| (h.key.clone(), h)).collect(),
            expires: BTreeMap::new(),
            primed: false,
        }
    }

    /// Merges one poll.
    pub fn observe(&mut self, snap: &Snapshot, now: u64) -> Change {
        let before = self.hosts.clone();

        // A lease that carries both identifiers links a client id to its MAC
        // for good; the link is kept on the MAC row.
        let mut links: BTreeMap<String, String> = self
            .hosts
            .values()
            .filter_map(|h| Some((h.client_id.clone()?, h.mac.clone()?)))
            .collect();
        for l in &snap.leases {
            if let (Some(cid), Some(mac)) = (&l.client_id, &l.mac) {
                links.insert(cid.clone(), mac.clone());
            }
        }
        for (cid, mac) in &links {
            if let Some(row) = self.hosts.remove(&client_key(cid)) {
                self.row(mac, now).absorb(row);
            }
            if let Some(h) = self.hosts.get_mut(mac) {
                h.client_id = Some(cid.clone());
            }
        }
        let key_of = |mac: Option<&str>, cid: Option<&str>| -> Option<String> {
            match (mac, cid) {
                (Some(m), _) => Some(m.to_owned()),
                (None, Some(c)) => Some(match links.get(c) {
                    Some(m) => m.clone(),
                    None => client_key(c),
                }),
                (None, None) => None,
            }
        };

        // Reservations: the reserved set and names follow the document.
        let mut reserved = BTreeSet::new();
        for r in &snap.reservations {
            let Some(key) = key_of(r.mac.as_deref(), r.client_id.as_deref()) else {
                continue;
            };
            let h = self.row(&key, now);
            h.sources.insert(Source::Reserved);
            h.reserved_name = r.hostname.clone();
            h.ipv4 = h.ipv4.or(r.ip);
            if h.interface.is_none() {
                h.interface = r.interface.clone();
            }
            reserved.insert(key);
        }
        for (key, h) in &mut self.hosts {
            if !reserved.contains(key) && h.sources.remove(&Source::Reserved) {
                h.reserved_name = None;
            }
        }

        // Active leases; the lease field and expiry follow what Kea holds now.
        let mut leased = BTreeSet::new();
        let previous = std::mem::take(&mut self.expires);
        for l in snap.leases.iter().filter(|l| l.active) {
            // the lease's own client, stable however the row is keyed
            let client = match (&l.mac, &l.client_id) {
                (Some(m), _) => m.clone(),
                (None, Some(c)) => client_key(c),
                (None, None) => continue,
            };
            let Some(key) = key_of(l.mac.as_deref(), l.client_id.as_deref()) else {
                continue;
            };
            let renewed = self.primed && previous.get(&client) != Some(&l.expire);
            self.expires.insert(client, l.expire);
            let h = self.row(&key, now);
            if l.mac.is_some() && l.client_id.is_some() {
                h.client_id = l.client_id.clone();
            }
            h.sources.insert(Source::Lease);
            h.ipv4 = Some(l.address);
            if let Some(i) = snap.subnet_iface.get(&l.subnet_id) {
                h.interface = Some(i.clone());
            }
            if l.hostname.is_some() {
                h.lease_hostname = l.hostname.clone();
            }
            h.lease = Some(LeaseInfo {
                state: "active".into(),
                expires: l.expire,
            });
            // issued or renewed since the last poll
            if renewed {
                h.last_seen = Some(now);
            }
            leased.insert(key);
        }
        for (key, h) in &mut self.hosts {
            if !leased.contains(key) {
                h.lease = None;
            }
        }

        // Neighbours on internal interfaces.
        for n in &snap.neigh {
            let Some(iface) = snap.internal.iter().find(|i| i.device == n.dev) else {
                continue;
            };
            let h = self.row(&n.mac, now);
            h.sources.insert(Source::Neighbour);
            h.interface = Some(iface.id.clone());
            match n.ip {
                IpAddr::V4(a) => h.ipv4 = Some(a),
                IpAddr::V6(a) => h.add_ipv6(a),
            }
            if n.state.iter().any(|s| ACTIVE_STATES.contains(&s.as_str())) {
                h.last_seen = Some(now);
            }
        }

        for h in self.hosts.values_mut() {
            h.name = h.reserved_name.clone().or_else(|| h.lease_hostname.clone());
        }
        self.primed = true;

        if self.hosts.len() != before.len()
            || self
                .hosts
                .iter()
                .zip(&before)
                .any(|((k, h), (bk, b))| k != bk || !h.same_structure(b))
        {
            Change::Structural
        } else if self
            .hosts
            .values()
            .zip(before.values())
            .any(|(h, b)| h.last_seen != b.last_seen || h.lease != b.lease)
        {
            Change::Seen
        } else {
            Change::None
        }
    }

    fn row(&mut self, key: &str, now: u64) -> &mut Host {
        self.hosts
            .entry(key.to_owned())
            .or_insert_with(|| Host::new(key.to_owned(), now))
    }

    /// Removes an unreserved host; `false` if `key` is unknown or reserved.
    pub fn forget(&mut self, key: &str) -> bool {
        match self.hosts.get(key) {
            Some(h) if !h.reserved() => {
                self.hosts.remove(key);
                true
            }
            _ => false,
        }
    }

    /// Drops unreserved hosts idle for [`RETENTION_SECS`], then the oldest
    /// unreserved beyond [`MAX_HOSTS`]. Returns whether any went.
    pub fn prune(&mut self, now: u64) -> bool {
        let before = self.hosts.len();
        self.hosts
            .retain(|_, h| h.reserved() || now.saturating_sub(h.age_from()) <= RETENTION_SECS);
        if self.hosts.len() > MAX_HOSTS {
            let mut unreserved: Vec<(u64, String)> = self
                .hosts
                .values()
                .filter(|h| !h.reserved())
                .map(|h| (h.age_from(), h.key.clone()))
                .collect();
            unreserved.sort();
            let excess = self.hosts.len() - MAX_HOSTS;
            for (_, key) in unreserved.into_iter().take(excess) {
                self.hosts.remove(&key);
            }
        }
        self.hosts.len() != before
    }

    /// Every host, in key order.
    pub fn hosts(&self) -> impl Iterator<Item = &Host> {
        self.hosts.values()
    }

    /// The wire format: `{now, hosts}`, online first, then most recently seen.
    pub fn view(&self, now: u64, internal: &[InternalIf]) -> serde_json::Value {
        let online = |h: &Host| {
            h.last_seen
                .is_some_and(|t| now.saturating_sub(t) <= ONLINE_SECS)
        };
        let mut hosts: Vec<&Host> = self.hosts.values().collect();
        hosts.sort_by(|a, b| {
            online(b)
                .cmp(&online(a))
                .then(b.last_seen.cmp(&a.last_seen))
                .then(a.key.cmp(&b.key))
        });
        let hosts: Vec<serde_json::Value> = hosts
            .into_iter()
            .map(|h| {
                let mut v = serde_json::to_value(h).expect("host serialises");
                let name = h
                    .interface
                    .as_deref()
                    .and_then(|id| internal.iter().find(|i| i.id == id))
                    .map(|i| i.descr.clone());
                v["interface_name"] = name.into();
                v["online"] = online(h).into();
                v
            })
            .collect();
        serde_json::json!({ "now": now, "hosts": hosts })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: &str = "aa:bb:cc:dd:ee:01";

    fn lan() -> Vec<InternalIf> {
        vec![InternalIf {
            id: "lan".into(),
            device: "ue1".into(),
            descr: "LAN".into(),
            subnets: vec!["192.168.68.0/22".parse().unwrap()],
        }]
    }

    fn snap() -> Snapshot {
        Snapshot {
            neigh: Vec::new(),
            leases: Vec::new(),
            reservations: Vec::new(),
            internal: lan(),
            subnet_iface: BTreeMap::from([(7, "lan".to_owned())]),
        }
    }

    fn neigh(mac: &str, ip: &str, dev: &str, state: &str) -> NeighEntry {
        NeighEntry {
            mac: mac.into(),
            ip: ip.parse().unwrap(),
            dev: dev.into(),
            state: vec![state.into()],
        }
    }

    fn lease(mac: Option<&str>, cid: Option<&str>, expire: u64) -> KeaLease {
        KeaLease {
            address: "192.168.68.50".parse().unwrap(),
            mac: mac.map(Into::into),
            client_id: cid.map(Into::into),
            hostname: None,
            subnet_id: 7,
            expire,
            active: true,
        }
    }

    fn reservation(key: &str, mac: Option<&str>, cid: Option<&str>) -> ReservationView {
        ReservationView {
            key: key.into(),
            mac: mac.map(Into::into),
            client_id: cid.map(Into::into),
            ip: Some("192.168.68.40".parse().unwrap()),
            hostname: Some("printer".into()),
            interface: Some("lan".into()),
        }
    }

    fn with_neigh(state: &str) -> Snapshot {
        let mut s = snap();
        s.neigh.push(neigh(MAC, "192.168.68.50", "ue1", state));
        s
    }

    fn with_lease(expire: u64) -> Snapshot {
        let mut s = snap();
        s.leases.push(lease(Some(MAC), None, expire));
        s
    }

    fn only(inv: &Inventory) -> &Host {
        let v: Vec<_> = inv.hosts().collect();
        assert_eq!(v.len(), 1, "{v:#?}");
        v[0]
    }

    fn host(key: &str, first_seen: u64, last_seen: Option<u64>) -> Host {
        Host {
            key: key.into(),
            mac: Some(key.into()),
            client_id: None,
            name: None,
            reserved_name: None,
            lease_hostname: None,
            interface: Some("lan".into()),
            ipv4: None,
            ipv6: Vec::new(),
            sources: BTreeSet::from([Source::Neighbour]),
            lease: None,
            first_seen,
            last_seen,
        }
    }

    #[test]
    fn reachable_neighbour_creates_and_sees_host() {
        let mut inv = Inventory::from_hosts(Vec::new());
        assert_eq!(
            inv.observe(&with_neigh("REACHABLE"), 1000),
            Change::Structural
        );
        let h = only(&inv);
        assert_eq!(h.first_seen, 1000);
        assert_eq!(h.last_seen, Some(1000));
        assert_eq!(h.sources, BTreeSet::from([Source::Neighbour]));
        assert_eq!(h.mac.as_deref(), Some(MAC));
        assert_eq!(h.interface.as_deref(), Some("lan"));
        assert_eq!(h.ipv4, Some("192.168.68.50".parse().unwrap()));
    }

    #[test]
    fn delay_and_probe_count_as_activity() {
        for state in ["DELAY", "PROBE"] {
            let mut inv = Inventory::from_hosts(Vec::new());
            inv.observe(&with_neigh(state), 1000);
            assert_eq!(only(&inv).last_seen, Some(1000), "{state}");
        }
    }

    #[test]
    fn stale_neighbour_keeps_but_does_not_see() {
        let mut inv = Inventory::from_hosts(Vec::new());
        inv.observe(&with_neigh("REACHABLE"), 1000);
        assert_eq!(inv.observe(&with_neigh("STALE"), 2000), Change::None);
        assert_eq!(only(&inv).last_seen, Some(1000));
    }

    #[test]
    fn reachable_again_is_a_sighting_only() {
        let mut inv = Inventory::from_hosts(Vec::new());
        inv.observe(&with_neigh("REACHABLE"), 1000);
        assert_eq!(inv.observe(&with_neigh("REACHABLE"), 1030), Change::Seen);
        assert_eq!(only(&inv).last_seen, Some(1030));
    }

    #[test]
    fn lease_alone_does_not_refresh_last_seen() {
        let mut inv = Inventory::from_hosts(Vec::new());
        for now in [1000, 1030, 1060] {
            inv.observe(&with_lease(9000), now);
            let h = only(&inv);
            assert_eq!(h.last_seen, None, "at {now}");
            assert_eq!(h.sources, BTreeSet::from([Source::Lease]));
        }
        let h = only(&inv);
        assert_eq!(h.first_seen, 1000);
        assert_eq!(
            h.lease,
            Some(LeaseInfo {
                state: "active".into(),
                expires: 9000
            })
        );
    }

    #[test]
    fn renewed_lease_counts_as_activity() {
        let mut inv = Inventory::from_hosts(Vec::new());
        inv.observe(&with_lease(9000), 1000);
        assert_eq!(inv.observe(&with_lease(9030), 1030), Change::Seen);
        assert_eq!(only(&inv).last_seen, Some(1030));
    }

    #[test]
    fn first_poll_does_not_count_existing_leases_as_activity() {
        let mut h = host(MAC, 500, Some(600));
        h.sources = BTreeSet::from([Source::Lease]);
        let mut inv = Inventory::from_hosts(vec![h]);
        inv.observe(&with_lease(9000), 1000);
        assert_eq!(only(&inv).last_seen, Some(600));
        // once primed, the next renewal is activity
        inv.observe(&with_lease(9030), 1030);
        assert_eq!(only(&inv).last_seen, Some(1030));
    }

    #[test]
    fn wan_and_unknown_devices_are_ignored() {
        let mut inv = Inventory::from_hosts(Vec::new());
        let mut s = snap();
        s.neigh
            .push(neigh(MAC, "203.0.113.9", "rp1eth0", "REACHABLE"));
        s.neigh.push(neigh(MAC, "10.0.0.9", "nope0", "REACHABLE"));
        assert_eq!(inv.observe(&s, 1000), Change::None);
        assert_eq!(inv.hosts().count(), 0);
    }

    #[test]
    fn reservation_without_sighting_is_listed() {
        let mut inv = Inventory::from_hosts(Vec::new());
        let mut s = snap();
        s.reservations.push(reservation(MAC, Some(MAC), None));
        assert_eq!(inv.observe(&s, 1000), Change::Structural);
        let h = only(&inv);
        assert_eq!(h.name.as_deref(), Some("printer"));
        assert_eq!(h.reserved_name.as_deref(), Some("printer"));
        assert_eq!(h.sources, BTreeSet::from([Source::Reserved]));
        assert_eq!(h.last_seen, None);
        assert_eq!(h.ipv4, Some("192.168.68.40".parse().unwrap()));
        assert_eq!(h.interface.as_deref(), Some("lan"));
    }

    #[test]
    fn removed_reservation_drops_the_reserved_source() {
        let mut inv = Inventory::from_hosts(Vec::new());
        let mut s = snap();
        s.reservations.push(reservation(MAC, Some(MAC), None));
        inv.observe(&s, 1000);
        assert_eq!(inv.observe(&snap(), 1030), Change::Structural);
        let h = only(&inv);
        assert!(h.sources.is_empty());
        assert_eq!(h.reserved_name, None);
        assert_eq!(h.name, None);
        assert!(inv.forget(MAC));
    }

    #[test]
    fn client_id_row_merges_into_mac() {
        let mut inv = Inventory::from_hosts(Vec::new());
        let mut s = snap();
        s.reservations
            .push(reservation("id:01:aa", None, Some("01:aa")));
        inv.observe(&s, 1000);
        assert_eq!(only(&inv).key, "id:01:aa");

        s.leases.push(lease(Some(MAC), Some("01:aa"), 9000));
        assert_eq!(inv.observe(&s, 1030), Change::Structural);
        let h = only(&inv);
        assert_eq!(h.key, MAC);
        assert_eq!(h.mac.as_deref(), Some(MAC));
        assert_eq!(h.first_seen, 1000);
        assert!(h.sources.contains(&Source::Reserved));
        assert!(h.sources.contains(&Source::Lease));
        assert_eq!(h.name.as_deref(), Some("printer"));

        // later polls keep the single MAC row
        assert_ne!(inv.observe(&s, 1060), Change::Structural);
        assert_eq!(only(&inv).key, MAC);
    }

    #[test]
    fn client_id_merge_keeps_the_earliest_first_seen() {
        let mut inv = Inventory::from_hosts(Vec::new());
        let mut s = snap();
        s.reservations
            .push(reservation("id:01:aa", None, Some("01:aa")));
        inv.observe(&s, 1000);
        // the device is already known by MAC from the neighbour table
        inv.observe(&with_neigh("REACHABLE"), 1010);
        assert_eq!(inv.hosts().count(), 2);

        s.leases.push(lease(Some(MAC), Some("01:aa"), 9000));
        assert_eq!(inv.observe(&s, 1030), Change::Structural);
        let h = only(&inv);
        assert_eq!(h.key, MAC);
        assert_eq!(h.first_seen, 1000);
        assert_eq!(h.last_seen, Some(1030));
        assert_eq!(
            h.sources,
            BTreeSet::from([Source::Reserved, Source::Lease, Source::Neighbour])
        );
    }

    #[test]
    fn client_id_link_outlives_the_lease() {
        let mut inv = Inventory::from_hosts(Vec::new());
        let mut s = snap();
        s.reservations
            .push(reservation("id:01:aa", None, Some("01:aa")));
        inv.observe(&s, 1000);
        let mut linked = snap();
        linked.reservations = s.reservations.clone();
        linked.leases.push(lease(Some(MAC), Some("01:aa"), 9000));
        inv.observe(&linked, 1030);
        assert_eq!(only(&inv).key, MAC);
        assert_eq!(only(&inv).client_id.as_deref(), Some("01:aa"));

        // Kea reclaims the lease: the reservation still attaches to the MAC row
        inv.observe(&s, 1060);
        let h = only(&inv);
        assert_eq!(h.key, MAC);
        assert!(h.sources.contains(&Source::Reserved));
        assert_eq!(h.reserved_name.as_deref(), Some("printer"));

        // and the link is persisted across a restart
        let stored = serde_json::to_string(&inv.hosts().cloned().collect::<Vec<_>>()).unwrap();
        let mut inv = Inventory::from_hosts(serde_json::from_str(&stored).unwrap());
        inv.observe(&s, 1090);
        let h = only(&inv);
        assert_eq!(h.key, MAC);
        assert!(h.sources.contains(&Source::Reserved));
    }

    #[test]
    fn forgotten_leased_host_returns_unseen() {
        let mut inv = Inventory::from_hosts(Vec::new());
        inv.observe(&with_lease(9000), 1000);
        inv.observe(&with_lease(9000), 1030);
        assert!(inv.forget(MAC));
        // the same lease, unrenewed, is not activity for the recreated row
        inv.observe(&with_lease(9000), 1060);
        let h = only(&inv);
        assert_eq!(h.first_seen, 1060);
        assert_eq!(h.last_seen, None);
    }

    #[test]
    fn lease_without_mac_is_keyed_by_client_id() {
        let mut inv = Inventory::from_hosts(Vec::new());
        let mut s = snap();
        s.leases.push(lease(None, Some("01:bb"), 9000));
        inv.observe(&s, 1000);
        let h = only(&inv);
        assert_eq!(h.key, "id:01:bb");
        assert_eq!(h.mac, None);
    }

    #[test]
    fn name_precedence() {
        let mut inv = Inventory::from_hosts(Vec::new());
        let mut s = snap();
        let mut l = lease(Some(MAC), None, 9000);
        l.hostname = Some("diskstation".into());
        s.leases.push(l);
        inv.observe(&s, 1000);
        assert_eq!(only(&inv).name.as_deref(), Some("diskstation"));

        let mut r = reservation(MAC, Some(MAC), None);
        r.hostname = Some("nas".into());
        s.reservations.push(r);
        assert_eq!(inv.observe(&s, 1030), Change::Structural);
        let h = only(&inv);
        assert_eq!(h.name.as_deref(), Some("nas"));
        assert_eq!(h.lease_hostname.as_deref(), Some("diskstation"));
    }

    #[test]
    fn forget_refuses_reserved_and_unknown() {
        let printer_mac = "aa:bb:cc:dd:ee:40";
        let mut inv = Inventory::from_hosts(Vec::new());
        let mut s = snap();
        s.reservations
            .push(reservation(printer_mac, Some(printer_mac), None));
        inv.observe(&s, 1000);
        assert!(!inv.forget(printer_mac));
        assert!(!inv.forget("nope"));
        assert_eq!(inv.hosts().count(), 1);
    }

    #[test]
    fn forgotten_online_host_returns_with_new_first_seen() {
        let mut inv = Inventory::from_hosts(Vec::new());
        inv.observe(&with_neigh("REACHABLE"), 900);
        assert!(inv.forget(MAC));
        assert_eq!(inv.hosts().count(), 0);
        inv.observe(&with_neigh("REACHABLE"), 1030);
        assert_eq!(only(&inv).first_seen, 1030);
    }

    #[test]
    fn prune_drops_after_90_days_but_keeps_reserved() {
        let now = 10_000_000;
        let old = now - 7_776_001;
        let mut reserved = host("aa:bb:cc:dd:ee:02", old, Some(old));
        reserved.sources = BTreeSet::from([Source::Reserved]);
        let mut never_seen = host("aa:bb:cc:dd:ee:03", old, None);
        never_seen.sources = BTreeSet::from([Source::Lease]);
        let mut inv = Inventory::from_hosts(vec![
            host(MAC, old, Some(old)),
            reserved,
            never_seen,
            host("aa:bb:cc:dd:ee:04", old, Some(now - 7_776_000)),
        ]);
        assert!(inv.prune(now));
        let keys: Vec<_> = inv.hosts().map(|h| h.key.as_str()).collect();
        assert_eq!(keys, ["aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:04"]);
        assert!(!inv.prune(now));
    }

    #[test]
    fn cap_drops_oldest_unreserved() {
        let now = 10_000_000;
        let mut hosts: Vec<Host> = (0..5_000u64)
            .map(|i| host(&format!("k{i:05}"), now - 100_000, Some(now - 10 - i)))
            .collect();
        // a reserved host older than all of them is never the one dropped
        let mut r = host("reserved", now - 200_000, Some(now - 200_000));
        r.sources = BTreeSet::from([Source::Reserved]);
        hosts.push(r);
        assert_eq!(hosts.len(), 5_001);
        let mut inv = Inventory::from_hosts(hosts);
        assert!(inv.prune(now));
        assert_eq!(inv.hosts().count(), 5_000);
        assert!(inv.hosts().any(|h| h.key == "reserved"));
        assert!(!inv.hosts().any(|h| h.key == "k04999"));
        assert!(inv.hosts().any(|h| h.key == "k04998"));
    }

    #[test]
    fn view_sorts_online_first_and_flags_online() {
        let now = 1_763_830_000;
        let inv = Inventory::from_hosts(vec![
            host("aa:bb:cc:dd:ee:01", now - 1000, Some(now - 400)),
            host("aa:bb:cc:dd:ee:02", now - 1000, Some(now - 10)),
        ]);
        let v = inv.view(now, &lan());
        assert_eq!(v["now"], now);
        let hosts = v["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0]["key"], "aa:bb:cc:dd:ee:02");
        assert_eq!(hosts[0]["online"], true);
        assert_eq!(hosts[1]["online"], false);
        assert_eq!(hosts[0]["interface_name"], "LAN");
        assert_eq!(hosts[0]["sources"], serde_json::json!(["neighbour"]));
    }

    #[test]
    fn view_wire_format_omits_unknowns() {
        let now = 1000;
        let mut h = host("id:01:aa", 900, None);
        h.mac = None;
        let v = Inventory::from_hosts(vec![h]).view(now, &lan());
        let h = v["hosts"][0].as_object().unwrap();
        for absent in ["mac", "client_id", "name", "lease", "last_seen"] {
            assert!(!h.contains_key(absent), "{absent}: {h:?}");
        }
        assert_eq!(h["first_seen"], 900);
        assert_eq!(h["online"], false);
        assert!(h["reserved_name"].is_null());
    }

    #[test]
    fn host_round_trips() {
        let mut h = host(MAC, 1, Some(2));
        h.client_id = Some("01:aa".into());
        h.lease = Some(LeaseInfo {
            state: "active".into(),
            expires: 9000,
        });
        let json = serde_json::to_value(&h).unwrap();
        assert_eq!(json["client_id"], "01:aa");
        let back: Host = serde_json::from_value(json).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn ipv6_keeps_four_newest_and_drops_link_local() {
        let mut inv = Inventory::from_hosts(Vec::new());
        let mut s = snap();
        s.neigh.push(neigh(MAC, "fe80::1", "ue1", "STALE"));
        inv.observe(&s, 1000);
        assert_eq!(
            only(&inv).ipv6,
            ["fe80::1".parse::<std::net::Ipv6Addr>().unwrap()]
        );
        for (i, now) in [(1, 1030), (2, 1060), (3, 1090), (4, 1120), (5, 1150)] {
            let mut s = snap();
            s.neigh
                .push(neigh(MAC, &format!("2001:db8::{i}"), "ue1", "STALE"));
            inv.observe(&s, now);
        }
        let want: Vec<std::net::Ipv6Addr> =
            ["2001:db8::5", "2001:db8::4", "2001:db8::3", "2001:db8::2"]
                .iter()
                .map(|a| a.parse().unwrap())
                .collect();
        assert_eq!(only(&inv).ipv6, want);
    }

    fn home_router() -> Document {
        let path = format!(
            "{}/../sensr-import-opnsense/tests/golden/home-router.sensr.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(&path).expect("importer golden"))
            .expect("document")
    }

    #[test]
    fn reservations_from_the_document() {
        let doc = home_router();
        let r = reservations(&doc);
        let nas = r
            .iter()
            .find(|r| r.key == "02:00:5e:10:00:0a")
            .expect("nas");
        assert_eq!(nas.mac.as_deref(), Some("02:00:5e:10:00:0a"));
        assert_eq!(nas.client_id, None);
        assert_eq!(nas.ip, Some("192.168.1.10".parse().unwrap()));
        assert_eq!(nas.hostname.as_deref(), Some("nas"));
        assert_eq!(nas.interface.as_deref(), Some("lan"));
        let thermostat = r
            .iter()
            .find(|r| r.hostname.as_deref() == Some("thermostat"))
            .unwrap();
        assert_eq!(thermostat.interface.as_deref(), Some("opt1"));
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn subnet_ids_follow_kea_and_fall_back_to_the_containing_interface() {
        let mut doc = home_router();
        let lan_subnet: sensr_schema::array::Uuid =
            "13bd4fc8-a09b-4bc7-a6b4-026ebf8ad3e3".parse().unwrap();
        let m = subnet_ifaces(&doc, &internal_interfaces(&doc));
        assert_eq!(
            m.get(&kea_subnet_id(&lan_subnet)).map(String::as_str),
            Some("lan")
        );
        assert_eq!(m.len(), 3);
        // an unbound subnet is placed by the internal interface that holds it
        for (_, s) in doc.dhcpv4.subnets.iter_mut() {
            s.interface = None;
        }
        let m = subnet_ifaces(&doc, &internal_interfaces(&doc));
        assert_eq!(
            m.get(&kea_subnet_id(&lan_subnet)).map(String::as_str),
            Some("lan")
        );
        let ids: BTreeSet<&str> = m.values().map(String::as_str).collect();
        assert_eq!(ids, BTreeSet::from(["lan", "opt1", "opt2"]));
    }
}
