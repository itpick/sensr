//! The host inventory: every device seen on an internal network, merged by
//! MAC from the neighbour table, Kea's leases and the configured
//! reservations (docs/superpowers/specs/2026-11-22-host-inventory-design.md).
//!
//! The model and merge ([`Inventory`]), its file ([`HostStore`]) and the
//! 30 s loop that feeds both ([`HostCollector`]).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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
    /// What the device said about itself in DHCP and mDNS (MAC rows only).
    #[serde(default, skip_serializing_if = "HostEvidence::is_empty")]
    pub evidence: HostEvidence,
}

/// Most mDNS service types kept per host.
pub const MAX_MDNS_SERVICES: usize = 16;

/// Passive evidence about a host, kept on its row: what its DHCP requests
/// and mDNS announcements said. Strings are at most 128 bytes.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct HostEvidence {
    /// DHCP option 60.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp_vendor: Option<String>,
    /// DHCP option 55, comma-joined decimal option codes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp_prl: Option<String>,
    /// DHCP option 12.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp_hostname: Option<String>,
    /// Advertised service types (`_ipp._tcp`), at most [`MAX_MDNS_SERVICES`].
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub mdns_services: BTreeSet<String>,
    /// TXT `model=` / `md=` / `am=`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mdns_model: Option<String>,
    /// The instance name it announces (`Living Room`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mdns_name: Option<String>,
}

/// One packet's worth of evidence for [`HostCollector::record_evidence`].
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct EvidenceUpdate {
    pub dhcp_vendor: Option<String>,
    pub dhcp_prl: Option<String>,
    pub dhcp_hostname: Option<String>,
    pub mdns_services: Vec<String>,
    pub mdns_model: Option<String>,
    pub mdns_name: Option<String>,
}

impl EvidenceUpdate {
    /// Carries nothing.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

fn cap(s: &str) -> String {
    let mut at = s.len().min(sensr_fingerprint::MAX_STRING);
    while !s.is_char_boundary(at) {
        at -= 1;
    }
    s[..at].to_owned()
}

impl HostEvidence {
    /// Nothing recorded.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Merges one packet's evidence. DHCP fields take the latest value (a
    /// client sends the same ones in every request); the mDNS model and
    /// name keep the first one, since one device announces several
    /// instances and alternating between them would rewrite the inventory
    /// every few seconds; services accumulate up to [`MAX_MDNS_SERVICES`].
    pub fn merge(&mut self, u: &EvidenceUpdate) {
        let latest = |f: &mut Option<String>, v: &Option<String>| {
            if let Some(v) = v {
                *f = Some(cap(v));
            }
        };
        latest(&mut self.dhcp_vendor, &u.dhcp_vendor);
        latest(&mut self.dhcp_prl, &u.dhcp_prl);
        latest(&mut self.dhcp_hostname, &u.dhcp_hostname);
        let first = |f: &mut Option<String>, v: &Option<String>| {
            if f.is_none() {
                *f = v.as_deref().map(cap);
            }
        };
        first(&mut self.mdns_model, &u.mdns_model);
        first(&mut self.mdns_name, &u.mdns_name);
        self.add_services(u.mdns_services.iter().map(String::as_str));
    }

    fn add_services<'a>(&mut self, services: impl Iterator<Item = &'a str>) {
        for s in services {
            if self.mdns_services.len() >= MAX_MDNS_SERVICES {
                break;
            }
            self.mdns_services.insert(cap(s));
        }
    }

    /// Takes in another row's evidence; this row's values win.
    fn absorb(&mut self, other: HostEvidence) {
        self.dhcp_vendor = self.dhcp_vendor.take().or(other.dhcp_vendor);
        self.dhcp_prl = self.dhcp_prl.take().or(other.dhcp_prl);
        self.dhcp_hostname = self.dhcp_hostname.take().or(other.dhcp_hostname);
        self.mdns_model = self.mdns_model.take().or(other.mdns_model);
        self.mdns_name = self.mdns_name.take().or(other.mdns_name);
        self.add_services(other.mdns_services.iter().map(String::as_str));
    }
}

fn confidence_str(c: sensr_fingerprint::Confidence) -> &'static str {
    match c {
        sensr_fingerprint::Confidence::High => "high",
        sensr_fingerprint::Confidence::Medium => "medium",
        sensr_fingerprint::Confidence::Low => "low",
    }
}

/// The automatic label of a MAC row: its maker and evidence through
/// [`sensr_fingerprint::classify`]. `None` for `id:` rows.
pub fn auto_label(h: &Host) -> Option<sensr_fingerprint::Label> {
    let mac = h.mac.as_deref()?.to_ascii_lowercase();
    let e = &h.evidence;
    let services: Vec<String> = e.mdns_services.iter().cloned().collect();
    Some(sensr_fingerprint::classify(&sensr_fingerprint::Evidence {
        mac: &mac,
        hostname: h.lease_hostname.as_deref().or(e.dhcp_hostname.as_deref()),
        dhcp_vendor: e.dhcp_vendor.as_deref(),
        dhcp_prl: e.dhcp_prl.as_deref(),
        mdns_services: &services,
        mdns_model: e.mdns_model.as_deref(),
    }))
}

/// The wire shape of a label (`by`: `auto` or `owner`).
pub fn label_json(l: &sensr_fingerprint::Label, by: &str) -> serde_json::Value {
    serde_json::json!({
        "maker": l.maker,
        "kind": l.kind,
        "confidence": confidence_str(l.confidence),
        "reasons": l.reasons,
        "by": by,
    })
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
            evidence: HostEvidence::default(),
        }
    }

    fn reserved(&self) -> bool {
        self.sources.contains(&Source::Reserved)
    }

    /// The prune clock: last activity, else creation.
    fn age_from(&self) -> u64 {
        self.last_seen.unwrap_or(self.first_seen)
    }

    /// Activity at `now`. Never moves `last_seen` back: without an RTC the
    /// clock reads early until NTP syncs.
    fn seen(&mut self, now: u64) {
        self.last_seen = Some(self.last_seen.map_or(now, |t| t.max(now)));
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
        self.evidence.absorb(other.evidence);
        let mine = std::mem::replace(&mut self.ipv6, other.ipv6);
        for a in mine.into_iter().rev() {
            self.add_ipv6(a);
        }
    }

    /// Equal apart from the fields that move without a structural change.
    fn same_structure(&self, other: &Host) -> bool {
        // the kernel dumps addresses in any order; only the set matters
        let strip = |h: &Host| {
            let mut ipv6 = h.ipv6.clone();
            ipv6.sort();
            Host {
                last_seen: None,
                lease: None,
                ipv6,
                ..h.clone()
            }
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
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
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
    /// (MAC, else `id:<client id>`) and Kea subnet: one device can hold a
    /// lease on each network. Kept apart from the rows so forgetting or
    /// re-keying a row does not make an unchanged lease look renewed.
    expires: BTreeMap<(String, u32), u64>,
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
            let id = (client, l.subnet_id);
            let renewed = self.primed && previous.get(&id) != Some(&l.expire);
            self.expires.insert(id, l.expire);
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
                h.seen(now);
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
            let active = n.state.iter().any(|s| ACTIVE_STATES.contains(&s.as_str()));
            let has_lease = leased.contains(&n.mac);
            let h = self.row(&n.mac, now);
            h.sources.insert(Source::Neighbour);
            h.interface = Some(iface.id.clone());
            match n.ip {
                // the active lease's address wins (Make static reserves it); a
                // STALE entry only fills a gap, as it can outlive a move
                IpAddr::V4(a) if !has_lease && (active || h.ipv4.is_none()) => h.ipv4 = Some(a),
                IpAddr::V4(_) => {}
                IpAddr::V6(a) => h.add_ipv6(a),
            }
            if active {
                h.seen(now);
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

    /// Merges evidence into the row keyed `mac` (lowercase colon form).
    /// Never creates a row: the inventory follows leases and neighbours.
    /// [`Change::Seen`] when the merged evidence differs, so a host
    /// re-announcing the same thing writes nothing and a new detail is
    /// saved within the `last_seen` throttle.
    pub fn record_evidence(&mut self, mac: &str, u: &EvidenceUpdate) -> Change {
        let Some(h) = self.hosts.get_mut(mac).filter(|h| h.mac.is_some()) else {
            return Change::None;
        };
        let before = h.evidence.clone();
        h.evidence.merge(u);
        if h.evidence == before {
            Change::None
        } else {
            Change::Seen
        }
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
    ///
    /// Retention is skipped while `now` is behind the newest stamp in the
    /// inventory: the clock has not synced yet and cannot age anything.
    pub fn prune(&mut self, now: u64) -> bool {
        let before = self.hosts.len();
        let newest = self
            .hosts
            .values()
            .map(|h| h.age_from().max(h.first_seen))
            .max()
            .unwrap_or(0);
        if now >= newest {
            self.hosts
                .retain(|_, h| h.reserved() || now.saturating_sub(h.age_from()) <= RETENTION_SECS);
        }
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
                // always strings: the interface id (empty if unknown) and its
                // description, else the id in capitals for one no longer internal
                let id = h.interface.as_deref().unwrap_or_default();
                let name = match internal.iter().find(|i| i.id == id) {
                    Some(i) => i.descr.clone(),
                    None => id.to_uppercase(),
                };
                v["interface"] = id.into();
                v["interface_name"] = name.into();
                v["online"] = online(h).into();
                if let Some(l) = auto_label(h) {
                    v["label"] = label_json(&l, "auto");
                }
                v
            })
            .collect();
        serde_json::json!({ "now": now, "hosts": hosts })
    }
}

/// Minimum seconds between writes for `last_seen`-only changes.
const FLUSH_SECS: u64 = 300;

/// On-disk format version.
const FILE_VERSION: u64 = 1;

#[derive(Serialize)]
struct FileOut<'a> {
    version: u64,
    hosts: Vec<&'a Host>,
}

#[derive(Deserialize)]
struct FileIn {
    version: u64,
    hosts: Vec<Host>,
}

/// Persists the inventory to a JSON file, throttling `last_seen`-only writes.
pub struct HostStore {
    path: PathBuf,
    last_flush: Option<u64>,
    dirty: Change,
}

impl HostStore {
    /// A store writing to `path`.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            last_flush: None,
            dirty: Change::None,
        }
    }

    /// The saved hosts; empty (with a warning) when the file is missing,
    /// unparsable or of another version. An unusable file is renamed to
    /// `hosts.json.bad` (replacing an older one) so the next flush keeps it.
    pub fn load(&self) -> Vec<Host> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(path = %self.path.display(), error = %e, "reading host inventory");
                }
                return Vec::new();
            }
        };
        match serde_json::from_slice::<FileIn>(&bytes) {
            Ok(f) if f.version == FILE_VERSION => return f.hosts,
            Ok(f) => {
                tracing::warn!(
                    version = f.version,
                    "host inventory has an unknown version; starting empty"
                );
            }
            Err(e) => {
                tracing::warn!(path = %self.path.display(), error = %e, "host inventory is unreadable; starting empty");
            }
        }
        // the next flush would overwrite it; keep it for a look (or a newer agent)
        let bad = self.path.with_extension("json.bad");
        match std::fs::rename(&self.path, &bad) {
            Ok(()) => tracing::warn!(path = %bad.display(), "kept the old host inventory"),
            Err(e) => {
                tracing::warn!(path = %bad.display(), error = %e, "keeping the old host inventory")
            }
        }
        Vec::new()
    }

    /// Records a change, keeping the strongest pending one.
    pub fn note(&mut self, c: Change) {
        self.dirty = self.dirty.max(c);
    }

    /// Writes when a structural change is pending, or a `Seen` one is and the
    /// throttle has elapsed. Returns whether it wrote.
    pub fn maybe_flush(&mut self, inv: &Inventory, now: u64) -> std::io::Result<bool> {
        let due = match self.dirty {
            Change::None => false,
            Change::Structural => true,
            Change::Seen => self
                .last_flush
                .is_none_or(|t| now.saturating_sub(t) >= FLUSH_SECS),
        };
        if due {
            self.flush(inv, now)?;
        }
        Ok(due)
    }

    /// Writes unconditionally (for shutdown).
    pub fn flush(&mut self, inv: &Inventory, now: u64) -> std::io::Result<()> {
        use std::io::Write;
        let dir = self.path.parent().filter(|p| !p.as_os_str().is_empty());
        if let Some(dir) = dir {
            std::fs::create_dir_all(dir)?;
        }
        let out = FileOut {
            version: FILE_VERSION,
            hosts: inv.hosts().collect(),
        };
        let bytes = serde_json::to_vec(&out).map_err(std::io::Error::other)?;
        let tmp = self.path.with_extension("json.tmp");
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &self.path)?;
        self.dirty = Change::None;
        self.last_flush = Some(now);
        Ok(())
    }
}

/// Enabled host modes of `doc`: lowercase MAC → `isolated` / `quarantine`.
fn host_modes(doc: &Document) -> BTreeMap<String, &'static str> {
    use sensr_schema::models::firewall::HostModeKind;
    doc.firewall
        .host_modes
        .values()
        .filter(|h| h.enabled)
        .map(|h| {
            let mode = match h.mode {
                HostModeKind::Isolated => "isolated",
                HostModeKind::Quarantine => "quarantine",
            };
            (h.mac.to_string(), mode)
        })
        .collect()
}

/// Enabled owner labels of `doc`: lowercase MAC → the entry. An entry for a
/// MAC that is not in the inventory is kept and applies when that host
/// appears.
fn host_labels(doc: &Document) -> BTreeMap<String, sensr_schema::models::hosts::HostLabel> {
    doc.hosts
        .labels
        .values()
        .filter(|l| l.enabled)
        .map(|l| (l.mac.to_string(), l.clone()))
        .collect()
}

/// `label` (the automatic one, as wire JSON) with the owner's fields laid
/// over it: a set field wins, `by` becomes `owner`, confidence `high` and
/// the first reason `Set by you`.
fn overlay_label(label: &mut serde_json::Value, owner: &sensr_schema::models::hosts::HostLabel) {
    let maker = owner
        .maker
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty());
    if owner.kind.is_none() && maker.is_none() {
        return;
    }
    if let Some(k) = owner.kind {
        label["kind"] = serde_json::json!(k);
    }
    if let Some(m) = maker {
        label["maker"] = m.into();
    }
    let mut reasons = vec![serde_json::Value::from("Set by you")];
    if let Some(auto) = label["reasons"].as_array() {
        reasons.extend(auto.iter().cloned());
    }
    label["reasons"] = reasons.into();
    label["confidence"] = "high".into();
    label["by"] = "owner".into();
}

/// How often the collector polls its sources.
const POLL: std::time::Duration = std::time::Duration::from_secs(30);

/// Reads the neighbour table and Kea's leases (at call time).
pub type Sources = Arc<dyn Fn() -> (Vec<NeighEntry>, Vec<KeaLease>) + Send + Sync>;

struct Collected {
    inv: Inventory,
    store: HostStore,
    /// Reservations and interfaces of the applied document; `neigh` and
    /// `leases` are filled per poll.
    snap: Snapshot,
    /// No document applied yet: polling would read every loaded
    /// reservation as removed.
    ready: bool,
    /// Hosts in a mode (enabled `firewall.host_modes` entries of the
    /// applied document): MAC → `isolated` / `quarantine`.
    modes: BTreeMap<String, &'static str>,
    /// Owner labels (enabled `hosts.labels` entries of the applied
    /// document), by lowercase MAC.
    labels: BTreeMap<String, sensr_schema::models::hosts::HostLabel>,
}

/// The host inventory service: polls [`Sources`] every 30 s, merges them into
/// the [`Inventory`] and persists it through a [`HostStore`].
pub struct HostCollector {
    sources: Sources,
    state: Mutex<Collected>,
    /// Called after each poll with what it read (the ARP interceptor's
    /// inputs follow the inventory's).
    on_poll: Mutex<Option<PollHook>>,
}

/// Sees each poll's neighbour table and leases.
pub type PollHook = Arc<dyn Fn(&[NeighEntry], &[KeaLease]) + Send + Sync>;

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl HostCollector {
    /// Loads what `store` saved; polls nothing until [`Self::set_document`].
    pub fn new(store: HostStore, sources: Sources) -> Arc<Self> {
        let inv = Inventory::from_hosts(store.load());
        Arc::new(Self {
            sources,
            state: Mutex::new(Collected {
                inv,
                store,
                snap: Snapshot {
                    neigh: Vec::new(),
                    leases: Vec::new(),
                    reservations: Vec::new(),
                    internal: Vec::new(),
                    subnet_iface: BTreeMap::new(),
                },
                ready: false,
                modes: BTreeMap::new(),
                labels: BTreeMap::new(),
            }),
            on_poll: Mutex::new(None),
        })
    }

    /// Runs `hook` after every poll, outside the inventory lock.
    pub fn on_poll(&self, hook: PollHook) {
        *lock(&self.on_poll) = Some(hook);
    }

    /// After an apply: the document's internal interfaces, Kea subnets,
    /// reservations and host modes.
    pub fn set_document(&self, doc: &Document) {
        let internal = internal_interfaces(doc);
        let modes = host_modes(doc);
        let labels = host_labels(doc);
        let mut st = lock(&self.state);
        st.modes = modes;
        st.labels = labels;
        st.snap.subnet_iface = subnet_ifaces(doc, &internal);
        st.snap.reservations = reservations(doc);
        st.snap.internal = internal;
        st.ready = true;
    }

    /// One poll at `now`: merge, prune, persist when due. Write failures are
    /// logged; the in-memory inventory stays authoritative.
    pub fn poll(&self, now: u64) {
        if !lock(&self.state).ready {
            return;
        }
        // outside the lock: this runs `ip` and reads Kea's files
        let (neigh, leases) = (self.sources)();
        let (neigh, leases) = {
            let mut st = lock(&self.state);
            let st = &mut *st;
            st.snap.neigh = neigh;
            st.snap.leases = leases;
            let change = st.inv.observe(&st.snap, now);
            let read = (
                std::mem::take(&mut st.snap.neigh),
                std::mem::take(&mut st.snap.leases),
            );
            st.store.note(change);
            if st.inv.prune(now) {
                st.store.note(Change::Structural);
            }
            if let Err(e) = st.store.maybe_flush(&st.inv, now) {
                tracing::warn!(error = %e, "saving the host inventory");
            }
            read
        };
        let hook = lock(&self.on_poll).clone();
        if let Some(hook) = hook {
            hook(&neigh, &leases);
        }
    }

    /// Starts polling in a thread.
    pub fn start(self: &Arc<Self>) {
        let s = Arc::clone(self);
        let r = std::thread::Builder::new()
            .name("sensr-hosts".into())
            .spawn(move || {
                loop {
                    s.poll(unix_now());
                    std::thread::sleep(POLL);
                }
            });
        if let Err(e) = r {
            tracing::error!(error = %e, "host collector not started");
        }
    }

    /// The wire format ([`Inventory::view`]), each host in a mode with its
    /// `mode` (`isolated` / `quarantine`; omitted when Normal).
    pub fn view(&self, now: u64) -> serde_json::Value {
        let st = lock(&self.state);
        let mut v = st.inv.view(now, &st.snap.internal);
        if let Some(hosts) = v["hosts"].as_array_mut() {
            for h in hosts {
                if let Some(mode) = h["mac"].as_str().and_then(|m| st.modes.get(m)) {
                    h["mode"] = (*mode).into();
                }
                let owner = h["mac"]
                    .as_str()
                    .and_then(|m| st.labels.get(&m.to_ascii_lowercase()));
                if let (Some(owner), Some(label)) = (owner, h.get_mut("label")) {
                    overlay_label(label, owner);
                }
            }
        }
        v
    }

    /// Hosts seen within [`ONLINE_SECS`] of `now` with a MAC, an IPv4
    /// address and an interface: `(mac, ipv4, interface id)`.
    pub fn online_v4(&self, now: u64) -> Vec<(String, Ipv4Addr, String)> {
        let st = lock(&self.state);
        st.inv
            .hosts()
            .filter(|h| {
                h.last_seen
                    .is_some_and(|t| now.saturating_sub(t) <= ONLINE_SECS)
            })
            .filter_map(|h| Some((h.mac.clone()?, h.ipv4?, h.interface.clone()?)))
            .collect()
    }

    /// The MAC of the inventory host holding `ip`; when a stale row still
    /// lists the address too, the most recently seen one.
    pub fn mac_for_ip(&self, ip: IpAddr) -> Option<String> {
        let st = lock(&self.state);
        st.inv
            .hosts()
            .filter(|h| match ip {
                IpAddr::V4(a) => h.ipv4 == Some(a),
                IpAddr::V6(a) => h.ipv6.contains(&a),
            })
            .filter_map(|h| Some((h.last_seen, h.mac.clone()?)))
            .max()
            .map(|(_, mac)| mac)
    }

    /// Forgets an unreserved host and saves at once; `false` if `key` is
    /// reserved or unknown.
    pub fn forget(&self, key: &str) -> bool {
        let mut st = lock(&self.state);
        let st = &mut *st;
        if !st.inv.forget(key) {
            return false;
        }
        st.store.note(Change::Structural);
        if let Err(e) = st.store.flush(&st.inv, unix_now()) {
            tracing::warn!(error = %e, "saving the host inventory");
        }
        true
    }

    /// Merges one packet's evidence into an existing MAC row
    /// ([`Inventory::record_evidence`]); saved with the next poll's flush.
    pub fn record_evidence(&self, mac: &str, u: &EvidenceUpdate) -> Change {
        let mut st = lock(&self.state);
        let c = st.inv.record_evidence(mac, u);
        st.store.note(c);
        c
    }

    /// Final save (clean shutdown).
    pub fn shutdown(&self) {
        let mut st = lock(&self.state);
        let st = &mut *st;
        if let Err(e) = st.store.flush(&st.inv, unix_now()) {
            tracing::warn!(error = %e, "saving the host inventory");
        }
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
            evidence: HostEvidence::default(),
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

    #[test]
    fn two_leases_for_one_mac_are_not_activity() {
        // the same device leased on LAN and LAN2: neither expiry moves
        let two = |a: u64, b: u64| {
            let mut s = snap();
            s.subnet_iface.insert(8, "opt1".into());
            s.leases.push(lease(Some(MAC), None, a));
            let mut l2 = lease(Some(MAC), None, b);
            l2.address = "192.168.72.50".parse().unwrap();
            l2.subnet_id = 8;
            s.leases.push(l2);
            s
        };
        let mut inv = Inventory::from_hosts(Vec::new());
        inv.observe(&two(9000, 9500), 1000);
        assert_eq!(inv.observe(&two(9000, 9500), 1030), Change::None);
        assert_eq!(inv.observe(&two(9000, 9500), 1060), Change::None);
        assert_eq!(only(&inv).last_seen, None);
        // renewing one of them is activity
        assert_eq!(inv.observe(&two(9030, 9500), 1090), Change::Seen);
        assert_eq!(only(&inv).last_seen, Some(1090));
    }

    #[test]
    fn stale_neighbour_does_not_override_the_lease_address() {
        let leased_with = |state: &str| {
            let mut s = with_lease(9000);
            s.neigh.push(neigh(MAC, "192.168.68.77", "ue1", state));
            s
        };
        for state in ["STALE", "REACHABLE"] {
            let mut inv = Inventory::from_hosts(Vec::new());
            inv.observe(&leased_with(state), 1000);
            assert_eq!(
                only(&inv).ipv4,
                Some("192.168.68.50".parse().unwrap()),
                "{state}"
            );
        }
        // without a lease, a STALE entry fills a missing address but does not
        // replace a known one; an active entry does
        let mut inv = Inventory::from_hosts(Vec::new());
        inv.observe(&with_neigh("STALE"), 1000);
        assert_eq!(only(&inv).ipv4, Some("192.168.68.50".parse().unwrap()));
        let mut s = snap();
        s.neigh.push(neigh(MAC, "192.168.68.77", "ue1", "STALE"));
        inv.observe(&s, 1030);
        assert_eq!(only(&inv).ipv4, Some("192.168.68.50".parse().unwrap()));
        let mut s = snap();
        s.neigh
            .push(neigh(MAC, "192.168.68.77", "ue1", "REACHABLE"));
        inv.observe(&s, 1060);
        assert_eq!(only(&inv).ipv4, Some("192.168.68.77".parse().unwrap()));
    }

    #[test]
    fn last_seen_never_moves_backwards() {
        // a poll before NTP sync: the clock reads earlier than what is stored
        let mut h = host(MAC, 4_000_000, Some(5_000_000));
        h.ipv4 = Some("192.168.68.50".parse().unwrap());
        let mut inv = Inventory::from_hosts(vec![h]);
        assert_eq!(inv.observe(&with_neigh("REACHABLE"), 1000), Change::None);
        assert_eq!(only(&inv).last_seen, Some(5_000_000));
        // a renewed lease neither
        let mut inv = Inventory::from_hosts(vec![host(MAC, 4_000_000, Some(5_000_000))]);
        inv.observe(&with_lease(9000), 1000);
        inv.observe(&with_lease(9030), 1030);
        assert_eq!(only(&inv).last_seen, Some(5_000_000));
    }

    #[test]
    fn prune_waits_while_the_clock_is_behind_the_inventory() {
        let newest = 20_000_000;
        let mut inv = Inventory::from_hosts(vec![
            host("aa:bb:cc:dd:ee:02", newest, Some(newest)),
            host("aa:bb:cc:dd:ee:03", 1000, Some(1000)),
        ]);
        // behind the newest stamp: the clock is not trusted to age anything
        assert!(!inv.prune(newest - 1));
        assert_eq!(inv.hosts().count(), 2);
        // once it catches up, retention applies again
        assert!(inv.prune(newest));
        assert_eq!(inv.hosts().count(), 1);
    }

    #[test]
    fn ipv6_order_alone_is_not_structural() {
        let both = |a: &str, b: &str| {
            let mut s = snap();
            s.neigh.push(neigh(MAC, a, "ue1", "STALE"));
            s.neigh.push(neigh(MAC, b, "ue1", "STALE"));
            s
        };
        let mut inv = Inventory::from_hosts(Vec::new());
        inv.observe(&both("2001:db8::1", "2001:db8::2"), 1000);
        assert_eq!(
            inv.observe(&both("2001:db8::2", "2001:db8::1"), 1030),
            Change::None
        );
        assert_eq!(
            inv.observe(&both("2001:db8::1", "2001:db8::2"), 1060),
            Change::None
        );
        // a new address still is
        assert_eq!(
            inv.observe(&both("2001:db8::1", "2001:db8::3"), 1090),
            Change::Structural
        );
    }

    /// The `view()` the UI parses: a seen host, a reservation-only host on an
    /// interface that is no longer internal, and one with no interface at all.
    /// The UI's tests parse the same file (`tests/golden/hosts-view.json`).
    #[test]
    fn view_matches_the_ui_contract() {
        let mut s = with_neigh("REACHABLE");
        let mut gone = reservation("aa:bb:cc:dd:ee:09", Some("aa:bb:cc:dd:ee:09"), None);
        gone.interface = Some("opt9".into());
        gone.hostname = Some("camera".into());
        gone.ip = Some("10.9.0.5".parse().unwrap());
        s.reservations.push(gone);
        let mut nowhere = reservation("id:01:cc", None, Some("01:cc"));
        nowhere.interface = None;
        nowhere.hostname = Some("orphan".into());
        s.reservations.push(nowhere);
        let mut inv = Inventory::from_hosts(Vec::new());
        inv.observe(&s, 1000);
        let v = inv.view(1010, &lan());
        let golden = format!(
            "{}/tests/golden/hosts-view.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let want: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&golden).expect("golden")).unwrap();
        assert_eq!(
            v,
            want,
            "actual:\n{}",
            serde_json::to_string_pretty(&v).unwrap()
        );
        let hosts = v["hosts"].as_array().unwrap();
        let camera = hosts.iter().find(|h| h["name"] == "camera").unwrap();
        assert_eq!(camera["interface"], "opt9");
        assert_eq!(camera["interface_name"], "OPT9");
        let orphan = hosts.iter().find(|h| h["name"] == "orphan").unwrap();
        assert_eq!(orphan["interface"], "");
        assert_eq!(orphan["interface_name"], "");
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
    fn dhcp_update() -> EvidenceUpdate {
        EvidenceUpdate {
            dhcp_vendor: Some("android-dhcp-14".into()),
            dhcp_prl: Some("1,3,6,15,26,28,51,58,59,43".into()),
            dhcp_hostname: Some("Pixel-8".into()),
            ..EvidenceUpdate::default()
        }
    }

    /// Review focus 4: a host repeating itself never marks the inventory.
    #[test]
    fn same_evidence_is_not_a_change() {
        let mut inv = Inventory::from_hosts(vec![host(MAC, 1, Some(2))]);
        assert_eq!(inv.record_evidence(MAC, &dhcp_update()), Change::Seen);
        assert_eq!(inv.record_evidence(MAC, &dhcp_update()), Change::None);
        let mdns = EvidenceUpdate {
            mdns_services: vec!["_googlecast._tcp".into()],
            mdns_name: Some("Living Room".into()),
            ..EvidenceUpdate::default()
        };
        assert_eq!(inv.record_evidence(MAC, &mdns), Change::Seen);
        for _ in 0..5 {
            assert_eq!(inv.record_evidence(MAC, &mdns), Change::None);
        }
        // another instance of the same device does not flip the name back and forth
        let other = EvidenceUpdate {
            mdns_name: Some("Living Room speaker group".into()),
            ..mdns.clone()
        };
        assert_eq!(inv.record_evidence(MAC, &other), Change::None);
        assert_eq!(
            only(&inv).evidence.mdns_name.as_deref(),
            Some("Living Room")
        );
        // through the collector: nothing pending, nothing written
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.json");
        let mut store = HostStore::new(path.clone());
        store.flush(&inv, 1).unwrap();
        let c = HostCollector::new(HostStore::new(path), Arc::new(|| (Vec::new(), Vec::new())));
        assert_eq!(c.record_evidence(MAC, &mdns), Change::None);
        assert_eq!(lock(&c.state).store.dirty, Change::None);
        assert_eq!(
            c.record_evidence(
                MAC,
                &EvidenceUpdate {
                    mdns_services: vec!["_airplay._tcp".into()],
                    ..EvidenceUpdate::default()
                }
            ),
            Change::Seen
        );
        assert_eq!(lock(&c.state).store.dirty, Change::Seen);
    }

    #[test]
    fn evidence_for_unknown_mac_creates_no_row() {
        let mut inv = Inventory::from_hosts(vec![host(MAC, 1, Some(2))]);
        assert_eq!(
            inv.record_evidence("aa:bb:cc:dd:ee:77", &dhcp_update()),
            Change::None
        );
        let mut cid = host("id:01:aa", 1, None);
        cid.mac = None;
        let mut inv2 = Inventory::from_hosts(vec![cid]);
        assert_eq!(
            inv2.record_evidence("id:01:aa", &dhcp_update()),
            Change::None
        );
        assert_eq!(inv.hosts().count(), 1);
        assert!(only(&inv).evidence.is_empty());
    }

    #[test]
    fn evidence_merges_and_caps_services() {
        let mut e = HostEvidence::default();
        e.merge(&EvidenceUpdate {
            mdns_services: (0..10).map(|i| format!("_a{i}._tcp")).collect(),
            mdns_model: Some("x".repeat(300)),
            ..EvidenceUpdate::default()
        });
        e.merge(&EvidenceUpdate {
            mdns_services: (0..10).map(|i| format!("_b{i}._tcp")).collect(),
            ..EvidenceUpdate::default()
        });
        assert_eq!(e.mdns_services.len(), MAX_MDNS_SERVICES);
        assert_eq!(e.mdns_model.as_deref().map(str::len), Some(128));
        // a DHCP update without a field keeps the old value
        e.merge(&dhcp_update());
        e.merge(&EvidenceUpdate {
            dhcp_hostname: Some("pixel".into()),
            ..EvidenceUpdate::default()
        });
        assert_eq!(e.dhcp_vendor.as_deref(), Some("android-dhcp-14"));
        assert_eq!(e.dhcp_hostname.as_deref(), Some("pixel"));
    }

    #[test]
    fn absorb_merges_evidence_mac_row_wins() {
        let mut mac_row = host(MAC, 1, Some(2));
        mac_row.evidence.dhcp_vendor = Some("MSFT 5.0".into());
        mac_row.evidence.mdns_services.insert("_smb._tcp".into());
        let mut cid = host("id:01:aa", 1, None);
        cid.mac = None;
        cid.evidence.dhcp_vendor = Some("other".into());
        cid.evidence.dhcp_prl = Some("1,3,6".into());
        cid.evidence.mdns_services.insert("_ipp._tcp".into());
        mac_row.absorb(cid);
        let e = &mac_row.evidence;
        assert_eq!(e.dhcp_vendor.as_deref(), Some("MSFT 5.0"));
        assert_eq!(e.dhcp_prl.as_deref(), Some("1,3,6"));
        assert_eq!(e.mdns_services.len(), 2);
    }

    #[test]
    fn evidence_is_omitted_when_empty_and_old_files_load() {
        let h = host(MAC, 1, Some(2));
        let v = serde_json::to_value(&h).unwrap();
        assert!(v.get("evidence").is_none(), "{v}");
        // a hosts.json row from before evidence existed
        let old = serde_json::json!({"key": MAC, "mac": MAC, "first_seen": 1});
        let h: Host = serde_json::from_value(old).unwrap();
        assert!(h.evidence.is_empty());
        let mut h = host(MAC, 1, Some(2));
        h.evidence.mdns_services.insert("_ipp._tcp".into());
        let back: Host = serde_json::from_value(serde_json::to_value(&h).unwrap()).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn view_has_auto_label() {
        let cam = "7c:78:b2:00:00:01";
        let mut cid = host("id:01:aa", 900, None);
        cid.mac = None;
        let v = Inventory::from_hosts(vec![host(cam, 900, Some(950)), cid]).view(1000, &lan());
        let hosts = v["hosts"].as_array().unwrap();
        let c = hosts.iter().find(|h| h["key"] == cam).unwrap();
        assert_eq!(c["label"]["kind"], "camera");
        assert_eq!(c["label"]["by"], "auto");
        assert_eq!(c["label"]["maker"], "Wyze");
        assert_eq!(c["label"]["confidence"], "medium");
        assert_eq!(
            c["label"]["reasons"],
            serde_json::json!(["MAC maker: Wyze"])
        );
        let id = hosts.iter().find(|h| h["key"] == "id:01:aa").unwrap();
        assert!(id.get("label").is_none(), "{id}");
    }

    #[test]
    fn label_uses_evidence_and_dhcp_hostname() {
        // a private MAC with only a DHCP host name: the name decides
        let mut h = host("da:a1:19:00:00:01", 1, Some(2));
        h.evidence.dhcp_hostname = Some("iPhone".into());
        let l = auto_label(&h).unwrap();
        assert_eq!(l.maker.as_deref(), Some("Private MAC"));
        assert_eq!(l.kind, sensr_schema::models::hosts::HostKind::Phone);
        assert!(l.reasons.iter().any(|r| r.contains("iPhone")), "{l:?}");
        // the lease's host name wins over the DHCP option seen on the wire
        h.lease_hostname = Some("Johns-iPad".into());
        let l = auto_label(&h).unwrap();
        assert_eq!(l.kind, sensr_schema::models::hosts::HostKind::Tablet);
        assert!(l.reasons.iter().any(|r| r.contains("Johns-iPad")), "{l:?}");
        assert!(!l.reasons.iter().any(|r| r.contains("iPhone")), "{l:?}");
        // an uppercase MAC is classified in lowercase colon form
        let mut docker = host("02:42:ac:11:00:02", 1, None);
        docker.mac = Some("02:42:AC:11:00:02".into());
        assert_eq!(
            auto_label(&docker).unwrap().maker.as_deref(),
            Some("Docker")
        );
    }
}

#[cfg(test)]
mod store {
    use super::*;

    fn inv_with(macs: &[&str]) -> Inventory {
        let mut inv = Inventory::default();
        let snap = Snapshot {
            neigh: macs
                .iter()
                .enumerate()
                .map(|(i, m)| NeighEntry {
                    mac: (*m).into(),
                    ip: format!("192.168.68.{}", 10 + i).parse().unwrap(),
                    dev: "ue1".into(),
                    state: vec!["REACHABLE".into()],
                })
                .collect(),
            leases: Vec::new(),
            reservations: Vec::new(),
            internal: vec![InternalIf {
                id: "lan".into(),
                device: "ue1".into(),
                descr: "LAN".into(),
                subnets: vec!["192.168.68.0/22".parse().unwrap()],
            }],
            subnet_iface: BTreeMap::new(),
        };
        inv.observe(&snap, 1000);
        inv
    }

    fn store(dir: &tempfile::TempDir) -> HostStore {
        HostStore::new(dir.path().join("hosts.json"))
    }

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let inv = inv_with(&["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]);
        let mut s = store(&dir);
        s.flush(&inv, 0).unwrap();
        let loaded = s.load();
        let want: Vec<Host> = inv.hosts().cloned().collect();
        assert_eq!(want.len(), 2);
        assert_eq!(loaded, want);
    }

    #[test]
    fn corrupt_file_starts_empty() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hosts.json"), r#"{"version":1,"hosts":["#).unwrap();
        assert!(store(&dir).load().is_empty());
    }

    #[test]
    fn missing_and_wrong_version_start_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(store(&dir).load().is_empty());
        std::fs::write(dir.path().join("hosts.json"), r#"{"version":2,"hosts":[]}"#).unwrap();
        assert!(store(&dir).load().is_empty());
    }

    #[test]
    fn unreadable_file_is_kept_aside() {
        for bad in [r#"{"version":1,"hosts":["#, r#"{"version":2,"hosts":[]}"#] {
            let dir = tempfile::tempdir().unwrap();
            let file = dir.path().join("hosts.json");
            // a previous .bad is replaced
            std::fs::write(dir.path().join("hosts.json.bad"), "old").unwrap();
            std::fs::write(&file, bad).unwrap();
            let mut s = store(&dir);
            assert!(s.load().is_empty());
            assert_eq!(
                std::fs::read_to_string(dir.path().join("hosts.json.bad")).unwrap(),
                bad
            );
            assert!(!file.exists());
            // the first flush does not destroy it
            s.flush(&inv_with(&["aa:bb:cc:dd:ee:01"]), 0).unwrap();
            assert_eq!(
                std::fs::read_to_string(dir.path().join("hosts.json.bad")).unwrap(),
                bad
            );
        }
    }

    #[test]
    fn seen_only_changes_are_throttled() {
        let dir = tempfile::tempdir().unwrap();
        let inv = inv_with(&["aa:bb:cc:dd:ee:01"]);
        let mut s = store(&dir);
        s.note(Change::Seen);
        assert!(s.maybe_flush(&inv, 0).unwrap());
        s.note(Change::Seen);
        assert!(!s.maybe_flush(&inv, 100).unwrap());
        s.note(Change::Seen);
        assert!(s.maybe_flush(&inv, 300).unwrap());
    }

    #[test]
    fn structural_change_flushes_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let inv = inv_with(&["aa:bb:cc:dd:ee:01"]);
        let mut s = store(&dir);
        s.note(Change::Seen);
        assert!(s.maybe_flush(&inv, 0).unwrap());
        s.note(Change::Structural);
        assert!(s.maybe_flush(&inv, 10).unwrap());
        assert!(!s.maybe_flush(&inv, 11).unwrap());
    }

    #[test]
    fn no_tmp_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        let inv = inv_with(&["aa:bb:cc:dd:ee:01"]);
        store(&dir).flush(&inv, 0).unwrap();
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["hosts.json".to_owned()]);
    }

    #[test]
    fn creates_missing_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = HostStore::new(dir.path().join("sub/hosts.json"));
        s.flush(&inv_with(&["aa:bb:cc:dd:ee:01"]), 0).unwrap();
        assert_eq!(s.load().len(), 1);
    }
}

#[cfg(test)]
mod collector {
    use super::*;

    const MAC: &str = "aa:bb:cc:dd:ee:42";

    fn home_router() -> Document {
        let path = format!(
            "{}/../sensr-import-opnsense/tests/golden/home-router.sensr.json",
            env!("CARGO_MANIFEST_DIR")
        );
        serde_json::from_str(&std::fs::read_to_string(&path).expect("importer golden"))
            .expect("document")
    }

    /// A collector whose neighbour table holds one REACHABLE host on the
    /// document's LAN device.
    fn collector(dir: &tempfile::TempDir) -> (Arc<HostCollector>, Document) {
        let doc = home_router();
        let lan = internal_interfaces(&doc)
            .into_iter()
            .find(|i| i.id == "lan")
            .expect("lan");
        let ip = IpAddr::V4(lan.subnets[0].hosts().nth(41).unwrap());
        let dev = lan.device.clone();
        let sources = Arc::new(move || {
            (
                vec![NeighEntry {
                    mac: MAC.into(),
                    ip,
                    dev: dev.clone(),
                    state: vec!["REACHABLE".into()],
                }],
                Vec::new(),
            )
        });
        let c = HostCollector::new(HostStore::new(dir.path().join("hosts.json")), sources);
        c.set_document(&doc);
        (c, doc)
    }

    #[test]
    fn collector_poll_and_view() {
        let dir = tempfile::tempdir().unwrap();
        let (c, _) = collector(&dir);
        c.poll(1000);
        let v = c.view(1000);
        assert_eq!(v["now"], 1000);
        let row = v["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["key"] == MAC)
            .expect("seen host");
        assert_eq!(row["online"], true);
        assert_eq!(row["interface"], "lan");
        assert!(dir.path().join("hosts.json").exists());
    }

    #[test]
    fn collector_forget_flushes() {
        let dir = tempfile::tempdir().unwrap();
        let (c, _) = collector(&dir);
        c.poll(1000);
        let file = dir.path().join("hosts.json");
        assert!(std::fs::read_to_string(&file).unwrap().contains(MAC));
        assert!(c.forget(MAC));
        assert!(!std::fs::read_to_string(&file).unwrap().contains(MAC));
        // a reserved host stays
        assert!(!c.forget("02:00:5e:10:00:0a"));
        assert!(!c.forget("00:00:00:00:00:00"));
    }

    #[test]
    fn collector_reloads_the_saved_inventory() {
        let dir = tempfile::tempdir().unwrap();
        let (c, _) = collector(&dir);
        c.poll(1000);
        c.shutdown();
        let again = HostCollector::new(
            HostStore::new(dir.path().join("hosts.json")),
            Arc::new(|| (Vec::new(), Vec::new())),
        );
        let v = again.view(1000);
        assert!(
            v["hosts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|h| h["key"] == MAC)
        );
    }

    #[test]
    fn poll_hook_sees_the_read_and_online_v4_lists_recent_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let (c, _) = collector(&dir);
        let seen: Arc<Mutex<Vec<NeighEntry>>> = Arc::default();
        let s = Arc::clone(&seen);
        c.on_poll(Arc::new(move |neigh, _| lock(&s).extend_from_slice(neigh)));
        c.poll(1000);
        assert_eq!(lock(&seen).len(), 1);
        assert_eq!(lock(&seen)[0].mac, MAC);
        let online = c.online_v4(1000);
        assert_eq!(online.len(), 1);
        assert_eq!((online[0].0.as_str(), online[0].2.as_str()), (MAC, "lan"));
        assert!(c.online_v4(1000 + ONLINE_SECS + 1).is_empty());
    }

    #[test]
    fn poll_survives_an_unwritable_store() {
        let dir = tempfile::tempdir().unwrap();
        // the store's parent is a file, so every write fails
        std::fs::write(dir.path().join("blocker"), b"").unwrap();
        let c = HostCollector::new(
            HostStore::new(dir.path().join("blocker/hosts.json")),
            Arc::new(|| (Vec::new(), Vec::new())),
        );
        c.set_document(&home_router());
        c.poll(1000);
        c.shutdown();
        assert!(!c.view(1000)["hosts"].as_array().unwrap().is_empty());
    }

    fn with_mode(mut doc: Document, mac: &str, mode: &str) -> Document {
        use sensr_schema::PathAccess;
        doc.set_by_path(
            "firewall.host_modes.6d0de000-0000-4000-8000-000000000001",
            serde_json::json!({"mac": mac, "mode": mode}),
        )
        .unwrap();
        doc
    }

    #[test]
    fn view_includes_mode() {
        let dir = tempfile::tempdir().unwrap();
        let (c, doc) = collector(&dir);
        c.poll(1000);
        let row = |c: &HostCollector, key: &str| {
            c.view(1000)["hosts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|h| h["key"] == key)
                .cloned()
                .expect("row")
        };
        // Normal hosts carry no `mode`
        assert!(row(&c, MAC).get("mode").is_none());
        c.set_document(&with_mode(doc.clone(), MAC, "isolated"));
        assert_eq!(row(&c, MAC)["mode"], "isolated");
        // the reserved host stays Normal
        assert!(row(&c, "02:00:5e:10:00:0a").get("mode").is_none());
        c.set_document(&with_mode(doc.clone(), MAC, "quarantine"));
        assert_eq!(row(&c, MAC)["mode"], "quarantine");
        // a disabled entry is not in force
        let mut off = with_mode(doc.clone(), MAC, "quarantine");
        for h in off.firewall.host_modes.iter_mut() {
            h.1.enabled = false;
        }
        c.set_document(&off);
        assert!(row(&c, MAC).get("mode").is_none());
        c.set_document(&doc);
        assert!(row(&c, MAC).get("mode").is_none());
    }

    fn with_label(mut doc: Document, mac: &str, label: serde_json::Value) -> Document {
        use sensr_schema::PathAccess;
        let mut l = label;
        l["mac"] = mac.into();
        doc.set_by_path("hosts.labels.6d0de000-0000-4000-8000-000000000001", l)
            .unwrap();
        doc
    }

    fn row(c: &HostCollector, key: &str) -> serde_json::Value {
        c.view(1000)["hosts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|h| h["key"] == key)
            .cloned()
            .expect("row")
    }

    #[test]
    fn view_overlays_owner_label() {
        let dir = tempfile::tempdir().unwrap();
        let (c, doc) = collector(&dir);
        c.poll(1000);
        let auto = row(&c, MAC)["label"].clone();
        assert_eq!(auto["by"], "auto");

        // kind set, maker unset: kind from the owner, maker from the OUI
        c.set_document(&with_label(
            doc.clone(),
            MAC,
            serde_json::json!({"kind": "camera"}),
        ));
        let l = row(&c, MAC)["label"].clone();
        assert_eq!(l["kind"], "camera");
        assert_eq!(l["maker"], auto["maker"]);
        assert_eq!(l["by"], "owner");
        assert_eq!(l["confidence"], "high");
        assert_eq!(l["reasons"][0], "Set by you");
        assert!(
            l["reasons"].as_array().unwrap().len() > 1,
            "the guess is kept after Set by you"
        );

        // maker set, kind unset; an upper-case entry still matches
        c.set_document(&with_label(
            doc.clone(),
            &MAC.to_uppercase(),
            serde_json::json!({"maker": "Home brew"}),
        ));
        let l = row(&c, MAC)["label"].clone();
        assert_eq!(l["maker"], "Home brew");
        assert_eq!(l["kind"], auto["kind"]);
        assert_eq!(l["by"], "owner");

        // other rows are untouched
        assert_eq!(row(&c, "02:00:5e:10:00:0a")["label"]["by"], "auto");

        // a disabled entry is ignored
        let mut off = with_label(doc.clone(), MAC, serde_json::json!({"kind": "camera"}));
        for l in off.hosts.labels.iter_mut() {
            l.1.enabled = false;
        }
        c.set_document(&off);
        assert_eq!(row(&c, MAC)["label"], auto);
    }

    #[test]
    fn override_for_unknown_mac_is_kept_but_not_rendered() {
        let dir = tempfile::tempdir().unwrap();
        let (c, doc) = collector(&dir);
        c.poll(1000);
        let before = c.view(1000);
        let stranger = "aa:bb:cc:00:99:99";
        c.set_document(&with_label(
            doc.clone(),
            stranger,
            serde_json::json!({"kind": "tv", "maker": "Nobody"}),
        ));
        // no row is invented and none changes
        assert_eq!(c.view(1000), before);
        assert_eq!(lock(&c.state).labels.len(), 1, "the override is kept");
    }

    #[test]
    fn mac_for_ip_finds_the_inventory_host() {
        let dir = tempfile::tempdir().unwrap();
        let (c, doc) = collector(&dir);
        c.poll(1000);
        let lan = internal_interfaces(&doc)
            .into_iter()
            .find(|i| i.id == "lan")
            .unwrap();
        let ip = IpAddr::V4(lan.subnets[0].hosts().nth(41).unwrap());
        assert_eq!(c.mac_for_ip(ip).as_deref(), Some(MAC));
        assert_eq!(c.mac_for_ip("198.51.100.7".parse().unwrap()), None);
    }
}
