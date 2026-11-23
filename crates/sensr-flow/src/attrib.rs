//! Per-device service attribution and the active-minute rule (pure; the
//! daemon feeds it and stores what [`Attributor::drain_minute`] returns).
//!
//! **IP map.** Each DNS answer a device receives maps the answer addresses,
//! *for that device only*, to the queried name (plus the first CNAME target
//! the catalogue recognises, when the queried name itself is unknown). The
//! device's latest answer for an address wins. An entry lasts the answer TTL
//! plus [`GRACE_SECS`]; bytes to the address slide that expiry forward, so a
//! long stream after one lookup keeps its service. The map is capped per
//! device and in total ([`Caps`]); the least recently used entry goes first.
//!
//! **Bytes.** Byte deltas are gathered per (device, remote address) for the
//! minute and attributed when the minute is drained, through the device's
//! mapping at that point: bytes sampled just before the answer that maps
//! the address was processed still find it, and owner overrides apply at
//! once. A mapped name goes to its catalogue service, or, when the
//! catalogue does not know it, to a service named after its registrable
//! domain ([`registrable_domain`], category Other). Only traffic with no
//! live mapping goes to [`OTHER_BY_ADDRESS`].
//!
//! **Minute rule** (per device, per service, per minute): active when the
//! service moved at least [`BULK_BYTES`], or when the device looked up one
//! of its names in that minute or the one before (so a lookup at :55 and
//! bytes sampled at :05 still count) and it moved at least [`QUERY_BYTES`].
//! A lookup a blocklist answered does not count. Category minutes are the
//! union of their services' ([`active_categories`]).
//!
//! **Clock.** Events land in the minute of their own timestamp. A minute is
//! returned at most once: anything arriving for a minute already drained (a
//! backwards clock step) is dropped, and so is anything more than
//! [`MAX_BACKFILL`] seconds before the newest drained minute.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use crate::dnstap::{DnstapEvent, EventKind, is_blocked};
use crate::services::{Catalogue, Category};

/// Seconds a mapping outlives its answer's TTL.
pub const GRACE_SECS: i64 = 600;
/// Bytes in a minute that make a service active on their own.
pub const BULK_BYTES: u64 = 32_768;
/// Bytes in a minute that make a service active when it was also looked up.
pub const QUERY_BYTES: u64 = 4_096;
/// Service name for traffic with no (known) DNS name.
pub const OTHER_BY_ADDRESS: &str = "Other (by address)";
/// How far before the newest drained minute a minute may still be written.
pub const MAX_BACKFILL: i64 = 86_400;
/// Second-level labels that, with the top-level label, form a public
/// suffix: under them the registrable domain has three labels.
const TWO_LEVEL_SUFFIXES: [&str; 9] = [
    "co.uk", "com.au", "co.jp", "co.nz", "com.br", "co.in", "org.uk", "ac.uk", "gov.uk",
];
/// Undrained minutes kept at most (the furthest in the future go first).
const MAX_PENDING: usize = 2 * 1440;

fn minute_of(t: i64) -> i64 {
    t.saturating_sub(t.rem_euclid(60))
}

/// IP-map size limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Entries per device.
    pub per_device: usize,
    /// Entries over all devices.
    pub total: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            per_device: 4096,
            total: 65_536,
        }
    }
}

/// One device's minute.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostMinute {
    /// Services the device was active on.
    pub services_active: BTreeSet<String>,
    /// Names looked up: (qname, count, answered by a blocklist), by name.
    pub queries: Vec<(String, u32, bool)>,
    /// Bytes (both directions) per service.
    pub bytes_by_service: BTreeMap<String, u64>,
}

/// One minute, per device MAC.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MinuteResult {
    /// Devices with any lookups or traffic that minute.
    pub per_host: BTreeMap<String, HostMinute>,
}

/// What an address or a lookup is attributed to: the queried name, and the
/// first CNAME target the catalogue knew when the queried name was unknown.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Target {
    qname: String,
    alias: Option<String>,
}

impl Target {
    /// The catalogue's service, else the queried name's registrable domain.
    fn service(&self, cat: &Catalogue) -> String {
        cat.lookup(&self.qname)
            .or_else(|| self.alias.as_deref().and_then(|a| cat.lookup(a)))
            .map_or_else(|| registrable_domain(&self.qname), |(s, _)| s.to_string())
    }
}

/// The registrable domain of `name` (lowercased, no trailing dot): its last
/// two labels, or three under a known two-level public suffix (`co.uk`, …).
/// A name with fewer labels is returned whole.
pub fn registrable_domain(name: &str) -> String {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = name.split('.').collect();
    let n = labels.len();
    let keep = if n >= 3 && TWO_LEVEL_SUFFIXES.contains(&labels[n - 2..].join(".").as_str()) {
        3
    } else {
        2
    };
    labels[n.saturating_sub(keep)..].join(".")
}

#[derive(Debug)]
struct Entry {
    target: Target,
    ttl: i64,
    expires: i64,
    seq: u64,
}

#[derive(Debug, Default)]
struct Device {
    by_ip: HashMap<IpAddr, Entry>,
    /// seq → address, oldest first.
    order: BTreeMap<u64, IpAddr>,
}

#[derive(Debug, Default)]
struct Acc {
    /// Bytes per remote address, attributed when the minute is drained.
    bytes: HashMap<IpAddr, u64>,
    /// Bytes to addresses past the per-device cap (unattributed).
    overflow: u64,
    /// Unblocked lookups in this minute or the one before.
    looked_up: BTreeSet<Target>,
    queries: BTreeMap<String, (u32, bool)>,
}

/// The attribution and minute engine.
#[derive(Debug)]
pub struct Attributor {
    caps: Caps,
    devices: HashMap<String, Device>,
    /// seq → (device, address), oldest first, over all devices.
    order: BTreeMap<u64, (String, IpAddr)>,
    seq: u64,
    pending: BTreeMap<i64, HashMap<String, Acc>>,
    drained: BTreeSet<i64>,
    newest: Option<i64>,
}

impl Attributor {
    /// An empty engine with these map limits.
    pub fn new(caps: Caps) -> Self {
        Attributor {
            caps: Caps {
                per_device: caps.per_device.max(1),
                total: caps.total.max(1),
            },
            devices: HashMap::new(),
            order: BTreeMap::new(),
            seq: 0,
            pending: BTreeMap::new(),
            drained: BTreeSet::new(),
            newest: None,
        }
    }

    /// A client response for device `mac`: counts the lookup in its minute
    /// and maps the answer addresses. Queries (as opposed to responses) are
    /// ignored, since Unbound logs both for every lookup.
    pub fn on_dns(&mut self, mac: &str, ev: &DnstapEvent, cat: &Catalogue) {
        if ev.kind != EventKind::ClientResponse {
            return;
        }
        let alias = if cat.lookup(&ev.qname).is_some() {
            None
        } else {
            ev.cnames.iter().find(|c| cat.lookup(c).is_some()).cloned()
        };
        let target = Target {
            qname: ev.qname.clone(),
            alias,
        };
        let blocked = is_blocked(ev);
        let per_device = self.caps.per_device;
        if let Some(acc) = self.acc(mac, ev.time)
            && (acc.queries.len() < per_device || acc.queries.contains_key(&ev.qname))
        {
            let q = acc.queries.entry(ev.qname.clone()).or_default();
            q.0 = q.0.saturating_add(1);
            q.1 |= blocked;
        }
        if blocked {
            return;
        }
        // the lookup counts for its minute and the next
        for t in [ev.time, ev.time.saturating_add(60)] {
            if let Some(acc) = self.acc(mac, t)
                && acc.looked_up.len() < per_device
            {
                acc.looked_up.insert(target.clone());
            }
        }
        for (ip, ttl) in &ev.answers {
            if !ip.is_unspecified() {
                self.map(mac, *ip, target.clone(), i64::from(*ttl), ev.time);
            }
        }
    }

    /// `bytes` (both directions) between device `mac` and `remote`, counted
    /// in the minute of `now`. A live mapping's expiry slides forward.
    pub fn on_bytes(&mut self, mac: &str, remote: IpAddr, bytes: u64, now: i64) {
        if bytes == 0 {
            return;
        }
        self.touch(mac, remote, now);
        let per_device = self.caps.per_device;
        if let Some(acc) = self.acc(mac, now) {
            let b = if acc.bytes.len() < per_device || acc.bytes.contains_key(&remote) {
                acc.bytes.entry(remote).or_default()
            } else {
                &mut acc.overflow
            };
            *b = b.saturating_add(bytes);
        }
    }

    /// The result for the minute starting at `minute` (Unix seconds), once:
    /// a minute already drained, or more than [`MAX_BACKFILL`] before the
    /// newest drained one, gives an empty result. Also drops mappings that
    /// expired by the end of the minute.
    pub fn drain_minute(&mut self, minute: i64, cat: &Catalogue) -> MinuteResult {
        let minute = minute_of(minute);
        let mut out = MinuteResult::default();
        if !self.writable(minute) {
            self.pending.remove(&minute);
            return out;
        }
        self.drained.insert(minute);
        self.newest = Some(self.newest.map_or(minute, |n| n.max(minute)));
        let accs = self.pending.remove(&minute).unwrap_or_default();
        for (mac, acc) in accs {
            if acc.bytes.is_empty() && acc.overflow == 0 && acc.queries.is_empty() {
                // only a lookup carried over from the minute before
                continue;
            }
            let mut h = HostMinute::default();
            let dev = self.devices.get(&mac);
            let mut add = |service: String, b: u64| {
                let v = h.bytes_by_service.entry(service).or_default();
                *v = v.saturating_add(b);
            };
            if acc.overflow > 0 {
                add(OTHER_BY_ADDRESS.to_string(), acc.overflow);
            }
            for (ip, b) in &acc.bytes {
                let service = dev
                    .and_then(|d| d.by_ip.get(ip))
                    .filter(|e| e.expires >= minute)
                    .map_or_else(|| OTHER_BY_ADDRESS.to_string(), |e| e.target.service(cat));
                add(service, *b);
            }
            let looked_up: BTreeSet<String> =
                acc.looked_up.iter().map(|t| t.service(cat)).collect();
            for (s, b) in &h.bytes_by_service {
                if *b >= BULK_BYTES || (*b >= QUERY_BYTES && looked_up.contains(s.as_str())) {
                    h.services_active.insert(s.clone());
                }
            }
            h.queries = acc
                .queries
                .into_iter()
                .map(|(q, (n, blocked))| (q, n, blocked))
                .collect();
            out.per_host.insert(mac, h);
        }
        self.expire(minute.saturating_add(60));
        self.prune();
        out
    }

    /// Minutes with gathered data not yet drained, oldest first.
    pub fn pending_minutes(&self) -> Vec<i64> {
        self.pending.keys().copied().collect()
    }

    /// Mappings held, over all devices.
    pub fn map_len(&self) -> usize {
        self.order.len()
    }

    fn writable(&self, minute: i64) -> bool {
        !self.drained.contains(&minute)
            && self
                .newest
                .is_none_or(|n| minute >= n.saturating_sub(MAX_BACKFILL))
    }

    /// The accumulator for `mac` in the minute of `t`, unless that minute is
    /// no longer writable.
    fn acc(&mut self, mac: &str, t: i64) -> Option<&mut Acc> {
        let minute = minute_of(t);
        if !self.writable(minute) {
            return None;
        }
        if !self.pending.contains_key(&minute) && self.pending.len() >= MAX_PENDING {
            let last = *self.pending.keys().next_back()?;
            if minute > last {
                return None;
            }
            self.pending.remove(&last);
        }
        let bucket = self.pending.entry(minute).or_default();
        if !bucket.contains_key(mac) {
            bucket.insert(mac.to_string(), Acc::default());
        }
        bucket.get_mut(mac)
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn map(&mut self, mac: &str, ip: IpAddr, target: Target, ttl: i64, now: i64) {
        let seq = self.next_seq();
        let expires = now.saturating_add(ttl).saturating_add(GRACE_SECS);
        let dev = self.devices.entry(mac.to_string()).or_default();
        if let Some(e) = dev.by_ip.get_mut(&ip) {
            dev.order.remove(&e.seq);
            self.order.remove(&e.seq);
            *e = Entry {
                target,
                ttl,
                expires,
                seq,
            };
            dev.order.insert(seq, ip);
            self.order.insert(seq, (mac.to_string(), ip));
            return;
        }
        if dev.by_ip.len() >= self.caps.per_device
            && let Some((old, old_ip)) = dev.order.pop_first()
        {
            dev.by_ip.remove(&old_ip);
            self.order.remove(&old);
        }
        while self.order.len() >= self.caps.total {
            let Some((_, (m, old_ip))) = self.order.pop_first() else {
                break;
            };
            self.forget(&m, old_ip);
        }
        let dev = self.devices.entry(mac.to_string()).or_default();
        dev.by_ip.insert(
            ip,
            Entry {
                target,
                ttl,
                expires,
                seq,
            },
        );
        dev.order.insert(seq, ip);
        self.order.insert(seq, (mac.to_string(), ip));
    }

    /// Removes a mapping from its device (the global index is the caller's).
    fn forget(&mut self, mac: &str, ip: IpAddr) {
        if let Some(dev) = self.devices.get_mut(mac) {
            if let Some(e) = dev.by_ip.remove(&ip) {
                dev.order.remove(&e.seq);
            }
            if dev.by_ip.is_empty() {
                self.devices.remove(mac);
            }
        }
    }

    /// Slides the expiry of the live mapping for (`mac`, `ip`) at `now` and
    /// marks it recently used; an expired one is dropped.
    fn touch(&mut self, mac: &str, ip: IpAddr, now: i64) {
        let seq = self.next_seq();
        let Some(dev) = self.devices.get_mut(mac) else {
            return;
        };
        let Some(e) = dev.by_ip.get_mut(&ip) else {
            return;
        };
        let old = e.seq;
        if e.expires < now {
            self.order.remove(&old);
            self.forget(mac, ip);
            return;
        }
        let slid = now.saturating_add(e.ttl).saturating_add(GRACE_SECS);
        e.expires = e.expires.max(slid);
        e.seq = seq;
        dev.order.remove(&old);
        dev.order.insert(seq, ip);
        self.order.remove(&old);
        self.order.insert(seq, (mac.to_string(), ip));
    }

    fn expire(&mut self, now: i64) {
        let mut gone = Vec::new();
        for (mac, dev) in &self.devices {
            for (ip, e) in &dev.by_ip {
                if e.expires < now {
                    gone.push((mac.clone(), *ip, e.seq));
                }
            }
        }
        for (mac, ip, seq) in gone {
            self.order.remove(&seq);
            self.forget(&mac, ip);
        }
    }

    fn prune(&mut self) {
        if let Some(n) = self.newest {
            let floor = n.saturating_sub(MAX_BACKFILL);
            self.drained = self.drained.split_off(&floor);
            self.pending = self.pending.split_off(&floor);
        }
    }
}

/// The category a service name counts under in `cat` ([`OTHER_BY_ADDRESS`]
/// and unknown names are Other; a name listed under several categories
/// takes the first in display order).
pub fn category_of(service: &str, cat: &Catalogue) -> Category {
    cat.services()
        .filter(|(s, _)| *s == service)
        .map(|(_, c)| c)
        .min()
        .unwrap_or(Category::Other)
}

/// The categories active in a device's minute: the union of its active
/// services' categories.
pub fn active_categories(m: &HostMinute, cat: &Catalogue) -> BTreeSet<Category> {
    m.services_active
        .iter()
        .map(|s| category_of(s, cat))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A start time on a minute boundary (1.8e9 is a multiple of 60).
    const T0: i64 = 1_800_000_000;
    const KID: &str = "aa:bb:cc:00:00:01";
    const TV: &str = "aa:bb:cc:00:00:02";

    fn cat() -> &'static Catalogue {
        Catalogue::builtin()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn resp(qname: &str, answers: &[(&str, u32)], time: i64) -> DnstapEvent {
        DnstapEvent {
            kind: EventKind::ClientResponse,
            client: ip("192.168.1.100"),
            time,
            qname: qname.into(),
            qtype: 1,
            rcode: 0,
            authority_count: 0,
            answers: answers.iter().map(|(a, t)| (ip(a), *t)).collect(),
            cnames: Vec::new(),
        }
    }

    fn active(r: &MinuteResult, mac: &str, service: &str) -> bool {
        r.per_host
            .get(mac)
            .is_some_and(|h| h.services_active.contains(service))
    }

    fn service_bytes(r: &MinuteResult, mac: &str, service: &str) -> u64 {
        r.per_host
            .get(mac)
            .and_then(|h| h.bytes_by_service.get(service))
            .copied()
            .unwrap_or(0)
    }

    const YT: &str = "142.250.1.1";

    #[test]
    fn streaming_minutes_count_after_one_lookup() {
        let mut a = Attributor::new(Caps::default());
        a.on_dns(
            KID,
            &resp("rr1.googlevideo.com", &[(YT, 300)], T0 + 1),
            cat(),
        );
        let mut minutes = 0;
        for m in 0..40 {
            let t = T0 + m * 60;
            for s in 0..6 {
                a.on_bytes(KID, ip(YT), 6_000, t + s * 10);
            }
            let r = a.drain_minute(t, cat());
            assert_eq!(service_bytes(&r, KID, "YouTube"), 36_000, "minute {m}");
            minutes += usize::from(active(&r, KID, "YouTube"));
        }
        assert_eq!(minutes, 40);
    }

    #[test]
    fn background_pings_do_not_count() {
        let mut a = Attributor::new(Caps::default());
        a.on_dns(KID, &resp("www.youtube.com", &[(YT, 300)], T0 + 1), cat());
        for m in 0..30 {
            let t = T0 + m * 60;
            a.on_bytes(KID, ip(YT), 1_024, t + 5);
            let r = a.drain_minute(t, cat());
            assert!(!active(&r, KID, "YouTube"), "minute {m}");
            assert_eq!(service_bytes(&r, KID, "YouTube"), 1_024);
        }
    }

    #[test]
    fn query_plus_small_transfer_counts() {
        let mut a = Attributor::new(Caps::default());
        a.on_dns(KID, &resp("www.youtube.com", &[(YT, 300)], T0 + 1), cat());
        a.on_bytes(KID, ip(YT), 4_096, T0 + 2);
        let r = a.drain_minute(T0, cat());
        assert!(active(&r, KID, "YouTube"));
        assert_eq!(
            r.per_host[KID].queries,
            [("www.youtube.com".into(), 1, false)]
        );
        // two minutes on, with no fresh lookup, the same transfer does not
        assert!(a.drain_minute(T0 + 60, cat()).per_host.is_empty());
        a.on_bytes(KID, ip(YT), 4_096, T0 + 122);
        assert!(!active(&a.drain_minute(T0 + 120, cat()), KID, "YouTube"));
        // a lookup with too little traffic does not either
        a.on_dns(KID, &resp("www.youtube.com", &[(YT, 300)], T0 + 181), cat());
        a.on_bytes(KID, ip(YT), 4_095, T0 + 182);
        assert!(!active(&a.drain_minute(T0 + 180, cat()), KID, "YouTube"));
    }

    #[test]
    fn lookup_counts_into_the_next_minute() {
        let mut a = Attributor::new(Caps::default());
        // looked up at :55, bytes first sampled at :05 of the next minute
        a.on_dns(KID, &resp("www.youtube.com", &[(YT, 300)], T0 + 55), cat());
        let r = a.drain_minute(T0, cat());
        assert!(!active(&r, KID, "YouTube"));
        a.on_bytes(KID, ip(YT), 5_000, T0 + 65);
        let r = a.drain_minute(T0 + 60, cat());
        assert!(active(&r, KID, "YouTube"));
        // the carried-over lookup is not a second query
        assert!(r.per_host[KID].queries.is_empty());
        // but not into the one after
        a.on_bytes(KID, ip(YT), 5_000, T0 + 125);
        assert!(!active(&a.drain_minute(T0 + 120, cat()), KID, "YouTube"));
    }

    #[test]
    fn bytes_before_the_answer_in_the_same_minute_are_attributed() {
        let mut a = Attributor::new(Caps::default());
        // the sample is read before the dnstap answer is processed
        a.on_bytes(KID, ip(YT), 40_000, T0 + 10);
        a.on_dns(KID, &resp("www.youtube.com", &[(YT, 300)], T0 + 9), cat());
        let r = a.drain_minute(T0, cat());
        assert!(active(&r, KID, "YouTube"));
        assert_eq!(service_bytes(&r, KID, OTHER_BY_ADDRESS), 0);
    }

    #[test]
    fn blocked_lookups_do_not_count_as_looked_up() {
        let mut a = Attributor::new(Caps::default());
        // mapped earlier, so the bytes are YouTube's
        a.on_dns(
            KID,
            &resp("www.youtube.com", &[(YT, 3600)], T0 - 600),
            cat(),
        );
        // a blocked lookup of a YouTube name this minute
        let mut blocked = resp("i.ytimg.com", &[], T0 + 1);
        blocked.rcode = 3;
        assert!(is_blocked(&blocked));
        a.on_dns(KID, &blocked, cat());
        a.on_bytes(KID, ip(YT), 5_000, T0 + 2);
        let r = a.drain_minute(T0, cat());
        assert!(!active(&r, KID, "YouTube"));
        assert_eq!(service_bytes(&r, KID, "YouTube"), 5_000);
        assert_eq!(r.per_host[KID].queries, [("i.ytimg.com".into(), 1, true)]);
    }

    #[test]
    fn small_transfer_needs_a_lookup_of_that_service() {
        let mut a = Attributor::new(Caps::default());
        let nf = "45.57.1.1";
        a.on_dns(KID, &resp("www.netflix.com", &[(nf, 300)], T0 - 600), cat());
        // look up YouTube (A), move 4-32 KB to Netflix (B)
        a.on_dns(KID, &resp("www.youtube.com", &[(YT, 300)], T0 + 1), cat());
        a.on_bytes(KID, ip(nf), 20_000, T0 + 2);
        let r = a.drain_minute(T0, cat());
        assert!(!active(&r, KID, "Netflix"));
        assert_eq!(service_bytes(&r, KID, "Netflix"), 20_000);
    }

    #[test]
    fn uncatalogued_names_are_their_registrable_domain() {
        let mut a = Attributor::new(Caps::default());
        let addr = "198.51.100.7";
        a.on_dns(
            KID,
            &resp("eu-3.edge.some-new-game-cdn.net", &[(addr, 60)], T0 + 1),
            cat(),
        );
        a.on_bytes(KID, ip(addr), 40_000, T0 + 2);
        let r = a.drain_minute(T0, cat());
        assert!(active(&r, KID, "some-new-game-cdn.net"));
        assert_eq!(category_of("some-new-game-cdn.net", cat()), Category::Other);
        assert_eq!(
            active_categories(&r.per_host[KID], cat()),
            BTreeSet::from([Category::Other])
        );
        assert_eq!(registrable_domain("foo.bar.co.uk"), "bar.co.uk");
        assert_eq!(registrable_domain("x.y.school.ac.uk"), "school.ac.uk");
        assert_eq!(registrable_domain("a.b.Example.COM."), "example.com");
        assert_eq!(registrable_domain("co.uk"), "co.uk");
        assert_eq!(registrable_domain("localhost"), "localhost");
        assert_eq!(registrable_domain(""), "");
        assert_eq!(registrable_domain("\u{0}.\u{fffd}..ü"), ".ü");
    }

    #[test]
    fn unknown_lookup_does_not_activate_unmapped_traffic() {
        let mut a = Attributor::new(Caps::default());
        let addr = "198.51.100.8";
        a.on_dns(
            KID,
            &resp("thing.unknown-iot.example", &[(addr, 60)], T0 + 1),
            cat(),
        );
        a.on_bytes(KID, ip("203.0.113.50"), 10_000, T0 + 2);
        let r = a.drain_minute(T0, cat());
        assert_eq!(service_bytes(&r, KID, OTHER_BY_ADDRESS), 10_000);
        assert!(r.per_host[KID].services_active.is_empty());
    }

    #[test]
    fn category_minutes_are_union() {
        let mut a = Attributor::new(Caps::default());
        let nf = "45.57.1.1";
        a.on_dns(KID, &resp("www.youtube.com", &[(YT, 300)], T0 + 1), cat());
        a.on_dns(KID, &resp("www.netflix.com", &[(nf, 300)], T0 + 1), cat());
        let mut video = 0;
        let mut both = 0;
        for m in 0..3 {
            let t = T0 + m * 60;
            a.on_bytes(KID, ip(YT), 40_000, t + 5);
            if m != 1 {
                a.on_bytes(KID, ip(nf), 40_000, t + 5);
            }
            let r = a.drain_minute(t, cat());
            let h = &r.per_host[KID];
            both += usize::from(h.services_active.len() == 2);
            let cats = active_categories(h, cat());
            assert_eq!(cats, BTreeSet::from([Category::Video]), "minute {m}");
            video += usize::from(cats.contains(&Category::Video));
        }
        assert_eq!(both, 2);
        assert_eq!(video, 3, "two services in one minute are one Video minute");
        assert_eq!(category_of("YouTube", cat()), Category::Video);
        assert_eq!(category_of(OTHER_BY_ADDRESS, cat()), Category::Other);
        assert_eq!(category_of("Google", cat()), Category::System);
    }

    #[test]
    fn ip_map_is_per_device_and_latest_wins() {
        let mut a = Attributor::new(Caps::default());
        // one CDN address, two devices, two services
        a.on_dns(KID, &resp("www.youtube.com", &[(YT, 300)], T0 + 1), cat());
        a.on_dns(TV, &resp("www.netflix.com", &[(YT, 300)], T0 + 2), cat());
        a.on_bytes(KID, ip(YT), 40_000, T0 + 3);
        a.on_bytes(TV, ip(YT), 40_000, T0 + 3);
        a.on_bytes("aa:bb:cc:00:00:03", ip(YT), 40_000, T0 + 3);
        let r = a.drain_minute(T0, cat());
        assert!(active(&r, KID, "YouTube") && !active(&r, KID, "Netflix"));
        assert!(active(&r, TV, "Netflix") && !active(&r, TV, "YouTube"));
        // a device that never looked the address up gets no one else's name
        assert!(active(&r, "aa:bb:cc:00:00:03", OTHER_BY_ADDRESS));
        // the device's latest answer for the address wins
        a.on_dns(KID, &resp("www.netflix.com", &[(YT, 300)], T0 + 61), cat());
        a.on_bytes(KID, ip(YT), 40_000, T0 + 62);
        let r = a.drain_minute(T0 + 60, cat());
        assert!(active(&r, KID, "Netflix") && !active(&r, KID, "YouTube"));
    }

    #[test]
    fn active_flow_keeps_mapping_alive() {
        let mut a = Attributor::new(Caps::default());
        a.on_dns(KID, &resp("www.youtube.com", &[(YT, 300)], T0), cat());
        // 60 minutes of streaming after one lookup with a 300 s TTL
        for m in 0..60 {
            let t = T0 + m * 60;
            a.on_bytes(KID, ip(YT), 50_000, t + 30);
            assert!(
                active(&a.drain_minute(t, cat()), KID, "YouTube"),
                "minute {m}"
            );
        }
        // idle past TTL + grace: the mapping is gone
        let t = T0 + 60 * 60 + 300 + GRACE_SECS + 120;
        let t = t - t % 60;
        a.on_bytes(KID, ip(YT), 50_000, t + 1);
        let r = a.drain_minute(t, cat());
        assert!(active(&r, KID, OTHER_BY_ADDRESS) && !active(&r, KID, "YouTube"));
        // without traffic a mapping lasts TTL + grace only
        let mut b = Attributor::new(Caps::default());
        b.on_dns(KID, &resp("www.youtube.com", &[(YT, 300)], T0), cat());
        b.on_bytes(KID, ip(YT), 50_000, T0 + 300 + GRACE_SECS);
        assert_eq!(
            service_bytes(&b.drain_minute(T0 + 900, cat()), KID, "YouTube"),
            50_000
        );
        b.on_bytes(KID, ip(YT), 50_000, T0 + 300 + GRACE_SECS + 1200);
        let r = b.drain_minute(T0 + 2100, cat());
        assert_eq!(service_bytes(&r, KID, OTHER_BY_ADDRESS), 50_000);
    }

    #[test]
    fn minute_engine_ignores_clock_jumps() {
        let mut a = Attributor::new(Caps::default());
        a.on_dns(KID, &resp("www.youtube.com", &[(YT, 86_400)], T0), cat());
        a.on_bytes(KID, ip(YT), 40_000, T0 + 5);
        assert!(active(&a.drain_minute(T0, cat()), KID, "YouTube"));
        // the clock steps back into a minute already written: not again
        a.on_bytes(KID, ip(YT), 40_000, T0 + 30);
        a.on_dns(
            KID,
            &resp("www.youtube.com", &[(YT, 86_400)], T0 + 31),
            cat(),
        );
        assert!(a.drain_minute(T0, cat()).per_host.is_empty());
        // only the lookup's carry-over into the next minute is pending
        assert_eq!(a.pending_minutes(), [T0 + 60]);
        // a jump forward by two days (NTP at boot) is followed
        let late = T0 + 2 * 86_400;
        a.on_bytes(KID, ip(YT), 40_000, late + 5);
        assert!(!a.drain_minute(late, cat()).per_host.is_empty());
        // and nothing more than a day before the newest bucket is written
        a.on_bytes(KID, ip(YT), 40_000, T0 + 3_600);
        assert!(a.pending_minutes().is_empty());
        assert!(a.drain_minute(T0 + 3_600, cat()).per_host.is_empty());
        // within the day, a minute not yet written still is
        a.on_bytes(KID, ip(YT), 40_000, late - 3_600);
        assert_eq!(a.pending_minutes(), [late - 3_600]);
        assert!(!a.drain_minute(late - 3_600, cat()).per_host.is_empty());
    }

    #[test]
    fn caps_evict_oldest() {
        let caps = Caps {
            per_device: 2,
            total: 3,
        };
        let mut a = Attributor::new(caps);
        let names = [
            ("www.youtube.com", "10.0.0.1", "YouTube"),
            ("www.netflix.com", "10.0.0.2", "Netflix"),
            ("www.roblox.com", "10.0.0.3", "Roblox"),
            ("www.twitch.tv", "10.0.0.4", "Twitch"),
            ("www.tiktok.com", "10.0.0.5", "TikTok"),
        ];
        let lookup = |a: &mut Attributor, mac: &str, i: usize, t: i64| {
            a.on_dns(mac, &resp(names[i].0, &[(names[i].1, 3600)], t), cat());
        };
        // per device: the third answer pushes out the first
        lookup(&mut a, KID, 0, T0);
        lookup(&mut a, KID, 1, T0 + 1);
        lookup(&mut a, KID, 2, T0 + 2);
        // globally: the TV's second answer pushes out the oldest anywhere
        lookup(&mut a, TV, 3, T0 + 3);
        lookup(&mut a, TV, 4, T0 + 4);
        let got = |a: &mut Attributor, mac: &str, i: usize, t: i64| {
            a.on_bytes(mac, ip(names[i].1), 40_000, t);
            let r = a.drain_minute(t - t % 60, cat());
            r.per_host[mac]
                .services_active
                .iter()
                .next()
                .unwrap()
                .clone()
        };
        assert_eq!(got(&mut a, KID, 0, T0 + 60), OTHER_BY_ADDRESS);
        assert_eq!(got(&mut a, KID, 1, T0 + 120), OTHER_BY_ADDRESS);
        assert_eq!(got(&mut a, KID, 2, T0 + 180), names[2].2);
        assert_eq!(got(&mut a, TV, 3, T0 + 240), names[3].2);
        assert_eq!(got(&mut a, TV, 4, T0 + 300), names[4].2);
        assert!(a.map_len() <= 3);
    }

    #[test]
    fn unattributed_goes_to_other_by_address() {
        let mut a = Attributor::new(Caps::default());
        a.on_bytes(KID, ip("203.0.113.9"), 40_000, T0 + 1);
        // a mapped name the catalogue does not know is its own domain's
        a.on_dns(
            KID,
            &resp("printer.example.test", &[("203.0.113.10", 60)], T0 + 2),
            cat(),
        );
        a.on_bytes(KID, ip("203.0.113.10"), 2_000, T0 + 3);
        let r = a.drain_minute(T0, cat());
        let h = &r.per_host[KID];
        assert_eq!(
            h.bytes_by_service,
            BTreeMap::from([
                (OTHER_BY_ADDRESS.to_string(), 40_000),
                ("example.test".to_string(), 2_000)
            ])
        );
        assert_eq!(
            h.services_active,
            BTreeSet::from([OTHER_BY_ADDRESS.to_string()])
        );
        assert_eq!(h.queries, [("printer.example.test".into(), 1, false)]);
        assert_eq!(
            active_categories(h, cat()),
            BTreeSet::from([Category::Other])
        );
    }

    #[test]
    fn cname_chain_uses_first_recognised_name() {
        let mut a = Attributor::new(Caps::default());
        // the queried name already matches: YouTube, not the Google target
        let mut ev = resp("www.youtube.com", &[(YT, 300)], T0);
        ev.cnames = vec!["youtube-ui.l.google.com".into()];
        a.on_dns(KID, &ev, cat());
        // an unknown name whose chain leads to a known one
        let mut ev = resp("cdn.kidsportal.test", &[("10.9.9.9", 300)], T0);
        ev.cnames = vec!["edge.unknown.test".into(), "rr3.googlevideo.com".into()];
        a.on_dns(TV, &ev, cat());
        a.on_bytes(KID, ip(YT), 40_000, T0 + 1);
        a.on_bytes(TV, ip("10.9.9.9"), 40_000, T0 + 1);
        let r = a.drain_minute(T0, cat());
        assert!(active(&r, KID, "YouTube"));
        assert!(active(&r, TV, "YouTube"));
        // queries are recorded under the queried name
        assert_eq!(r.per_host[TV].queries[0].0, "cdn.kidsportal.test");
    }

    #[test]
    fn blocked_and_queries_and_hostile_names() {
        let mut a = Attributor::new(Caps::default());
        let blocked = resp("ads.doubleclick.net", &[("0.0.0.0", 300)], T0);
        a.on_dns(KID, &blocked, cat());
        a.on_dns(KID, &blocked, cat());
        // a query event alone is not counted (the response is)
        let mut q = resp("www.youtube.com", &[], T0);
        q.kind = EventKind::ClientQuery;
        a.on_dns(KID, &q, cat());
        // odd bytes in names never panic and are kept as-is
        let odd = "\u{0}\u{fffd}ü.\u{7f}..";
        a.on_dns(KID, &resp(odd, &[("10.1.1.1", u32::MAX)], i64::MAX), cat());
        a.on_dns(KID, &resp(odd, &[("10.1.1.1", u32::MAX)], T0), cat());
        a.on_bytes(KID, ip("10.1.1.1"), u64::MAX, T0);
        a.on_bytes(KID, ip("10.1.1.1"), u64::MAX, T0);
        a.on_bytes(KID, ip("10.1.1.2"), 1, i64::MIN);
        let r = a.drain_minute(T0, cat());
        let h = &r.per_host[KID];
        assert!(h.queries.contains(&("ads.doubleclick.net".into(), 2, true)));
        assert!(h.queries.contains(&(odd.into(), 1, false)));
        assert!(!h.queries.iter().any(|q| q.0 == "www.youtube.com"));
        // the blocked answer created no mapping
        assert_eq!(a.map_len(), 1);
    }
}
