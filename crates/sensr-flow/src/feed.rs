//! The per-host DNS activity feed: ties Unbound's client addresses and the
//! pair counters' local addresses to device MACs through the neighbour
//! table, and drives the [`Attributor`].
//!
//! **Devices** are MACs from `ip -j neigh show` (read by the daemon every
//! sample). An IPv6 temporary (privacy) address is in that table as soon as
//! the device talks through the router, so it maps to the same MAC as the
//! device's other addresses. An address that is not in the table (the
//! router itself, a device that has not been seen yet) is dropped: never
//! guessed, so traffic is never attributed to the wrong device.
//!
//! **Order.** The daemon hands over DNS events before the counter deltas of
//! the same sample, so an answer and the bytes that follow it meet in the
//! same minute; a minute is returned once it ended [`LATE_SECS`] ago.

use std::collections::{HashMap, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::PathBuf;

use crate::attrib::{Attributor, Caps, MinuteResult};
use crate::dnstap::{DnstapEvent, EventKind};
use crate::nft::{Count, Key, Kind};
use crate::services::Catalogue;

/// Seconds after a minute's end before it is drained (late frames).
/// Anything that arrives for a minute after it was drained (a frame
/// delayed longer than this, a query-log line read late) is dropped by the
/// [`Attributor`], which returns each minute once: the store's writes are
/// idempotent per minute, not additive, so a second partial result for a
/// written minute could not be merged correctly.
pub const LATE_SECS: i64 = 5;
/// The window of the staleness watch: no frames over this long while
/// Unbound's query counter grew means the feed is stale.
pub const STALE_SECS: i64 = 300;
/// Minutes older than this when drained are not returned (the store keeps
/// minute detail for 7 days; a clock that jumped is not trusted further).
pub const MAX_AGE_SECS: i64 = 6 * 86_400;
/// Neighbour entries kept at most (the kernel's own default limit is far
/// lower).
pub const MAX_NEIGHBOURS: usize = 16_384;

/// Address → MAC, from the neighbour table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Neighbours {
    by_ip: HashMap<IpAddr, String>,
}

impl Neighbours {
    /// Parses `ip -j neigh show` (both families). Entries without a MAC
    /// and failed or incomplete ones are skipped; malformed output gives an
    /// empty table.
    pub fn parse(json: &[u8]) -> Neighbours {
        #[derive(serde::Deserialize)]
        struct Entry {
            dst: Option<IpAddr>,
            lladdr: Option<String>,
            #[serde(default)]
            state: Vec<String>,
        }
        let entries: Vec<Entry> = serde_json::from_slice(json).unwrap_or_default();
        let by_ip = entries
            .into_iter()
            .filter(|e| !e.state.iter().any(|s| s == "FAILED" || s == "INCOMPLETE"))
            .filter_map(|e| {
                let mac = e.lladdr?.to_ascii_lowercase();
                let ok = mac.len() == 17 && mac.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
                ok.then_some(())?;
                Some((e.dst?.to_canonical(), mac))
            })
            .take(MAX_NEIGHBOURS)
            .collect();
        Neighbours { by_ip }
    }

    /// The MAC of `ip`, if the table has it.
    pub fn mac(&self, ip: IpAddr) -> Option<&str> {
        self.by_ip.get(&ip.to_canonical()).map(String::as_str)
    }

    /// Entries held.
    pub fn len(&self) -> usize {
        self.by_ip.len()
    }

    /// No entries.
    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }
}

/// The feed: neighbour table, catalogue and attribution engine.
#[derive(Debug)]
pub struct Feed {
    attrib: Attributor,
    cat: Catalogue,
    neigh: Neighbours,
    /// Events and deltas dropped because the address had no MAC.
    pub unknown: u64,
}

impl Feed {
    /// A feed attributing through `cat` (the catalogue with the owner's
    /// overrides).
    pub fn new(cat: Catalogue) -> Feed {
        Feed {
            attrib: Attributor::new(Caps::default()),
            cat,
            neigh: Neighbours::default(),
            unknown: 0,
        }
    }

    /// Replaces the neighbour table (each sample).
    pub fn set_neighbours(&mut self, n: Neighbours) {
        self.neigh = n;
    }

    /// The current neighbour table.
    pub fn neighbours(&self) -> &Neighbours {
        &self.neigh
    }

    /// One dnstap event. Returns false when its client has no MAC (the
    /// event is dropped).
    pub fn on_dns(&mut self, ev: &DnstapEvent) -> bool {
        let Some(mac) = self.neigh.mac(ev.client) else {
            self.unknown += 1;
            return false;
        };
        let mac = mac.to_owned();
        self.attrib.on_dns(&mac, ev, &self.cat);
        true
    }

    /// A lookup read from Unbound's query log (the fallback while dnstap is
    /// stale), at the line's own `time`: counted as a lookup with no
    /// answer, so it lists the name but maps no address.
    pub fn on_logged_query(&mut self, client: IpAddr, qname: &str, time: i64) -> bool {
        let qname = qname.trim_end_matches('.').to_ascii_lowercase();
        if qname.is_empty() || qname.len() > 253 {
            return false;
        }
        self.on_dns(&DnstapEvent {
            kind: EventKind::ClientResponse,
            client,
            time,
            qname,
            qtype: 0,
            rcode: 0,
            authority_count: 0,
            answers: Vec::new(),
            cnames: Vec::new(),
        })
    }

    /// Counter deltas sampled at `now`: the pair ones (both directions)
    /// become bytes per (device, remote address); the rest are ignored.
    pub fn on_pairs(&mut self, deltas: &[(Key, Count)], now: i64) {
        for (k, c) in deltas {
            let (Kind::Pair, Some(remote)) = (k.kind, k.remote) else {
                continue;
            };
            let Some(mac) = self.neigh.mac(k.addr) else {
                self.unknown += 1;
                continue;
            };
            let mac = mac.to_owned();
            self.attrib.on_bytes(&mac, remote, c.bytes, now);
        }
    }

    /// The minutes that ended at least [`LATE_SECS`] before `now`, oldest
    /// first, each once; empty ones and those older than [`MAX_AGE_SECS`]
    /// are drained but not returned.
    pub fn due(&mut self, now: i64) -> Vec<(i64, MinuteResult)> {
        let mut out = Vec::new();
        for m in self.attrib.pending_minutes() {
            if m + 60 + LATE_SECS > now {
                break;
            }
            let r = self.attrib.drain_minute(m, &self.cat);
            if !r.per_host.is_empty() && m >= now - MAX_AGE_SECS {
                out.push((m, r));
            }
        }
        out
    }

    /// IP-map entries held.
    pub fn map_len(&self) -> usize {
        self.attrib.map_len()
    }
}

/// Unbound's total query counter (`queries`) from sensr-dns's
/// `unbound-stats.json`; `None` when the file is missing or unreadable.
pub fn read_query_counter(path: &std::path::Path) -> Option<u64> {
    #[derive(serde::Deserialize)]
    struct Stats {
        queries: u64,
    }
    let b = std::fs::read(path).ok()?;
    serde_json::from_slice::<Stats>(&b).ok().map(|s| s.queries)
}

/// Decides whether the dnstap feed is stale: Unbound answered queries (its
/// counter grew) during a whole [`STALE_SECS`] window in which no dnstap
/// frame arrived. A quiet network (no counter growth) is not stale, and
/// neither is an unknown counter.
#[derive(Debug, Default)]
pub struct StaleWatch {
    /// (time, query counter, frames read), oldest first, spanning just over
    /// one window.
    hist: VecDeque<(i64, Option<u64>, u64)>,
}

impl StaleWatch {
    /// Records one sample and says whether the feed is stale now.
    pub fn observe(&mut self, t: i64, queries: Option<u64>, frames: u64) -> bool {
        if self.hist.back().is_some_and(|b| t < b.0) {
            // the clock went back: start over
            self.hist.clear();
        }
        self.hist.push_back((t, queries, frames));
        // keep one sample at or before the window's start
        while self.hist.len() > 1 && self.hist.get(1).is_some_and(|s| s.0 <= t - STALE_SECS) {
            self.hist.pop_front();
        }
        while self.hist.len() > 4096 {
            self.hist.pop_front();
        }
        let Some(&(t0, q0, f0)) = self.hist.front() else {
            return false;
        };
        if t - t0 < STALE_SECS || frames != f0 {
            return false;
        }
        match (q0, queries) {
            (Some(before), Some(now)) if now >= before => now > before,
            // Unbound restarted (the counter reset): queries since then
            (Some(_), Some(now)) => now > 0,
            _ => false,
        }
    }
}

/// Bytes of the query log read per call at most.
pub const MAX_LOG_READ: u64 = 1024 * 1024;

/// A lookup from the query log: its own time (the line's `[epoch]`, if
/// any), the client and the name as logged.
pub type LoggedQuery = (Option<i64>, IpAddr, String);

/// One lookup line of Unbound's query log (`log-queries: yes`):
/// `[<epoch>] unbound[<pid>:<n>] info: <client> <name> <type> <class>`.
/// Reply lines (more fields) and anything else give `None`.
pub fn parse_query_line(line: &str) -> Option<LoggedQuery> {
    let time = line
        .strip_prefix('[')
        .and_then(|r| r.split_once(']'))
        .and_then(|(t, _)| t.parse::<i64>().ok());
    let body = line.split_once(" info: ")?.1.trim();
    let mut f = body.split_whitespace();
    let (Some(client), Some(name), Some(_kind), Some(class), None) =
        (f.next(), f.next(), f.next(), f.next(), f.next())
    else {
        return None;
    };
    if !matches!(class, "IN" | "CH" | "HS") || name.len() > 255 {
        return None;
    }
    Some((time, client.parse().ok()?, name.to_string()))
}

/// Unbound's query log, followed from where it was last read. The fallback
/// source of lookups while the dnstap feed is stale.
#[derive(Debug)]
pub struct QueryLog {
    path: PathBuf,
    offset: u64,
}

impl QueryLog {
    /// Follows `path` from its current end.
    pub fn new(path: impl Into<PathBuf>) -> QueryLog {
        let mut q = QueryLog {
            path: path.into(),
            offset: 0,
        };
        q.skip();
        q
    }

    /// Moves to the end: what is there now is never read.
    pub fn skip(&mut self) {
        self.offset = std::fs::metadata(&self.path).map_or(0, |m| m.len());
    }

    /// Lookups in the complete lines appended since the last call (at most
    /// [`MAX_LOG_READ`] bytes). A shorter file was rotated: reading starts
    /// over. A missing or unreadable file gives nothing.
    pub fn read_new(&mut self) -> Vec<LoggedQuery> {
        let Ok(mut f) = std::fs::File::open(&self.path) else {
            return Vec::new();
        };
        let len = f.metadata().map_or(0, |m| m.len());
        if len < self.offset {
            self.offset = 0;
        }
        if len == self.offset || f.seek(SeekFrom::Start(self.offset)).is_err() {
            return Vec::new();
        }
        let mut buf = Vec::new();
        if f.take(MAX_LOG_READ).read_to_end(&mut buf).is_err() {
            return Vec::new();
        }
        let used = match buf.iter().rposition(|&b| b == b'\n') {
            Some(i) => i + 1,
            // one line longer than a whole read: not a lookup line, skip it
            None if buf.len() as u64 >= MAX_LOG_READ => buf.len(),
            None => return Vec::new(),
        };
        self.offset += used as u64;
        String::from_utf8_lossy(buf.get(..used).unwrap_or_default())
            .lines()
            .filter_map(parse_query_line)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nft::Dir;

    const T0: i64 = 1_800_000_000;
    const KID: &str = "aa:bb:cc:00:00:01";

    /// `ip -j neigh show` on the router: the kid's tablet with its IPv4,
    /// its stable IPv6 and a temporary (privacy) IPv6 address, a failed
    /// entry, and an entry without a MAC.
    const NEIGH: &str = r#"[
      {"dst":"192.168.1.100","dev":"lan0","lladdr":"AA:BB:CC:00:00:01","state":["REACHABLE"]},
      {"dst":"2001:db8:1::1c2b:3cff:fe4d:5e6f","dev":"lan0","lladdr":"aa:bb:cc:00:00:01","state":["STALE"]},
      {"dst":"2001:db8:1::9f3e:41a7:22d0:7b15","dev":"lan0","lladdr":"aa:bb:cc:00:00:01","state":["DELAY"]},
      {"dst":"fe80::a8bb:ccff:fe00:1","dev":"lan0","lladdr":"aa:bb:cc:00:00:01","router":null,"state":["STALE"]},
      {"dst":"192.168.1.101","dev":"lan0","lladdr":"aa:bb:cc:00:00:09","state":["FAILED"]},
      {"dst":"192.168.1.102","dev":"lan0","state":["INCOMPLETE"]}
    ]"#;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn feed() -> Feed {
        let mut f = Feed::new(Catalogue::builtin().clone());
        f.set_neighbours(Neighbours::parse(NEIGH.as_bytes()));
        f
    }

    fn resp(client: &str, qname: &str, answer: &str, time: i64) -> DnstapEvent {
        DnstapEvent {
            kind: EventKind::ClientResponse,
            client: ip(client),
            time,
            qname: qname.into(),
            qtype: 1,
            rcode: 0,
            authority_count: 0,
            answers: vec![(ip(answer), 300)],
            cnames: Vec::new(),
        }
    }

    fn pair(local: &str, remote: &str, dir: Dir, bytes: u64) -> (Key, Count) {
        let mut k = Key::addr(Kind::Pair, dir, ip(local));
        k.remote = Some(ip(remote));
        (k, Count { packets: 1, bytes })
    }

    #[test]
    fn neighbour_table_parsed() {
        let n = Neighbours::parse(NEIGH.as_bytes());
        assert_eq!(n.len(), 4);
        assert_eq!(n.mac(ip("192.168.1.100")), Some(KID), "lowercased");
        assert_eq!(n.mac(ip("::ffff:192.168.1.100")), Some(KID), "v4-mapped");
        assert_eq!(n.mac(ip("192.168.1.101")), None, "failed");
        assert!(Neighbours::parse(b"garbage").is_empty());
    }

    #[test]
    fn unknown_client_ip_is_ignored() {
        let mut f = feed();
        // a lookup and a download from an address the table does not have
        assert!(!f.on_dns(&resp(
            "192.168.1.77",
            "www.youtube.com",
            "142.250.1.1",
            T0 + 1
        )));
        f.on_pairs(
            &[pair("192.168.1.77", "142.250.1.1", Dir::Down, 1_000_000)],
            T0 + 10,
        );
        // the router itself asking (no neighbour entry for its own address)
        assert!(!f.on_dns(&resp("127.0.0.1", "example.com", "93.184.216.34", T0 + 2)));
        assert_eq!(f.unknown, 3);
        assert!(f.due(T0 + 600).is_empty(), "nothing attributed to anyone");
        // the same traffic from a known address is the kid's
        assert!(f.on_dns(&resp(
            "192.168.1.100",
            "www.youtube.com",
            "142.250.1.1",
            T0 + 601
        )));
        f.on_pairs(
            &[pair("192.168.1.100", "142.250.1.1", Dir::Down, 100_000)],
            T0 + 610,
        );
        let due = f.due(T0 + 1200);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].1.per_host.keys().collect::<Vec<_>>(), [KID]);
    }

    #[test]
    fn ipv6_temporary_address_maps_via_neigh() {
        let mut f = feed();
        // the lookup comes over the temporary address, the bytes over both
        // it and the stable one: all of it is the same device's
        let tmp = "2001:db8:1::9f3e:41a7:22d0:7b15";
        let stable = "2001:db8:1::1c2b:3cff:fe4d:5e6f";
        let yt = "2a00:1450:4001:80b::200e";
        assert!(f.on_dns(&resp(tmp, "rr3.googlevideo.com", yt, T0 + 2)));
        f.on_pairs(
            &[
                pair(tmp, yt, Dir::Down, 30_000),
                pair(tmp, yt, Dir::Up, 1_000),
                pair(stable, yt, Dir::Down, 5_000),
            ],
            T0 + 10,
        );
        let due = f.due(T0 + 60 + LATE_SECS);
        let (m, r) = &due[0];
        assert_eq!(*m, T0);
        let h = &r.per_host[KID];
        assert!(h.services_active.contains("YouTube"));
        assert_eq!(h.bytes_by_service["YouTube"], 36_000);
        assert_eq!(h.queries, [("rr3.googlevideo.com".to_string(), 1, false)]);
        assert_eq!(f.unknown, 0);
    }

    #[test]
    fn minutes_are_due_once_after_they_end() {
        let mut f = feed();
        f.on_dns(&resp("192.168.1.100", "roblox.com", "128.116.1.1", T0 + 30));
        f.on_pairs(
            &[pair("192.168.1.100", "128.116.1.1", Dir::Down, 50_000)],
            T0 + 40,
        );
        assert!(f.due(T0 + 60).is_empty(), "the minute is not over yet");
        assert!(f.due(T0 + 64).is_empty(), "late frames still expected");
        let due = f.due(T0 + 65);
        assert_eq!(due.len(), 1);
        assert!(due[0].1.per_host[KID].services_active.contains("Roblox"));
        assert!(f.due(T0 + 600).is_empty(), "drained once");
        // the query log fallback lists the name, attributes no bytes
        assert!(f.on_logged_query(ip("192.168.1.100"), "Example.ORG.", T0 + 700));
        let due = f.due(T0 + 800);
        assert_eq!(
            due[0].1.per_host[KID].queries,
            [("example.org".to_string(), 1, false)]
        );
        assert!(due[0].1.per_host[KID].services_active.is_empty());
    }

    #[test]
    fn query_log_followed_from_its_end() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("query.log");
        let line = |c: &str, n: &str| format!("[1700000000] unbound[1:0] info: {c} {n} A IN\n");
        std::fs::write(&p, line("192.168.1.100", "old.example.")).unwrap();
        let mut q = QueryLog::new(&p);
        assert!(
            q.read_new().is_empty(),
            "lines before the start are not read"
        );
        let mut text = std::fs::read_to_string(&p).unwrap();
        text.push_str(&line("192.168.1.100", "www.youtube.com."));
        text.push_str("[1700000000] unbound[1:0] info: 192.168.1.100 www.youtube.com. A IN NOERROR 0.001 0 60\n");
        text.push_str("[1700000000] unbound[1:0] info: 192.168.1.100 half.example. A");
        std::fs::write(&p, &text).unwrap();
        assert_eq!(
            q.read_new(),
            [(
                Some(1_700_000_000),
                ip("192.168.1.100"),
                "www.youtube.com.".to_string()
            )],
            "replies and the unfinished line are left out"
        );
        text.push_str(" IN\n");
        std::fs::write(&p, &text).unwrap();
        assert_eq!(q.read_new()[0].2, "half.example.");
        // rotated
        std::fs::write(&p, line("fd00::5", "new.example.")).unwrap();
        assert_eq!(
            q.read_new(),
            [(
                Some(1_700_000_000),
                ip("fd00::5"),
                "new.example.".to_string()
            )]
        );
        assert_eq!(
            parse_query_line("unbound[1:0] info: 10.0.0.1 a.example. A IN"),
            Some((None, ip("10.0.0.1"), "a.example.".to_string())),
            "no time stamp"
        );
        assert_eq!(parse_query_line("garbage"), None);
        assert_eq!(parse_query_line("x info: not-an-ip a.example. A IN"), None);
    }

    #[test]
    fn quiet_night_is_not_stale_but_lost_frames_are() {
        let t0 = T0;
        // a quiet night: no frames, and Unbound answered nothing either
        let mut w = StaleWatch::default();
        for i in 0..100 {
            assert!(!w.observe(t0 + i * 10, Some(5_000), 0), "sample {i}");
        }
        // Unbound answers queries but no frames arrive: stale once a whole
        // window has passed
        let mut w = StaleWatch::default();
        let mut stale_at = None;
        for i in 0..60 {
            let t = t0 + i * 10;
            if w.observe(t, Some(5_000 + 3 * i as u64), 0) && stale_at.is_none() {
                stale_at = Some(t - t0);
            }
        }
        assert_eq!(stale_at, Some(STALE_SECS));
        // frames come back: not stale
        assert!(!w.observe(t0 + 600, Some(5_400), 7));
        // the counter is unknown (statistics off): never stale
        let mut w = StaleWatch::default();
        for i in 0..60 {
            assert!(!w.observe(t0 + i * 10, None, 0));
        }
        // Unbound restarted (counter reset) and answers: stale
        let mut w = StaleWatch::default();
        w.observe(t0, Some(9_000), 3);
        assert!(w.observe(t0 + STALE_SECS, Some(40), 3));
        assert!(w.hist.len() <= 32);
    }

    #[test]
    fn query_counter_read_from_the_stats_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("unbound-stats.json");
        assert_eq!(read_query_counter(&p), None);
        std::fs::write(
            &p,
            r#"{"at":"2026-11-23T10:00:00Z","queries":1234,"cache_hits":1000,"nxdomain":0,"uptime_seconds":5.0}"#,
        )
        .unwrap();
        assert_eq!(read_query_counter(&p), Some(1234));
    }
}
