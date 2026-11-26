//! Host discovery and neighbour (ARP/NDP) lookups.
//!
//! A neighbour entry on its own is not proof of life: the kernel keeps
//! entries for departed devices (STALE) for a while, and `/proc/net/arp`
//! flags those as complete too. A host is alive when it answers a probe, or
//! when the kernel confirms its entry (REACHABLE) after the probe made it
//! re-check.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What the neighbour table says about an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighState {
    /// Confirmed recently (`NUD_REACHABLE`).
    Reachable,
    /// Known but not confirmed lately (`STALE`, `DELAY`, `PROBE`): traffic
    /// to it makes the kernel re-check, ending `REACHABLE` or gone.
    Stale,
    /// No reachability state: static entries (`PERMANENT`, `NOARP`), or
    /// `/proc/net/arp`, which does not carry it.
    Unknown,
}

/// One neighbour entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbour {
    /// Lowercase MAC.
    pub mac: String,
    pub state: NeighState,
}

impl Neighbour {
    /// A confirmed entry (tests, and the agent-style callers).
    #[must_use]
    pub fn reachable(mac: &str) -> Neighbour {
        Neighbour {
            mac: mac.to_ascii_lowercase(),
            state: NeighState::Reachable,
        }
    }

    /// An unconfirmed entry.
    #[must_use]
    pub fn stale(mac: &str) -> Neighbour {
        Neighbour {
            mac: mac.to_ascii_lowercase(),
            state: NeighState::Stale,
        }
    }
}

/// The neighbour table: address -> entry.
pub type Neighbours = HashMap<IpAddr, Neighbour>;

fn valid_mac(mac: &str) -> bool {
    mac.split(':').count() == 6
        && mac
            .split(':')
            .all(|o| o.len() == 2 && o.bytes().all(|b| b.is_ascii_hexdigit()))
        && mac != "00:00:00:00:00:00"
}

/// Parse `/proc/net/arp` text. Incomplete rows (flags 0x0 or an all-zero
/// MAC) and anything malformed are skipped; the rest are
/// [`NeighState::Unknown`] (the file has no reachability state).
#[must_use]
pub fn neighbours(proc_arp: &str) -> Neighbours {
    let mut out = HashMap::new();
    for line in proc_arp.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 {
            continue;
        }
        let Ok(ip) = f[0].parse::<Ipv4Addr>() else {
            continue;
        };
        let flags = f[2]
            .strip_prefix("0x")
            .and_then(|h| u32::from_str_radix(h, 16).ok());
        if flags.is_none_or(|v| v == 0) {
            continue;
        }
        let mac = f[3].to_ascii_lowercase();
        if !valid_mac(&mac) {
            continue;
        }
        out.insert(
            IpAddr::V4(ip),
            Neighbour {
                mac,
                state: NeighState::Unknown,
            },
        );
    }
    out
}

/// MAC address recorded for `ip`, if any.
#[must_use]
pub fn mac_for(ip: IpAddr, neigh: &Neighbours) -> Option<String> {
    neigh.get(&ip).map(|n| n.mac.clone())
}

/// IPv4 address recorded for `mac` (case-insensitive), if any. A MAC seen
/// at several addresses (an old entry not yet expired) gives the confirmed
/// one, then the lowest.
#[must_use]
pub fn ip_for(mac: &str, neigh: &Neighbours) -> Option<Ipv4Addr> {
    neigh
        .iter()
        .filter_map(|(ip, n)| match ip {
            IpAddr::V4(v4) if n.mac.eq_ignore_ascii_case(mac) => {
                Some((n.state != NeighState::Reachable, *v4))
            }
            _ => None,
        })
        .min()
        .map(|(_, ip)| ip)
}

// ---- rtnetlink neighbour dump (RTM_GETNEIGH) ----

const NLMSG_HDR: usize = 16;
const NDMSG: usize = 12;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWNEIGH: u16 = 28;
const RTM_GETNEIGH: u16 = 30;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NUD_REACHABLE: u16 = 0x02;
const NUD_STALE: u16 = 0x04;
const NUD_DELAY: u16 = 0x08;
const NUD_PROBE: u16 = 0x10;
const NUD_NOARP: u16 = 0x40;
const NUD_PERMANENT: u16 = 0x80;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn ne_u16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn ne_u32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The `RTM_GETNEIGH` dump request for every family.
#[must_use]
pub fn neigh_dump_request(seq: u32) -> Vec<u8> {
    let len = u32::try_from(NLMSG_HDR + NDMSG).unwrap_or(28);
    let mut m = Vec::with_capacity(NLMSG_HDR + NDMSG);
    m.extend_from_slice(&len.to_ne_bytes());
    m.extend_from_slice(&RTM_GETNEIGH.to_ne_bytes());
    m.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes());
    m.extend_from_slice(&[0u8; NDMSG]);
    m
}

/// Fold one buffer of rtnetlink replies into `out`. Returns true once the
/// dump is over (`NLMSG_DONE` or an error), and on malformed input.
/// Entries without an address or MAC, and incomplete or failed ones, are
/// skipped.
pub fn parse_neigh_dump(buf: &[u8], out: &mut Neighbours) -> bool {
    let mut at = 0;
    while at + NLMSG_HDR <= buf.len() {
        let (Some(len), Some(kind)) = (ne_u32(buf, at), ne_u16(buf, at + 4)) else {
            return true;
        };
        let len = usize::try_from(len).unwrap_or(0);
        if len < NLMSG_HDR || at + len > buf.len() {
            return true;
        }
        match kind {
            NLMSG_DONE | NLMSG_ERROR => return true,
            RTM_NEWNEIGH => {
                if let Some((ip, n)) = parse_neigh(&buf[at + NLMSG_HDR..at + len]) {
                    out.insert(ip, n);
                }
            }
            _ => {}
        }
        at += align4(len);
    }
    false
}

/// One `ndmsg` and its attributes.
fn parse_neigh(b: &[u8]) -> Option<(IpAddr, Neighbour)> {
    let state = ne_u16(b, 8)?;
    let state = if state & NUD_REACHABLE != 0 {
        NeighState::Reachable
    } else if state & (NUD_STALE | NUD_DELAY | NUD_PROBE) != 0 {
        NeighState::Stale
    } else if state & (NUD_PERMANENT | NUD_NOARP) != 0 {
        NeighState::Unknown
    } else {
        return None;
    };
    let (mut ip, mut mac) = (None, None);
    let mut at = NDMSG;
    while at + 4 <= b.len() {
        let len = usize::from(ne_u16(b, at)?);
        let kind = ne_u16(b, at + 2)?;
        if len < 4 || at + len > b.len() {
            break;
        }
        let data = &b[at + 4..at + len];
        match (kind, data.len()) {
            (NDA_DST, 4) => {
                let o: [u8; 4] = data.try_into().ok()?;
                ip = Some(IpAddr::V4(Ipv4Addr::from(o)));
            }
            (NDA_DST, 16) => {
                let o: [u8; 16] = data.try_into().ok()?;
                ip = Some(IpAddr::V6(Ipv6Addr::from(o)));
            }
            (NDA_LLADDR, 6) => {
                mac = Some(
                    data.iter()
                        .map(|o| format!("{o:02x}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                );
            }
            _ => {}
        }
        at += align4(len);
    }
    let mac = mac.filter(|m| valid_mac(m))?;
    Some((ip?, Neighbour { mac, state }))
}

#[cfg(feature = "daemon")]
pub use live::{Life, SETTLE, answers, live_hosts, system_neighbours};

#[cfg(feature = "daemon")]
mod live {
    use std::collections::{HashMap, HashSet};
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use socket2::{Domain, Protocol, Socket, Type};
    use tokio::sync::Semaphore;
    use tokio::task::JoinSet;
    use tokio_util::sync::CancellationToken;

    use super::{NeighState, Neighbours};

    const TCP_PORTS: [u16; 5] = [22, 80, 443, 445, 8080];
    const TCP_TIMEOUT: Duration = Duration::from_millis(500);
    const ICMP_TIMEOUT: Duration = Duration::from_secs(1);
    /// Addresses probed at once.
    const PARALLEL: usize = 32;
    /// How long an unconfirmed (STALE) entry of a host that did not answer
    /// is watched for the kernel's verdict: our probe moves it to DELAY,
    /// then (after `delay_first_probe_time`, 5 s) unicast ARP probes make
    /// it REACHABLE or failed.
    pub const SETTLE: Duration = Duration::from_secs(7);
    const POLL: Duration = Duration::from_millis(250);

    /// A live host.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Life {
        /// The MAC at the address after the probe, if it is on a local link.
        pub mac: Option<String>,
        /// Round trip of the first answer, if it answered.
        pub rtt: Option<Duration>,
    }

    /// Production neighbour source: an rtnetlink dump (with reachability
    /// state), else `/proc/net/arp`, else nothing.
    #[must_use]
    pub fn system_neighbours() -> Neighbours {
        match netlink_dump() {
            Ok(n) => n,
            Err(e) => {
                tracing::debug!(error = %e, "neighbour dump failed; reading /proc/net/arp");
                std::fs::read_to_string("/proc/net/arp")
                    .map(|t| super::neighbours(&t))
                    .unwrap_or_default()
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn netlink_dump() -> io::Result<Neighbours> {
        use std::io::Read;
        const AF_NETLINK: i32 = 16;
        const NETLINK_ROUTE: i32 = 0;
        let sock = Socket::new(
            Domain::from(AF_NETLINK),
            Type::RAW,
            Some(Protocol::from(NETLINK_ROUTE)),
        )?;
        sock.set_read_timeout(Some(Duration::from_secs(1)))?;
        // Unbound and unconnected: the kernel autobinds and sends to itself.
        sock.send(&super::neigh_dump_request(1))?;
        let mut out = HashMap::new();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = (&sock).read(&mut buf)?;
            if n == 0 || super::parse_neigh_dump(&buf[..n], &mut out) {
                return Ok(out);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn netlink_dump() -> io::Result<Neighbours> {
        Err(io::ErrorKind::Unsupported.into())
    }

    /// What one neighbour read says about a host.
    #[derive(Debug, PartialEq, Eq)]
    enum Verdict {
        Alive(Life),
        Dead,
        Wait,
    }

    fn verdict(answered: Option<Duration>, neigh: &Neighbours, ip: IpAddr, last: bool) -> Verdict {
        let entry = neigh.get(&ip);
        let mac = entry.map(|n| n.mac.clone());
        if answered.is_some() {
            return Verdict::Alive(Life { mac, rtt: answered });
        }
        match entry.map(|n| n.state) {
            Some(NeighState::Reachable) => Verdict::Alive(Life { mac, rtt: None }),
            Some(NeighState::Stale) if !last => Verdict::Wait,
            _ => Verdict::Dead,
        }
    }

    /// Which of `ips` are alive, in address order, each with the MAC it is
    /// at now; `None` if cancelled.
    ///
    /// Every address is probed ([`answers`]); then the neighbour table is
    /// read. One that answered is alive. One that did not is alive only if
    /// its entry is confirmed (REACHABLE); an unconfirmed (STALE) entry is
    /// watched for up to `settle` for the kernel's re-check. A bare entry
    /// is never enough.
    pub async fn live_hosts(
        ips: &[IpAddr],
        neighbours: &dyn Fn() -> Neighbours,
        cancel: &CancellationToken,
        settle: Duration,
    ) -> Option<Vec<(IpAddr, Life)>> {
        let slots = Arc::new(Semaphore::new(PARALLEL));
        let mut set = JoinSet::new();
        for &ip in ips {
            let slots = Arc::clone(&slots);
            set.spawn(async move {
                let _slot = slots.acquire_owned().await.ok();
                (ip, answers(ip).await)
            });
        }
        let mut answered = HashMap::new();
        loop {
            let next = tokio::select! {
                () = cancel.cancelled() => { set.abort_all(); return None; }
                n = set.join_next() => n,
            };
            match next {
                Some(Ok((ip, rtt))) => {
                    answered.insert(ip, rtt);
                }
                Some(Err(_)) => {}
                None => break,
            }
        }

        let deadline = Instant::now() + settle;
        let mut pending: HashSet<IpAddr> = ips.iter().copied().collect();
        let mut live = Vec::new();
        loop {
            let neigh = neighbours();
            let last = Instant::now() >= deadline;
            pending.retain(|&ip| {
                let rtt = answered.get(&ip).copied().flatten();
                match verdict(rtt, &neigh, ip, last) {
                    Verdict::Alive(l) => {
                        live.push((ip, l));
                        false
                    }
                    Verdict::Dead => false,
                    Verdict::Wait => true,
                }
            });
            if pending.is_empty() {
                break;
            }
            let wait = POLL.min(deadline.saturating_duration_since(Instant::now()));
            tokio::select! {
                () = cancel.cancelled() => return None,
                () = tokio::time::sleep(wait) => {}
            }
        }
        live.sort_unstable_by_key(|(ip, _)| *ip);
        Some(live)
    }

    /// Does the host answer? An ICMP echo reply (unprivileged ping socket)
    /// or any TCP accept/refuse on a common port; the round trip of the
    /// first answer.
    pub async fn answers(ip: IpAddr) -> Option<Duration> {
        let mut set = JoinSet::new();
        set.spawn(async move {
            let t = Instant::now();
            tokio::task::spawn_blocking(move || icmp_echo(ip))
                .await
                .unwrap_or(false)
                .then(|| t.elapsed())
        });
        for port in TCP_PORTS {
            set.spawn(async move { tcp_up(SocketAddr::new(ip, port)).await });
        }
        while let Some(r) = set.join_next().await {
            if let Ok(Some(rtt)) = r {
                return Some(rtt);
            }
        }
        None
    }

    async fn tcp_up(addr: SocketAddr) -> Option<Duration> {
        let t = Instant::now();
        match tokio::time::timeout(TCP_TIMEOUT, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => Some(t.elapsed()),
            Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => Some(t.elapsed()),
            _ => None,
        }
    }

    fn next_id() -> u16 {
        use std::sync::atomic::{AtomicU16, Ordering};
        static N: AtomicU16 = AtomicU16::new(1);
        (std::process::id() as u16).wrapping_add(N.fetch_add(1, Ordering::Relaxed))
    }

    fn checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        for c in data.chunks(2) {
            sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
        }
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// One echo request, wait up to 1 s for a reply. Any failure to open the
    /// socket (no ping_group_range, sandbox) is just "no answer".
    fn icmp_echo(ip: IpAddr) -> bool {
        let (domain, proto, req_type, reply_type) = match ip {
            IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4, 8u8, 0u8),
            IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6, 128u8, 129u8),
        };
        let Ok(sock) = Socket::new(domain, Type::DGRAM, Some(proto)).map(std::net::UdpSocket::from)
        else {
            return false;
        };
        let id = next_id().to_be_bytes();
        let mut pkt = [
            req_type, 0, 0, 0, id[0], id[1], 0, 1, b's', b'e', b'n', b's', b'r', 0, 0, 0,
        ];
        if ip.is_ipv4() {
            let c = checksum(&pkt).to_be_bytes();
            pkt[2] = c[0];
            pkt[3] = c[1];
        }
        let dest = SocketAddr::new(ip, 0);
        if sock.send_to(&pkt, dest).is_err() {
            return false;
        }
        let deadline = Instant::now() + ICMP_TIMEOUT;
        let mut buf = [0u8; 256];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || sock.set_read_timeout(Some(left)).is_err() {
                return false;
            }
            let Ok(n) = sock.recv(&mut buf) else {
                return false;
            };
            let b = &buf[..n];
            // macOS hands back the IPv4 header on datagram ICMP sockets.
            let off = if ip.is_ipv4() && b.first().is_some_and(|v| v >> 4 == 4) {
                usize::from(b[0] & 0xf) * 4
            } else {
                0
            };
            // Where the kernel keeps our id (macOS) other sockets' replies
            // arrive here too, so check it; Linux rewrites it and filters.
            let id_ok = off == 0 || b.get(off + 4..off + 6) == Some(&id[..]);
            if b.get(off) == Some(&reply_type) && id_ok {
                return true;
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::super::Neighbour;
        use super::*;

        const MAC: &str = "aa:bb:cc:dd:ee:ff";

        fn ip(s: &str) -> IpAddr {
            s.parse().unwrap()
        }

        fn one(ip_: IpAddr, n: Neighbour) -> Neighbours {
            HashMap::from([(ip_, n)])
        }

        #[test]
        fn verdicts() {
            let a = ip("192.0.2.1");
            let none = HashMap::new();
            let rtt = Some(Duration::from_millis(3));
            assert_eq!(
                verdict(rtt, &one(a, Neighbour::stale(MAC)), a, false),
                Verdict::Alive(Life {
                    mac: Some(MAC.into()),
                    rtt
                })
            );
            assert_eq!(
                verdict(None, &one(a, Neighbour::reachable(MAC)), a, true),
                Verdict::Alive(Life {
                    mac: Some(MAC.into()),
                    rtt: None
                })
            );
            assert_eq!(
                verdict(None, &one(a, Neighbour::stale(MAC)), a, false),
                Verdict::Wait
            );
            assert_eq!(
                verdict(None, &one(a, Neighbour::stale(MAC)), a, true),
                Verdict::Dead
            );
            let unknown = Neighbour {
                mac: MAC.into(),
                state: NeighState::Unknown,
            };
            assert_eq!(verdict(None, &one(a, unknown), a, false), Verdict::Dead);
            assert_eq!(verdict(None, &none, a, false), Verdict::Dead);
        }

        #[tokio::test]
        async fn loopback_is_alive_with_a_round_trip() {
            let live = live_hosts(
                &[ip("127.0.0.1")],
                &HashMap::new,
                &CancellationToken::new(),
                SETTLE,
            )
            .await
            .unwrap();
            assert_eq!(live.len(), 1);
            assert!(live[0].1.rtt.is_some());
            assert_eq!(live[0].1.mac, None);
        }

        #[tokio::test]
        async fn a_stale_entry_alone_is_not_life() {
            let a = ip("192.0.2.1");
            let t = std::time::Instant::now();
            let live = live_hosts(
                &[a],
                &|| one(a, Neighbour::stale(MAC)),
                &CancellationToken::new(),
                Duration::from_millis(400),
            )
            .await
            .unwrap();
            assert!(live.is_empty(), "{live:?}");
            assert!(t.elapsed() >= Duration::from_millis(400));
        }

        #[tokio::test]
        async fn a_confirmed_entry_is_life() {
            let a = ip("192.0.2.1");
            let live = live_hosts(
                &[a],
                &|| one(a, Neighbour::reachable(MAC)),
                &CancellationToken::new(),
                SETTLE,
            )
            .await
            .unwrap();
            assert_eq!(
                live,
                vec![(
                    a,
                    Life {
                        mac: Some(MAC.into()),
                        rtt: None
                    }
                )]
            );
        }

        #[tokio::test]
        async fn a_stale_entry_confirmed_after_the_probe_is_life() {
            use std::sync::atomic::{AtomicU32, Ordering};
            let a = ip("192.0.2.1");
            let reads = AtomicU32::new(0);
            let src = || {
                if reads.fetch_add(1, Ordering::SeqCst) < 2 {
                    one(a, Neighbour::stale(MAC))
                } else {
                    one(a, Neighbour::reachable(MAC))
                }
            };
            let live = live_hosts(&[a], &src, &CancellationToken::new(), SETTLE)
                .await
                .unwrap();
            assert_eq!(live.len(), 1);
        }

        #[tokio::test]
        async fn a_stale_entry_that_fails_ends_the_wait() {
            use std::sync::atomic::{AtomicU32, Ordering};
            let a = ip("192.0.2.1");
            let reads = AtomicU32::new(0);
            let src = || {
                if reads.fetch_add(1, Ordering::SeqCst) < 1 {
                    one(a, Neighbour::stale(MAC))
                } else {
                    HashMap::new()
                }
            };
            let t = std::time::Instant::now();
            let live = live_hosts(&[a], &src, &CancellationToken::new(), SETTLE)
                .await
                .unwrap();
            assert!(live.is_empty());
            assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
        }

        #[tokio::test]
        async fn test_net_is_dead_quickly() {
            let t = std::time::Instant::now();
            assert!(answers(ip("192.0.2.1")).await.is_none());
            assert!(t.elapsed() < Duration::from_secs(3));
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn the_netlink_dump_works() {
            // Every Linux host has at least an empty table; the dump must
            // not error (CI runs this).
            netlink_dump().unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ARP: &str = "IP address       HW type     Flags       HW address            Mask     Device\n\
192.168.1.10     0x1         0x2         AA:BB:CC:DD:EE:FF     *        eth0\n\
192.168.1.11     0x1         0x0         00:00:00:00:00:00     *        eth0\n\
garbage\n\
192.168.1.12     0x1         0x2         zz:bb     *        eth0\n";

    #[test]
    fn parses_complete_rows_lowercased_with_no_state() {
        let n = neighbours(ARP);
        assert_eq!(n.len(), 1);
        assert_eq!(
            n[&"192.168.1.10".parse::<IpAddr>().unwrap()],
            Neighbour {
                mac: "aa:bb:cc:dd:ee:ff".into(),
                state: NeighState::Unknown
            }
        );
    }

    #[test]
    fn empty_and_malformed_do_not_panic() {
        assert!(neighbours("").is_empty());
        assert!(neighbours("hdr\n\u{0}\u{1}\n1.2.3.4").is_empty());
    }

    #[test]
    fn skips_zero_mac_with_nonzero_flags() {
        let t = "h\n10.0.0.1 0x1 0x2 00:00:00:00:00:00 * e\n";
        assert!(neighbours(t).is_empty());
    }

    #[test]
    fn lookups() {
        let n = neighbours(ARP);
        let ip: IpAddr = "192.168.1.10".parse().unwrap();
        assert_eq!(mac_for(ip, &n).as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(
            ip_for("AA:bb:CC:dd:EE:ff", &n),
            Some(Ipv4Addr::new(192, 168, 1, 10))
        );
        assert_eq!(ip_for("11:22:33:44:55:66", &n), None);
        assert_eq!(mac_for("10.9.9.9".parse().unwrap(), &n), None);
    }

    #[test]
    fn ip_for_prefers_the_confirmed_entry() {
        let mac = "aa:bb:cc:dd:ee:ff";
        let n = HashMap::from([
            ("192.168.1.5".parse().unwrap(), Neighbour::stale(mac)),
            ("192.168.1.9".parse().unwrap(), Neighbour::reachable(mac)),
        ]);
        assert_eq!(ip_for(mac, &n), Some(Ipv4Addr::new(192, 168, 1, 9)));
    }

    /// One RTM_NEWNEIGH message as the kernel sends it.
    fn newneigh(state: u16, dst: &[u8], lladdr: Option<&[u8]>) -> Vec<u8> {
        let attr = |kind: u16, data: &[u8]| {
            let mut a = Vec::new();
            a.extend_from_slice(&(u16::try_from(4 + data.len()).unwrap()).to_ne_bytes());
            a.extend_from_slice(&kind.to_ne_bytes());
            a.extend_from_slice(data);
            while a.len() % 4 != 0 {
                a.push(0);
            }
            a
        };
        let mut body = vec![0u8; NDMSG];
        body[0] = if dst.len() == 4 { 2 } else { 10 };
        body[8..10].copy_from_slice(&state.to_ne_bytes());
        body.extend(attr(NDA_DST, dst));
        if let Some(l) = lladdr {
            body.extend(attr(NDA_LLADDR, l));
        }
        let mut m = Vec::new();
        m.extend_from_slice(&(u32::try_from(NLMSG_HDR + body.len()).unwrap()).to_ne_bytes());
        m.extend_from_slice(&RTM_NEWNEIGH.to_ne_bytes());
        m.extend_from_slice(&0x2u16.to_ne_bytes());
        m.extend_from_slice(&1u32.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.extend(body);
        m
    }

    fn done() -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&20u32.to_ne_bytes());
        m.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        m.extend_from_slice(&[0u8; 14]);
        m
    }

    #[test]
    fn parses_a_neighbour_dump_with_states() {
        let mac = [0xaa, 0xbb, 0xcc, 0, 0, 1];
        let mut buf = newneigh(NUD_REACHABLE, &[192, 168, 1, 10], Some(&mac));
        buf.extend(newneigh(NUD_STALE, &[192, 168, 1, 11], Some(&mac)));
        buf.extend(newneigh(NUD_DELAY, &[192, 168, 1, 12], Some(&mac)));
        buf.extend(newneigh(NUD_PERMANENT, &[192, 168, 1, 13], Some(&mac)));
        // failed and incomplete: no life, no MAC
        buf.extend(newneigh(0x20, &[192, 168, 1, 14], Some(&mac)));
        buf.extend(newneigh(0x01, &[192, 168, 1, 15], None));
        let v6 = "fe80::1".parse::<Ipv6Addr>().unwrap().octets();
        buf.extend(newneigh(NUD_PROBE, &v6, Some(&mac)));
        let mut out = HashMap::new();
        assert!(!parse_neigh_dump(&buf, &mut out));
        assert!(parse_neigh_dump(&done(), &mut out));
        let st = |s: &str| out.get(&s.parse::<IpAddr>().unwrap()).map(|n| n.state);
        assert_eq!(st("192.168.1.10"), Some(NeighState::Reachable));
        assert_eq!(st("192.168.1.11"), Some(NeighState::Stale));
        assert_eq!(st("192.168.1.12"), Some(NeighState::Stale));
        assert_eq!(st("192.168.1.13"), Some(NeighState::Unknown));
        assert_eq!(st("192.168.1.14"), None);
        assert_eq!(st("192.168.1.15"), None);
        assert_eq!(st("fe80::1"), Some(NeighState::Stale));
        assert_eq!(
            out[&"192.168.1.10".parse::<IpAddr>().unwrap()].mac,
            "aa:bb:cc:00:00:01"
        );
    }

    #[test]
    fn malformed_dumps_end_without_panicking() {
        let mut out = HashMap::new();
        assert!(parse_neigh_dump(&[0xff; 20], &mut out));
        let mut m = newneigh(NUD_REACHABLE, &[10, 0, 0, 1], Some(&[1, 2, 3, 4, 5, 6]));
        m.truncate(m.len() - 3);
        assert!(parse_neigh_dump(&m, &mut out));
        assert!(!parse_neigh_dump(&[], &mut out));
        assert!(out.is_empty());
    }

    #[test]
    fn the_dump_request_is_well_formed() {
        let r = neigh_dump_request(7);
        assert_eq!(r.len(), 28);
        assert_eq!(ne_u32(&r, 0), Some(28));
        assert_eq!(ne_u16(&r, 4), Some(RTM_GETNEIGH));
        assert_eq!(ne_u16(&r, 6), Some(NLM_F_REQUEST | NLM_F_DUMP));
        assert_eq!(ne_u32(&r, 8), Some(7));
    }
}
