//! Passive evidence for smart host labels
//! (docs/superpowers/specs/2026-11-23-host-labels-design.md).
//!
//! - [`Sniffer`]: the `sensr-fp` thread. It reads DHCP requests and mDNS
//!   announcements off the internal interfaces through a read-only
//!   [`PacketSource`] and hands what
//!   they say to the inventory, keyed by the sender's MAC. On Linux these are
//!   two receive-only `AF_PACKET` taps (`ETH_P_IP`, `ETH_P_IPV6`) with a
//!   kernel BPF filter, and per-interface mDNS group memberships so the NIC
//!   passes the multicast frames up.
//! - [`evidence`]: Ethernet → IPv4/IPv6 → UDP → DHCP/mDNS, pure.
//! - [`Querier`]: the one packet the router sends, a DNS-SD
//!   `_services._dns-sd._udp.local` PTR query per internal interface at
//!   start and every [`QUERY_EVERY`], over an ordinary UDP socket
//!   ([`QuerySender`]). Never on the packet socket, which has no send.
//!
//! The caller builds the interface list only from `internal_interfaces(doc)`
//! ([`interfaces`]); frames from any other interface index are dropped.

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sensr_fingerprint::{dhcp, mdns};
use sensr_rules::document::InternalIf;

use crate::arp_intercept::{Clock, LinkLookup, SystemClock};
use crate::hosts::EvidenceUpdate;

/// How often each interface is asked for its services.
pub const QUERY_EVERY: Duration = Duration::from_secs(900);
/// Wait without a socket before looking again.
const IDLE_WAIT: Duration = Duration::from_millis(100);
/// mDNS port.
pub const MDNS_PORT: u16 = 5353;
/// DHCP server port: client requests go here.
const DHCP_SERVER_PORT: u16 = 67;
/// Ethertypes the two packet taps listen for.
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86dd;
/// Wait between receive attempts while the socket keeps failing.
const ERROR_WAIT: Duration = Duration::from_secs(1);
/// DHCP DISCOVER and REQUEST: what a client sends when it joins. INFORM
/// and the rest carry different option lists on some systems (Windows),
/// which would make the evidence flip back and forth.
const DHCP_TYPES: [u8; 2] = [1, 3];

/// An internal interface the sniffer listens on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SniffIface {
    /// Interface id (`lan`).
    pub id: String,
    /// Linux device.
    pub device: String,
    /// Kernel interface index.
    pub index: u32,
}

/// The internal interfaces whose device the kernel knows.
pub fn interfaces(internal: &[InternalIf], link: &LinkLookup) -> Vec<SniffIface> {
    internal
        .iter()
        .filter_map(|i| {
            let (index, _) = link(&i.device)?;
            Some(SniffIface {
                id: i.id.clone(),
                device: i.device.clone(),
                index,
            })
        })
        .collect()
}

/// `aa:bb:cc:dd:ee:ff`, the form `classify` and the inventory use.
pub fn mac_string(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// A host's own address: not group, not zero.
fn unicast(m: [u8; 6]) -> bool {
    m[0] & 1 == 0 && m != [0; 6]
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

/// One UDP datagram out of an Ethernet frame.
struct Udp<'a> {
    src_mac: [u8; 6],
    dst: IpAddr,
    sport: u16,
    dport: u16,
    payload: &'a [u8],
}

fn udp(frame: &[u8]) -> Option<Udp<'_>> {
    let src_mac: [u8; 6] = frame.get(6..12)?.try_into().ok()?;
    let ip = frame.get(14..)?;
    let (dst, seg) = match u16_at(frame, 12)? {
        0x0800 => {
            if ip.first()? >> 4 != 4 || *ip.get(9)? != 17 {
                return None;
            }
            // a fragment's tail has no UDP header; its head is truncated
            if u16_at(ip, 6)? & 0x3fff != 0 {
                return None;
            }
            let ihl = usize::from(ip.first()? & 0x0f) * 4;
            let total = usize::from(u16_at(ip, 2)?);
            let d: [u8; 4] = ip.get(16..20)?.try_into().ok()?;
            if ihl < 20 || total < ihl {
                return None;
            }
            (IpAddr::from(d), ip.get(ihl..total)?)
        }
        0x86dd => {
            // UDP right after the fixed header only; extension headers
            // are not walked
            if ip.first()? >> 4 != 6 || *ip.get(6)? != 17 {
                return None;
            }
            let len = usize::from(u16_at(ip, 4)?);
            let d: [u8; 16] = ip.get(24..40)?.try_into().ok()?;
            (IpAddr::from(d), ip.get(40..40 + len)?)
        }
        _ => return None,
    };
    let ulen = usize::from(u16_at(seg, 4)?);
    if ulen < 8 {
        return None;
    }
    Some(Udp {
        src_mac,
        dst,
        sport: u16_at(seg, 0)?,
        dport: u16_at(seg, 2)?,
        payload: seg.get(8..ulen)?,
    })
}

/// What one frame says about a host, and that host's MAC: a client's DHCP
/// request (keyed by `chaddr`) or a multicast mDNS packet (keyed by the
/// Ethernet source).
///
/// Passive evidence is only what a device claims: anyone on the LAN can
/// spoof it, and a sleep proxy (an Apple TV answering for a sleeping Mac) or
/// an mDNS reflector re-sending others' records gets them misattributed to
/// itself. Labels built on it are hints, never access decisions.
pub fn evidence(frame: &[u8]) -> Option<(String, EvidenceUpdate)> {
    let u = udp(frame)?;
    let (mac, ev) = if u.dport == DHCP_SERVER_PORT {
        let d = dhcp::parse_bootp(u.payload)?;
        if !d.msg_type.is_some_and(|t| DHCP_TYPES.contains(&t)) {
            return None;
        }
        let ev = EvidenceUpdate {
            dhcp_vendor: d.vendor_class,
            dhcp_prl: d.prl,
            dhcp_hostname: d.hostname,
            ..EvidenceUpdate::default()
        };
        (d.chaddr, ev)
    } else if (u.sport == MDNS_PORT || u.dport == MDNS_PORT) && u.dst.is_multicast() {
        let m = mdns::parse(u.payload)?;
        let ev = EvidenceUpdate {
            mdns_services: m.services,
            mdns_model: m.model,
            mdns_name: m.instance,
            ..EvidenceUpdate::default()
        };
        (u.src_mac, ev)
    } else {
        return None;
    };
    (unicast(mac) && !ev.is_empty()).then(|| (mac_string(mac), ev))
}

/// The DNS-SD service enumeration query (RFC 6763 §9), a plain multicast
/// question: answers come back multicast, where the sniffer sees them.
pub fn query_packet() -> Vec<u8> {
    let mut p = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in ["_services", "_dns-sd", "_udp", "local"] {
        p.push(u8::try_from(l.len()).unwrap_or(0));
        p.extend_from_slice(l.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&[0, 12, 0, 1]); // PTR, IN
    p
}

/// A classic BPF instruction: `(code, jt, jf, k)`.
pub type Insn = (u16, u8, u8, u32);

/// The kernel-side filter on the packet socket: UDP over IPv4 (unfragmented)
/// or IPv6 (no extension headers) to port 67, or from or to port 5353.
/// Everything else (forwarded traffic) stays in the kernel. User space
/// checks again ([`evidence`]).
pub const FILTER: [Insn; 22] = [
    (0x28, 0, 0, 12),          // 0  ldh [12]
    (0x15, 0, 7, 0x86dd),      // 1  ipv6? else 9
    (0x30, 0, 0, 20),          // 2  ldb [20] next header
    (0x15, 0, 17, 17),         // 3  udp? else reject
    (0x28, 0, 0, 54),          // 4  ldh [54] source port
    (0x15, 14, 0, 5353),       // 5  accept
    (0x28, 0, 0, 56),          // 6  ldh [56] destination port
    (0x15, 12, 0, 67),         // 7  accept
    (0x15, 11, 12, 5353),      // 8  accept / reject
    (0x15, 0, 11, 0x0800),     // 9  ipv4? else reject
    (0x30, 0, 0, 23),          // 10 ldb [23] protocol
    (0x15, 0, 9, 17),          // 11 udp? else reject
    (0x28, 0, 0, 20),          // 12 ldh [20] flags/fragment
    (0x45, 7, 0, 0x3fff),      // 13 fragment: reject
    (0xb1, 0, 0, 14),          // 14 ldxb 4*([14]&0xf)
    (0x48, 0, 0, 14),          // 15 ldh [x+14] source port
    (0x15, 3, 0, 5353),        // 16 accept
    (0x48, 0, 0, 16),          // 17 ldh [x+16] destination port
    (0x15, 1, 0, 67),          // 18 accept
    (0x15, 0, 1, 5353),        // 19 accept / reject
    (0x06, 0, 0, 0x0004_0000), // 20 accept (whole frame)
    (0x06, 0, 0, 0),           // 21 reject
];

/// Held while an interface is in the set: its mDNS group memberships.
/// Dropping it leaves the groups.
pub type Membership = Box<dyn Send + Sync>;

/// A raw, receive-only link-layer socket.
pub trait PacketSource: Send + Sync {
    /// Has interface `iface` pass the mDNS multicast groups up, so the
    /// frames reach this socket; held until the guard is dropped.
    fn join(&self, _iface: &SniffIface) -> io::Result<Membership> {
        Ok(Box::new(()))
    }
    /// The next frame and the index of the interface it came in on (frames
    /// this host sent are skipped); `WouldBlock`/`TimedOut` after a short
    /// wait with none.
    fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, u32)>;
}

/// Sends the service query out of one interface.
pub trait QuerySender: Send + Sync {
    fn send(&self, iface: &SniffIface) -> io::Result<()>;
}

/// The mDNS groups.
pub const MDNS_V4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(224, 0, 0, 251);
pub const MDNS_V6: std::net::Ipv6Addr = std::net::Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

/// How long [`Polled::recv`] waits for either tap before the loop takes a
/// turn.
pub const POLL_WAIT: Duration = Duration::from_millis(200);

/// Two non-blocking receive sockets and one wait over both.
pub trait Taps: Send + Sync {
    /// Waits up to `timeout` for either tap to have a frame; which are ready.
    fn wait(&self, timeout: Duration) -> io::Result<[bool; 2]>;
    /// A frame from tap `i` if one is queued, without waiting.
    fn try_recv(&self, i: usize, buf: &mut [u8]) -> io::Result<Option<(usize, u32)>>;
}

/// Reads two [`Taps`] as one stream: whatever is queued on either goes
/// first (taking turns, so neither starves), and only when both are empty
/// does it wait, on both at once. An idle tap never delays the busy one.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct Polled<T> {
    taps: T,
    /// The tap read first next.
    turn: std::sync::atomic::AtomicUsize,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl<T: Taps> Polled<T> {
    pub fn new(taps: T) -> Self {
        Self {
            taps,
            turn: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn take(&self, ready: [bool; 2], buf: &mut [u8]) -> io::Result<Option<(usize, u32)>> {
        let first = self.turn.load(Ordering::Relaxed);
        for k in 0..2 {
            let i = (first + k) % 2;
            if !ready[i] {
                continue;
            }
            if let Some(r) = self.taps.try_recv(i, buf)? {
                self.turn.store((i + 1) % 2, Ordering::Relaxed);
                return Ok(Some(r));
            }
        }
        Ok(None)
    }

    /// The next frame from either tap; `WouldBlock` after [`POLL_WAIT`]
    /// with none.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, u32)> {
        if let Some(r) = self.take([true; 2], buf)? {
            return Ok(r);
        }
        let ready = self.taps.wait(POLL_WAIT)?;
        self.take(ready, buf)?
            .ok_or_else(|| io::ErrorKind::WouldBlock.into())
    }
}

#[cfg(target_os = "linux")]
mod sys {
    use std::io::{self, Read};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::os::fd::{AsFd, AsRawFd};
    use std::time::Duration;

    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use nix::sys::socket::{LinkAddr, recvfrom};

    use super::{
        ETH_P_IP, ETH_P_IPV6, FILTER, MDNS_PORT, MDNS_V4, MDNS_V6, Membership, PacketSource,
        Polled, QuerySender, SniffIface, Taps,
    };

    /// `sll_pkttype` of a frame this host sent (a backstop: protocol taps
    /// see received frames only).
    const PACKET_OUTGOING: u8 = 4;
    /// Most frames discarded right after the filter is attached.
    const DRAIN_MAX: usize = 4096;

    /// An `AF_PACKET`/`SOCK_RAW` tap for one ethertype, with [`FILTER`].
    /// A protocol-specific tap is on the receive path only, so frames the
    /// router transmits or forwards out are never copied to it.
    fn tap(ethertype: u16) -> io::Result<socket2::Socket> {
        let sock = socket2::Socket::new(
            socket2::Domain::PACKET,
            socket2::Type::RAW,
            Some(socket2::Protocol::from(i32::from(ethertype.to_be()))),
        )?;
        let prog: Vec<socket2::SockFilter> = FILTER
            .iter()
            .map(|&(code, jt, jf, k)| socket2::SockFilter::new(code, jt, jf, k))
            .collect();
        sock.attach_filter(&prog)?;
        drain(&sock)?;
        Ok(sock)
    }

    /// Discards what was queued before the filter was attached, and leaves
    /// the socket non-blocking ([`super::Polled`] waits in `poll`).
    fn drain(sock: &socket2::Socket) -> io::Result<()> {
        sock.set_nonblocking(true)?;
        // a short read drops the rest of the frame
        let mut buf = [0u8; 64];
        for _ in 0..DRAIN_MAX {
            match (&*sock).read(&mut buf) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Two receive-only taps, IPv4 and IPv6, on every interface. Nothing is
    /// ever sent on them.
    pub struct AfPacketSource {
        taps: Polled<LinuxTaps>,
    }

    /// The two non-blocking taps.
    pub struct LinuxTaps([socket2::Socket; 2]);

    impl AfPacketSource {
        /// Needs `CAP_NET_RAW`.
        pub fn open() -> io::Result<Self> {
            Ok(Self {
                taps: Polled::new(LinuxTaps([tap(ETH_P_IP)?, tap(ETH_P_IPV6)?])),
            })
        }
    }

    impl Taps for LinuxTaps {
        fn wait(&self, timeout: Duration) -> io::Result<[bool; 2]> {
            let ms = u16::try_from(timeout.as_millis()).unwrap_or(u16::MAX);
            let mut fds = [
                PollFd::new(self.0[0].as_fd(), PollFlags::POLLIN),
                PollFd::new(self.0[1].as_fd(), PollFlags::POLLIN),
            ];
            match poll(&mut fds, PollTimeout::from(ms)) {
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => return Ok([false; 2]),
                Err(e) => return Err(e.into()),
            }
            // an error or hang-up counts as ready: the read reports it
            Ok(fds.map(|f| f.revents().is_some_and(|r| !r.is_empty())))
        }

        fn try_recv(&self, i: usize, buf: &mut [u8]) -> io::Result<Option<(usize, u32)>> {
            let Some(sock) = self.0.get(i) else {
                return Ok(None);
            };
            loop {
                let (n, from) = match recvfrom::<LinkAddr>(sock.as_raw_fd(), buf) {
                    Ok(r) => r,
                    Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => return Ok(None),
                    Err(e) => return Err(e.into()),
                };
                let Some(from) = from else { continue };
                if from.pkttype() == PACKET_OUTGOING {
                    continue;
                }
                return Ok(Some((n, u32::try_from(from.ifindex()).unwrap_or(0))));
            }
        }
    }

    impl PacketSource for AfPacketSource {
        /// A UDP socket per family on an ephemeral port (so nothing is
        /// delivered to it) that joins the mDNS group on the interface: the
        /// kernel then programs the NIC to accept the group's frames.
        fn join(&self, iface: &SniffIface) -> io::Result<Membership> {
            let (v4, ll) = addrs(&iface.device)?;
            let mut held: Vec<socket2::Socket> = Vec::new();
            let mut first_err = None;
            if let Some(a) = v4 {
                let r = (|| {
                    let s = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::DGRAM,
                        Some(socket2::Protocol::UDP),
                    )?;
                    bind_or_any(&s, SocketAddr::from((a, 0)))?;
                    s.join_multicast_v4(&MDNS_V4, &a)?;
                    Ok::<_, io::Error>(s)
                })();
                match r {
                    Ok(s) => held.push(s),
                    Err(e) => {
                        first_err.get_or_insert(e);
                    }
                }
            }
            let r = (|| {
                let s = socket2::Socket::new(
                    socket2::Domain::IPV6,
                    socket2::Type::DGRAM,
                    Some(socket2::Protocol::UDP),
                )?;
                s.set_only_v6(true)?;
                let own = ll.unwrap_or(Ipv6Addr::UNSPECIFIED);
                bind_or_any(&s, SocketAddrV6::new(own, 0, 0, iface.index).into())?;
                s.join_multicast_v6(&MDNS_V6, iface.index)?;
                Ok::<_, io::Error>(s)
            })();
            match r {
                Ok(s) => held.push(s),
                Err(e) => {
                    first_err.get_or_insert(e);
                }
            }
            match (held.is_empty(), first_err) {
                (true, Some(e)) => Err(e),
                _ => Ok(Box::new(held)),
            }
        }

        fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, u32)> {
            self.taps.recv(buf)
        }
    }

    /// Binds `s` to `addr` on an ephemeral port, else to the wildcard
    /// (the address went away, or the scope is refused).
    fn bind_or_any(s: &socket2::Socket, addr: SocketAddr) -> io::Result<()> {
        if s.bind(&addr.into()).is_ok() {
            return Ok(());
        }
        let any = match addr {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        s.bind(&any.into())
    }

    /// The device's IPv4 address and IPv6 link-local address.
    fn addrs(device: &str) -> io::Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        let mut v4 = None;
        let mut v6 = None;
        for a in nix::ifaddrs::getifaddrs()?.filter(|a| a.interface_name == device) {
            let Some(addr) = a.address else { continue };
            if let Some(s) = addr.as_sockaddr_in() {
                v4.get_or_insert(s.ip());
            } else if let Some(s) = addr.as_sockaddr_in6()
                && s.ip().segments()[0] & 0xffc0 == 0xfe80
            {
                v6.get_or_insert(s.ip());
            }
        }
        Ok((v4, v6))
    }

    /// A UDP socket from `bind`, port 5353 where the host allows sharing it
    /// (answers to a query from 5353 go to the group), else any port.
    /// `IPV6_V6ONLY` is set before the bind: Linux refuses it after.
    fn udp(bind: SocketAddr) -> io::Result<socket2::Socket> {
        let domain = socket2::Domain::for_address(bind);
        let s = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        if bind.is_ipv6() {
            s.set_only_v6(true)?;
        }
        s.set_reuse_address(true)?;
        s.set_reuse_port(true)?;
        if s.bind(&bind.into()).is_err() {
            let mut any = bind;
            any.set_port(0);
            s.bind(&any.into())?;
        }
        Ok(s)
    }

    /// The IPv4 query socket: from `a`, out of `a`'s interface.
    fn v4_sender(a: Ipv4Addr) -> io::Result<socket2::Socket> {
        let s = udp(SocketAddrV4::new(a, MDNS_PORT).into())?;
        s.set_multicast_if_v4(&a)?;
        s.set_multicast_ttl_v4(255)?;
        s.set_multicast_loop_v4(false)?;
        Ok(s)
    }

    /// The IPv6 query socket: from link-local `a` on interface `index`.
    fn v6_sender(a: Ipv6Addr, index: u32) -> io::Result<socket2::Socket> {
        let s = udp(SocketAddrV6::new(a, MDNS_PORT, 0, index).into())?;
        s.set_multicast_if_v6(index)?;
        s.set_multicast_hops_v6(255)?;
        s.set_multicast_loop_v6(false)?;
        Ok(s)
    }

    /// Sends [`super::query_packet`] to 224.0.0.251 and, with a link-local
    /// address, ff02::fb, from the interface's own address.
    pub struct UdpQuerySender;

    impl QuerySender for UdpQuerySender {
        fn send(&self, iface: &SniffIface) -> io::Result<()> {
            let (v4, v6) = addrs(&iface.device)?;
            if v4.is_none() && v6.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    format!("{} has no address", iface.device),
                ));
            }
            let q = super::query_packet();
            let mut first_err = None;
            if let Some(a) = v4 {
                let to = SocketAddr::from(SocketAddrV4::new(MDNS_V4, MDNS_PORT));
                if let Err(e) = v4_sender(a).and_then(|s| s.send_to(&q, &to.into())) {
                    first_err.get_or_insert(e);
                }
            }
            if let Some(a) = v6 {
                let to = SocketAddr::from(SocketAddrV6::new(MDNS_V6, MDNS_PORT, 0, iface.index));
                if let Err(e) = v6_sender(a, iface.index).and_then(|s| s.send_to(&q, &to.into())) {
                    first_err.get_or_insert(e);
                }
            }
            first_err.map_or(Ok(()), Err)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn would_block(e: &io::Error) -> bool {
            matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
            )
        }

        /// Every option the senders set is accepted, in this order (Linux
        /// refuses `IPV6_V6ONLY` after the bind).
        #[test]
        fn sender_sockets_build_on_loopback() {
            v4_sender(Ipv4Addr::LOCALHOST).expect("IPv4 sender");
            let lo = nix::net::if_::if_nametoindex("lo").expect("lo");
            match socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None) {
                // no IPv6 in this environment
                Err(_) => {}
                Ok(_) => {
                    v6_sender(Ipv6Addr::LOCALHOST, lo).expect("IPv6 sender");
                }
            }
        }

        /// The real taps end to end: filter attached, both sockets read,
        /// the interface index reported, and other traffic kept out.
        #[test]
        #[ignore = "needs CAP_NET_RAW"]
        fn af_packet_taps_see_dhcp_on_loopback() {
            let lo = nix::net::if_::if_nametoindex("lo").expect("lo");
            let src = AfPacketSource::open().unwrap();
            let _m = src.join(&SniffIface {
                id: "lo".into(),
                device: "lo".into(),
                index: lo,
            });
            let chaddr = [0xaa, 0xbb, 0xcc, 0, 0, 1];
            let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            tx.send_to(b"not for us", "127.0.0.1:9").unwrap();
            let dhcp = crate::fingerprint::tests::dhcp_discover(chaddr);
            tx.send_to(&dhcp, "127.0.0.1:67").unwrap();
            let mut buf = [0u8; 2048];
            let mut got = None;
            for _ in 0..20 {
                match src.recv(&mut buf) {
                    Ok(r) => {
                        got = Some(r);
                        break;
                    }
                    Err(e) if would_block(&e) => {}
                    Err(e) => panic!("{e}"),
                }
            }
            let (n, index) = got.expect("the DHCP frame");
            assert_eq!(index, lo);
            let (mac, ev) = crate::fingerprint::evidence(&buf[..n]).expect("parsed");
            assert_eq!(mac, "aa:bb:cc:00:00:01");
            assert_eq!(ev.dhcp_hostname.as_deref(), Some("Pixel-8"));
            let again = src.recv(&mut buf).unwrap_err();
            assert!(would_block(&again), "port 9 was filtered: {again:?}");
        }

        #[test]
        fn udp_sets_v6only_before_bind() {
            if socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None).is_err() {
                return;
            }
            let s = udp(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))).expect("bound");
            assert!(s.only_v6().unwrap());
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod sys {
    use std::io;

    use super::{PacketSource, QuerySender, SniffIface};

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "host fingerprinting needs Linux (AF_PACKET)",
        )
    }

    /// Off Linux: never opens.
    pub struct AfPacketSource;

    impl AfPacketSource {
        pub fn open() -> io::Result<Self> {
            Err(unsupported())
        }
    }

    impl PacketSource for AfPacketSource {
        fn recv(&self, _: &mut [u8]) -> io::Result<(usize, u32)> {
            Err(unsupported())
        }
    }

    /// Off Linux: sends nothing.
    pub struct UdpQuerySender;

    impl QuerySender for UdpQuerySender {
        fn send(&self, _: &SniffIface) -> io::Result<()> {
            Err(unsupported())
        }
    }
}

pub use sys::{AfPacketSource, UdpQuerySender};

/// When each interface is next asked for its services.
#[derive(Default)]
pub struct Querier {
    next: BTreeMap<u32, Instant>,
}

impl Querier {
    /// The interfaces due a query at `now`: one just added, or one asked
    /// [`QUERY_EVERY`] ago. Each is then not due for another interval.
    pub fn due(&mut self, now: Instant, ifaces: &[SniffIface]) -> Vec<SniffIface> {
        self.next
            .retain(|index, _| ifaces.iter().any(|i| i.index == *index));
        let mut out = Vec::new();
        for i in ifaces {
            if self.next.get(&i.index).is_none_or(|t| *t <= now) {
                self.next.insert(i.index, now + QUERY_EVERY);
                out.push(i.clone());
            }
        }
        out
    }
}

/// Opens the packet socket (when the sniffer gets interfaces).
pub type OpenFn = Arc<dyn Fn() -> io::Result<Arc<dyn PacketSource>> + Send + Sync>;
/// Where evidence goes: the inventory's `record_evidence`.
pub type Sink = Arc<dyn Fn(&str, &EvidenceUpdate) + Send + Sync>;

#[derive(Default)]
struct State {
    /// The internal interfaces; frames from any other index are dropped.
    ifaces: Vec<SniffIface>,
    socket: Option<Arc<dyn PacketSource>>,
    /// mDNS group memberships by interface index, held while the
    /// interface is in the set.
    joined: BTreeMap<u32, Membership>,
    /// Why the socket could not be opened, logged once.
    error: Option<String>,
    querier: Querier,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The passive evidence task.
pub struct Sniffer {
    open: OpenFn,
    sender: Arc<dyn QuerySender>,
    clock: Arc<dyn Clock>,
    sink: Sink,
    state: Mutex<State>,
    /// The last receive error's kind: logged at warn once, then debug.
    recv_error: Mutex<Option<io::ErrorKind>>,
    stopped: AtomicBool,
    started: AtomicBool,
}

impl Sniffer {
    /// Idle until [`Self::set_interfaces`] gives it an interface.
    pub fn new(
        open: OpenFn,
        sender: Arc<dyn QuerySender>,
        clock: Arc<dyn Clock>,
        sink: Sink,
    ) -> Arc<Self> {
        Arc::new(Self {
            open,
            sender,
            clock,
            sink,
            state: Mutex::new(State::default()),
            recv_error: Mutex::new(None),
            stopped: AtomicBool::new(false),
            started: AtomicBool::new(false),
        })
    }

    /// On the host: `AF_PACKET`, UDP queries and the real clock.
    pub fn system(sink: Sink) -> Arc<Self> {
        Self::new(
            Arc::new(|| AfPacketSource::open().map(|s| Arc::new(s) as Arc<dyn PacketSource>)),
            Arc::new(UdpQuerySender),
            Arc::new(SystemClock),
            sink,
        )
    }

    /// The internal interfaces to listen on (empty: close the socket).
    /// Opens the socket when needed; a failure is logged once and retried
    /// on the next call.
    pub fn set_interfaces(&self, ifaces: Vec<SniffIface>) {
        let mut st = lock(&self.state);
        if self.stopped.load(Ordering::SeqCst) {
            return;
        }
        if ifaces.is_empty() {
            *st = State::default();
            return;
        }
        if st.socket.is_none() {
            match (self.open)() {
                Ok(s) => {
                    if st.error.take().is_some() {
                        tracing::info!("host fingerprint socket opened");
                    }
                    st.joined.clear();
                    st.socket = Some(s);
                }
                Err(e) => {
                    let msg = format!("raw socket: {e}");
                    if st.error.as_deref() != Some(msg.as_str()) {
                        tracing::warn!(error = %e, "host fingerprinting unavailable");
                    }
                    st.error = Some(msg);
                }
            }
        }
        // leaving the set leaves the groups
        st.joined
            .retain(|index, _| ifaces.iter().any(|i| i.index == *index));
        if let Some(sock) = st.socket.clone() {
            for i in &ifaces {
                if st.joined.contains_key(&i.index) {
                    continue;
                }
                match sock.join(i) {
                    Ok(m) => {
                        st.joined.insert(i.index, m);
                    }
                    Err(e) => {
                        tracing::debug!(device = %i.device, error = %e, "mDNS group membership");
                    }
                }
            }
        }
        st.ifaces = ifaces;
    }

    /// Starts the loop in a thread (once); it exits after [`Self::stop`].
    pub fn start(self: &Arc<Self>) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let s = Arc::clone(self);
        let r = std::thread::Builder::new()
            .name("sensr-fp".into())
            .spawn(move || {
                let mut buf = vec![0u8; 2048];
                while !s.stopped.load(Ordering::SeqCst) {
                    s.step(&mut buf);
                }
            });
        if let Err(e) = r {
            tracing::error!(error = %e, "host fingerprint sniffer not started");
        }
    }

    /// Stops the loop and closes the socket. Later calls do nothing.
    pub fn stop(&self) {
        let mut st = lock(&self.state);
        self.stopped.store(true, Ordering::SeqCst);
        *st = State::default();
    }

    /// Whether the packet socket is open.
    pub fn listening(&self) -> bool {
        lock(&self.state).socket.is_some()
    }

    /// One turn of the loop: a frame (or a short wait), then any query due.
    pub fn step(&self, buf: &mut [u8]) {
        let sock = lock(&self.state).socket.clone();
        match sock {
            None => self.clock.sleep(IDLE_WAIT),
            Some(s) => match s.recv(buf) {
                Ok((n, index)) => {
                    lock(&self.recv_error).take();
                    self.on_frame(buf.get(..n).unwrap_or_default(), index);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => {
                    {
                        let mut last = lock(&self.recv_error);
                        if *last == Some(e.kind()) {
                            tracing::debug!(error = %e, "host fingerprint receive");
                        } else {
                            tracing::warn!(error = %e, "host fingerprint receive");
                            *last = Some(e.kind());
                        }
                    }
                    self.clock.sleep(ERROR_WAIT);
                }
            },
        }
        self.query();
    }

    fn on_frame(&self, frame: &[u8], index: u32) {
        if !lock(&self.state).ifaces.iter().any(|i| i.index == index) {
            return;
        }
        if let Some((mac, ev)) = evidence(frame) {
            (self.sink)(&mac, &ev);
        }
    }

    /// Sends the queries due, outside the lock. Only while listening:
    /// answers nobody reads are not worth asking for.
    fn query(&self) {
        let now = self.clock.now();
        let due = {
            let mut st = lock(&self.state);
            let st = &mut *st;
            if st.socket.is_none() {
                return;
            }
            st.querier.due(now, &st.ifaces)
        };
        for i in due {
            if let Err(e) = self.sender.send(&i) {
                tracing::debug!(device = %i.device, error = %e, "mDNS service query");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hosts::{HostCollector, HostStore};

    const LAN: u32 = 3;
    const WAN: u32 = 2;
    const PHONE: [u8; 6] = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01];

    fn lan() -> SniffIface {
        SniffIface {
            id: "lan".into(),
            device: "igc1".into(),
            index: LAN,
        }
    }

    fn eth(src: [u8; 6], dst: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn udp_seg(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut u = Vec::new();
        u.extend_from_slice(&sport.to_be_bytes());
        u.extend_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(payload);
        u
    }

    fn ipv4_udp(src: [u8; 6], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let seg = udp_seg(sport, dport, payload);
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&u16::try_from(20 + seg.len()).unwrap().to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0x40, 0, 64, 17, 0, 0]); // DF
        ip.extend_from_slice(&[0, 0, 0, 0]);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&seg);
        ip.extend_from_slice(&[0; 6]); // Ethernet padding
        eth(src, [0xff; 6], 0x0800, &ip)
    }

    fn ipv6_udp(src: [u8; 6], dst: [u16; 8], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let seg = udp_seg(sport, dport, payload);
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend_from_slice(&u16::try_from(seg.len()).unwrap().to_be_bytes());
        ip.extend_from_slice(&[17, 255]);
        ip.extend_from_slice(&std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets());
        let d = std::net::Ipv6Addr::new(
            dst[0], dst[1], dst[2], dst[3], dst[4], dst[5], dst[6], dst[7],
        );
        ip.extend_from_slice(&d.octets());
        ip.extend_from_slice(&seg);
        eth(src, [0x33, 0x33, 0, 0, 0, 0xfb], 0x86dd, &ip)
    }

    pub(crate) fn dhcp_discover(chaddr: [u8; 6]) -> Vec<u8> {
        let mut p = vec![0u8; 240];
        p[0] = 1;
        p[1] = 1;
        p[2] = 6;
        p[28..34].copy_from_slice(&chaddr);
        p[236..240].copy_from_slice(&[99, 130, 83, 99]);
        let mut opt = |code: u8, v: &[u8]| {
            p.push(code);
            p.push(u8::try_from(v.len()).unwrap());
            p.extend_from_slice(v);
        };
        opt(53, &[1]);
        opt(12, b"Pixel-8");
        opt(55, &[1, 3, 6, 15, 26, 28, 51, 58, 59, 43]);
        opt(60, b"android-dhcp-14");
        p.push(255);
        p
    }

    fn name(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for l in labels {
            out.push(u8::try_from(l.len()).unwrap());
            out.extend_from_slice(l.as_bytes());
        }
        out.push(0);
        out
    }

    /// An mDNS response enumerating `services` (`_x._tcp` each).
    fn mdns_response(services: &[String]) -> Vec<u8> {
        let mut p = vec![0, 0, 0x84, 0, 0, 0];
        p.extend_from_slice(&u16::try_from(services.len()).unwrap().to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0]);
        for s in services {
            let (svc, proto) = s.split_once('.').unwrap();
            let target = name(&[svc, proto, "local"]);
            p.extend_from_slice(&name(&["_services", "_dns-sd", "_udp", "local"]));
            p.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0x11, 0x94]);
            p.extend_from_slice(&u16::try_from(target.len()).unwrap().to_be_bytes());
            p.extend_from_slice(&target);
        }
        p
    }

    /// Counts joins per interface index and releases (guard drops).
    #[derive(Default)]
    struct MockSource {
        frames: Mutex<Vec<(Vec<u8>, u32)>>,
        joins: Mutex<Vec<u32>>,
        released: Arc<Mutex<Vec<u32>>>,
        /// Returned by every `recv` while set.
        fail: Mutex<Option<io::ErrorKind>>,
    }

    struct Guard(u32, Arc<Mutex<Vec<u32>>>);

    impl Drop for Guard {
        fn drop(&mut self) {
            lock(&self.1).push(self.0);
        }
    }

    impl MockSource {
        fn push(&self, frame: Vec<u8>, index: u32) {
            lock(&self.frames).push((frame, index));
        }
    }

    impl PacketSource for MockSource {
        fn join(&self, iface: &SniffIface) -> io::Result<Membership> {
            lock(&self.joins).push(iface.index);
            Ok(Box::new(Guard(iface.index, Arc::clone(&self.released))))
        }

        fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, u32)> {
            if let Some(k) = *lock(&self.fail) {
                return Err(k.into());
            }
            let mut q = lock(&self.frames);
            if q.is_empty() {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let (f, i) = q.remove(0);
            buf[..f.len()].copy_from_slice(&f);
            Ok((f.len(), i))
        }
    }

    #[derive(Default)]
    struct MockSender(Mutex<Vec<String>>);

    impl QuerySender for MockSender {
        fn send(&self, iface: &SniffIface) -> io::Result<()> {
            lock(&self.0).push(iface.id.clone());
            Ok(())
        }
    }

    struct TestClock(Mutex<Instant>, Mutex<Vec<Duration>>);

    impl TestClock {
        fn advance(&self, d: Duration) {
            *lock(&self.0) += d;
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> Instant {
            *lock(&self.0)
        }
        fn sleep(&self, d: Duration) {
            lock(&self.1).push(d);
        }
    }

    struct Rig {
        sniffer: Arc<Sniffer>,
        source: Arc<MockSource>,
        sender: Arc<MockSender>,
        clock: Arc<TestClock>,
        hosts: Arc<HostCollector>,
        _dir: tempfile::TempDir,
    }

    /// A sniffer on the LAN feeding an inventory that knows `macs`.
    fn rig(macs: &[[u8; 6]]) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts.json");
        let rows: Vec<serde_json::Value> = macs
            .iter()
            .map(|m| {
                let m = mac_string(*m);
                serde_json::json!({"key": m, "mac": m, "first_seen": 1})
            })
            .collect();
        std::fs::write(
            &path,
            serde_json::json!({"version": 1, "hosts": rows}).to_string(),
        )
        .unwrap();
        let hosts = HostCollector::new(HostStore::new(path), Arc::new(|| (Vec::new(), Vec::new())));
        let source = Arc::new(MockSource::default());
        let sender = Arc::new(MockSender::default());
        let clock = Arc::new(TestClock(Mutex::new(Instant::now()), Mutex::default()));
        let (s, h) = (Arc::clone(&source), Arc::clone(&hosts));
        let sniffer = Sniffer::new(
            Arc::new(move || Ok(Arc::clone(&s) as Arc<dyn PacketSource>)),
            Arc::clone(&sender) as Arc<dyn QuerySender>,
            Arc::clone(&clock) as Arc<dyn Clock>,
            Arc::new(move |mac, ev| {
                h.record_evidence(mac, ev);
            }),
        );
        sniffer.set_interfaces(vec![lan()]);
        Rig {
            sniffer,
            source,
            sender,
            clock,
            hosts,
            _dir: dir,
        }
    }

    impl Rig {
        fn drain(&self) {
            let mut buf = vec![0u8; 2048];
            while !lock(&self.source.frames).is_empty() {
                self.sniffer.step(&mut buf);
            }
        }

        fn evidence(&self, mac: [u8; 6]) -> serde_json::Value {
            let v = self.hosts.view(1000);
            v["hosts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|h| h["key"] == mac_string(mac))
                .map(|h| h["evidence"].clone())
                .unwrap_or_default()
        }
    }

    #[test]
    fn sniffer_records_dhcp_evidence() {
        let r = rig(&[PHONE]);
        // from 0.0.0.0:68 to 255.255.255.255:67; the Ethernet source is a
        // relay's here, the client is chaddr
        let relay = [0x02, 0, 0, 0, 0, 0x99];
        r.source.push(
            ipv4_udp(relay, [255; 4], 68, 67, &dhcp_discover(PHONE)),
            LAN,
        );
        r.drain();
        let e = r.evidence(PHONE);
        assert_eq!(e["dhcp_vendor"], "android-dhcp-14");
        assert_eq!(e["dhcp_prl"], "1,3,6,15,26,28,51,58,59,43");
        assert_eq!(e["dhcp_hostname"], "Pixel-8");
        let label = &r.hosts.view(1000)["hosts"][0]["label"];
        assert_eq!(label["kind"], "phone", "{label}");
        assert_eq!(label["by"], "auto");
    }

    #[test]
    fn sniffer_ignores_wan_and_unknown_ifindex() {
        let r = rig(&[PHONE]);
        let f = ipv4_udp(PHONE, [255; 4], 68, 67, &dhcp_discover(PHONE));
        r.source.push(f.clone(), WAN);
        r.source.push(f, 99);
        // mDNS sent unicast is not an announcement
        let m = mdns_response(&["_ipp._tcp".to_owned()]);
        r.source
            .push(ipv4_udp(PHONE, [192, 168, 1, 1], 5353, 5353, &m), LAN);
        r.drain();
        assert_eq!(r.evidence(PHONE), serde_json::Value::Null);
    }

    #[test]
    fn sniffer_records_mdns_services_capped_at_16() {
        let r = rig(&[PHONE]);
        let a: Vec<String> = (0..10).map(|i| format!("_a{i}._tcp")).collect();
        let b: Vec<String> = (0..10).map(|i| format!("_b{i}._tcp")).collect();
        r.source.push(
            ipv4_udp(PHONE, [224, 0, 0, 251], 5353, 5353, &mdns_response(&a)),
            LAN,
        );
        r.source.push(
            ipv6_udp(
                PHONE,
                [0xff02, 0, 0, 0, 0, 0, 0, 0xfb],
                5353,
                5353,
                &mdns_response(&b),
            ),
            LAN,
        );
        r.drain();
        let services = r.evidence(PHONE)["mdns_services"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(services.len(), 16, "{services:?}");
        assert!(services.contains(&"_a0._tcp".into()));
        assert!(
            services.contains(&"_b0._tcp".into()),
            "the IPv6 packet counted"
        );
    }

    #[test]
    fn querier_sends_one_query_per_interval() {
        let r = rig(&[]);
        let opt = SniffIface {
            id: "opt1".into(),
            device: "igc2".into(),
            index: 4,
        };
        r.sniffer.set_interfaces(vec![lan(), opt]);
        let mut buf = vec![0u8; 2048];
        let sent = |r: &Rig| std::mem::take(&mut *lock(&r.sender.0));
        r.sniffer.step(&mut buf);
        assert_eq!(sent(&r), ["lan", "opt1"], "one per interface at start");
        r.sniffer.step(&mut buf);
        r.clock.advance(Duration::from_secs(899));
        r.sniffer.step(&mut buf);
        assert!(sent(&r).is_empty(), "none before 900 s");
        r.clock.advance(Duration::from_secs(1));
        r.sniffer.step(&mut buf);
        assert_eq!(sent(&r), ["lan", "opt1"]);
        r.sniffer.step(&mut buf);
        assert!(sent(&r).is_empty());
        // no interfaces: nothing sent at all
        r.sniffer.set_interfaces(Vec::new());
        r.clock.advance(QUERY_EVERY);
        r.sniffer.step(&mut buf);
        assert!(sent(&r).is_empty());
        assert!(!r.sniffer.listening());
    }

    #[test]
    fn query_is_the_services_ptr_question() {
        let q = query_packet();
        assert_eq!(&q[..12], &[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        let mut want = name(&["_services", "_dns-sd", "_udp", "local"]);
        want.extend_from_slice(&[0, 12, 0, 1]);
        assert_eq!(&q[12..], &want[..]);
    }

    #[test]
    fn evidence_ignores_what_is_not_a_client_announcement() {
        let d = dhcp_discover(PHONE);
        // the server's reply (to 68) and a non-request type
        assert!(evidence(&ipv4_udp(PHONE, [255; 4], 67, 68, &d)).is_none());
        let mut inform = d.clone();
        inform[242] = 8;
        assert!(evidence(&ipv4_udp(PHONE, [255; 4], 68, 67, &inform)).is_none());
        // a group chaddr
        assert!(
            evidence(&ipv4_udp(
                PHONE,
                [255; 4],
                68,
                67,
                &dhcp_discover([1, 0, 0x5e, 0, 0, 1])
            ))
            .is_none()
        );
        // a fragment
        let mut frag = ipv4_udp(PHONE, [255; 4], 68, 67, &d);
        frag[14 + 6] = 0x20; // MF
        assert!(evidence(&frag).is_none());
        // a truncated frame at every length never panics
        let f = ipv4_udp(PHONE, [255; 4], 68, 67, &d);
        for cut in 0..f.len() {
            let _ = evidence(&f[..cut]);
        }
        assert_eq!(
            evidence(&f).map(|(m, _)| m).as_deref(),
            Some("aa:bb:cc:00:00:01")
        );
    }

    /// A classic BPF interpreter, enough for [`FILTER`]'s instructions.
    fn bpf(prog: &[Insn], pkt: &[u8]) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let byte = |at: u32| pkt.get(at as usize).copied().map(u32::from);
        let half = |at: u32| Some((byte(at)? << 8) | byte(at + 1)?);
        loop {
            let (code, jt, jf, k) = prog[pc];
            pc += 1;
            let jump = |c: bool| usize::from(if c { jt } else { jf });
            match code {
                0x28 => match half(k) {
                    Some(v) => a = v,
                    None => return 0,
                },
                0x30 => match byte(k) {
                    Some(v) => a = v,
                    None => return 0,
                },
                0x48 => match half(x + k) {
                    Some(v) => a = v,
                    None => return 0,
                },
                0xb1 => match byte(k) {
                    Some(v) => x = (v & 0xf) * 4,
                    None => return 0,
                },
                0x15 => pc += jump(a == k),
                0x45 => pc += jump(a & k != 0),
                0x06 => return k,
                other => panic!("opcode {other:#x}"),
            }
        }
    }

    #[test]
    fn kernel_filter_keeps_only_dhcp_and_mdns() {
        let d = dhcp_discover(PHONE);
        let m = mdns_response(&["_ipp._tcp".to_owned()]);
        let keep = [
            ipv4_udp(PHONE, [255; 4], 68, 67, &d),
            ipv4_udp(PHONE, [224, 0, 0, 251], 5353, 5353, &m),
            ipv4_udp(PHONE, [224, 0, 0, 251], 40000, 5353, &m),
            ipv6_udp(PHONE, [0xff02, 0, 0, 0, 0, 0, 0, 0xfb], 5353, 5353, &m),
        ];
        for f in &keep {
            assert_ne!(bpf(&FILTER, f), 0, "{f:02x?}");
            assert!(evidence(f).is_some());
        }
        let mut frag = keep[0].clone();
        frag[14 + 7] = 1; // fragment offset
        let mut tcp = keep[0].clone();
        tcp[14 + 9] = 6;
        let drop = [
            ipv4_udp(PHONE, [8, 8, 8, 8], 50000, 53, b"dns"),
            ipv4_udp(PHONE, [255; 4], 67, 68, &d),
            ipv6_udp(PHONE, [0xff02, 0, 0, 0, 0, 0, 0, 1], 546, 547, b"dhcp6"),
            frag,
            tcp,
            eth(PHONE, [0xff; 6], 0x0806, &[0; 28]),
        ];
        for f in &drop {
            assert_eq!(bpf(&FILTER, f), 0, "{f:02x?}");
        }
    }

    fn opt1() -> SniffIface {
        SniffIface {
            id: "opt1".into(),
            device: "igc2".into(),
            index: 4,
        }
    }

    #[test]
    fn groups_are_joined_once_per_interface_and_left_on_removal() {
        let r = rig(&[]);
        assert_eq!(*lock(&r.source.joins), [LAN]);
        r.sniffer.set_interfaces(vec![lan(), opt1()]);
        r.sniffer.set_interfaces(vec![lan(), opt1()]);
        assert_eq!(*lock(&r.source.joins), [LAN, 4], "once each");
        assert!(lock(&r.source.released).is_empty());
        r.sniffer.set_interfaces(vec![lan()]);
        assert_eq!(*lock(&r.source.released), [4], "opt1 left the set");
        r.sniffer.set_interfaces(Vec::new());
        assert_eq!(*lock(&r.source.released), [4, LAN], "all left when off");
        // back on: joined again
        r.sniffer.set_interfaces(vec![lan()]);
        assert_eq!(*lock(&r.source.joins), [LAN, 4, LAN]);
        r.sniffer.stop();
        assert_eq!(*lock(&r.source.released), [4, LAN, LAN], "and on stop");
    }

    #[test]
    fn a_failing_socket_backs_off_to_one_second() {
        let r = rig(&[]);
        *lock(&r.source.fail) = Some(io::ErrorKind::NetworkDown);
        let mut buf = vec![0u8; 2048];
        for _ in 0..3 {
            r.sniffer.step(&mut buf);
        }
        assert_eq!(*lock(&r.clock.1), [ERROR_WAIT; 3]);
        assert_eq!(
            *lock(&r.sniffer.recv_error),
            Some(io::ErrorKind::NetworkDown)
        );
        // a frame clears it; a timeout is not an error
        *lock(&r.source.fail) = None;
        r.source.push(vec![0; 20], LAN);
        r.sniffer.step(&mut buf);
        r.sniffer.step(&mut buf);
        assert_eq!(*lock(&r.sniffer.recv_error), None);
        assert_eq!(lock(&r.clock.1).len(), 3, "no more sleeps");
    }

    /// `ipv4_udp`'s frame with 4 bytes of IPv4 options (IHL 6).
    fn with_ip_options(mut f: Vec<u8>) -> Vec<u8> {
        f[14] = 0x46;
        let total = u16::from_be_bytes([f[16], f[17]]) + 4;
        f[16..18].copy_from_slice(&total.to_be_bytes());
        f.splice(34..34, [1, 1, 1, 0]); // NOP NOP NOP EOL
        f
    }

    #[test]
    fn ipv4_options_are_skipped() {
        let f = with_ip_options(ipv4_udp(PHONE, [255; 4], 68, 67, &dhcp_discover(PHONE)));
        assert_ne!(bpf(&FILTER, &f), 0, "kernel filter keeps it");
        let (mac, ev) = evidence(&f).expect("parsed past the options");
        assert_eq!(mac, "aa:bb:cc:00:00:01");
        assert_eq!(ev.dhcp_hostname.as_deref(), Some("Pixel-8"));
        let m = mdns_response(&["_ipp._tcp".to_owned()]);
        let f = with_ip_options(ipv4_udp(PHONE, [224, 0, 0, 251], 5353, 5353, &m));
        assert_ne!(bpf(&FILTER, &f), 0);
        assert_eq!(evidence(&f).unwrap().1.mdns_services, ["_ipp._tcp"]);
    }

    /// Two queued taps; `wait` is a blocking wait in the real thing, so
    /// each call is recorded and costs its full timeout on the mock clock.
    /// Frames and their interface index, oldest first.
    type Queue = Mutex<Vec<(Vec<u8>, u32)>>;

    #[derive(Default)]
    struct TwoQueues {
        queues: [Queue; 2],
        waits: Mutex<Vec<Duration>>,
    }

    impl Taps for &TwoQueues {
        fn wait(&self, timeout: Duration) -> io::Result<[bool; 2]> {
            lock(&self.waits).push(timeout);
            Ok([0, 1].map(|i| !lock(&self.queues[i]).is_empty()))
        }

        fn try_recv(&self, i: usize, buf: &mut [u8]) -> io::Result<Option<(usize, u32)>> {
            let mut q = lock(&self.queues[i]);
            if q.is_empty() {
                return Ok(None);
            }
            let (f, index) = q.remove(0);
            buf[..f.len()].copy_from_slice(&f);
            Ok(Some((f.len(), index)))
        }
    }

    #[test]
    fn a_busy_tap_is_not_held_up_by_an_idle_one() {
        let q = TwoQueues::default();
        for n in [1u8, 2] {
            lock(&q.queues[0]).push((vec![n; 4], LAN));
        }
        let p = Polled::new(&q);
        let mut buf = [0u8; 64];
        assert_eq!(p.recv(&mut buf).unwrap(), (4, LAN));
        assert_eq!(buf[0], 1);
        assert_eq!(p.recv(&mut buf).unwrap(), (4, LAN));
        assert_eq!(buf[0], 2);
        assert!(
            lock(&q.waits).is_empty(),
            "never waited while a frame was queued"
        );
        // both empty: one wait over both, then WouldBlock
        let e = p.recv(&mut buf).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(*lock(&q.waits), [POLL_WAIT]);
    }

    #[test]
    fn both_taps_take_turns() {
        let q = TwoQueues::default();
        for n in [1u8, 2, 3] {
            lock(&q.queues[0]).push((vec![n], LAN));
            lock(&q.queues[1]).push((vec![10 + n], LAN));
        }
        let p = Polled::new(&q);
        let mut buf = [0u8; 8];
        let got: Vec<u8> = (0..6)
            .map(|_| {
                p.recv(&mut buf).unwrap();
                buf[0]
            })
            .collect();
        assert_eq!(got, [1, 11, 2, 12, 3, 13]);
        assert!(lock(&q.waits).is_empty());
    }
}
