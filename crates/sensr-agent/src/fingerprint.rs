//! Passive evidence for smart host labels
//! (docs/superpowers/specs/2026-11-23-host-labels-design.md).
//!
//! - [`Sniffer`]: the `sensr-fp` thread. It reads DHCP requests and mDNS
//!   announcements off the internal interfaces through a read-only
//!   [`PacketSource`] (`AF_PACKET`, `ETH_P_ALL` on Linux) and hands what
//!   they say to the inventory, keyed by the sender's MAC.
//! - [`evidence`]: Ethernet → IPv4/IPv6 → UDP → DHCP/mDNS, pure.
//! - [`Querier`]: the one packet the router sends, a DNS-SD
//!   `_services._dns-sd._udp.local` PTR query per internal interface at
//!   start and every [`QUERY_EVERY`], over an ordinary UDP socket
//!   ([`QuerySender`]). Never on the packet socket, which has no send.
//!
//! The caller builds the interface list only from `internal_interfaces(doc)`
//! ([`interfaces`]); frames from any other interface index are dropped.

use std::collections::{BTreeMap, BTreeSet};
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
/// `ETH_P_ALL`.
pub const ETH_P_ALL: u16 = 0x0003;
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

/// A raw, receive-only link-layer socket.
pub trait PacketSource: Send + Sync {
    /// Has interface `index` deliver the mDNS multicast MACs to this
    /// socket, as a link-layer filter entry: nothing goes on the wire.
    fn join(&self, _index: u32) -> io::Result<()> {
        Ok(())
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

#[cfg(target_os = "linux")]
mod sys {
    use std::io;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    use nix::libc;
    use nix::sys::socket::{LinkAddr, recvfrom, setsockopt};
    use nix::{setsockopt_impl, sockopt_impl};

    use super::{ETH_P_ALL, FILTER, MDNS_PORT, PacketSource, QuerySender, SniffIface};

    sockopt_impl!(
        /// `PACKET_ADD_MEMBERSHIP`: a link-layer multicast address for one
        /// interface, held while the socket is open.
        AddMembership,
        SetOnly,
        libc::SOL_PACKET,
        libc::PACKET_ADD_MEMBERSHIP,
        libc::packet_mreq
    );

    /// How long `recv` blocks before the loop takes a turn.
    const RECV_WAIT: Duration = Duration::from_millis(250);
    /// `sll_pkttype` of a frame this host sent.
    const PACKET_OUTGOING: u8 = 4;
    /// 224.0.0.251 and ff02::fb at the link layer.
    const MDNS_MACS: [[u8; 6]; 2] = [
        [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb],
        [0x33, 0x33, 0x00, 0x00, 0x00, 0xfb],
    ];

    /// One `AF_PACKET`/`SOCK_RAW` socket for `ETH_P_ALL` on every interface,
    /// with [`FILTER`] attached. Nothing is ever sent on it.
    pub struct AfPacketSource {
        sock: socket2::Socket,
    }

    impl AfPacketSource {
        /// Needs `CAP_NET_RAW`.
        pub fn open() -> io::Result<Self> {
            let sock = socket2::Socket::new(
                socket2::Domain::PACKET,
                socket2::Type::RAW,
                Some(socket2::Protocol::from(i32::from(ETH_P_ALL.to_be()))),
            )?;
            let prog: Vec<socket2::SockFilter> = FILTER
                .iter()
                .map(|&(code, jt, jf, k)| socket2::SockFilter::new(code, jt, jf, k))
                .collect();
            sock.attach_filter(&prog)?;
            sock.set_read_timeout(Some(RECV_WAIT))?;
            Ok(Self { sock })
        }
    }

    impl PacketSource for AfPacketSource {
        fn join(&self, index: u32) -> io::Result<()> {
            let ifindex = i32::try_from(index).map_err(io::Error::other)?;
            for mac in MDNS_MACS {
                let mut mr_address = [0u8; 8];
                mr_address[..6].copy_from_slice(&mac);
                let m = libc::packet_mreq {
                    mr_ifindex: ifindex,
                    mr_type: libc::PACKET_MR_MULTICAST as u16,
                    mr_alen: 6,
                    mr_address,
                };
                setsockopt(&self.sock, AddMembership, &m)?;
            }
            Ok(())
        }

        fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, u32)> {
            loop {
                let (n, from) = recvfrom::<LinkAddr>(self.sock.as_raw_fd(), buf)?;
                let Some(from) = from else { continue };
                if from.pkttype() == PACKET_OUTGOING {
                    continue;
                }
                return Ok((n, u32::try_from(from.ifindex()).unwrap_or(0)));
            }
        }
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
    fn udp(bind: SocketAddr) -> io::Result<socket2::Socket> {
        let domain = socket2::Domain::for_address(bind);
        let s = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        s.set_reuse_address(true)?;
        s.set_reuse_port(true)?;
        if s.bind(&bind.into()).is_err() {
            let mut any = bind;
            any.set_port(0);
            s.bind(&any.into())?;
        }
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
                let r = (|| {
                    let s = udp(SocketAddrV4::new(a, MDNS_PORT).into())?;
                    s.set_multicast_if_v4(&a)?;
                    s.set_multicast_ttl_v4(255)?;
                    s.set_multicast_loop_v4(false)?;
                    let to = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), MDNS_PORT);
                    s.send_to(&q, &SocketAddr::from(to).into()).map(drop)
                })();
                if let Err(e) = r {
                    first_err.get_or_insert(e);
                }
            }
            if let Some(a) = v6 {
                let r = (|| {
                    let s = udp(SocketAddrV6::new(a, MDNS_PORT, 0, iface.index).into())?;
                    s.set_only_v6(true)?;
                    s.set_multicast_if_v6(iface.index)?;
                    s.set_multicast_hops_v6(255)?;
                    s.set_multicast_loop_v6(false)?;
                    let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
                    let to = SocketAddrV6::new(group, MDNS_PORT, 0, iface.index);
                    s.send_to(&q, &SocketAddr::from(to).into()).map(drop)
                })();
                if let Err(e) = r {
                    first_err.get_or_insert(e);
                }
            }
            first_err.map_or(Ok(()), Err)
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
    /// Interface indexes the socket has the mDNS MACs for.
    joined: BTreeSet<u32>,
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
        if let Some(sock) = st.socket.clone() {
            for i in &ifaces {
                if st.joined.contains(&i.index) {
                    continue;
                }
                match sock.join(i.index) {
                    Ok(()) => {
                        st.joined.insert(i.index);
                    }
                    Err(e) => {
                        tracing::debug!(device = %i.device, error = %e, "mDNS link membership");
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
                Ok((n, index)) => self.on_frame(buf.get(..n).unwrap_or_default(), index),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "host fingerprint receive");
                    self.clock.sleep(IDLE_WAIT);
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

    fn dhcp_discover(chaddr: [u8; 6]) -> Vec<u8> {
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

    #[derive(Default)]
    struct MockSource(Mutex<Vec<(Vec<u8>, u32)>>);

    impl MockSource {
        fn push(&self, frame: Vec<u8>, index: u32) {
            lock(&self.0).push((frame, index));
        }
    }

    impl PacketSource for MockSource {
        fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, u32)> {
            let mut q = lock(&self.0);
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

    struct TestClock(Mutex<Instant>);

    impl TestClock {
        fn advance(&self, d: Duration) {
            *lock(&self.0) += d;
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> Instant {
            *lock(&self.0)
        }
        fn sleep(&self, _: Duration) {}
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
        let clock = Arc::new(TestClock(Mutex::new(Instant::now())));
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
            while !lock(&self.source.0).is_empty() {
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
}
