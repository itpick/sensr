//! ICMP / ICMPv6 echo prober on top of `socket2` and tokio.
//!
//! A raw socket is tried first (the agent runs with `CAP_NET_RAW`); when
//! that is not permitted the prober falls back to an unprivileged ping
//! socket (`SOCK_DGRAM` + `IPPROTO_ICMP[V6]`, Linux `ping_group_range`,
//! always available on macOS). Each prober connects its socket to the
//! target, so the kernel only hands it replies from that address.

use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicU16, Ordering};

use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use crate::packet::{self, ECHO_HEADER_LEN};
use crate::{Family, ProbeSpec, Prober, ProberFactory, Reply};

/// Room for the largest IPv4 header in front of the echo.
const MAX_IP_HEADER: usize = 60;

/// Which kind of socket a prober ended up with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SocketKind {
    /// `SOCK_RAW`: needs `CAP_NET_RAW` (root on macOS).
    Raw,
    /// `SOCK_DGRAM` ping socket: unprivileged where the OS allows it.
    Datagram,
}

/// Opens [`IcmpProber`]s.
#[derive(Debug, Clone, Copy, Default)]
pub struct IcmpFactory;

impl IcmpFactory {
    /// An echo identifier not used by another prober of this process. It
    /// starts from the process id so concurrent processes (another sensr
    /// instance, a stray ping) are unlikely to collide on raw sockets.
    pub fn next_ident() -> u16 {
        static NEXT: AtomicU16 = AtomicU16::new(0);
        (std::process::id() as u16).wrapping_add(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

impl ProberFactory for IcmpFactory {
    type Prober = IcmpProber;

    fn open(&self, spec: &ProbeSpec) -> io::Result<IcmpProber> {
        IcmpProber::open(spec)
    }
}

/// One ICMP or ICMPv6 echo socket for one target.
#[derive(Debug)]
pub struct IcmpProber {
    sock: UdpSocket,
    family: Family,
    kind: SocketKind,
    ident: u16,
    payload: Vec<u8>,
}

impl IcmpProber {
    /// Opens a raw socket, or a ping socket if raw ones are not permitted.
    /// Must be called within a tokio runtime.
    pub fn open(spec: &ProbeSpec) -> io::Result<Self> {
        let (sock, kind) = match open_socket(spec, Type::RAW) {
            Ok(s) => (s, SocketKind::Raw),
            Err(raw) if raw.kind() == io::ErrorKind::PermissionDenied => {
                match open_socket(spec, Type::DGRAM) {
                    Ok(s) => (s, SocketKind::Datagram),
                    Err(dgram) => {
                        return Err(io::Error::new(
                            dgram.kind(),
                            format!("raw ICMP socket: {raw}; ping socket: {dgram}"),
                        ));
                    }
                }
            }
            Err(e) => return Err(e),
        };
        // A recognisable payload; content is irrelevant to the statistics.
        let payload = (0..spec.data_length).map(|i| (i % 251) as u8).collect();
        Ok(Self {
            sock: UdpSocket::from_std(std::net::UdpSocket::from(sock))?,
            family: Family::of(spec.target),
            kind,
            ident: spec.ident,
            payload,
        })
    }

    /// The socket kind in use.
    pub fn kind(&self) -> SocketKind {
        self.kind
    }

    /// Linux ping sockets replace the identifier with the socket's own and
    /// demultiplex replies themselves; everywhere else we filter.
    fn checks_ident(&self) -> bool {
        !(cfg!(any(target_os = "linux", target_os = "android"))
            && self.kind == SocketKind::Datagram)
    }
}

fn open_socket(spec: &ProbeSpec, ty: Type) -> io::Result<Socket> {
    let (domain, proto) = match spec.target {
        IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4),
        IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6),
    };
    let sock = Socket::new(domain, ty, Some(proto))?;
    sock.set_nonblocking(true)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Some(dev) = &spec.device {
        sock.bind_device(Some(dev.as_bytes()))?;
    }
    let scope = spec
        .scope_id
        .or_else(|| device_index(spec.device.as_deref()));
    if let Some(src) = spec.source {
        sock.bind(&with_scope(src, scope).into())?;
    }
    sock.connect(&with_scope(spec.target, scope).into())?;
    Ok(sock)
}

/// Socket address with port 0 and, for IPv6 link-local addresses, the
/// interface scope.
fn with_scope(addr: IpAddr, scope: Option<u32>) -> SocketAddr {
    match addr {
        IpAddr::V6(v6) if v6.is_unicast_link_local() => {
            SocketAddr::V6(SocketAddrV6::new(v6, 0, 0, scope.unwrap_or(0)))
        }
        other => SocketAddr::new(other, 0),
    }
}

#[cfg(target_os = "linux")]
fn device_index(device: Option<&str>) -> Option<u32> {
    let dev = device?;
    // An interface name never contains a path separator; refuse anything
    // that could escape /sys/class/net.
    if dev.is_empty() || dev.contains('/') || dev == "." || dev == ".." {
        return None;
    }
    std::fs::read_to_string(format!("/sys/class/net/{dev}/ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(not(target_os = "linux"))]
fn device_index(_device: Option<&str>) -> Option<u32> {
    None
}

impl Prober for IcmpProber {
    async fn send(&self, seq: u16) -> io::Result<()> {
        let pkt = packet::echo_request(self.family, self.ident, seq, &self.payload);
        self.sock.send(&pkt).await.map(|_| ())
    }

    async fn recv(&self) -> io::Result<Reply> {
        let mut buf = vec![0u8; MAX_IP_HEADER + ECHO_HEADER_LEN + self.payload.len() + 64];
        loop {
            let n = self.sock.recv(&mut buf).await?;
            let received = tokio::time::Instant::now();
            let data = buf.get(..n).unwrap_or(&[]);
            let Some(reply) = packet::parse_echo_reply(self.family, data, n == buf.len()) else {
                continue;
            };
            if self.checks_ident() && reply.ident != self.ident {
                continue;
            }
            return Ok(Reply {
                seq: reply.seq,
                received,
            });
        }
    }
}
