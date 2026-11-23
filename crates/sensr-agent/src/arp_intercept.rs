//! ARP interception: same-LAN enforcement of host modes
//! (docs/superpowers/specs/2026-11-22-host-modes-design.md, "ARP interceptor").
//!
//! The nft rules only see traffic that reaches the router. On a flat LAN a
//! locked host T talks to a neighbour X directly, so the router tells T that
//! every X is at the router's MAC and tells each X that T is too; that
//! traffic then crosses the router, where the host-mode rules drop it.
//!
//! - [`plan`] / [`heal_plan`] / [`answer`]: pure decisions.
//! - [`ArpFrame`], [`build_reply`], [`build_request`]: the 42-byte frames.
//! - [`PacketSocket`]: the raw socket, `AF_PACKET` on Linux ([`AfPacketSocket`]).
//! - [`Interceptor`]: the task: seeds every 2 s, answers requests (and again
//!   50 ms later), heals three times 1 s apart whenever a pair stops being
//!   poisoned and on shutdown.
//!
//! Frames only ever go out on the interface index of an [`IfaceView`] the
//! caller passed in its latest [`Interceptor::set_inputs`], and the caller
//! builds those only from `internal_interfaces(doc)` ([`inputs`]).

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sensr_feeds::neigh::NeighEntry;
use sensr_rules::document::InternalIf;
use sensr_rules::ir::IfAddr;
use sensr_schema::fields::MacAddr;
use serde::Serialize;

/// How often every planned pair is seeded with a unicast request.
pub const SEED_EVERY: Duration = Duration::from_secs(2);
/// An answer is sent at once and again this much later, so the last answer
/// the requester hears is the router's.
pub const ANSWER_REPEAT: Duration = Duration::from_millis(50);
/// Heal rounds, [`HEAL_GAP`] apart.
pub const HEAL_ROUNDS: u32 = 3;
/// Time between heal rounds.
pub const HEAL_GAP: Duration = Duration::from_secs(1);
/// The receive loop's wait when there is no socket.
const IDLE_WAIT: Duration = Duration::from_millis(100);
/// Ethertype of ARP.
pub const ETH_P_ARP: u16 = 0x0806;
/// Ethernet header plus an IPv4-over-Ethernet ARP body.
pub const FRAME_LEN: usize = 42;
const OP_REQUEST: u16 = 1;
const OP_REPLY: u16 = 2;
/// Kernel neighbour states that count as live.
const LIVE_STATES: [&str; 4] = ["REACHABLE", "DELAY", "PROBE", "STALE"];

/// An IPv4 neighbour on an internal interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbour {
    pub ip: Ipv4Addr,
    pub mac: [u8; 6],
    /// Kernel state REACHABLE/DELAY/PROBE/STALE, or seen by the inventory
    /// within [`crate::hosts::ONLINE_SECS`]. Only live neighbours are poisoned.
    pub live: bool,
}

/// One internal interface as the interceptor needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfaceView {
    /// Interface id (`lan`, `opt1`).
    pub id: String,
    /// Kernel device.
    pub device: String,
    /// Kernel interface index; frames go out only on these.
    pub index: u32,
    pub router_ip: Ipv4Addr,
    pub router_mac: [u8; 6],
    pub neighbours: Vec<Neighbour>,
}

/// A locked (Isolated or Quarantine) host's current IPv4 address.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Locked {
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    /// Interface id.
    pub iface: String,
}

/// "Tell `target` that `claim_ip` is at `claim_mac`", on `iface`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PoisonMsg {
    pub iface: String,
    pub target_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub claim_ip: Ipv4Addr,
    pub claim_mac: [u8; 6],
}

/// Identifies a pair independently of the MAC claimed: what a heal undoes.
type Pair = (String, Ipv4Addr, Ipv4Addr);

fn pair(m: &PoisonMsg) -> Pair {
    (m.iface.clone(), m.target_ip, m.claim_ip)
}

/// The fields of an IPv4-over-Ethernet ARP frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArpFrame {
    pub op: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

/// Every (locked T, live neighbour X) pair on T's interface.
fn pairs<'a>(
    ifaces: &'a [IfaceView],
    locked: &'a [Locked],
) -> impl Iterator<Item = (&'a IfaceView, &'a Locked, &'a Neighbour)> {
    locked.iter().flat_map(move |t| {
        ifaces
            .iter()
            .filter(move |i| i.id == t.iface && t.ip != i.router_ip && t.mac != i.router_mac)
            .flat_map(move |i| {
                i.neighbours
                    .iter()
                    .filter(move |x| {
                        x.live
                            && x.ip != i.router_ip
                            && x.mac != i.router_mac
                            && x.ip != t.ip
                            && !x.ip.is_unspecified()
                    })
                    .map(move |x| (i, t, x))
            })
    })
}

fn sorted(v: impl Iterator<Item = PoisonMsg>) -> Vec<PoisonMsg> {
    v.collect::<BTreeSet<_>>().into_iter().collect()
}

/// The poison to keep in force: for each locked host T and each other live
/// neighbour X on T's interface, tell T that X is at the router and X that
/// T is. Never targets or claims the router; a [`Locked`] on an interface
/// missing from `ifaces` yields nothing.
pub fn plan(ifaces: &[IfaceView], locked: &[Locked]) -> Vec<PoisonMsg> {
    sorted(pairs(ifaces, locked).flat_map(|(i, t, x)| {
        [
            PoisonMsg {
                iface: i.id.clone(),
                target_ip: t.ip,
                target_mac: t.mac,
                claim_ip: x.ip,
                claim_mac: i.router_mac,
            },
            PoisonMsg {
                iface: i.id.clone(),
                target_ip: x.ip,
                target_mac: x.mac,
                claim_ip: t.ip,
                claim_mac: i.router_mac,
            },
        ]
    }))
}

/// [`plan`]'s pairs with the true owners' MACs: what undoes it.
pub fn heal_plan(ifaces: &[IfaceView], locked: &[Locked]) -> Vec<PoisonMsg> {
    sorted(pairs(ifaces, locked).flat_map(|(i, t, x)| {
        [
            PoisonMsg {
                iface: i.id.clone(),
                target_ip: t.ip,
                target_mac: t.mac,
                claim_ip: x.ip,
                claim_mac: x.mac,
            },
            PoisonMsg {
                iface: i.id.clone(),
                target_ip: x.ip,
                target_mac: x.mac,
                claim_ip: t.ip,
                claim_mac: t.mac,
            },
        ]
    }))
}

/// The reply to an observed request seen on `iface`: a request from a
/// locked host for any other address, or from anyone for a locked host's
/// address, is answered with the router's MAC. Requests from the router
/// itself (including our own seeds), address probes (sender 0.0.0.0),
/// announcements and requests for the router's address are left alone.
pub fn answer(req: &ArpFrame, iface: &IfaceView, locked: &[Locked]) -> Option<PoisonMsg> {
    if req.op != OP_REQUEST
        || req.sender_ip.is_unspecified()
        || req.sender_ip == iface.router_ip
        || req.sender_mac == iface.router_mac
        || req.target_ip == iface.router_ip
        || req.target_ip == req.sender_ip
        || req.target_ip.is_unspecified()
    {
        return None;
    }
    let mut here = locked.iter().filter(|l| l.iface == iface.id);
    let from_locked = here.clone().any(|l| l.mac == req.sender_mac);
    let for_locked = here.any(|l| l.ip == req.target_ip);
    (from_locked || for_locked).then(|| PoisonMsg {
        iface: iface.id.clone(),
        target_ip: req.sender_ip,
        target_mac: req.sender_mac,
        claim_ip: req.target_ip,
        claim_mac: iface.router_mac,
    })
}

fn mac_at(b: &[u8], at: usize) -> [u8; 6] {
    let mut m = [0; 6];
    m.copy_from_slice(&b[at..at + 6]);
    m
}

fn ip_at(b: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(b[at], b[at + 1], b[at + 2], b[at + 3])
}

impl ArpFrame {
    /// An Ethernet II IPv4 ARP frame (trailing padding ignored).
    pub fn parse(frame: &[u8]) -> Option<ArpFrame> {
        if frame.len() < FRAME_LEN || frame[12..14] != ETH_P_ARP.to_be_bytes() {
            return None;
        }
        // htype Ethernet, ptype IPv4, hlen 6, plen 4
        if frame[14..20] != [0, 1, 8, 0, 6, 4] {
            return None;
        }
        Some(ArpFrame {
            op: u16::from_be_bytes([frame[20], frame[21]]),
            sender_mac: mac_at(frame, 22),
            sender_ip: ip_at(frame, 28),
            target_mac: mac_at(frame, 32),
            target_ip: ip_at(frame, 38),
        })
    }
}

/// `m` as a reply from `router_mac`: Ethernet dst `target_mac`, src
/// `router_mac`; ARP sender (`claim_mac`, `claim_ip`), target
/// (`target_mac`, `target_ip`). The Ethernet source is always the router,
/// even in a heal (which claims the owner's MAC), so switches never learn
/// another host's MAC on the router's port.
pub fn build_reply(m: &PoisonMsg, router_mac: [u8; 6]) -> Vec<u8> {
    build(m, router_mac, OP_REPLY)
}

/// `m` as a unicast request (same layout as [`build_reply`], op 1).
pub fn build_request(m: &PoisonMsg, router_mac: [u8; 6]) -> Vec<u8> {
    build(m, router_mac, OP_REQUEST)
}

fn build(m: &PoisonMsg, router_mac: [u8; 6], op: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(FRAME_LEN);
    f.extend_from_slice(&m.target_mac);
    f.extend_from_slice(&router_mac);
    f.extend_from_slice(&ETH_P_ARP.to_be_bytes());
    f.extend_from_slice(&1u16.to_be_bytes());
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    f.extend_from_slice(&[6, 4]);
    f.extend_from_slice(&op.to_be_bytes());
    f.extend_from_slice(&m.claim_mac);
    f.extend_from_slice(&m.claim_ip.octets());
    f.extend_from_slice(&m.target_mac);
    f.extend_from_slice(&m.target_ip.octets());
    f
}

/// Kernel index and MAC of a device ([`link`] on the host).
pub type LinkLookup = dyn Fn(&str) -> Option<(u32, [u8; 6])> + Send + Sync;

/// What [`inputs`] are built from, per refresh.
pub struct Sources<'a> {
    /// `internal_interfaces(doc)`: the only interfaces acted on.
    pub internal: &'a [InternalIf],
    /// Current link addresses by interface id (the router's own address).
    pub addrs: &'a BTreeMap<String, Vec<IfAddr>>,
    /// Kernel index and MAC of a device.
    pub link: &'a LinkLookup,
    /// The kernel neighbour table.
    pub neigh: &'a [NeighEntry],
    /// Inventory hosts seen within `ONLINE_SECS`: (MAC, IPv4, interface id).
    pub online: &'a [(String, Ipv4Addr, String)],
    /// MACs in an enabled Isolated/Quarantine entry.
    pub locked_macs: &'a [MacAddr],
    /// Neighbour table and active leases, `(mac, address)`: the locked hosts'
    /// addresses (the table `with_locked` reads).
    pub table: &'a [(String, IpAddr)],
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    s.parse::<MacAddr>().ok().map(|m| m.octets())
}

/// The interceptor's inputs: one view per internal interface whose index,
/// MAC and IPv4 address are known, and the locked hosts' IPv4s on them.
/// Inventory rows not seen within `ONLINE_SECS` are not neighbours at all.
pub fn inputs(s: &Sources<'_>) -> (Vec<IfaceView>, Vec<Locked>) {
    let mut views = Vec::new();
    let mut nets: Vec<(String, Vec<ipnet::Ipv4Net>)> = Vec::new();
    for i in s.internal {
        let v4: Vec<(Ipv4Addr, ipnet::Ipv4Net)> = s
            .addrs
            .get(&i.id)
            .into_iter()
            .flatten()
            .filter_map(|a| match (a.addr, a.network()) {
                (IpAddr::V4(ip), Some(ipnet::IpNet::V4(net))) => Some((ip, net)),
                _ => None,
            })
            .collect();
        let Some(&(router_ip, _)) = v4.first() else {
            continue;
        };
        let Some((index, router_mac)) = (s.link)(&i.device) else {
            continue;
        };
        let subnets: Vec<ipnet::Ipv4Net> = v4
            .iter()
            .map(|(_, n)| *n)
            .chain(i.subnets.iter().copied())
            .collect();
        let on_link = |ip: &Ipv4Addr| subnets.iter().any(|n| n.contains(ip));
        let mut neighbours: BTreeMap<Ipv4Addr, Neighbour> = BTreeMap::new();
        for e in s.neigh.iter().filter(|e| e.dev == i.device) {
            let (IpAddr::V4(ip), Some(mac)) = (e.ip, parse_mac(&e.mac)) else {
                continue;
            };
            if !on_link(&ip) || mac == router_mac || v4.iter().any(|(r, _)| *r == ip) {
                continue;
            }
            let live = e.state.iter().any(|st| LIVE_STATES.contains(&st.as_str()));
            neighbours.entry(ip).or_insert(Neighbour { ip, mac, live });
        }
        for (mac, ip, iface) in s.online {
            let Some(mac) = parse_mac(mac) else { continue };
            if *iface != i.id || !on_link(ip) || mac == router_mac {
                continue;
            }
            if v4.iter().any(|(r, _)| r == ip) {
                continue;
            }
            // the kernel's MAC wins; the inventory only adds liveness
            let n = neighbours.entry(*ip).or_insert(Neighbour {
                ip: *ip,
                mac,
                live: true,
            });
            if n.mac == mac {
                n.live = true;
            }
        }
        nets.push((i.id.clone(), subnets.clone()));
        views.push(IfaceView {
            id: i.id.clone(),
            device: i.device.clone(),
            index,
            router_ip,
            router_mac,
            neighbours: neighbours.into_values().collect(),
        });
    }
    let macs: BTreeSet<[u8; 6]> = s.locked_macs.iter().map(MacAddr::octets).collect();
    let locked: BTreeSet<Locked> = s
        .table
        .iter()
        .filter_map(|(mac, ip)| {
            let mac = parse_mac(mac).filter(|m| macs.contains(m))?;
            let IpAddr::V4(ip) = *ip else { return None };
            let (iface, _) = nets
                .iter()
                .find(|(_, subnets)| subnets.iter().any(|n| n.contains(&ip)))?;
            Some(Locked {
                mac,
                ip,
                iface: iface.clone(),
            })
        })
        .collect();
    (views, locked.into_iter().collect())
}

/// A raw link-layer socket for ARP frames.
pub trait PacketSocket: Send + Sync {
    /// Sends a whole Ethernet frame out of interface `iface_index`.
    fn send(&self, iface_index: u32, frame: &[u8]) -> io::Result<()>;
    /// The next incoming ARP frame and the index of the interface it came
    /// in on; `WouldBlock`/`TimedOut` after a short wait with none.
    fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, u32)>;
}

#[cfg(target_os = "linux")]
mod sys {
    use std::collections::BTreeMap;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::sync::Mutex;
    use std::time::Duration;

    use nix::sys::socket::{LinkAddr, MsgFlags, recvfrom, sendto};

    use super::{ETH_P_ARP, PacketSocket, lock};

    /// How long `recv` blocks before giving the loop a turn; bounds the
    /// lateness of the 50 ms repeat.
    const RECV_WAIT: Duration = Duration::from_millis(20);
    /// `sll_pkttype` of a frame this host sent.
    const PACKET_OUTGOING: u8 = 4;

    /// The kernel's link address (index, MAC) of each interface, from
    /// `getifaddrs` (so no `sockaddr_ll` is built by hand).
    fn link_addrs() -> io::Result<Vec<(String, LinkAddr)>> {
        Ok(nix::ifaddrs::getifaddrs()?
            .filter_map(|a| {
                let l = *a.address?.as_link_addr()?;
                Some((a.interface_name, l))
            })
            .collect())
    }

    /// Index and MAC of `device`.
    pub fn link(device: &str) -> Option<(u32, [u8; 6])> {
        let (_, l) = link_addrs().ok()?.into_iter().find(|(n, _)| n == device)?;
        Some((u32::try_from(l.ifindex()).ok()?, l.addr()?))
    }

    /// One `AF_PACKET`/`SOCK_RAW` socket for `ETH_P_ARP` on every interface.
    pub struct AfPacketSocket {
        sock: socket2::Socket,
        links: Mutex<BTreeMap<u32, LinkAddr>>,
    }

    impl AfPacketSocket {
        /// Needs `CAP_NET_RAW`.
        pub fn open() -> io::Result<Self> {
            let sock = socket2::Socket::new(
                socket2::Domain::PACKET,
                socket2::Type::RAW,
                Some(socket2::Protocol::from(i32::from(ETH_P_ARP.to_be()))),
            )?;
            sock.set_read_timeout(Some(RECV_WAIT))?;
            Ok(Self {
                sock,
                links: Mutex::new(BTreeMap::new()),
            })
        }

        fn link_addr(&self, index: u32) -> io::Result<LinkAddr> {
            if let Some(a) = lock(&self.links).get(&index) {
                return Ok(*a);
            }
            let fresh: BTreeMap<u32, LinkAddr> = link_addrs()?
                .into_iter()
                .filter_map(|(_, l)| Some((u32::try_from(l.ifindex()).ok()?, l)))
                .collect();
            let found = fresh.get(&index).copied();
            *lock(&self.links) = fresh;
            found.ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("no interface {index}"))
            })
        }
    }

    impl PacketSocket for AfPacketSocket {
        fn send(&self, iface_index: u32, frame: &[u8]) -> io::Result<()> {
            let to = self.link_addr(iface_index)?;
            // SOCK_RAW: the frame carries its own Ethernet header; only the
            // address's interface index is used
            sendto(self.sock.as_raw_fd(), frame, &to, MsgFlags::empty())?;
            Ok(())
        }

        fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, u32)> {
            loop {
                let (n, from) = recvfrom::<LinkAddr>(self.sock.as_raw_fd(), buf)?;
                let Some(from) = from else { continue };
                // our own frames come back on the same socket
                if from.pkttype() == PACKET_OUTGOING {
                    continue;
                }
                let index = u32::try_from(from.ifindex()).unwrap_or(0);
                return Ok((n, index));
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod sys {
    use std::io;

    use super::PacketSocket;

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "ARP interception needs Linux (AF_PACKET)",
        )
    }

    /// Index and MAC of `device` (none off Linux).
    pub fn link(_device: &str) -> Option<(u32, [u8; 6])> {
        None
    }

    /// Off Linux: never opens.
    pub struct AfPacketSocket;

    impl AfPacketSocket {
        pub fn open() -> io::Result<Self> {
            Err(unsupported())
        }
    }

    impl PacketSocket for AfPacketSocket {
        fn send(&self, _: u32, _: &[u8]) -> io::Result<()> {
            Err(unsupported())
        }
        fn recv(&self, _: &mut [u8]) -> io::Result<(usize, u32)> {
            Err(unsupported())
        }
    }
}

pub use sys::{AfPacketSocket, link};

/// Opens the raw socket (when interception becomes active).
pub type OpenFn = Arc<dyn Fn() -> io::Result<Arc<dyn PacketSocket>> + Send + Sync>;

/// Time, injectable for tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
    fn sleep(&self, d: Duration);
}

/// The real clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// What the Hosts view shows as `intercept`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct InterceptStatus {
    /// Poisoning now: the socket is open and a locked host has an address.
    pub active: bool,
    /// Interface ids with a locked host, while active.
    pub interfaces: Vec<String>,
    /// Why the raw socket could not be opened.
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Request,
    Reply,
    /// A reply that undoes a pair; dropped if the pair is poisoned again.
    Heal,
}

struct Queued {
    due: Instant,
    msg: PoisonMsg,
    kind: Kind,
}

#[derive(Default)]
struct State {
    /// The internal interfaces; nothing is ever sent elsewhere.
    ifaces: Vec<IfaceView>,
    locked: Vec<Locked>,
    /// `plan(ifaces, locked)`: what is poisoned now.
    plan: Vec<PoisonMsg>,
    socket: Option<Arc<dyn PacketSocket>>,
    error: Option<String>,
    /// Last send failure, logged once per distinct message.
    send_error: Option<String>,
    next_seed: Option<Instant>,
    queue: Vec<Queued>,
}

/// Each message as (interface index, frame); messages for an interface not
/// in `ifaces` are dropped here, the only place frames are built for sending.
fn frames(ifaces: &[IfaceView], msgs: Vec<(PoisonMsg, Kind)>) -> Vec<(u32, Vec<u8>)> {
    msgs.into_iter()
        .filter_map(|(m, kind)| {
            let v = ifaces.iter().find(|v| v.id == m.iface)?;
            let f = match kind {
                Kind::Request => build_request(&m, v.router_mac),
                Kind::Reply | Kind::Heal => build_reply(&m, v.router_mac),
            };
            Some((v.index, f))
        })
        .collect()
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The ARP interception task.
pub struct Interceptor {
    open: OpenFn,
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
    stopped: AtomicBool,
    started: AtomicBool,
}

impl Interceptor {
    /// Idle until [`Self::set_inputs`] gives it a locked host.
    pub fn new(open: OpenFn, clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new(Self {
            open,
            clock,
            state: Mutex::new(State::default()),
            stopped: AtomicBool::new(false),
            started: AtomicBool::new(false),
        })
    }

    /// On the host: `AF_PACKET` and the real clock.
    pub fn system() -> Arc<Self> {
        Self::new(
            Arc::new(|| AfPacketSocket::open().map(|s| Arc::new(s) as Arc<dyn PacketSocket>)),
            Arc::new(SystemClock),
        )
    }

    /// New inputs. `ifaces` are always the internal interfaces (heals go out
    /// only on these); `locked` is empty while interception is off
    /// (`arp_intercept` false or no host locked). Pairs that drop out of the
    /// plan are healed; new ones are seeded at once.
    pub fn set_inputs(&self, ifaces: Vec<IfaceView>, locked: Vec<Locked>) {
        let now = self.clock.now();
        let next = plan(&ifaces, &locked);
        let mut st = lock(&self.state);
        // under the lock: a call racing stop_and_heal either lands before
        // its heal (and is healed) or is dropped here
        if self.stopped.load(Ordering::SeqCst) {
            return;
        }
        let keep: BTreeSet<Pair> = next.iter().map(pair).collect();
        let had: BTreeSet<Pair> = st.plan.iter().map(pair).collect();
        let heals: Vec<PoisonMsg> = heal_plan(&st.ifaces, &st.locked)
            .into_iter()
            .filter(|h| !keep.contains(&pair(h)))
            .collect();
        let healed: BTreeSet<Pair> = heals.iter().map(pair).collect();
        let off = locked.is_empty();
        st.queue.retain(|q| match q.kind {
            // poisoned again before its heal went out: the heal must not
            Kind::Heal => !keep.contains(&pair(&q.msg)),
            // a pending answer repeat must not undo a heal
            Kind::Reply | Kind::Request => !off && !healed.contains(&pair(&q.msg)),
        });
        for r in 0..HEAL_ROUNDS {
            for h in &heals {
                st.queue.push(Queued {
                    due: now + HEAL_GAP * r,
                    msg: h.clone(),
                    kind: Kind::Heal,
                });
            }
        }
        for m in next.iter().filter(|m| !had.contains(&pair(m))) {
            st.queue.push(Queued {
                due: now,
                msg: m.clone(),
                kind: Kind::Request,
            });
        }
        if off {
            st.next_seed = None;
            // nothing to open: an old failure no longer applies
            st.error = None;
        } else {
            if st.socket.is_none() {
                match (self.open)() {
                    Ok(s) => {
                        if st.error.take().is_some() {
                            tracing::info!("ARP interception socket opened");
                        }
                        st.socket = Some(s);
                    }
                    Err(e) => {
                        let msg = format!("raw socket: {e}");
                        if st.error.as_deref() != Some(msg.as_str()) {
                            tracing::warn!(error = %e, "ARP interception unavailable; nft rules still apply");
                        }
                        st.error = Some(msg);
                    }
                }
            }
            st.next_seed.get_or_insert(now + SEED_EVERY);
        }
        st.ifaces = ifaces;
        st.locked = locked;
        st.plan = next;
    }

    /// Starts the receive loop in a thread (once). The thread waits in
    /// `recv` (20 ms at most on Linux) or idles 100 ms without a socket,
    /// runs the timers after each wake, and exits once
    /// [`Self::stop_and_heal`] has run.
    pub fn start(self: &Arc<Self>) {
        if self.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let s = Arc::clone(self);
        let r = std::thread::Builder::new()
            .name("sensr-arp".into())
            .spawn(move || s.run());
        if let Err(e) = r {
            tracing::error!(error = %e, "ARP interceptor not started");
        }
    }

    fn run(&self) {
        let mut buf = [0u8; 2048];
        while !self.stopped.load(Ordering::SeqCst) {
            let sock = lock(&self.state).socket.clone();
            match sock {
                None => self.clock.sleep(IDLE_WAIT),
                Some(s) => match s.recv(&mut buf) {
                    Ok((n, index)) => self.on_frame(&buf[..n], index),
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "ARP interception receive");
                        self.clock.sleep(IDLE_WAIT);
                    }
                },
            }
            self.tick();
        }
    }

    /// Current status.
    pub fn status(&self) -> InterceptStatus {
        let st = lock(&self.state);
        let active = st.socket.is_some() && !st.locked.is_empty();
        let interfaces = if active {
            st.locked
                .iter()
                .map(|l| l.iface.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        } else {
            Vec::new()
        };
        InterceptStatus {
            active,
            interfaces,
            error: st.error.clone(),
        }
    }

    /// Stops the task and heals what it poisoned (and any heal still due):
    /// three rounds, 1 s apart. Blocks for those 2 s. Later inputs are ignored.
    pub fn stop_and_heal(&self) {
        let (sock, out) = {
            let mut st = lock(&self.state);
            self.stopped.store(true, Ordering::SeqCst);
            let st = &mut *st;
            let mut msgs: BTreeSet<PoisonMsg> =
                heal_plan(&st.ifaces, &st.locked).into_iter().collect();
            msgs.extend(
                st.queue
                    .drain(..)
                    .filter(|q| q.kind == Kind::Heal)
                    .map(|q| q.msg),
            );
            st.plan.clear();
            st.locked.clear();
            st.next_seed = None;
            let out = frames(
                &st.ifaces,
                msgs.into_iter().map(|m| (m, Kind::Heal)).collect(),
            );
            (st.socket.take(), out)
        };
        let Some(sock) = sock else { return };
        if out.is_empty() {
            return;
        }
        tracing::info!(frames = out.len(), "healing ARP caches");
        for r in 0..HEAL_ROUNDS {
            if r > 0 {
                self.clock.sleep(HEAL_GAP);
            }
            self.send_all(sock.as_ref(), &out);
        }
    }

    /// Sends what is due: the seed round every 2 s, answer repeats, heals.
    /// Closes the socket once idle and fully healed.
    fn tick(&self) {
        let now = self.clock.now();
        let (sock, out) = {
            let mut st = lock(&self.state);
            let st = &mut *st;
            let Some(sock) = st.socket.clone() else {
                st.queue.clear();
                return;
            };
            let mut msgs = Vec::new();
            if st.next_seed.is_some_and(|t| t <= now) {
                msgs.extend(st.plan.iter().map(|m| (m.clone(), Kind::Request)));
                st.next_seed = Some(now + SEED_EVERY);
            }
            let (due, later): (Vec<Queued>, Vec<Queued>) =
                st.queue.drain(..).partition(|q| q.due <= now);
            st.queue = later;
            msgs.extend(due.into_iter().map(|q| (q.msg, q.kind)));
            let out = frames(&st.ifaces, msgs);
            if st.locked.is_empty() && st.queue.is_empty() {
                st.socket = None;
            }
            (sock, out)
        };
        self.send_all(sock.as_ref(), &out);
    }

    /// An incoming frame on interface `index`: answers a matching request
    /// now and queues the repeat.
    fn on_frame(&self, frame: &[u8], index: u32) {
        let Some(req) = ArpFrame::parse(frame) else {
            return;
        };
        let now = self.clock.now();
        let (sock, out) = {
            let mut st = lock(&self.state);
            let Some(sock) = st.socket.clone() else {
                return;
            };
            let Some(view) = st.ifaces.iter().find(|v| v.index == index) else {
                return;
            };
            let Some(reply) = answer(&req, view, &st.locked) else {
                return;
            };
            let out = frames(&st.ifaces, vec![(reply.clone(), Kind::Reply)]);
            st.queue.push(Queued {
                due: now + ANSWER_REPEAT,
                msg: reply,
                kind: Kind::Reply,
            });
            (sock, out)
        };
        self.send_all(sock.as_ref(), &out);
    }

    fn send_all(&self, sock: &dyn PacketSocket, out: &[(u32, Vec<u8>)]) {
        for (index, f) in out {
            if let Err(e) = sock.send(*index, f) {
                let msg = format!("interface {index}: {e}");
                let mut st = lock(&self.state);
                if st.send_error.as_deref() != Some(msg.as_str()) {
                    tracing::warn!(error = %msg, "ARP interception send failed");
                    st.send_error = Some(msg);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTER: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const T_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x99];
    const A_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
    const B_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];
    const C_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0c];

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, last)
    }

    fn n(last: u8, mac: [u8; 6], live: bool) -> Neighbour {
        Neighbour {
            ip: ip(last),
            mac,
            live,
        }
    }

    fn lan(neighbours: Vec<Neighbour>) -> IfaceView {
        IfaceView {
            id: "lan".into(),
            device: "eth1".into(),
            index: 3,
            router_ip: ip(1),
            router_mac: ROUTER,
            neighbours,
        }
    }

    fn t() -> Locked {
        Locked {
            mac: T_MAC,
            ip: ip(99),
            iface: "lan".into(),
        }
    }

    fn msg(target: (u8, [u8; 6]), claim: (u8, [u8; 6])) -> PoisonMsg {
        PoisonMsg {
            iface: "lan".into(),
            target_ip: ip(target.0),
            target_mac: target.1,
            claim_ip: ip(claim.0),
            claim_mac: claim.1,
        }
    }

    /// The live LAN: router, T, A, B.
    fn live_lan() -> IfaceView {
        lan(vec![
            n(1, ROUTER, true),
            n(99, T_MAC, true),
            n(10, A_MAC, true),
            n(11, B_MAC, true),
        ])
    }

    #[test]
    fn plan_tells_both_sides_via_router() {
        let mut p = plan(&[live_lan()], &[t()]);
        p.sort();
        let mut want = vec![
            msg((99, T_MAC), (10, ROUTER)),
            msg((10, A_MAC), (99, ROUTER)),
            msg((99, T_MAC), (11, ROUTER)),
            msg((11, B_MAC), (99, ROUTER)),
        ];
        want.sort();
        assert_eq!(p, want);
        assert!(p.iter().all(|m| m.claim_mac == ROUTER));
        assert!(
            p.iter()
                .all(|m| m.target_ip != ip(1) && m.target_mac != ROUTER)
        );
    }

    #[test]
    fn plan_ignores_offline_and_router() {
        let view = lan(vec![
            n(1, ROUTER, true),
            n(10, A_MAC, true),
            n(12, C_MAC, false),
        ]);
        let p = plan(&[view], &[t()]);
        assert_eq!(p.len(), 2, "{p:?}");
        for m in &p {
            assert_ne!(m.target_ip, ip(12));
            assert_ne!(m.claim_ip, ip(12));
            assert_ne!(m.target_ip, ip(1), "never target the router");
            assert_ne!(m.claim_ip, ip(1), "never claim the router's address");
        }
    }

    #[test]
    fn plan_only_internal_interfaces() {
        let elsewhere = Locked {
            iface: "opt9".into(),
            ..t()
        };
        assert!(plan(&[live_lan()], std::slice::from_ref(&elsewhere)).is_empty());
        assert!(heal_plan(&[live_lan()], &[elsewhere]).is_empty());
    }

    #[test]
    fn plan_two_locked_hosts_are_cut_from_each_other_once() {
        let t2 = Locked {
            mac: C_MAC,
            ip: ip(12),
            iface: "lan".into(),
        };
        let view = lan(vec![n(99, T_MAC, true), n(12, C_MAC, true)]);
        let mut p = plan(&[view], &[t(), t2]);
        p.sort();
        let mut want = vec![
            msg((99, T_MAC), (12, ROUTER)),
            msg((12, C_MAC), (99, ROUTER)),
        ];
        want.sort();
        assert_eq!(p, want);
    }

    #[test]
    fn heal_plan_restores_true_macs() {
        let mut h = heal_plan(&[live_lan()], &[t()]);
        h.sort();
        let mut want = vec![
            msg((99, T_MAC), (10, A_MAC)),
            msg((10, A_MAC), (99, T_MAC)),
            msg((99, T_MAC), (11, B_MAC)),
            msg((11, B_MAC), (99, T_MAC)),
        ];
        want.sort();
        assert_eq!(h, want);
        // the same pairs as the plan
        let key = |m: &PoisonMsg| (m.iface.clone(), m.target_ip, m.claim_ip);
        let mut p: Vec<_> = plan(&[live_lan()], &[t()]).iter().map(key).collect();
        let mut hk: Vec<_> = h.iter().map(key).collect();
        p.sort();
        hk.sort();
        assert_eq!(p, hk);
    }

    fn request(sender: (u8, [u8; 6]), target: u8) -> ArpFrame {
        ArpFrame {
            op: 1,
            sender_mac: sender.1,
            sender_ip: ip(sender.0),
            target_mac: [0; 6],
            target_ip: ip(target),
        }
    }

    #[test]
    fn answer_replies_to_requests_for_locked_or_from_locked() {
        let view = live_lan();
        let locked = [t()];
        // T asks for A
        let r = answer(&request((99, T_MAC), 10), &view, &locked).unwrap();
        assert_eq!(r, msg((99, T_MAC), (10, ROUTER)));
        // A asks for T
        let r = answer(&request((10, A_MAC), 99), &view, &locked).unwrap();
        assert_eq!(r, msg((10, A_MAC), (99, ROUTER)));
        // unrelated: A asks for B
        assert_eq!(answer(&request((10, A_MAC), 11), &view, &locked), None);
        // a reply is not a request
        let mut rep = request((99, T_MAC), 10);
        rep.op = 2;
        assert_eq!(answer(&rep, &view, &locked), None);
        // T asking for the router: the router answers that itself
        assert_eq!(answer(&request((99, T_MAC), 1), &view, &locked), None);
        // the router's own request for T (and our own seeds) are left alone
        assert_eq!(answer(&request((1, ROUTER), 99), &view, &locked), None);
        assert_eq!(answer(&request((10, ROUTER), 99), &view, &locked), None);
        // an address probe for T's address (sender 0.0.0.0) must not see a
        // conflict; an announcement by T neither
        let mut probe = request((0, A_MAC), 99);
        probe.sender_ip = Ipv4Addr::UNSPECIFIED;
        assert_eq!(answer(&probe, &view, &locked), None);
        assert_eq!(answer(&request((99, T_MAC), 99), &view, &locked), None);
        // a locked host on another interface
        let other = Locked {
            iface: "opt1".into(),
            ..t()
        };
        assert_eq!(answer(&request((10, A_MAC), 99), &view, &[other]), None);
    }

    #[test]
    fn frame_round_trips() {
        let m = msg((99, T_MAC), (10, ROUTER));
        let f = build_reply(&m, ROUTER);
        assert_eq!(f.len(), FRAME_LEN);
        assert_eq!(&f[0..6], &T_MAC, "Ethernet dst is the target");
        assert_eq!(&f[6..12], &ROUTER, "Ethernet src is the router");
        assert_eq!(&f[12..14], &[0x08, 0x06]);
        assert_eq!(&f[14..22], &[0, 1, 8, 0, 6, 4, 0, 2]);
        let p = ArpFrame::parse(&f).unwrap();
        assert_eq!(
            p,
            ArpFrame {
                op: 2,
                sender_mac: ROUTER,
                sender_ip: ip(10),
                target_mac: T_MAC,
                target_ip: ip(99),
            }
        );
        let q = ArpFrame::parse(&build_request(&m, ROUTER)).unwrap();
        assert_eq!(q.op, 1);
        // a heal frame claims the owner's MAC but still comes from the router
        let h = build_reply(&msg((99, T_MAC), (10, A_MAC)), ROUTER);
        assert_eq!(&h[6..12], &ROUTER);
        assert_eq!(ArpFrame::parse(&h).unwrap().sender_mac, A_MAC);
        // padded to the Ethernet minimum: still parses
        let mut padded = f.clone();
        padded.resize(60, 0);
        assert_eq!(ArpFrame::parse(&padded), Some(p));
        // not ARP, or truncated
        let mut ip4 = f.clone();
        ip4[12..14].copy_from_slice(&[0x08, 0x00]);
        assert_eq!(ArpFrame::parse(&ip4), None);
        assert_eq!(ArpFrame::parse(&f[..41]), None);
    }

    fn entry(ip: &str, mac: &str, dev: &str, state: &str) -> NeighEntry {
        NeighEntry {
            mac: mac.into(),
            ip: ip.parse().unwrap(),
            dev: dev.into(),
            state: vec![state.into()],
        }
    }

    #[test]
    fn inputs_build_views_for_internal_interfaces_only() {
        let internal = vec![InternalIf {
            id: "lan".into(),
            device: "eth1".into(),
            descr: "LAN".into(),
            subnets: vec!["192.168.1.0/24".parse().unwrap()],
        }];
        let addrs: BTreeMap<String, Vec<IfAddr>> = [
            (
                "lan".to_owned(),
                vec![IfAddr {
                    addr: "192.168.1.1".parse().unwrap(),
                    prefix_len: 24,
                }],
            ),
            (
                "wan".to_owned(),
                vec![IfAddr {
                    addr: "203.0.113.2".parse().unwrap(),
                    prefix_len: 24,
                }],
            ),
        ]
        .into();
        let link = |dev: &str| match dev {
            "eth1" => Some((3, ROUTER)),
            "eth0" => Some((2, [0x02, 0, 0, 0, 0, 0x02])),
            _ => None,
        };
        let neigh = [
            entry("192.168.1.10", "02:00:00:00:00:0a", "eth1", "REACHABLE"),
            entry("192.168.1.11", "02:00:00:00:00:0b", "eth1", "STALE"),
            entry("192.168.1.12", "02:00:00:00:00:0c", "eth1", "FAILED"),
            // the WAN is never internal
            entry("203.0.113.1", "02:00:00:00:00:fe", "eth0", "REACHABLE"),
            // off-subnet on the LAN device
            entry("10.9.9.9", "02:00:00:00:00:ee", "eth1", "REACHABLE"),
            entry("fe80::a", "02:00:00:00:00:0a", "eth1", "REACHABLE"),
        ];
        // seen recently by the inventory only
        let online = [("02:00:00:00:00:0d".to_owned(), ip(13), "lan".to_owned())];
        let locked_macs: Vec<MacAddr> = vec!["02:00:00:00:00:99".parse().unwrap()];
        let table = [
            (
                "02:00:00:00:00:99".to_owned(),
                "192.168.1.99".parse().unwrap(),
            ),
            ("02:00:00:00:00:99".to_owned(), "fd00::99".parse().unwrap()),
            (
                "02:00:00:00:00:0a".to_owned(),
                "192.168.1.10".parse().unwrap(),
            ),
        ];
        let (views, locked) = inputs(&Sources {
            internal: &internal,
            addrs: &addrs,
            link: &link,
            neigh: &neigh,
            online: &online,
            locked_macs: &locked_macs,
            table: &table,
        });
        assert_eq!(views.len(), 1);
        let v = &views[0];
        assert_eq!(
            (v.id.as_str(), v.device.as_str(), v.index),
            ("lan", "eth1", 3)
        );
        assert_eq!((v.router_ip, v.router_mac), (ip(1), ROUTER));
        let mut ns = v.neighbours.clone();
        ns.sort_by_key(|n| n.ip);
        assert_eq!(
            ns,
            [
                n(10, A_MAC, true),
                n(11, B_MAC, true),
                n(12, C_MAC, false),
                n(13, [0x02, 0, 0, 0, 0, 0x0d], true),
            ]
        );
        assert_eq!(locked, [t()]);
    }

    /// Records every frame sent, hands out queued incoming ones.
    #[derive(Default)]
    struct MockSocket {
        sent: Mutex<Vec<(u32, Vec<u8>)>>,
    }

    impl PacketSocket for MockSocket {
        fn send(&self, iface_index: u32, frame: &[u8]) -> io::Result<()> {
            lock(&self.sent).push((iface_index, frame.to_vec()));
            Ok(())
        }
        fn recv(&self, _: &mut [u8]) -> io::Result<(usize, u32)> {
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    impl MockSocket {
        /// Sent frames parsed, with their interface index; clears the record.
        fn take(&self) -> Vec<(u32, ArpFrame)> {
            std::mem::take(&mut *lock(&self.sent))
                .into_iter()
                .map(|(i, f)| (i, ArpFrame::parse(&f).unwrap()))
                .collect()
        }
    }

    /// Time moves only when told to, or when the interceptor sleeps.
    struct TestClock {
        now: Mutex<Instant>,
        slept: Mutex<Vec<Duration>>,
    }

    impl TestClock {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                now: Mutex::new(Instant::now()),
                slept: Mutex::new(Vec::new()),
            })
        }
        fn advance(&self, d: Duration) {
            *lock(&self.now) += d;
        }
    }

    impl Clock for TestClock {
        fn now(&self) -> Instant {
            *lock(&self.now)
        }
        fn sleep(&self, d: Duration) {
            lock(&self.slept).push(d);
            self.advance(d);
        }
    }

    fn interceptor() -> (Arc<Interceptor>, Arc<MockSocket>, Arc<TestClock>) {
        let sock = Arc::new(MockSocket::default());
        let s = Arc::clone(&sock);
        let clock = TestClock::new();
        let i = Interceptor::new(
            Arc::new(move || Ok(Arc::clone(&s) as Arc<dyn PacketSocket>)),
            clock.clone(),
        );
        (i, sock, clock)
    }

    fn requests_to(sent: &[(u32, ArpFrame)]) -> BTreeSet<(Ipv4Addr, Ipv4Addr)> {
        sent.iter()
            .map(|(_, f)| {
                assert_eq!(f.op, 1);
                assert_eq!(f.sender_mac, ROUTER);
                (f.target_ip, f.sender_ip)
            })
            .collect()
    }

    #[test]
    fn seeds_every_two_seconds_with_unicast_requests() {
        let (i, sock, clock) = interceptor();
        i.set_inputs(vec![live_lan()], vec![t()]);
        i.tick();
        let first = sock.take();
        assert_eq!(first.len(), 4, "{first:?}");
        assert!(first.iter().all(|(idx, _)| *idx == 3));
        let want: BTreeSet<_> = [
            (ip(99), ip(10)),
            (ip(10), ip(99)),
            (ip(99), ip(11)),
            (ip(11), ip(99)),
        ]
        .into();
        assert_eq!(requests_to(&first), want);
        // nothing until 2 s have passed
        clock.advance(Duration::from_millis(1_900));
        i.tick();
        assert!(sock.take().is_empty());
        clock.advance(Duration::from_millis(100));
        i.tick();
        assert_eq!(requests_to(&sock.take()), want);
        assert!(i.status().active);
        assert_eq!(i.status().interfaces, ["lan"]);
    }

    #[test]
    fn answers_at_once_and_again_after_50ms() {
        let (i, sock, clock) = interceptor();
        i.set_inputs(vec![live_lan()], vec![t()]);
        i.tick();
        sock.take();
        let req = build_request(&msg((10, [0; 6]), (99, T_MAC)), T_MAC);
        // T asks who has A, broadcast on the LAN
        i.on_frame(&req, 3);
        let now = sock.take();
        assert_eq!(now.len(), 1);
        let (idx, f) = &now[0];
        assert_eq!(*idx, 3);
        assert_eq!(
            *f,
            ArpFrame {
                op: 2,
                sender_mac: ROUTER,
                sender_ip: ip(10),
                target_mac: T_MAC,
                target_ip: ip(99),
            }
        );
        clock.advance(Duration::from_millis(40));
        i.tick();
        assert!(sock.take().is_empty());
        clock.advance(Duration::from_millis(10));
        i.tick();
        assert_eq!(sock.take(), now, "the repeat 50 ms later");
        // the same request on another interface (index 2: the WAN) is ignored
        i.on_frame(&req, 2);
        assert!(sock.take().is_empty());
    }

    #[test]
    fn a_pending_answer_repeat_does_not_follow_the_heal() {
        let (i, sock, clock) = interceptor();
        i.set_inputs(vec![live_lan()], vec![t()]);
        i.tick();
        sock.take();
        i.on_frame(&build_request(&msg((10, [0; 6]), (99, T_MAC)), T_MAC), 3);
        assert_eq!(sock.take().len(), 1);
        // T leaves before the repeat is due
        i.set_inputs(vec![live_lan()], vec![]);
        clock.advance(ANSWER_REPEAT);
        i.tick();
        let sent = sock.take();
        assert_eq!(sent.len(), 4, "{sent:?}");
        assert!(
            sent.iter().all(|(_, f)| f.sender_mac != ROUTER),
            "heals only"
        );
    }

    #[test]
    fn turning_off_clears_a_socket_error() {
        let clock = TestClock::new();
        let i = Interceptor::new(
            Arc::new(|| Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))),
            clock,
        );
        i.set_inputs(vec![live_lan()], vec![t()]);
        assert!(i.status().error.is_some());
        i.set_inputs(vec![live_lan()], vec![]);
        assert_eq!(i.status(), InterceptStatus::default());
    }

    fn assert_heal_rounds(sent: &[(u32, ArpFrame)]) {
        let mut want: Vec<(u32, ArpFrame)> = heal_plan(&[live_lan()], &[t()])
            .iter()
            .map(|m| (3, ArpFrame::parse(&build_reply(m, ROUTER)).unwrap()))
            .collect();
        assert_eq!(want.len(), 4);
        want.sort_by_key(|(_, f)| (f.target_ip, f.sender_ip));
        for round in sent.chunks(4) {
            let mut r = round.to_vec();
            r.sort_by_key(|(_, f)| (f.target_ip, f.sender_ip));
            assert_eq!(r, want);
        }
    }

    #[test]
    fn collector_shutdown_sends_heal() {
        let (i, sock, clock) = interceptor();
        i.set_inputs(vec![live_lan()], vec![t()]);
        i.tick();
        sock.take();
        i.stop_and_heal();
        let sent = sock.take();
        assert_eq!(sent.len(), 12, "three rounds of four");
        assert_heal_rounds(&sent);
        assert_eq!(*lock(&clock.slept), [HEAL_GAP, HEAL_GAP], "1 s apart");
        assert!(!i.status().active);
        // stopped: nothing is poisoned again
        i.set_inputs(vec![live_lan()], vec![t()]);
        i.tick();
        assert!(sock.take().is_empty());
    }

    #[test]
    fn leaving_the_locked_set_heals_three_rounds_one_second_apart() {
        let (i, sock, clock) = interceptor();
        i.set_inputs(vec![live_lan()], vec![t()]);
        i.tick();
        sock.take();
        // the host goes back to Normal (or arp_intercept is turned off)
        i.set_inputs(vec![live_lan()], vec![]);
        assert!(!i.status().active);
        let mut rounds = Vec::new();
        for _ in 0..3 {
            i.tick();
            let r = sock.take();
            assert_eq!(r.len(), 4, "{r:?}");
            rounds.extend(r);
            clock.advance(Duration::from_millis(500));
            i.tick();
            assert!(sock.take().is_empty(), "nothing between rounds");
            clock.advance(Duration::from_millis(500));
        }
        assert_heal_rounds(&rounds);
        // healed and idle: no seeds, nothing more
        clock.advance(Duration::from_secs(10));
        i.tick();
        assert!(sock.take().is_empty());
    }

    #[test]
    fn a_neighbour_dropping_out_is_healed_alone() {
        let (i, sock, _clock) = interceptor();
        i.set_inputs(vec![live_lan()], vec![t()]);
        i.tick();
        sock.take();
        // B goes offline: only the T<->B pair is healed, A stays poisoned
        let view = lan(vec![
            n(99, T_MAC, true),
            n(10, A_MAC, true),
            n(11, B_MAC, false),
        ]);
        i.set_inputs(vec![view], vec![t()]);
        i.tick();
        let sent = sock.take();
        let heals: BTreeSet<_> = sent
            .iter()
            .map(|(_, f)| (f.op, f.target_ip, f.sender_ip, f.sender_mac))
            .collect();
        assert_eq!(
            heals,
            [(2, ip(99), ip(11), B_MAC), (2, ip(11), ip(99), T_MAC)].into()
        );
    }

    #[test]
    fn never_sends_outside_the_given_interfaces() {
        let (i, sock, clock) = interceptor();
        i.set_inputs(vec![live_lan()], vec![t()]);
        i.tick();
        sock.take();
        // the LAN stops being internal while a heal is due: nothing goes out
        i.set_inputs(vec![], vec![]);
        for _ in 0..4 {
            i.tick();
            clock.advance(HEAL_GAP);
        }
        assert!(sock.take().is_empty());
    }

    #[test]
    fn status_reports_socket_error() {
        let clock = TestClock::new();
        let i = Interceptor::new(
            Arc::new(|| {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "no CAP_NET_RAW",
                ))
            }),
            clock,
        );
        assert_eq!(i.status(), InterceptStatus::default());
        // nothing panics or fails: the nft layer is applied independently
        i.set_inputs(vec![live_lan()], vec![t()]);
        i.tick();
        i.on_frame(&build_request(&msg((10, [0; 6]), (99, T_MAC)), T_MAC), 3);
        let s = i.status();
        assert!(!s.active);
        assert!(s.interfaces.is_empty());
        assert!(
            s.error.as_deref().unwrap().contains("no CAP_NET_RAW"),
            "{s:?}"
        );
        i.stop_and_heal();
    }

    /// Needs `CAP_NET_RAW` (run as root): a frame sent on `lo` comes back
    /// once, as incoming, with lo's index; our own outgoing copy is skipped.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs CAP_NET_RAW"]
    fn af_packet_round_trip_on_loopback() {
        let (index, _) = link("lo").expect("lo");
        let sock = AfPacketSocket::open().unwrap();
        let f = build_request(&msg((99, T_MAC), (10, ROUTER)), ROUTER);
        sock.send(index, &f).unwrap();
        let mut buf = [0u8; 2048];
        let (n, from) = sock.recv(&mut buf).unwrap();
        assert_eq!(from, index);
        assert_eq!(ArpFrame::parse(&buf[..n]), ArpFrame::parse(&f));
        let again = sock.recv(&mut buf).unwrap_err();
        assert!(
            matches!(
                again.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{again:?}"
        );
    }

    #[test]
    fn non_linux_socket_is_unsupported() {
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            AfPacketSocket::open().err().map(|e| e.kind()),
            Some(io::ErrorKind::Unsupported)
        );
    }
}
