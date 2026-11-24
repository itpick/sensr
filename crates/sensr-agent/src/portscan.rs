//! The daily TCP port scan of LAN hosts
//! (docs/superpowers/specs/2026-11-24-port-scan-design.md).
//!
//! A plain connect scan: a port is open when the connection is accepted
//! (and closed again at once), closed when refused, filtered on timeout.
//! Only open ports are kept, per MAC, in `ports.json` in the state
//! directory ([`PortStore`]).
//!
//! The pieces: the port list ([`port_list`]) and service names
//! ([`service`]); one host's scan ([`Scanner`], over a [`Connector`] and a
//! global [`RateLimiter`]); the merge into the store; who is scanned
//! ([`targets`]); when ([`next_run`], in the router's time zone); and the
//! service that owns all of it ([`PortScan`]): a schedule thread, one host
//! at a time per interface, and "scan now" for one host.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use sensr_rules::document::{InternalIf, internal_interfaces};
use sensr_schema::Document;
use serde::{Deserialize, Serialize};

use crate::hosts::Host;

/// Ports scanned on top of 1-1024: common home and IoT services.
pub const EXTRA_PORTS: [u16; 22] = [
    554, 1883, 1900, 3000, 3389, 5000, 5001, 5353, 5555, 5900, 8000, 8008, 8009, 8080, 8123, 8443,
    8554, 8883, 8888, 9000, 32400, 49152,
];
/// How long one connection attempt may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);
/// Connection attempts in flight to one host.
pub const PER_HOST: usize = 8;
/// Connection attempts per second, over all scans.
pub const RATE_PER_SEC: u32 = 200;
/// Hosts seen within this long are scanned daily (24 h).
pub const TARGET_SEEN_SECS: u64 = 86_400;
/// A port first seen within this long is new (24 h).
pub const NEW_SECS: u64 = 86_400;
/// A closed port, and a host not scanned, is kept this long (90 days).
pub const KEEP_SECS: u64 = 7_776_000;
/// Ports kept per host.
pub const MAX_PORTS_PER_HOST: usize = 1024;
/// Hosts kept in the store (as the inventory).
pub const MAX_HOSTS: usize = crate::hosts::MAX_HOSTS;
/// "Scan now" jobs running at once.
pub const MAX_SCAN_NOW: usize = 2;
/// How often the schedule is checked.
const TICK: Duration = Duration::from_secs(30);

/// Every port scanned: 1-1024, [`EXTRA_PORTS`] and the owner's extra ports
/// (already capped and cleaned by [`PortScan::extra`]), sorted, once each.
///
/// [`PortScan::extra`]: sensr_schema::models::hosts::PortScan::extra
pub fn port_list(extra: &[u16]) -> Vec<u16> {
    let set: BTreeSet<u16> = (1..=1024)
        .chain(EXTRA_PORTS)
        .chain(extra.iter().copied().filter(|p| *p != 0))
        .collect();
    set.into_iter().collect()
}

/// The usual service on `port`, or `""`.
pub fn service(port: u16) -> &'static str {
    match port {
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        81 => "http-alt",
        88 => "kerberos",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios",
        143 => "imap",
        161 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        515 => "printer",
        548 => "afp",
        554 => "rtsp",
        587 => "submission",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        993 => "imaps",
        995 => "pop3s",
        1883 => "mqtt",
        1900 => "upnp",
        3000 => "http-dev",
        3389 => "rdp",
        5000 => "upnp-http",
        5001 => "https-alt",
        5353 => "mdns",
        5555 => "adb",
        5900 => "vnc",
        8000 => "http-alt",
        8008 => "http-alt",
        8009 => "cast",
        8080 => "http-alt",
        8123 => "home-assistant",
        8443 => "https-alt",
        8554 => "rtsp-alt",
        8883 => "mqtts",
        8888 => "http-alt",
        9000 => "http-alt",
        9100 => "jetdirect",
        32400 => "plex",
        49152 => "upnp",
        _ => "",
    }
}

/// What one connection attempt found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Probe {
    /// Accepted.
    Open,
    /// Refused (or reset): the host is there and nothing listens.
    Closed,
    /// An ICMP host-unreachable or host-down within the timeout
    /// (`EHOSTUNREACH`, `EHOSTDOWN`): the port counts as closed, but the
    /// kernel also says this when the neighbour lookup failed, so on its
    /// own it does not prove the host is there.
    Rejected,
    /// No answer before the timeout.
    Filtered,
    /// The router cannot send (`ENETUNREACH`, `EPERM`, anything else that
    /// says nothing about the port): the scan stops without a result.
    Unreachable,
}

/// Errno values for [`classify`] where `std::io::ErrorKind` has no stable
/// kind.
mod errno {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    pub const EHOSTDOWN: i32 = 64;
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
    pub const EHOSTDOWN: i32 = 112;
}

/// What a failed connect says about the port.
pub fn classify(e: &std::io::Error) -> Probe {
    use std::io::ErrorKind as K;
    match e.kind() {
        K::ConnectionRefused | K::ConnectionReset => Probe::Closed,
        K::TimedOut | K::WouldBlock => Probe::Filtered,
        K::HostUnreachable => Probe::Rejected,
        _ if e.raw_os_error() == Some(errno::EHOSTDOWN) => Probe::Rejected,
        // ENETUNREACH, EPERM/EACCES (a local firewall), the rest
        _ => Probe::Unreachable,
    }
}

/// Makes one connection attempt (a fake in tests).
pub trait Connector: Send + Sync {
    /// Tries `addr` for at most `timeout`. An accepted connection is closed
    /// before this returns.
    fn probe(&self, addr: SocketAddr, timeout: Duration) -> Probe;
}

/// Real TCP connects.
pub struct TcpConnector;

impl Connector for TcpConnector {
    fn probe(&self, addr: SocketAddr, timeout: Duration) -> Probe {
        match std::net::TcpStream::connect_timeout(&addr, timeout) {
            // dropped here: closed straight after the handshake
            Ok(s) => {
                drop(s);
                Probe::Open
            }
            Err(e) => classify(&e),
        }
    }
}

/// Time for the rate limiter (virtual in tests).
pub trait Clock: Send + Sync {
    /// Time since an arbitrary start.
    fn now(&self) -> Duration;
    /// Waits `d`.
    fn sleep(&self, d: Duration);
}

/// The monotonic clock.
pub struct SystemClock(Instant);

impl Default for SystemClock {
    fn default() -> Self {
        Self(Instant::now())
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// Spaces connection attempts evenly: at most `per_sec` a second over every
/// caller, with no burst.
pub struct RateLimiter {
    interval: Duration,
    next: Mutex<Duration>,
}

impl RateLimiter {
    /// `per_sec` attempts a second (at least 1).
    pub fn new(per_sec: u32) -> Self {
        Self {
            interval: Duration::from_secs(1) / per_sec.max(1),
            next: Mutex::new(Duration::ZERO),
        }
    }

    /// Waits for the caller's slot.
    pub fn acquire(&self, clock: &dyn Clock) {
        let wait = {
            let mut next = lock(&self.next);
            let now = clock.now();
            let slot = (*next).max(now);
            *next = slot + self.interval;
            slot - now
        };
        if !wait.is_zero() {
            clock.sleep(wait);
        }
    }
}

/// Why a host's scan has no result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScanError {
    /// Stopped by an agent shutdown or an apply.
    #[error("cancelled")]
    Cancelled,
    /// The router could not reach the host's network
    /// ([`Probe::Unreachable`]).
    #[error("host unreachable")]
    Unreachable,
}

/// One host's per-port findings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanOutcome {
    /// Accepted, sorted.
    pub open: Vec<u16>,
    /// Refused or rejected: these, and only these, close a known port.
    pub closed: BTreeSet<u16>,
    /// No answer, even on the retry of a port that was open before.
    pub filtered: BTreeSet<u16>,
    /// Some port was accepted or refused with a reset: the host is there.
    pub answered: bool,
}

impl ScanOutcome {
    fn absorb(&mut self, other: ScanOutcome) {
        self.open.extend(other.open);
        self.closed.extend(other.closed);
        self.filtered.extend(other.filtered);
        self.answered |= other.answered;
    }
}

/// Scans one host.
pub struct Scanner {
    connector: Arc<dyn Connector>,
    clock: Arc<dyn Clock>,
    limiter: Option<Arc<RateLimiter>>,
    timeout: Duration,
    per_host: usize,
}

impl Scanner {
    /// The production scanner: real connects, [`CONNECT_TIMEOUT`],
    /// [`PER_HOST`] in flight, [`RATE_PER_SEC`] overall.
    pub fn system() -> Self {
        Self::new(
            Arc::new(TcpConnector),
            Arc::new(SystemClock::default()),
            Some(Arc::new(RateLimiter::new(RATE_PER_SEC))),
            CONNECT_TIMEOUT,
            PER_HOST,
        )
    }

    /// With explicit parts (tests).
    pub fn new(
        connector: Arc<dyn Connector>,
        clock: Arc<dyn Clock>,
        limiter: Option<Arc<RateLimiter>>,
        timeout: Duration,
        per_host: usize,
    ) -> Self {
        Self {
            connector,
            clock,
            limiter,
            timeout,
            per_host: per_host.max(1),
        }
    }

    /// What each of `ports` on `ip` does. At most `per_host` attempts are
    /// in flight; each lane takes every `per_host`-th port, so a host that
    /// drops everything takes `ceil(ports / per_host)` timeouts. A port of
    /// `recheck` (open at the last scan) that comes back filtered is tried
    /// once more.
    ///
    /// Fails with [`ScanError::Cancelled`] once `cancel` is set (nothing is
    /// started after that) and with [`ScanError::Unreachable`] when the
    /// router cannot send: neither is a result.
    pub fn scan_host(
        &self,
        ip: Ipv4Addr,
        ports: &[u16],
        recheck: &BTreeSet<u16>,
        cancel: &AtomicBool,
    ) -> Result<ScanOutcome, ScanError> {
        let mut out = self.pass(ip, ports, cancel)?;
        let again: Vec<u16> = out.filtered.intersection(recheck).copied().collect();
        if !again.is_empty() {
            for p in &again {
                out.filtered.remove(p);
            }
            out.absorb(self.pass(ip, &again, cancel)?);
        }
        out.open.sort_unstable();
        Ok(out)
    }

    /// One pass over `ports`.
    fn pass(
        &self,
        ip: Ipv4Addr,
        ports: &[u16],
        cancel: &AtomicBool,
    ) -> Result<ScanOutcome, ScanError> {
        let lanes = self.per_host.min(ports.len()).max(1);
        let gone = AtomicBool::new(false);
        let out = Mutex::new(ScanOutcome::default());
        std::thread::scope(|s| {
            for lane in 0..lanes {
                let (gone, out) = (&gone, &out);
                let r = std::thread::Builder::new()
                    .name("sensr-portscan".into())
                    .spawn_scoped(s, move || {
                        for &port in ports.iter().skip(lane).step_by(lanes) {
                            if cancel.load(Ordering::SeqCst) || gone.load(Ordering::SeqCst) {
                                return;
                            }
                            if let Some(l) = &self.limiter {
                                l.acquire(&*self.clock);
                            }
                            if cancel.load(Ordering::SeqCst) {
                                return;
                            }
                            let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));
                            let probe = self.connector.probe(addr, self.timeout);
                            let mut o = lock(out);
                            match probe {
                                Probe::Open => {
                                    o.answered = true;
                                    o.open.push(port);
                                }
                                Probe::Closed => {
                                    o.answered = true;
                                    o.closed.insert(port);
                                }
                                Probe::Rejected => {
                                    o.closed.insert(port);
                                }
                                Probe::Filtered => {
                                    o.filtered.insert(port);
                                }
                                Probe::Unreachable => gone.store(true, Ordering::SeqCst),
                            }
                        }
                    });
                if let Err(e) = r {
                    // a lane that never ran leaves its ports unknown
                    tracing::warn!(error = %e, "port scan lane not started");
                    gone.store(true, Ordering::SeqCst);
                }
            }
        });
        if cancel.load(Ordering::SeqCst) {
            return Err(ScanError::Cancelled);
        }
        if gone.load(Ordering::SeqCst) {
            return Err(ScanError::Unreachable);
        }
        Ok(out.into_inner().unwrap_or_else(|e| e.into_inner()))
    }
}

/// One port as stored.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PortEntry {
    /// The TCP port.
    pub port: u16,
    /// [`service`] of the port, or empty.
    #[serde(default)]
    pub service: String,
    /// First found open, Unix seconds.
    pub first_seen: u64,
    /// Last found open, Unix seconds.
    pub last_seen: u64,
    /// When a scan found it closed again; dropped [`KEEP_SECS`] later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<u64>,
}

impl PortEntry {
    /// First seen within [`NEW_SECS`] of `now`.
    pub fn is_new(&self, now: u64) -> bool {
        now.saturating_sub(self.first_seen) < NEW_SECS
    }
}

/// One host's results.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Default)]
pub struct HostPorts {
    /// The last scan with a result, Unix seconds.
    pub last_scan: u64,
    /// Open and recently closed ports, by port.
    #[serde(default)]
    pub ports: Vec<PortEntry>,
    /// The last scan found the host up but no port answered (it drops
    /// everything); its ports were left as they were.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub all_filtered: bool,
}

impl HostPorts {
    /// The ports open at the last scan.
    pub fn open(&self) -> impl Iterator<Item = &PortEntry> {
        self.ports.iter().filter(|p| p.closed_at.is_none())
    }
}

/// On-disk format version.
const FILE_VERSION: u64 = 1;

#[derive(Serialize)]
struct FileOut<'a> {
    version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_sweep: Option<u64>,
    hosts: &'a BTreeMap<String, HostPorts>,
}

#[derive(Deserialize)]
struct FileIn {
    version: u64,
    #[serde(default)]
    last_sweep: Option<u64>,
    hosts: BTreeMap<String, HostPorts>,
}

/// The scan results by lowercase MAC, saved to `ports.json`.
pub struct PortStore {
    path: PathBuf,
    hosts: BTreeMap<String, HostPorts>,
    /// When the last daily sweep that ran to the end started.
    pub last_sweep: Option<u64>,
}

impl PortStore {
    /// What `path` holds; empty (with a warning) when the file is missing,
    /// unparsable or of another version. An unusable file is renamed to
    /// `ports.json.bad` so the next save keeps it.
    pub fn load(path: PathBuf) -> Self {
        let mut last_sweep = None;
        let hosts = match std::fs::read(&path) {
            Ok(b) => match serde_json::from_slice::<FileIn>(&b) {
                Ok(f) if f.version == FILE_VERSION => {
                    last_sweep = f.last_sweep;
                    Some(f.hosts)
                }
                Ok(f) => {
                    tracing::warn!(
                        version = f.version,
                        "port scan results have an unknown version"
                    );
                    None
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "port scan results are unreadable");
                    None
                }
            },
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(path = %path.display(), error = %e, "reading port scan results");
                }
                Some(BTreeMap::new())
            }
        };
        let mut hosts = hosts.unwrap_or_else(|| {
            let bad = path.with_extension("json.bad");
            if let Err(e) = std::fs::rename(&path, &bad) {
                tracing::warn!(path = %bad.display(), error = %e, "keeping the old port scan results");
            }
            BTreeMap::new()
        });
        // a hand-edited or older file is held to the same bound
        for h in hosts.values_mut() {
            cap_ports(&mut h.ports);
        }
        Self {
            path,
            hosts,
            last_sweep,
        }
    }

    /// One host's results.
    pub fn get(&self, mac: &str) -> Option<&HostPorts> {
        self.hosts.get(&mac.to_ascii_lowercase())
    }

    /// Records a scan of `mac` at `now`: open ports are (again) open, a
    /// known port is closed only when `o` has it refused or rejected, and a
    /// filtered one is left as it was.
    pub fn merge(&mut self, mac: &str, o: &ScanOutcome, now: u64) {
        let h = self.hosts.entry(mac.to_ascii_lowercase()).or_default();
        h.last_scan = now;
        h.all_filtered = o.open.is_empty() && o.closed.is_empty();
        let open: BTreeSet<u16> = o.open.iter().copied().collect();
        for e in &mut h.ports {
            if open.contains(&e.port) {
                e.last_seen = now;
                e.closed_at = None;
            } else if e.closed_at.is_none() && o.closed.contains(&e.port) {
                e.closed_at = Some(now);
            }
            e.service = service(e.port).to_owned();
        }
        let known: BTreeSet<u16> = h.ports.iter().map(|e| e.port).collect();
        h.ports
            .extend(open.difference(&known).map(|&port| PortEntry {
                port,
                service: service(port).to_owned(),
                first_seen: now,
                last_seen: now,
                closed_at: None,
            }));
        cap_ports(&mut h.ports);
    }

    /// Drops closed ports and unscanned hosts older than [`KEEP_SECS`], and
    /// the longest-unscanned hosts past [`MAX_HOSTS`].
    pub fn prune(&mut self, now: u64) {
        let old = |t: u64| now.saturating_sub(t) > KEEP_SECS;
        for h in self.hosts.values_mut() {
            h.ports.retain(|e| !e.closed_at.is_some_and(old));
        }
        self.hosts.retain(|_, h| !old(h.last_scan));
        if self.hosts.len() > MAX_HOSTS {
            let mut by_age: Vec<(u64, String)> = self
                .hosts
                .iter()
                .map(|(m, h)| (h.last_scan, m.clone()))
                .collect();
            by_age.sort();
            for (_, m) in by_age.iter().take(self.hosts.len() - MAX_HOSTS) {
                self.hosts.remove(m);
            }
        }
    }

    /// The file's contents now (taken under the caller's lock, written by
    /// [`write_file`] outside it).
    pub fn snapshot(&self) -> std::io::Result<(PathBuf, Vec<u8>)> {
        let bytes = serde_json::to_vec(&FileOut {
            version: FILE_VERSION,
            last_sweep: self.last_sweep,
            hosts: &self.hosts,
        })
        .map_err(std::io::Error::other)?;
        Ok((self.path.clone(), bytes))
    }

    /// Writes the file now ([`Self::snapshot`] then [`write_file`]).
    pub fn persist(&self) -> std::io::Result<()> {
        let (path, bytes) = self.snapshot()?;
        write_file(&path, &bytes)
    }
}

/// Writes `bytes` to `path`: a temporary file, synced, renamed over it.
pub fn write_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

/// Keeps at most [`MAX_PORTS_PER_HOST`]: open ports first (lowest first),
/// then the most recently closed; sorted by port.
fn cap_ports(ports: &mut Vec<PortEntry>) {
    if ports.len() > MAX_PORTS_PER_HOST {
        ports.sort_by_key(|e| match e.closed_at {
            None => (0, 0, e.port),
            Some(t) => (1, u64::MAX - t, e.port),
        });
        ports.truncate(MAX_PORTS_PER_HOST);
    }
    ports.sort_by_key(|e| e.port);
}

/// A first instant after `from` (Unix seconds) at which the local clock,
/// `offset` seconds east of UTC, reads `hour:minute`.
pub fn next_run(from: i64, offset: i64, (hour, minute): (u8, u8)) -> i64 {
    const DAY: i64 = 86_400;
    let local = from + offset;
    let mut at = local - local.rem_euclid(DAY) + i64::from(hour) * 3600 + i64::from(minute) * 60;
    if at <= local {
        at += DAY;
    }
    at - offset
}

/// `+0530` / `-0800` as seconds east of UTC.
fn parse_offset(z: &str) -> Option<i64> {
    let (sign, rest) = match z.as_bytes().first()? {
        b'+' => (1, &z[1..]),
        b'-' => (-1, &z[1..]),
        _ => return None,
    };
    if rest.len() != 4 || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let h: i64 = rest[..2].parse().ok()?;
    let m: i64 = rest[2..].parse().ok()?;
    Some(sign * (h * 3600 + m * 60))
}

/// The current UTC offset of time zone `tz` (`system.timezone`), from
/// `date +%z` with `TZ` set (the image does not set its own zone, so the
/// configured one is asked for by name); 0 when that fails.
pub fn tz_offset(tz: &str) -> i64 {
    let mut cmd = std::process::Command::new("date");
    cmd.arg("+%z").env("TZ", tz);
    if std::env::var_os("TZDIR").is_none() && std::path::Path::new("/etc/zoneinfo").is_dir() {
        // NixOS keeps tzdata there, not in /usr/share/zoneinfo
        cmd.env("TZDIR", "/etc/zoneinfo");
    }
    let got = cmd
        .output()
        .ok()
        .and_then(|o| parse_offset(String::from_utf8_lossy(&o.stdout).trim()));
    if got.is_none() {
        tracing::warn!(timezone = tz, "no UTC offset for the time zone; using UTC");
    }
    got.unwrap_or(0)
}

/// One host to scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// Lowercase MAC: the results' key.
    pub mac: String,
    /// The address scanned.
    pub ip: Ipv4Addr,
    /// The internal interface id it was seen on.
    pub interface: String,
}

/// What the applied document says about scanning.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Plan {
    enabled: bool,
    time: (u8, u8),
    ports: Vec<u16>,
    timezone: String,
    internal: Vec<InternalIf>,
    quarantine: BTreeSet<String>,
    own: BTreeSet<IpAddr>,
}

impl Plan {
    fn from_doc(doc: &Document, own: &[IpAddr]) -> Self {
        use sensr_schema::models::firewall::HostModeKind;
        let p = &doc.hosts.portscan;
        let internal = internal_interfaces(doc);
        // the live link addresses, and the configured static ones in case
        // a link has not got its address yet
        let own = own
            .iter()
            .copied()
            .chain(doc.interfaces.iter().filter_map(|(_, i)| match &i.ipv4 {
                sensr_schema::models::interfaces::Ipv4Config::Static { address, .. } => {
                    Some(IpAddr::V4(address.addr()))
                }
                _ => None,
            }))
            .collect();
        Self {
            enabled: p.enabled,
            time: p.hour_minute().unwrap_or((3, 30)),
            ports: port_list(&p.extra()),
            timezone: doc.system.timezone.to_string(),
            internal,
            quarantine: doc
                .firewall
                .host_modes
                .values()
                .filter(|h| h.enabled && h.mode == HostModeKind::Quarantine)
                .map(|h| h.mac.to_string().to_ascii_lowercase())
                .collect(),
            own,
        }
    }
}

/// Whether `h` may be scanned at all: a MAC and an IPv4 address inside one
/// of its internal interface's networks (never a WAN or a remote address),
/// not in Quarantine, not one of the router's own addresses, and a usable
/// unicast address.
fn eligible(
    h: &Host,
    internal: &[InternalIf],
    quarantine: &BTreeSet<String>,
    own: &BTreeSet<IpAddr>,
) -> Option<Target> {
    let mac = h.mac.as_deref()?.to_ascii_lowercase();
    let ip = h.ipv4?;
    let iface = h.interface.as_deref()?;
    let on = internal.iter().find(|i| i.id == iface)?;
    let inside = on.subnets.is_empty() || on.subnets.iter().any(|n| n.contains(&ip));
    let usable = inside
        && !(ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_broadcast()
            || ip.is_multicast()
            || on
                .subnets
                .iter()
                .any(|n| n.prefix_len() < 31 && (n.network() == ip || n.broadcast() == ip)));
    if !usable || quarantine.contains(&mac) || own.contains(&IpAddr::V4(ip)) {
        return None;
    }
    Some(Target {
        mac,
        ip,
        interface: iface.to_owned(),
    })
}

/// The daily scan's hosts: [`eligible`] ones seen within
/// [`TARGET_SEEN_SECS`] of `now`.
pub fn targets(
    hosts: &[Host],
    internal: &[InternalIf],
    quarantine: &BTreeSet<String>,
    own: &BTreeSet<IpAddr>,
    now: u64,
) -> Vec<Target> {
    hosts
        .iter()
        .filter(|h| {
            h.last_seen
                .is_some_and(|t| now.saturating_sub(t) <= TARGET_SEEN_SECS)
        })
        .filter_map(|h| eligible(h, internal, quarantine, own))
        .collect()
}

/// Why "scan now" did not start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ScanNowError {
    /// That host is being scanned already.
    #[error("a scan of this host is already running")]
    Busy,
    /// [`MAX_SCAN_NOW`] scans are running already.
    #[error("too many scans are running")]
    TooMany,
    /// No such MAC in the inventory.
    #[error("no such host")]
    Unknown,
    /// A known host the router does not scan (no IPv4 address, not on an
    /// internal network, in Quarantine, or the router itself).
    #[error(
        "this host cannot be scanned: it needs an IPv4 address on an internal network and must not be quarantined"
    )]
    NotScannable,
    /// No document applied yet, or the service stopped.
    #[error("the port scanner is not running")]
    NotReady,
}

/// The inventory as the scanner reads it.
pub trait HostSource: Send + Sync {
    /// Every row (once per sweep).
    fn hosts(&self) -> Vec<Host>;
    /// The row with this MAC (any case).
    fn host(&self, mac: &str) -> Option<Host>;
}

impl HostSource for std::sync::Weak<crate::hosts::HostCollector> {
    fn hosts(&self) -> Vec<Host> {
        self.upgrade().map(|h| h.hosts()).unwrap_or_default()
    }
    fn host(&self, mac: &str) -> Option<Host> {
        self.upgrade()?.host(mac)
    }
}

impl HostSource for Mutex<Vec<Host>> {
    fn hosts(&self) -> Vec<Host> {
        lock(self).clone()
    }
    fn host(&self, mac: &str) -> Option<Host> {
        lock(self)
            .iter()
            .find(|h| {
                h.mac
                    .as_deref()
                    .is_some_and(|m| m.eq_ignore_ascii_case(mac))
            })
            .cloned()
    }
}

/// Unix seconds now.
pub type NowFn = dyn Fn() -> u64 + Send + Sync;
/// The UTC offset of a time zone, seconds east.
pub type OffsetFn = dyn Fn(&str) -> i64 + Send + Sync;

/// A missed daily sweep (the agent was down at its time and the last one is
/// over a day old) runs this long after start, not during boot.
pub const CATCH_UP_DELAY_SECS: u64 = 300;

struct State {
    plan: Option<Plan>,
    /// Hosts being scanned now (daily or scan-now), by MAC.
    running: BTreeSet<String>,
    /// Scan-now jobs running.
    scan_now: usize,
    /// When the service was made.
    started: u64,
    /// The schedule counts from here: the next run is the first
    /// `hosts.portscan.time` after it.
    anchor: u64,
    /// A daily sweep that started at this time and has not finished; hosts
    /// scanned since are skipped when it resumes after a cancel.
    sweep_since: Option<u64>,
    /// Set to cancel every scan in flight; replaced after each cancel.
    cancel: Arc<AtomicBool>,
    stopped: bool,
}

/// Marks a host running for as long as it lives (and, for scan-now, holds
/// one of the [`MAX_SCAN_NOW`] slots).
struct Running<'a> {
    state: &'a Mutex<State>,
    mac: String,
    scan_now: bool,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let mut st = lock(self.state);
        st.running.remove(&self.mac);
        if self.scan_now {
            st.scan_now = st.scan_now.saturating_sub(1);
        }
    }
}

/// The port scan service, owned by the slice applier.
pub struct PortScan {
    scanner: Scanner,
    store: Mutex<PortStore>,
    /// Held from a snapshot of the store to the end of its write, so an
    /// older snapshot never lands after a newer one.
    writing: Mutex<()>,
    hosts: Arc<dyn HostSource>,
    now: Arc<NowFn>,
    offset: Arc<OffsetFn>,
    state: Mutex<State>,
    wake: Condvar,
    /// One host at a time per interface.
    iface_locks: Mutex<BTreeMap<String, Arc<Mutex<()>>>>,
    /// One sweep at a time.
    sweeping: Mutex<()>,
}

impl PortScan {
    /// Loads `ports.json` from `path`; scans nothing until
    /// [`Self::set_document`], and nothing daily until [`Self::start`].
    pub fn new(
        scanner: Scanner,
        path: PathBuf,
        hosts: Arc<dyn HostSource>,
        now: Arc<NowFn>,
        offset: Arc<OffsetFn>,
    ) -> Arc<Self> {
        let started = now();
        Arc::new(Self {
            scanner,
            store: Mutex::new(PortStore::load(path)),
            writing: Mutex::new(()),
            hosts,
            now,
            offset,
            state: Mutex::new(State {
                plan: None,
                running: BTreeSet::new(),
                scan_now: 0,
                started,
                anchor: started,
                sweep_since: None,
                cancel: Arc::default(),
                stopped: false,
            }),
            wake: Condvar::new(),
            iface_locks: Mutex::default(),
            sweeping: Mutex::new(()),
        })
    }

    /// The production service: real connects, the system clock, the
    /// configured time zone via `date`.
    pub fn system(path: PathBuf, hosts: Arc<dyn HostSource>) -> Arc<Self> {
        let cache: Mutex<Option<(String, u64, i64)>> = Mutex::default();
        Self::new(
            Scanner::system(),
            path,
            hosts,
            Arc::new(unix_now),
            Arc::new(move |tz: &str| {
                let now = unix_now();
                if let Some((t, at, off)) = lock(&cache).as_ref()
                    && t == tz
                    && now.saturating_sub(*at) < 600
                {
                    return *off;
                }
                let off = tz_offset(tz);
                *lock(&cache) = Some((tz.to_owned(), now, off));
                off
            }),
        )
    }

    /// After an apply: the document's settings, interfaces and host modes,
    /// and the router's own addresses. Any change cancels the scans in
    /// flight (their hosts keep their previous results); an unfinished
    /// daily sweep resumes on the next tick.
    pub fn set_document(&self, doc: &Document, own: &[IpAddr]) {
        let plan = Plan::from_doc(doc, own);
        let mut st = lock(&self.state);
        if st.stopped || st.plan.as_ref() == Some(&plan) {
            return;
        }
        if st.plan.is_some() {
            st.cancel.store(true, Ordering::SeqCst);
            st.cancel = Arc::default();
        }
        if !plan.enabled {
            st.sweep_since = None;
        }
        st.plan = Some(plan);
        drop(st);
        self.wake.notify_all();
    }

    /// Starts the schedule thread.
    pub fn start(self: &Arc<Self>) {
        let s = Arc::clone(self);
        let r = std::thread::Builder::new()
            .name("sensr-portscan-sched".into())
            .spawn(move || {
                loop {
                    s.tick();
                    let st = lock(&s.state);
                    if st.stopped {
                        return;
                    }
                    let (st, _) = s
                        .wake
                        .wait_timeout(st, TICK)
                        .unwrap_or_else(|e| e.into_inner());
                    if st.stopped {
                        return;
                    }
                }
            });
        if let Err(e) = r {
            tracing::error!(error = %e, "port scan schedule not started");
        }
    }

    /// Stops for good: scans in flight are cancelled (nothing partial is
    /// saved) and nothing new starts.
    pub fn stop(&self) {
        let mut st = lock(&self.state);
        st.stopped = true;
        st.cancel.store(true, Ordering::SeqCst);
        drop(st);
        self.wake.notify_all();
    }

    /// One schedule check: starts the daily sweep when its time has come
    /// (or [`CATCH_UP_DELAY_SECS`] after start when the last finished one
    /// is over a day old), or resumes one a cancel interrupted, and runs it
    /// to the end (in the caller's thread).
    pub fn tick(&self) {
        let Ok(_one) = self.sweeping.try_lock() else {
            return;
        };
        let last_sweep = lock(&self.store).last_sweep;
        let (since, plan, cancel) = {
            let mut st = lock(&self.state);
            let Some(plan) = st.plan.clone().filter(|p| p.enabled && !st.stopped) else {
                return;
            };
            let now = self.now();
            if st.sweep_since.is_none() {
                let off = (self.offset)(&plan.timezone);
                let mut due = next_run(st.anchor as i64, off, plan.time);
                if last_sweep.is_some_and(|t| now.saturating_sub(t) > 86_400) {
                    due = due.min((st.started + CATCH_UP_DELAY_SECS) as i64);
                }
                if (now as i64) < due {
                    return;
                }
                st.anchor = now;
                st.sweep_since = Some(now);
            }
            (st.sweep_since.unwrap_or(now), plan, Arc::clone(&st.cancel))
        };
        if self.sweep(since, &plan, &cancel) {
            let mut st = lock(&self.state);
            if st.sweep_since == Some(since) {
                st.sweep_since = None;
            }
            drop(st);
            self.save(|s| s.last_sweep = Some(since));
        }
    }

    /// Changes the store and writes it, the write outside the store's lock.
    fn save(&self, change: impl FnOnce(&mut PortStore)) {
        let _w = lock(&self.writing);
        let snap = {
            let mut store = lock(&self.store);
            change(&mut store);
            store.snapshot()
        };
        if let Err(e) = snap.and_then(|(path, bytes)| write_file(&path, &bytes)) {
            tracing::warn!(error = %e, "saving port scan results");
        }
    }

    /// Marks `mac` running; `None` if it already is.
    fn claim(&self, mac: &str) -> Option<Running<'_>> {
        lock(&self.state)
            .running
            .insert(mac.to_owned())
            .then(|| Running {
                state: &self.state,
                mac: mac.to_owned(),
                scan_now: false,
            })
    }

    /// Scans every target not scanned since `since`: interfaces in
    /// parallel, one host at a time on each. True when it ran to the end.
    fn sweep(&self, since: u64, plan: &Plan, cancel: &AtomicBool) -> bool {
        let now = self.now();
        let hosts = self.hosts.hosts();
        let mut by_iface: BTreeMap<String, Vec<Target>> = BTreeMap::new();
        for t in targets(&hosts, &plan.internal, &plan.quarantine, &plan.own, now) {
            let done = lock(&self.store)
                .get(&t.mac)
                .is_some_and(|h| h.last_scan >= since);
            if !done {
                by_iface.entry(t.interface.clone()).or_default().push(t);
            }
        }
        drop(hosts);
        let count: usize = by_iface.values().map(Vec::len).sum();
        tracing::info!(hosts = count, "port scan started");
        std::thread::scope(|s| {
            for list in by_iface.values() {
                let r = std::thread::Builder::new()
                    .name("sensr-portscan-if".into())
                    .spawn_scoped(s, move || {
                        for t in list {
                            if cancel.load(Ordering::SeqCst) {
                                return;
                            }
                            // a scan-now of it is running: that one counts
                            if let Some(_running) = self.claim(&t.mac) {
                                self.scan_target(t, &plan.ports, cancel);
                            }
                        }
                    });
                if let Err(e) = r {
                    tracing::warn!(error = %e, "port scan of an interface not started");
                }
            }
        });
        let finished = !cancel.load(Ordering::SeqCst);
        tracing::info!(hosts = count, finished, "port scan ended");
        finished
    }

    /// Scans `t` (the caller has marked it running) under its interface's
    /// lock and saves what it found. Nothing changes after a cancel, when
    /// the router could not send, when the address moved to another host
    /// meanwhile, or when no port answered with a reset or an accept and the
    /// host was not seen within [`crate::hosts::ONLINE_SECS`] (it is
    /// probably gone). A host that is up but drops everything gets its scan
    /// time and the `all_filtered` mark, its ports untouched.
    fn scan_target(&self, t: &Target, ports: &[u16], cancel: &AtomicBool) {
        let iface = Arc::clone(
            lock(&self.iface_locks)
                .entry(t.interface.clone())
                .or_default(),
        );
        let _one = lock(&iface);
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        let recheck: BTreeSet<u16> = lock(&self.store)
            .get(&t.mac)
            .map(|h| h.open().map(|e| e.port).collect())
            .unwrap_or_default();
        let outcome = match self.scanner.scan_host(t.ip, ports, &recheck, cancel) {
            Ok(o) => o,
            Err(e) => {
                tracing::debug!(mac = %t.mac, ip = %t.ip, error = %e, "port scan without a result");
                return;
            }
        };
        let now = self.now();
        let Some(h) = self.hosts.host(&t.mac).filter(|h| h.ipv4 == Some(t.ip)) else {
            tracing::debug!(mac = %t.mac, ip = %t.ip, "address changed during the port scan; result dropped");
            return;
        };
        if !outcome.answered {
            let alive = h
                .last_seen
                .is_some_and(|s| now.saturating_sub(s) <= crate::hosts::ONLINE_SECS);
            if !alive {
                tracing::debug!(mac = %t.mac, ip = %t.ip, "no port answered and the host is not seen; result dropped");
                return;
            }
        }
        self.save(|store| {
            store.merge(&t.mac, &outcome, now);
            store.prune(now);
        });
    }

    /// Scans `mac` now in the background. Refused while that host is being
    /// scanned, while [`MAX_SCAN_NOW`] such scans run, and for a host the
    /// router does not scan; allowed when the daily scan is off.
    pub fn scan_now(self: &Arc<Self>, mac: &str) -> Result<(), ScanNowError> {
        let mac = mac.to_ascii_lowercase();
        let host = self.hosts.host(&mac);
        let mut st = lock(&self.state);
        let Some(plan) = st.plan.clone().filter(|_| !st.stopped) else {
            return Err(ScanNowError::NotReady);
        };
        if st.running.contains(&mac) {
            return Err(ScanNowError::Busy);
        }
        if st.scan_now >= MAX_SCAN_NOW {
            return Err(ScanNowError::TooMany);
        }
        let Some(host) = host else {
            return Err(ScanNowError::Unknown);
        };
        let t = eligible(&host, &plan.internal, &plan.quarantine, &plan.own)
            .ok_or(ScanNowError::NotScannable)?;
        st.running.insert(mac.clone());
        st.scan_now += 1;
        let cancel = Arc::clone(&st.cancel);
        drop(st);
        let s = Arc::clone(self);
        let r = std::thread::Builder::new()
            .name("sensr-portscan-now".into())
            .spawn(move || {
                let _running = Running {
                    state: &s.state,
                    mac: t.mac.clone(),
                    scan_now: true,
                };
                s.scan_target(&t, &plan.ports, &cancel);
            });
        if let Err(e) = r {
            tracing::warn!(error = %e, "scan now not started");
            drop(Running {
                state: &self.state,
                mac,
                scan_now: true,
            });
            return Err(ScanNowError::NotReady);
        }
        Ok(())
    }

    /// Whether `mac` is being scanned.
    pub fn scanning(&self, mac: &str) -> bool {
        lock(&self.state)
            .running
            .contains(&mac.to_ascii_lowercase())
    }

    /// `GET /api/v1/hosts/<mac>/ports`: `{last_scan, scanning, all_filtered,
    /// ports}` with the open ports only (`port`, `service`, `first_seen`,
    /// `last_seen`, `new`); `last_scan` is `null` before the first scan.
    /// `None` for a MAC that is not in the inventory.
    pub fn view(&self, mac: &str) -> Option<serde_json::Value> {
        self.hosts.host(mac)?;
        let now = self.now();
        let r = self.ports(&mac.to_ascii_lowercase()).unwrap_or_default();
        let ports: Vec<serde_json::Value> = r
            .open()
            .map(|p| {
                serde_json::json!({
                    "port": p.port,
                    "service": p.service,
                    "first_seen": p.first_seen,
                    "last_seen": p.last_seen,
                    "new": p.is_new(now),
                })
            })
            .collect();
        Some(serde_json::json!({
            "last_scan": (r.last_scan != 0).then_some(r.last_scan),
            "scanning": self.scanning(mac),
            "all_filtered": r.all_filtered,
            "ports": ports,
        }))
    }

    /// How many ports `mac` has open as of its last scan; `None` when it was
    /// never scanned.
    pub fn open_count(&self, mac: &str) -> Option<u32> {
        let r = self.ports(&mac.to_ascii_lowercase())?;
        (r.last_scan != 0).then(|| u32::try_from(r.open().count()).unwrap_or(u32::MAX))
    }

    /// `mac`'s results.
    pub fn ports(&self, mac: &str) -> Option<HostPorts> {
        lock(&self.store).get(mac).cloned()
    }

    fn now(&self) -> u64 {
        (self.now)()
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests;
