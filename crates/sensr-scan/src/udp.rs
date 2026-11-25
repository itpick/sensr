//! Paced UDP scan: service probes first, then an empty-datagram sweep.
//!
//! Each port gets its own connected [`UdpSocket`], so the kernel reports an
//! ICMP port unreachable as `ECONNREFUSED`:
//! - any reply → [`PortState::Open`] (parsed by the port's probes);
//! - `ECONNREFUSED` → [`PortState::Closed`];
//! - no answer within 1 s, twice → [`PortState::OpenFiltered`].
//!
//! Datagrams to one target never exceed [`UDP_PORTS_PER_SEC`], whatever the
//! scan's pace, so hosts do not start dropping ICMP replies; the cap covers
//! retries too.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::config::PaceLimits;
use crate::pace::{Pacer, PacerPermit};
use crate::ports::top_udp;
pub use crate::types::{Ident, PortState};
use crate::udp_probes::{PROBES, UdpProbe, probes_for};

/// Datagrams per second to one target, retries included.
pub const UDP_PORTS_PER_SEC: u32 = 20;
/// Sends outstanding at once under the UDP cap.
const UDP_IN_FLIGHT: u16 = 8;
/// How long to wait for a reply after each try.
const WAIT: Duration = Duration::from_secs(1);
/// First try plus one retry.
const TRIES: usize = 2;
/// After the first reply, how long to keep reading further replies (a port
/// with several probes, or a multi-datagram answer).
const GRACE: Duration = Duration::from_millis(250);
/// Most replies read per port.
const MAX_REPLIES: usize = 8;
const BUF: usize = 16 * 1024;

/// Result of a UDP scan of one host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UdpResult {
    /// Every port probed to completion, sorted by port.
    pub ports: Vec<(u16, PortState, Option<Ident>)>,
    /// Ports probed to completion.
    pub done: u32,
}

/// The scan order: probe ports in [`PROBES`] order, then the rest of
/// [`top_udp`].
pub fn udp_order() -> Vec<u16> {
    let mut seen = HashSet::new();
    PROBES
        .iter()
        .map(|p| p.port)
        .chain(top_udp().iter().copied())
        .filter(|p| seen.insert(*p))
        .collect()
}

/// Scan [`udp_order`] on `ip`.
pub async fn scan_udp(
    ip: IpAddr,
    pacer: &Pacer,
    cancel: &CancellationToken,
    progress: &AtomicU32,
) -> UdpResult {
    scan_udp_ports(ip, &udp_order(), pacer, cancel, progress).await
}

/// Scan `ports` (duplicates dropped) on `ip`. Ports with a probe in
/// [`PROBES`] get its payloads; the rest get an empty datagram.
///
/// `pacer` bounds ports in flight as for TCP; on top of it every datagram
/// waits for a per-target [`UDP_PORTS_PER_SEC`] permit.
pub async fn scan_udp_ports(
    ip: IpAddr,
    ports: &[u16],
    pacer: &Pacer,
    cancel: &CancellationToken,
    progress: &AtomicU32,
) -> UdpResult {
    let cap = Arc::new(Pacer::new(PaceLimits {
        connects_per_sec: UDP_PORTS_PER_SEC,
        in_flight: UDP_IN_FLIGHT,
    }));
    let mut seen = HashSet::new();
    let mut res = UdpResult::default();
    let mut set: JoinSet<(u16, PortState, Option<Ident>)> = JoinSet::new();

    for &port in ports.iter().filter(|p| seen.insert(**p)) {
        let permit: PacerPermit = tokio::select! {
            () = cancel.cancelled() => break,
            p = pacer.permit() => p,
        };
        let cap = Arc::clone(&cap);
        set.spawn(async move {
            let (st, id) = probe(SocketAddr::new(ip, port), &cap).await;
            drop(permit);
            (port, st, id)
        });
        while let Some(joined) = set.try_join_next() {
            absorb(&mut res, joined, progress);
        }
    }
    loop {
        let joined = tokio::select! {
            () = cancel.cancelled() => { set.abort_all(); break; }
            j = set.join_next() => j,
        };
        match joined {
            Some(j) => absorb(&mut res, j, progress),
            None => break,
        }
    }
    res.ports.sort_unstable_by_key(|p| p.0);
    res
}

fn absorb(
    res: &mut UdpResult,
    joined: Result<(u16, PortState, Option<Ident>), tokio::task::JoinError>,
    progress: &AtomicU32,
) {
    let Ok(p) = joined else { return };
    res.done += 1;
    progress.fetch_add(1, Ordering::Relaxed);
    res.ports.push(p);
}

/// What one socket error says about the port.
fn refused(e: &io::Error) -> PortState {
    if e.kind() == io::ErrorKind::ConnectionRefused {
        PortState::Closed
    } else {
        PortState::Filtered
    }
}

async fn probe(addr: SocketAddr, cap: &Pacer) -> (PortState, Option<Ident>) {
    let probes: Vec<&'static UdpProbe> = probes_for(addr.port()).collect();
    let payloads: Vec<Vec<u8>> = if probes.is_empty() {
        vec![Vec::new()]
    } else {
        probes.iter().map(|p| (p.payload)()).collect()
    };
    let local: IpAddr = match addr {
        SocketAddr::V4(_) => Ipv4Addr::UNSPECIFIED.into(),
        SocketAddr::V6(_) => Ipv6Addr::UNSPECIFIED.into(),
    };
    let sock = match UdpSocket::bind(SocketAddr::new(local, 0)).await {
        Ok(s) => s,
        Err(e) => return (refused(&e), None),
    };
    if let Err(e) = sock.connect(addr).await {
        return (refused(&e), None);
    }
    let mut buf = vec![0u8; BUF];
    for _ in 0..TRIES {
        for p in &payloads {
            let slot = cap.permit().await;
            let sent = sock.send(p).await;
            drop(slot);
            if let Err(e) = sent {
                return (refused(&e), None);
            }
        }
        match tokio::time::timeout(WAIT, sock.recv(&mut buf)).await {
            Err(_) => {}
            Ok(Ok(n)) => {
                let mut id = identify(&probes, &buf[..n]);
                let until = Instant::now() + GRACE;
                for _ in 1..MAX_REPLIES {
                    match tokio::time::timeout_at(until, sock.recv(&mut buf)).await {
                        Ok(Ok(n)) => merge(&mut id, identify(&probes, &buf[..n])),
                        _ => break,
                    }
                }
                return (PortState::Open, id);
            }
            Ok(Err(e)) => return (refused(&e), None),
        }
    }
    (PortState::OpenFiltered, None)
}

/// Every probe's reading of one reply, merged in probe order.
fn identify(probes: &[&UdpProbe], reply: &[u8]) -> Option<Ident> {
    let mut id = None;
    for p in probes {
        merge(&mut id, (p.parse)(reply));
    }
    id
}

/// Fill the fields `into` lacks from `from`.
fn merge(into: &mut Option<Ident>, from: Option<Ident>) {
    let Some(f) = from else { return };
    let Some(i) = into else {
        *into = Some(f);
        return;
    };
    i.product = i.product.take().or(f.product);
    i.version = i.version.take().or(f.version);
    i.title = i.title.take().or(f.title);
    i.tls = i.tls.take().or(f.tls);
    i.banner = i.banner.take().or(f.banner);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(p: Option<&str>, t: Option<&str>, b: Option<&str>) -> Ident {
        Ident {
            product: p.map(Into::into),
            title: t.map(Into::into),
            banner: b.map(Into::into),
            ..Ident::default()
        }
    }

    #[test]
    fn udp_merge_fills_only_missing_fields() {
        let mut a = None;
        merge(&mut a, None);
        assert_eq!(a, None);
        merge(&mut a, Some(id(None, None, Some("services"))));
        merge(
            &mut a,
            Some(id(Some("Chromecast"), Some("TV"), Some("other"))),
        );
        assert_eq!(
            a,
            Some(id(Some("Chromecast"), Some("TV"), Some("services")))
        );
    }

    #[test]
    fn udp_identify_tries_every_probe_of_the_port() {
        let probes: Vec<_> = probes_for(5353).collect();
        assert_eq!(probes.len(), 2);
        assert_eq!(identify(&probes, b"junk"), None);
    }
}
