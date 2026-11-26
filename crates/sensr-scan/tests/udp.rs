#![cfg(feature = "daemon")]

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sensr_scan::config::PaceLimits;
use sensr_scan::pace::Pacer;
use sensr_scan::ports::top_udp;
use sensr_scan::types::PortState;
use sensr_scan::udp::{UDP_PORTS_PER_SEC, scan_udp_ports, udp_order};
use sensr_scan::udp_probes::PROBES;
use tokio_util::sync::CancellationToken;

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn fast() -> Pacer {
    Pacer::new(PaceLimits {
        connects_per_sec: 100_000,
        in_flight: 64,
    })
}

/// A server on an ephemeral port; `reply` decides whether it answers.
/// Returns its port and a counter of datagrams it received.
fn server(reply: bool) -> (u16, Arc<AtomicUsize>) {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = s.local_addr().unwrap().port();
    let seen = Arc::new(AtomicUsize::new(0));
    let n = Arc::clone(&seen);
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((len, from)) = s.recv_from(&mut buf) {
            n.fetch_add(1, Ordering::SeqCst);
            if reply {
                s.send_to(&buf[..len], from).ok();
            }
        }
    });
    (port, seen)
}

fn closed_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap().port()
}

fn state(r: &sensr_scan::udp::UdpResult, port: u16) -> PortState {
    r.ports
        .iter()
        .find(|p| p.0 == port)
        .expect("port in result")
        .1
}

#[tokio::test]
async fn udp_echo_server_is_open() {
    let (port, seen) = server(true);
    let progress = AtomicU32::new(0);
    let r = scan_udp_ports(LO, &[port], &fast(), &CancellationToken::new(), &progress).await;
    assert_eq!(state(&r, port), PortState::Open);
    assert_eq!(r.ports[0].2, None, "no probe for an ephemeral port");
    assert_eq!(r.done, 1);
    assert_eq!(progress.load(Ordering::Relaxed), 1);
    assert_eq!(seen.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn udp_closed_port_is_closed() {
    let port = closed_port();
    let r = scan_udp_ports(
        LO,
        &[port],
        &fast(),
        &CancellationToken::new(),
        &AtomicU32::new(0),
    )
    .await;
    assert_eq!(state(&r, port), PortState::Closed);
}

#[tokio::test]
async fn udp_silent_port_is_open_filtered_after_one_retry() {
    let (port, seen) = server(false);
    let t = Instant::now();
    let r = scan_udp_ports(
        LO,
        &[port],
        &fast(),
        &CancellationToken::new(),
        &AtomicU32::new(0),
    )
    .await;
    assert_eq!(state(&r, port), PortState::OpenFiltered);
    let took = t.elapsed();
    assert!(took >= Duration::from_millis(1900), "{took:?}");
    assert!(took < Duration::from_secs(4), "{took:?}");
    assert_eq!(seen.load(Ordering::SeqCst), 2, "first try plus one retry");
}

#[tokio::test]
async fn udp_mixed_ports_sorted_and_counted() {
    let (open, _) = server(true);
    let (quiet, _) = server(false);
    let closed = closed_port();
    let progress = AtomicU32::new(0);
    let r = scan_udp_ports(
        LO,
        &[quiet, open, closed, open],
        &fast(),
        &CancellationToken::new(),
        &progress,
    )
    .await;
    assert_eq!(r.done, 3, "duplicates probed once");
    assert_eq!(progress.load(Ordering::Relaxed), 3);
    let ports: Vec<u16> = r.ports.iter().map(|p| p.0).collect();
    let mut sorted = vec![open, quiet, closed];
    sorted.sort_unstable();
    assert_eq!(ports, sorted);
    assert_eq!(state(&r, open), PortState::Open);
    assert_eq!(state(&r, quiet), PortState::OpenFiltered);
    assert_eq!(state(&r, closed), PortState::Closed);
}

#[tokio::test]
async fn udp_rate_is_capped_regardless_of_pacer() {
    // 25 echo servers = 25 datagrams; at 20/s the last can go no sooner than
    // 24 intervals of 50 ms after the first, even with a 100k/s pacer.
    let mut ports = Vec::new();
    let mut keep = Vec::new();
    for _ in 0..25 {
        let (p, seen) = server(true);
        ports.push(p);
        keep.push(seen);
    }
    assert_eq!(UDP_PORTS_PER_SEC, 20);
    let t = Instant::now();
    let r = scan_udp_ports(
        LO,
        &ports,
        &fast(),
        &CancellationToken::new(),
        &AtomicU32::new(0),
    )
    .await;
    assert!(
        t.elapsed() >= Duration::from_millis(1150),
        "{:?}",
        t.elapsed()
    );
    assert!(r.ports.iter().all(|p| p.1 == PortState::Open));
}

#[tokio::test]
async fn udp_retries_go_through_the_rate_cap() {
    // 30 silent ports: first tries go out over 0..1.45 s and their retries
    // from 1 s on, so they contend. Paced, 60 datagrams need 59 x 50 ms
    // = 2.95 s of sending plus the last 1 s wait (>= 3.95 s); retries that
    // skipped the cap would finish at ~3.45 s.
    let servers: Vec<(u16, Arc<AtomicUsize>)> = (0..30).map(|_| server(false)).collect();
    let ports: Vec<u16> = servers.iter().map(|s| s.0).collect();
    let t = Instant::now();
    let r = scan_udp_ports(
        LO,
        &ports,
        &fast(),
        &CancellationToken::new(),
        &AtomicU32::new(0),
    )
    .await;
    assert!(
        t.elapsed() >= Duration::from_millis(3800),
        "{:?}",
        t.elapsed()
    );
    assert!(r.ports.iter().all(|p| p.1 == PortState::OpenFiltered));
    let sent: usize = servers.iter().map(|s| s.1.load(Ordering::SeqCst)).sum();
    assert_eq!(sent, 60);
}

#[tokio::test]
async fn udp_cancel_stops_early() {
    let ports: Vec<u16> = (0..40).map(|_| server(false).0).collect();
    let cancel = CancellationToken::new();
    let c = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        c.cancel();
    });
    let t = Instant::now();
    let r = scan_udp_ports(LO, &ports, &fast(), &cancel, &AtomicU32::new(0)).await;
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert!(r.done < 40);
}

#[test]
fn udp_order_is_probes_then_top_udp() {
    let o = udp_order();
    let mut probe_ports: Vec<u16> = Vec::new();
    for p in PROBES {
        if !probe_ports.contains(&p.port) {
            probe_ports.push(p.port);
        }
    }
    assert_eq!(&o[..probe_ports.len()], &probe_ports[..]);
    let rest: Vec<u16> = top_udp()
        .iter()
        .copied()
        .filter(|p| !probe_ports.contains(p))
        .collect();
    assert_eq!(&o[probe_ports.len()..], &rest[..]);
}
