#![cfg(feature = "daemon")]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sensr_scan::config::PaceLimits;
use sensr_scan::pace::Pacer;
use sensr_scan::tcp::{Connector, PortState, scan_tcp, scan_tcp_with};
use tokio_util::sync::CancellationToken;

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn fast() -> Pacer {
    Pacer::new(PaceLimits {
        connects_per_sec: 100_000,
        in_flight: 64,
    })
}

#[tokio::test]
async fn finds_open_listeners() {
    let mut listeners = Vec::new();
    let mut ports = Vec::new();
    for _ in 0..3 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        ports.push(l.local_addr().unwrap().port());
        listeners.push(l);
    }
    let mut open_expected = ports.clone();
    open_expected.sort_unstable();
    for _ in 0..3 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        ports.push(l.local_addr().unwrap().port());
    }
    let progress = AtomicU32::new(0);
    let r = scan_tcp(LO, &ports, &fast(), &CancellationToken::new(), &progress).await;
    assert_eq!(r.open, open_expected);
    assert_eq!(r.done, 6);
    assert_eq!(progress.load(Ordering::Relaxed), 6);
    assert_eq!(r.filtered, 0);
    assert!(!r.all_open);
}

#[tokio::test]
async fn pacer_limits_rate() {
    let pacer = Arc::new(Pacer::new(PaceLimits {
        connects_per_sec: 50,
        in_flight: 4,
    }));
    let cur = Arc::new(AtomicUsize::new(0));
    let max = Arc::new(AtomicUsize::new(0));
    let start = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..100 {
        let permit = pacer.permit().await;
        let (cur, max) = (cur.clone(), max.clone());
        tasks.push(tokio::spawn(async move {
            let n = cur.fetch_add(1, Ordering::SeqCst) + 1;
            max.fetch_max(n, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(30)).await;
            cur.fetch_sub(1, Ordering::SeqCst);
            drop(permit);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert!(
        start.elapsed() >= Duration::from_millis(1800),
        "{:?}",
        start.elapsed()
    );
    assert!(max.load(Ordering::SeqCst) <= 4);
}

#[tokio::test]
async fn cancel_stops_early() {
    let pacer = Pacer::new(PaceLimits {
        connects_per_sec: 200,
        in_flight: 16,
    });
    let ports: Vec<u16> = (1..=5000).collect();
    let cancel = CancellationToken::new();
    let c2 = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        c2.cancel();
    });
    let progress = AtomicU32::new(0);
    let r = scan_tcp(LO, &ports, &pacer, &cancel, &progress).await;
    assert!(r.done < ports.len() as u32, "done {}", r.done);
}

struct AlwaysOpen;
impl Connector for AlwaysOpen {
    async fn connect(&self, _addr: SocketAddr, _t: Duration) -> io::Result<()> {
        Ok(())
    }
}

struct Silent;
impl Connector for Silent {
    async fn connect(&self, _addr: SocketAddr, t: Duration) -> io::Result<()> {
        tokio::time::sleep(t).await;
        Err(io::ErrorKind::TimedOut.into())
    }
}

#[tokio::test]
async fn all_open_capped() {
    let ports: Vec<u16> = (1..=2000).collect();
    let progress = AtomicU32::new(0);
    let r = scan_tcp_with(
        &Arc::new(AlwaysOpen),
        LO,
        &ports,
        &fast(),
        &CancellationToken::new(),
        &progress,
    )
    .await;
    assert_eq!(r.open.len(), 1000);
    assert!(r.all_open);
}

#[tokio::test]
async fn timeouts_are_filtered() {
    let ports = [10u16, 20, 30];
    let progress = AtomicU32::new(0);
    let r = scan_tcp_with(
        &Arc::new(Silent),
        LO,
        &ports,
        &fast(),
        &CancellationToken::new(),
        &progress,
    )
    .await;
    assert!(r.open.is_empty());
    assert_eq!(r.filtered, 3);
    assert_eq!(r.done, 3);
}

#[test]
fn port_state_serde() {
    assert_eq!(
        serde_json::to_string(&PortState::OpenFiltered).unwrap(),
        "\"open_filtered\""
    );
}
