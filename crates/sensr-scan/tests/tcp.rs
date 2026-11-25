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
    let r = scan_tcp(
        LO,
        &ports,
        &fast(),
        &CancellationToken::new(),
        &progress,
        None,
    )
    .await;
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
    let r = scan_tcp(LO, &ports, &pacer, &cancel, &progress, None).await;
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
        None,
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
        None,
    )
    .await;
    assert!(r.open.is_empty());
    assert_eq!(r.filtered, 3);
    assert_eq!(r.done, 3);
}

/// Times out at once on even ports, refuses odd ones; counts every call.
struct HalfSilent(AtomicUsize);
impl Connector for HalfSilent {
    async fn connect(&self, addr: SocketAddr, _t: Duration) -> io::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        if addr.port().is_multiple_of(2) {
            Err(io::ErrorKind::TimedOut.into())
        } else {
            Err(io::ErrorKind::ConnectionRefused.into())
        }
    }
}

#[tokio::test]
async fn retries_take_rate_tokens() {
    // 100 ports, half time out and are retried: 150 connects at 100/s is
    // at least 1.49 s; unpaced retries would finish in ~1 s.
    let pacer = Pacer::new(PaceLimits {
        connects_per_sec: 100,
        in_flight: 64,
    });
    let c = Arc::new(HalfSilent(AtomicUsize::new(0)));
    let ports: Vec<u16> = (1..=100).collect();
    let progress = AtomicU32::new(0);
    let t = Instant::now();
    let r = scan_tcp_with(
        &c,
        LO,
        &ports,
        &pacer,
        &CancellationToken::new(),
        &progress,
        None,
    )
    .await;
    let elapsed = t.elapsed();
    let calls = c.0.load(Ordering::SeqCst);
    assert_eq!(calls, 150);
    assert_eq!(r.filtered, 50);
    #[allow(clippy::cast_precision_loss)]
    let rate = (calls - 1) as f64 / elapsed.as_secs_f64();
    assert!(rate <= 101.0, "{rate:.1} connects/s over {elapsed:?}");
}

struct PanicOn(u16);
impl Connector for PanicOn {
    async fn connect(&self, addr: SocketAddr, _t: Duration) -> io::Result<()> {
        assert_ne!(addr.port(), self.0, "connector broke");
        Err(io::ErrorKind::ConnectionRefused.into())
    }
}

#[tokio::test]
async fn panicked_probe_is_filtered_and_counted() {
    let progress = AtomicU32::new(0);
    let r = scan_tcp_with(
        &Arc::new(PanicOn(20)),
        LO,
        &[10, 20, 30],
        &fast(),
        &CancellationToken::new(),
        &progress,
        None,
    )
    .await;
    assert_eq!(r.done, 3);
    assert_eq!(progress.load(Ordering::Relaxed), 3);
    assert_eq!(r.filtered, 1);
}

struct Unreachable;
impl Connector for Unreachable {
    async fn connect(&self, _addr: SocketAddr, _t: Duration) -> io::Result<()> {
        Err(io::ErrorKind::HostUnreachable.into())
    }
}

#[tokio::test]
async fn unreachable_is_filtered_and_counted() {
    let progress = AtomicU32::new(0);
    let r = scan_tcp_with(
        &Arc::new(Unreachable),
        LO,
        &[10, 20, 30],
        &fast(),
        &CancellationToken::new(),
        &progress,
        None,
    )
    .await;
    assert_eq!((r.filtered, r.unreachable, r.replied), (3, 3, 0));
    let r = scan_tcp_with(
        &Arc::new(PanicOn(0)),
        LO,
        &[10, 20],
        &fast(),
        &CancellationToken::new(),
        &progress,
        None,
    )
    .await;
    assert_eq!((r.unreachable, r.replied), (0, 2));
}

/// Records the longest timeout it was given.
struct Timeouts(std::sync::Mutex<Duration>);
impl Connector for Timeouts {
    async fn connect(&self, _addr: SocketAddr, t: Duration) -> io::Result<()> {
        let mut m = self.0.lock().unwrap();
        *m = (*m).max(t);
        Err(io::ErrorKind::TimedOut.into())
    }
}

#[tokio::test]
async fn discovery_rtt_seeds_the_timeout() {
    let progress = AtomicU32::new(0);
    let run = |seed| {
        let c = Arc::new(Timeouts(std::sync::Mutex::new(Duration::ZERO)));
        let progress = &progress;
        async move {
            scan_tcp_with(
                &c,
                LO,
                &[10, 20],
                &fast(),
                &CancellationToken::new(),
                progress,
                seed,
            )
            .await;
            *c.0.lock().unwrap()
        }
    };
    assert_eq!(run(None).await, Duration::from_secs(2));
    assert_eq!(
        run(Some(Duration::from_millis(5))).await,
        Duration::from_millis(300)
    );
    assert_eq!(
        run(Some(Duration::from_millis(200))).await,
        Duration::from_millis(600)
    );
}

#[test]
fn port_state_serde() {
    assert_eq!(
        serde_json::to_string(&PortState::OpenFiltered).unwrap(),
        "\"open_filtered\""
    );
}
