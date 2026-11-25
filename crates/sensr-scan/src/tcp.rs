//! Paced TCP connect scan.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::pace::{Pacer, PacerPermit};
pub use crate::types::PortState;

/// Recording stops once more ports than this are open.
const MAX_OPEN: usize = 1000;
/// Floor and ceiling of the adaptive connect timeout.
const MIN_TIMEOUT: Duration = Duration::from_millis(300);
const MAX_TIMEOUT: Duration = Duration::from_secs(2);
/// How many early replies feed the RTT median.
const RTT_SAMPLES: usize = 16;

/// Result of scanning one host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpResult {
    /// Open ports, sorted.
    pub open: Vec<u16>,
    /// Ports that never answered.
    pub filtered: u32,
    /// More than 1,000 ports were open; the scan stopped recording.
    pub all_open: bool,
    /// Ports probed to completion.
    pub done: u32,
}

/// One connection attempt. `Ok` means accepted; `ConnectionRefused` means
/// closed; `TimedOut` means no answer within `t`.
pub trait Connector: Sync {
    fn connect(&self, addr: SocketAddr, t: Duration)
    -> impl Future<Output = io::Result<()>> + Send;
}

/// Real sockets via tokio.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioConnector;

impl Connector for TokioConnector {
    async fn connect(&self, addr: SocketAddr, t: Duration) -> io::Result<()> {
        match tokio::time::timeout(t, tokio::net::TcpStream::connect(addr)).await {
            Ok(r) => r.map(drop),
            Err(_) => Err(io::ErrorKind::TimedOut.into()),
        }
    }
}

/// Adaptive timeout: 3x the median RTT of the first replies, clamped.
#[derive(Debug)]
struct Rtt {
    samples: Mutex<Vec<Duration>>,
}

impl Rtt {
    fn timeout(&self) -> Duration {
        let s = self.samples.lock().expect("rtt lock");
        if s.is_empty() {
            return MAX_TIMEOUT;
        }
        let mut v = s.clone();
        v.sort_unstable();
        (v[v.len() / 2] * 3).clamp(MIN_TIMEOUT, MAX_TIMEOUT)
    }

    fn record(&self, d: Duration) {
        let mut s = self.samples.lock().expect("rtt lock");
        if s.len() < RTT_SAMPLES {
            s.push(d);
        }
    }
}

async fn probe<C: Connector>(c: &C, addr: SocketAddr, rtt: &Rtt) -> PortState {
    for _ in 0..2 {
        let t = rtt.timeout();
        let started = tokio::time::Instant::now();
        match c.connect(addr, t).await {
            Ok(()) => {
                rtt.record(started.elapsed());
                return PortState::Open;
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                rtt.record(started.elapsed());
                return PortState::Closed;
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
            Err(_) => return PortState::Filtered,
        }
    }
    PortState::Filtered
}

/// Scan `ports` on `ip` with real sockets.
pub async fn scan_tcp(
    ip: IpAddr,
    ports: &[u16],
    pacer: &Pacer,
    cancel: &CancellationToken,
    progress: &AtomicU32,
) -> TcpResult {
    scan_tcp_with(
        &Arc::new(TokioConnector),
        ip,
        ports,
        pacer,
        cancel,
        progress,
    )
    .await
}

/// [`scan_tcp`] with a caller-supplied [`Connector`].
pub async fn scan_tcp_with<C: Connector + Send + 'static>(
    connector: &Arc<C>,
    ip: IpAddr,
    ports: &[u16],
    pacer: &Pacer,
    cancel: &CancellationToken,
    progress: &AtomicU32,
) -> TcpResult {
    let rtt = Arc::new(Rtt {
        samples: Mutex::new(Vec::new()),
    });
    let mut res = TcpResult::default();
    let mut set: JoinSet<(u16, PortState)> = JoinSet::new();

    'outer: for &port in ports {
        let permit: PacerPermit = tokio::select! {
            () = cancel.cancelled() => break,
            p = pacer.permit() => p,
        };
        let (c, rtt) = (Arc::clone(connector), Arc::clone(&rtt));
        set.spawn(async move {
            let st = probe(&*c, SocketAddr::new(ip, port), &rtt).await;
            drop(permit);
            (port, st)
        });
        while let Some(joined) = set.try_join_next() {
            if absorb(&mut res, joined, progress) {
                break 'outer;
            }
        }
    }
    if res.all_open {
        set.abort_all();
    } else {
        // Finish probes already started, unless cancelled.
        loop {
            let joined = tokio::select! {
                () = cancel.cancelled() => { set.abort_all(); break; }
                j = set.join_next() => j,
            };
            match joined {
                Some(j) => {
                    if absorb(&mut res, j, progress) {
                        set.abort_all();
                        break;
                    }
                }
                None => break,
            }
        }
    }
    res.open.sort_unstable();
    res
}

/// Fold one finished probe into the result; true once recording must stop.
fn absorb(
    res: &mut TcpResult,
    joined: Result<(u16, PortState), tokio::task::JoinError>,
    progress: &AtomicU32,
) -> bool {
    let Ok((port, st)) = joined else { return false };
    res.done += 1;
    progress.fetch_add(1, Ordering::Relaxed);
    match st {
        PortState::Open => {
            if res.open.len() >= MAX_OPEN {
                res.all_open = true;
                return true;
            }
            res.open.push(port);
        }
        PortState::Filtered => res.filtered += 1,
        PortState::Closed | PortState::OpenFiltered => {}
    }
    false
}
