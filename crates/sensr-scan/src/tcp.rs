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
    /// Of those, ports whose connect failed with host/network unreachable
    /// (the host may have left).
    pub unreachable: u32,
    /// Ports that answered (open or closed).
    pub replied: u32,
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

/// How one port's probe ended.
#[derive(Debug, Clone, Copy)]
struct Outcome {
    state: PortState,
    unreachable: bool,
}

impl Outcome {
    fn of(state: PortState) -> Outcome {
        Outcome {
            state,
            unreachable: false,
        }
    }
}

impl Rtt {
    /// Seeded with the discovery round trip, when known, so a host that
    /// drops every port is not probed at the 2 s ceiling.
    fn new(seed: Option<Duration>) -> Rtt {
        Rtt {
            samples: Mutex::new(seed.into_iter().collect()),
        }
    }

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

/// Connect, with one retry after a timeout. The retry takes its own rate
/// token, so retries count against the pace.
async fn probe<C: Connector>(c: &C, addr: SocketAddr, rtt: &Rtt, pacer: &Pacer) -> Outcome {
    for attempt in 0..2 {
        if attempt > 0 {
            pacer.tick().await;
        }
        let t = rtt.timeout();
        let started = tokio::time::Instant::now();
        match c.connect(addr, t).await {
            Ok(()) => {
                rtt.record(started.elapsed());
                return Outcome::of(PortState::Open);
            }
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                rtt.record(started.elapsed());
                return Outcome::of(PortState::Closed);
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
            Err(e) => {
                return Outcome {
                    state: PortState::Filtered,
                    unreachable: matches!(
                        e.kind(),
                        io::ErrorKind::HostUnreachable
                            | io::ErrorKind::NetworkUnreachable
                            | io::ErrorKind::NetworkDown
                    ),
                };
            }
        }
    }
    Outcome::of(PortState::Filtered)
}

/// Scan `ports` on `ip` with real sockets. `rtt_seed` is the round trip
/// measured by discovery, if any: the first timeouts are based on it.
pub async fn scan_tcp(
    ip: IpAddr,
    ports: &[u16],
    pacer: &Pacer,
    cancel: &CancellationToken,
    progress: &AtomicU32,
    rtt_seed: Option<Duration>,
) -> TcpResult {
    scan_tcp_with(
        &Arc::new(TokioConnector),
        ip,
        ports,
        pacer,
        cancel,
        progress,
        rtt_seed,
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
    rtt_seed: Option<Duration>,
) -> TcpResult {
    let rtt = Arc::new(Rtt::new(rtt_seed));
    let mut res = TcpResult::default();
    let mut set: JoinSet<(u16, Outcome)> = JoinSet::new();

    'outer: for &port in ports {
        let permit: PacerPermit = tokio::select! {
            () = cancel.cancelled() => break,
            p = pacer.permit() => p,
        };
        let (c, rtt, pacer) = (Arc::clone(connector), Arc::clone(&rtt), pacer.clone());
        set.spawn(async move {
            let st = probe(&*c, SocketAddr::new(ip, port), &rtt, &pacer).await;
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
/// A probe that panicked is logged and counted as `Filtered` (as for UDP);
/// an aborted one (cancel, cap reached) is not counted.
fn absorb(
    res: &mut TcpResult,
    joined: Result<(u16, Outcome), tokio::task::JoinError>,
    progress: &AtomicU32,
) -> bool {
    let (port, out) = match joined {
        Ok(j) => j,
        Err(e) if e.is_cancelled() => return false,
        Err(e) => {
            tracing::warn!(error = %e, "tcp probe task failed; port counted as filtered");
            (0, Outcome::of(PortState::Filtered))
        }
    };
    res.done += 1;
    progress.fetch_add(1, Ordering::Relaxed);
    match out.state {
        PortState::Open => {
            res.replied += 1;
            if res.open.len() >= MAX_OPEN {
                res.all_open = true;
                return true;
            }
            res.open.push(port);
        }
        PortState::Filtered => {
            res.filtered += 1;
            if out.unreachable {
                res.unreachable += 1;
            }
        }
        PortState::Closed => res.replied += 1,
        PortState::OpenFiltered => {}
    }
    false
}
