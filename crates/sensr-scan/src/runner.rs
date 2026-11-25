//! Running one job: discovery, TCP, identification, UDP, and the store
//! writes (one transaction per address).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::discover::{alive, ip_for, mac_for};
use crate::ident::identify;
use crate::pace::Pacer;
use crate::ports::{Services, tcp_order};
use crate::proto::{JobKind, JobProgress};
use crate::queue::Job;
use crate::store::Store;
use crate::target::{self, Target};
use crate::types::{Ident, PortRow, PortState, Proto, ScanStatus};
use crate::udp::udp_order;
use crate::udp_probes::PROBES;

/// Open TCP ports identified at once (a silent port takes ~4.5 s).
const IDENT_PARALLEL: usize = 8;
/// Ports identified when a host answers on every port.
const IDENT_ALL_OPEN: usize = 50;
/// Range addresses checked for life at once.
const DISCOVER_PARALLEL: usize = 32;

/// The ports a scan probes.
///
/// [`Ports::full`] is what the daemon uses. Tests pass a few ports instead
/// (the test hook), since all 65,535 TCP ports of localhost take minutes at
/// the gentle pace.
#[derive(Debug, Clone)]
pub struct Ports {
    /// TCP ports, in probe order.
    pub tcp: Arc<Vec<u16>>,
    /// UDP ports, in probe order.
    pub udp: Vec<u16>,
}

impl Ports {
    /// Every TCP port ([`tcp_order`], built once per process) and
    /// [`udp_order`].
    #[must_use]
    pub fn full() -> Ports {
        static TCP: OnceLock<Arc<Vec<u16>>> = OnceLock::new();
        Ports {
            tcp: Arc::clone(TCP.get_or_init(|| Arc::new(tcp_order()))),
            udp: udp_order(),
        }
    }
}

/// Live progress of the running job, read by `status`.
#[derive(Debug, Default)]
pub struct Progress {
    current: Mutex<Option<(u64, JobKind, String)>>,
    /// Alive hosts plus one; 0 while discovery runs.
    alive: AtomicU32,
    address_n: AtomicU32,
    address_total: AtomicU32,
    /// TCP probes finished on the current address.
    pub tcp_done: AtomicU32,
    /// UDP probes finished on the current address.
    pub udp_done: AtomicU32,
}

impl Progress {
    /// A job starts.
    pub fn begin(&self, job: &Job) {
        *self.current.lock().expect("progress lock") = Some((job.id, job.kind, job.target.clone()));
        for a in [
            &self.alive,
            &self.address_n,
            &self.address_total,
            &self.tcp_done,
            &self.udp_done,
        ] {
            a.store(0, Ordering::Relaxed);
        }
    }

    /// The job ended.
    pub fn clear(&self) {
        *self.current.lock().expect("progress lock") = None;
    }

    fn address(&self, n: u32, total: u32) {
        self.address_n.store(n, Ordering::Relaxed);
        self.address_total.store(total, Ordering::Relaxed);
        self.tcp_done.store(0, Ordering::Relaxed);
        self.udp_done.store(0, Ordering::Relaxed);
    }

    fn alive(&self, n: u32) {
        self.alive.store(n.saturating_add(1), Ordering::Relaxed);
    }

    /// The running job's progress, if one runs.
    #[must_use]
    pub fn view(&self) -> Option<JobProgress> {
        let cur = self.current.lock().expect("progress lock");
        let (job_id, kind, target) = cur.as_ref()?;
        Some(JobProgress {
            job_id: *job_id,
            kind: *kind,
            target: target.clone(),
            alive: self.alive.load(Ordering::Relaxed).checked_sub(1),
            address_n: self.address_n.load(Ordering::Relaxed),
            address_total: self.address_total.load(Ordering::Relaxed),
            tcp_done: self.tcp_done.load(Ordering::Relaxed),
            udp_done: self.udp_done.load(Ordering::Relaxed),
        })
    }
}

/// Production neighbour source: `/proc/net/arp`, empty if unreadable.
#[must_use]
pub fn proc_neighbours() -> HashMap<IpAddr, String> {
    std::fs::read_to_string("/proc/net/arp")
        .map(|t| crate::discover::neighbours(&t))
        .unwrap_or_default()
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

struct Ctx<'a> {
    services: &'a Services,
    ports: &'a Ports,
    progress: &'a Progress,
    cancel: &'a CancellationToken,
    pacer: Pacer,
}

/// What scanning one live address found.
struct HostScan {
    status: ScanStatus,
    all_open: bool,
    ports: Vec<PortRow>,
}

/// Run `job` to the end and record it in `store`; returns the store's job id.
/// `job.id` must be the job's `queued` row ([`Store::queue_job`]); it is
/// marked running here.
///
/// - A device job scans the MAC's current IPv4 from `neighbours()` when it
///   is local (or `public_ok`), else the job's address. An address that is
///   not alive is recorded `Failed` with no ports and the job `failed`.
/// - A range job checks every address of the target for life (skipping
///   excluded ones unless `include_excluded`, recorded in `jobs.skipped`),
///   then scans each live one, with its MAC from the neighbour table. The
///   job ends `complete`.
/// - A scan is TCP, identification of the open TCP ports (the first 50 when
///   the host answers on every port), then UDP. Cancelling writes the
///   address being scanned as `Partial` with what was found, and the job as
///   `cancelled`.
///
/// `neighbours` is injectable for tests; the daemon passes
/// [`proc_neighbours`].
///
/// # Errors
/// A store error; the job may then be left `running` (failed at next start).
#[allow(clippy::too_many_arguments)]
pub async fn run_job(
    job: Job,
    cfg: &Config,
    store: &Store,
    services: &Services,
    ports: &Ports,
    progress: &Progress,
    cancel: CancellationToken,
    neighbours: &dyn Fn() -> HashMap<IpAddr, String>,
) -> rusqlite::Result<i64> {
    let ctx = Ctx {
        services,
        ports,
        progress,
        cancel: &cancel,
        pacer: Pacer::new(cfg.pace.limits()),
    };
    let neigh = neighbours();
    match job.kind {
        JobKind::Device => run_device(&job, cfg, store, &ctx, &neigh).await,
        JobKind::Range => run_range(&job, cfg, store, &ctx, neigh).await,
    }
}

/// The address a device job scans.
fn device_address(job: &Job, cfg: &Config, neigh: &HashMap<IpAddr, String>) -> Option<IpAddr> {
    let Target::One(given) = job.parsed else {
        return None;
    };
    let current = job
        .mac
        .as_deref()
        .and_then(|m| ip_for(m, neigh))
        .map(IpAddr::V4)
        .filter(|ip| job.public_ok || target::is_local(*ip, &cfg.local))
        .filter(|ip| !cfg.router.contains(ip) && !cfg.excludes(*ip, None));
    Some(current.unwrap_or(given))
}

/// The job's row in the store: its id is the protocol `job_id` (R5).
fn store_id(job: &Job) -> i64 {
    i64::try_from(job.id).unwrap_or(i64::MAX)
}

/// Whether a UDP result is stored: open ports, and open|filtered only for
/// ports with a protocol probe (silence after an empty datagram says too
/// little to keep ~1,000 rows a scan, R6).
fn keep_udp(port: u16, state: PortState) -> bool {
    match state {
        PortState::Open => true,
        PortState::OpenFiltered => PROBES.iter().any(|p| p.port == port),
        PortState::Closed | PortState::Filtered => false,
    }
}

async fn run_device(
    job: &Job,
    cfg: &Config,
    store: &Store,
    ctx: &Ctx<'_>,
    neigh: &HashMap<IpAddr, String>,
) -> rusqlite::Result<i64> {
    let ip = device_address(job, cfg, neigh);
    let mac = job
        .mac
        .clone()
        .or_else(|| ip.and_then(|ip| mac_for(ip, neigh)));
    let id = store_id(job);
    store.start_job(id, mac.as_deref())?;
    let Some(ip) = ip else {
        store.end_job(id, "failed", &[])?;
        return Ok(id);
    };
    ctx.progress.address(1, 1);
    let started = now();
    let up = tokio::select! {
        () = ctx.cancel.cancelled() => None,
        up = alive(ip, neigh) => Some(up),
    };
    let (scan, end) = match up {
        None => (
            HostScan {
                status: ScanStatus::Partial,
                all_open: false,
                ports: Vec::new(),
            },
            "cancelled",
        ),
        Some(false) => (
            HostScan {
                status: ScanStatus::Failed,
                all_open: false,
                ports: Vec::new(),
            },
            "failed",
        ),
        Some(true) => {
            let s = scan_host(ctx, ip).await;
            let end = if s.status == ScanStatus::Partial {
                "cancelled"
            } else {
                "complete"
            };
            (s, end)
        }
    };
    store.write_scan(
        id,
        ip,
        mac.as_deref(),
        started,
        now(),
        scan.status,
        scan.all_open,
        &scan.ports,
    )?;
    store.end_job(id, end, &[])?;
    Ok(id)
}

async fn run_range(
    job: &Job,
    cfg: &Config,
    store: &Store,
    ctx: &Ctx<'_>,
    neigh: HashMap<IpAddr, String>,
) -> rusqlite::Result<i64> {
    let id = store_id(job);
    store.start_job(id, None)?;
    let mut skipped = Vec::new();
    let mut candidates = Vec::new();
    for ip in target::addresses(&job.parsed, &cfg.router) {
        let mac = mac_for(ip, &neigh);
        if !job.include_excluded && cfg.excludes(ip, mac.as_deref()) {
            skipped.push(ip);
        } else {
            candidates.push(ip);
        }
    }
    ctx.progress
        .address(0, u32::try_from(candidates.len()).unwrap_or(u32::MAX));

    let neigh = Arc::new(neigh);
    let Some(live) = discover(&candidates, &neigh, ctx.cancel).await else {
        store.end_job(id, "cancelled", &skipped)?;
        return Ok(id);
    };
    let total = u32::try_from(live.len()).unwrap_or(u32::MAX);
    ctx.progress.alive(total);
    for (n, ip) in live.into_iter().enumerate() {
        ctx.progress
            .address(u32::try_from(n + 1).unwrap_or(u32::MAX), total);
        let started = now();
        let scan = scan_host(ctx, ip).await;
        store.write_scan(
            id,
            ip,
            mac_for(ip, &neigh).as_deref(),
            started,
            now(),
            scan.status,
            scan.all_open,
            &scan.ports,
        )?;
        if scan.status == ScanStatus::Partial {
            store.end_job(id, "cancelled", &skipped)?;
            return Ok(id);
        }
    }
    store.end_job(id, "complete", &skipped)?;
    Ok(id)
}

/// The live addresses of `candidates`, in order; `None` if cancelled.
async fn discover(
    candidates: &[IpAddr],
    neigh: &Arc<HashMap<IpAddr, String>>,
    cancel: &CancellationToken,
) -> Option<Vec<IpAddr>> {
    let slots = Arc::new(Semaphore::new(DISCOVER_PARALLEL));
    let mut set = JoinSet::new();
    for &ip in candidates {
        let (slots, neigh) = (Arc::clone(&slots), Arc::clone(neigh));
        set.spawn(async move {
            let _slot = slots.acquire_owned().await.ok()?;
            alive(ip, &neigh).await.then_some(ip)
        });
    }
    let mut live = Vec::new();
    loop {
        let next = tokio::select! {
            () = cancel.cancelled() => { set.abort_all(); return None; }
            n = set.join_next() => n,
        };
        match next {
            Some(Ok(Some(ip))) => live.push(ip),
            Some(_) => {}
            None => break,
        }
    }
    live.sort_unstable();
    Some(live)
}

fn row(ctx: &Ctx<'_>, proto: Proto, port: u16, state: PortState, ident: Ident) -> PortRow {
    PortRow {
        proto,
        port,
        state,
        service: ctx.services.name(proto, port).map(str::to_string),
        ident,
    }
}

/// TCP, identification, UDP on one live address.
async fn scan_host(ctx: &Ctx<'_>, ip: IpAddr) -> HostScan {
    let tcp = crate::tcp::scan_tcp(
        ip,
        &ctx.ports.tcp,
        &ctx.pacer,
        ctx.cancel,
        &ctx.progress.tcp_done,
    )
    .await;
    let mut idents = if ctx.cancel.is_cancelled() {
        HashMap::new()
    } else {
        let n = if tcp.all_open {
            IDENT_ALL_OPEN
        } else {
            tcp.open.len()
        };
        identify_all(ctx, ip, &tcp.open[..n.min(tcp.open.len())]).await
    };
    let mut ports: Vec<PortRow> = tcp
        .open
        .iter()
        .map(|&p| {
            let ident = idents.remove(&p).unwrap_or_default();
            row(ctx, Proto::Tcp, p, PortState::Open, ident)
        })
        .collect();
    if !ctx.cancel.is_cancelled() {
        let udp = crate::udp::scan_udp_ports(
            ip,
            &ctx.ports.udp,
            &ctx.pacer,
            ctx.cancel,
            &ctx.progress.udp_done,
        )
        .await;
        ports.extend(
            udp.ports
                .into_iter()
                .filter(|(p, st, _)| keep_udp(*p, *st))
                .map(|(p, st, id)| row(ctx, Proto::Udp, p, st, id.unwrap_or_default())),
        );
    }
    HostScan {
        status: if ctx.cancel.is_cancelled() {
            ScanStatus::Partial
        } else {
            ScanStatus::Complete
        },
        all_open: tcp.all_open,
        ports,
    }
}

/// Identify `ports`, [`IDENT_PARALLEL`] at a time; stops early on cancel
/// with what was learned so far.
async fn identify_all(ctx: &Ctx<'_>, ip: IpAddr, ports: &[u16]) -> HashMap<u16, Ident> {
    let slots = Arc::new(Semaphore::new(IDENT_PARALLEL));
    let mut set = JoinSet::new();
    for &port in ports {
        let hint = ctx.services.name(Proto::Tcp, port).map(str::to_string);
        let slots = Arc::clone(&slots);
        set.spawn(async move {
            let _slot = slots.acquire_owned().await.ok()?;
            identify(ip, port, hint.as_deref()).await.map(|i| (port, i))
        });
    }
    let mut out = HashMap::new();
    loop {
        let next = tokio::select! {
            () = ctx.cancel.cancelled() => { set.abort_all(); break; }
            n = set.join_next() => n,
        };
        match next {
            Some(Ok(Some((port, ident)))) => {
                out.insert(port, ident);
            }
            Some(Ok(None)) => {}
            Some(Err(e)) => {
                if !e.is_cancelled() {
                    tracing::warn!(%ip, error = %e, "identification task failed");
                }
            }
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Pace;
    use crate::proto::StartReq;

    fn cfg() -> Config {
        Config {
            enabled: true,
            auto_scan_new: true,
            pace: Pace::Gentle,
            history: 10,
            max_range: 4096,
            exclude: vec![],
            local: vec![],
            router: vec![],
        }
    }

    fn job(target: &str, mac: Option<&str>, public_ok: bool) -> Job {
        Job::new(&StartReq {
            target: target.into(),
            kind: JobKind::Device,
            auto: false,
            mac: mac.map(Into::into),
            public_ok,
            confirm: false,
            include_excluded: false,
        })
        .unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn device_follows_mac_to_a_local_address() {
        let neigh = HashMap::from([(ip("192.168.1.20"), "aa:bb:cc:dd:ee:ff".to_string())]);
        let j = job("192.168.1.5", Some("AA:BB:CC:DD:EE:FF"), false);
        assert_eq!(device_address(&j, &cfg(), &neigh), Some(ip("192.168.1.20")));
        // Unknown MAC: the given address.
        let j = job("192.168.1.5", Some("aa:bb:cc:dd:ee:00"), false);
        assert_eq!(device_address(&j, &cfg(), &neigh), Some(ip("192.168.1.5")));
    }

    #[test]
    fn device_does_not_follow_mac_off_the_local_network() {
        let neigh = HashMap::from([(ip("203.0.113.9"), "aa:bb:cc:dd:ee:ff".to_string())]);
        let j = job("192.168.1.5", Some("aa:bb:cc:dd:ee:ff"), false);
        assert_eq!(device_address(&j, &cfg(), &neigh), Some(ip("192.168.1.5")));
        let j = job("192.168.1.5", Some("aa:bb:cc:dd:ee:ff"), true);
        assert_eq!(device_address(&j, &cfg(), &neigh), Some(ip("203.0.113.9")));
    }

    #[test]
    fn device_does_not_follow_mac_to_an_excluded_or_router_address() {
        let neigh = HashMap::from([(ip("192.168.1.20"), "aa:bb:cc:dd:ee:ff".to_string())]);
        let j = job("192.168.1.5", Some("aa:bb:cc:dd:ee:ff"), false);
        let mut c = cfg();
        c.exclude = vec![crate::config::Exclude::Addr(ip("192.168.1.20"))];
        assert_eq!(device_address(&j, &c, &neigh), Some(ip("192.168.1.5")));
        let mut c = cfg();
        c.router = vec![ip("192.168.1.20")];
        assert_eq!(device_address(&j, &c, &neigh), Some(ip("192.168.1.5")));
    }

    #[test]
    fn udp_open_filtered_kept_only_for_probed_ports() {
        let probed = PROBES[0].port;
        let unprobed = (1..=u16::MAX)
            .find(|p| PROBES.iter().all(|x| x.port != *p))
            .unwrap();
        assert!(keep_udp(probed, PortState::OpenFiltered));
        assert!(!keep_udp(unprobed, PortState::OpenFiltered));
        assert!(keep_udp(unprobed, PortState::Open));
        assert!(!keep_udp(probed, PortState::Closed));
        assert!(!keep_udp(probed, PortState::Filtered));
    }

    #[test]
    fn progress_reports_alive_only_after_discovery() {
        let p = Progress::default();
        assert!(p.view().is_none());
        let mut j = job("192.168.1.5", None, false);
        j.id = 4;
        p.begin(&j);
        p.address(0, 254);
        let v = p.view().unwrap();
        assert_eq!((v.job_id, v.alive, v.address_total), (4, None, 254));
        p.alive(0);
        assert_eq!(p.view().unwrap().alive, Some(0));
        p.alive(3);
        p.address(2, 3);
        p.tcp_done.store(10, Ordering::Relaxed);
        let v = p.view().unwrap();
        assert_eq!(
            (v.alive, v.address_n, v.address_total, v.tcp_done),
            (Some(3), 2, 3, 10)
        );
        p.clear();
        assert!(p.view().is_none());
    }

    #[test]
    fn full_ports_cache_the_tcp_order() {
        let (a, b) = (Ports::full(), Ports::full());
        assert!(Arc::ptr_eq(&a.tcp, &b.tcp));
        assert_eq!(a.tcp.len(), 65_535);
        assert!(!a.udp.is_empty());
    }
}
