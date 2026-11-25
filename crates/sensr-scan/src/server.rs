//! The daemon's shared state, its job worker and the control socket.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::discover::Neighbours;
use crate::ports::Services;
use crate::proto::{JobKind, KnownDevice, Refusal, Reply, Request, StartReq, StatusView};
use crate::queue::{Job, Queue};
use crate::runner::{Ports, Progress, proc_neighbours, run_job};
use crate::store::Store;
use crate::target::{self, Target};

/// Longest request line accepted, in bytes.
const MAX_LINE: u64 = 1024 * 1024;
/// Most devices of one `Known` request considered; the rest are ignored.
pub const MAX_KNOWN: usize = 4096;
/// A connection that sends nothing for this long is closed.
pub const IDLE: Duration = Duration::from_secs(60);
/// A device whose automatic scan failed is not queued automatically again
/// for this long, in seconds.
pub const AUTO_RETRY_AFTER: i64 = 24 * 3600;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

type NeighbourFn = dyn Fn() -> Neighbours + Send + Sync;

struct Jobs {
    queue: Queue,
    /// The running job's id and cancel token.
    running: Option<(u64, CancellationToken)>,
}

/// Everything the server and the worker share.
pub struct Daemon {
    cfg: Config,
    db: PathBuf,
    /// The server's own connection (the worker opens another).
    store: Mutex<Store>,
    services: Arc<Services>,
    ports: Ports,
    neighbours: Arc<NeighbourFn>,
    jobs: Mutex<Jobs>,
    progress: Progress,
    wake: Notify,
    idle: Duration,
    /// Set by [`Daemon::stop`]: the worker starts no new job.
    stopping: AtomicBool,
}

impl Daemon {
    /// A daemon writing to the database at `db`, scanning [`Ports::full`]
    /// with neighbours from the kernel ([`proc_neighbours`]).
    ///
    /// # Errors
    /// The database could not be opened.
    pub fn new(cfg: Config, db: &Path, services: Services) -> rusqlite::Result<Daemon> {
        Ok(Daemon {
            cfg,
            db: db.to_path_buf(),
            store: Mutex::new(Store::open(db)?),
            services: Arc::new(services),
            ports: Ports::full(),
            neighbours: Arc::new(proc_neighbours),
            jobs: Mutex::new(Jobs {
                queue: Queue::default(),
                running: None,
            }),
            progress: Progress::default(),
            wake: Notify::new(),
            idle: IDLE,
            stopping: AtomicBool::new(false),
        })
    }

    /// Test hook: scan these ports instead of [`Ports::full`].
    #[must_use]
    pub fn with_ports(mut self, ports: Ports) -> Daemon {
        self.ports = ports;
        self
    }

    /// Test hook: read neighbours from `f` instead of the kernel.
    #[must_use]
    pub fn with_neighbours(mut self, f: impl Fn() -> Neighbours + Send + Sync + 'static) -> Daemon {
        self.neighbours = Arc::new(f);
        self
    }

    /// Test hook: close idle connections after `d` instead of [`IDLE`].
    #[must_use]
    pub fn with_idle_timeout(mut self, d: Duration) -> Daemon {
        self.idle = d;
        self
    }

    fn jobs(&self) -> MutexGuard<'_, Jobs> {
        self.jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn store(&self) -> MutexGuard<'_, Store> {
        self.store
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Delete old results (see [`Store::prune`]).
    ///
    /// # Errors
    /// Any SQLite error.
    pub fn prune(&self, now: i64) -> rusqlite::Result<()> {
        self.store().prune(self.cfg.history, now)
    }

    /// What runs and waits.
    #[must_use]
    pub fn status(&self) -> StatusView {
        let queue = self.jobs().queue.view();
        StatusView {
            running: self.progress.view(),
            queue,
        }
    }

    /// Answer one request. Blocks on SQLite: async callers use
    /// `spawn_blocking`.
    #[must_use]
    pub fn handle(&self, req: Request) -> Reply {
        match req {
            Request::Start(r) => self.start(&r),
            Request::Cancel { job_id } => self.cancel(job_id),
            Request::Status => Reply::Status(self.status()),
            Request::Known { macs } => {
                for KnownDevice { mac, ipv4 } in capped(macs) {
                    let _ = self.start(&StartReq {
                        target: ipv4.to_string(),
                        kind: JobKind::Device,
                        auto: true,
                        mac: Some(mac),
                        public_ok: false,
                        confirm: false,
                        include_excluded: false,
                    });
                }
                Reply::Ok
            }
        }
    }

    /// Stop for a shutdown: the running job is cancelled (it writes what it
    /// found as `Partial`; the worker then marks the job `failed`, so an
    /// automatic one is not taken for an owner cancel) and the worker
    /// thread ends instead of starting the next job.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        if let Some((_, token)) = self.jobs().running.as_ref() {
            token.cancel();
        }
        self.wake.notify_one();
    }

    fn stopping(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }

    /// Whether an automatic scan of `mac` is wanted: not after a complete
    /// scan, an owner cancel, or a failed automatic scan in the last
    /// [`AUTO_RETRY_AFTER`] (an offline device is not re-queued every time
    /// the agent resends its list).
    fn wants_auto(&self, mac: &str) -> bool {
        if !self.cfg.enabled || !self.cfg.auto_scan_new {
            return false;
        }
        let store = self.store();
        let since = now().saturating_sub(AUTO_RETRY_AFTER);
        match (
            store.has_complete(mac),
            store.auto_cancelled(mac),
            store.auto_failed_since(mac, since),
        ) {
            (Ok(done), Ok(cancelled), Ok(failed)) => !done && !cancelled && !failed,
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                tracing::warn!(mac, error = %e, "auto-scan check failed; not queued");
                false
            }
        }
    }

    fn start(&self, r: &StartReq) -> Reply {
        let refused = |reason| Reply::Refused { reason };
        if r.auto {
            let wanted = r.kind == JobKind::Device
                && r.mac
                    .as_deref()
                    .is_some_and(|m| self.wants_auto(&m.to_ascii_lowercase()));
            if !wanted {
                return Reply::Ok;
            }
        } else if !self.cfg.enabled {
            return refused(Refusal::Disabled);
        }
        let job = match Job::new(r) {
            Ok(j) => j,
            Err(e) => return refused(e),
        };
        if let Err(e) = target::check(&job.parsed, &self.cfg, r.public_ok) {
            return refused(e);
        }
        if let Target::One(ip) = job.parsed
            && job.kind == JobKind::Device
        {
            if self.cfg.router.contains(&ip) {
                return if r.auto {
                    Reply::Ok
                } else {
                    refused(Refusal::Excluded)
                };
            }
            if self.cfg.excludes(ip, job.mac.as_deref()) {
                if r.auto {
                    return Reply::Ok;
                }
                if !r.confirm {
                    return refused(Refusal::Excluded);
                }
            }
        }
        match self.enqueue(job) {
            Ok(job_id) => {
                self.wake.notify_one();
                Reply::Started { job_id }
            }
            Err(e) => refused(e),
        }
    }

    /// Queue `job` under its store row (`queued`), whose id is the
    /// protocol `job_id` (R5). A target already queued or running gets that
    /// job's id, and a person asking for an automatic job takes it over.
    fn enqueue(&self, mut job: Job) -> Result<u64, Refusal> {
        let mut jobs = self.jobs();
        if let Some(have) = jobs.queue.find(&job) {
            let (id, was_auto) = (have.id, have.auto);
            if was_auto && !job.auto {
                if let Err(e) = self.store().own_job(store_id(id)) {
                    tracing::warn!(job_id = id, error = %e, "could not mark job as the owner's");
                }
                if jobs.running.as_ref().is_some_and(|(r, _)| *r == id) {
                    return Ok(id);
                }
            }
            return jobs.queue.push(job);
        }
        if jobs.queue.is_full() {
            return Err(Refusal::Invalid("too many scans are queued".to_string()));
        }
        let id = self
            .store()
            .queue_job(
                job.kind,
                &job.target,
                job.mac.as_deref(),
                job.auto,
                job.public_ok,
            )
            .map_err(|e| {
                tracing::error!(error = %e, "could not record a queued job");
                Refusal::Invalid("the scan could not be recorded".to_string())
            })?;
        job.id = u64::try_from(id).unwrap_or(0);
        jobs.queue.push(job)
    }

    fn cancel(&self, id: u64) -> Reply {
        let taken = {
            let mut jobs = self.jobs();
            if let Some((_, token)) = jobs.running.as_ref().filter(|(r, _)| *r == id) {
                token.cancel();
                return Reply::Ok;
            }
            jobs.queue.take(id)
        };
        // Out of the queue, the worker can no longer start it.
        match taken {
            Some(_) => {
                if let Err(e) = self.store().end_job(store_id(id), "cancelled", &[]) {
                    tracing::warn!(job_id = id, error = %e, "could not record cancelled job");
                }
                Reply::Ok
            }
            None => Reply::Refused {
                reason: Refusal::Invalid(format!("no scan job {id}")),
            },
        }
    }

    /// Start the job worker on its own thread (with its own runtime and
    /// database connection): it runs queued jobs one at a time, forever.
    /// The thread ends only if the database cannot be opened; the binary
    /// exits then so systemd restarts it. A job that panics is recorded
    /// `failed` and the worker goes on.
    ///
    /// # Panics
    /// If the thread or its runtime cannot be created.
    pub fn spawn_worker(self: &Arc<Self>) -> std::thread::JoinHandle<()> {
        let me = Arc::clone(self);
        std::thread::Builder::new()
            .name("sensr-scan-worker".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("worker runtime");
                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, work(me));
            })
            .expect("worker thread")
    }

    /// Take the next job and mark it running.
    fn next_job(&self) -> Option<(Job, CancellationToken)> {
        let mut jobs = self.jobs();
        let job = jobs.queue.next()?;
        let token = CancellationToken::new();
        jobs.running = Some((job.id, token.clone()));
        self.progress.begin(&job);
        Some((job, token))
    }

    fn job_ended(&self, id: u64) {
        let mut jobs = self.jobs();
        jobs.queue.finish(id);
        jobs.running = None;
        self.progress.clear();
    }
}

fn store_id(id: u64) -> i64 {
    i64::try_from(id).unwrap_or(i64::MAX)
}

/// The first [`MAX_KNOWN`] devices.
fn capped(mut macs: Vec<KnownDevice>) -> Vec<KnownDevice> {
    if macs.len() > MAX_KNOWN {
        tracing::warn!(
            sent = macs.len(),
            max = MAX_KNOWN,
            "known-device list too long; the rest ignored"
        );
        macs.truncate(MAX_KNOWN);
    }
    macs
}

async fn work(me: Arc<Daemon>) {
    let store = match Store::open(&me.db) {
        Ok(s) => Rc::new(s),
        Err(e) => {
            tracing::error!(error = %e, "worker cannot open the database");
            return;
        }
    };
    loop {
        if me.stopping() {
            return;
        }
        let Some((job, token)) = me.next_job() else {
            // `notify_one` keeps a permit, so a push since `next` is not lost.
            me.wake.notified().await;
            continue;
        };
        let id = job.id;
        tracing::info!(job_id = id, target = %job.target, auto = job.auto, "scan started");
        // A task of its own, so a panic ends this job only.
        let (d, st) = (Arc::clone(&me), Rc::clone(&store));
        let task = tokio::task::spawn_local(async move {
            run_job(
                job,
                &d.cfg,
                &st,
                &d.services,
                &d.ports,
                &d.progress,
                token,
                &*d.neighbours,
            )
            .await
        });
        match task.await {
            Ok(Ok(_)) => tracing::info!(job_id = id, "scan ended"),
            Ok(Err(e)) => {
                tracing::error!(job_id = id, error = %e, "scan could not be recorded; job failed");
                if let Err(e) = store.end_job(store_id(id), "failed", &[]) {
                    tracing::error!(job_id = id, error = %e, "could not record failed job");
                }
            }
            Err(e) => {
                tracing::error!(job_id = id, error = %e, "scan crashed; job failed");
                if let Err(e) = store.end_job(store_id(id), "failed", &[]) {
                    tracing::error!(job_id = id, error = %e, "could not record failed job");
                }
            }
        }
        if me.stopping() {
            // Cut short by the shutdown, not by the owner.
            if let Err(e) = store.interrupt_job(store_id(id)) {
                tracing::error!(job_id = id, error = %e, "could not record interrupted job");
            }
        }
        me.job_ended(id);
    }
}

/// Bind `path` (replacing a stale socket file), set it to mode 0660.
///
/// # Errors
/// Binding or setting permissions failed.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(l)
}

/// Serve the JSON-lines protocol on `path` until an accept fails.
///
/// # Errors
/// Binding, or accepting a connection, failed.
pub async fn serve(path: &Path, state: Arc<Daemon>) -> io::Result<()> {
    let l = bind(path)?;
    loop {
        let (s, _) = l.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = connection(s, state).await {
                tracing::debug!(error = %e, "control connection ended");
            }
        });
    }
}

async fn connection(s: UnixStream, state: Arc<Daemon>) -> io::Result<()> {
    let (r, mut w) = s.into_split();
    let mut r = BufReader::new(r);
    let mut line = String::new();
    loop {
        line.clear();
        let mut limited = (&mut r).take(MAX_LINE);
        let read = limited.read_line(&mut line);
        let Ok(n) = tokio::time::timeout(state.idle, read).await else {
            return Ok(());
        };
        let n = n?;
        if n == 0 {
            return Ok(());
        }
        let too_long = !line.ends_with('\n') && u64::try_from(n).is_ok_and(|n| n >= MAX_LINE);
        let reply = if too_long {
            Reply::Refused {
                reason: Refusal::Invalid("request too long".into()),
            }
        } else if line.trim().is_empty() {
            continue;
        } else {
            match serde_json::from_str::<Request>(&line) {
                Ok(req) => {
                    let st = Arc::clone(&state);
                    tokio::task::spawn_blocking(move || st.handle(req))
                        .await
                        .map_err(io::Error::other)?
                }
                Err(e) => Reply::Refused {
                    reason: Refusal::Invalid(format!("bad request: {e}")),
                },
            }
        };
        let mut out = serde_json::to_vec(&reply).map_err(io::Error::other)?;
        out.push(b'\n');
        w.write_all(&out).await?;
        if too_long {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_lists_are_capped() {
        let dev = |n: usize| KnownDevice {
            mac: format!("{n}"),
            ipv4: std::net::Ipv4Addr::LOCALHOST,
        };
        let v: Vec<_> = (0..MAX_KNOWN + 5).map(dev).collect();
        let c = capped(v);
        assert_eq!(c.len(), MAX_KNOWN);
        assert_eq!(c.last().unwrap().mac, format!("{}", MAX_KNOWN - 1));
        assert_eq!(capped(vec![dev(1)]).len(), 1);
    }
}
