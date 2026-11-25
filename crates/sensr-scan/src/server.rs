//! The daemon's shared state, its job worker and the control socket.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::ports::Services;
use crate::proto::{JobKind, KnownDevice, Refusal, Reply, Request, StartReq, StatusView};
use crate::queue::{Job, Queue};
use crate::runner::{Ports, Progress, proc_neighbours, run_job};
use crate::store::Store;
use crate::target::{self, Target};

/// Longest request line accepted, in bytes.
const MAX_LINE: u64 = 1024 * 1024;

type Neighbours = dyn Fn() -> HashMap<IpAddr, String> + Send + Sync;

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
    neighbours: Arc<Neighbours>,
    jobs: Mutex<Jobs>,
    progress: Progress,
    wake: Notify,
}

impl Daemon {
    /// A daemon writing to the database at `db`, scanning [`Ports::full`]
    /// with neighbours from `/proc/net/arp`.
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
        })
    }

    /// Test hook: scan these ports instead of [`Ports::full`].
    #[must_use]
    pub fn with_ports(mut self, ports: Ports) -> Daemon {
        self.ports = ports;
        self
    }

    /// Test hook: read neighbours from `f` instead of `/proc/net/arp`.
    #[must_use]
    pub fn with_neighbours(
        mut self,
        f: impl Fn() -> HashMap<IpAddr, String> + Send + Sync + 'static,
    ) -> Daemon {
        self.neighbours = Arc::new(f);
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

    /// Answer one request.
    #[must_use]
    pub fn handle(&self, req: Request) -> Reply {
        match req {
            Request::Start(r) => self.start(&r),
            Request::Cancel { job_id } => self.cancel(job_id),
            Request::Status => Reply::Status(self.status()),
            Request::Known { macs } => {
                for KnownDevice { mac, ipv4 } in macs {
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

    /// Whether an automatic scan of `mac` is wanted.
    fn wants_auto(&self, mac: &str) -> bool {
        if !self.cfg.enabled || !self.cfg.auto_scan_new {
            return false;
        }
        let store = self.store();
        match (store.has_complete(mac), store.auto_cancelled(mac)) {
            (Ok(done), Ok(cancelled)) => !done && !cancelled,
            (Err(e), _) | (_, Err(e)) => {
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
                return refused(Refusal::Excluded);
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
        let pushed = self.jobs().queue.push(job);
        match pushed {
            Ok(job_id) => {
                self.wake.notify_one();
                Reply::Started { job_id }
            }
            Err(e) => refused(e),
        }
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
        match taken {
            Some(job) => {
                // Recorded, so the device is not queued automatically again.
                if job.auto {
                    let store = self.store();
                    let r = store
                        .begin_job(
                            job.kind,
                            &job.target,
                            job.mac.as_deref(),
                            true,
                            job.public_ok,
                        )
                        .and_then(|sid| store.end_job(sid, "cancelled", &[]));
                    if let Err(e) = r {
                        tracing::warn!(job_id = id, error = %e, "could not record cancelled job");
                    }
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
                rt.block_on(me.work());
            })
            .expect("worker thread")
    }

    async fn work(&self) {
        let store = match Store::open(&self.db) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "worker cannot open the database");
                return;
            }
        };
        loop {
            let next = {
                let mut jobs = self.jobs();
                let job = jobs.queue.next();
                if let Some(j) = &job {
                    let token = CancellationToken::new();
                    jobs.running = Some((j.id, token.clone()));
                    self.progress.begin(j);
                    Some((j.clone(), token))
                } else {
                    None
                }
            };
            let Some((job, token)) = next else {
                // `notify_one` keeps a permit, so a push since `next` is not lost.
                self.wake.notified().await;
                continue;
            };
            let id = job.id;
            tracing::info!(job_id = id, target = %job.target, auto = job.auto, "scan started");
            let neighbours = Arc::clone(&self.neighbours);
            let r = run_job(
                job,
                &self.cfg,
                &store,
                &self.services,
                &self.ports,
                &self.progress,
                token,
                &*neighbours,
            )
            .await;
            match r {
                Ok(sid) => tracing::info!(job_id = id, store_id = sid, "scan ended"),
                Err(e) => tracing::error!(job_id = id, error = %e, "scan could not be recorded"),
            }
            let mut jobs = self.jobs();
            jobs.queue.finish(id);
            jobs.running = None;
            self.progress.clear();
        }
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
            if let Err(e) = connection(s, &state).await {
                tracing::debug!(error = %e, "control connection ended");
            }
        });
    }
}

async fn connection(s: UnixStream, state: &Daemon) -> io::Result<()> {
    let (r, mut w) = s.into_split();
    let mut r = BufReader::new(r);
    let mut line = String::new();
    loop {
        line.clear();
        let n = (&mut r).take(MAX_LINE).read_line(&mut line).await?;
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
                Ok(req) => state.handle(req),
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
