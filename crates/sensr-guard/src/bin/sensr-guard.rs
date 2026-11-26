//! `sensr-guard`: the runtime guard daemon.
//!
//! `sensr-guard --config <json> --state <dir> --socket <path> --builtin <dir>
//! --keys <dir>` checks kernel lockdown (it refuses `confidentiality`, exit
//! status 78), reads the kill switch, loads the enabled packs from their
//! verified bytes, applies the rules and serves the control socket. A
//! thread drains the ring buffers into the event pipeline and writes its
//! batches to `<state>/events.db`; another runs the daily pack check when
//! `pack_auto_check` is set. SIGTERM drains the pending events and exits;
//! the programs detach with the process (nothing is pinned).

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("sensr-guard: Linux only");
    std::process::ExitCode::from(2)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use anyhow::Context;
    use clap::Parser;
    use sensr_guard::config;
    use sensr_guard::daemon::kernel::Kernel;
    use sensr_guard::daemon::{
        Daemon, HttpFetcher, LOCKDOWN, Options, RELEASE_FILE, StartError, auto_check_due,
    };
    use sensr_guard::events::BootClock;
    use sensr_guard::proto::Reply;
    use sensr_guard::server::{Shared, bind, serve};
    use sensr_guard::store::Store;
    use tracing_subscriber::EnvFilter;

    /// Exit status when lockdown forbids running (systemd does not restart
    /// on it: RestartPreventExitStatus).
    const EXIT_LOCKDOWN: u8 = 78;
    /// How often the event loop drains the ring buffers.
    const POLL: Duration = Duration::from_millis(100);
    /// How often old events are pruned.
    const PRUNE_EVERY: Duration = Duration::from_secs(3600);
    /// How often the automatic pack check looks whether it is due.
    const AUTO_CHECK_POLL: Duration = Duration::from_secs(600);

    /// Runtime guard daemon for sensr (eBPF LSM packs).
    #[derive(Debug, Parser)]
    #[command(version, about)]
    struct Args {
        /// Configuration JSON written by the agent.
        #[arg(long, default_value = config::CONFIG_PATH)]
        config: PathBuf,
        /// State directory (installed packs, events.db, kill switch).
        #[arg(long, default_value = config::STATE_DIR)]
        state: PathBuf,
        /// Control socket to serve.
        #[arg(long, default_value = config::SOCKET)]
        socket: PathBuf,
        /// Built-in packs.
        #[arg(long, default_value = config::BUILTIN_PACKS)]
        builtin: PathBuf,
        /// Trusted public keys for signed packs (*.pub).
        #[arg(long, default_value = config::KEYS_DIR)]
        keys: PathBuf,
        /// While this file exists nothing blocks.
        #[arg(long, default_value = config::KILL_SWITCH)]
        kill_switch_file: PathBuf,
        /// Users (besides root) whose reload, kill-switch and pack-check
        /// requests are taken; looked up in /etc/passwd at start.
        #[arg(long = "trusted-user", default_value = "sensr-api")]
        trusted_users: Vec<String>,
        /// The running sensr release, as the system updater records it
        /// (packs' min_sensr).
        #[arg(long, default_value = RELEASE_FILE)]
        release_file: PathBuf,
    }

    /// The uid of `name` in /etc/passwd.
    fn uid_of(name: &str) -> Option<u32> {
        let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
        passwd.lines().find_map(|l| {
            let mut f = l.split(':');
            (f.next()? == name).then_some(())?;
            f.nth(1)?.parse().ok()
        })
    }

    fn unix_now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }

    /// Wall time and CLOCK_BOOTTIME read together (/proc/uptime counts
    /// suspended time too, like CLOCK_BOOTTIME; 10 ms resolution).
    fn boot_clock() -> anyhow::Result<BootClock> {
        let up = std::fs::read_to_string("/proc/uptime").context("reading /proc/uptime")?;
        let secs: f64 = up
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .context("parsing /proc/uptime")?;
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
        Ok(BootClock::new(wall, (secs * 1e9) as u64))
    }

    pub fn main() -> ExitCode {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .init();
        match run(Args::parse()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                if let Some(StartError::Lockdown(_)) = e.downcast_ref::<StartError>() {
                    tracing::error!("{e}");
                    return ExitCode::from(EXIT_LOCKDOWN);
                }
                tracing::error!("{e:#}");
                ExitCode::FAILURE
            }
        }
    }

    fn run(args: Args) -> anyhow::Result<()> {
        let opts = Options {
            config: args.config.clone(),
            state_dir: args.state.clone(),
            builtin_dir: args.builtin.clone(),
            keys_dir: args.keys.clone(),
            kill_switch_file: args.kill_switch_file.clone(),
            lockdown_file: PathBuf::from(LOCKDOWN),
            release_file: args.release_file.clone(),
            own_tgid: std::process::id(),
            clock: boot_clock()?,
            arch: std::env::consts::ARCH.to_owned(),
        };
        std::fs::create_dir_all(&args.state)
            .with_context(|| format!("creating {}", args.state.display()))?;
        let daemon = Daemon::start(opts, Kernel)?;
        log_status(&daemon.status());
        let mut trusted = vec![0];
        for u in &args.trusted_users {
            match uid_of(u) {
                Some(uid) => trusted.push(uid),
                None => tracing::warn!(user = %u, "no such user: not trusted"),
            }
        }
        let shared =
            Arc::new(Shared::new(daemon, Box::new(HttpFetcher::default())).with_trusted(trusted));

        let stop = Arc::new(AtomicBool::new(false));
        let events = {
            let (shared, stop) = (Arc::clone(&shared), Arc::clone(&stop));
            let db = args.state.join(config::EVENTS_DB);
            std::thread::Builder::new()
                .name("events".into())
                .spawn(move || event_loop(&shared, &db, &stop))?
        };
        {
            let shared = Arc::clone(&shared);
            std::thread::Builder::new()
                .name("pack-check".into())
                .spawn(move || auto_check_loop(&shared))?;
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let socket = args.socket.clone();
        let served = rt.block_on(async {
            let l = bind(&socket).with_context(|| format!("binding {}", socket.display()))?;
            tracing::info!(socket = %socket.display(), "sensr-guard serving");
            tokio::select! {
                r = serve(l, Arc::clone(&shared)) => {
                    r.with_context(|| format!("serving {}", socket.display()))
                }
                r = shutdown() => r,
            }
        });
        stop.store(true, Ordering::SeqCst);
        let _ = events.join();
        let _ = std::fs::remove_file(&args.socket);
        rt.shutdown_timeout(Duration::from_secs(1));
        served
    }

    fn log_status(s: &sensr_guard::proto::StatusView) {
        for p in &s.packs {
            tracing::info!(
                pack = %p.name, version = %p.version, active = p.active,
                reason = p.reason.as_deref().unwrap_or(""), "pack"
            );
        }
        let active = s.rules.iter().filter(|r| r.active).count();
        tracing::info!(
            running = s.running,
            enforcing = s.enforcing,
            kill_switch = s.kill_switch,
            lockdown = %s.lockdown,
            rules = s.rules.len(),
            active,
            reason = s.reason.as_deref().unwrap_or(""),
            "status"
        );
    }

    fn event_loop(shared: &Shared<Kernel>, db: &Path, stop: &AtomicBool) {
        let mut store: Option<Store> = None;
        let mut last_prune: Option<Instant> = None;
        loop {
            let stopping = stop.load(Ordering::SeqCst);
            let batches = {
                let mut d = shared.lock();
                let mut b = d.poll_events(Instant::now());
                if stopping {
                    // what the ring buffers still held, then everything
                    b.extend(d.drain());
                }
                b
            };
            for batch in batches {
                if store.is_none() {
                    store = Store::open(db)
                        .inspect_err(
                            |e| tracing::warn!(error = %e, db = %db.display(), "events.db"),
                        )
                        .ok();
                }
                let written = match store.as_mut() {
                    Some(s) => s.write_batch(&batch).map_err(|e| e.to_string()),
                    None => Err("events.db is not open".into()),
                };
                if let Err(e) = written {
                    tracing::warn!(error = %e, rows = batch.rows.len(), "writing events");
                    store = None;
                    if stopping {
                        tracing::warn!(rows = batch.rows.len(), "events lost at shutdown");
                    } else {
                        shared.lock().requeue(batch);
                    }
                }
            }
            if last_prune.is_none_or(|t| t.elapsed() >= PRUNE_EVERY) {
                last_prune = Some(Instant::now());
                let (days, rows) = {
                    let d = shared.lock();
                    (d.config().retention_days, d.config().max_rows)
                };
                if store.is_none() {
                    store = Store::open(db).ok();
                }
                if let Some(s) = store.as_mut()
                    && let Err(e) = s.prune(u32::from(days), u64::from(rows), unix_now())
                {
                    tracing::warn!(error = %e, "pruning events");
                }
            }
            if stopping {
                return;
            }
            std::thread::sleep(POLL);
        }
    }

    fn auto_check_loop(shared: &Shared<Kernel>) {
        loop {
            std::thread::sleep(AUTO_CHECK_POLL);
            let (on, state) = {
                let d = shared.lock();
                (d.config().pack_auto_check, d.options().state_dir.clone())
            };
            if !on || !auto_check_due(&state, unix_now()) {
                continue;
            }
            match shared.check_packs() {
                Reply::Packs(r) => {
                    for c in r {
                        tracing::info!(
                            pack = %c.name, installed = c.installed,
                            available = c.available.as_deref().unwrap_or(""),
                            error = c.error.as_deref().unwrap_or(""), "pack check"
                        );
                    }
                }
                other => tracing::warn!(reply = ?other, "pack check"),
            }
        }
    }

    async fn shutdown() -> anyhow::Result<()> {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = term.recv() => {}
            r = tokio::signal::ctrl_c() => r?,
        }
        tracing::info!("shutting down");
        Ok(())
    }
}
