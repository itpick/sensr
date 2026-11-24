//! `sensr-agent`, the privileged daemon (docs/PLAN.md §2.3): owns the config
//! store, runs the apply pipeline and commit-confirm, and serves
//! `sensr-ipc` on `/run/sensr/agent.sock`.
//!
//! The config store is `sensr-config`'s [`Store`](sensr_config::Store) over
//! the typed `sensr-schema` document (in memory for tests). The apply
//! pipeline sits behind the [`applier::Applier`] trait so the daemon, its
//! IPC surface and the CLI/API on top can be tested end to end with a fake.

pub mod agent;
pub mod applier;
pub mod arp_intercept;
pub mod auth;
pub mod diff;
pub mod fingerprint;
pub mod gateways;
pub mod hosts;
pub mod ifnames;
pub mod pd;
pub mod portscan;
pub mod redact;
pub mod seed;
pub mod slice_applier;
pub mod ssh;
pub mod store;
pub mod systemd;
pub mod tls;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::watch;
use tokio::task::JoinHandle;

pub use agent::{Agent, Settings};
use applier::Applier;

/// A running agent: IPC server, confirm timer and watchdog tasks.
pub struct Running {
    /// Socket the agent listens on.
    pub socket: PathBuf,
    stop: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl Running {
    /// Signals shutdown and waits for in-flight requests to finish.
    pub async fn shutdown(self) {
        let _ = self.stop.send(true);
        for t in self.tasks {
            let _ = t.await;
        }
    }
}

/// Binds `socket` (mode `mode`, optionally group-owned by `gid`) and starts
/// serving `agent`.
pub fn start<A: Applier>(
    agent: Arc<Agent<A>>,
    socket: &Path,
    mode: u32,
    gid: Option<u32>,
) -> std::io::Result<Running> {
    let listener = sensr_ipc::server::bind(socket, mode)?;
    if gid.is_some() {
        std::os::unix::fs::chown(socket, None, gid)?;
    }
    let (stop, rx) = watch::channel(false);
    let mut tasks = Vec::new();
    tasks.push(tokio::spawn(sensr_ipc::server::serve(
        listener,
        agent.clone(),
        rx.clone(),
    )));
    tasks.push(tokio::spawn(agent.clone().run_confirm_timer(rx.clone())));
    let probe = agent.clone();
    tasks.push(tokio::spawn(async move {
        systemd::watchdog(
            move || {
                let a = probe.clone();
                async move { a.health().await }
            },
            rx,
        )
        .await
    }));
    Ok(Running {
        socket: socket.to_owned(),
        stop,
        tasks,
    })
}

/// Runs until `SIGTERM`/`SIGINT`; `SIGHUP` re-applies head (graceful
/// reload: the socket stays open and in-flight requests are unaffected).
pub async fn run_until_signal<A: Applier>(
    agent: Arc<Agent<A>>,
    running: Running,
) -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut hup = signal(SignalKind::hangup())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    systemd::ready("serving");
    loop {
        tokio::select! {
            _ = hup.recv() => {
                systemd::reloading();
                tracing::info!("SIGHUP: re-applying head");
                match agent.reload().await {
                    Ok(()) => systemd::ready("serving"),
                    Err(e) => {
                        tracing::error!(error = %e, "reload failed; previous state kept");
                        systemd::ready("serving (last reload failed)");
                    }
                }
            }
            _ = term.recv() => break,
            _ = int.recv() => break,
        }
    }
    systemd::stopping();
    tracing::info!("shutting down");
    running.shutdown().await;
    Ok(())
}
