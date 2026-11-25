//! `sensr-scan`: the port scanner daemon.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use clap::Parser;
use sensr_scan::config::{self, Config};
use sensr_scan::ports::Services;
use sensr_scan::server::{Daemon, serve};
use sensr_scan::store::Store;
use tracing_subscriber::EnvFilter;

/// How often old results are pruned.
const PRUNE_EVERY: Duration = Duration::from_secs(24 * 3600);

/// Port scanner daemon for sensr (Diagnostics > Port Scan).
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Configuration JSON written by the agent.
    #[arg(long, default_value = config::CONFIG_PATH)]
    config: PathBuf,
    /// Results database.
    #[arg(long, default_value_t = format!("{}/{}", config::DB_DIR, config::DB))]
    db: String,
    /// Control socket to serve.
    #[arg(long, default_value = config::SOCKET)]
    socket: PathBuf,
    /// Service names, in /etc/services format.
    #[arg(long, default_value = "/etc/services")]
    services: PathBuf,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();

    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("reading {}", args.config.display()))?;
    let cfg: Config = serde_json::from_str(&text)
        .with_context(|| format!("parsing {}", args.config.display()))?;
    let db = PathBuf::from(&args.db);

    {
        let store = Store::open(&db).with_context(|| format!("opening {}", db.display()))?;
        let stale = store.fail_stale().context("failing stale jobs")?;
        if stale > 0 {
            tracing::warn!(stale, "jobs left running by a previous run marked failed");
        }
    }
    let daemon = Arc::new(
        Daemon::new(cfg, &db, Services::load(&args.services))
            .with_context(|| format!("opening {}", db.display()))?,
    );

    let pruner = Arc::clone(&daemon);
    tokio::spawn(async move {
        let mut every = tokio::time::interval(PRUNE_EVERY);
        loop {
            // The first tick is immediate: prune at startup.
            every.tick().await;
            if let Err(e) = pruner.prune(now()) {
                tracing::error!(error = %e, "pruning failed");
            }
        }
    });
    daemon.spawn_worker();

    tracing::info!(socket = %args.socket.display(), "sensr-scan serving");
    let socket = args.socket.clone();
    tokio::select! {
        r = serve(&socket, daemon) => r.with_context(|| format!("serving {}", socket.display()))?,
        r = shutdown() => r?,
    }
    let _ = std::fs::remove_file(&args.socket);
    Ok(())
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
