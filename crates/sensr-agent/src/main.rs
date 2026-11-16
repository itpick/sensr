//! `sensr-agent` binary.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use sensr_agent::applier::PreviewApplier;
use sensr_agent::store::{ConfigStore, JsonDirStore, MemStore, NewRevision};
use sensr_agent::{Agent, Settings};

/// The privileged sensr daemon.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// IPC socket path.
    #[arg(long, default_value = sensr_ipc::client::DEFAULT_SOCKET, env = "SENSR_AGENT_SOCKET")]
    socket: PathBuf,
    /// Socket permission bits (octal).
    #[arg(long, default_value = "660", value_parser = parse_mode)]
    socket_mode: u32,
    /// Group owning the socket (numeric gid).
    #[arg(long)]
    socket_gid: Option<u32>,
    /// State directory (revisions, agent state). Omit for an in-memory store.
    #[arg(long, env = "SENSR_STATE_DIR")]
    state_dir: Option<PathBuf>,
    /// Seed document committed as revision 1 when the store is empty.
    #[arg(long)]
    seed: Option<PathBuf>,
    /// Peer uid allowed to act for the principals it authenticated (sensr-api).
    #[arg(long = "trust-uid")]
    trust_uids: Vec<u32>,
    /// Peer gid allowed to act for the principals it authenticated.
    #[arg(long = "trust-gid")]
    trust_gids: Vec<u32>,
    /// Longest commit-confirm window accepted, in seconds.
    #[arg(long, default_value_t = 86_400)]
    max_confirm_secs: u64,
}

fn parse_mode(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s, 8).map_err(|e| format!("not an octal mode: {e}"))
}

fn seed_store(store: &mut dyn ConfigStore, seed: Option<&PathBuf>) -> anyhow::Result<()> {
    let Some(path) = seed else { return Ok(()) };
    if store.head()?.is_some() {
        return Ok(());
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading seed {}", path.display()))?;
    let document: serde_json::Value = serde_json::from_str(&text).context("seed is not JSON")?;
    anyhow::ensure!(document.is_object(), "seed must be a JSON object");
    store.commit(NewRevision {
        document,
        username: "sensr-agent@system".into(),
        description: format!("initial seed from {}", path.display()),
        impersonated_by: None,
    })?;
    Ok(())
}

async fn serve<S: ConfigStore>(args: Args, mut store: S) -> anyhow::Result<()> {
    seed_store(&mut store, args.seed.as_ref())?;
    let settings = Settings {
        trusted_uids: args.trust_uids,
        trusted_gids: args.trust_gids,
        state_file: args.state_dir.as_ref().map(|d| d.join("agent-state.json")),
        max_confirm: Duration::from_secs(args.max_confirm_secs),
        ..Settings::default()
    };
    let agent = Agent::new(store, PreviewApplier, settings).map_err(|e| anyhow::anyhow!(e))?;
    if let Err(e) = agent.boot().await {
        // Keep serving: the operator needs the socket to fix the config.
        tracing::error!(error = %e, "boot apply failed");
    }
    let running = sensr_agent::start(
        agent.clone(),
        &args.socket,
        args.socket_mode,
        args.socket_gid,
    )
    .with_context(|| format!("binding {}", args.socket.display()))?;
    tracing::info!(socket = %args.socket.display(), "sensr-agent listening");
    sensr_agent::run_until_signal(agent, running).await
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    match &args.state_dir {
        Some(dir) => {
            let store = JsonDirStore::open(&dir.join("revisions"))?;
            serve(args, store).await
        }
        None => serve(args, MemStore::new()).await,
    }
}
