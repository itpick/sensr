//! `sensr-agent` binary.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use sensr_agent::applier::{Applier, PreviewApplier};
use sensr_agent::slice_applier::SliceApplier;
use sensr_agent::{Agent, Settings};
use sensr_config::{CommitMeta, Store};

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
    /// State directory: the sensr-config store (`config.db`, head exported
    /// redacted to `config.json`) and the secrets key. Omit for an
    /// in-memory store.
    #[arg(long, env = "SENSR_STATE_DIR")]
    state_dir: Option<PathBuf>,
    /// Key file sealing the store's secrets table (created 0600 if
    /// missing). Defaults to `<state-dir>/secrets.key`.
    #[arg(long, env = "SENSR_SECRETS_KEY")]
    secrets_key: Option<PathBuf>,
    /// Store secrets without encryption at rest (they still live in their
    /// own table, never in the revision documents).
    #[arg(long)]
    no_secrets_encryption: bool,
    /// Declarative mode: a sensr document (JSON) that is the source of
    /// truth. At startup it is committed whenever head differs from it.
    #[arg(long)]
    seed: Option<PathBuf>,
    /// First-boot seed folder: a `config.xml` here is imported once onto a
    /// store that holds only the factory revision.
    #[arg(long, env = "SENSR_SEED_DIR")]
    seed_dir: Option<PathBuf>,
    /// A seed config.xml that does not validate: `strict` imports nothing
    /// (factory config, report in the seed folder); `partial` drops the
    /// items that fail and imports the rest.
    #[arg(long, value_enum, default_value_t = SeedImport::Strict, env = "SENSR_SEED_IMPORT")]
    seed_import: SeedImport,
    /// Peer uid allowed to act for the principals it authenticated (sensr-api).
    #[arg(long = "trust-uid")]
    trust_uids: Vec<u32>,
    /// Peer gid allowed to act for the principals it authenticated.
    #[arg(long = "trust-gid")]
    trust_gids: Vec<u32>,
    /// Group names whose members (primary or supplementary group) may act
    /// for the principals they authenticated.
    #[arg(
        long = "trust-group",
        env = "SENSR_TRUST_GROUPS",
        value_delimiter = ','
    )]
    trust_groups: Vec<String>,
    /// Longest commit-confirm window accepted, in seconds.
    #[arg(long, default_value_t = 86_400)]
    max_confirm_secs: u64,
    /// Apply pipeline: `preview` plans but changes nothing on the host;
    /// `slice` applies (networkd links, nftables, Kea, Unbound, WireGuard,
    /// sysctls, qdiscs).
    #[arg(long, value_enum, default_value_t = ApplierKind::Preview, env = "SENSR_APPLIER")]
    applier: ApplierKind,
}

/// How a seed config.xml that does not validate is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum SeedImport {
    /// Import nothing.
    Strict,
    /// Import what validates.
    Partial,
}

/// Which apply pipeline the agent runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ApplierKind {
    /// Plan only.
    Preview,
    /// The routing-slice engine.
    Slice,
}

fn parse_mode(s: &str) -> Result<u32, String> {
    u32::from_str_radix(s, 8).map_err(|e| format!("not an octal mode: {e}"))
}

fn seed_store(store: &Store, seed: Option<&PathBuf>) -> anyhow::Result<()> {
    let Some(path) = seed else { return Ok(()) };
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading seed {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&text).context("seed is not JSON")?;
    let document = sensr_agent::agent::decode(&value).map_err(|e| {
        let issues: Vec<String> = e
            .validations
            .iter()
            .map(|v| format!("{}: {}", v.path, v.message))
            .collect();
        anyhow::anyhow!(
            "seed {} does not fit the schema: {}",
            path.display(),
            issues.join("; ")
        )
    })?;
    store.import(
        &document,
        CommitMeta::new(
            "sensr-agent@system",
            format!("declarative config {}", path.display()),
        ),
    )?;
    Ok(())
}

fn open_store(args: &Args) -> anyhow::Result<Store> {
    let Some(dir) = &args.state_dir else {
        return Ok(sensr_agent::store::in_memory());
    };
    let key = (!args.no_secrets_encryption).then(|| {
        args.secrets_key
            .clone()
            .unwrap_or_else(|| dir.join("secrets.key"))
    });
    sensr_agent::store::open(
        &dir.join("config.db"),
        Some(dir.join("config.json")),
        key.as_deref(),
    )
    .with_context(|| format!("opening the config store in {}", dir.display()))
}

async fn serve(args: Args) -> anyhow::Result<()> {
    let store = open_store(&args)?;
    seed_store(&store, args.seed.as_ref())?;
    let mut seed_problems = Vec::new();
    if let (Some(seed_dir), Some(state_dir)) = (&args.seed_dir, &args.state_dir) {
        let mode = match args.seed_import {
            SeedImport::Strict => sensr_agent::seed::ImportMode::Strict,
            SeedImport::Partial => sensr_agent::seed::ImportMode::Partial,
        };
        match sensr_agent::seed::import_seed(&store, seed_dir, state_dir, mode) {
            Ok(outcome) => {
                if let sensr_agent::seed::SeedOutcome::Imported {
                    dropped, report, ..
                } = &outcome
                    && !dropped.is_empty()
                {
                    seed_problems.push(format!(
                        "config.xml partially imported: {} item(s) dropped, see {}",
                        dropped.len(),
                        report.display()
                    ));
                }
                tracing::info!(?outcome, seed_dir = %seed_dir.display(), "seed folder checked")
            }
            // Keep booting on the factory config; the report says why.
            Err(e) => {
                tracing::error!(error = %e, "seed import failed");
                seed_problems.push(format!("config.xml not imported: {e}"));
            }
        }
        let nics = sensr_agent::ifnames::host_nics(std::path::Path::new("/"));
        match sensr_agent::seed::apply_seed_files(&store, seed_dir, state_dir, &nics) {
            Ok(notes) => notes.iter().for_each(|n| tracing::info!("{n}")),
            Err(e) => {
                tracing::error!(error = %e, "seed.toml / ifnames / authorized_keys not applied");
                seed_problems.push(format!("seed files not applied: {e}"));
            }
        }
    }
    let mut trusted_gids = args.trust_gids.clone();
    for name in &args.trust_groups {
        match sensr_agent::agent::group_id(name) {
            Some(gid) => trusted_gids.push(gid),
            None => tracing::warn!(group = %name, "trusted group does not exist"),
        }
    }
    let settings = Settings {
        trusted_uids: args.trust_uids.clone(),
        trusted_gids,
        max_confirm: Duration::from_secs(args.max_confirm_secs),
        tls_dir: args.state_dir.as_ref().map(|d| d.join("tls")),
        // binding cards is only worth doing when the config is really applied
        pin_first_boot: args.applier == ApplierKind::Slice,
        state_dir: args.state_dir.clone(),
        // a persistent agent is the box's agent: sshd reads these files
        ssh_keys_dir: args
            .state_dir
            .as_ref()
            .map(|_| PathBuf::from(sensr_agent::ssh::KEYS_DIR)),
        ..Settings::default()
    };
    match args.applier {
        ApplierKind::Preview => {
            run_agent(args, store, PreviewApplier, settings, seed_problems).await
        }
        ApplierKind::Slice => {
            let feeds = args.state_dir.as_ref().map(|d| d.join("state/aliases"));
            let applier =
                SliceApplier::system_with_feeds(feeds).context("starting the apply engine")?;
            run_agent(args, store, applier, settings, seed_problems).await
        }
    }
}

async fn run_agent<A: Applier>(
    args: Args,
    store: Store,
    applier: A,
    settings: Settings,
    seed_problems: Vec<String>,
) -> anyhow::Result<()> {
    let agent = Agent::new(store, applier, settings).map_err(|e| anyhow::anyhow!(e))?;
    if !seed_problems.is_empty() {
        agent.set_seed_error(Some(seed_problems.join("\n")));
    }
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
    serve(Args::parse()).await
}
