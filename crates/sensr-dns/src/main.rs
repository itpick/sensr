//! `sensr-dns`: the blocklist refresh, the lease watcher, and tools.

use std::collections::BTreeMap;
use std::fs;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sensr_apply::appliers::dns_runtime::{self, DnsRuntime};
use sensr_apply::cmd::SystemRunner;
use sensr_dns::compile::{Verdict, compile};
use sensr_dns::control::Control;
use sensr_dns::fetch::HttpFetcher;
use sensr_dns::leases;
use sensr_dns::parse::parse_reader;
use sensr_dns::stats::UnboundStats;
use sensr_dns::update::{self, Paths, rfc3339, write_atomic};

#[derive(Parser)]
#[command(about = "sensr DNS runtime: blocklists and DHCP lease registration for Unbound")]
struct Cli {
    /// Runtime configuration rendered by the sensr agent.
    #[arg(long, default_value = dns_runtime::RUNTIME_CONF)]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Fetch the lists that are due, compile, and swap the result in.
    BlocklistUpdate {
        /// Download every list now, ignoring the refresh intervals.
        #[arg(long)]
        force: bool,
    },
    /// Register DHCP leases as they change, and sample resolver counters.
    Watch,
    /// Show what the compiled blocklist answers for a name (cached lists).
    Check {
        /// The name.
        name: String,
        /// The client asking.
        #[arg(long, default_value = "192.0.2.1")]
        client: IpAddr,
    },
    /// Compile local list files with the first policy's settings and report
    /// time and size (benchmarking).
    Compile {
        /// List files.
        files: Vec<PathBuf>,
        /// Where to write the include.
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load(path: &PathBuf) -> Result<DnsRuntime> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .without_time()
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::BlocklistUpdate { force } => {
            // A configuration change while a refresh runs (its path unit
            // cannot start it twice) is picked up by running again.
            let mut text = fs::read_to_string(&cli.config).unwrap_or_default();
            loop {
                let cfg = load(&cli.config)?;
                let control = Control::new(&SystemRunner, &cfg.control_conf);
                let st = update::run(
                    &cfg,
                    &Paths::new(&cfg.state_dir),
                    &HttpFetcher::default(),
                    &control,
                    force,
                    now(),
                )?;
                tracing::info!(
                    "blocklist: {} names in {} ms, {}; peak RSS {}",
                    st.names,
                    st.duration_ms,
                    st.applied,
                    peak_rss().unwrap_or_else(|| "?".into())
                );
                let again = fs::read_to_string(&cli.config).unwrap_or_default();
                if again == text {
                    break;
                }
                tracing::info!("configuration changed during the refresh; running again");
                text = again;
            }
        }
        Cmd::Watch => watch(&cli.config)?,
        Cmd::Check { name, client } => {
            let cfg = load(&cli.config)?;
            let bl = cfg.blocklist.context("no blocklist is enabled")?;
            let paths = Paths::new(&cfg.state_dir);
            let cache = sensr_dns::fetch::Cache::new(&paths.cache);
            let mut sources = BTreeMap::new();
            for u in bl.policies.iter().flat_map(|p| p.policy.sources()) {
                let mut v = Vec::new();
                if let Ok(f) = fs::File::open(cache.body_path(&u)) {
                    parse_reader(BufReader::new(f), |e| v.push(e))?;
                }
                sources.insert(u, v);
            }
            let c = compile(&bl, &sources);
            match c.lookup(client, &name) {
                Some(Verdict::Blocked(i)) => {
                    println!(
                        "blocked by {:?} ({:?})",
                        c.policies[i].description, c.policies[i].answer
                    )
                }
                Some(Verdict::Allowed) => println!("allowed"),
                None => println!("not listed"),
            }
        }
        Cmd::Compile { files, out } => {
            let cfg = load(&cli.config).ok();
            let mut bl = cfg
                .and_then(|c| c.blocklist)
                .context("compile needs a runtime config with a blocklist policy")?;
            bl.policies.truncate(1);
            let p = &mut bl.policies[0].policy;
            p.lists.clear();
            p.urls = files
                .iter()
                .map(|f| format!("http://local/{}", f.display()).parse())
                .collect::<Result<_, _>>()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let t = Instant::now();
            let mut sources = BTreeMap::new();
            for (f, u) in files.iter().zip(p.sources()) {
                let mut v = Vec::new();
                let st = parse_reader(BufReader::new(fs::File::open(f)?), |e| v.push(e))?;
                eprintln!(
                    "{}: {} entries, {} rejected",
                    f.display(),
                    st.entries,
                    st.rejected
                );
                sources.insert(u, v);
            }
            let parsed = t.elapsed();
            let c = compile(&bl, &sources);
            drop(sources);
            let compiled = t.elapsed();
            let text = c.render();
            let rendered = t.elapsed();
            if let Some(o) = out {
                write_atomic(&o, text.as_bytes())?;
            }
            eprintln!(
                "{} names, {} bytes; parse {:?}, compile {:?}, render {:?}; peak RSS {}",
                c.len(),
                text.len(),
                parsed,
                compiled - parsed,
                rendered - compiled,
                peak_rss().unwrap_or_else(|| "?".into())
            );
        }
    }
    Ok(())
}

/// VmHWM from /proc (Linux).
fn peak_rss() -> Option<String> {
    let s = fs::read_to_string("/proc/self/status").ok()?;
    s.lines()
        .find(|l| l.starts_with("VmHWM"))
        .map(|l| l.split_whitespace().skip(1).collect::<Vec<_>>().join(" "))
}

/// The lease watcher and statistics sampler.
fn watch(config: &PathBuf) -> Result<()> {
    let cfg = load(config)?;
    let control = Control::new(&SystemRunner, &cfg.control_conf);
    let include = cfg.state_dir.join("leases.conf");
    let stats_file = PathBuf::from(dns_runtime::STATS_FILE);
    let mut pushed: Option<leases::Records> = None;
    let mut last_stamp = None;
    let mut last_uptime = f64::MAX;
    let mut last_stats = Instant::now() - Duration::from_secs(3600);
    if cfg.leases.is_none() {
        let _ = fs::remove_file(&include);
    }
    loop {
        // Unbound restarted (uptime went down): what was pushed is gone,
        // except what the include file restored. Push everything again.
        if last_stats.elapsed() >= Duration::from_secs(60) {
            last_stats = Instant::now();
            match control.stats() {
                Ok(c) => {
                    let up = c.get("time.up").copied().unwrap_or(0.0);
                    if up < last_uptime {
                        pushed = None;
                    }
                    last_uptime = up;
                    if cfg.statistics {
                        let s = UnboundStats::from_counters(&c, rfc3339(now()));
                        if let Err(e) = write_atomic(
                            &stats_file,
                            &serde_json::to_vec_pretty(&s).unwrap_or_default(),
                        ) {
                            tracing::warn!("writing {}: {e}", stats_file.display());
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("unbound not answering: {e}");
                    pushed = None;
                    last_uptime = f64::MAX;
                }
            }
        }
        if let Some(l) = &cfg.leases {
            let st = leases::stamp(&l.lease_file);
            // Leases also expire without the file changing.
            let due =
                pushed.is_none() || last_stamp.as_ref() != Some(&st) || now().is_multiple_of(30);
            if due {
                last_stamp = Some(st);
                let recs = leases::records(l, &leases::read_leases(&l.lease_file), now());
                if pushed.as_ref() != Some(&recs) {
                    write_atomic(&include, leases::render(&recs).as_bytes())?;
                    let empty = leases::Records::new();
                    match leases::push(&control, pushed.as_ref().unwrap_or(&empty), &recs) {
                        Ok(n) => {
                            if n > 0 {
                                tracing::info!(
                                    "leases: {} names registered ({n} changes)",
                                    recs.len()
                                );
                            }
                            pushed = Some(recs);
                        }
                        Err(e) => tracing::debug!("pushing leases: {e}"),
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
