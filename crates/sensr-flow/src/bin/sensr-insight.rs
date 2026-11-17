//! `sensr-insight`: reads the accounting sets and interface counters into
//! `flows.db`, and tails Suricata's eve.json into `alerts.db`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use clap::Parser;
use sensr_flow::config::{ALERTS_DB, CONFIG_PATH, Config, DB_DIR, FLOWS_DB, FlowConfig, IdsConfig};
use sensr_flow::eve::{AlertStore, Event, Tailer, parse_line};
use sensr_flow::nft::{self, Deltas};
use sensr_flow::store::{Batch, FlowStore};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Configuration rendered by the agent.
    #[arg(long, default_value = CONFIG_PATH)]
    config: PathBuf,
    /// Database directory.
    #[arg(long, default_value = DB_DIR)]
    db_dir: PathBuf,
    /// The nft binary.
    #[arg(long, default_value = "nft")]
    nft: PathBuf,
    /// Interface counters (a test can point this elsewhere).
    #[arg(long, default_value = "/sys/class/net")]
    sysfs: PathBuf,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

fn read_u64(p: &Path) -> Option<u64> {
    std::fs::read_to_string(p).ok()?.trim().parse().ok()
}

/// This process's CPU seconds (user + system), for the periodic cost line.
fn cpu_seconds() -> f64 {
    let Ok(s) = std::fs::read_to_string("/proc/self/stat") else {
        return 0.0;
    };
    // fields after the ")" of the command name: utime is the 12th, stime 13th
    let rest = s.rsplit_once(')').map_or("", |x| x.1);
    let f: Vec<&str> = rest.split_whitespace().collect();
    let tick = |i: usize| f.get(i).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
    (tick(11) + tick(12)) / 100.0
}

fn flows(cfg: FlowConfig, db: PathBuf, nft_bin: PathBuf, sysfs: PathBuf) -> anyhow::Result<()> {
    let mut store = FlowStore::open(&db).with_context(|| db.display().to_string())?;
    let every = Duration::from_secs(u64::from(cfg.sample_seconds.max(1)));
    let mut deltas = Deltas::default();
    let mut ifaces: HashMap<String, (u64, u64)> = HashMap::new();
    let mut last_prune = 0;
    let mut last_cost = (Instant::now(), cpu_seconds());
    let mut next = Instant::now();
    loop {
        let t = now();
        let mut batch = Batch::default();
        match std::process::Command::new(&nft_bin)
            .args(["-j", "list", "table", "inet", nft::TABLE])
            .output()
        {
            Ok(out) if out.status.success() => {
                batch.add_counters(&deltas.next(nft::parse(&out.stdout)));
            }
            Ok(out) => tracing::debug!(
                stderr = %String::from_utf8_lossy(&out.stderr),
                "accounting table not readable (not loaded yet?)"
            ),
            Err(e) => tracing::warn!(error = %e, "running nft"),
        }
        let mut sample = Batch::default();
        for i in &cfg.interfaces {
            let stat = sysfs.join(&i.device).join("statistics");
            let (Some(rx), Some(tx)) = (
                read_u64(&stat.join("rx_bytes")),
                read_u64(&stat.join("tx_bytes")),
            ) else {
                continue;
            };
            if let Some((prx, ptx)) = ifaces.insert(i.name.clone(), (rx, tx)) {
                // a counter going down: the device was re-created
                let d = |now: u64, prev: u64| if now >= prev { now - prev } else { now };
                sample.add_iface(&i.name, d(rx, prx), d(tx, ptx));
            }
        }
        for (k, v) in &sample.rows {
            batch.rows.insert(k.clone(), *v);
        }
        if !sample.is_empty() {
            store.write_samples(t, &sample)?;
        }
        if !batch.is_empty() {
            // buckets accumulate, so writing every sample loses nothing on a stop
            store.write_minute(t, &batch)?;
        }
        if t - last_prune >= 3600 {
            match store.prune(t, &cfg.retention) {
                Ok(n) => tracing::info!(rows = n, "flow history pruned"),
                Err(e) => tracing::warn!(error = %e, "pruning flow history"),
            }
            last_prune = t;
        }
        if last_cost.0.elapsed() >= Duration::from_secs(600) {
            let cpu = cpu_seconds();
            let wall = last_cost.0.elapsed().as_secs_f64();
            tracing::info!(
                cpu_percent = format!("{:.3}", 100.0 * (cpu - last_cost.1) / wall),
                "insight cost over the last 10 minutes"
            );
            last_cost = (Instant::now(), cpu);
        }
        next += every;
        let now_i = Instant::now();
        if next > now_i {
            std::thread::sleep(next - now_i);
        } else {
            next = now_i;
        }
    }
}

fn alerts(cfg: IdsConfig, db: PathBuf) -> anyhow::Result<()> {
    let mut store = AlertStore::open(&db).with_context(|| db.display().to_string())?;
    let mut tail = Tailer::new(cfg.eve.clone(), store.position()?);
    let mut last_prune = 0;
    loop {
        let (lines, pos) = tail.poll();
        if !lines.is_empty() {
            let events: Vec<Event> = lines.iter().filter_map(|l| parse_line(l)).collect();
            store.write(&events, pos)?;
        }
        let t = now();
        if t - last_prune >= 3600 {
            match store.prune(t * 1000, cfg.retention_days, cfg.max_alerts) {
                Ok(n) => tracing::info!(rows = n, "alerts pruned"),
                Err(e) => tracing::warn!(error = %e, "pruning alerts"),
            }
            last_prune = t;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    let text =
        std::fs::read_to_string(&args.config).with_context(|| args.config.display().to_string())?;
    let cfg: Config = serde_json::from_str(&text).context("parsing the configuration")?;
    std::fs::create_dir_all(&args.db_dir).ok();
    let mut threads = Vec::new();
    if let Some(f) = cfg.flows {
        let (db, nft, sysfs) = (
            args.db_dir.join(FLOWS_DB),
            args.nft.clone(),
            args.sysfs.clone(),
        );
        threads.push(std::thread::spawn(move || flows(f, db, nft, sysfs)));
    }
    if let Some(i) = cfg.ids {
        let db = args.db_dir.join(ALERTS_DB);
        threads.push(std::thread::spawn(move || alerts(i, db)));
    }
    if threads.is_empty() {
        tracing::info!("nothing to do");
        return Ok(());
    }
    // one part failing (a broken database) takes the process down so
    // systemd restarts it
    for t in threads {
        match t.join() {
            Ok(r) => r?,
            Err(_) => anyhow::bail!("a worker thread panicked"),
        }
    }
    Ok(())
}
