//! `sensr-insight`: reads the accounting sets and interface counters into
//! `flows.db`, Unbound's dnstap feed into per-host DNS activity (also in
//! `flows.db`), and tails Suricata's eve.json into `alerts.db`.

use std::collections::HashMap;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, sync_channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use clap::Parser;
use sensr_flow::attrib::MinuteResult;
use sensr_flow::config::{
    ALERTS_DB, CONFIG_PATH, Config, DB_DIR, DNS_STATUS, DNSTAP_GROUP, DnsConfig, DnsStatus,
    FLOWS_DB, FlowConfig, IdsConfig,
};
use sensr_flow::dnstap::DnstapEvent;
use sensr_flow::eve::{AlertStore, Event, Tailer, parse_line};
use sensr_flow::feed::{Feed, Neighbours, QueryLog, StaleWatch, read_query_counter};
use sensr_flow::nft::{self, Count, Deltas, Key};
use sensr_flow::services::Catalogue;
use sensr_flow::store::{Batch, FlowStore};
use sensr_flow::tap;

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
    /// The ip binary (the neighbour table, for per-host DNS activity).
    #[arg(long, default_value = "ip")]
    ip: PathBuf,
    /// Interface counters (a test can point this elsewhere).
    #[arg(long, default_value = "/sys/class/net")]
    sysfs: PathBuf,
}

/// External programs the flow loop runs.
#[derive(Debug, Clone)]
struct Tools {
    nft: PathBuf,
    ip: PathBuf,
}

/// How old the status file's `last_frame` may get while frames arrive.
const STATUS_REFRESH_SECS: i64 = 300;

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

/// One `nft -j list table`, streamed from the pipe into counters. `None`
/// when nft failed or the listing was damaged: then no deltas are taken, so
/// the next good listing is compared with the last good one.
fn list_counters(nft_bin: &Path) -> Option<HashMap<Key, Count>> {
    let mut child = match Command::new(nft_bin)
        .args(["-j", "list", "table", "inet", nft::TABLE])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "running nft");
            return None;
        }
    };
    let parsed = child
        .stdout
        .take()
        .map(|out| nft::parse_reader(BufReader::with_capacity(64 * 1024, out)));
    if !matches!(parsed, Some(Ok(_))) {
        let _ = child.kill();
    }
    let ok = child.wait().is_ok_and(|s| s.success());
    match parsed {
        Some(Ok(m)) if ok => Some(m),
        Some(Err(e)) if ok => {
            tracing::warn!(error = %e, "accounting table listing unreadable");
            None
        }
        _ => {
            tracing::debug!("accounting table not readable (not loaded yet?)");
            None
        }
    }
}

/// Per-host DNS activity: the dnstap listener's events, the neighbour
/// table, the attribution feed, and the staleness watch.
struct Dns {
    feed: Feed,
    rx: Receiver<DnstapEvent>,
    shared: Arc<tap::Shared>,
    log: Option<QueryLog>,
    stats: Option<PathBuf>,
    watch: StaleWatch,
    frames_seen: u64,
    status: Option<DnsStatus>,
    status_path: PathBuf,
}

impl Dns {
    fn start(cfg: &DnsConfig, db_dir: &Path) -> Dns {
        let (tx, rx) = sync_channel(tap::QUEUE);
        let shared = Arc::new(tap::Shared::default());
        match tap::bind(&cfg.socket, Some(DNSTAP_GROUP)) {
            Ok(l) => {
                let s = Arc::clone(&shared);
                let spawned = std::thread::Builder::new()
                    .name("dnstap".into())
                    .spawn(move || tap::serve(l, tx, s));
                match spawned {
                    Ok(_) => {
                        tracing::info!(socket = %cfg.socket.display(), "listening for dnstap");
                    }
                    Err(e) => tracing::error!(error = %e, "starting the dnstap listener"),
                }
            }
            // the page says the feed is stale; traffic accounting goes on
            Err(e) => tracing::error!(
                error = %e, socket = %cfg.socket.display(), "creating the dnstap socket"
            ),
        }
        let cat = Catalogue::builtin().with_overrides(&cfg.service_overrides);
        Dns {
            feed: Feed::new(cat),
            rx,
            shared,
            log: cfg.query_log.as_deref().map(QueryLog::new),
            stats: cfg.unbound_stats.clone(),
            watch: StaleWatch::default(),
            frames_seen: 0,
            status: None,
            status_path: db_dir.join(DNS_STATUS),
        }
    }

    fn refresh_neighbours(&mut self, ip_bin: &Path) {
        match Command::new(ip_bin)
            .args(["-j", "neigh", "show"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        {
            Ok(out) if out.status.success() => {
                self.feed.set_neighbours(Neighbours::parse(&out.stdout));
            }
            Ok(out) => tracing::debug!(status = %out.status, "ip neigh failed"),
            Err(e) => tracing::warn!(error = %e, "running ip"),
        }
    }

    /// One sample: neighbours, then the DNS events gathered since the last
    /// sample (or the query log while stale), then the pair deltas, then
    /// the minutes that are over, which it returns for writing.
    fn sample(
        &mut self,
        t: i64,
        deltas: &[(Key, Count)],
        tools: &Tools,
    ) -> Vec<(i64, MinuteResult)> {
        self.refresh_neighbours(&tools.ip);
        // the events first: an answer and the bytes that follow it meet in
        // the same minute (the channel is bounded, so is this loop)
        while let Ok(ev) = self.rx.try_recv() {
            self.feed.on_dns(&ev);
        }
        let frames = self.shared.frames.load(Ordering::Relaxed);
        let fresh = frames != self.frames_seen;
        self.frames_seen = frames;
        let last = self.shared.last_frame.load(Ordering::Relaxed);
        let queries = self.stats.as_deref().and_then(read_query_counter);
        let stale = self.watch.observe(t, queries, frames);
        if let Some(log) = &mut self.log {
            if fresh {
                log.skip();
            } else if stale {
                for (time, client, qname) in log.read_new() {
                    self.feed.on_logged_query(client, &qname, time.unwrap_or(t));
                }
            }
        }
        self.feed.on_pairs(deltas, t);
        let due = self.feed.due(t);
        let status = DnsStatus {
            dns_feed_stale: stale,
            last_frame: (last > 0).then_some(last),
        };
        // rewritten when staleness flips, and every few minutes while
        // frames arrive (so `last_frame` stays roughly current)
        let refresh = self.status.is_none_or(|s| {
            s.dns_feed_stale != stale
                || s.last_frame
                    .is_some_and(|l| last - l >= STATUS_REFRESH_SECS)
                || (s.last_frame.is_none() && last > 0)
        });
        if refresh {
            if stale && self.status.is_none_or(|s| !s.dns_feed_stale) {
                tracing::warn!("no dnstap frames for 5 minutes while Unbound answered queries");
            }
            match write_status(&self.status_path, &status) {
                Ok(()) => self.status = Some(status),
                Err(e) => tracing::warn!(error = %e, "writing the DNS feed status"),
            }
        }
        due
    }

    fn cost_fields(&self) -> String {
        format!(
            "ip_map={} neighbours={} dropped_events={} unknown_addresses={} connections={}",
            self.feed.map_len(),
            self.feed.neighbours().len(),
            self.shared.dropped.load(Ordering::Relaxed),
            self.feed.unknown,
            self.shared.connections.load(Ordering::Relaxed),
        )
    }
}

/// Replaces the status file in one step (the API may read it any time).
fn write_status(path: &Path, s: &DnsStatus) -> std::io::Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(s).unwrap_or_default())?;
    std::fs::rename(&tmp, path)
}

fn flows(cfg: FlowConfig, db_dir: PathBuf, tools: Tools, sysfs: PathBuf) -> anyhow::Result<()> {
    let db = db_dir.join(FLOWS_DB);
    let mut store = FlowStore::open(&db).with_context(|| db.display().to_string())?;
    let every = Duration::from_secs(u64::from(cfg.sample_seconds.max(1)));
    let mut deltas = Deltas::default();
    let mut dns = cfg.dns.as_ref().map(|d| Dns::start(d, &db_dir));
    if dns.is_none() {
        // no feed: no status (the API reads its absence as "off")
        let _ = std::fs::remove_file(db_dir.join(DNS_STATUS));
    }
    let mut ifaces: HashMap<String, (u64, u64)> = HashMap::new();
    let mut last_prune = 0;
    let mut last_cost = (Instant::now(), cpu_seconds());
    let mut next = Instant::now();
    loop {
        let t = now();
        let mut batch = Batch::default();
        let changed = list_counters(&tools.nft)
            .map(|m| deltas.next(m))
            .unwrap_or_default();
        batch.add_counters(&changed);
        let activity = dns
            .as_mut()
            .map(|d| d.sample(t, &changed, &tools))
            .unwrap_or_default();
        drop(changed);
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
        // buckets accumulate, so writing every sample loses nothing on a
        // stop; the closed activity minutes go in the same transaction
        if !batch.is_empty() || !activity.is_empty() {
            match store.write_minute_and_activity(t, &batch, &activity) {
                Ok(()) => {}
                // DNS activity never takes traffic accounting down
                Err(e) if !activity.is_empty() => {
                    tracing::warn!(error = %e, "writing DNS activity; traffic written alone");
                    if !batch.is_empty() {
                        store.write_minute(t, &batch)?;
                    }
                }
                Err(e) => return Err(e.into()),
            }
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
                dns = dns.as_ref().map(Dns::cost_fields).unwrap_or_default(),
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
        let tools = Tools {
            nft: args.nft.clone(),
            ip: args.ip.clone(),
        };
        let (dir, sysfs) = (args.db_dir.clone(), args.sysfs.clone());
        threads.push(std::thread::spawn(move || flows(f, dir, tools, sysfs)));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_file_replaced_whole() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(DNS_STATUS);
        let s = DnsStatus {
            dns_feed_stale: true,
            last_frame: Some(5),
        };
        write_status(&p, &s).unwrap();
        assert_eq!(DnsStatus::read(d.path()), s);
        assert_eq!(
            DnsStatus::read(&d.path().join("missing")),
            DnsStatus::default()
        );
    }
}
