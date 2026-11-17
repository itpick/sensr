//! The blocklist refresh: fetch, compile, swap in.
//!
//! The include file is replaced atomically (write + rename), so a resolver
//! (re)start always reads a complete blocklist. The running resolver is
//! updated in place: when only global zones changed (the daily refresh),
//! the difference goes in through `unbound-control local_zones` /
//! `local_datas` and their `_remove` forms, removals of changed names first,
//! so names that stay blocked are never unblocked and there is no reload,
//! no outage and no cache flush. When views or access control changed, or
//! the difference is large (first run), Unbound re-reads its configuration
//! (`fast_reload`, which keeps answering while it loads).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::time::Instant;

use sensr_apply::appliers::dns_runtime::DnsRuntime;
use serde::{Deserialize, Serialize};

use crate::compile::{Compiled, compile};
use crate::control::Control;
use crate::fetch::{Cache, Fetch};
use crate::parse::{Entry, parse_reader};

/// More changed lines than this and a reload is cheaper than the delta
/// (Unbound takes ~15 µs per control line; a reload ~3 s for 1.6 M names).
pub const MAX_DELTA: usize = 100_000;

/// Where the job keeps its files.
#[derive(Debug, Clone)]
pub struct Paths {
    /// The include Unbound reads.
    pub include: PathBuf,
    /// Downloaded lists.
    pub cache: PathBuf,
    /// `status.json` for the web UI.
    pub status: PathBuf,
}

impl Paths {
    /// The layout below a state directory.
    pub fn new(state_dir: &Path) -> Self {
        Self {
            include: state_dir.join("blocklist.conf"),
            cache: state_dir.join("cache"),
            status: state_dir.join("status.json"),
        }
    }
}

/// One source in `status.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceStatus {
    /// The URL.
    pub url: String,
    /// Names read from it.
    pub entries: u64,
    /// When the cached copy was last confirmed (RFC 3339).
    pub fetched: Option<String>,
    /// Served from the cache.
    pub from_cache: bool,
    /// Download error, if any.
    pub error: Option<String>,
}

/// One policy in `status.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyStatus {
    /// The policy's UUID.
    pub id: String,
    /// Its description.
    pub description: String,
    /// Names it blocks after deduplication.
    pub names: u64,
    /// Its sources.
    pub sources: Vec<SourceStatus>,
}

/// `status.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// When the refresh finished (RFC 3339).
    pub updated: String,
    /// How long it took.
    pub duration_ms: u64,
    /// Names in force.
    pub names: u64,
    /// How the running resolver was updated (`delta`, `fast_reload`,
    /// `reload`, `unchanged`, `not running`).
    pub applied: String,
    /// Per policy.
    pub policies: Vec<PolicyStatus>,
}

/// Seconds since the epoch as RFC 3339 UTC.
pub fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Writes `contents` to `path` via a temporary file and rename.
pub fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    // Not matching the `*.conf` include glob while it is being written.
    let tmp = dir.join(format!(".{name}.tmp"));
    fs::write(&tmp, contents)?;
    fs::File::open(&tmp)?.sync_all()?;
    fs::rename(tmp, path)
}

/// The global-zone lines of an include, and everything after them (access
/// control for views and the views).
fn split(include: &str) -> (BTreeSet<&str>, &str) {
    let mut zones = BTreeSet::new();
    let mut rest_at = include.len();
    let mut offset = 0;
    for line in include.split_inclusive('\n') {
        let l = line.trim_end();
        if l.starts_with("  local-zone: ") || l.starts_with("  local-data: ") {
            zones.insert(l);
        } else if l.starts_with("  access-control") || l.starts_with("view:") {
            rest_at = offset;
            break;
        }
        offset += line.len();
    }
    (zones, &include[rest_at..])
}

/// The quoted name of a zone line (`local-zone: "x." t` / `local-data: "x. A a"`).
fn line_name(l: &str) -> &str {
    l.split('"')
        .nth(1)
        .unwrap_or_default()
        .split(' ')
        .next()
        .unwrap_or_default()
}

/// unbound-control input for a zone line.
fn control_input(l: &str) -> (bool, String) {
    let l = l.trim();
    if let Some(z) = l.strip_prefix("local-zone: ") {
        (true, z.replace('"', ""))
    } else {
        let d = l.strip_prefix("local-data: ").unwrap_or(l);
        (false, d.trim_matches('"').to_owned())
    }
}

/// The control commands taking `old` to `new`, or `None` when a reload is
/// needed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Delta {
    /// `local_zones_remove` names.
    pub zones_remove: Vec<String>,
    /// `local_datas_remove` names.
    pub datas_remove: Vec<String>,
    /// `local_zones` lines.
    pub zones_add: Vec<String>,
    /// `local_datas` lines.
    pub datas_add: Vec<String>,
}

impl Delta {
    /// Number of control lines.
    pub fn len(&self) -> usize {
        self.zones_remove.len()
            + self.datas_remove.len()
            + self.zones_add.len()
            + self.datas_add.len()
    }

    /// No change.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Computes the live update from the old to the new include text.
pub fn delta(old: &str, new: &str) -> Option<Delta> {
    let (old_z, old_rest) = split(old);
    let (new_z, new_rest) = split(new);
    if old_rest != new_rest {
        return None;
    }
    let mut d = Delta::default();
    let new_zone_names: BTreeSet<&str> = new_z
        .iter()
        .filter(|l| l.starts_with("  local-zone"))
        .map(|l| line_name(l))
        .collect();
    for l in old_z.difference(&new_z) {
        let (zone, _) = control_input(l);
        let name = line_name(l).to_owned();
        if zone {
            // A zone that only changes type is overwritten by the add.
            if !new_zone_names.contains(name.as_str()) {
                d.zones_remove.push(name);
            }
        } else {
            d.datas_remove.push(name);
        }
    }
    for l in new_z.difference(&old_z) {
        let (zone, input) = control_input(l);
        if zone {
            d.zones_add.push(input);
        } else {
            d.datas_add.push(input);
        }
    }
    d.datas_remove.dedup();
    Some(d)
}

/// Pushes the change into the running resolver; returns how.
pub fn apply_live(control: &Control<'_>, old: &str, new: &str) -> String {
    if !control.is_running() {
        return "not running".into();
    }
    match delta(old, new) {
        Some(d) if d.is_empty() => "unchanged".into(),
        Some(d) if d.len() <= MAX_DELTA => {
            let r = control
                .local_datas_remove(&d.datas_remove)
                .and_then(|_| control.local_zones_remove(&d.zones_remove))
                .and_then(|_| control.local_zones(&d.zones_add))
                .and_then(|_| control.local_datas(&d.datas_add));
            match r {
                Ok(()) => format!("delta ({} lines)", d.len()),
                Err(e) => {
                    tracing::warn!("live update failed ({e}); reloading");
                    reload(control)
                }
            }
        }
        _ => reload(control),
    }
}

fn reload(control: &Control<'_>) -> String {
    match control.reload() {
        Ok(how) => how.into(),
        Err(e) => {
            tracing::error!("reloading unbound: {e}");
            format!("reload failed: {e}")
        }
    }
}

/// Reads and parses the cached lists of `urls`.
fn load_sources(
    cfg: &DnsRuntime,
    cache: &Cache,
    fetcher: &dyn Fetch,
    force: bool,
    now: u64,
) -> (BTreeMap<String, Vec<Entry>>, BTreeMap<String, SourceStatus>) {
    let mut max_age: BTreeMap<String, u64> = BTreeMap::new();
    for p in cfg.blocklist.iter().flat_map(|b| b.policies.iter()) {
        for u in p.policy.sources() {
            let age = u64::from(p.policy.refresh_seconds);
            max_age
                .entry(u)
                .and_modify(|a| *a = (*a).min(age))
                .or_insert(age);
        }
    }
    let mut sources = BTreeMap::new();
    let mut status = BTreeMap::new();
    // Downloads run in parallel: a slow or unreachable list (DNS timeouts
    // take tens of seconds) must not hold up the others.
    let refreshed: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = max_age
            .iter()
            .map(|(url, age)| s.spawn(move || cache.refresh(fetcher, url, *age, force, now)))
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join().unwrap_or_else(|_| crate::fetch::Refreshed {
                    path: None,
                    fetched: None,
                    from_cache: false,
                    error: Some("download thread panicked".into()),
                })
            })
            .collect()
    });
    for ((url, _), r) in max_age.iter().zip(refreshed) {
        let mut entries = Vec::new();
        let mut error = r.error.clone();
        if let Some(path) = &r.path {
            match fs::File::open(path)
                .and_then(|f| parse_reader(BufReader::new(f), |e| entries.push(e)))
            {
                Ok(stats) => tracing::info!(
                    "{url}: {} names ({} unusable lines){}",
                    stats.entries,
                    stats.rejected,
                    if r.from_cache { ", cached" } else { "" }
                ),
                Err(e) => error = Some(format!("reading the cached list: {e}")),
            }
        }
        if let Some(e) = &error {
            tracing::warn!("{url}: {e}");
        }
        status.insert(
            url.clone(),
            SourceStatus {
                url: url.clone(),
                entries: entries.len() as u64,
                fetched: r.fetched.map(rfc3339),
                from_cache: r.from_cache,
                error,
            },
        );
        sources.insert(url.clone(), entries);
    }
    cache.prune(&max_age.keys().cloned().collect::<Vec<_>>());
    (sources, status)
}

/// One refresh. Returns the status written to `status.json`.
pub fn run(
    cfg: &DnsRuntime,
    paths: &Paths,
    fetcher: &dyn Fetch,
    control: &Control<'_>,
    force: bool,
    now: u64,
) -> io::Result<Status> {
    let started = Instant::now();
    let old = fs::read_to_string(&paths.include).unwrap_or_default();
    let Some(bl) = &cfg.blocklist else {
        // Blocklists turned off: drop the include and what is loaded.
        let mut applied = "unchanged".to_owned();
        if paths.include.exists() {
            fs::remove_file(&paths.include)?;
            applied = apply_live(control, &old, "");
        }
        let _ = fs::remove_file(&paths.status);
        return Ok(Status {
            updated: rfc3339(now),
            duration_ms: 0,
            names: 0,
            applied,
            policies: Vec::new(),
        });
    };
    let cache = Cache::new(&paths.cache);
    let (sources, source_status) = load_sources(cfg, &cache, fetcher, force, now);
    let compiled: Compiled = compile(bl, &sources);
    drop(sources);
    let text = compiled.render();
    let applied = if text == old {
        "unchanged".to_owned()
    } else {
        write_atomic(&paths.include, text.as_bytes())?;
        apply_live(control, &old, &text)
    };
    let counts = compiled.counts();
    let policies = bl
        .policies
        .iter()
        .map(|p| PolicyStatus {
            id: p.id.to_string(),
            description: p.policy.description.to_string(),
            names: counts.get(&p.id).copied().unwrap_or(0),
            sources: p
                .policy
                .sources()
                .iter()
                .filter_map(|u| source_status.get(u).cloned())
                .collect(),
        })
        .collect();
    let status = Status {
        updated: rfc3339(now),
        duration_ms: started.elapsed().as_millis() as u64,
        names: compiled.len() as u64,
        applied,
        policies,
    };
    write_atomic(
        &paths.status,
        &serde_json::to_vec_pretty(&status).unwrap_or_default(),
    )?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::tests::MapFetcher;
    use sensr_apply::appliers::dns_runtime::{BlocklistRuntime, PolicyRuntime};
    use sensr_apply::appliers::unbound::AclAction;
    use sensr_apply::cmd::{FakeRunner, Output};
    use sensr_schema::Uuid;
    use sensr_schema::models::dnsbl::{Blocklist, KnownList};

    #[test]
    fn rfc3339_dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_794_868_680), "2026-11-16T22:38:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn delta_swaps_changed_names_and_detects_views() {
        let old = "# x\nserver:\n  local-zone: \"a.example.\" always_null\n  local-data: \"b.example. A 0.0.0.0\"\n  local-zone: \"c.example.\" always_null\n";
        let new = "# x\nserver:\n  local-zone: \"a.example.\" always_nxdomain\n  local-zone: \"d.example.\" always_null\n  local-zone: \"c.example.\" always_null\n";
        let d = delta(old, new).unwrap();
        assert_eq!(d.zones_remove, Vec::<String>::new());
        assert_eq!(d.datas_remove, ["b.example."]);
        assert_eq!(
            d.zones_add,
            ["a.example. always_nxdomain", "d.example. always_null"]
        );
        assert!(d.datas_add.is_empty());
        let with_view =
            format!("{new}  access-control-view: 10.0.0.0/24 \"v\"\nview:\n  name: \"v\"\n");
        assert!(delta(new, &with_view).is_none());
        assert_eq!(delta(&with_view, &with_view), Some(Delta::default()));
        let gone = delta(new, "").unwrap();
        assert_eq!(gone.zones_remove.len(), 3);
    }

    fn runtime(dir: &Path) -> DnsRuntime {
        let mut b = Blocklist::new("Ads".parse().unwrap());
        b.lists = vec![KnownList::HageziPro];
        b.urls = vec!["https://down.example/list.txt".parse().unwrap()];
        b.block = vec!["tracker.example.net".parse().unwrap()];
        DnsRuntime {
            control_conf: dir.join("control.conf"),
            state_dir: dir.to_owned(),
            statistics: false,
            blocklist: Some(BlocklistRuntime {
                policies: vec![PolicyRuntime {
                    id: Uuid::from_u128(1),
                    policy: b,
                }],
                protected: vec!["home.arpa".parse().unwrap()],
                default_action: AclAction::Allow,
                acls: Vec::new(),
            }),
            leases: None,
        }
    }

    #[test]
    fn refresh_writes_include_status_and_pushes_delta() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = runtime(dir.path());
        let paths = Paths::new(dir.path());
        let f = MapFetcher::default();
        f.bodies.lock().unwrap().insert(
            KnownList::HageziPro.url(),
            Some("*.ads.example.com\n*.telemetry.example.org\n".into()),
        );
        let r = FakeRunner::new();
        let c = Control::new(&r, &cfg.control_conf);
        let st = run(&cfg, &paths, &f, &c, false, 1_000).unwrap();
        assert_eq!(st.names, 3);
        assert_eq!(st.applied, "delta (3 lines)");
        let srcs = &st.policies[0].sources;
        assert_eq!(srcs[0].entries, 2);
        assert_eq!(srcs[1].url, "https://down.example/list.txt");
        assert!(srcs[1].error.as_deref().unwrap().contains("503"));
        let include = fs::read_to_string(&paths.include).unwrap();
        assert!(include.contains("local-zone: \"ads.example.com.\" always_null"));
        assert!(include.contains("local-data: \"tracker.example.net. A 0.0.0.0\""));
        let status: Status =
            serde_json::from_str(&fs::read_to_string(&paths.status).unwrap()).unwrap();
        assert_eq!(status, st);

        // The list changes: one name goes, one comes; a live delta.
        f.bodies.lock().unwrap().insert(
            KnownList::HageziPro.url(),
            Some("*.ads.example.com\n*.new.example.org\n".into()),
        );
        let before = r.calls().len();
        let st = run(&cfg, &paths, &f, &c, true, 2_000).unwrap();
        assert_eq!(st.applied, "delta (2 lines)");
        let calls = r.calls()[before..].to_vec();
        let inputs: Vec<String> = calls
            .iter()
            .filter_map(|c| c.stdin.as_ref())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        assert_eq!(
            inputs,
            ["telemetry.example.org.\n", "new.example.org. always_null\n"]
        );

        // Unchanged: nothing pushed.
        let before = r.calls().len();
        assert_eq!(
            run(&cfg, &paths, &f, &c, false, 2_100).unwrap().applied,
            "unchanged"
        );
        assert_eq!(r.calls().len(), before);

        // Unbound down: the file is still written, nothing pushed.
        let down = FakeRunner::new();
        down.push(
            "unbound-control",
            Output::failed(1, "connect: No such file"),
        );
        let c2 = Control::new(&down, &cfg.control_conf);
        let mut cfg2 = cfg.clone();
        cfg2.blocklist.as_mut().unwrap().policies[0]
            .policy
            .block
            .clear();
        assert_eq!(
            run(&cfg2, &paths, &f, &c2, false, 2_200).unwrap().applied,
            "not running"
        );
        assert!(
            !fs::read_to_string(&paths.include)
                .unwrap()
                .contains("tracker")
        );

        // Turned off: the include goes.
        let mut off = cfg.clone();
        off.blocklist = None;
        run(&off, &paths, &f, &c, false, 3_000).unwrap();
        assert!(!paths.include.exists());
    }
}
