//! Alias data feeds (OPNsense `update_tables.py` and `lib/alias`): everything
//! an alias needs from outside the configuration, fetched on its own
//! schedule and kept last-good.
//!
//! - URL and URL-table aliases: HTTP(S) with conditional requests; a URL
//!   table refreshes every `refresh` (upstream `updatefreq`), a URL alias
//!   once. A failed fetch never empties an alias: the stored body stays in
//!   force and the failure is reported per alias, with a retry back-off.
//! - GeoIP aliases: a country database (default DB-IP Lite, CC BY 4.0),
//!   checked daily; only the countries in use are stored.
//! - ASN aliases: an AS database (default iptoasn.com, public domain),
//!   checked daily; only the AS numbers in use are stored.
//! - Host names in host aliases: re-resolved every `resolve_interval`.
//! - MAC aliases: the neighbour table and DHCP leases, every 30 s.
//!
//! [`Feeds::sources`] gives `sensr-rules` a [`Sources`] that only reads the
//! store, so rendering a ruleset never waits on the network; [`Feeds::refresh`]
//! does the fetching and returns the aliases whose contents changed, ready
//! for an atomic set update.

pub mod asn;
pub mod cache;
pub mod geo;
pub mod http;
pub mod neigh;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ipnet::IpNet;
use sensr_rules::alias::dns::{DnsError, Record, RecordType, Resolver};
use sensr_rules::alias::{self, AliasDef, AliasKind, Auth, FetchError, HostEntry, Sources};
use sensr_rules::ir::{IfAddr, IpFamily};
use sensr_rules::render::nft::ResolvedAlias;
use sensr_schema::Document;
use serde::Serialize;

use cache::{Cache, Meta};
use http::{Fetched, Fetcher};

/// How often the neighbour table is read for MAC aliases (upstream TTL).
pub const MAC_INTERVAL: u64 = 30;
/// How often the country and AS databases are checked (upstream TTL).
pub const DB_INTERVAL: u64 = 86_400;
/// First retry after a failed fetch; doubles per failure up to [`MAX_BACKOFF`].
pub const RETRY_AFTER: u64 = 300;
/// First retry for a source that has never been fetched successfully.
///
/// At boot the feeds are read before the resolver answers, so the first attempt
/// fails with "Name or service not known" on every URL. Waiting the full
/// [`RETRY_AFTER`] leaves every alias table empty for five minutes, which is
/// long enough that the first firewall check sees an empty GeoIP set and lets
/// traffic through. A never-successful source is much more likely to be a
/// not-yet-ready network than a dead URL, so retry it soon; the back-off below
/// still doubles from here, and a source that has worked once uses
/// [`RETRY_AFTER`].
pub const EARLY_RETRY_AFTER: u64 = 10;
/// Longest retry interval.
pub const MAX_BACKOFF: u64 = 3_600;
/// URL sources fetched at once.
const PARALLEL_FETCHES: usize = 8;
/// Largest decompressed database accepted.
const MAX_DB_BYTES: u64 = 512 * 1024 * 1024;

/// Per-alias state for the API and UI (Firewall › Aliases status column).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct AliasStatus {
    /// alias name
    pub name: String,
    /// alias type (`url_table`, `geo_ip`, …)
    pub kind: String,
    /// entries currently loaded (networks after merging)
    pub entries: usize,
    /// when the contents were last fetched successfully (s since the epoch)
    pub updated_at: Option<u64>,
    /// last error, while the previous contents stay loaded
    pub error: Option<String>,
    /// next scheduled check
    pub next_check: Option<u64>,
    /// data attribution to show (GeoIP from DB-IP)
    pub attribution: Option<String>,
}

/// One fetch made by a refresh, for logs and timing reports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FetchReport {
    /// what was fetched (URL, or `geoip`/`asn` database URL)
    pub url: String,
    /// `200`, `304` or the error
    pub outcome: String,
    /// bytes received
    pub bytes: u64,
    /// wall time of the request and processing
    pub millis: u128,
}

/// Result of [`Feeds::refresh`].
#[derive(Clone, Debug, Default)]
pub struct Refreshed {
    /// aliases whose contents changed, with the new contents
    pub updates: Vec<(String, ResolvedAlias)>,
    /// requests made
    pub fetches: Vec<FetchReport>,
}

struct DnsEntry {
    at: u64,
    answer: Result<Vec<Record>, DnsError>,
}

#[derive(Default)]
struct Inner {
    dns: BTreeMap<(String, bool), DnsEntry>,
    neigh: Option<(u64, Vec<(String, IpAddr)>)>,
    /// contents the loaded ruleset has, per alias
    pushed: Option<BTreeMap<String, ResolvedAlias>>,
    /// per-alias errors from the last resolution
    errors: BTreeMap<String, String>,
}

/// Looks up the neighbour (ARP/NDP) table.
pub type NeighbourFn = dyn Fn() -> Vec<(String, IpAddr)> + Send + Sync;

/// The feed store and refresher. Cheap to share (`Arc`).
pub struct Feeds {
    dir: PathBuf,
    cache: Cache,
    geo: geo::GeoStore,
    asn: asn::AsnStore,
    fetcher: Arc<dyn Fetcher>,
    resolver: Arc<dyn Resolver + Send + Sync>,
    neighbours: Arc<NeighbourFn>,
    inner: Mutex<Inner>,
}

/// The operating system's resolver (`getaddrinfo`): on the box that is the
/// local Unbound, so host overrides apply as they do upstream.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn query(&self, name: &str, rtype: RecordType) -> Result<Vec<Record>, DnsError> {
        let addrs = (name, 0u16)
            .to_socket_addrs()
            .map_err(|e| DnsError::Other(format!("{name}: {e}")))?;
        let want_v4 = rtype == RecordType::A;
        let mut v: Vec<IpAddr> = addrs
            .map(|a| a.ip())
            .filter(|ip| ip.is_ipv4() == want_v4)
            .collect();
        v.sort_unstable();
        v.dedup();
        Ok(v.into_iter().map(Record::Addr).collect())
    }
}

fn lock(m: &Mutex<Inner>) -> std::sync::MutexGuard<'_, Inner> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Seconds between refreshes of a URL table; `None`: never expires.
fn url_ttl(kind: &AliasKind) -> Option<u64> {
    match kind {
        AliasKind::UrlTable { refresh_secs, .. } if *refresh_secs > 0 => Some(*refresh_secs),
        _ => None,
    }
}

/// When a source may be tried again after failures.
fn retry_at(m: &Meta) -> u64 {
    if m.failures == 0 {
        return 0;
    }
    // A source that has never loaded because the network was not up yet (at
    // boot every URL fails with "Name or service not known") is retried soon:
    // otherwise the alias tables stay empty for five minutes and the first
    // firewall checks see nothing. An HTTP status is a definitive answer, and a
    // source that worked before still has its last-good content, so both keep
    // the cautious retry.
    let transport = m
        .error
        .as_deref()
        .is_some_and(|e| !e.starts_with("HTTP status"));
    let base = if m.fetched_at.is_none() && transport {
        EARLY_RETRY_AFTER
    } else {
        RETRY_AFTER
    };
    let shift = (m.failures - 1).min(10);
    let wait = (base << shift).min(MAX_BACKOFF);
    m.attempted_at.unwrap_or(0) + wait
}

/// When `m` is next due, given a refresh period.
fn next_due(m: &Meta, ttl: Option<u64>) -> Option<u64> {
    if m.fetched_at.is_none() || m.failures > 0 {
        return Some(retry_at(m));
    }
    ttl.map(|t| m.checked_at.unwrap_or(0) + t)
}

/// Every URL of an alias.
fn urls(kind: &AliasKind) -> Vec<(&str, &Auth)> {
    match kind {
        AliasKind::Url { urls, auth, .. } => urls.iter().map(|u| (u.as_str(), auth)).collect(),
        AliasKind::UrlTable { url, auth, .. } => vec![(url.as_str(), auth)],
        _ => Vec::new(),
    }
}

fn kind_name(k: &AliasKind) -> &'static str {
    match k {
        AliasKind::Host(_) => "host",
        AliasKind::Network(_) => "network",
        AliasKind::NetworkGroup(_) => "network_group",
        AliasKind::Port(_) => "port",
        AliasKind::Url { .. } => "url",
        AliasKind::UrlTable { .. } => "url_table",
        AliasKind::GeoIp { .. } => "geo_ip",
        AliasKind::Asn { .. } => "asn",
        AliasKind::Mac(_) => "mac",
        AliasKind::DynIpv6Host { .. } => "dynipv6host",
        AliasKind::External => "external",
    }
}

fn host_names(kind: &AliasKind) -> Vec<String> {
    match kind {
        AliasKind::Host(v) | AliasKind::Network(v) => v
            .iter()
            .filter_map(|e| match e {
                HostEntry::Name(n) => Some(n.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// The alias definitions of a document.
pub fn alias_defs(doc: &Document) -> Vec<AliasDef> {
    doc.firewall.aliases.values().map(AliasDef::from).collect()
}

impl Feeds {
    /// A store under `dir` (e.g. `/var/lib/sensr/state/aliases`).
    pub fn new(
        dir: impl Into<PathBuf>,
        fetcher: Arc<dyn Fetcher>,
        resolver: Arc<dyn Resolver + Send + Sync>,
        neighbours: Arc<NeighbourFn>,
    ) -> Feeds {
        let dir = dir.into();
        Feeds {
            cache: Cache::new(&dir),
            geo: geo::GeoStore::new(dir.join("geoip")),
            asn: asn::AsnStore::new(dir.join("asn")),
            dir,
            fetcher,
            resolver,
            neighbours,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// The store directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Read-only [`Sources`] over the store, for rendering.
    pub fn sources(&self) -> FeedSources<'_> {
        FeedSources { feeds: self }
    }

    /// Records what the freshly loaded ruleset holds (call after every
    /// apply): later refreshes push only differences from it.
    pub fn applied(&self, contents: BTreeMap<String, ResolvedAlias>) {
        lock(&self.inner).pushed = Some(contents);
    }

    /// Forgets the loaded contents (the ruleset is gone or unknown).
    pub fn reset(&self) {
        lock(&self.inner).pushed = None;
    }

    fn fetch_url(&self, url: &str, auth: &Auth, now: u64, out: &mut Vec<FetchReport>) -> bool {
        let mut m = self.cache.meta(url);
        let t0 = Instant::now();
        m.attempted_at = Some(now);
        let (changed, outcome, bytes) = match self.fetcher.get(url, auth, &m.conditional()) {
            Ok(Fetched::NotModified) => {
                m.checked_at = Some(now);
                m.failures = 0;
                m.error = None;
                (false, "304".to_owned(), 0)
            }
            Ok(Fetched::Body { bytes, conditional }) => {
                let n = bytes.len() as u64;
                match self.cache.put_body(&mut m, &bytes, now) {
                    Ok(changed) => {
                        m.checked_at = Some(now);
                        m.failures = 0;
                        m.error = None;
                        m.etag = conditional.etag;
                        m.last_modified = conditional.last_modified;
                        (changed, "200".to_owned(), n)
                    }
                    Err(e) => {
                        m.failures += 1;
                        m.error = Some(format!("storing: {e}"));
                        (false, format!("error: storing: {e}"), n)
                    }
                }
            }
            Err(e) => {
                m.failures += 1;
                m.error = Some(e.0.clone());
                (false, format!("error: {}", e.0), 0)
            }
        };
        if let Err(e) = self.cache.put_meta(&m) {
            tracing::warn!(url, error = %e, "alias feed metadata not saved");
        }
        out.push(FetchReport {
            url: url.to_owned(),
            outcome,
            bytes,
            millis: t0.elapsed().as_millis(),
        });
        changed
    }

    /// Downloads a database when due; returns the decompressed body if new.
    fn fetch_db(
        &self,
        key: &str,
        candidates: &[String],
        need_full: bool,
        now: u64,
        out: &mut Vec<FetchReport>,
    ) -> Option<Vec<u8>> {
        for url in candidates {
            let meta_key = format!("{key}:{url}");
            let mut m = self.cache.meta(&meta_key);
            let due = if need_full {
                now >= retry_at(&m)
            } else {
                next_due(&m, Some(DB_INTERVAL)).is_some_and(|d| now >= d)
            };
            if !due {
                return None;
            }
            let t0 = Instant::now();
            m.attempted_at = Some(now);
            let cond = if need_full {
                http::Conditional::default()
            } else {
                m.conditional()
            };
            let res = self.fetcher.get(url, &Auth::None, &cond);
            let (outcome, bytes, body) = match res {
                Ok(Fetched::NotModified) => {
                    m.checked_at = Some(now);
                    m.failures = 0;
                    m.error = None;
                    ("304".to_owned(), 0, None)
                }
                Ok(Fetched::Body { bytes, conditional }) => {
                    let n = bytes.len() as u64;
                    match http::gunzip_if_needed(bytes, MAX_DB_BYTES) {
                        Ok(b) => {
                            m.checked_at = Some(now);
                            m.fetched_at = Some(now);
                            m.failures = 0;
                            m.error = None;
                            m.etag = conditional.etag;
                            m.last_modified = conditional.last_modified;
                            ("200".to_owned(), n, Some(b))
                        }
                        Err(e) => {
                            m.failures += 1;
                            m.error = Some(e.0.clone());
                            (format!("error: {}", e.0), n, None)
                        }
                    }
                }
                Err(e) => {
                    m.failures += 1;
                    m.error = Some(e.0.clone());
                    (format!("error: {}", e.0), 0, None)
                }
            };
            let failed = m.error.is_some();
            let _ = self.cache.put_meta(&m);
            out.push(FetchReport {
                url: url.clone(),
                outcome,
                bytes,
                millis: t0.elapsed().as_millis(),
            });
            if body.is_some() || !failed {
                return body;
            }
            // try the next candidate (last month's DB-IP file early in a month)
        }
        None
    }

    fn geo_candidates(&self, doc: &Document, now: u64) -> Vec<String> {
        match &doc.firewall.feeds.geoip_url {
            Some(u) => vec![u.to_string()],
            None => {
                let (y, m) = geo::year_month(now);
                let (py, pm) = geo::previous_month(y, m);
                vec![geo::dbip_url(y, m), geo::dbip_url(py, pm)]
            }
        }
    }

    fn asn_candidates(doc: &Document) -> Vec<String> {
        match &doc.firewall.feeds.asn_url {
            Some(u) => vec![u.to_string()],
            None => vec![asn::IPTOASN_URL.to_owned()],
        }
    }

    /// Fetches whatever is due at `now` (seconds since the epoch) and returns
    /// the aliases whose resolved contents changed since the ruleset was
    /// loaded. Never fails: problems end up in [`Feeds::status`].
    pub fn refresh(&self, doc: &Document, now: u64) -> Refreshed {
        let defs = alias_defs(doc);
        let enabled: Vec<&AliasDef> = defs.iter().filter(|d| d.enabled).collect();
        let mut fetches = Vec::new();
        let mut changed = false;

        // URL and URL-table aliases, fetched in parallel: one slow or
        // unreachable host must not hold up the others
        let mut seen = BTreeSet::new();
        let mut due: Vec<(&str, &Auth)> = Vec::new();
        for d in &enabled {
            let ttl = url_ttl(&d.kind);
            for (url, auth) in urls(&d.kind) {
                if !seen.insert(url.to_owned()) {
                    continue;
                }
                let m = self.cache.meta(url);
                if next_due(&m, ttl).is_some_and(|d| now >= d) {
                    due.push((url, auth));
                }
            }
        }
        for batch in due.chunks(PARALLEL_FETCHES) {
            let results: Vec<(bool, Vec<FetchReport>)> = std::thread::scope(|sc| {
                let handles: Vec<_> = batch
                    .iter()
                    .map(|(url, auth)| {
                        sc.spawn(move || {
                            let mut r = Vec::new();
                            let c = self.fetch_url(url, auth, now, &mut r);
                            (c, r)
                        })
                    })
                    .collect();
                handles.into_iter().filter_map(|h| h.join().ok()).collect()
            });
            for (c, r) in results {
                changed |= c;
                fetches.extend(r);
            }
        }

        // country database
        let countries: BTreeSet<String> = enabled
            .iter()
            .filter_map(|d| match &d.kind {
                AliasKind::GeoIp { countries, .. } => Some(countries.clone()),
                _ => None,
            })
            .flatten()
            .map(|c| c.to_ascii_uppercase())
            .collect();
        if !countries.is_empty() {
            let missing = countries.iter().any(|c| !self.geo.has(c));
            let cands = self.geo_candidates(doc, now);
            if let Some(body) = self.fetch_db("geoip", &cands, missing, now, &mut fetches) {
                match geo::parse(&body, Some(&countries)) {
                    Ok(db) => match self.geo.store(&countries, &db) {
                        Ok(n) => {
                            tracing::info!(
                                countries = countries.len(),
                                networks = n,
                                "GeoIP data updated"
                            );
                            changed = true;
                        }
                        Err(e) => tracing::warn!(error = %e, "GeoIP data not stored"),
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "GeoIP database rejected; previous data kept");
                        if let Some(f) = fetches.last_mut() {
                            f.outcome = format!("error: {e}");
                        }
                        for u in &cands {
                            let mut m = self.cache.meta(&format!("geoip:{u}"));
                            if m.fetched_at == Some(now) {
                                m.fetched_at = None;
                                m.failures += 1;
                                m.error = Some(e.to_string());
                                let _ = self.cache.put_meta(&m);
                            }
                        }
                    }
                }
            }
        }

        // AS database
        let asns: BTreeSet<u32> = enabled
            .iter()
            .filter_map(|d| match &d.kind {
                AliasKind::Asn { asns, .. } => Some(asns.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        if !asns.is_empty() {
            let missing = asns.iter().any(|a| !self.asn.has(*a));
            let cands = Self::asn_candidates(doc);
            if let Some(body) = self.fetch_db("asn", &cands, missing, now, &mut fetches) {
                let db = asn::parse(&String::from_utf8_lossy(&body), Some(&asns));
                match self.asn.store(&asns, &db) {
                    Ok(n) => {
                        tracing::info!(asns = asns.len(), networks = n, "ASN data updated");
                        changed = true;
                    }
                    Err(e) => tracing::warn!(error = %e, "ASN data not stored"),
                }
            }
        }

        // host names
        let interval = u64::from(doc.firewall.feeds.resolve_interval.max(1));
        let names: BTreeSet<String> = enabled.iter().flat_map(|d| host_names(&d.kind)).collect();
        if !names.is_empty() {
            changed |= self.refresh_dns(&names, interval, now);
        }

        // MAC aliases
        let macs: Vec<String> = enabled
            .iter()
            .filter_map(|d| match &d.kind {
                AliasKind::Mac(v) => Some(v.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        if !macs.is_empty() {
            let due = lock(&self.inner)
                .neigh
                .as_ref()
                .is_none_or(|(at, _)| now >= at + MAC_INTERVAL);
            if due {
                let table = (self.neighbours)();
                let pick = |t: &[(String, IpAddr)]| -> BTreeSet<IpAddr> {
                    macs.iter().flat_map(|m| alias::mac::lookup(t, m)).collect()
                };
                let mut inner = lock(&self.inner);
                let before = inner.neigh.as_ref().map(|(_, t)| pick(t));
                let after = pick(&table);
                if before.as_ref() != Some(&after) {
                    changed = true;
                }
                inner.neigh = Some((now, table));
            }
        }

        let first = lock(&self.inner).pushed.is_none();
        if !changed && !first {
            return Refreshed {
                updates: Vec::new(),
                fetches,
            };
        }
        let res = alias::resolve_all(&defs, &self.sources());
        let mut inner = lock(&self.inner);
        inner.errors = res
            .errors
            .iter()
            .filter_map(|e| match e {
                alias::AliasError::Dns { alias, error } => Some((alias.clone(), error.to_string())),
                alias::AliasError::Cycle(a) => Some((a.clone(), e.to_string())),
                alias::AliasError::Fetch(_) => None,
            })
            .collect();
        let pushed = inner.pushed.get_or_insert_with(BTreeMap::new);
        let mut updates = Vec::new();
        for (name, contents) in res.aliases {
            // an alias whose source never answered keeps what the ruleset has
            if res.failed.contains(&name) && contents.nets.is_empty() && !first {
                continue;
            }
            if pushed.get(&name) != Some(&contents) {
                pushed.insert(name.clone(), contents.clone());
                updates.push((name, contents));
            }
        }
        Refreshed { updates, fetches }
    }

    fn refresh_dns(&self, names: &BTreeSet<String>, interval: u64, now: u64) -> bool {
        let mut changed = false;
        for name in names {
            for v6 in [false, true] {
                let key = (name.clone(), v6);
                let due = lock(&self.inner)
                    .dns
                    .get(&key)
                    .is_none_or(|e| now >= e.at + interval);
                if !due {
                    continue;
                }
                let rt = if v6 { RecordType::Aaaa } else { RecordType::A };
                let answer = self.resolver.query(name, rt);
                let mut inner = lock(&self.inner);
                let differs = inner.dns.get(&key).is_none_or(|old| old.answer != answer);
                // a failed lookup keeps the last good answer (pf keeps the
                // table when the resolver is down)
                let keep_old =
                    answer.is_err() && inner.dns.get(&key).is_some_and(|old| old.answer.is_ok());
                if keep_old {
                    if let Some(e) = inner.dns.get_mut(&key) {
                        e.at = now;
                    }
                    continue;
                }
                changed |= differs;
                inner.dns.insert(key, DnsEntry { at: now, answer });
            }
        }
        changed
    }

    /// When an alias is next checked, if it has a schedule.
    fn next_check(&self, d: &AliasDef, doc: &Document, now: u64) -> Option<u64> {
        match &d.kind {
            AliasKind::Url { .. } | AliasKind::UrlTable { .. } => urls(&d.kind)
                .iter()
                .filter_map(|(u, _)| next_due(&self.cache.meta(u), url_ttl(&d.kind)))
                .min(),
            AliasKind::GeoIp { .. } => self
                .geo_candidates(doc, now)
                .first()
                .and_then(|u| next_due(&self.cache.meta(&format!("geoip:{u}")), Some(DB_INTERVAL))),
            AliasKind::Asn { .. } => Self::asn_candidates(doc)
                .first()
                .and_then(|u| next_due(&self.cache.meta(&format!("asn:{u}")), Some(DB_INTERVAL))),
            AliasKind::Mac(_) => lock(&self.inner)
                .neigh
                .as_ref()
                .map(|(at, _)| at + MAC_INTERVAL),
            _ => None,
        }
    }

    /// Status of every alias of `doc`.
    pub fn status(&self, doc: &Document, now: u64) -> Vec<AliasStatus> {
        let defs = alias_defs(doc);
        let inner_pushed: BTreeMap<String, usize> = lock(&self.inner)
            .pushed
            .as_ref()
            .map(|p| {
                p.iter()
                    .map(|(k, v)| (k.clone(), v.nets.len() + v.ports.len()))
                    .collect()
            })
            .unwrap_or_default();
        let errors = lock(&self.inner).errors.clone();
        defs.iter()
            .map(|d| {
                let (updated_at, mut error) = match &d.kind {
                    AliasKind::Url { .. } | AliasKind::UrlTable { .. } => {
                        let metas: Vec<Meta> = urls(&d.kind)
                            .iter()
                            .map(|(u, _)| self.cache.meta(u))
                            .collect();
                        (
                            metas.iter().filter_map(|m| m.fetched_at).min(),
                            metas.iter().find_map(|m| m.error.clone()),
                        )
                    }
                    AliasKind::GeoIp { .. } | AliasKind::Asn { .. } => {
                        let key = if matches!(d.kind, AliasKind::GeoIp { .. }) {
                            "geoip"
                        } else {
                            "asn"
                        };
                        let cands = if key == "geoip" {
                            self.geo_candidates(doc, now)
                        } else {
                            Self::asn_candidates(doc)
                        };
                        let metas: Vec<Meta> = cands
                            .iter()
                            .map(|u| self.cache.meta(&format!("{key}:{u}")))
                            .collect();
                        let ok = metas.iter().filter_map(|m| m.fetched_at).max();
                        let err = if ok.is_some() {
                            None
                        } else {
                            metas.iter().find_map(|m| m.error.clone())
                        };
                        (ok, err)
                    }
                    _ => (None, None),
                };
                if error.is_none() {
                    error = errors.get(&d.name).cloned();
                }
                let geo_default = matches!(d.kind, AliasKind::GeoIp { .. })
                    && doc.firewall.feeds.geoip_url.is_none();
                AliasStatus {
                    name: d.name.clone(),
                    kind: kind_name(&d.kind).into(),
                    entries: if d.enabled {
                        inner_pushed.get(&d.name).copied().unwrap_or(0)
                    } else {
                        0
                    },
                    updated_at,
                    error: if d.enabled { error } else { None },
                    next_check: if d.enabled {
                        self.next_check(d, doc, now)
                    } else {
                        None
                    },
                    attribution: geo_default.then(|| geo::DBIP_ATTRIBUTION.to_owned()),
                }
            })
            .collect()
    }
}

/// [`Sources`] over the store: no network access, no waiting.
pub struct FeedSources<'a> {
    feeds: &'a Feeds,
}

impl Resolver for FeedSources<'_> {
    fn query(&self, name: &str, rtype: RecordType) -> Result<Vec<Record>, DnsError> {
        let v6 = rtype == RecordType::Aaaa;
        let inner = lock(&self.feeds.inner);
        if let Some(e) = inner.dns.get(&(name.to_owned(), v6)) {
            return e.answer.clone();
        }
        drop(inner);
        // never looked up yet (first render): ask now, remember the answer
        let answer = self.feeds.resolver.query(name, rtype);
        lock(&self.feeds.inner).dns.insert(
            (name.to_owned(), v6),
            DnsEntry {
                at: 0,
                answer: answer.clone(),
            },
        );
        answer
    }
}

impl Sources for FeedSources<'_> {
    fn fetch(&self, url: &str, _: &Auth) -> Result<String, FetchError> {
        match self.feeds.cache.body(url) {
            Some(b) => {
                let b = http::gunzip_if_needed(b, MAX_DB_BYTES).map_err(|e| FetchError {
                    url: url.into(),
                    reason: e.0,
                })?;
                Ok(String::from_utf8_lossy(&b).into_owned())
            }
            None => Err(FetchError {
                url: url.into(),
                reason: self
                    .feeds
                    .cache
                    .meta(url)
                    .error
                    .unwrap_or_else(|| "not fetched yet".into()),
            }),
        }
    }

    fn resolver(&self) -> &dyn Resolver {
        self
    }

    fn geoip(&self, country: &str, fam: IpFamily) -> Vec<IpNet> {
        self.feeds.geo.lookup(country, fam)
    }

    fn asn(&self, asn: u32) -> Vec<IpNet> {
        self.feeds.asn.lookup(asn)
    }

    fn neighbours(&self) -> Vec<(String, IpAddr)> {
        if let Some((_, t)) = &lock(&self.feeds.inner).neigh {
            return t.clone();
        }
        (self.feeds.neighbours)()
    }

    fn interface_addrs(&self, _: &str) -> Vec<IfAddr> {
        Vec::new()
    }

    fn external(&self, _: &str) -> Vec<IpNet> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests;
