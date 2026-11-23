//! The flow database: byte and packet counts per bucket at four
//! resolutions (10 s for interfaces only, then 1 min, 1 h, 1 day), with
//! retention.
//!
//! One table, keyed by (resolution, kind, key, host, bucket start):
//!
//! | kind | key | host |
//! |---|---|---|
//! | `iface` | logical interface (`lan`) | `""` |
//! | `host` | local address | `""` |
//! | `app` | `tcp/443`, `udp/3478` | local address |
//! | `remote` | remote address | `""` |
//!
//! `up` is what the local host (or the interface) sent, `down` what it
//! received.
//!
//! **Per-host DNS activity** (per device MAC, from [`crate::attrib`]):
//! `dns_queries(host, minute, qname, count, blocked)` and
//! `service_minutes(host, minute, service)` for [`ACTIVITY_MINUTE_DAYS`],
//! `service_days(host, day, service, minutes)` (UTC days) and
//! `domains_seen(host, qname, first_seen, last_seen, count, blocked)` for
//! [`ACTIVITY_DAY_DAYS`]. Writing a minute is idempotent (a minute drained
//! again after a restart adds nothing): lookup counts only grow to the
//! larger value, the domain totals take the difference, and the day rollup
//! is recounted from `service_minutes`. Categories are not stored: the
//! reader maps services and names through the catalogue it is given, so an
//! owner override applies to history at once. Names are untrusted text and
//! only ever bound as parameters. The journal is a rollback journal, not WAL, so the API process
//! can read the file with read-only permissions while the daemon writes once
//! a minute.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::Serialize;

use crate::attrib::{MinuteResult, category_of, registrable_domain};
use crate::config::Retention;
use crate::nft::{Count, Dir, Key, Kind};
use crate::services::{Catalogue, Category};

/// Resolutions in seconds.
pub const SAMPLE: i64 = 10;
/// One minute.
pub const MINUTE: i64 = 60;
/// One hour.
pub const HOUR: i64 = 3600;
/// One day.
pub const DAY: i64 = 86400;

/// Store errors.
pub type Result<T> = rusqlite::Result<T>;

/// What a row counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RowKind {
    /// An interface.
    Iface,
    /// A local host.
    Host,
    /// A local host's service.
    App,
    /// A remote address.
    Remote,
}

impl RowKind {
    fn tag(self) -> &'static str {
        match self {
            RowKind::Iface => "iface",
            RowKind::Host => "host",
            RowKind::App => "app",
            RowKind::Remote => "remote",
        }
    }
}

/// Accumulated counts of one row.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Totals {
    /// Bytes sent.
    pub up: u64,
    /// Bytes received.
    pub down: u64,
    /// Packets sent.
    pub up_packets: u64,
    /// Packets received.
    pub down_packets: u64,
}

impl Totals {
    fn add(&mut self, dir: Dir, c: Count) {
        match dir {
            Dir::Up => {
                self.up += c.bytes;
                self.up_packets += c.packets;
            }
            Dir::Down => {
                self.down += c.bytes;
                self.down_packets += c.packets;
            }
        }
    }
}

/// A row key: kind, key, host.
pub type RowKey = (RowKind, String, String);

fn proto_name(p: u8) -> String {
    match p {
        6 => "tcp".into(),
        17 => "udp".into(),
        n => n.to_string(),
    }
}

/// Counts gathered in memory until they are written.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Batch {
    /// Rows.
    pub rows: BTreeMap<RowKey, Totals>,
}

impl Batch {
    /// Adds counter deltas.
    pub fn add_counters(&mut self, deltas: &[(Key, Count)]) {
        for (k, c) in deltas {
            let key = match k.kind {
                Kind::Host => (RowKind::Host, k.addr.to_string(), String::new()),
                Kind::Remote => (RowKind::Remote, k.addr.to_string(), String::new()),
                // per-(host, remote) counters feed service attribution
                // (`attrib`), not the traffic rollups
                Kind::Pair => continue,
                Kind::App => (
                    RowKind::App,
                    format!("{}/{}", proto_name(k.proto), k.port),
                    k.addr.to_string(),
                ),
            };
            self.rows.entry(key).or_default().add(k.dir, *c);
        }
    }

    /// Adds an interface's byte deltas (`tx` is up, `rx` down).
    pub fn add_iface(&mut self, name: &str, rx: u64, tx: u64) {
        let t = self
            .rows
            .entry((RowKind::Iface, name.to_owned(), String::new()))
            .or_default();
        t.up += tx;
        t.down += rx;
    }

    /// Nothing gathered.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// The flow database.
pub struct FlowStore {
    db: Connection,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS traffic (
    res INTEGER NOT NULL,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    up INTEGER NOT NULL DEFAULT 0,
    down INTEGER NOT NULL DEFAULT 0,
    up_packets INTEGER NOT NULL DEFAULT 0,
    down_packets INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (res, kind, key, host, ts)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS traffic_time ON traffic (res, kind, ts);
CREATE INDEX IF NOT EXISTS traffic_host ON traffic (res, kind, host, ts);
CREATE TABLE IF NOT EXISTS dns_queries (
    host TEXT NOT NULL,
    minute INTEGER NOT NULL,
    qname TEXT NOT NULL,
    count INTEGER NOT NULL,
    blocked INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host, minute, qname)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS dns_queries_minute ON dns_queries (minute);
CREATE TABLE IF NOT EXISTS service_minutes (
    host TEXT NOT NULL,
    minute INTEGER NOT NULL,
    service TEXT NOT NULL,
    PRIMARY KEY (host, minute, service)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS service_minutes_minute ON service_minutes (minute);
CREATE TABLE IF NOT EXISTS service_days (
    host TEXT NOT NULL,
    day INTEGER NOT NULL,
    service TEXT NOT NULL,
    minutes INTEGER NOT NULL,
    PRIMARY KEY (host, day, service)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS service_days_day ON service_days (day);
CREATE TABLE IF NOT EXISTS domains_seen (
    host TEXT NOT NULL,
    qname TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    count INTEGER NOT NULL,
    blocked INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (host, qname)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS domains_seen_last ON domains_seen (last_seen);
";

/// Days of per-minute DNS activity (`dns_queries`, `service_minutes`).
pub const ACTIVITY_MINUTE_DAYS: i64 = 7;
/// Days of the daily rollup and the domain list (`service_days`,
/// `domains_seen`).
pub const ACTIVITY_DAY_DAYS: i64 = 90;
/// Domains per page of [`HostActivity::domains`].
pub const DOMAINS_PAGE: u32 = 100;
/// A domain first seen less than this long ago is new.
pub const NEW_SECS: i64 = DAY;

/// Whether a category counts toward the headline screen time (all but the
/// platforms' own system traffic and ads/tracking).
pub fn is_screen_time(c: Category) -> bool {
    !matches!(c, Category::System | Category::AdsTracking)
}

fn floor(ts: i64, res: i64) -> i64 {
    ts - ts.rem_euclid(res)
}

impl FlowStore {
    /// Opens (creating) the database for writing.
    pub fn open(path: &Path) -> Result<FlowStore> {
        let db = Connection::open(path)?;
        db.pragma_update(None, "journal_mode", "TRUNCATE")?;
        db.pragma_update(None, "synchronous", "NORMAL")?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(SCHEMA)?;
        Ok(FlowStore { db })
    }

    /// Opens an existing database read-only (the API).
    pub fn open_read_only(path: &Path) -> Result<FlowStore> {
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(FlowStore { db })
    }

    /// An in-memory database (tests).
    pub fn memory() -> Result<FlowStore> {
        let db = Connection::open_in_memory()?;
        db.execute_batch(SCHEMA)?;
        Ok(FlowStore { db })
    }

    /// Writes one sample of interface counts at 10 s resolution.
    pub fn write_samples(&mut self, ts: i64, batch: &Batch) -> Result<()> {
        let tx = self.db.transaction()?;
        Self::upsert(&tx, SAMPLE, floor(ts, SAMPLE), batch, |k| {
            k.0 == RowKind::Iface
        })?;
        tx.commit()
    }

    /// Adds a minute's counts to the minute, hour and day buckets.
    pub fn write_minute(&mut self, ts: i64, batch: &Batch) -> Result<()> {
        let tx = self.db.transaction()?;
        for res in [MINUTE, HOUR, DAY] {
            Self::upsert(&tx, res, floor(ts, res), batch, |_| true)?;
        }
        tx.commit()
    }

    fn upsert(
        tx: &rusqlite::Transaction<'_>,
        res: i64,
        ts: i64,
        batch: &Batch,
        keep: impl Fn(&RowKey) -> bool,
    ) -> Result<()> {
        let mut st = tx.prepare_cached(
            "INSERT INTO traffic (res, ts, kind, key, host, up, down, up_packets, down_packets)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (res, kind, key, host, ts) DO UPDATE SET
               up = up + excluded.up, down = down + excluded.down,
               up_packets = up_packets + excluded.up_packets,
               down_packets = down_packets + excluded.down_packets",
        )?;
        for (k, t) in batch.rows.iter().filter(|(k, _)| keep(k)) {
            st.execute(params![
                res,
                ts,
                k.0.tag(),
                k.1,
                k.2,
                t.up as i64,
                t.down as i64,
                t.up_packets as i64,
                t.down_packets as i64
            ])?;
        }
        Ok(())
    }

    /// Drops buckets older than the retention (and 10 s samples older than
    /// an hour). Returns the number of rows removed.
    pub fn prune(&mut self, now: i64, r: &Retention) -> Result<usize> {
        let mut n = 0;
        for (res, keep) in [
            (SAMPLE, HOUR),
            (MINUTE, i64::from(r.minute_hours) * HOUR),
            (HOUR, i64::from(r.hour_days) * DAY),
            (DAY, i64::from(r.day_days) * DAY),
        ] {
            n += self.db.execute(
                "DELETE FROM traffic WHERE res = ?1 AND ts < ?2",
                params![res, now - keep],
            )?;
        }
        let minutes = now - ACTIVITY_MINUTE_DAYS * DAY;
        let days = now - ACTIVITY_DAY_DAYS * DAY;
        for (sql, before) in [
            ("DELETE FROM dns_queries WHERE minute < ?1", minutes),
            ("DELETE FROM service_minutes WHERE minute < ?1", minutes),
            ("DELETE FROM service_days WHERE day < ?1", floor(days, DAY)),
            ("DELETE FROM domains_seen WHERE last_seen < ?1", days),
        ] {
            n += self.db.execute(sql, params![before])?;
        }
        Ok(n)
    }

    /// Stores one drained minute of per-host DNS activity (idempotent; see
    /// the module notes).
    pub fn write_activity_minute(&mut self, minute: i64, r: &MinuteResult) -> Result<()> {
        let minute = floor(minute, MINUTE);
        let day = floor(minute, DAY);
        let tx = self.db.transaction()?;
        {
            let mut old_q = tx.prepare_cached(
                "SELECT count, blocked FROM dns_queries WHERE host = ?1 AND minute = ?2 AND qname = ?3",
            )?;
            let mut put_q = tx.prepare_cached(
                "INSERT INTO dns_queries (host, minute, qname, count, blocked)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (host, minute, qname) DO UPDATE SET
                   count = max(count, excluded.count), blocked = max(blocked, excluded.blocked)",
            )?;
            let mut put_d = tx.prepare_cached(
                "INSERT INTO domains_seen (host, qname, first_seen, last_seen, count, blocked)
                 VALUES (?1, ?2, ?3, ?3, ?4, ?5)
                 ON CONFLICT (host, qname) DO UPDATE SET
                   first_seen = min(first_seen, excluded.first_seen),
                   last_seen = max(last_seen, excluded.last_seen),
                   count = count + excluded.count,
                   blocked = CASE
                     WHEN excluded.last_seen > last_seen THEN excluded.blocked
                     WHEN excluded.last_seen = last_seen THEN max(blocked, excluded.blocked)
                     ELSE blocked END",
            )?;
            let mut put_m = tx.prepare_cached(
                "INSERT OR IGNORE INTO service_minutes (host, minute, service) VALUES (?1, ?2, ?3)",
            )?;
            let mut put_day = tx.prepare_cached(
                "INSERT INTO service_days (host, day, service, minutes)
                 SELECT ?1, ?2, ?3, COUNT(*) FROM service_minutes
                 WHERE host = ?1 AND service = ?3 AND minute >= ?2 AND minute < ?2 + 86400
                 ON CONFLICT (host, day, service) DO UPDATE SET
                   minutes = max(minutes, excluded.minutes)",
            )?;
            for (host, h) in &r.per_host {
                for (qname, n, blocked) in &h.queries {
                    let n = i64::from(*n);
                    let (had, was_blocked) = old_q
                        .query_row(params![host, minute, qname], |r| {
                            Ok((r.get::<_, i64>(0)?, r.get::<_, bool>(1)?))
                        })
                        .optional()?
                        .unwrap_or((0, false));
                    if n <= had && (was_blocked || !blocked) {
                        continue;
                    }
                    put_q.execute(params![host, minute, qname, n, blocked])?;
                    put_d.execute(params![host, qname, minute, (n - had).max(0), blocked])?;
                }
                for service in &h.services_active {
                    if put_m.execute(params![host, minute, service])? > 0 {
                        put_day.execute(params![host, day, service])?;
                    }
                }
            }
        }
        tx.commit()
    }

    /// The daily rollup of `host` for the UTC day starting at `day`:
    /// (service, minutes), by service.
    pub fn service_days(&self, host: &str, day: i64) -> Result<Vec<(String, u32)>> {
        let mut st = self.db.prepare_cached(
            "SELECT service, minutes FROM service_days WHERE host = ?1 AND day = ?2 ORDER BY service",
        )?;
        let rows = st.query_map(params![host, floor(day, DAY)], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
        rows.collect()
    }

    /// One device's activity over `range` (domain page `page`, from 0).
    pub fn host_activity(
        &self,
        host: &str,
        range: &ActivityRange,
        page: u32,
        cat: &Catalogue,
    ) -> Result<HostActivity> {
        let mut out = HostActivity::default();
        let mut st = self.db.prepare_cached(
            "SELECT minute, service FROM service_minutes
             WHERE host = ?1 AND minute >= ?2 AND minute < ?3",
        )?;
        let rows = st.query_map(params![host, range.from, range.to], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut per_service: BTreeMap<String, u32> = BTreeMap::new();
        let mut per_category: BTreeMap<Category, BTreeSet<i64>> = BTreeMap::new();
        let mut screen: BTreeSet<i64> = BTreeSet::new();
        let mut cats: HashMap<String, Category> = HashMap::new();
        for row in rows {
            let (minute, service) = row?;
            let c = *cats
                .entry(service.clone())
                .or_insert_with(|| category_of(&service, cat));
            *per_service.entry(service).or_default() += 1;
            per_category.entry(c).or_default().insert(minute);
            if is_screen_time(c) {
                screen.insert(minute);
            }
        }
        out.services = per_service
            .into_iter()
            .map(|(service, minutes)| ServiceMinutes {
                category: cats.get(&service).copied().unwrap_or(Category::Other),
                service,
                minutes,
            })
            .collect();
        out.services.sort_by(|a, b| {
            b.minutes
                .cmp(&a.minutes)
                .then_with(|| a.service.cmp(&b.service))
        });
        out.categories = per_category
            .into_iter()
            .map(|(category, m)| CategoryMinutes {
                category,
                minutes: count_u32(m.len()),
            })
            .collect();
        out.categories
            .sort_by(|a, b| b.minutes.cmp(&a.minutes).then(a.category.cmp(&b.category)));
        out.screen_time = count_u32(screen.len());
        let mut cells: BTreeMap<(i64, u8), u32> = BTreeMap::new();
        for m in &screen {
            let local = m + range.utc_offset;
            let hour = u8::try_from(local.rem_euclid(DAY) / HOUR).unwrap_or(0);
            *cells.entry((local.div_euclid(DAY), hour)).or_default() += 1;
        }
        out.timeline = cells
            .into_iter()
            .map(|((day, hour), minutes)| TimelineCell { day, hour, minutes })
            .collect();

        out.domains_total = self.db.prepare_cached(
            "SELECT COUNT(DISTINCT qname) FROM dns_queries WHERE host = ?1 AND minute >= ?2 AND minute < ?3",
        )?
        .query_row(params![host, range.from, range.to], |r| r.get(0))?;
        let mut st = self.db.prepare_cached(
            "SELECT q.qname, SUM(q.count), MAX(q.blocked), MIN(q.minute), MAX(q.minute),
                    d.first_seen, d.last_seen
             FROM dns_queries q LEFT JOIN domains_seen d ON d.host = q.host AND d.qname = q.qname
             WHERE q.host = ?1 AND q.minute >= ?2 AND q.minute < ?3
             GROUP BY q.qname ORDER BY SUM(q.count) DESC, q.qname LIMIT ?4 OFFSET ?5",
        )?;
        let rows = st.query_map(
            params![
                host,
                range.from,
                range.to,
                DOMAINS_PAGE,
                i64::from(page) * i64::from(DOMAINS_PAGE)
            ],
            |r| {
                let qname: String = r.get(0)?;
                let first = r.get::<_, Option<i64>>(5)?.unwrap_or(r.get(3)?);
                let last = r.get::<_, Option<i64>>(6)?.unwrap_or(r.get(4)?);
                Ok((
                    qname,
                    r.get::<_, i64>(1)?,
                    r.get::<_, bool>(2)?,
                    first,
                    last,
                ))
            },
        )?;
        for row in rows {
            let (qname, count, blocked, first_seen, last_seen) = row?;
            let (service, category) = cat.lookup(&qname).map_or_else(
                || (registrable_domain(&qname), Category::Other),
                |(s, c)| (s.to_string(), c),
            );
            out.domains.push(DomainRow {
                count: u64::try_from(count).unwrap_or(0),
                first_seen,
                last_seen,
                new: range.now - first_seen < NEW_SECS,
                blocked,
                service,
                category,
                qname,
            });
        }
        Ok(out)
    }

    /// Screen-time minutes per device since `since` (normally local
    /// midnight): minutes with any active service outside the system and
    /// ads/tracking categories, each minute once.
    pub fn today_minutes(&self, since: i64, cat: &Catalogue) -> Result<BTreeMap<String, u32>> {
        let mut st = self
            .db
            .prepare_cached("SELECT DISTINCT service FROM service_minutes WHERE minute >= ?1")?;
        let mut excluded = Vec::new();
        for s in st.query_map(params![since], |r| r.get::<_, String>(0))? {
            let s = s?;
            if !is_screen_time(category_of(&s, cat)) {
                excluded.push(s);
            }
        }
        let excluded = serde_json::to_string(&excluded).unwrap_or_else(|_| "[]".into());
        let mut st = self.db.prepare_cached(
            "SELECT host, COUNT(DISTINCT minute) FROM service_minutes
             WHERE minute >= ?1 AND service NOT IN (SELECT value FROM json_each(?2))
             GROUP BY host",
        )?;
        let rows = st.query_map(params![since, excluded], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect()
    }

    /// Each device's lookups over the 24 hours before `now`, by the category
    /// of the name (unknown names are Other), in category order: the Hosts
    /// card's colour preview.
    pub fn dns_mix_24h(
        &self,
        now: i64,
        cat: &Catalogue,
    ) -> Result<BTreeMap<String, Vec<(Category, u32)>>> {
        let mut st = self.db.prepare_cached(
            "SELECT host, qname, SUM(count) FROM dns_queries WHERE minute >= ?1
             GROUP BY host, qname",
        )?;
        let rows = st.query_map(params![now - DAY], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        let mut mix: BTreeMap<String, BTreeMap<Category, u32>> = BTreeMap::new();
        for row in rows {
            let (host, qname, n) = row?;
            let c = cat.lookup(&qname).map_or(Category::Other, |x| x.1);
            let v = mix.entry(host).or_default().entry(c).or_default();
            *v = v.saturating_add(u32::try_from(n).unwrap_or(u32::MAX));
        }
        Ok(mix
            .into_iter()
            .map(|(h, m)| (h, m.into_iter().filter(|(_, n)| *n > 0).collect()))
            .collect())
    }

    /// The resolution a time range is shown at.
    pub fn resolution(from: i64, to: i64) -> i64 {
        let span = to - from;
        if span <= 6 * HOUR {
            MINUTE
        } else if span <= 31 * DAY {
            HOUR
        } else {
            DAY
        }
    }

    /// The largest `kind` rows in `[from, to)`, by total bytes.
    pub fn top(
        &self,
        kind: RowKind,
        host: Option<&str>,
        from: i64,
        to: i64,
        limit: u32,
    ) -> Result<Vec<TopRow>> {
        let res = Self::resolution(from, to);
        let mut st = self.db.prepare_cached(
            "SELECT key, SUM(up), SUM(down), SUM(up_packets), SUM(down_packets)
             FROM traffic
             WHERE res = ?1 AND kind = ?2 AND ts >= ?3 AND ts < ?4 AND (?5 IS NULL OR host = ?5)
             GROUP BY key ORDER BY SUM(up) + SUM(down) DESC LIMIT ?6",
        )?;
        let rows = st.query_map(
            params![res, kind.tag(), floor(from, res), to, host, limit],
            |r| {
                Ok(TopRow {
                    key: r.get(0)?,
                    up: r.get::<_, i64>(1)? as u64,
                    down: r.get::<_, i64>(2)? as u64,
                    up_packets: r.get::<_, i64>(3)? as u64,
                    down_packets: r.get::<_, i64>(4)? as u64,
                })
            },
        )?;
        rows.collect()
    }

    /// A row's counts over time (`key` `None`: the sum of every row of the
    /// kind, e.g. all interfaces). `res` `None` picks by range; `Some(10)`
    /// gives interface samples.
    pub fn series(
        &self,
        kind: RowKind,
        key: Option<&str>,
        from: i64,
        to: i64,
        res: Option<i64>,
    ) -> Result<Vec<Point>> {
        let res = res.unwrap_or_else(|| Self::resolution(from, to));
        let mut st = self.db.prepare_cached(
            "SELECT ts, SUM(up), SUM(down) FROM traffic
             WHERE res = ?1 AND kind = ?2 AND ts >= ?3 AND ts < ?4 AND (?5 IS NULL OR key = ?5)
             GROUP BY ts ORDER BY ts",
        )?;
        let rows = st.query_map(params![res, kind.tag(), floor(from, res), to, key], |r| {
            Ok(Point {
                ts: r.get(0)?,
                res,
                up: r.get::<_, i64>(1)? as u64,
                down: r.get::<_, i64>(2)? as u64,
            })
        })?;
        rows.collect()
    }
}

fn count_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// The time span of a [`FlowStore::host_activity`] query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivityRange {
    /// Start (Unix seconds, inclusive).
    pub from: i64,
    /// End (exclusive).
    pub to: i64,
    /// Now, for the `new` badge.
    pub now: i64,
    /// Local time minus UTC, in seconds (for days and hours).
    pub utc_offset: i64,
}

impl ActivityRange {
    fn local_midnight(now: i64, utc_offset: i64) -> i64 {
        let local = now + utc_offset;
        local - local.rem_euclid(DAY) - utc_offset
    }

    /// The local day `now` falls in.
    pub fn today(now: i64, utc_offset: i64) -> ActivityRange {
        let from = Self::local_midnight(now, utc_offset);
        ActivityRange {
            from,
            to: from + DAY,
            now,
            utc_offset,
        }
    }

    /// The last seven local days, today included.
    pub fn week(now: i64, utc_offset: i64) -> ActivityRange {
        let today = Self::today(now, utc_offset);
        ActivityRange {
            from: today.from - 6 * DAY,
            ..today
        }
    }
}

/// A device's DNS activity over a range (the host page, without its
/// header).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HostActivity {
    /// Minutes per service, largest first.
    pub services: Vec<ServiceMinutes>,
    /// Minutes per category (the union of its services' minutes), largest
    /// first.
    pub categories: Vec<CategoryMinutes>,
    /// Screen-time minutes ([`is_screen_time`] categories, each minute once).
    pub screen_time: u32,
    /// Screen-time minutes per local hour, oldest first; empty hours left out.
    pub timeline: Vec<TimelineCell>,
    /// One page of the names looked up in the range, most queried first.
    pub domains: Vec<DomainRow>,
    /// Names looked up in the range, over all pages.
    pub domains_total: u32,
}

/// Active minutes of one service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceMinutes {
    /// Service name.
    pub service: String,
    /// Its category.
    pub category: Category,
    /// Active minutes.
    pub minutes: u32,
}

/// Active minutes of one category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CategoryMinutes {
    /// Category.
    pub category: Category,
    /// Minutes in which any of its services was active.
    pub minutes: u32,
}

/// One hour of the timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TimelineCell {
    /// Local day, as days since 1970-01-01 (local).
    pub day: i64,
    /// Local hour, 0-23.
    pub hour: u8,
    /// Screen-time minutes in it.
    pub minutes: u32,
}

/// One name a device looked up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainRow {
    /// The name as looked up (untrusted text).
    pub qname: String,
    /// Lookups in the range.
    pub count: u64,
    /// First lookup ever kept (Unix seconds, minute start).
    pub first_seen: i64,
    /// Latest lookup.
    pub last_seen: i64,
    /// Its service (the catalogue's, else its registrable domain).
    pub service: String,
    /// The service's category.
    pub category: Category,
    /// First seen less than [`NEW_SECS`] ago.
    pub new: bool,
    /// Answered by a blocklist in the range.
    pub blocked: bool,
}

/// A ranked row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TopRow {
    /// Address, interface or `proto/port`.
    pub key: String,
    /// Bytes sent.
    pub up: u64,
    /// Bytes received.
    pub down: u64,
    /// Packets sent.
    pub up_packets: u64,
    /// Packets received.
    pub down_packets: u64,
}

/// One bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Point {
    /// Bucket start (Unix seconds).
    pub ts: i64,
    /// Bucket length in seconds.
    pub res: i64,
    /// Bytes sent.
    pub up: u64,
    /// Bytes received.
    pub down: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(kind: Kind, dir: Dir, addr: &str, port: u16) -> Key {
        Key {
            kind,
            dir,
            addr: addr.parse().unwrap(),
            remote: None,
            proto: if port > 0 { 6 } else { 0 },
            port,
        }
    }

    fn c(bytes: u64) -> Count {
        Count { packets: 1, bytes }
    }

    #[test]
    fn rollups_top_series_and_retention() {
        let mut s = FlowStore::memory().unwrap();
        let t0 = 1_800_000_000 - 1_800_000_000 % DAY;
        for m in 0..120 {
            let mut b = Batch::default();
            b.add_counters(&[
                (key(Kind::Host, Dir::Up, "192.168.1.100", 0), c(100)),
                (key(Kind::Host, Dir::Down, "192.168.1.100", 0), c(1000)),
                (key(Kind::Host, Dir::Down, "192.168.1.101", 0), c(10)),
                (key(Kind::App, Dir::Down, "192.168.1.100", 443), c(900)),
                (key(Kind::App, Dir::Down, "192.168.1.101", 443), c(10)),
                (key(Kind::Remote, Dir::Down, "11.0.1.10", 0), c(1010)),
            ]);
            b.add_iface("lan", 5, 1010);
            s.write_minute(t0 + m * MINUTE, &b).unwrap();
            s.write_samples(t0 + m * MINUTE, &b).unwrap();
        }
        let top = s.top(RowKind::Host, None, t0, t0 + 2 * HOUR, 10).unwrap();
        assert_eq!(top[0].key, "192.168.1.100");
        assert_eq!(top[0].down, 120 * 1000);
        assert_eq!(top[0].up, 120 * 100);
        // the same totals from the hour buckets (a longer range)
        let top = s.top(RowKind::Host, None, t0, t0 + DAY, 10).unwrap();
        assert_eq!(top[0].down, 120 * 1000);
        let apps = s.top(RowKind::App, None, t0, t0 + HOUR, 10).unwrap();
        assert_eq!(apps[0].key, "tcp/443");
        assert_eq!(apps[0].down, 60 * 910);
        let mine = s
            .top(RowKind::App, Some("192.168.1.101"), t0, t0 + HOUR, 10)
            .unwrap();
        assert_eq!(mine[0].down, 60 * 10);
        let series = s
            .series(RowKind::Host, Some("192.168.1.100"), t0, t0 + HOUR, None)
            .unwrap();
        assert_eq!(series.len(), 60);
        assert_eq!(series[0].down, 1000);
        let hourly = s
            .series(RowKind::Iface, None, t0, t0 + 2 * DAY, None)
            .unwrap();
        assert_eq!(hourly.len(), 2);
        assert_eq!(hourly[0].up, 60 * 1010);
        // retention: minutes go after their hours, the hour and day rows stay
        let gone = s
            .prune(
                t0 + 49 * HOUR,
                &Retention {
                    minute_hours: 48,
                    hour_days: 62,
                    day_days: 730,
                },
            )
            .unwrap();
        assert_eq!(
            gone,
            60 * 6 + 120,
            "minute rows of the first hour, all samples"
        );
        assert!(
            s.series(RowKind::Host, None, t0, t0 + HOUR, Some(MINUTE))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            s.top(RowKind::Host, None, t0, t0 + DAY, 10).unwrap()[0].down,
            120_000
        );
    }

    #[test]
    fn read_only_open_sees_writes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("flows.db");
        let mut w = FlowStore::open(&p).unwrap();
        let mut b = Batch::default();
        b.add_iface("wan", 1, 2);
        w.write_minute(0, &b).unwrap();
        let r = FlowStore::open_read_only(&p).unwrap();
        assert_eq!(r.top(RowKind::Iface, None, 0, 60, 5).unwrap()[0].up, 2);
    }

    // ---- per-host DNS activity ------------------------------------------

    use crate::attrib::{HostMinute, MinuteResult};
    use crate::services::{Catalogue, Category};

    const KID: &str = "aa:bb:cc:00:00:01";
    const CAM: &str = "aa:bb:cc:00:00:02";
    /// Midnight UTC (a multiple of a day).
    const D0: i64 = 1_800_028_800 - 1_800_028_800 % DAY;

    fn minute(services: &[&str], queries: &[(&str, u32, bool)]) -> HostMinute {
        HostMinute {
            services_active: services.iter().map(|s| s.to_string()).collect(),
            queries: queries
                .iter()
                .map(|(q, n, b)| (q.to_string(), *n, *b))
                .collect(),
            bytes_by_service: Default::default(),
        }
    }

    fn result(rows: Vec<(&str, HostMinute)>) -> MinuteResult {
        MinuteResult {
            per_host: rows.into_iter().map(|(m, h)| (m.to_string(), h)).collect(),
        }
    }

    fn cat() -> &'static Catalogue {
        Catalogue::builtin()
    }

    #[test]
    fn host_activity_today_and_7d() {
        let mut s = FlowStore::memory().unwrap();
        // yesterday 20:00-20:29 UTC: 30 minutes of Roblox
        for m in 0..30 {
            let t = D0 - 4 * HOUR + m * MINUTE;
            s.write_activity_minute(
                t,
                &result(vec![(
                    KID,
                    minute(&["Roblox"], &[("roblox.com", 1, false)]),
                )]),
            )
            .unwrap();
        }
        // today 15:00-15:44: YouTube; 15:30-15:44 also Roblox (overlap)
        for m in 0..45 {
            let t = D0 + 15 * HOUR + m * MINUTE;
            let mut svc = vec!["YouTube"];
            if m >= 30 {
                svc.push("Roblox");
            }
            let q: &[(&str, u32, bool)] = if m == 0 {
                &[("www.youtube.com", 3, false), ("doubleclick.net", 2, true)]
            } else {
                &[]
            };
            s.write_activity_minute(t, &result(vec![(KID, minute(&svc, q))]))
                .unwrap();
        }
        // another host's data never shows up
        s.write_activity_minute(
            D0 + 15 * HOUR,
            &result(vec![(
                CAM,
                minute(&["Netflix"], &[("netflix.com", 9, false)]),
            )]),
        )
        .unwrap();
        let now = D0 + 16 * HOUR;
        let today = s
            .host_activity(KID, &ActivityRange::today(now, 0), 0, cat())
            .unwrap();
        let svc: Vec<_> = today
            .services
            .iter()
            .map(|r| (r.service.as_str(), r.category, r.minutes))
            .collect();
        assert_eq!(
            svc,
            [
                ("YouTube", Category::Video, 45),
                ("Roblox", Category::Games, 15)
            ]
        );
        let cats: Vec<_> = today
            .categories
            .iter()
            .map(|c| (c.category, c.minutes))
            .collect();
        assert_eq!(cats, [(Category::Video, 45), (Category::Games, 15)]);
        assert_eq!(today.screen_time, 45, "the overlap counts once");
        assert_eq!(
            today.timeline,
            [TimelineCell {
                day: D0 / DAY,
                hour: 15,
                minutes: 45
            }]
        );
        assert_eq!(today.domains_total, 2);
        let d = &today.domains[0];
        assert_eq!(
            (d.qname.as_str(), d.count, d.service.as_str()),
            ("www.youtube.com", 3, "YouTube")
        );
        assert!(d.new && !d.blocked);
        assert_eq!(
            (d.first_seen, d.last_seen),
            (D0 + 15 * HOUR, D0 + 15 * HOUR)
        );
        let ads = &today.domains[1];
        assert!(ads.blocked);
        assert_eq!(ads.category, Category::AdsTracking);

        let week = s
            .host_activity(KID, &ActivityRange::week(now, 0), 0, cat())
            .unwrap();
        let svc: Vec<_> = week
            .services
            .iter()
            .map(|r| (r.service.as_str(), r.minutes))
            .collect();
        assert_eq!(svc, [("Roblox", 45), ("YouTube", 45)], "ties by name");
        assert_eq!(week.screen_time, 75);
        assert_eq!(week.timeline.len(), 2);
        assert_eq!(
            week.timeline[0],
            TimelineCell {
                day: D0 / DAY - 1,
                hour: 20,
                minutes: 30
            }
        );
        assert_eq!(week.domains_total, 3);
        // a local day: at UTC+5 "today" starts at 19:00 UTC yesterday
        let east = s
            .host_activity(KID, &ActivityRange::today(now, 5 * HOUR), 0, cat())
            .unwrap();
        assert_eq!(east.screen_time, 75);
        assert_eq!(
            east.timeline,
            [
                TimelineCell {
                    day: D0 / DAY,
                    hour: 1,
                    minutes: 30
                },
                TimelineCell {
                    day: D0 / DAY,
                    hour: 20,
                    minutes: 45
                }
            ]
        );
        // paging
        assert!(
            s.host_activity(KID, &ActivityRange::week(now, 0), 1, cat())
                .unwrap()
                .domains
                .is_empty()
        );
        // a domain seen before today is not new
        let r = s
            .host_activity(KID, &ActivityRange::week(now + 2 * DAY, 0), 0, cat())
            .unwrap();
        assert!(r.domains.iter().all(|d| !d.new));
        // the daily rollup
        assert_eq!(
            s.service_days(KID, D0).unwrap(),
            [("Roblox".to_string(), 15), ("YouTube".to_string(), 45)]
        );
    }

    #[test]
    fn rewritten_minute_is_not_double_counted() {
        let mut s = FlowStore::memory().unwrap();
        let r = result(vec![(
            KID,
            minute(&["YouTube"], &[("youtube.com", 4, false)]),
        )]);
        let t = D0 + HOUR;
        s.write_activity_minute(t, &r).unwrap();
        // a restart drains the same minute again
        s.write_activity_minute(t, &r).unwrap();
        let a = s
            .host_activity(KID, &ActivityRange::today(t, 0), 0, cat())
            .unwrap();
        assert_eq!(a.services[0].minutes, 1);
        assert_eq!(a.domains[0].count, 4);
        assert_eq!(
            s.service_days(KID, D0).unwrap(),
            [("YouTube".to_string(), 1)]
        );
        // a later drain with more lookups adds only the difference
        let r = result(vec![(
            KID,
            minute(&["YouTube"], &[("youtube.com", 6, false)]),
        )]);
        s.write_activity_minute(t, &r).unwrap();
        s.write_activity_minute(t + MINUTE, &r).unwrap();
        let a = s
            .host_activity(KID, &ActivityRange::today(t, 0), 0, cat())
            .unwrap();
        assert_eq!(a.domains[0].count, 12);
        assert_eq!(
            s.service_days(KID, D0).unwrap(),
            [("YouTube".to_string(), 2)]
        );
        let total: i64 =
            s.db.query_row(
                "SELECT count FROM domains_seen WHERE host = ?1",
                [KID],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(total, 12);
    }

    #[test]
    fn hostile_names_are_stored_as_given() {
        let mut s = FlowStore::memory().unwrap();
        let evil = "x'); DROP TABLE dns_queries; --.example";
        s.write_activity_minute(D0, &result(vec![(KID, minute(&[], &[(evil, 1, false)]))]))
            .unwrap();
        let a = s
            .host_activity(KID, &ActivityRange::today(D0, 0), 0, cat())
            .unwrap();
        assert_eq!(a.domains[0].qname, evil);
    }

    #[test]
    fn retention_prunes() {
        let mut s = FlowStore::memory().unwrap();
        let now = D0 + 100 * DAY;
        for age in [0, 6, 8, 89, 91] {
            let t = now - age * DAY;
            s.write_activity_minute(
                t,
                &result(vec![(
                    KID,
                    minute(&["YouTube"], &[(&format!("d{age}.example"), 1, false)]),
                )]),
            )
            .unwrap();
        }
        s.prune(now, &Retention::default()).unwrap();
        let count = |sql: &str| -> i64 { s.db.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(count("SELECT COUNT(*) FROM dns_queries"), 2, "7 days");
        assert_eq!(count("SELECT COUNT(*) FROM service_minutes"), 2, "7 days");
        assert_eq!(count("SELECT COUNT(*) FROM service_days"), 4, "90 days");
        assert_eq!(count("SELECT COUNT(*) FROM domains_seen"), 4, "90 days");
    }

    #[test]
    fn today_minutes_excludes_system_and_ads() {
        let mut s = FlowStore::memory().unwrap();
        for m in 0..20 {
            let t = D0 + 9 * HOUR + m * MINUTE;
            // Apple (system) and Google Ads all the time, YouTube for 10
            let mut svc = vec!["Apple", "Google Ads"];
            if m < 10 {
                svc.push("YouTube");
            }
            s.write_activity_minute(
                t,
                &result(vec![
                    (KID, minute(&svc, &[])),
                    (CAM, minute(&["Apple"], &[])),
                ]),
            )
            .unwrap();
        }
        // yesterday does not count
        s.write_activity_minute(D0 - HOUR, &result(vec![(KID, minute(&["YouTube"], &[]))]))
            .unwrap();
        let t = s.today_minutes(D0, cat()).unwrap();
        assert_eq!(t.get(KID), Some(&10));
        assert_eq!(t.get(CAM), None, "only system traffic: no screen time");
    }

    #[test]
    fn dns_mix_counts_queries_by_category() {
        let mut s = FlowStore::memory().unwrap();
        let now = D0 + 12 * HOUR;
        s.write_activity_minute(
            now - HOUR,
            &result(vec![(
                CAM,
                minute(
                    &[],
                    &[
                        ("youtube.com", 3, false),
                        ("doubleclick.net", 1, true),
                        ("unknown.example", 2, false),
                    ],
                ),
            )]),
        )
        .unwrap();
        // older than 24 h: not in the mix
        s.write_activity_minute(
            now - 2 * DAY,
            &result(vec![(CAM, minute(&[], &[("roblox.com", 50, false)]))]),
        )
        .unwrap();
        let mix = s.dns_mix_24h(now, cat()).unwrap();
        assert_eq!(
            mix[CAM],
            [
                (Category::Video, 3),
                (Category::AdsTracking, 1),
                (Category::Other, 2)
            ]
        );
        assert!(!mix.contains_key(KID));
    }
}
