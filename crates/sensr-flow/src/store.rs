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
//! received. The journal is a rollback journal, not WAL, so the API process
//! can read the file with read-only permissions while the daemon writes once
//! a minute.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::{Connection, OpenFlags, params};
use serde::Serialize;

use crate::config::Retention;
use crate::nft::{Count, Dir, Key, Kind};

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
                Kind::Host => (RowKind::Host, k.addr.clone(), String::new()),
                Kind::Remote => (RowKind::Remote, k.addr.clone(), String::new()),
                // per-(host, remote) counters feed service attribution
                // (`attrib`), not the traffic rollups
                Kind::Pair => continue,
                Kind::App => (
                    RowKind::App,
                    format!("{}/{}", proto_name(k.proto), k.port),
                    k.addr.clone(),
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
";

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
        Ok(n)
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
            addr: addr.into(),
            remote: String::new(),
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
}
