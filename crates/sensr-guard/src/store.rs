//! The events database (`events.db`), written in batches by sensr-guard and
//! read by the API. Conventions follow `sensr-flow`'s `AlertStore`: WAL,
//! a busy timeout, a read-only open for the API. `PRAGMA user_version = 1`.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, params, params_from_iter, types::Value};
use serde::Serialize;

use crate::events::{Batch, Row};

/// Store errors.
pub type Result<T> = rusqlite::Result<T>;

/// Schema version (`PRAGMA user_version`).
pub const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,           -- unix seconds
    ts_ms   INTEGER NOT NULL DEFAULT 0, -- millisecond part, 0..999
    hook    TEXT NOT NULL,
    action  TEXT NOT NULL,
    blocked INTEGER NOT NULL,
    rule_id INTEGER NOT NULL,           -- rule slot
    exe     TEXT NOT NULL,
    target  TEXT NOT NULL,
    unit    TEXT NOT NULL,
    pid     INTEGER NOT NULL,
    uid     INTEGER NOT NULL,
    count   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
PRAGMA user_version = 1;
";

/// A stored row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoredEvent {
    /// Database id.
    pub id: i64,
    /// The row.
    #[serde(flatten)]
    pub row: Row,
}

/// Query filter; all set fields must match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// Hook name.
    pub hook: Option<String>,
    /// Blocked or not.
    pub blocked: Option<bool>,
    /// Rule slot.
    pub rule_id: Option<u32>,
    /// Unit.
    pub unit: Option<String>,
    /// Unix seconds, inclusive lower bound.
    pub since: Option<i64>,
}

/// The events database.
pub struct Store {
    db: Connection,
}

impl Store {
    /// Opens (creating) for writing.
    pub fn open(path: &Path) -> Result<Store> {
        let db = Connection::open(path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "NORMAL")?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch(SCHEMA)?;
        Ok(Store { db })
    }

    /// Opens read-only (the API).
    pub fn open_ro(path: &Path) -> Result<Store> {
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.busy_timeout(Duration::from_secs(5))?;
        Ok(Store { db })
    }

    /// In memory (tests).
    pub fn memory() -> Result<Store> {
        let db = Connection::open_in_memory()?;
        db.execute_batch(SCHEMA)?;
        Ok(Store { db })
    }

    #[cfg(test)]
    fn pragma_i64(&self, name: &str) -> Result<i64> {
        self.db.pragma_query_value(None, name, |r| r.get(0))
    }

    #[cfg(test)]
    fn pragma_string(&self, name: &str) -> Result<String> {
        self.db.pragma_query_value(None, name, |r| r.get(0))
    }

    /// Writes the batch in one transaction (all rows or none).
    pub fn write_batch(&mut self, batch: &Batch) -> Result<()> {
        let tx = self.db.transaction()?;
        {
            let mut ins = tx.prepare_cached(
                "INSERT INTO events (ts, ts_ms, hook, action, blocked, rule_id, exe, target,
                 unit, pid, uid, count) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            )?;
            for r in &batch.rows {
                ins.execute(params![
                    r.ts, r.ts_ms, r.hook, r.action, r.blocked, r.rule_id, r.exe, r.target, r.unit,
                    r.pid, r.uid, r.count
                ])?;
            }
        }
        tx.commit()
    }

    /// Events, newest first.
    pub fn events(&self, f: &Filter, limit: u32, offset: u32) -> Result<Vec<StoredEvent>> {
        let mut conds = Vec::new();
        let mut args: Vec<Value> = Vec::new();
        if let Some(h) = &f.hook {
            conds.push("hook = ?");
            args.push(h.clone().into());
        }
        if let Some(b) = f.blocked {
            conds.push("blocked = ?");
            args.push(i64::from(b).into());
        }
        if let Some(r) = f.rule_id {
            conds.push("rule_id = ?");
            args.push(i64::from(r).into());
        }
        if let Some(u) = &f.unit {
            conds.push("unit = ?");
            args.push(u.clone().into());
        }
        if let Some(t) = f.since {
            conds.push("ts >= ?");
            args.push(t.into());
        }
        let wher = if conds.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conds.join(" AND "))
        };
        args.push(i64::from(limit).into());
        args.push(i64::from(offset).into());
        let sql = format!(
            "SELECT id, ts, ts_ms, hook, action, blocked, rule_id, exe, target, unit, pid, uid,
             count FROM events {wher} ORDER BY ts DESC, ts_ms DESC, id DESC LIMIT ? OFFSET ?"
        );
        let mut st = self.db.prepare(&sql)?;
        st.query_map(params_from_iter(args), |r| {
            Ok(StoredEvent {
                id: r.get(0)?,
                row: Row {
                    ts: r.get(1)?,
                    ts_ms: r.get(2)?,
                    hook: r.get(3)?,
                    action: r.get(4)?,
                    blocked: r.get(5)?,
                    rule_id: r.get(6)?,
                    exe: r.get(7)?,
                    target: r.get(8)?,
                    unit: r.get(9)?,
                    pid: r.get(10)?,
                    uid: r.get(11)?,
                    count: r.get(12)?,
                },
            })
        })?
        .collect()
    }

    /// Deletes rows older than `retention_days` (unix seconds `now`), then
    /// the oldest rows beyond `max_rows`. Returns the number deleted.
    pub fn prune(&mut self, retention_days: u32, max_rows: u64, now: i64) -> Result<usize> {
        let cutoff = now - i64::from(retention_days) * 86_400;
        let tx = self.db.transaction()?;
        let mut n = tx.execute("DELETE FROM events WHERE ts < ?1", [cutoff])?;
        n += tx.execute(
            "DELETE FROM events WHERE id IN
             (SELECT id FROM events ORDER BY ts DESC, ts_ms DESC, id DESC LIMIT -1 OFFSET ?1)",
            [i64::try_from(max_rows).unwrap_or(i64::MAX)],
        )?;
        tx.commit()?;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Batch, Row};

    fn row(ts: i64, hook: &str, blocked: bool, target: &str) -> Row {
        Row {
            ts,
            ts_ms: 250,
            hook: hook.into(),
            action: "alert".into(),
            blocked,
            rule_id: 4,
            exe: "/bin/sh".into(),
            target: target.into(),
            unit: "u.service".into(),
            pid: 9,
            uid: 1000,
            count: 3,
        }
    }

    fn batch(rows: Vec<Row>) -> Batch {
        Batch { rows }
    }

    #[test]
    fn write_batch_round_trips() {
        let mut s = Store::memory().unwrap();
        s.write_batch(&batch(vec![row(100, "exec", true, "/x")]))
            .unwrap();
        let ev = s.events(&Filter::default(), 10, 0).unwrap();
        assert_eq!(ev.len(), 1);
        assert!(ev[0].id > 0);
        assert_eq!(ev[0].row, row(100, "exec", true, "/x"));
    }

    #[test]
    fn events_filter_order_and_paging() {
        let mut s = Store::memory().unwrap();
        s.write_batch(&batch(vec![
            row(100, "exec", false, "/a"),
            row(200, "connect", true, "1.1.1.1:53"),
            row(300, "exec", true, "/c"),
        ]))
        .unwrap();
        let all = s.events(&Filter::default(), 10, 0).unwrap();
        let t: Vec<_> = all.iter().map(|e| e.row.ts).collect();
        assert_eq!(t, [300, 200, 100]);
        let page = s.events(&Filter::default(), 1, 1).unwrap();
        assert_eq!(page[0].row.ts, 200);
        let f = Filter {
            hook: Some("exec".into()),
            ..Filter::default()
        };
        assert_eq!(s.events(&f, 10, 0).unwrap().len(), 2);
        let f = Filter {
            blocked: Some(true),
            since: Some(250),
            ..Filter::default()
        };
        let r = s.events(&f, 10, 0).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].row.target, "/c");
        let f = Filter {
            rule_id: Some(99),
            ..Filter::default()
        };
        assert!(s.events(&f, 10, 0).unwrap().is_empty());
    }

    #[test]
    fn prune_by_age_and_rows() {
        let mut s = Store::memory().unwrap();
        let day = 86_400;
        let now = 100 * day;
        let rows = vec![
            row(now - 31 * day, "exec", false, "/old"),
            row(now - 29 * day, "exec", false, "/a"),
            row(now - 2 * day, "exec", false, "/b"),
            row(now - day, "exec", false, "/c"),
        ];
        s.write_batch(&batch(rows)).unwrap();
        assert_eq!(s.prune(30, 200_000, now).unwrap(), 1);
        assert_eq!(s.events(&Filter::default(), 10, 0).unwrap().len(), 3);
        // Row cap keeps the newest.
        assert_eq!(s.prune(30, 2, now).unwrap(), 1);
        let left: Vec<_> = s
            .events(&Filter::default(), 10, 0)
            .unwrap()
            .into_iter()
            .map(|e| e.row.target)
            .collect();
        assert_eq!(left, ["/c", "/b"]);
        assert_eq!(s.prune(30, 0, now).unwrap(), 2);
        assert!(s.events(&Filter::default(), 10, 0).unwrap().is_empty());
    }

    #[test]
    fn open_sets_wal_version_and_read_only_reads() {
        let dir = std::env::temp_dir().join(format!("guard-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("events.db");
        let mut s = Store::open(&p).unwrap();
        s.write_batch(&batch(vec![row(1, "bpf", false, "prog_load")]))
            .unwrap();
        assert_eq!(s.pragma_i64("user_version").unwrap(), 1);
        assert_eq!(s.pragma_string("journal_mode").unwrap(), "wal");
        let ro = Store::open_ro(&p).unwrap();
        assert_eq!(ro.events(&Filter::default(), 10, 0).unwrap().len(), 1);
        let mut ro = ro;
        assert!(
            ro.write_batch(&batch(vec![row(2, "bpf", false, "x")]))
                .is_err()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_batch_is_one_transaction() {
        let mut s = Store::memory().unwrap();
        // A row that violates NOT NULL via direct SQL would abort; here,
        // verify an empty batch is a no-op and a failing insert rolls back.
        s.write_batch(&batch(vec![])).unwrap();
        s.db.execute_batch("CREATE TRIGGER boom BEFORE INSERT ON events WHEN NEW.target = 'boom' BEGIN SELECT RAISE(ABORT, 'x'); END;").unwrap();
        let r = s.write_batch(&batch(vec![
            row(1, "exec", false, "/ok"),
            row(2, "exec", false, "boom"),
        ]));
        assert!(r.is_err());
        assert!(s.events(&Filter::default(), 10, 0).unwrap().is_empty());
    }
}
