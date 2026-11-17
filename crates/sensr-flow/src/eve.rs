//! Suricata alerts: `eve.json` lines tailed into `alerts.db`.
//!
//! The tailer follows the file across rotation (a new inode is read from
//! the start once the old one is exhausted) and truncation, and remembers
//! its position in the database, so a restart neither loses nor repeats
//! alerts. Engine counters (`event_type: stats`) are kept as the latest
//! snapshot for the UI (capture drops, IPS verdicts).

use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::Serialize;
use serde_json::Value;

/// Store errors.
pub type Result<T> = rusqlite::Result<T>;

/// One alert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alert {
    /// Database id (0 before insert).
    pub id: i64,
    /// Unix milliseconds.
    pub ts: i64,
    /// Generator id.
    pub gid: u32,
    /// Signature id.
    pub sid: u32,
    /// Revision.
    pub rev: u32,
    /// Message.
    pub signature: String,
    /// Classification.
    pub category: String,
    /// 1 (high) - 4.
    pub severity: u8,
    /// `allowed` or `blocked`.
    pub action: String,
    /// IP protocol name.
    pub proto: String,
    /// Source address.
    pub src_ip: String,
    /// Source port.
    pub src_port: Option<u16>,
    /// Destination address.
    pub dest_ip: String,
    /// Destination port.
    pub dest_port: Option<u16>,
    /// Capture interface.
    pub iface: String,
    /// Application protocol.
    pub app_proto: String,
    /// The eve record.
    pub raw: String,
}

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Suricata's timestamp (`2018-05-21T13:05:42.646499+0200`) in Unix ms.
pub fn parse_timestamp(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    let mut rest = &s[19..];
    let mut ms = 0;
    if let Some(frac) = rest.strip_prefix('.') {
        let digits = frac.bytes().take_while(u8::is_ascii_digit).count();
        let f = &frac[..digits];
        ms = format!("{f:0<3}").get(..3)?.parse::<i64>().ok()?;
        rest = &frac[digits..];
    }
    let offset = match rest {
        "" | "Z" => 0,
        tz => {
            let sign = match tz.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let t = tz[1..].replace(':', "");
            let hh: i64 = t.get(0..2)?.parse().ok()?;
            let mm: i64 = t.get(2..4)?.parse().ok()?;
            sign * (hh * 3600 + mm * 60)
        }
    };
    let secs = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se - offset;
    Some(secs * 1000 + ms)
}

/// An eve line, if it is an alert or a stats record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// An alert.
    Alert(Box<Alert>),
    /// Engine counters.
    Stats(String),
}

/// Parses one eve.json line.
pub fn parse_line(line: &str) -> Option<Event> {
    let v: Value = serde_json::from_str(line).ok()?;
    let s = |v: &Value, k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let n = |v: &Value, k: &str| v.get(k).and_then(Value::as_u64);
    match v.get("event_type")?.as_str()? {
        "alert" => {
            let a = v.get("alert")?;
            Some(Event::Alert(Box::new(Alert {
                id: 0,
                ts: parse_timestamp(v.get("timestamp")?.as_str()?)?,
                gid: n(a, "gid").and_then(|x| u32::try_from(x).ok()).unwrap_or(1),
                sid: u32::try_from(n(a, "signature_id")?).ok()?,
                rev: n(a, "rev").and_then(|x| u32::try_from(x).ok()).unwrap_or(0),
                signature: s(a, "signature"),
                category: s(a, "category"),
                severity: n(a, "severity")
                    .and_then(|x| u8::try_from(x).ok())
                    .unwrap_or(3),
                action: s(a, "action"),
                proto: s(&v, "proto"),
                src_ip: s(&v, "src_ip"),
                src_port: n(&v, "src_port").and_then(|x| u16::try_from(x).ok()),
                dest_ip: s(&v, "dest_ip"),
                dest_port: n(&v, "dest_port").and_then(|x| u16::try_from(x).ok()),
                iface: s(&v, "in_iface"),
                app_proto: s(&v, "app_proto"),
                raw: line.to_owned(),
            })))
        }
        "stats" => Some(Event::Stats(v.get("stats")?.to_string())),
        _ => None,
    }
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    gid INTEGER NOT NULL,
    sid INTEGER NOT NULL,
    rev INTEGER NOT NULL,
    signature TEXT NOT NULL,
    category TEXT NOT NULL,
    severity INTEGER NOT NULL,
    action TEXT NOT NULL,
    proto TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER,
    iface TEXT NOT NULL,
    app_proto TEXT NOT NULL,
    raw TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts (ts);
CREATE INDEX IF NOT EXISTS alerts_sid ON alerts (sid, ts);
CREATE INDEX IF NOT EXISTS alerts_src ON alerts (src_ip, ts);
CREATE INDEX IF NOT EXISTS alerts_dest ON alerts (dest_ip, ts);
CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
";

/// What to list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AlertFilter {
    /// Only this signature.
    pub sid: Option<u32>,
    /// Signature text contains this (case-insensitive).
    pub text: Option<String>,
    /// Source or destination is this address.
    pub host: Option<String>,
    /// Not before (Unix ms).
    pub since: Option<i64>,
    /// Before (Unix ms).
    pub until: Option<i64>,
    /// Page size.
    pub limit: u32,
    /// Rows skipped.
    pub offset: u32,
}

/// A signature's count in a range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureCount {
    /// Signature id.
    pub sid: u32,
    /// Message.
    pub signature: String,
    /// Alerts.
    pub count: u64,
    /// Latest (Unix ms).
    pub last: i64,
}

/// The alert database.
pub struct AlertStore {
    db: Connection,
}

impl AlertStore {
    /// Opens (creating) for writing.
    pub fn open(path: &Path) -> Result<AlertStore> {
        let db = Connection::open(path)?;
        db.pragma_update(None, "journal_mode", "TRUNCATE")?;
        db.pragma_update(None, "synchronous", "NORMAL")?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(SCHEMA)?;
        Ok(AlertStore { db })
    }

    /// Opens read-only (the API).
    pub fn open_read_only(path: &Path) -> Result<AlertStore> {
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(AlertStore { db })
    }

    /// In memory (tests).
    pub fn memory() -> Result<AlertStore> {
        let db = Connection::open_in_memory()?;
        db.execute_batch(SCHEMA)?;
        Ok(AlertStore { db })
    }

    /// Stores events and the tail position in one transaction.
    pub fn write(&mut self, events: &[Event], pos: Option<(u64, u64)>) -> Result<()> {
        let tx = self.db.transaction()?;
        {
            let mut ins = tx.prepare_cached(
                "INSERT INTO alerts (ts, gid, sid, rev, signature, category, severity, action,
                 proto, src_ip, src_port, dest_ip, dest_port, iface, app_proto, raw)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16)",
            )?;
            let mut state =
                tx.prepare_cached("INSERT OR REPLACE INTO state (key, value) VALUES (?1, ?2)")?;
            for e in events {
                match e {
                    Event::Alert(a) => {
                        ins.execute(params![
                            a.ts,
                            a.gid,
                            a.sid,
                            a.rev,
                            a.signature,
                            a.category,
                            a.severity,
                            a.action,
                            a.proto,
                            a.src_ip,
                            a.src_port,
                            a.dest_ip,
                            a.dest_port,
                            a.iface,
                            a.app_proto,
                            a.raw
                        ])?;
                    }
                    Event::Stats(s) => {
                        state.execute(params!["stats", s])?;
                    }
                }
            }
            if let Some((ino, off)) = pos {
                state.execute(params!["tail", format!("{ino}:{off}")])?;
            }
        }
        tx.commit()
    }

    /// The remembered tail position (inode, offset).
    pub fn position(&self) -> Result<Option<(u64, u64)>> {
        let v: Option<String> = self
            .db
            .query_row("SELECT value FROM state WHERE key = 'tail'", [], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(v.and_then(|v| {
            let (a, b) = v.split_once(':')?;
            Some((a.parse().ok()?, b.parse().ok()?))
        }))
    }

    /// The latest engine counters (JSON), if any.
    pub fn stats(&self) -> Result<Option<String>> {
        self.db
            .query_row("SELECT value FROM state WHERE key = 'stats'", [], |r| {
                r.get(0)
            })
            .optional()
    }

    /// Drops alerts older than `days` and beyond the newest `max`.
    pub fn prune(&mut self, now_ms: i64, days: u32, max: u64) -> Result<usize> {
        let mut n = self.db.execute(
            "DELETE FROM alerts WHERE ts < ?1",
            params![now_ms - i64::from(days) * 86_400_000],
        )?;
        n += self.db.execute(
            "DELETE FROM alerts WHERE id <= (SELECT MAX(id) FROM alerts) - ?1",
            params![i64::try_from(max).unwrap_or(i64::MAX)],
        )?;
        Ok(n)
    }

    fn where_clause(f: &AlertFilter) -> (String, Vec<rusqlite::types::Value>) {
        use rusqlite::types::Value as V;
        let mut w = vec!["1=1".to_owned()];
        let mut p: Vec<V> = Vec::new();
        if let Some(sid) = f.sid {
            w.push(format!("sid = ?{}", p.len() + 1));
            p.push(V::Integer(i64::from(sid)));
        }
        if let Some(t) = &f.text {
            w.push(format!("signature LIKE ?{} ESCAPE '\\'", p.len() + 1));
            let esc = t
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            p.push(V::Text(format!("%{esc}%")));
        }
        if let Some(h) = &f.host {
            w.push(format!("(src_ip = ?{0} OR dest_ip = ?{0})", p.len() + 1));
            p.push(V::Text(h.clone()));
        }
        if let Some(s) = f.since {
            w.push(format!("ts >= ?{}", p.len() + 1));
            p.push(V::Integer(s));
        }
        if let Some(u) = f.until {
            w.push(format!("ts < ?{}", p.len() + 1));
            p.push(V::Integer(u));
        }
        (w.join(" AND "), p)
    }

    /// Alerts matching `f`, newest first, and the total matching.
    pub fn list(&self, f: &AlertFilter) -> Result<(Vec<Alert>, u64)> {
        let (w, p) = Self::where_clause(f);
        let total: i64 = self.db.query_row(
            &format!("SELECT COUNT(*) FROM alerts WHERE {w}"),
            rusqlite::params_from_iter(p.iter()),
            |r| r.get(0),
        )?;
        let mut st = self.db.prepare(&format!(
            "SELECT id, ts, gid, sid, rev, signature, category, severity, action, proto,
                    src_ip, src_port, dest_ip, dest_port, iface, app_proto, raw
             FROM alerts WHERE {w} ORDER BY ts DESC, id DESC LIMIT {} OFFSET {}",
            f.limit.clamp(1, 5000),
            f.offset
        ))?;
        let rows = st.query_map(rusqlite::params_from_iter(p.iter()), |r| {
            Ok(Alert {
                id: r.get(0)?,
                ts: r.get(1)?,
                gid: r.get(2)?,
                sid: r.get(3)?,
                rev: r.get(4)?,
                signature: r.get(5)?,
                category: r.get(6)?,
                severity: r.get(7)?,
                action: r.get(8)?,
                proto: r.get(9)?,
                src_ip: r.get(10)?,
                src_port: r.get(11)?,
                dest_ip: r.get(12)?,
                dest_port: r.get(13)?,
                iface: r.get(14)?,
                app_proto: r.get(15)?,
                raw: r.get(16)?,
            })
        })?;
        Ok((
            rows.collect::<Result<_>>()?,
            u64::try_from(total).unwrap_or(0),
        ))
    }

    /// The most frequent signatures matching `f`.
    pub fn top_signatures(&self, f: &AlertFilter) -> Result<Vec<SignatureCount>> {
        let (w, p) = Self::where_clause(f);
        let mut st = self.db.prepare(&format!(
            "SELECT sid, MAX(signature), COUNT(*), MAX(ts) FROM alerts WHERE {w}
             GROUP BY sid ORDER BY COUNT(*) DESC LIMIT {}",
            f.limit.clamp(1, 1000)
        ))?;
        let rows = st.query_map(rusqlite::params_from_iter(p.iter()), |r| {
            Ok(SignatureCount {
                sid: r.get(0)?,
                signature: r.get(1)?,
                count: u64::try_from(r.get::<_, i64>(2)?).unwrap_or(0),
                last: r.get(3)?,
            })
        })?;
        rows.collect()
    }
}

/// Follows eve.json.
pub struct Tailer {
    path: PathBuf,
    reader: Option<(u64, BufReader<File>)>,
    partial: String,
}

impl Tailer {
    /// Starts at `pos` (inode, offset) when it still names the current file.
    pub fn new(path: PathBuf, pos: Option<(u64, u64)>) -> Tailer {
        let mut t = Tailer {
            path,
            reader: None,
            partial: String::new(),
        };
        if let (Some((ino, off)), Ok(f)) = (pos, File::open(&t.path))
            && let Ok(m) = f.metadata()
            && m.ino() == ino
            && m.len() >= off
        {
            let mut r = BufReader::new(f);
            if r.seek(SeekFrom::Start(off)).is_ok() {
                t.reader = Some((ino, r));
            }
        }
        t
    }

    /// Reads every complete new line; returns them and the position after
    /// the last one.
    pub fn poll(&mut self) -> (Vec<String>, Option<(u64, u64)>) {
        let mut lines = Vec::new();
        loop {
            if self.reader.is_none() {
                match File::open(&self.path).and_then(|f| Ok((f.metadata()?.ino(), f))) {
                    Ok((ino, f)) => {
                        self.partial.clear();
                        self.reader = Some((ino, BufReader::new(f)));
                    }
                    Err(_) => return (lines, None),
                }
            }
            let Some((ino, r)) = self.reader.as_mut() else {
                return (lines, None);
            };
            let ino = *ino;
            loop {
                let mut buf = String::new();
                match r.read_line(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if buf.ends_with('\n') {
                            let mut l = std::mem::take(&mut self.partial);
                            l.push_str(buf.trim_end_matches('\n'));
                            if !l.is_empty() {
                                lines.push(l);
                            }
                        } else {
                            self.partial.push_str(&buf);
                        }
                    }
                }
            }
            let off = r.stream_position().unwrap_or(0) - self.partial.len() as u64;
            // rotated (new inode at the path) or truncated (shorter than us)
            let now = std::fs::metadata(&self.path).ok();
            match now {
                Some(m) if m.ino() != ino => {
                    self.reader = None;
                    continue;
                }
                Some(m) if m.len() < off => {
                    self.reader = None;
                    continue;
                }
                _ => return (lines, Some((ino, off))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const FIXTURE: &str = include_str!("../tests/fixtures/etpro-telemetry-eve.jsonl");

    #[test]
    fn timestamps() {
        assert_eq!(parse_timestamp("1970-01-01T00:00:01.5+0000"), Some(1500));
        assert_eq!(
            parse_timestamp("2018-05-21T13:05:42.646499+0200"),
            Some(1_526_900_742_646)
        );
        assert_eq!(
            parse_timestamp("2026-11-16T21:46:17.608604+00:00"),
            parse_timestamp("2026-11-16T22:46:17.608604+0100")
        );
        assert_eq!(parse_timestamp("garbage"), None);
    }

    #[test]
    fn eve_sample_parses_and_batches_t0408() {
        let mut s = AlertStore::memory().unwrap();
        let events: Vec<Event> = FIXTURE.lines().filter_map(parse_line).collect();
        assert_eq!(events.len(), FIXTURE.lines().count());
        s.write(&events, Some((1, FIXTURE.len() as u64))).unwrap();
        let (all, total) = s
            .list(&AlertFilter {
                limit: 100,
                ..AlertFilter::default()
            })
            .unwrap();
        assert_eq!(total as usize, events.len());
        assert!(all.windows(2).all(|w| w[0].ts >= w[1].ts), "newest first");
        let top = s
            .top_signatures(&AlertFilter {
                limit: 10,
                ..AlertFilter::default()
            })
            .unwrap();
        assert_eq!(top[0].sid, 2200094);
        let by_host = s
            .list(&AlertFilter {
                host: Some(all[0].src_ip.clone()),
                text: Some("padn".into()),
                limit: 10,
                ..AlertFilter::default()
            })
            .unwrap();
        assert!(by_host.1 >= 1);
        assert_eq!(s.position().unwrap(), Some((1, FIXTURE.len() as u64)));
    }

    #[test]
    fn retention_by_age_and_count() {
        let mut s = AlertStore::memory().unwrap();
        let mut events: Vec<Event> = Vec::new();
        for i in 0..10 {
            let mut a = match parse_line(FIXTURE.lines().next().unwrap()).unwrap() {
                Event::Alert(a) => *a,
                Event::Stats(_) => unreachable!(),
            };
            a.ts = i * 86_400_000;
            events.push(Event::Alert(Box::new(a)));
        }
        s.write(&events, None).unwrap();
        // older than 5 days at day 9: days 0..3 go; then keep the newest 3
        assert_eq!(s.prune(9 * 86_400_000, 5, 1000).unwrap(), 4);
        assert_eq!(s.prune(9 * 86_400_000, 5, 3).unwrap(), 3);
        let f = AlertFilter {
            limit: 100,
            ..AlertFilter::default()
        };
        assert_eq!(s.list(&f).unwrap().1, 3);
    }

    #[test]
    fn tailer_follows_appends_partial_lines_and_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("eve.json");
        let mut f = File::create(&p).unwrap();
        writeln!(f, "a").unwrap();
        write!(f, "b-part").unwrap();
        f.flush().unwrap();
        let mut t = Tailer::new(p.clone(), None);
        let (l, pos) = t.poll();
        assert_eq!(l, ["a"]);
        writeln!(f, "-rest").unwrap();
        let (l, pos2) = t.poll();
        assert_eq!(l, ["b-part-rest"]);
        assert!(pos2.unwrap().1 > pos.unwrap().1);
        // a restart resumes where it was
        let mut t2 = Tailer::new(p.clone(), pos2);
        writeln!(f, "c").unwrap();
        assert_eq!(t2.poll().0, ["c"]);
        // rotation: rename away, new file
        std::fs::rename(&p, dir.path().join("eve.json.1")).unwrap();
        writeln!(f, "d").unwrap(); // still the old inode
        let mut g = File::create(&p).unwrap();
        writeln!(g, "e").unwrap();
        assert_eq!(t2.poll().0, ["d", "e"]);
        // truncation
        let g = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&p)
            .unwrap();
        drop(g);
        assert!(t2.poll().0.is_empty());
        let mut g = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        writeln!(g, "f").unwrap();
        assert_eq!(t2.poll().0, ["f"]);
    }
}
