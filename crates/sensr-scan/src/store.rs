//! SQLite storage of scan results.
//!
//! The daemon opens the database with [`Store::open`] and writes; the API and
//! UI open it with [`Store::open_ro`]. WAL mode and a busy timeout let the two
//! coexist. Times are Unix seconds.

use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params};

use crate::proto::JobKind;
use crate::types::{
    Changes, Ident, JobView, PortRow, PortState, Proto, ScanStatus, ScanView, TlsInfo,
};

/// Schema version stored in `PRAGMA user_version`.
const SCHEMA_VERSION: i64 = 1;
/// How long a connection waits for a lock held by the other process.
const BUSY: Duration = Duration::from_secs(5);
/// Range jobs older than this are deleted by [`Store::prune`], in seconds.
const RANGE_JOB_TTL: i64 = 90 * 86_400;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    target TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    started INTEGER NOT NULL,
    finished INTEGER,
    status TEXT NOT NULL,
    public_ok INTEGER NOT NULL,
    skipped TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    job_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    mac TEXT,
    started INTEGER NOT NULL,
    finished INTEGER NOT NULL,
    status TEXT NOT NULL,
    all_open INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ports (
    scan_id INTEGER NOT NULL,
    proto TEXT NOT NULL,
    port INTEGER NOT NULL,
    state TEXT NOT NULL,
    service TEXT,
    product TEXT,
    version TEXT,
    title TEXT,
    tls_subject TEXT,
    tls_issuer TEXT,
    tls_not_after INTEGER,
    banner TEXT
);
CREATE INDEX IF NOT EXISTS scans_mac ON scans(mac);
CREATE INDEX IF NOT EXISTS scans_address ON scans(address);
CREATE INDEX IF NOT EXISTS scans_job ON scans(job_id);
CREATE INDEX IF NOT EXISTS ports_scan ON ports(scan_id);
";

const SCAN_COLS: &str = "id, job_id, address, mac, started, finished, status, all_open";
const PORT_COLS: &str = "proto, port, state, service, product, version, title, \
                         tls_subject, tls_issuer, tls_not_after, banner";

/// The results database.
pub struct Store {
    conn: Connection,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn bad<E: std::error::Error + Send + Sync + 'static>(col: usize, e: E) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(col, rusqlite::types::Type::Text, Box::new(e))
}

fn bad_text(col: usize, what: &str, s: &str) -> rusqlite::Error {
    bad(col, std::io::Error::other(format!("unknown {what} {s:?}")))
}

fn proto_str(p: Proto) -> &'static str {
    match p {
        Proto::Tcp => "tcp",
        Proto::Udp => "udp",
    }
}

fn state_str(s: PortState) -> &'static str {
    match s {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
        PortState::OpenFiltered => "open_filtered",
    }
}

fn kind_str(k: JobKind) -> &'static str {
    match k {
        JobKind::Device => "device",
        JobKind::Range => "range",
    }
}

fn scan_from_row(r: &Row<'_>) -> rusqlite::Result<ScanView> {
    let address: String = r.get(2)?;
    let status: String = r.get(6)?;
    Ok(ScanView {
        id: r.get(0)?,
        job_id: r.get(1)?,
        address: address.parse().map_err(|e| bad(2, e))?,
        mac: r.get(3)?,
        started: r.get(4)?,
        finished: r.get(5)?,
        status: status
            .parse()
            .map_err(|e: String| bad(6, std::io::Error::other(e)))?,
        all_open: r.get(7)?,
        ports: Vec::new(),
    })
}

fn port_from_row(r: &Row<'_>) -> rusqlite::Result<PortRow> {
    let proto: String = r.get(0)?;
    let state: String = r.get(2)?;
    let subject: Option<String> = r.get(7)?;
    let issuer: Option<String> = r.get(8)?;
    let not_after: Option<i64> = r.get(9)?;
    let tls = (subject.is_some() || issuer.is_some()).then(|| TlsInfo {
        subject: subject.unwrap_or_default(),
        sans: Vec::new(),
        issuer: issuer.unwrap_or_default(),
        not_after: not_after.unwrap_or_default(),
    });
    Ok(PortRow {
        proto: match proto.as_str() {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            other => return Err(bad_text(0, "protocol", other)),
        },
        port: r.get(1)?,
        state: match state.as_str() {
            "open" => PortState::Open,
            "closed" => PortState::Closed,
            "filtered" => PortState::Filtered,
            "open_filtered" => PortState::OpenFiltered,
            other => return Err(bad_text(2, "port state", other)),
        },
        service: r.get(3)?,
        ident: Ident {
            product: r.get(4)?,
            version: r.get(5)?,
            title: r.get(6)?,
            tls,
            banner: r.get(10)?,
        },
    })
}

fn job_from_row(r: &Row<'_>) -> rusqlite::Result<JobView> {
    let kind: String = r.get(1)?;
    let skipped: String = r.get(7)?;
    Ok(JobView {
        id: r.get(0)?,
        kind: match kind.as_str() {
            "device" => JobKind::Device,
            "range" => JobKind::Range,
            other => return Err(bad_text(1, "job kind", other)),
        },
        target: r.get(2)?,
        requested_by: r.get(3)?,
        started: r.get(4)?,
        finished: r.get(5)?,
        status: r.get(6)?,
        skipped: serde_json::from_str::<Vec<IpAddr>>(&skipped).map_err(|e| bad(7, e))?,
        hosts_alive: r.get(8)?,
    })
}

const JOB_SELECT: &str = "SELECT id, kind, target, requested_by, started, finished, status, \
    skipped, (SELECT count(*) FROM scans WHERE scans.job_id = jobs.id) FROM jobs";

impl Store {
    /// Open (creating if needed) the database for writing.
    ///
    /// # Errors
    /// Any SQLite error.
    pub fn open(path: &Path) -> rusqlite::Result<Store> {
        let conn = Connection::open(path)?;
        conn.busy_timeout(BUSY)?;
        conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
        conn.execute_batch(SCHEMA)?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(Store { conn })
    }

    /// Open an existing database read-only. Works while a writer is active.
    ///
    /// # Errors
    /// Any SQLite error, including a missing file.
    pub fn open_ro(path: &Path) -> rusqlite::Result<Store> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )?;
        conn.busy_timeout(BUSY)?;
        Ok(Store { conn })
    }

    /// Record a job that is starting now. Returns its id.
    ///
    /// # Errors
    /// Any SQLite error.
    pub fn begin_job(
        &self,
        kind: JobKind,
        target: &str,
        auto: bool,
        public_ok: bool,
    ) -> rusqlite::Result<i64> {
        self.conn.execute(
            "INSERT INTO jobs (kind, target, requested_by, started, status, public_ok) \
             VALUES (?1, ?2, ?3, ?4, 'running', ?5)",
            params![
                kind_str(kind),
                target,
                if auto { "auto" } else { "owner" },
                now(),
                public_ok
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Mark a job finished: `status` is `"complete"`, `"cancelled"` or
    /// `"failed"`; `skipped` lists addresses that were left out.
    ///
    /// # Errors
    /// Any SQLite error.
    pub fn end_job(&self, id: i64, status: &str, skipped: &[IpAddr]) -> rusqlite::Result<()> {
        let skipped = serde_json::to_string(skipped)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        self.conn.execute(
            "UPDATE jobs SET finished = ?1, status = ?2, skipped = ?3 WHERE id = ?4",
            params![now(), status, skipped, id],
        )?;
        Ok(())
    }

    /// Store one address's scan and its ports in one transaction.
    ///
    /// # Errors
    /// Any SQLite error; nothing is written then.
    #[allow(clippy::too_many_arguments)]
    pub fn write_scan(
        &self,
        job_id: i64,
        address: IpAddr,
        mac: Option<&str>,
        started: i64,
        finished: i64,
        status: ScanStatus,
        all_open: bool,
        ports: &[PortRow],
    ) -> rusqlite::Result<i64> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO scans (job_id, address, mac, started, finished, status, all_open) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                job_id,
                address.to_string(),
                mac,
                started,
                finished,
                status.as_str(),
                all_open
            ],
        )?;
        let id = tx.last_insert_rowid();
        {
            let mut ins = tx.prepare(&format!(
                "INSERT INTO ports (scan_id, {PORT_COLS}) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
            ))?;
            for p in ports {
                let tls = p.ident.tls.as_ref();
                ins.execute(params![
                    id,
                    proto_str(p.proto),
                    p.port,
                    state_str(p.state),
                    p.service,
                    p.ident.product,
                    p.ident.version,
                    p.ident.title,
                    tls.map(|t| t.subject.as_str()),
                    tls.map(|t| t.issuer.as_str()),
                    tls.map(|t| t.not_after),
                    p.ident.banner,
                ])?;
            }
        }
        tx.commit()?;
        Ok(id)
    }

    fn ports_of(&self, scan_id: i64) -> rusqlite::Result<Vec<PortRow>> {
        let mut st = self.conn.prepare_cached(&format!(
            "SELECT {PORT_COLS} FROM ports WHERE scan_id = ?1 ORDER BY proto, port, rowid"
        ))?;
        let rows = st.query_map([scan_id], port_from_row)?;
        rows.collect()
    }

    fn scans_where(
        &self,
        clause: &str,
        args: &[&dyn rusqlite::ToSql],
    ) -> rusqlite::Result<Vec<ScanView>> {
        let mut st = self
            .conn
            .prepare_cached(&format!("SELECT {SCAN_COLS} FROM scans WHERE {clause}"))?;
        let mut scans = st
            .query_map(args, scan_from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for s in &mut scans {
            s.ports = self.ports_of(s.id)?;
        }
        Ok(scans)
    }

    /// The newest scan of a device, whatever its status.
    ///
    /// # Errors
    /// Any SQLite error.
    pub fn latest_for_mac(&self, mac: &str) -> rusqlite::Result<Option<ScanView>> {
        Ok(self
            .scans_where("mac = ?1 ORDER BY started DESC, id DESC LIMIT 1", &[&mac])?
            .pop())
    }

    /// Whether the device has ever had a complete scan.
    ///
    /// # Errors
    /// Any SQLite error.
    pub fn has_complete(&self, mac: &str) -> rusqlite::Result<bool> {
        self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM scans WHERE mac = ?1 AND status = 'complete')",
            [mac],
            |r| r.get(0),
        )
    }

    /// Whether the owner cancelled an auto-started job for this device (its
    /// scans carry the MAC, or it targeted the MAC directly).
    ///
    /// # Errors
    /// Any SQLite error.
    pub fn auto_cancelled(&self, mac: &str) -> rusqlite::Result<bool> {
        self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM jobs j WHERE j.requested_by = 'auto' \
               AND j.status = 'cancelled' \
               AND (j.target = ?1 OR EXISTS(SELECT 1 FROM scans s \
                    WHERE s.job_id = j.id AND s.mac = ?1)))",
            [mac],
            |r| r.get(0),
        )
    }

    /// Scans of a MAC or an address, newest first.
    ///
    /// # Errors
    /// Any SQLite error.
    pub fn history(&self, mac_or_addr: &str, limit: u32) -> rusqlite::Result<Vec<ScanView>> {
        self.scans_where(
            "mac = ?1 OR address = ?1 ORDER BY started DESC, id DESC LIMIT ?2",
            &[&mac_or_addr, &limit],
        )
    }

    /// Jobs of one kind, newest first.
    ///
    /// # Errors
    /// Any SQLite error.
    pub fn jobs(&self, kind: JobKind, limit: u32) -> rusqlite::Result<Vec<JobView>> {
        let mut st = self.conn.prepare_cached(&format!(
            "{JOB_SELECT} WHERE kind = ?1 ORDER BY started DESC, id DESC LIMIT ?2"
        ))?;
        let rows = st.query_map(params![kind_str(kind), limit], job_from_row)?;
        rows.collect()
    }

    /// One job with its scans (oldest first).
    ///
    /// # Errors
    /// Any SQLite error.
    pub fn job(&self, id: i64) -> rusqlite::Result<Option<(JobView, Vec<ScanView>)>> {
        let Some(job) = self
            .conn
            .query_row(&format!("{JOB_SELECT} WHERE id = ?1"), [id], job_from_row)
            .optional()?
        else {
            return Ok(None);
        };
        let scans = self.scans_where("job_id = ?1 ORDER BY id", &[&id])?;
        Ok(Some((job, scans)))
    }

    /// How a complete scan differs from the previous complete scan of the same
    /// device (by MAC, or by address when it has no MAC). Empty when the scan
    /// is not complete or has no earlier complete scan.
    ///
    /// # Errors
    /// Any SQLite error.
    pub fn changes(&self, scan_id: i64) -> rusqlite::Result<Changes> {
        let Some(cur) = self.scans_where("id = ?1", &[&scan_id])?.pop() else {
            return Ok(Changes::default());
        };
        if cur.status != ScanStatus::Complete {
            return Ok(Changes::default());
        }
        let (clause, key) = match &cur.mac {
            Some(m) => ("mac = ?1", m.clone()),
            None => ("mac IS NULL AND address = ?1", cur.address.to_string()),
        };
        let prev = self
            .scans_where(
                &format!(
                    "{clause} AND status = 'complete' AND (started, id) < (?2, ?3) \
                     ORDER BY started DESC, id DESC LIMIT 1"
                ),
                &[&key, &cur.started, &cur.id],
            )?
            .pop();
        let Some(prev) = prev else {
            return Ok(Changes::default());
        };
        let open = |s: &ScanView| -> std::collections::BTreeMap<(Proto, u16), Vec<Option<String>>> {
            s.ports
                .iter()
                .filter(|p| p.state == PortState::Open)
                .map(|p| {
                    let i = &p.ident;
                    let t = i.tls.as_ref();
                    let fields = vec![
                        i.product.clone(),
                        i.version.clone(),
                        i.title.clone(),
                        t.map(|t| t.subject.clone()),
                        t.map(|t| t.issuer.clone()),
                        i.banner.clone(),
                    ];
                    ((p.proto, p.port), fields)
                })
                .collect()
        };
        let (a, b) = (open(&prev), open(&cur));
        let mut out = Changes::default();
        for (k, v) in &b {
            match a.get(k) {
                None => out.opened.push(*k),
                Some(old) if old != v => out.changed.push(*k),
                Some(_) => {}
            }
        }
        out.closed = a.keys().filter(|k| !b.contains_key(*k)).copied().collect();
        Ok(out)
    }

    /// Drop old results, in one transaction. For each device (MAC, or address
    /// when there is no MAC) keep the newest `history` (at least 1) complete
    /// scans and anything newer than the oldest of them. A device with no
    /// complete scan keeps its newest `history` scans. Range jobs finished
    /// more than 90 days before `now` are deleted with their scans, except
    /// scans kept by a MAC's history, which keep their job row too.
    ///
    /// # Errors
    /// Any SQLite error; nothing is deleted then.
    pub fn prune(&self, history: u16, now: i64) -> rusqlite::Result<()> {
        use std::collections::{HashMap, HashSet};
        let keep_n = usize::from(history.max(1));
        let tx = self.conn.unchecked_transaction()?;

        // (id, started, complete) per device, newest first.
        let mut groups: HashMap<String, Vec<(i64, i64, bool)>> = HashMap::new();
        let mut macs: HashMap<i64, bool> = HashMap::new();
        {
            let mut st = tx.prepare(
                "SELECT id, COALESCE(mac, address), mac IS NOT NULL, started, status = 'complete' \
                 FROM scans ORDER BY started DESC, id DESC",
            )?;
            let mut rows = st.query([])?;
            while let Some(r) = rows.next()? {
                let (id, key, has_mac, started, complete): (i64, String, bool, i64, bool) =
                    (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?);
                macs.insert(id, has_mac);
                groups.entry(key).or_default().push((id, started, complete));
            }
        }
        let mut kept: HashSet<i64> = HashSet::new();
        let mut drop_ids: Vec<i64> = Vec::new();
        for scans in groups.values() {
            let completes: Vec<&(i64, i64, bool)> = scans.iter().filter(|s| s.2).collect();
            // The oldest scan to keep: the keep_n-th newest complete one, else
            // the oldest complete one, else the keep_n-th newest of any kind.
            let boundary = completes
                .get(keep_n - 1)
                .or(completes.last())
                .copied()
                .or_else(|| scans.get(keep_n - 1).or(scans.last()));
            // `scans` is newest first, so everything before the boundary is newer.
            let cut = boundary.and_then(|b| scans.iter().position(|s| s.0 == b.0));
            for (i, s) in scans.iter().enumerate() {
                if cut.is_some_and(|c| i <= c) {
                    kept.insert(s.0);
                } else {
                    drop_ids.push(s.0);
                }
            }
        }

        // Expired range jobs: their scans go unless a MAC's history keeps them.
        let expired: Vec<i64> = {
            let mut st = tx.prepare(
                "SELECT id FROM jobs WHERE kind = 'range' AND finished IS NOT NULL AND finished < ?1",
            )?;
            let rows = st.query_map([now - RANGE_JOB_TTL], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        {
            let mut st = tx.prepare("SELECT id FROM scans WHERE job_id = ?1")?;
            for job in &expired {
                for id in st
                    .query_map([job], |r| r.get::<_, i64>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?
                {
                    if !(kept.contains(&id) && macs.get(&id).copied().unwrap_or(false)) {
                        kept.remove(&id);
                        drop_ids.push(id);
                    }
                }
            }
        }

        {
            let mut dp = tx.prepare("DELETE FROM ports WHERE scan_id = ?1")?;
            let mut ds = tx.prepare("DELETE FROM scans WHERE id = ?1")?;
            for id in &drop_ids {
                dp.execute([id])?;
                ds.execute([id])?;
            }
        }
        for job in &expired {
            tx.execute(
                "DELETE FROM jobs WHERE id = ?1 AND NOT EXISTS(SELECT 1 FROM scans WHERE job_id = ?1)",
                [job],
            )?;
        }
        tx.commit()
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use crate::proto::JobKind;
    use crate::types::{Changes, Ident, PortRow, PortState, Proto, ScanStatus, TlsInfo};

    const MAC: &str = "aa:bb:cc:dd:ee:01";
    const DAY: i64 = 86_400;

    fn mem() -> Store {
        Store::open(std::path::Path::new(":memory:")).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn open(port: u16, banner: Option<&str>) -> PortRow {
        PortRow {
            proto: Proto::Tcp,
            port,
            state: PortState::Open,
            service: Some("svc".into()),
            ident: Ident {
                banner: banner.map(Into::into),
                ..Ident::default()
            },
        }
    }

    fn put(
        s: &Store,
        job: i64,
        mac: Option<&str>,
        at: i64,
        st: ScanStatus,
        ports: &[PortRow],
    ) -> i64 {
        s.write_scan(job, ip("192.168.1.10"), mac, at, at + 5, st, false, ports)
            .unwrap()
    }

    fn device_job(s: &Store) -> i64 {
        s.begin_job(JobKind::Device, "192.168.1.10", false, false)
            .unwrap()
    }

    fn count(s: &Store, table: &str) -> i64 {
        s.conn
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn changes_opened_and_closed() {
        let s = mem();
        let j = device_job(&s);
        put(
            &s,
            j,
            Some(MAC),
            100,
            ScanStatus::Complete,
            &[open(22, None), open(80, None)],
        );
        let b = put(
            &s,
            j,
            Some(MAC),
            200,
            ScanStatus::Complete,
            &[open(22, None), open(3389, None)],
        );
        assert_eq!(
            s.changes(b).unwrap(),
            Changes {
                opened: vec![(Proto::Tcp, 3389)],
                closed: vec![(Proto::Tcp, 80)],
                changed: vec![]
            }
        );
    }

    #[test]
    fn partial_scan_has_no_changes_and_is_skipped_as_baseline() {
        let s = mem();
        let j = device_job(&s);
        put(
            &s,
            j,
            Some(MAC),
            100,
            ScanStatus::Complete,
            &[open(22, None), open(80, None)],
        );
        let b = put(
            &s,
            j,
            Some(MAC),
            200,
            ScanStatus::Complete,
            &[open(22, None), open(3389, None)],
        );
        let p = put(
            &s,
            j,
            Some(MAC),
            300,
            ScanStatus::Partial,
            &[open(22, None)],
        );
        assert_eq!(s.changes(p).unwrap(), Changes::default());
        let c = put(
            &s,
            j,
            Some(MAC),
            400,
            ScanStatus::Complete,
            &[open(22, None), open(3389, None)],
        );
        assert_eq!(s.changes(c).unwrap(), Changes::default());
        assert_ne!(b, c);
        let d = put(
            &s,
            j,
            Some(MAC),
            500,
            ScanStatus::Complete,
            &[open(22, None)],
        );
        assert_eq!(s.changes(d).unwrap().closed, vec![(Proto::Tcp, 3389)]);
    }

    #[test]
    fn banner_change_is_changed() {
        let s = mem();
        let j = device_job(&s);
        put(
            &s,
            j,
            Some(MAC),
            100,
            ScanStatus::Complete,
            &[open(22, Some("SSH-2.0-a"))],
        );
        let b = put(
            &s,
            j,
            Some(MAC),
            200,
            ScanStatus::Complete,
            &[open(22, Some("SSH-2.0-b"))],
        );
        assert_eq!(
            s.changes(b).unwrap(),
            Changes {
                opened: vec![],
                closed: vec![],
                changed: vec![(Proto::Tcp, 22)]
            }
        );
    }

    #[test]
    fn tls_change_is_changed_and_open_filtered_is_not_open() {
        let s = mem();
        let j = device_job(&s);
        let tls = |issuer: &str| {
            let mut p = open(443, None);
            p.ident.tls = Some(TlsInfo {
                subject: "CN=x".into(),
                sans: vec![],
                issuer: issuer.into(),
                not_after: 5,
            });
            p
        };
        let of = PortRow {
            proto: Proto::Udp,
            port: 161,
            state: PortState::OpenFiltered,
            service: None,
            ident: Ident::default(),
        };
        put(&s, j, Some(MAC), 100, ScanStatus::Complete, &[tls("CN=a")]);
        let b = put(
            &s,
            j,
            Some(MAC),
            200,
            ScanStatus::Complete,
            &[tls("CN=b"), of],
        );
        let c = s.changes(b).unwrap();
        assert_eq!(c.changed, vec![(Proto::Tcp, 443)]);
        assert!(c.opened.is_empty() && c.closed.is_empty());
    }

    #[test]
    fn changes_without_mac_uses_address_and_first_scan_is_empty() {
        let s = mem();
        let j = device_job(&s);
        let a = put(&s, j, None, 100, ScanStatus::Complete, &[open(22, None)]);
        assert_eq!(s.changes(a).unwrap(), Changes::default());
        // Another address with no MAC is not a baseline.
        s.write_scan(
            j,
            ip("192.168.1.99"),
            None,
            150,
            155,
            ScanStatus::Complete,
            false,
            &[open(9, None)],
        )
        .unwrap();
        let b = put(
            &s,
            j,
            None,
            200,
            ScanStatus::Complete,
            &[open(22, None), open(80, None)],
        );
        assert_eq!(s.changes(b).unwrap().opened, vec![(Proto::Tcp, 80)]);
    }

    #[test]
    fn prune_keeps_newest_history_complete() {
        let s = mem();
        let j = device_job(&s);
        let ids: Vec<i64> = (1..=4)
            .map(|i| {
                put(
                    &s,
                    j,
                    Some(MAC),
                    i * 100,
                    ScanStatus::Complete,
                    &[open(22, None)],
                )
            })
            .collect();
        // A newer failed scan survives; an older partial than the boundary goes.
        let old_partial = put(&s, j, Some(MAC), 50, ScanStatus::Partial, &[open(1, None)]);
        let newer_failed = put(&s, j, Some(MAC), 450, ScanStatus::Failed, &[]);
        s.prune(2, 1000).unwrap();
        let left: Vec<i64> = s.history(MAC, 100).unwrap().iter().map(|v| v.id).collect();
        assert_eq!(left, vec![newer_failed, ids[3], ids[2]]);
        assert!(!left.contains(&old_partial));
        assert_eq!(count(&s, "ports"), 2);
    }

    #[test]
    fn prune_expires_range_jobs_but_keeps_scans_in_mac_history() {
        let s = mem();
        let now = 1_000 * DAY;
        let old = s
            .begin_job(JobKind::Range, "192.168.1.0/24", false, false)
            .unwrap();
        s.end_job(old, "complete", &[]).unwrap();
        s.conn
            .execute(
                "UPDATE jobs SET started=?1, finished=?1 WHERE id=?2",
                rusqlite::params![now - 91 * DAY, old],
            )
            .unwrap();
        // MAC A: only scan is in the old job -> within history, kept.
        let kept = s
            .write_scan(
                old,
                ip("192.168.1.2"),
                Some("aa:aa:aa:aa:aa:aa"),
                now - 91 * DAY,
                now - 91 * DAY + 1,
                ScanStatus::Complete,
                false,
                &[open(22, None)],
            )
            .unwrap();
        // MAC B: two newer complete scans elsewhere push the old one out.
        let gone = s
            .write_scan(
                old,
                ip("192.168.1.3"),
                Some("bb:bb:bb:bb:bb:bb"),
                now - 91 * DAY,
                now - 91 * DAY + 1,
                ScanStatus::Complete,
                false,
                &[open(80, None)],
            )
            .unwrap();
        // No MAC: dropped with the job.
        let nomac = s
            .write_scan(
                old,
                ip("192.168.1.4"),
                None,
                now - 91 * DAY,
                now - 91 * DAY + 1,
                ScanStatus::Complete,
                false,
                &[],
            )
            .unwrap();
        let dj = device_job(&s);
        for t in [10, 20] {
            s.write_scan(
                dj,
                ip("192.168.1.3"),
                Some("bb:bb:bb:bb:bb:bb"),
                now - t * DAY,
                now - t * DAY + 1,
                ScanStatus::Complete,
                false,
                &[],
            )
            .unwrap();
        }
        // A fresh range job is untouched.
        let fresh = s
            .begin_job(JobKind::Range, "10.0.0.0/24", false, false)
            .unwrap();
        s.end_job(fresh, "complete", &[]).unwrap();

        s.prune(2, now).unwrap();
        let ids: Vec<i64> = s
            .jobs(JobKind::Range, 10)
            .unwrap()
            .iter()
            .map(|j| j.id)
            .collect();
        assert!(ids.contains(&old), "job kept because one scan is kept");
        assert!(ids.contains(&fresh));
        let (_, scans) = s.job(old).unwrap().unwrap();
        assert_eq!(scans.iter().map(|v| v.id).collect::<Vec<_>>(), vec![kept]);
        let _ = (gone, nomac);

        // With history 1, MAC A's scan is still its newest, so the job stays;
        // once A has a newer scan the job disappears entirely.
        s.write_scan(
            dj,
            ip("192.168.1.2"),
            Some("aa:aa:aa:aa:aa:aa"),
            now - DAY,
            now - DAY + 1,
            ScanStatus::Complete,
            false,
            &[],
        )
        .unwrap();
        s.prune(1, now).unwrap();
        assert!(s.job(old).unwrap().is_none());
        assert!(s.job(fresh).unwrap().is_some());
        assert_eq!(count(&s, "ports"), 0);
    }

    #[test]
    fn auto_cancelled_only_for_auto_and_cancelled() {
        let s = mem();
        let mk = |auto: bool, status: &str, mac: &str| {
            let j = s.begin_job(JobKind::Device, "x", auto, false).unwrap();
            s.write_scan(
                j,
                ip("10.0.0.1"),
                Some(mac),
                1,
                2,
                ScanStatus::Cancelled,
                false,
                &[],
            )
            .unwrap();
            s.end_job(j, status, &[]).unwrap();
        };
        mk(true, "cancelled", "m:auto-cancelled");
        mk(false, "cancelled", "m:owner-cancelled");
        mk(true, "complete", "m:auto-complete");
        mk(true, "failed", "m:auto-failed");
        assert!(s.auto_cancelled("m:auto-cancelled").unwrap());
        assert!(!s.auto_cancelled("m:owner-cancelled").unwrap());
        assert!(!s.auto_cancelled("m:auto-complete").unwrap());
        assert!(!s.auto_cancelled("m:auto-failed").unwrap());
        assert!(!s.auto_cancelled("m:unknown").unwrap());
    }

    #[test]
    fn latest_for_mac_shows_failed_and_has_complete() {
        let s = mem();
        assert!(s.latest_for_mac(MAC).unwrap().is_none());
        assert!(!s.has_complete(MAC).unwrap());
        let j = device_job(&s);
        put(&s, j, Some(MAC), 100, ScanStatus::Failed, &[]);
        assert!(!s.has_complete(MAC).unwrap());
        put(
            &s,
            j,
            Some(MAC),
            200,
            ScanStatus::Complete,
            &[open(22, None)],
        );
        assert!(s.has_complete(MAC).unwrap());
        let f = put(&s, j, Some(MAC), 300, ScanStatus::Failed, &[]);
        let v = s.latest_for_mac(MAC).unwrap().unwrap();
        assert_eq!((v.id, v.status), (f, ScanStatus::Failed));
        assert!(v.ports.is_empty());
    }

    #[test]
    fn ports_round_trip() {
        let s = mem();
        let j = device_job(&s);
        let row = PortRow {
            proto: Proto::Tcp,
            port: 443,
            state: PortState::Open,
            service: Some("https".into()),
            ident: Ident {
                product: Some("nginx".into()),
                version: Some("1.2".into()),
                title: Some("Home".into()),
                tls: Some(TlsInfo {
                    subject: "CN=a".into(),
                    sans: vec![],
                    issuer: "CN=b".into(),
                    not_after: 99,
                }),
                banner: Some("hi".into()),
            },
        };
        let udp = PortRow {
            proto: Proto::Udp,
            port: 53,
            state: PortState::OpenFiltered,
            service: None,
            ident: Ident::default(),
        };
        s.write_scan(
            j,
            ip("fe80::1"),
            Some(MAC),
            1,
            2,
            ScanStatus::Complete,
            true,
            &[row.clone(), udp.clone()],
        )
        .unwrap();
        let v = s.latest_for_mac(MAC).unwrap().unwrap();
        assert_eq!(v.address, ip("fe80::1"));
        assert!(v.all_open);
        assert_eq!((v.started, v.finished, v.job_id), (1, 2, j));
        assert_eq!(v.ports, vec![row, udp]);
    }

    #[test]
    fn jobs_views_and_history() {
        let s = mem();
        let j = s
            .begin_job(JobKind::Range, "10.0.0.0/30", true, true)
            .unwrap();
        let d = device_job(&s);
        s.write_scan(
            j,
            ip("10.0.0.1"),
            None,
            1,
            2,
            ScanStatus::Complete,
            false,
            &[],
        )
        .unwrap();
        s.write_scan(
            j,
            ip("10.0.0.2"),
            Some(MAC),
            3,
            4,
            ScanStatus::Complete,
            false,
            &[],
        )
        .unwrap();
        let running = s.job(j).unwrap().unwrap().0;
        assert_eq!(running.status, "running");
        assert_eq!(running.finished, None);
        s.end_job(j, "complete", &[ip("10.0.0.3"), ip("8.8.8.8")])
            .unwrap();
        let (jv, scans) = s.job(j).unwrap().unwrap();
        assert_eq!(
            (jv.kind, jv.requested_by.as_str(), jv.status.as_str()),
            (JobKind::Range, "auto", "complete")
        );
        assert_eq!(jv.hosts_alive, 2);
        assert_eq!(jv.skipped, vec![ip("10.0.0.3"), ip("8.8.8.8")]);
        assert!(jv.finished.is_some());
        assert_eq!(scans.len(), 2);
        let ranges = s.jobs(JobKind::Range, 10).unwrap();
        assert_eq!(ranges.len(), 1);
        assert_eq!(s.jobs(JobKind::Device, 10).unwrap()[0].id, d);
        assert_eq!(
            s.jobs(JobKind::Device, 10).unwrap()[0].requested_by,
            "owner"
        );
        assert!(s.job(9999).unwrap().is_none());
        assert_eq!(s.history("10.0.0.1", 5).unwrap().len(), 1);
        assert_eq!(s.history(MAC, 5).unwrap().len(), 1);
        assert_eq!(s.history(MAC, 0).unwrap().len(), 0);
    }

    #[test]
    fn schema_is_versioned_idempotent_and_readable_while_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.db");
        let w = Store::open(&path).unwrap();
        let j = device_job(&w);
        put(&w, j, Some(MAC), 1, ScanStatus::Complete, &[open(22, None)]);
        let v: i64 = w
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, 1);
        let mode: String = w
            .conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        // Reopen: nothing lost, schema not recreated.
        drop(Store::open(&path).unwrap());
        let ro = Store::open_ro(&path).unwrap();
        // Writer open and mid-transaction while the reader reads.
        w.conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        w.conn
            .execute("UPDATE scans SET status='failed'", [])
            .unwrap();
        assert!(ro.has_complete(MAC).unwrap());
        w.conn.execute_batch("COMMIT").unwrap();
        assert!(!ro.has_complete(MAC).unwrap());
        assert!(ro.conn.execute("DELETE FROM scans", []).is_err());
    }

    #[test]
    fn scan_status_text_round_trip() {
        for s in [
            ScanStatus::Complete,
            ScanStatus::Partial,
            ScanStatus::Cancelled,
            ScanStatus::Failed,
        ] {
            assert_eq!(s.as_str().parse::<ScanStatus>().unwrap(), s);
        }
        assert!("nope".parse::<ScanStatus>().is_err());
    }
}
