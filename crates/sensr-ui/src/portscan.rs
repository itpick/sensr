//! Port scanner results for the Hosts card, the host page and Services › Port Scanner.
//!
//! The views here travel to the browser. On the server, results are read from the
//! database `sensr-scan` writes (`scans.db`, read-only per request like the insight
//! databases: a missing file is "never scanned", not an error), and the daemon's queue
//! comes from its control socket through [`crate::api::Backend::portscan`].
//!
//! Everything a device said (titles, banners, products, certificate subjects) is
//! untrusted: views carry it as plain text, and pages render it only as text.

use crate::runtime::{HostPorts, OPEN_FILTERED_TIP, PortChip, port_name};
use sensr_scan::proto::{JobKind, JobProgress, Refusal, StatusView};
use sensr_scan::types::{Changes, Ident, JobView, PortRow, PortState, Proto, ScanView};
use serde::{Deserialize, Serialize};

/// What the UI says when the daemon's socket cannot be used.
pub const NOT_RUNNING: &str = "The port scanner is not running.";

/// Answer to a scan request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanStart {
    /// Queued as this job.
    Started(u64),
    /// Not accepted: the refusal's text.
    Refused(String),
}

/// Services › Port Scanner. Rows carry display text only: the browser bundle needs no
/// scanner types.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortscanView {
    /// The running job, then the queued ones; empty when nothing runs (or `note` is set).
    pub jobs: Vec<QueueRow>,
    /// Why the queue is unknown ([`NOT_RUNNING`]).
    pub note: Option<String>,
    /// The caller may start and cancel scans.
    pub can_scan: bool,
    /// Every inventory device with a MAC, and its latest scan.
    pub devices: Vec<DeviceRow>,
    /// Range scans, newest first.
    pub ranges: Vec<RangeJob>,
}

/// A running or queued job.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueRow {
    pub job_id: u64,
    pub target: String,
    /// `device` or `range`.
    pub kind: String,
    /// Its progress in words ([`progress_text`]), or `queued`.
    pub progress: String,
}

impl QueueRow {
    /// The rows of the daemon's status: the running job first.
    pub fn of(s: &StatusView) -> Vec<QueueRow> {
        let kind = |k: JobKind| {
            if k == JobKind::Device {
                "device"
            } else {
                "range"
            }
        };
        s.running
            .iter()
            .map(|r| QueueRow {
                job_id: r.job_id,
                target: r.target.clone(),
                kind: kind(r.kind).to_owned(),
                progress: progress_text(r),
            })
            .chain(s.queue.iter().map(|q| QueueRow {
                job_id: q.job_id,
                target: q.target.clone(),
                kind: kind(q.kind).to_owned(),
                progress: "queued".to_owned(),
            }))
            .collect()
    }
}

/// One inventory device on the Port Scanner page.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRow {
    /// Inventory key (for the host page link).
    pub key: String,
    /// Display name.
    pub name: String,
    pub mac: String,
    pub ipv4: Option<String>,
    pub ports: HostPorts,
}

/// A range scan and what each live address had open.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeJob {
    pub target: String,
    /// When it started, `YYYY-MM-DD HH:MM:SS UTC`.
    pub started: String,
    /// `complete`, `running`, ..., with how many addresses were skipped.
    pub status: String,
    /// Addresses that were alive and scanned.
    pub alive: u32,
    pub results: Vec<RangeResult>,
}

impl RangeJob {
    /// The row of a stored job and its results.
    pub fn of(j: &JobView, results: Vec<RangeResult>) -> RangeJob {
        RangeJob {
            target: j.target.clone(),
            started: crate::runtime::fmt_time(u64::try_from(j.started).unwrap_or(0)),
            status: if j.skipped.is_empty() {
                j.status.clone()
            } else {
                format!("{}, {} skipped", j.status, j.skipped.len())
            },
            alive: j.hosts_alive,
            results,
        }
    }
}

/// One address of a range scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeResult {
    pub address: String,
    pub open: Vec<PortChip>,
}

/// A device's ports for its host page.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPortsDetail {
    /// Every port of the latest scan, open first.
    pub ports: Vec<PortRow>,
    /// Earlier and latest scans, newest first.
    pub history: Vec<HistoryEntry>,
    /// A scan of it is running or queued.
    pub scanning: bool,
    /// The caller may start a scan (and the device has an address to scan).
    pub can_scan: bool,
    /// The address Scan now scans.
    pub ipv4: Option<String>,
    pub mac: String,
}

/// One scan in a device's history.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Unix seconds.
    pub finished: i64,
    /// `complete`, `partial`, `cancelled`, `failed`.
    pub status: String,
    pub address: String,
    /// Open ports found.
    pub open: u32,
    /// What changed since the scan before (as on the Hosts card).
    pub changes: Vec<String>,
}

/// What the Port Scanner page was sent back with after a form post (`/ui/portscan?…`).
/// Only codes, numbers and a target that parses travel in the URL: messages are rebuilt
/// from them, so no free text is reflected.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortscanQuery {
    /// A scan was queued as this job.
    pub started: Option<u64>,
    /// The target of the form (only kept when it parses as one).
    pub target: String,
    /// A refusal: `public`, `too_large`, `excluded`, `invalid`, `disabled`.
    pub refused: Option<String>,
    /// [`Refusal::TooLarge`]'s numbers.
    pub addresses: Option<u64>,
    pub max: Option<u32>,
    /// This job was cancelled.
    pub cancelled: Option<u64>,
    /// `not_running`, `forbidden` or another failure.
    pub error: Option<String>,
}

impl PortscanQuery {
    /// Reads the query (each value through `get`).
    pub fn from_query(get: impl Fn(&str) -> Option<String>) -> Self {
        let target = get("target")
            .map(|t| t.trim().to_owned())
            .filter(|t| t.len() <= 100 && sensr_scan::target::parse(t).is_ok())
            .unwrap_or_default();
        PortscanQuery {
            started: get("started").and_then(|v| v.parse().ok()),
            target,
            refused: get("refused"),
            addresses: get("addresses").and_then(|v| v.parse().ok()),
            max: get("max").and_then(|v| v.parse().ok()),
            cancelled: get("cancelled").and_then(|v| v.parse().ok()),
            error: get("error"),
        }
    }

    /// The message to show: `(is an error, text)`.
    pub fn message(&self) -> Option<(bool, String)> {
        if let Some(e) = &self.error {
            return Some((
                true,
                match e.as_str() {
                    "not_running" => NOT_RUNNING.to_owned(),
                    "forbidden" => "You may not start or cancel port scans.".to_owned(),
                    _ => "The scan could not be started.".to_owned(),
                },
            ));
        }
        if let Some(code) = &self.refused {
            let r = match code.as_str() {
                "public" => Refusal::Public,
                "too_large" => Refusal::TooLarge {
                    addresses: self.addresses.unwrap_or(0),
                    max: self.max.unwrap_or(0),
                },
                "excluded" => Refusal::Excluded,
                "disabled" => Refusal::Disabled,
                _ => Refusal::Invalid("check the address, network or range".to_owned()),
            };
            return Some((true, format!("Not scanned: {r}.")));
        }
        if let Some(id) = self.started {
            let what = if self.target.is_empty() {
                String::new()
            } else {
                format!(" of {}", self.target)
            };
            return Some((false, format!("Scan{what} queued (job {id}).")));
        }
        self.cancelled
            .map(|id| (false, format!("Scan job {id} cancelled.")))
    }
}

/// The query pairs for a refusal (an invalid target is not echoed: the page says so in
/// general words).
pub fn refusal_pairs(r: &Refusal) -> Vec<(&'static str, String)> {
    let code = |c: &str| vec![("refused", c.to_owned())];
    match r {
        Refusal::Public => code("public"),
        Refusal::TooLarge { addresses, max } => vec![
            ("refused", "too_large".to_owned()),
            ("addresses", addresses.to_string()),
            ("max", max.to_string()),
        ],
        Refusal::Excluded => code("excluded"),
        Refusal::Invalid(_) => code("invalid"),
        Refusal::Disabled => code("disabled"),
    }
}

/// What a device said on a port, as one line of plain text: product and version, page
/// title, banner and certificate, joined with ` · `.
pub fn said(i: &Ident) -> String {
    let mut parts = Vec::new();
    match (&i.product, &i.version) {
        (Some(p), Some(v)) => parts.push(format!("{p} {v}")),
        (Some(p), None) => parts.push(p.clone()),
        (None, Some(v)) => parts.push(v.clone()),
        (None, None) => {}
    }
    if let Some(t) = &i.title {
        parts.push(format!("\"{t}\""));
    }
    if let Some(b) = &i.banner {
        parts.push(b.clone());
    }
    if let Some(t) = &i.tls {
        let expires = crate::runtime::fmt_time(u64::try_from(t.not_after).unwrap_or(0));
        parts.push(format!(
            "certificate {}, expires {}",
            t.subject,
            expires.get(..10).unwrap_or(&expires)
        ));
    }
    parts.join(" · ")
}

/// The chip of one port row.
pub fn chip(p: &PortRow) -> PortChip {
    let open_filtered = p.state == PortState::OpenFiltered;
    PortChip {
        proto: p.proto,
        port: p.port,
        service: p.service.clone(),
        label: p.ident.title.clone().or_else(|| p.ident.product.clone()),
        tip: if open_filtered {
            OPEN_FILTERED_TIP.to_owned()
        } else {
            said(&p.ident)
        },
        open_filtered,
    }
}

/// `+3389 new`, `-22 closed`, `443 changed`.
pub fn change_text(c: &Changes) -> Vec<String> {
    let name = |(proto, port): &(Proto, u16)| port_name(*proto, *port);
    c.opened
        .iter()
        .map(|p| format!("+{} new", name(p)))
        .chain(c.closed.iter().map(|p| format!("-{} closed", name(p))))
        .chain(c.changed.iter().map(|p| format!("{} changed", name(p))))
        .collect()
}

/// Port rows in display order: open (TCP, then UDP, by port), then open|filtered, then
/// the rest.
pub fn sorted(ports: &[PortRow]) -> Vec<PortRow> {
    let rank = |s: PortState| match s {
        PortState::Open => 0,
        PortState::OpenFiltered => 1,
        PortState::Closed => 2,
        PortState::Filtered => 3,
    };
    let mut v = ports.to_vec();
    v.sort_by_key(|p| (rank(p.state), p.proto, p.port));
    v
}

/// The Hosts card's view of a device's latest scan and what changed since the one before.
pub fn host_ports(scan: &ScanView, changes: &Changes) -> HostPorts {
    let shown: Vec<PortChip> = sorted(&scan.ports)
        .iter()
        .filter(|p| matches!(p.state, PortState::Open | PortState::OpenFiltered))
        .filter(|p| !changes.opened.contains(&(p.proto, p.port)))
        .map(chip)
        .collect();
    let more = shown.len().saturating_sub(HostPorts::SHOWN);
    HostPorts {
        open: shown.into_iter().take(HostPorts::SHOWN).collect(),
        more: u32::try_from(more).unwrap_or(u32::MAX),
        changes: change_text(changes),
        scanned_at: Some(scan.finished),
        status: scan.status.as_str().to_owned(),
        scanning: false,
    }
}

/// Whether the daemon is scanning `ipv4` (a device job running or queued for it).
pub fn scanning(status: Option<&StatusView>, ipv4: Option<&str>) -> bool {
    let (Some(s), Some(ip)) = (status, ipv4) else {
        return false;
    };
    let running = s
        .running
        .as_ref()
        .is_some_and(|r| r.kind == JobKind::Device && r.target == ip);
    running
        || s.queue
            .iter()
            .any(|q| q.kind == JobKind::Device && q.target == ip)
}

/// The running job's progress in words: `12 of 254 alive · address 3 of 12 · 4100 TCP
/// and 31 UDP probes` for a range, `4100 TCP and 31 UDP probes` for a device.
pub fn progress_text(p: &JobProgress) -> String {
    let probes = format!("{} TCP and {} UDP probes", p.tcp_done, p.udp_done);
    if p.kind == JobKind::Device {
        return probes;
    }
    let size = sensr_scan::target::parse(&p.target)
        .map(|t| sensr_scan::target::addresses(&t, &[]).count())
        .unwrap_or(p.address_total as usize);
    match p.alive {
        None => format!("finding live hosts among {size} addresses"),
        Some(a) => format!(
            "{a} of {size} alive · address {} of {} · {probes}",
            p.address_n, p.address_total
        ),
    }
}

#[cfg(feature = "ssr")]
pub use server::*;

#[cfg(feature = "ssr")]
mod server {
    use super::*;
    use sensr_scan::store::Store;
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    /// Scans of one device on its host page.
    pub const HISTORY: u32 = 10;
    /// Range scans on the Port Scanner page.
    pub const RANGES: u32 = 20;
    /// How long [`latest`] reuses its reads while the daemon's jobs stay the same: the
    /// Hosts card polls every few seconds.
    pub const CACHE_SECS: i64 = 20;

    fn msg(e: impl std::fmt::Display) -> String {
        e.to_string()
    }

    /// The database in `dir`, or `None` while the scanner has never run.
    fn store(dir: &Path) -> Result<Option<Store>, String> {
        let p = dir.join(sensr_scan::config::DB);
        if !p.exists() {
            return Ok(None);
        }
        Store::open_ro(&p).map(Some).map_err(msg)
    }

    /// The jobs the daemon has running and queued: when they change, a scan ended.
    pub fn jobs_key(status: Option<&StatusView>) -> Vec<u64> {
        status.map_or_else(Vec::new, |s| {
            s.running
                .iter()
                .map(|r| r.job_id)
                .chain(s.queue.iter().map(|q| q.job_id))
                .collect()
        })
    }

    type Latest = BTreeMap<String, HostPorts>;
    type LatestCache = Option<(PathBuf, i64, Vec<u64>, Vec<String>, Latest)>;
    static LATEST: Mutex<LatestCache> = Mutex::new(None);

    /// The latest scan of each of `macs` (lowercase) that has one. Reused for
    /// [`CACHE_SECS`] while `jobs` (see [`jobs_key`]) is unchanged; a read that fails is
    /// logged and not cached, and the last good read of `dir` is returned.
    pub fn latest(dir: &Path, macs: &[String], jobs: &[u64], now: i64) -> Latest {
        {
            let c = LATEST.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((d, at, j, m, v)) = &*c
                && d == dir
                && j == jobs
                && m == macs
                && (0..CACHE_SECS).contains(&(now - at))
            {
                return v.clone();
            }
        }
        match read_latest(dir, macs) {
            Ok(v) => {
                *LATEST.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some((dir.to_owned(), now, jobs.to_vec(), macs.to_vec(), v.clone()));
                v
            }
            Err(e) => {
                tracing::warn!("port scan read failed: {e}");
                let c = LATEST.lock().unwrap_or_else(|e| e.into_inner());
                match &*c {
                    Some((d, _, _, _, v)) if d == dir => v.clone(),
                    _ => Latest::new(),
                }
            }
        }
    }

    fn read_latest(dir: &Path, macs: &[String]) -> Result<Latest, String> {
        let Some(s) = store(dir)? else {
            return Ok(Latest::new());
        };
        let mut out = Latest::new();
        for mac in macs {
            if let Some(scan) = s.latest_for_mac(mac).map_err(msg)? {
                let changes = s.changes(scan.id).map_err(msg)?;
                out.insert(mac.clone(), host_ports(&scan, &changes));
            }
        }
        Ok(out)
    }

    /// Sets `ports` on every host with a MAC: its latest scan (empty when never scanned)
    /// and whether one is running.
    pub fn apply(
        hosts: &mut [crate::runtime::HostRow],
        latest: &Latest,
        status: Option<&StatusView>,
    ) {
        for h in hosts {
            let Some(mac) = h
                .mac
                .as_deref()
                .filter(|_| !h.key.starts_with("id:"))
                .map(str::to_ascii_lowercase)
            else {
                continue;
            };
            let mut p = latest.get(&mac).cloned().unwrap_or_default();
            p.scanning = scanning(status, h.ipv4.as_deref());
            h.ports = Some(p);
        }
    }

    /// A device's host page section: its latest scan's ports and its history.
    ///
    /// # Errors
    /// The database could not be read.
    pub fn detail(dir: &Path, mac: &str) -> Result<HostPortsDetail, String> {
        let Some(s) = store(dir)? else {
            return Ok(HostPortsDetail::default());
        };
        let history = s.history(mac, HISTORY).map_err(msg)?;
        let mut out = HostPortsDetail {
            ports: history
                .first()
                .map(|l| sorted(&l.ports))
                .unwrap_or_default(),
            ..HostPortsDetail::default()
        };
        for scan in &history {
            let changes = s.changes(scan.id).map_err(msg)?;
            out.history.push(HistoryEntry {
                finished: scan.finished,
                status: scan.status.as_str().to_owned(),
                address: scan.address.to_string(),
                open: u32::try_from(
                    scan.ports
                        .iter()
                        .filter(|p| p.state == PortState::Open)
                        .count(),
                )
                .unwrap_or(u32::MAX),
                changes: change_text(&changes),
            });
        }
        Ok(out)
    }

    /// The newest [`RANGES`] range scans with each address's open ports.
    ///
    /// # Errors
    /// The database could not be read.
    pub fn ranges(dir: &Path) -> Result<Vec<RangeJob>, String> {
        let Some(s) = store(dir)? else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for job in s.jobs(JobKind::Range, RANGES).map_err(msg)? {
            let scans = s
                .job(job.id)
                .map_err(msg)?
                .map(|(_, v)| v)
                .unwrap_or_default();
            let results = scans
                .iter()
                .map(|sc| RangeResult {
                    address: sc.address.to_string(),
                    open: sorted(&sc.ports)
                        .iter()
                        .filter(|p| matches!(p.state, PortState::Open | PortState::OpenFiltered))
                        .map(chip)
                        .collect(),
                })
                .collect();
            out.push(RangeJob::of(&job, results));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensr_scan::proto::QueuedJob;
    use sensr_scan::types::{ScanStatus, TlsInfo};

    fn row(proto: Proto, port: u16, state: PortState, ident: Ident) -> PortRow {
        PortRow {
            proto,
            port,
            state,
            service: Some("svc".into()),
            ident,
        }
    }

    fn scan(ports: Vec<PortRow>, status: ScanStatus) -> ScanView {
        ScanView {
            id: 1,
            job_id: 1,
            address: "192.168.1.5".parse().unwrap(),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            started: 0,
            finished: 1_795_608_000,
            status,
            all_open: false,
            ports,
        }
    }

    #[test]
    fn said_joins_what_the_service_told() {
        let i = Ident {
            product: Some("nginx".into()),
            version: Some("1.27".into()),
            title: Some("NAS".into()),
            banner: Some("hello".into()),
            tls: Some(TlsInfo {
                subject: "CN=nas".into(),
                sans: vec![],
                issuer: "CN=ca".into(),
                not_after: 1_795_608_000,
            }),
        };
        assert_eq!(
            said(&i),
            r#"nginx 1.27 · "NAS" · hello · certificate CN=nas, expires 2026-11-25"#
        );
        assert_eq!(said(&Ident::default()), "");
    }

    #[test]
    fn chips_label_and_grey() {
        let c = chip(&row(
            Proto::Tcp,
            80,
            PortState::Open,
            Ident {
                product: Some("lighttpd".into()),
                ..Ident::default()
            },
        ));
        assert_eq!(c.text(), r#"80 svc "lighttpd""#);
        let c = chip(&row(
            Proto::Udp,
            161,
            PortState::OpenFiltered,
            Ident::default(),
        ));
        assert!(c.open_filtered);
        assert_eq!(c.text(), "161/udp svc");
        assert_eq!(c.tip, OPEN_FILTERED_TIP);
    }

    #[test]
    fn host_ports_shows_eight_and_moves_new_ports_to_changes() {
        let mut ports: Vec<PortRow> = (1..=11)
            .map(|p| row(Proto::Tcp, 100 - p, PortState::Open, Ident::default()))
            .collect();
        ports.push(row(Proto::Udp, 53, PortState::Open, Ident::default()));
        ports.push(row(Proto::Tcp, 9, PortState::Closed, Ident::default()));
        let changes = Changes {
            opened: vec![(Proto::Tcp, 99), (Proto::Udp, 53)],
            closed: vec![(Proto::Tcp, 22)],
            changed: vec![(Proto::Tcp, 98)],
        };
        let h = host_ports(&scan(ports, ScanStatus::Complete), &changes);
        // 11 open TCP + 1 UDP, two new: 10 shown as chips, sorted, the first 8 kept
        assert_eq!(h.open.len(), 8);
        assert_eq!(h.more, 2);
        assert_eq!(h.open[0].port, 89);
        assert!(h.open.iter().all(|c| c.port != 99));
        assert_eq!(
            h.changes,
            ["+99 new", "+53/udp new", "-22 closed", "98 changed"]
        );
        assert_eq!(h.scanned_at, Some(1_795_608_000));
        assert_eq!(h.status_note(), None);
        let failed = host_ports(&scan(vec![], ScanStatus::Failed), &Changes::default());
        assert_eq!(failed.status_note(), Some("no response"));
        let partial = host_ports(&scan(vec![], ScanStatus::Partial), &Changes::default());
        assert_eq!(partial.status_note(), Some("partial scan"));
        assert!(!partial.is_empty() && HostPorts::default().is_empty());
    }

    #[test]
    fn scanning_matches_device_jobs_by_address() {
        let s = StatusView {
            running: None,
            queue: vec![
                QueuedJob {
                    job_id: 1,
                    kind: JobKind::Device,
                    target: "192.168.1.5".into(),
                },
                QueuedJob {
                    job_id: 2,
                    kind: JobKind::Range,
                    target: "192.168.1.6".into(),
                },
            ],
        };
        assert!(scanning(Some(&s), Some("192.168.1.5")));
        assert!(!scanning(Some(&s), Some("192.168.1.6")));
        assert!(!scanning(None, Some("192.168.1.5")));
        assert!(!scanning(Some(&s), None));
        assert_eq!(jobs_key(Some(&s)), [1, 2]);
    }

    #[test]
    fn progress_reads_as_words() {
        let mut p = JobProgress {
            job_id: 1,
            kind: JobKind::Range,
            target: "192.168.1.0/24".into(),
            alive: None,
            address_n: 0,
            address_total: 254,
            tcp_done: 0,
            udp_done: 0,
        };
        assert_eq!(progress_text(&p), "finding live hosts among 254 addresses");
        p.alive = Some(12);
        p.address_n = 3;
        p.address_total = 12;
        p.tcp_done = 41;
        p.udp_done = 3;
        assert_eq!(
            progress_text(&p),
            "12 of 254 alive · address 3 of 12 · 41 TCP and 3 UDP probes"
        );
        p.kind = JobKind::Device;
        assert_eq!(progress_text(&p), "41 TCP and 3 UDP probes");
    }

    #[test]
    fn day_format() {
        assert_eq!(crate::runtime::fmt_day(1_795_608_000), "Nov 25");
        assert_eq!(crate::runtime::fmt_day(0), "Jan 1");
    }

    #[test]
    fn latest_is_cached_until_jobs_change() {
        use sensr_scan::store::Store;
        let d = tempfile::tempdir().unwrap();
        let macs = vec!["aa:bb:cc:dd:ee:ff".to_owned()];
        // no database yet: nothing scanned
        assert!(latest(d.path(), &macs, &[], 100).is_empty());
        let s = Store::open(&d.path().join(sensr_scan::config::DB)).unwrap();
        let write = |port| {
            let job = s
                .begin_job(JobKind::Device, "192.168.1.5", Some(&macs[0]), false, false)
                .unwrap();
            s.write_scan(
                job,
                "192.168.1.5".parse().unwrap(),
                Some(&macs[0]),
                port,
                port,
                ScanStatus::Complete,
                false,
                &[row(
                    Proto::Tcp,
                    u16::try_from(port).unwrap(),
                    PortState::Open,
                    Ident::default(),
                )],
            )
            .unwrap();
        };
        write(22);
        let first = latest(d.path(), &macs, &[7], 1_000);
        assert_eq!(first[&macs[0]].open[0].port, 22);
        write(80);
        // same jobs within the window: the cached read
        assert_eq!(latest(d.path(), &macs, &[7], 1_005), first);
        // a job ended: read again
        let next = latest(d.path(), &macs, &[], 1_006);
        assert_eq!(next[&macs[0]].changes, ["+80 new", "-22 closed"]);
        // and after the window
        write(443);
        let later = latest(d.path(), &macs, &[], 1_006 + CACHE_SECS);
        assert_eq!(later[&macs[0]].open.len(), 0);
        assert_eq!(later[&macs[0]].changes, ["+443 new", "-80 closed"]);
        // a database that cannot be read is not cached: the last good read stands
        let bad = tempfile::tempdir().unwrap();
        std::fs::write(bad.path().join(sensr_scan::config::DB), b"not a database").unwrap();
        assert!(latest(bad.path(), &macs, &[], 2_000).is_empty());
    }

    #[test]
    fn detail_lists_history_newest_first() {
        use sensr_scan::store::Store;
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            detail(d.path(), "aa:bb:cc:dd:ee:ff").unwrap(),
            HostPortsDetail::default()
        );
        let s = Store::open(&d.path().join(sensr_scan::config::DB)).unwrap();
        for (t, status) in [(10, ScanStatus::Complete), (20, ScanStatus::Partial)] {
            let job = s
                .begin_job(
                    JobKind::Device,
                    "192.168.1.5",
                    Some("aa:bb:cc:dd:ee:ff"),
                    false,
                    false,
                )
                .unwrap();
            s.write_scan(
                job,
                "192.168.1.5".parse().unwrap(),
                Some("aa:bb:cc:dd:ee:ff"),
                t,
                t,
                status,
                false,
                &[
                    row(Proto::Udp, 53, PortState::OpenFiltered, Ident::default()),
                    row(Proto::Tcp, 22, PortState::Open, Ident::default()),
                ],
            )
            .unwrap();
        }
        let v = detail(d.path(), "aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(v.history.len(), 2);
        assert_eq!(
            (v.history[0].finished, v.history[0].status.as_str()),
            (20, "partial")
        );
        assert_eq!(v.history[0].open, 1);
        // the latest scan's ports, open first
        assert_eq!(v.ports[0].port, 22);
        assert_eq!(v.ports[1].state, PortState::OpenFiltered);
    }
}
