//! Reads sensr-insight's databases for Reporting › Insight, the dashboard traffic graph and
//! Services › Intrusion Detection › Alerts.
//!
//! The databases belong to the daemon: they are opened read-only per request (the daemon may
//! create them at any time, and a read-only SQLite handle is cheap), and a missing file is
//! "no data yet", not an error.

use crate::api::{
    ActivityCategory, ActivityCell, ActivityDomain, ActivityService, AlertPage, AlertRow,
    HostActivityView, InsightReport, TrafficHistory, TrafficPoint, TrafficRow,
};
use sensr_flow::config::{ALERTS_DB, CONFIG_PATH, Config, DnsStatus, FLOWS_DB};
use sensr_flow::eve::{AlertFilter, AlertStore};
use sensr_flow::services::{Catalogue, Category};
use sensr_flow::store::{
    ActivityRange, DOMAINS_PAGE, FlowStore, HostActivity, MINUTE, Point, RowKind, SAMPLE, TopRow,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

/// Rows per top list.
const TOP: u32 = 10;

/// Alerts per page.
pub const ALERTS_PER_PAGE: u32 = 25;

fn flows(dir: &Path) -> Option<FlowStore> {
    let p = dir.join(FLOWS_DB);
    if !p.exists() {
        return None;
    }
    FlowStore::open_read_only(&p).ok()
}

fn alert_db(dir: &Path) -> Option<AlertStore> {
    let p = dir.join(ALERTS_DB);
    if !p.exists() {
        return None;
    }
    AlertStore::open_read_only(&p).ok()
}

fn point(p: Point) -> TrafficPoint {
    TrafficPoint {
        ts: p.ts,
        res: p.res,
        up: p.up,
        down: p.down,
    }
}

/// A well-known name for an app key (`tcp/443` → `HTTPS`), empty when there is none.
pub fn service_name(key: &str) -> &'static str {
    match key {
        "tcp/22" => "SSH",
        "udp/53" | "tcp/53" => "DNS",
        "tcp/80" => "HTTP",
        "udp/123" => "NTP",
        "tcp/443" => "HTTPS",
        "udp/443" => "QUIC",
        "tcp/853" => "DNS over TLS",
        "tcp/993" => "IMAPS",
        "tcp/587" | "tcp/465" => "SMTP submission",
        "udp/3478" | "udp/19302" => "STUN",
        "tcp/8080" => "HTTP (alt)",
        "udp/51820" => "WireGuard",
        "tcp/25565" => "Minecraft",
        _ => "",
    }
}

fn row(t: TopRow, label: String) -> TrafficRow {
    TrafficRow {
        key: t.key,
        label,
        up: t.up,
        down: t.down,
        up_packets: t.up_packets,
        down_packets: t.down_packets,
    }
}

/// The report for `[to - span, to)`; with `host`, its own series and services.
///
/// `iface_label` names an interface id (`lan` → `LAN`).
pub fn report(
    dir: &Path,
    span: i64,
    to: i64,
    host: Option<&str>,
    iface_label: impl Fn(&str) -> String,
) -> Result<InsightReport, String> {
    let from = to - span;
    let Some(s) = flows(dir) else {
        return Ok(InsightReport {
            from,
            to,
            resolution: FlowStore::resolution(from, to),
            ..InsightReport::default()
        });
    };
    let e = |e: sensr_flow::store::Result<Vec<TopRow>>| e.map_err(|e| e.to_string());
    let plain = |rows: Vec<TopRow>| {
        rows.into_iter()
            .map(|t| row(t, String::new()))
            .collect::<Vec<_>>()
    };
    let apps = e(s.top(RowKind::App, host, from, to, TOP))?
        .into_iter()
        .map(|t| {
            let name = service_name(&t.key).to_owned();
            row(t, name)
        })
        .collect();
    let ifaces = e(s.top(RowKind::Iface, None, from, to, TOP))?
        .into_iter()
        .map(|t| {
            let name = iface_label(&t.key);
            row(t, name)
        })
        .collect();
    // Without a host, the series is every local host together: interfaces would count
    // forwarded traffic once per interface it crosses.
    let series = s
        .series(RowKind::Host, host, from, to, None)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(point)
        .collect();
    Ok(InsightReport {
        available: true,
        from,
        to,
        resolution: FlowStore::resolution(from, to),
        hosts: plain(e(s.top(RowKind::Host, None, from, to, TOP))?),
        apps,
        remotes: plain(e(s.top(RowKind::Remote, None, from, to, TOP))?),
        ifaces,
        series,
    })
}

/// The dashboard graph: every interface summed, live samples and the last hour.
pub fn history(dir: &Path, now: i64) -> Option<TrafficHistory> {
    let s = flows(dir)?;
    let live = s
        .series(RowKind::Iface, None, now - 600, now, Some(SAMPLE))
        .ok()?;
    let hour = s
        .series(RowKind::Iface, None, now - 3600, now, Some(MINUTE))
        .ok()?;
    Some(TrafficHistory {
        live: live.into_iter().map(point).collect(),
        hour: hour.into_iter().map(point).collect(),
    })
}

/// A page of alerts. `text` is a signature id when it is a number, else part of the
/// signature message; `host` matches the source or destination address.
pub fn alerts(dir: &Path, text: &str, host: &str, page: u32) -> Result<AlertPage, String> {
    let Some(s) = alert_db(dir) else {
        return Ok(AlertPage {
            per_page: ALERTS_PER_PAGE,
            ..AlertPage::default()
        });
    };
    let text = text.trim();
    let host = host.trim();
    let sid = text.parse::<u32>().ok();
    let f = AlertFilter {
        sid,
        text: (sid.is_none() && !text.is_empty()).then(|| text.to_owned()),
        host: (!host.is_empty()).then(|| host.to_owned()),
        since: None,
        until: None,
        limit: ALERTS_PER_PAGE,
        offset: page.saturating_mul(ALERTS_PER_PAGE),
    };
    let (rows, total) = s.list(&f).map_err(|e| e.to_string())?;
    Ok(AlertPage {
        available: true,
        rows: rows
            .into_iter()
            .map(|a| AlertRow {
                id: a.id,
                ts: a.ts,
                gid: a.gid,
                sid: a.sid,
                signature: a.signature,
                category: a.category,
                severity: a.severity,
                action: a.action,
                proto: a.proto,
                src_ip: a.src_ip,
                src_port: a.src_port,
                dest_ip: a.dest_ip,
                dest_port: a.dest_port,
                iface: a.iface,
                suppressed: false,
            })
            .collect(),
        total,
        page,
        per_page: ALERTS_PER_PAGE,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("sensr-ui-insight-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn missing_databases_are_not_errors() {
        let d = dir("missing");
        let r = report(&d, 7200, 1_000_000, None, str::to_owned).unwrap();
        assert!(!r.available);
        assert!(history(&d, 1_000_000).is_none());
        let a = alerts(&d, "", "", 0).unwrap();
        assert!(!a.available);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn reads_the_seeded_fixture() {
        let d = dir("seeded");
        let now = 1_794_787_200;
        crate::mock::seed_insight(&d, now).unwrap();
        let r = report(&d, 7200, now, None, str::to_uppercase).unwrap();
        assert!(r.available);
        assert_eq!(r.hosts[0].key, "192.168.1.20", "{:?}", r.hosts);
        assert!(r.ifaces.iter().any(|i| i.label == "WAN"));
        assert!(r.apps.iter().any(|a| a.label == "HTTPS"));
        assert!(!r.series.is_empty() && r.series.iter().all(|p| p.res == 60));
        let host = report(&d, 86_400, now, Some("192.168.1.100"), str::to_owned).unwrap();
        assert!(host.series.iter().all(|p| p.res == 3600));
        assert!(host.apps.len() < r.apps.len() || !host.apps.is_empty());
        let year = report(&d, 365 * 86_400, now, None, str::to_owned).unwrap();
        assert!(year.series.len() > 100, "{}", year.series.len());

        let h = history(&d, now).unwrap();
        assert!(h.live.len() >= 50 && h.live.iter().all(|p| p.res == 10));
        assert!(h.hour.len() >= 55 && h.hour.iter().all(|p| p.res == 60));

        let all = alerts(&d, "", "", 0).unwrap();
        assert!(all.total > u64::from(ALERTS_PER_PAGE));
        assert_eq!(all.rows.len(), ALERTS_PER_PAGE as usize);
        assert!(all.rows.windows(2).all(|w| w[0].ts >= w[1].ts));
        let scan = alerts(&d, "ssh scan", "", 0).unwrap();
        assert!(scan.total > 0 && scan.rows.iter().all(|a| a.signature.contains("SSH Scan")));
        let by_sid = alerts(&d, &scan.rows[0].sid.to_string(), "", 0).unwrap();
        assert_eq!(by_sid.total, scan.total);
        let by_host = alerts(&d, "", "192.168.1.101", 0).unwrap();
        assert!(by_host.total > 0);
        assert!(
            by_host
                .rows
                .iter()
                .all(|a| a.src_ip == "192.168.1.101" || a.dest_ip == "192.168.1.101")
        );
        let last = alerts(
            &d,
            "",
            "",
            u32::try_from(all.total).unwrap() / ALERTS_PER_PAGE,
        )
        .unwrap();
        assert!(!last.rows.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// Why a host activity request failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivityError {
    /// The range is not `today` or `7d`.
    BadRange,
    /// The MAC is not in the host inventory.
    UnknownHost,
    /// The database could not be read.
    Failed(String),
}

/// The category's key (`ads_tracking`), as in [`crate::runtime::CATEGORIES`].
fn category_key(c: Category) -> String {
    serde_json::to_value(c)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "other".into())
}

/// The catalogue the daemon attributes with: the built-in one plus the enabled overrides in
/// the configuration the agent rendered for it (`SENSR_INSIGHT_CONFIG` overrides the path).
/// Unreadable configuration means the built-in catalogue.
pub fn catalogue() -> Catalogue {
    let path = std::env::var_os("SENSR_INSIGHT_CONFIG")
        .map_or_else(|| Path::new(CONFIG_PATH).to_owned(), Into::into);
    let overrides = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<Config>(&b).ok())
        .and_then(|c| c.flows)
        .and_then(|f| f.dns)
        .map(|d| d.service_overrides)
        .unwrap_or_default();
    Catalogue::builtin().with_overrides(&overrides)
}

/// Whether a store error only says the activity tables do not exist yet (a database from
/// before per-host DNS activity).
fn no_table(e: &impl std::fmt::Display) -> bool {
    e.to_string().contains("no such table")
}

static OFFSET: Mutex<Option<(i64, i64)>> = Mutex::new(None);

/// The router's local time minus UTC in seconds, from `date +%z` (so the system timezone
/// and its daylight saving apply); 0 when that does not work. Cached for ten minutes.
pub fn local_offset(now: i64) -> i64 {
    let mut c = OFFSET.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, off)) = *c
        && (0..600).contains(&(now - at))
    {
        return off;
    }
    let off = std::process::Command::new("date")
        .arg("+%z")
        .output()
        .ok()
        .and_then(|o| parse_offset(String::from_utf8_lossy(&o.stdout).trim()))
        .unwrap_or(0);
    *c = Some((now, off));
    off
}

/// `+0530` as seconds.
fn parse_offset(z: &str) -> Option<i64> {
    let (sign, rest) = match z.as_bytes().first()? {
        b'+' => (1, &z[1..]),
        b'-' => (-1, &z[1..]),
        _ => return None,
    };
    if rest.len() != 4 || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let h: i64 = rest[..2].parse().ok()?;
    let m: i64 = rest[2..].parse().ok()?;
    Some(sign * (h * 3600 + m * 60))
}

fn view_of(a: HostActivity) -> HostActivityView {
    HostActivityView {
        screen_time: a.screen_time,
        services: a
            .services
            .into_iter()
            .map(|s| ActivityService {
                service: s.service,
                category: category_key(s.category),
                minutes: s.minutes,
            })
            .collect(),
        categories: a
            .categories
            .into_iter()
            .map(|c| ActivityCategory {
                category: category_key(c.category),
                minutes: c.minutes,
            })
            .collect(),
        timeline: a
            .timeline
            .into_iter()
            .map(|c| ActivityCell {
                day: c.day,
                hour: c.hour,
                minutes: c.minutes,
            })
            .collect(),
        domains: a
            .domains
            .into_iter()
            .map(|d| ActivityDomain {
                qname: d.qname,
                count: d.count,
                first_seen: d.first_seen,
                last_seen: d.last_seen,
                service: d.service,
                category: category_key(d.category),
                new: d.new,
                blocked: d.blocked,
            })
            .collect(),
        domains_total: a.domains_total,
        ..HostActivityView::default()
    }
}

/// One device's DNS activity page. `hosts` is the agent's host inventory (the header comes
/// from it); `range` is `today` or `7d`; days and hours are in `utc_offset`.
pub fn host_activity(
    dir: &Path,
    hosts: serde_json::Value,
    mac: &str,
    range: &str,
    page: u32,
    now: i64,
    utc_offset: i64,
) -> Result<HostActivityView, ActivityError> {
    let r = match range {
        "today" => ActivityRange::today(now, utc_offset),
        "7d" => ActivityRange::week(now, utc_offset),
        _ => return Err(ActivityError::BadRange),
    };
    let mac = mac.trim().to_ascii_lowercase();
    let list: crate::runtime::HostList = crate::runtime::parse(hosts);
    let host = list
        .hosts
        .into_iter()
        .find(|h| {
            h.mac
                .as_deref()
                .is_some_and(|m| m.eq_ignore_ascii_case(&mac))
        })
        .ok_or(ActivityError::UnknownHost)?;
    let mut v = HostActivityView {
        mac,
        name: host.name,
        label: host.host_label,
        ipv4: host.ipv4,
        ipv6: host.ipv6,
        mode: host.mode,
        last_seen: host.last_seen,
        online: host.online,
        range: range.to_owned(),
        from: r.from,
        to: r.to,
        utc_offset,
        page,
        per_page: DOMAINS_PAGE,
        ..HostActivityView::default()
    };
    let status = DnsStatus::read(dir);
    v.feed_stale = status.dns_feed_stale;
    v.last_frame = status.last_frame;
    let Some(s) = flows(dir) else {
        return Ok(v);
    };
    match s.host_activity(&v.mac, &r, page, &catalogue()) {
        Ok(a) => {
            v.available = true;
            Ok(HostActivityView {
                mac: v.mac,
                name: v.name,
                label: v.label,
                ipv4: v.ipv4,
                ipv6: v.ipv6,
                mode: v.mode,
                last_seen: v.last_seen,
                online: v.online,
                range: v.range,
                from: v.from,
                to: v.to,
                utc_offset,
                available: true,
                feed_stale: v.feed_stale,
                last_frame: v.last_frame,
                page,
                per_page: DOMAINS_PAGE,
                ..view_of(a)
            })
        }
        Err(e) if no_table(&e) => Ok(v),
        Err(e) => Err(ActivityError::Failed(e.to_string())),
    }
}

/// Each device's screen time today and DNS mix over 24 hours: the Hosts card's figures.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostMix {
    /// Screen-time minutes since local midnight, by MAC.
    pub today: BTreeMap<String, u32>,
    /// Lookups per category key over 24 hours, by MAC (category order).
    pub mix: BTreeMap<String, Vec<(String, u32)>>,
}

/// How long [`host_mix`] reuses a scan: the dashboard polls the hosts view every few seconds
/// and each scan reads 24 hours of rows.
pub const MIX_CACHE_SECS: i64 = 45;

type MixCache = Option<(std::path::PathBuf, i64, HostMix)>;
static MIX: Mutex<MixCache> = Mutex::new(None);

/// [`HostMix`] from the database in `dir` (empty when there is none, or it predates
/// per-host DNS activity), reused for [`MIX_CACHE_SECS`].
pub fn host_mix(dir: &Path, now: i64) -> HostMix {
    {
        let c = MIX.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((d, at, m)) = &*c
            && d == dir
            && (0..MIX_CACHE_SECS).contains(&(now - at))
        {
            return m.clone();
        }
    }
    let m = scan_mix(dir, now);
    *MIX.lock().unwrap_or_else(|e| e.into_inner()) = Some((dir.to_owned(), now, m.clone()));
    m
}

fn scan_mix(dir: &Path, now: i64) -> HostMix {
    let Some(s) = flows(dir) else {
        return HostMix::default();
    };
    let cat = catalogue();
    let since = ActivityRange::today(now, local_offset(now)).from;
    let today = s.today_minutes(since, &cat).unwrap_or_default();
    let mix = s
        .dns_mix_24h(now, &cat)
        .unwrap_or_default()
        .into_iter()
        .map(|(h, v)| {
            (
                h,
                v.into_iter().map(|(c, n)| (category_key(c), n)).collect(),
            )
        })
        .collect();
    HostMix { today, mix }
}

/// Fills `today_minutes` and `dns_mix` of the rows that have data.
pub fn apply_mix(hosts: &mut [crate::runtime::HostRow], m: &HostMix) {
    for h in hosts {
        let Some(mac) = h.mac.as_deref().map(str::to_ascii_lowercase) else {
            continue;
        };
        if let Some(t) = m.today.get(&mac) {
            h.today_minutes = Some(*t);
        }
        if let Some(v) = m.mix.get(&mac) {
            h.dns_mix.clone_from(v);
        }
    }
}

#[cfg(test)]
mod activity_tests {
    use super::*;
    use sensr_flow::attrib::{HostMinute, MinuteResult};
    use serde_json::json;

    const MAC: &str = "aa:bb:cc:00:00:09";

    fn hosts() -> serde_json::Value {
        json!({"now": 0, "hosts": [{"key": MAC, "mac": MAC, "name": "kid-tablet",
            "ipv4": "192.168.1.50", "online": true, "last_seen": 10}]})
    }

    #[test]
    fn offsets_parse() {
        assert_eq!(parse_offset("+0530"), Some(19_800));
        assert_eq!(parse_offset("-0800"), Some(-28_800));
        assert_eq!(parse_offset("0100"), None);
        assert_eq!(parse_offset("+01"), None);
    }

    #[test]
    fn range_and_host_are_checked() {
        let d = tempfile::tempdir().unwrap();
        let e = |r: &str, m: &str| host_activity(d.path(), hosts(), m, r, 0, 100_000, 0);
        assert_eq!(e("1y", MAC), Err(ActivityError::BadRange));
        assert_eq!(
            e("today", "00:00:00:00:00:00"),
            Err(ActivityError::UnknownHost)
        );
        let v = e("today", &MAC.to_uppercase()).unwrap();
        assert_eq!(
            (v.name.as_deref(), v.available),
            (Some("kid-tablet"), false)
        );
    }

    #[test]
    fn reads_activity_and_status_and_caches_the_mix() {
        let d = tempfile::tempdir().unwrap();
        let now = 1_700_000_000;
        let mut s = sensr_flow::store::FlowStore::open(&d.path().join(FLOWS_DB)).unwrap();
        for m in 0..5 {
            let mut r = MinuteResult::default();
            r.per_host.insert(
                MAC.into(),
                HostMinute {
                    services_active: ["YouTube".to_owned()].into(),
                    queries: vec![("www.youtube.com".into(), 3, false)],
                    ..HostMinute::default()
                },
            );
            s.write_activity_minute(now - 600 + m * 60, &r).unwrap();
        }
        std::fs::write(
            d.path().join(sensr_flow::config::DNS_STATUS),
            r#"{"dns_feed_stale":true,"last_frame":42}"#,
        )
        .unwrap();
        let v = host_activity(d.path(), hosts(), MAC, "7d", 0, now, 0).unwrap();
        assert!(v.available && v.feed_stale);
        assert_eq!(v.last_frame, Some(42));
        assert_eq!(v.services[0].service, "YouTube");
        assert_eq!(v.services[0].category, "video");
        assert_eq!(v.domains[0].count, 15);
        assert_eq!(v.per_page, DOMAINS_PAGE);

        let m = host_mix(d.path(), now);
        assert_eq!(m.mix[MAC], vec![("video".to_owned(), 15)]);
        // within the cache window a later scan is not made: new rows stay unseen
        let mut r = MinuteResult::default();
        r.per_host.insert(
            MAC.into(),
            HostMinute {
                queries: vec![("roblox.com".into(), 9, false)],
                ..HostMinute::default()
            },
        );
        s.write_activity_minute(now - 30, &r).unwrap();
        assert_eq!(host_mix(d.path(), now + 10), m);
        assert_ne!(host_mix(d.path(), now + MIX_CACHE_SECS + 1), m);
    }
}
