//! Reads sensr-insight's databases for Reporting › Insight, the dashboard traffic graph and
//! Services › Intrusion Detection › Alerts.
//!
//! The databases belong to the daemon: they are opened read-only per request (the daemon may
//! create them at any time, and a read-only SQLite handle is cheap), and a missing file is
//! "no data yet", not an error.

use crate::api::{AlertPage, AlertRow, InsightReport, TrafficHistory, TrafficPoint, TrafficRow};
use sensr_flow::config::{ALERTS_DB, FLOWS_DB};
use sensr_flow::eve::{AlertFilter, AlertStore};
use sensr_flow::store::{FlowStore, MINUTE, Point, RowKind, SAMPLE, TopRow};
use std::path::Path;

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
