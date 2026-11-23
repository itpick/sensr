//! Reporting › Insight and IDS alerts: read-only queries on the databases
//! `sensr-insight` writes (`/var/lib/sensr-insight`, group `sensr`). The
//! API never writes them; suppressing an alert is a config change
//! (`ids.suppressions`) through the normal config routes.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::Query;
use axum::http::StatusCode;
use sensr_flow::config::{ALERTS_DB, DB_DIR, FLOWS_DB};
use sensr_flow::eve::{AlertFilter, AlertStore};
use sensr_flow::store::{FlowStore, RowKind};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::ApiError;

type ApiResult = Result<Json<Value>, ApiError>;

#[cfg(test)]
static TEST_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

pub(crate) fn dir() -> PathBuf {
    #[cfg(test)]
    if let Some(d) = TEST_DIR.get() {
        return d.clone();
    }
    std::env::var_os("SENSR_INSIGHT_DIR").map_or_else(|| PathBuf::from(DB_DIR), PathBuf::from)
}

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, msg)
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

async fn blocking<F>(f: F) -> ApiResult
where
    F: FnOnce() -> Result<Value, ApiError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(internal)?
        .map(Json)
}

fn kind(s: Option<&str>) -> Result<RowKind, ApiError> {
    Ok(match s.unwrap_or("host") {
        "host" => RowKind::Host,
        "app" => RowKind::App,
        "remote" => RowKind::Remote,
        "iface" => RowKind::Iface,
        other => return Err(bad(format!("unknown kind {other:?}"))),
    })
}

/// Time range and filters of traffic queries (Unix seconds).
#[derive(Debug, Default, Deserialize)]
pub struct TrafficQuery {
    kind: Option<String>,
    key: Option<String>,
    host: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
    limit: Option<u32>,
    res: Option<i64>,
}

impl TrafficQuery {
    fn range(&self) -> Result<(i64, i64), ApiError> {
        let to = self.to.unwrap_or_else(now);
        let from = self.from.unwrap_or(to - 3600);
        if from >= to {
            return Err(bad("from must be before to"));
        }
        Ok((from, to))
    }
}

fn flows() -> Option<FlowStore> {
    let p = dir().join(FLOWS_DB);
    p.exists().then(|| FlowStore::open_read_only(&p).ok())?
}

/// `GET /api/v1/insight/top`: the largest hosts, services (`kind=app`,
/// optionally `host=`), remotes or interfaces in a range.
pub async fn top(Query(q): Query<TrafficQuery>) -> ApiResult {
    let k = kind(q.kind.as_deref())?;
    let (from, to) = q.range()?;
    blocking(move || {
        let Some(s) = flows() else {
            return Ok(json!({ "available": false, "rows": [] }));
        };
        let rows = s
            .top(
                k,
                q.host.as_deref(),
                from,
                to,
                q.limit.unwrap_or(25).clamp(1, 1000),
            )
            .map_err(internal)?;
        Ok(json!({
            "available": true, "from": from, "to": to,
            "resolution": FlowStore::resolution(from, to), "rows": rows
        }))
    })
    .await
}

/// `GET /api/v1/insight/series`: bytes per bucket for one row (`key`) or a
/// whole kind (all interfaces: the dashboard graph). `res=10` gives the
/// last hour of interface samples.
pub async fn series(Query(q): Query<TrafficQuery>) -> ApiResult {
    let k = kind(q.kind.as_deref().or(Some("iface")))?;
    let (from, to) = q.range()?;
    if let Some(r) = q.res
        && ![10, 60, 3600, 86400].contains(&r)
    {
        return Err(bad("res is 10, 60, 3600 or 86400"));
    }
    blocking(move || {
        let Some(s) = flows() else {
            return Ok(json!({ "available": false, "points": [] }));
        };
        let points = s
            .series(k, q.key.as_deref(), from, to, q.res)
            .map_err(internal)?;
        Ok(json!({ "available": true, "from": from, "to": to, "points": points }))
    })
    .await
}

/// Alert filters (Unix milliseconds).
#[derive(Debug, Default, Deserialize)]
pub struct AlertQuery {
    sid: Option<u32>,
    text: Option<String>,
    host: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
    limit: Option<u32>,
    offset: Option<u32>,
}

impl AlertQuery {
    fn filter(self) -> AlertFilter {
        AlertFilter {
            sid: self.sid,
            text: self.text.filter(|t| !t.is_empty()),
            host: self.host.filter(|h| !h.is_empty()),
            since: self.since,
            until: self.until,
            limit: self.limit.unwrap_or(100),
            offset: self.offset.unwrap_or(0),
        }
    }
}

fn alerts_db() -> Option<AlertStore> {
    let p = dir().join(ALERTS_DB);
    p.exists().then(|| AlertStore::open_read_only(&p).ok())?
}

/// `GET /api/v1/ids/alerts`: newest first, filtered by signature id, text
/// or host.
pub async fn alerts(Query(q): Query<AlertQuery>) -> ApiResult {
    let f = q.filter();
    blocking(move || {
        let Some(s) = alerts_db() else {
            return Ok(json!({ "available": false, "rows": [], "total": 0 }));
        };
        let (rows, total) = s.list(&f).map_err(internal)?;
        Ok(json!({ "available": true, "rows": rows, "total": total }))
    })
    .await
}

/// `GET /api/v1/ids/signatures`: the most frequent signatures.
pub async fn signatures(Query(q): Query<AlertQuery>) -> ApiResult {
    let f = q.filter();
    blocking(move || {
        let Some(s) = alerts_db() else {
            return Ok(json!({ "available": false, "rows": [] }));
        };
        Ok(json!({ "available": true, "rows": s.top_signatures(&f).map_err(internal)? }))
    })
    .await
}

/// `GET /api/v1/ids/stats`: Suricata's latest counters.
pub async fn stats() -> ApiResult {
    blocking(|| {
        let stats = alerts_db()
            .and_then(|s| s.stats().ok().flatten())
            .and_then(|s| serde_json::from_str::<Value>(&s).ok());
        Ok(json!({ "available": stats.is_some(), "stats": stats }))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensr_flow::nft::{Count, Dir, Key, Kind};
    use sensr_flow::store::Batch;

    #[tokio::test]
    async fn queries_read_the_daemons_databases() {
        let d = tempfile::tempdir().unwrap();
        TEST_DIR.set(d.path().to_owned()).unwrap();
        let r = top(Query(TrafficQuery::default())).await.unwrap();
        assert_eq!(r.0["available"], false);
        let mut s = FlowStore::open(&d.path().join(FLOWS_DB)).unwrap();
        let mut b = Batch::default();
        b.add_counters(&[(
            Key::addr(Kind::Host, Dir::Down, "192.168.1.100".parse().unwrap()),
            Count {
                packets: 1,
                bytes: 4096,
            },
        )]);
        let t = now() - 30;
        s.write_minute(t, &b).unwrap();
        let r = top(Query(TrafficQuery::default())).await.unwrap();
        assert_eq!(r.0["rows"][0]["key"], "192.168.1.100");
        assert_eq!(r.0["rows"][0]["down"], 4096);
        let bad_kind = top(Query(TrafficQuery {
            kind: Some("nope".into()),
            ..TrafficQuery::default()
        }))
        .await;
        assert!(bad_kind.is_err());
        let a = alerts(Query(AlertQuery::default())).await.unwrap();
        assert_eq!(a.0["total"], 0);
    }
}
