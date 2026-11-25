//! Services › Port Scanner: results are read straight from the database
//! `sensr-scan` writes (`/var/lib/sensr-scan`, group `sensr`); starting and
//! cancelling go through the daemon's control socket. The API never writes
//! the database.

use std::path::PathBuf;
use std::sync::OnceLock;

use axum::Json;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sensr_scan::client;
use sensr_scan::config::{DB, DB_DIR, SOCKET};
use sensr_scan::proto::{JobKind, Refusal, Reply, Request, StartReq};
use sensr_scan::store::Store;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::ApiError;

type ApiResult = Result<Json<Value>, ApiError>;

/// Jobs listed when `limit` is not given, and the most that can be asked for.
const DEFAULT_LIMIT: u32 = 50;
const MAX_LIMIT: u32 = 500;
/// Scans of one device returned with its latest result.
const HISTORY: u32 = 10;

static PATHS: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();

/// Point the API at another database directory and control socket, for tests
/// (which cannot set the environment). Only the first call has any effect;
/// returns whether it did.
#[doc(hidden)]
pub fn use_paths(dir: PathBuf, socket: PathBuf) -> bool {
    PATHS.set((dir, socket)).is_ok()
}

fn dir() -> PathBuf {
    if let Some((d, _)) = PATHS.get() {
        return d.clone();
    }
    std::env::var_os("SENSR_SCAN_DIR").map_or_else(|| PathBuf::from(DB_DIR), PathBuf::from)
}

fn socket() -> PathBuf {
    if let Some((_, s)) = PATHS.get() {
        return s.clone();
    }
    std::env::var_os("SENSR_SCAN_SOCKET").map_or_else(|| PathBuf::from(SOCKET), PathBuf::from)
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, msg)
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

async fn blocking<T, F>(f: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ApiError> + Send + 'static,
{
    tokio::task::spawn_blocking(f).await.map_err(internal)?
}

/// The database, or `None` while the scanner has never run.
fn store() -> Result<Option<Store>, ApiError> {
    let p = dir().join(DB);
    if !p.exists() {
        return Ok(None);
    }
    Store::open_ro(&p).map(Some).map_err(internal)
}

/// A MAC in the form the store keeps: six lowercase hex pairs, colon separated.
fn mac(s: &str) -> Result<String, ApiError> {
    let ok = s.split(':').count() == 6
        && s.split(':')
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()));
    if ok {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(bad(format!(
            "{s:?} is not a MAC address (aa:bb:cc:dd:ee:ff)"
        )))
    }
}

/// Ask the daemon; an unreachable socket is 503, not a server fault.
async fn ask(req: Request) -> Result<Reply, ApiError> {
    let sock = socket();
    let r = tokio::task::spawn_blocking(move || client::send(&sock, &req))
        .await
        .map_err(internal)?;
    r.map_err(|e| {
        use std::io::ErrorKind::{ConnectionRefused, NotFound, PermissionDenied};
        if matches!(e.kind(), NotFound | ConnectionRefused | PermissionDenied) {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "the port scanner is not running",
            )
        } else {
            tracing::error!(error = %e, "sensr-scan control socket failure");
            ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!("the port scanner did not answer: {e}"),
            )
        }
    })
}

fn unexpected(r: &Reply) -> ApiError {
    ApiError::new(
        StatusCode::BAD_GATEWAY,
        format!("unexpected reply from the port scanner: {r:?}"),
    )
}

/// `GET /api/v1/portscan/status`: what is running and queued.
pub async fn status() -> ApiResult {
    match ask(Request::Status).await? {
        Reply::Status(v) => Ok(Json(json!(v))),
        other => Err(unexpected(&other)),
    }
}

/// Query of `GET /api/v1/portscan/jobs`.
#[derive(Debug, Deserialize)]
pub struct JobsQuery {
    kind: Option<String>,
    limit: Option<u32>,
}

/// `GET /api/v1/portscan/jobs?kind=device|range&limit=`: newest first.
pub async fn jobs(Query(q): Query<JobsQuery>) -> ApiResult {
    let kind = match q.kind.as_deref() {
        Some("device") => JobKind::Device,
        Some("range") => JobKind::Range,
        other => return Err(bad(format!("kind is device or range, not {other:?}"))),
    };
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(bad(format!("limit is 1 to {MAX_LIMIT}")));
    }
    blocking(move || {
        let Some(s) = store()? else {
            return Ok(Json(json!([])));
        };
        Ok(Json(json!(s.jobs(kind, limit).map_err(internal)?)))
    })
    .await
}

/// `GET /api/v1/portscan/jobs/{id}`: one job and its scans.
pub async fn job(Path(id): Path<i64>) -> ApiResult {
    blocking(move || {
        let found = match store()? {
            Some(s) => s.job(id).map_err(internal)?,
            None => None,
        };
        let Some((job, scans)) = found else {
            return Err(ApiError::new(StatusCode::NOT_FOUND, "no such scan job"));
        };
        Ok(Json(json!({ "job": job, "scans": scans })))
    })
    .await
}

/// `GET /api/v1/portscan/hosts/{mac}`: the newest scan of a device, what it
/// changed since the one before, and recent history.
pub async fn host(Path(m): Path<String>) -> ApiResult {
    let m = mac(&m)?;
    blocking(move || {
        let Some(s) = store()? else {
            return Ok(Json(
                json!({"latest": null, "changes": null, "history": []}),
            ));
        };
        let latest = s.latest_for_mac(&m).map_err(internal)?;
        let changes = latest
            .as_ref()
            .map(|l| s.changes(l.id))
            .transpose()
            .map_err(internal)?;
        let history = s.history(&m, HISTORY).map_err(internal)?;
        Ok(Json(
            json!({"latest": latest, "changes": changes, "history": history}),
        ))
    })
    .await
}

/// Body of `POST /api/v1/portscan/start`. `auto` is the daemon's own and is
/// accepted but ignored.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartBody {
    target: String,
    kind: JobKind,
    #[serde(default)]
    #[allow(dead_code)]
    auto: bool,
    mac: Option<String>,
    #[serde(default)]
    public_ok: bool,
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    include_excluded: bool,
}

fn describe(r: &Refusal) -> String {
    match r {
        Refusal::Public => "the target is not local; confirm to scan it anyway".into(),
        Refusal::TooLarge { addresses, max } => {
            format!("{addresses} addresses is more than the {max} allowed")
        }
        Refusal::Excluded => "the target is on the exclude list".into(),
        Refusal::Invalid(why) => format!("the target is not valid: {why}"),
        Refusal::Disabled => "port scanning is disabled".into(),
    }
}

/// `POST /api/v1/portscan/start`: queue a scan. A refusal is 409 with its
/// reason.
pub async fn start(Json(b): Json<StartBody>) -> Result<Response, ApiError> {
    let mac = b.mac.as_deref().map(mac).transpose()?;
    let req = Request::Start(StartReq {
        target: b.target,
        kind: b.kind,
        auto: false,
        mac,
        public_ok: b.public_ok,
        confirm: b.confirm,
        include_excluded: b.include_excluded,
    });
    Ok(match ask(req).await? {
        Reply::Started { job_id } => Json(json!({ "job_id": job_id })).into_response(),
        Reply::Refused { reason } => (
            StatusCode::CONFLICT,
            Json(json!({ "error": describe(&reason), "reason": reason })),
        )
            .into_response(),
        other => return Err(unexpected(&other)),
    })
}

/// Body of `POST /api/v1/portscan/cancel`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelBody {
    job_id: u64,
}

/// `POST /api/v1/portscan/cancel`: stop a running or queued job.
pub async fn cancel(Json(b): Json<CancelBody>) -> ApiResult {
    match ask(Request::Cancel { job_id: b.job_id }).await? {
        Reply::Ok => Ok(Json(json!({}))),
        other => Err(unexpected(&other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No database and no daemon: reads are empty, writes are 503.
    #[tokio::test]
    async fn without_a_scanner_reads_are_empty_and_writes_are_503() {
        let d = tempfile::tempdir().unwrap();
        assert!(use_paths(d.path().to_owned(), d.path().join("none.sock")));

        let r = host(Path("AA:BB:CC:00:00:01".into())).await.unwrap();
        assert_eq!(r.0, json!({"latest": null, "changes": null, "history": []}));
        let q = |k: &str, l| {
            Query(JobsQuery {
                kind: Some(k.into()),
                limit: l,
            })
        };
        assert_eq!(jobs(q("range", None)).await.unwrap().0, json!([]));
        assert_eq!(
            jobs(q("x", None)).await.unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            jobs(q("range", Some(501))).await.unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            job(Path(1)).await.unwrap_err().status,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            host(Path("zz".into())).await.unwrap_err().status,
            StatusCode::BAD_REQUEST
        );

        let e = status().await.unwrap_err();
        assert_eq!(e.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(e.message, "the port scanner is not running");
        let e = cancel(Json(CancelBody { job_id: 1 })).await.unwrap_err();
        assert_eq!(e.status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn macs_are_checked_and_lowercased() {
        assert_eq!(mac("AA:bb:CC:00:11:22").unwrap(), "aa:bb:cc:00:11:22");
        for bad in [
            "",
            "aa:bb",
            "aa:bb:cc:00:11:2g",
            "aabbcc001122",
            "aa:bb:cc:00:11:22:33",
        ] {
            assert!(mac(bad).is_err(), "{bad}");
        }
    }
}
