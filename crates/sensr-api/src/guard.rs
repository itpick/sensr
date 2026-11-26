//! Services › Runtime Guard: events are read straight from the database
//! `sensr-guard` writes (`/var/lib/sensr-guard`, group `sensr`); status and
//! the switches go through the daemon's control socket. The API never
//! writes the database. While the daemon is down the status still lists the
//! configured rules, every one inactive.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use sensr_guard::client;
use sensr_guard::config::{EVENTS_DB, SOCKET, STATE_DIR};
use sensr_guard::proto::{Reply, Request, RuleStatus, StatusView};
use sensr_guard::rule::Action;
use sensr_guard::store::{Filter, Store, StoredEvent};
use sensr_ipc::{Op, Response, Source};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::Caller;
use crate::error::ApiError;

type ApiResult = Result<Json<Value>, ApiError>;

/// Events listed when `limit` is not given, and the most that can be asked for.
const DEFAULT_LIMIT: u32 = 100;
const MAX_LIMIT: u32 = 1000;
/// The hooks an event can come from.
const HOOKS: [&str; 7] = [
    "exec",
    "connect",
    "listen",
    "file_write",
    "setuid",
    "module",
    "bpf",
];

/// What the status says while the daemon is down.
pub const NOT_RUNNING: &str = "sensr-guard is not running";
/// The `source` of a guard row among the IDS alerts.
pub const SOURCE: &str = "runtime-guard";

static PATHS: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();

/// Test hook: point the API at another state directory and control socket
/// (tests cannot set the environment: `unsafe_code` is forbidden). Only the
/// first call has any effect; returns whether it did. Not for production use.
#[doc(hidden)]
pub fn use_paths(dir: PathBuf, socket: PathBuf) -> bool {
    PATHS.set((dir, socket)).is_ok()
}

/// The state directory (the test hook's, else `SENSR_GUARD_DIR`, else the default).
pub(crate) fn dir() -> PathBuf {
    if let Some((d, _)) = PATHS.get() {
        return d.clone();
    }
    std::env::var_os("SENSR_GUARD_DIR").map_or_else(|| PathBuf::from(STATE_DIR), PathBuf::from)
}

/// The control socket (the test hook's, else `SENSR_GUARD_SOCKET`, else the default).
pub(crate) fn socket() -> PathBuf {
    if let Some((_, s)) = PATHS.get() {
        return s.clone();
    }
    std::env::var_os("SENSR_GUARD_SOCKET").map_or_else(|| PathBuf::from(SOCKET), PathBuf::from)
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, msg)
}

fn internal(e: impl std::fmt::Display) -> ApiError {
    tracing::error!(error = %e, "runtime guard API failure");
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

async fn blocking<T, F>(f: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ApiError> + Send + 'static,
{
    tokio::task::spawn_blocking(f).await.map_err(internal)?
}

/// The events database, or `None` while the guard has never run.
fn store() -> Result<Option<Store>, ApiError> {
    let p = dir().join(EVENTS_DB);
    if !p.exists() {
        return Ok(None);
    }
    Store::open_ro(&p).map(Some).map_err(internal)
}

/// Writes change the router's behaviour: a read-only principal (holding
/// `user-config-readonly`) may not make them. They go straight to the
/// daemon, so they are checked here.
fn writable(caller: &Caller) -> Result<(), ApiError> {
    if caller.principal().readonly {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            format!("{} may not change the configuration", caller.info.user),
        ));
    }
    Ok(())
}

/// Ask the daemon.
async fn send(req: Request) -> std::io::Result<Reply> {
    let sock = socket();
    tokio::task::spawn_blocking(move || client::send(&sock, &req))
        .await
        .map_err(std::io::Error::other)?
}

/// Whether `e` means nothing is listening.
fn is_down(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::{ConnectionRefused, NotFound};
    matches!(e.kind(), NotFound | ConnectionRefused)
}

/// An unreachable socket is 503, not a server fault.
fn unreachable(e: &std::io::Error) -> ApiError {
    if is_down(e) {
        return ApiError::new(StatusCode::SERVICE_UNAVAILABLE, NOT_RUNNING);
    }
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        tracing::error!(error = %e, "sensr-guard socket: permission denied");
        return ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "the API may not use the sensr-guard socket (permissions)",
        );
    }
    tracing::error!(error = %e, "sensr-guard control socket failure");
    ApiError::new(StatusCode::BAD_GATEWAY, "sensr-guard did not answer")
}

async fn ask(req: Request) -> Result<Reply, ApiError> {
    send(req).await.map_err(|e| unreachable(&e))
}

fn unexpected(r: &Reply) -> ApiError {
    if let Reply::Error(e) = r {
        tracing::error!(error = %e, "sensr-guard refused a request");
        return ApiError::new(StatusCode::CONFLICT, "sensr-guard refused the request");
    }
    tracing::error!(reply = ?r, "unexpected reply from sensr-guard");
    ApiError::new(StatusCode::BAD_GATEWAY, "unexpected reply from sensr-guard")
}

/// The owner's rules from the configuration, each inactive: what the status
/// shows while the daemon is down. Pack rules live with the packs, which
/// only the daemon loads, so they are not listed.
async fn configured_rules(state: &AppState, caller: &Caller) -> Vec<RuleStatus> {
    let op = Op::ConfigGet {
        path: "guard.rules".parse().expect("a valid path"),
        source: Source::Head,
    };
    let rules = match crate::native::call(state, caller, op).await {
        Ok(Response::Value(Some(Value::Object(m)))) => m,
        Ok(_) => return Vec::new(),
        Err(e) => {
            tracing::warn!(error = %e.message, "could not read the configured guard rules");
            return Vec::new();
        }
    };
    rules
        .iter()
        .filter(|(_, r)| r.get("enabled").and_then(Value::as_bool) != Some(false))
        .map(|(id, r)| RuleStatus {
            id: id.clone(),
            pack: None,
            slot: None,
            action: if r.get("action").and_then(Value::as_str) == Some("block") {
                Action::Block
            } else {
                Action::Alert
            },
            active: false,
            reason: Some(NOT_RUNNING.to_owned()),
            hits: 0,
        })
        .collect()
}

/// The status of a daemon that is not running.
fn down_view(rules: Vec<RuleStatus>) -> StatusView {
    StatusView {
        running: false,
        enforcing: false,
        reason: Some(NOT_RUNNING.to_owned()),
        kill_switch: false,
        lockdown: "unknown".to_owned(),
        packs: Vec::new(),
        rules,
        dropped_kernel: 0,
        dropped_rate: 0,
        dropped_blocked: 0,
        boot_complete: false,
    }
}

/// `GET /api/v1/guard/status`: the daemon's status; when it is not running,
/// the configured rules, all inactive.
pub async fn status(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
) -> ApiResult {
    match send(Request::Status).await {
        Ok(Reply::Status(v)) => Ok(Json(json!(v))),
        Ok(other) => Err(unexpected(&other)),
        Err(e) if is_down(&e) => {
            let rules = configured_rules(&state, &caller).await;
            Ok(Json(json!(down_view(rules))))
        }
        Err(e) => Err(unreachable(&e)),
    }
}

/// Rule ids by event slot, from the daemon's current rules. A slot is the
/// position in a pack's maps: events carry no rule id of their own, so an
/// event recorded before a reload may map to a newer rule, and a slot that
/// two packs share maps to none. Empty while the daemon is down.
pub(crate) async fn slot_ids() -> HashMap<u32, Option<String>> {
    let mut m: HashMap<u32, Option<String>> = HashMap::new();
    if let Ok(Reply::Status(v)) = send(Request::Status).await {
        for r in v.rules {
            if let Some(slot) = r.slot {
                m.entry(slot)
                    .and_modify(|e| *e = None)
                    .or_insert(Some(r.id));
            }
        }
    }
    m
}

fn rule_of(slots: &HashMap<u32, Option<String>>, slot: u32) -> Value {
    slots
        .get(&slot)
        .cloned()
        .flatten()
        .map_or(Value::Null, Value::String)
}

/// Query of `GET /api/v1/guard/events`.
#[derive(Debug, Default, Deserialize)]
pub struct EventsQuery {
    hook: Option<String>,
    q: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

/// `GET /api/v1/guard/events?hook=&q=&limit=&offset=`: newest first.
pub async fn events(Query(q): Query<EventsQuery>) -> ApiResult {
    if let Some(h) = &q.hook
        && !HOOKS.contains(&h.as_str())
    {
        return Err(bad(format!("hook is one of {}", HOOKS.join(", "))));
    }
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(bad(format!("limit is 1 to {MAX_LIMIT}")));
    }
    let offset = q.offset.unwrap_or(0);
    let f = Filter {
        hook: q.hook,
        text: q.q.filter(|t| !t.is_empty()),
        ..Filter::default()
    };
    let slots = slot_ids().await;
    blocking(move || {
        let Some(s) = store()? else {
            return Ok(Json(json!({"available": false, "rows": [], "total": 0})));
        };
        let rows: Vec<Value> = s
            .events(&f, limit, offset)
            .map_err(internal)?
            .iter()
            .map(|e| {
                let mut v = json!(e);
                v["rule"] = rule_of(&slots, e.row.rule_id);
                v
            })
            .collect();
        let total = s.count(&f).map_err(internal)?;
        Ok(Json(
            json!({"available": true, "rows": rows, "total": total}),
        ))
    })
    .await
}

/// What the IDS alert list asks of the guard rows.
pub(crate) struct AlertsWanted {
    /// Case-insensitive text.
    pub text: Option<String>,
    /// Unix milliseconds, inclusive.
    pub since: Option<i64>,
    /// Unix milliseconds, exclusive.
    pub until: Option<i64>,
    /// Newest rows wanted (the page's offset plus its size).
    pub newest: u32,
}

/// An event as a row of the alerts list.
fn alert_row(e: &StoredEvent, rule: Value) -> Value {
    let r = &e.row;
    json!({
        "source": SOURCE,
        "id": e.id,
        "ts": r.ts * 1000 + i64::from(r.ts_ms),
        "signature": format!("{}: {}", r.hook, r.target),
        "category": SOURCE,
        "severity": if r.blocked { 1 } else { 3 },
        "action": if r.blocked { "blocked" } else { "allowed" },
        "hook": r.hook,
        "rule": rule,
        "rule_slot": r.rule_id,
        "exe": r.exe,
        "target": r.target,
        "unit": r.unit,
        "pid": r.pid,
        "uid": r.uid,
        "count": r.count,
    })
}

/// The newest guard events matching `w` as alert rows, and how many match.
/// `None` while the guard has never run.
pub(crate) async fn alert_rows(w: AlertsWanted) -> Result<Option<(Vec<Value>, u64)>, ApiError> {
    let slots = slot_ids().await;
    blocking(move || {
        let Some(s) = store()? else {
            return Ok(None);
        };
        let f = Filter {
            text: w.text,
            since_ms: w.since,
            until_ms: w.until,
            ..Filter::default()
        };
        let rows = s
            .events(&f, w.newest, 0)
            .map_err(internal)?
            .iter()
            .map(|e| alert_row(e, rule_of(&slots, e.row.rule_id)))
            .collect();
        Ok(Some((rows, s.count(&f).map_err(internal)?)))
    })
    .await
}

/// `POST /api/v1/guard/reload`: re-read the configuration.
pub async fn reload(Extension(caller): Extension<Caller>) -> ApiResult {
    writable(&caller)?;
    match ask(Request::Reload).await? {
        Reply::Ok => Ok(Json(json!({}))),
        other => Err(unexpected(&other)),
    }
}

/// Body of `POST /api/v1/guard/kill-switch`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KillSwitchBody {
    on: bool,
}

/// `POST /api/v1/guard/kill-switch {on}`: nothing blocks while it is on.
pub async fn kill_switch(
    Extension(caller): Extension<Caller>,
    Json(b): Json<KillSwitchBody>,
) -> ApiResult {
    writable(&caller)?;
    match ask(Request::KillSwitch { on: b.on }).await? {
        Reply::Ok => Ok(Json(json!({}))),
        other => Err(unexpected(&other)),
    }
}

/// `POST /api/v1/guard/check-packs`: fetch the pack index and install newer
/// packs that verify.
pub async fn check_packs(Extension(caller): Extension<Caller>) -> ApiResult {
    writable(&caller)?;
    match ask(Request::CheckPacks).await? {
        Reply::Packs(p) => Ok(Json(json!({ "packs": p }))),
        other => Err(unexpected(&other)),
    }
}
