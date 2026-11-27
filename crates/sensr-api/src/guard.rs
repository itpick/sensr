//! Services › Runtime Guard: events are read straight from the database
//! `sensr-guard` writes (`/var/lib/sensr-guard`, group `sensr`); status and
//! the switches go through the daemon's control socket. The API never
//! writes the database. While the daemon is down the status still lists the
//! configured rules, every one inactive.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(feature = "test-hooks")]
use std::sync::OnceLock;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
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

/// Failure of a switch: an API error, or the daemon's own refusal.
pub enum WriteError {
    /// Any other failure.
    Api(ApiError),
    /// The daemon answered with an error: its text is an owner-facing
    /// explanation and goes to the caller as `{"error": text}` (409).
    Refused(String),
}

impl From<ApiError> for WriteError {
    fn from(e: ApiError) -> Self {
        Self::Api(e)
    }
}

impl IntoResponse for WriteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Api(e) => e.into_response(),
            Self::Refused(text) => {
                (StatusCode::CONFLICT, Json(json!({ "error": text }))).into_response()
            }
        }
    }
}

type WriteResult = Result<Json<Value>, WriteError>;

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

#[cfg(feature = "test-hooks")]
static PATHS: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();

/// Test hook: point the API at another state directory and control socket
/// (tests cannot set the environment: `unsafe_code` is forbidden). Only the
/// first call has any effect; returns whether it did. Only in builds with
/// the `test-hooks` feature (the crate's own tests).
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub fn use_paths(dir: PathBuf, socket: PathBuf) -> bool {
    PATHS.set((dir, socket)).is_ok()
}

/// The state directory (the test hook's, else `SENSR_GUARD_DIR`, else the default).
pub(crate) fn dir() -> PathBuf {
    #[cfg(feature = "test-hooks")]
    if let Some((d, _)) = PATHS.get() {
        return d.clone();
    }
    std::env::var_os("SENSR_GUARD_DIR").map_or_else(|| PathBuf::from(STATE_DIR), PathBuf::from)
}

/// The control socket (the test hook's, else `SENSR_GUARD_SOCKET`, else the default).
pub(crate) fn socket() -> PathBuf {
    #[cfg(feature = "test-hooks")]
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

/// Ask the daemon, waiting `timeout` for the answer.
async fn send(req: Request, timeout: Duration) -> std::io::Result<Reply> {
    let sock = socket();
    tokio::task::spawn_blocking(move || client::send_with_timeout(&sock, &req, timeout))
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

async fn ask(req: Request, timeout: Duration) -> Result<Reply, ApiError> {
    send(req, timeout).await.map_err(|e| unreachable(&e))
}

/// A reply that is not the one asked for: the daemon's refusal, or a fault.
fn unexpected(r: Reply) -> WriteError {
    if let Reply::Error(e) = r {
        tracing::error!(error = %e, "sensr-guard refused a request");
        return WriteError::Refused(e);
    }
    WriteError::Api(unexpected_reply(&r))
}

fn unexpected_reply(r: &Reply) -> ApiError {
    tracing::error!(reply = ?r, "unexpected reply from sensr-guard");
    ApiError::new(StatusCode::BAD_GATEWAY, "unexpected reply from sensr-guard")
}

/// The owner's rules from the configuration, each inactive: what the status
/// shows while the daemon is down. Pack rules live with the packs, which
/// only the daemon loads, so they are not listed.
async fn configured_rules(state: &AppState, caller: &Caller) -> Result<Vec<RuleStatus>, String> {
    let op = Op::ConfigGet {
        path: "guard.rules".parse().expect("a valid path"),
        source: Source::Head,
    };
    let rules = match crate::native::call(state, caller, op).await {
        Ok(Response::Value(Some(Value::Object(m)))) => m,
        Ok(_) => return Ok(Vec::new()),
        Err(e) => {
            tracing::warn!(error = %e.message, "could not read the configured guard rules");
            return Err(e.message);
        }
    };
    Ok(rules
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
            held: false,
        })
        .collect())
}

/// The status of a daemon that is not running; `read_error` is why the
/// configured rules could not be listed, if that failed.
fn down_view(rules: Vec<RuleStatus>, read_error: Option<String>) -> StatusView {
    StatusView {
        running: false,
        enforcing: false,
        reason: Some(read_error.map_or_else(
            || NOT_RUNNING.to_owned(),
            |e| format!("{NOT_RUNNING}; the configured rules could not be read: {e}"),
        )),
        kill_switch: false,
        lockdown: "unknown".to_owned(),
        packs: Vec::new(),
        rules,
        dropped_kernel: 0,
        dropped_rate: 0,
        dropped_blocked: 0,
        boot_complete: false,
        pending_confirm: None,
        held: Vec::new(),
    }
}

/// `GET /api/v1/guard/status`: the daemon's status; when it is not running,
/// the configured rules, all inactive.
pub async fn status(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
) -> ApiResult {
    match send(Request::Status, client::SHORT_TIMEOUT).await {
        Ok(Reply::Status(v)) => Ok(Json(json!(v))),
        Ok(other) => Err(unexpected_reply(&other)),
        Err(e) if is_down(&e) => {
            let (rules, err) = match configured_rules(&state, &caller).await {
                Ok(r) => (r, None),
                Err(e) => (Vec::new(), Some(e)),
            };
            Ok(Json(json!(down_view(rules, err))))
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
    if let Ok(Reply::Status(v)) = send(Request::Status, client::SHORT_TIMEOUT).await {
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

/// The newest blocked guard events matching `w` as alert rows, and how many
/// match.
/// `None` while the guard has never run.
pub(crate) async fn alert_rows(w: AlertsWanted) -> Result<Option<(Vec<Value>, u64)>, ApiError> {
    let slots = slot_ids().await;
    blocking(move || {
        let Some(s) = store()? else {
            return Ok(None);
        };
        // the alert-worthy rows only: what was blocked (the rest is the
        // guard's own Events list)
        let f = Filter {
            blocked: Some(true),
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
pub async fn reload(Extension(caller): Extension<Caller>) -> WriteResult {
    writable(&caller)?;
    match ask(Request::Reload, client::TIMEOUT).await? {
        Reply::Ok => Ok(Json(json!({}))),
        other => Err(unexpected(other)),
    }
}

/// Body of `POST /api/v1/guard/kill-switch`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KillSwitchBody {
    on: bool,
}

/// `POST /api/v1/guard/kill-switch {on}`: nothing blocks while it is on.
/// Turning it off lets rules block again: the reply then carries
/// `pending_confirm` (its deadline), and unless `POST /api/v1/guard/confirm`
/// comes before it the kill switch turns back on.
pub async fn kill_switch(
    Extension(caller): Extension<Caller>,
    Json(b): Json<KillSwitchBody>,
) -> WriteResult {
    writable(&caller)?;
    match ask(Request::KillSwitch { on: b.on }, client::TIMEOUT).await? {
        Reply::Ok => Ok(Json(json!({}))),
        Reply::Pending(p) => Ok(Json(json!({ "pending_confirm": p }))),
        other => Err(unexpected(other)),
    }
}

/// `POST /api/v1/guard/confirm`: keep what the confirm window let block
/// (the kill switch off, released rules).
pub async fn confirm(Extension(caller): Extension<Caller>) -> WriteResult {
    writable(&caller)?;
    match ask(Request::Confirm, client::TIMEOUT).await? {
        Reply::Ok => Ok(Json(json!({}))),
        other => Err(unexpected(other)),
    }
}

/// `POST /api/v1/guard/release-held`: let the block rules a pack update
/// brought (held as alerts) block, in a confirm window (`pending_confirm`).
pub async fn release_held(Extension(caller): Extension<Caller>) -> WriteResult {
    writable(&caller)?;
    match ask(Request::ReleaseHeld, client::TIMEOUT).await? {
        Reply::Pending(p) => Ok(Json(json!({ "pending_confirm": p }))),
        other => Err(unexpected(other)),
    }
}

/// `POST /api/v1/guard/check-packs`: fetch the pack index and install newer
/// packs that verify.
pub async fn check_packs(Extension(caller): Extension<Caller>) -> WriteResult {
    writable(&caller)?;
    match ask(Request::CheckPacks, client::TIMEOUT).await? {
        Reply::Packs(p) => Ok(Json(json!({ "packs": p }))),
        other => Err(unexpected(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_config_read_is_said_in_the_reason() {
        let v = down_view(Vec::new(), None);
        assert_eq!(v.reason.as_deref(), Some("sensr-guard is not running"));
        let v = down_view(Vec::new(), Some("sensr-agent is not reachable".into()));
        assert!(!v.running && v.rules.is_empty());
        assert_eq!(
            v.reason.as_deref(),
            Some(
                "sensr-guard is not running; the configured rules could not be read: sensr-agent is not reachable"
            )
        );
    }
}
