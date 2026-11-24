//! The native REST API, `/api/v1/…`: config get/set/delete/commit/confirm/
//! rollback/history/diff, apply plan, status, sessions.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::{Extension, Json};
use sensr_ipc::{ConfigPath, Credential, Op, Response, Source};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::{Caller, bearer, verify};
use crate::error::ApiError;

type ApiResult = Result<Json<Value>, ApiError>;

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, msg)
}

fn parse_source(s: Option<&str>, default: Source) -> Result<Source, ApiError> {
    Ok(match s {
        None => default,
        Some("candidate") => Source::Candidate,
        Some("head") => Source::Head,
        Some("applied") | Some("running") => Source::Applied,
        Some(n) => Source::Revision(n.parse().map_err(|_| bad(format!("bad source {n:?}")))?),
    })
}

/// URL tail → path: `system/hostname` (slashes) or `system.hostname` (dots).
fn parse_path(p: &str) -> Result<ConfigPath, ApiError> {
    let spelled = if p.contains('/') {
        format!("/{p}")
    } else {
        p.to_owned()
    };
    spelled
        .parse()
        .map_err(|e| bad(format!("bad config path {p:?}: {e}")))
}

pub(crate) async fn call(state: &AppState, caller: &Caller, op: Op) -> Result<Response, ApiError> {
    Ok(state.agent.call(caller.principal(), op).await?)
}

fn to_json<T: serde::Serialize>(v: &T) -> Json<Value> {
    Json(serde_json::to_value(v).unwrap_or(Value::Null))
}

fn unexpected(r: Response) -> ApiError {
    ApiError::new(
        StatusCode::BAD_GATEWAY,
        format!("unexpected agent reply {r:?}"),
    )
}

/// Query string of document reads.
#[derive(Debug, Deserialize)]
pub struct SourceQuery {
    source: Option<String>,
}

/// `GET /api/v1/config/doc[/{path}]`.
pub async fn get_doc(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    path: Option<Path<String>>,
    Query(q): Query<SourceQuery>,
) -> ApiResult {
    let p = match &path {
        Some(Path(p)) => parse_path(p)?,
        None => ConfigPath::root(),
    };
    let source = parse_source(q.source.as_deref(), Source::Candidate)?;
    match call(
        &state,
        &caller,
        Op::ConfigGet {
            path: p.clone(),
            source,
        },
    )
    .await?
    {
        Response::Value(Some(v)) => Ok(Json(v)),
        Response::Value(None) => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("{p} is not set"),
        )),
        other => Err(unexpected(other)),
    }
}

/// `PUT /api/v1/config/doc/{path}` with a JSON value body.
pub async fn put_doc(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Path(p): Path<String>,
    Json(value): Json<Value>,
) -> ApiResult {
    let path = parse_path(&p)?;
    match call(&state, &caller, Op::ConfigSet { path, value }).await? {
        Response::Staged { dirty } => Ok(Json(json!({"status": "ok", "dirty": dirty}))),
        other => Err(unexpected(other)),
    }
}

/// `DELETE /api/v1/config/doc/{path}`.
pub async fn delete_doc(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Path(p): Path<String>,
) -> ApiResult {
    let path = parse_path(&p)?;
    match call(&state, &caller, Op::ConfigDelete { path }).await? {
        Response::Staged { dirty } => Ok(Json(json!({"status": "ok", "dirty": dirty}))),
        other => Err(unexpected(other)),
    }
}

/// `POST /api/v1/config/discard`.
pub async fn discard(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
) -> ApiResult {
    call(&state, &caller, Op::ConfigDiscard).await?;
    Ok(Json(json!({"status": "ok"})))
}

/// Body of `POST /api/v1/config/commit`.
#[derive(Debug, Default, Deserialize)]
pub struct CommitBody {
    description: Option<String>,
    confirm_secs: Option<u32>,
}

/// `POST /api/v1/config/commit`.
pub async fn commit(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    body: Option<Json<CommitBody>>,
) -> ApiResult {
    let b = body.map(|Json(b)| b).unwrap_or_default();
    match call(
        &state,
        &caller,
        Op::ConfigCommit {
            description: b.description,
            confirm_secs: b.confirm_secs,
        },
    )
    .await?
    {
        Response::Committed(o) => Ok(to_json(&*o)),
        other => Err(unexpected(other)),
    }
}

/// `POST /api/v1/config/confirm`.
pub async fn confirm(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
) -> ApiResult {
    match call(&state, &caller, Op::ConfigConfirm).await? {
        Response::Confirmed(rev) => Ok(Json(json!({"status": "ok", "revision": rev}))),
        other => Err(unexpected(other)),
    }
}

/// Body of `POST /api/v1/config/rollback`.
#[derive(Debug, Default, Deserialize)]
pub struct RollbackBody {
    revision: Option<u64>,
}

/// `POST /api/v1/config/rollback`.
pub async fn rollback(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    body: Option<Json<RollbackBody>>,
) -> ApiResult {
    let to = body.and_then(|Json(b)| b.revision);
    match call(&state, &caller, Op::ConfigRollback { to }).await? {
        Response::Committed(o) => Ok(to_json(&*o)),
        other => Err(unexpected(other)),
    }
}

/// Query of `GET /api/v1/config/history`.
#[derive(Debug, Deserialize)]
pub struct HistoryQuery {
    limit: Option<u32>,
}

/// `GET /api/v1/config/history`.
pub async fn history(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Query(q): Query<HistoryQuery>,
) -> ApiResult {
    match call(&state, &caller, Op::ConfigHistory { limit: q.limit }).await? {
        Response::History(h) => Ok(to_json(&h)),
        other => Err(unexpected(other)),
    }
}

/// Query of `GET /api/v1/config/diff`.
#[derive(Debug, Deserialize)]
pub struct DiffQuery {
    from: Option<String>,
    to: Option<String>,
}

/// `GET /api/v1/config/diff?from=head&to=candidate`.
pub async fn diff(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Query(q): Query<DiffQuery>,
) -> ApiResult {
    let from = parse_source(q.from.as_deref(), Source::Head)?;
    let to = parse_source(q.to.as_deref(), Source::Candidate)?;
    match call(&state, &caller, Op::ConfigDiff { from, to }).await? {
        Response::Diff(d) => Ok(to_json(&d)),
        other => Err(unexpected(other)),
    }
}

/// `GET /api/v1/apply/plan?source=candidate`.
pub async fn plan(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Query(q): Query<SourceQuery>,
) -> ApiResult {
    let source = parse_source(q.source.as_deref(), Source::Candidate)?;
    match call(&state, &caller, Op::ApplyDryRun { source }).await? {
        Response::Plan(p) => Ok(to_json(&p)),
        other => Err(unexpected(other)),
    }
}

/// `GET /api/v1/status`.
pub async fn status(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
) -> ApiResult {
    match call(&state, &caller, Op::Status).await? {
        Response::Status(s) => Ok(to_json(&*s)),
        other => Err(unexpected(other)),
    }
}

/// `GET /api/v1/interfaces/nics`: the host's network cards and the
/// interface each carries.
pub async fn nics(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
) -> ApiResult {
    match call(&state, &caller, Op::Nics).await? {
        Response::Nics(n) => Ok(to_json(&n)),
        other => Err(unexpected(other)),
    }
}

/// `POST /api/v1/interfaces/assign`: `[{interface, nic}]`, staged in the
/// candidate like any edit.
pub async fn assign(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Json(assignments): Json<Vec<sensr_ipc::Assignment>>,
) -> ApiResult {
    match call(&state, &caller, Op::InterfacesAssign { assignments }).await? {
        Response::Staged { dirty } => Ok(to_json(&serde_json::json!({ "dirty": dirty }))),
        other => Err(unexpected(other)),
    }
}

/// `GET /api/v1/status/{gateways|aliases|ipv6}`: run-time state.
pub async fn runtime(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    axum::extract::Path(section): axum::extract::Path<String>,
) -> ApiResult {
    let section = match section.as_str() {
        "gateways" => sensr_ipc::RuntimeSection::Gateways,
        "aliases" => sensr_ipc::RuntimeSection::Aliases,
        "ipv6" => sensr_ipc::RuntimeSection::Ipv6,
        other => {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                format!("no run-time section {other:?}"),
            ));
        }
    };
    match call(&state, &caller, Op::Runtime { section }).await? {
        Response::Value(v) => Ok(Json(v.unwrap_or(serde_json::Value::Null))),
        other => Err(unexpected(other)),
    }
}

/// `GET /api/v1/hosts`: the discovered host inventory, or an empty one when
/// the collector is not running.
pub async fn hosts(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
) -> ApiResult {
    let section = sensr_ipc::RuntimeSection::Hosts;
    match call(&state, &caller, Op::Runtime { section }).await? {
        Response::Value(v) => Ok(Json(
            v.unwrap_or_else(|| serde_json::json!({"now": 0, "hosts": []})),
        )),
        other => Err(unexpected(other)),
    }
}

/// Query of `GET /api/v1/hosts/{mac}/activity`.
#[derive(Deserialize)]
pub struct ActivityQuery {
    /// `today` (the default) or `7d`.
    range: Option<String>,
    /// Domains page, from 0.
    domains_page: Option<u32>,
}

/// Whether `caller` may read the insight database (what the activity route needs besides the
/// hosts privilege the middleware checked).
///
/// The insight privilege is `page-diagnostics-networkinsight`, whose patterns include
/// `api/v1/insight/*`; `/api/v1/insight/top` stands for "any insight route" because the
/// registry is queried by URL, not by privilege name.
pub(crate) fn may_read_insight(state: &AppState, caller: &Caller) -> bool {
    state.registry.grants(
        caller.info.privileges.iter().map(String::as_str),
        "/api/v1/insight/top",
    )
}

/// `GET /api/v1/hosts/{mac}/activity?range=today|7d&domains_page=N`: one device's DNS
/// activity (minutes per service and category, an hourly timeline, the names it looked up).
/// Needs the hosts and the insight privileges; 404 for a MAC not in the inventory, 400 for
/// a bad range.
pub async fn host_activity(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Path(mac): Path<String>,
    Query(q): Query<ActivityQuery>,
) -> ApiResult {
    if !may_read_insight(&state, &caller) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            format!("{} may not read insight data", caller.info.user),
        ));
    }
    let range = q.range.unwrap_or_else(|| "today".into());
    if !matches!(range.as_str(), "today" | "7d") {
        return Err(bad(format!("range is today or 7d, not {range:?}")));
    }
    let section = sensr_ipc::RuntimeSection::Hosts;
    let hosts = match call(&state, &caller, Op::Runtime { section }).await? {
        Response::Value(v) => v.unwrap_or(Value::Null),
        other => return Err(unexpected(other)),
    };
    let page = q.domains_page.unwrap_or(0);
    let view = tokio::task::spawn_blocking(move || {
        let now = crate::insight::now();
        sensr_ui::insight::host_activity(
            &crate::insight::dir(),
            hosts,
            &mac,
            &range,
            page,
            now,
            sensr_ui::insight::local_offset(now),
        )
    })
    .await
    .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    match view {
        Ok(v) => Ok(to_json(&v)),
        Err(sensr_ui::insight::ActivityError::BadRange) => Err(bad("range is today or 7d")),
        Err(sensr_ui::insight::ActivityError::UnknownHost) => {
            Err(ApiError::new(StatusCode::NOT_FOUND, "no such host"))
        }
        Err(sensr_ui::insight::ActivityError::Failed(m)) => {
            Err(ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, m))
        }
    }
}

/// `GET /api/v1/hosts/{mac}/ports`: the open TCP ports the daily scan found
/// on one host, `{last_scan, scanning, all_filtered, ports}` (`last_scan` is
/// `null` before the first scan; each port has `new` when first seen within
/// 24 hours). 404 for a MAC not in the inventory, 503 when the scanner is not
/// running.
pub async fn host_ports(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Path(mac): Path<String>,
) -> ApiResult {
    match call(&state, &caller, Op::HostPorts { mac }).await? {
        Response::Value(Some(v)) => Ok(Json(v)),
        other => Err(unexpected(other)),
    }
}

/// `POST /api/v1/hosts/{mac}/scan`: scan one host's ports now in the
/// background; 202 `{"started": true}`. 404 for an unknown MAC, 409 while that
/// host is being scanned or when it is not one the router scans (no IPv4
/// address, not on an internal network, quarantined), 429 while two such
/// scans run, 503 when the scanner is not running, 403 to read-only principals.
pub async fn host_scan(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Path(mac): Path<String>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    match call(&state, &caller, Op::HostScanNow { mac }).await? {
        Response::Value(Some(v)) => Ok((StatusCode::ACCEPTED, Json(v))),
        other => Err(unexpected(other)),
    }
}

/// Body of `POST /api/v1/hosts/forget`.
#[derive(Deserialize)]
pub struct ForgetBody {
    key: String,
}

/// `POST /api/v1/hosts/forget`: drop a host from the inventory. The agent
/// answers Conflict (409) for a reserved or unknown host and Forbidden
/// (403) to read-only principals.
pub async fn forget_host(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Json(b): Json<ForgetBody>,
) -> ApiResult {
    match call(&state, &caller, Op::HostForget { key: b.key }).await? {
        Response::Value(v) => Ok(Json(v.unwrap_or(serde_json::Value::Null))),
        other => Err(unexpected(other)),
    }
}

/// A mode in the body of `POST /api/v1/hosts/mode`.
#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ModeBody {
    /// No containment (the entry is removed); same as `null`.
    Normal,
    /// Router and internet only.
    Isolated,
    /// The router's DHCP, DNS and NTP only.
    Quarantine,
}

/// Body of `POST /api/v1/hosts/mode`.
#[derive(Deserialize)]
pub struct HostModeBody {
    mac: String,
    #[serde(default)]
    mode: Option<ModeBody>,
}

/// `POST /api/v1/hosts/mode`: put a host in a mode or back to Normal. The
/// agent commits at once when nothing else is staged (`{"result":
/// "applied"}`), else stages (`"staged"`); quarantining the device the
/// request comes from is a Conflict (409), read-only principals get 403.
pub async fn set_host_mode(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(b): Json<HostModeBody>,
) -> ApiResult {
    use sensr_ipc::HostModeMode;
    let mode = match b.mode {
        None | Some(ModeBody::Normal) => None,
        Some(ModeBody::Isolated) => Some(HostModeMode::Isolated),
        Some(ModeBody::Quarantine) => Some(HostModeMode::Quarantine),
    };
    let op = Op::HostModeSet {
        mac: b.mac,
        mode,
        remote_addr: connect.map(|Extension(ConnectInfo(a))| a.ip()),
    };
    match call(&state, &caller, op).await? {
        Response::Value(Some(v)) => Ok(Json(v)),
        other => Err(unexpected(other)),
    }
}

/// Body of `POST /api/v1/hosts/label`.
#[derive(Deserialize)]
pub struct HostLabelBody {
    mac: String,
    /// The owner's kind (`phone`, `camera`, `smart_home`, ...); `null` keeps the guess.
    #[serde(default)]
    kind: Option<sensr_schema::models::hosts::HostKind>,
    /// The owner's maker (1-64 characters); `null` keeps the guess.
    #[serde(default)]
    maker: Option<String>,
}

/// `POST /api/v1/hosts/label`: set what a host is called, or clear it with
/// both fields `null`. The agent commits at once when nothing else is staged
/// (`{"result": "applied"}`), else stages (`"staged"`); read-only principals
/// get 403.
pub async fn set_host_label(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Json(b): Json<HostLabelBody>,
) -> ApiResult {
    let op = Op::HostLabelSet {
        mac: b.mac,
        kind: b.kind,
        maker: b.maker,
    };
    match call(&state, &caller, op).await? {
        Response::Value(Some(v)) => Ok(Json(v)),
        other => Err(unexpected(other)),
    }
}

/// Body of `POST /api/v1/insight/service-override`.
#[derive(Deserialize)]
pub struct ServiceOverrideBody {
    /// Domain suffix (`example.com`).
    suffix: String,
    /// Service name (1-48 characters); `null` with `category` removes it.
    #[serde(default)]
    service: Option<String>,
    /// Category key (`games`, `ads_tracking`, ...).
    #[serde(default)]
    category: Option<sensr_schema::models::insight::Category>,
}

/// `POST /api/v1/insight/service-override`: set what a domain suffix counts
/// as on the per-host DNS activity page, or remove the override with both
/// `service` and `category` `null`. The agent commits at once when nothing
/// else is staged (`{"result": "applied"}`), else stages (`"staged"`);
/// read-only principals get 403.
pub async fn set_service_override(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<Caller>,
    Json(b): Json<ServiceOverrideBody>,
) -> ApiResult {
    let op = Op::ServiceOverrideSet {
        suffix: b.suffix,
        service: b.service,
        category: b.category,
    };
    match call(&state, &caller, op).await? {
        Response::Value(Some(v)) => Ok(Json(v)),
        other => Err(unexpected(other)),
    }
}

/// Body of `POST /api/v1/session`.
#[derive(Deserialize)]
pub struct LoginBody {
    user: String,
    password: String,
    /// TOTP code for accounts with two-factor login.
    #[serde(default)]
    otp: Option<String>,
}

/// `POST /api/v1/session`: password login, returns a bearer token.
pub async fn login(
    State(state): State<Arc<AppState>>,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(b): Json<LoginBody>,
) -> ApiResult {
    let remote = connect.map(|Extension(ConnectInfo(a))| a.ip());
    let caller = verify(
        &state,
        Credential::Password {
            user: b.user,
            password: b.password,
            otp: b.otp,
        },
        remote,
    )
    .await
    .map_err(|e| {
        if e.status == StatusCode::UNAUTHORIZED {
            ApiError::new(StatusCode::UNAUTHORIZED, "invalid credentials")
        } else {
            e
        }
    })?;
    let user = caller.info.user.clone();
    let privileges = caller.info.privileges.clone();
    let token = state.auth.open_session(caller)?;
    Ok(Json(
        json!({"token": token, "user": user, "privileges": privileges}),
    ))
}

/// `DELETE /api/v1/session`.
pub async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult {
    if let Some(t) = bearer(&headers) {
        state.auth.close_session(t);
    }
    Ok(Json(json!({"status": "ok"})))
}
