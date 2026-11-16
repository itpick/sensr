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

async fn call(state: &AppState, caller: &Caller, op: Op) -> Result<Response, ApiError> {
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

/// Body of `POST /api/v1/session`.
#[derive(Deserialize)]
pub struct LoginBody {
    user: String,
    password: String,
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
