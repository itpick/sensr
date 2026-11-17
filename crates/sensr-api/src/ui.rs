//! The web UI (`sensr-ui`) served next to the API, backed by the agent.
//!
//! [`UiSessions`] reuses the API's session table, so a UI login is also a valid bearer token,
//! and each UI request acts as the signed-in caller: the agent enforces privileges and
//! read-only access exactly as for REST calls.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures::future::{BoxFuture, FutureExt};
use sensr_ipc::{ClientError, ConfigPath, Credential, ErrorKind, Op, Response, Source};
use sensr_ui::api::{
    ApiError, ApiResult, Backend, ConfirmWindow, DiffKind, DiffLine, FieldError, Pending, Revision,
    Session, Sessions, SystemStatus,
};
use sensr_ui::hoststats::Sampler;
use serde_json::Value;

use crate::AppState;
use crate::auth::{Caller, verify};

fn ui_error(e: ClientError) -> ApiError {
    match e {
        ClientError::Agent(e) => match e.kind {
            ErrorKind::Validation => ApiError::Validation(
                e.validations
                    .into_iter()
                    .map(|v| FieldError::new(v.path, v.message))
                    .collect(),
            ),
            ErrorKind::Unauthenticated | ErrorKind::Forbidden => ApiError::Unauthorized,
            ErrorKind::NotFound => ApiError::NotFound(e.message),
            ErrorKind::Conflict => ApiError::Conflict(e.message),
            _ => ApiError::Backend(e.message),
        },
        other => ApiError::Backend(other.to_string()),
    }
}

fn unexpected(r: Response) -> ApiError {
    ApiError::Backend(format!("unexpected agent reply {r:?}"))
}

fn path(p: &str) -> ApiResult<ConfigPath> {
    if p.is_empty() {
        return Ok(ConfigPath::root());
    }
    p.parse()
        .map_err(|e| ApiError::Backend(format!("bad config path {p:?}: {e}")))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn revision(r: sensr_ipc::RevisionInfo) -> Revision {
    Revision {
        id: r.id,
        time: u64::try_from(r.time_ms / 1000).unwrap_or(0),
        user: r.username,
        message: r.description,
    }
}

/// One signed-in caller's view of the agent.
pub struct UiBackend {
    state: Arc<AppState>,
    caller: Caller,
    sampler: Arc<Sampler>,
}

impl UiBackend {
    async fn call(&self, op: Op) -> ApiResult<Response> {
        self.state
            .agent
            .call(self.caller.principal(), op)
            .await
            .map_err(ui_error)
    }

    async fn pending_now(&self) -> ApiResult<Pending> {
        let status = match self.call(Op::Status).await? {
            Response::Status(s) => s,
            other => return Err(unexpected(other)),
        };
        let mut changed = Vec::new();
        if status.candidate_dirty {
            if let Response::Diff(d) = self
                .call(Op::ConfigDiff {
                    from: Source::Head,
                    to: Source::Candidate,
                })
                .await?
            {
                for c in d.changes {
                    let section = c.path.to_string();
                    let section = section
                        .trim_start_matches('/')
                        .split(['.', '/'])
                        .next()
                        .unwrap_or_default()
                        .to_owned();
                    if !section.is_empty() && !changed.contains(&section) {
                        changed.push(section);
                    }
                }
            }
            if changed.is_empty() {
                changed.push("configuration".into());
            }
        }
        Ok(Pending {
            changed,
            confirm: status.pending_confirm.map(|p| ConfirmWindow {
                revision: p.revision,
                deadline: u64::try_from(p.deadline_ms / 1000).unwrap_or(0),
            }),
            now: now_secs(),
            alert: status.seed_error.clone(),
        })
    }
}

impl Backend for UiBackend {
    fn get<'a>(&'a self, p: &'a str) -> BoxFuture<'a, ApiResult<Value>> {
        async move {
            let op = Op::ConfigGet {
                path: path(p)?,
                source: Source::Candidate,
            };
            match self.call(op).await? {
                Response::Value(v) => Ok(v.unwrap_or(Value::Null)),
                other => Err(unexpected(other)),
            }
        }
        .boxed()
    }

    fn set<'a>(&'a self, p: &'a str, value: Value) -> BoxFuture<'a, ApiResult<()>> {
        async move {
            match self
                .call(Op::ConfigSet {
                    path: path(p)?,
                    value,
                })
                .await?
            {
                Response::Staged { .. } => Ok(()),
                other => Err(unexpected(other)),
            }
        }
        .boxed()
    }

    fn pending(&self) -> BoxFuture<'_, ApiResult<Pending>> {
        self.pending_now().boxed()
    }

    fn commit<'a>(
        &'a self,
        _user: &'a str,
        message: &'a str,
        confirm_secs: Option<u32>,
    ) -> BoxFuture<'a, ApiResult<Revision>> {
        async move {
            let op = Op::ConfigCommit {
                description: Some(message.to_owned()).filter(|m| !m.is_empty()),
                confirm_secs,
            };
            match self.call(op).await? {
                Response::Committed(o) => Ok(revision(o.revision)),
                other => Err(unexpected(other)),
            }
        }
        .boxed()
    }

    fn confirm(&self) -> BoxFuture<'_, ApiResult<()>> {
        async move {
            match self.call(Op::ConfigConfirm).await? {
                Response::Confirmed(_) => Ok(()),
                other => Err(unexpected(other)),
            }
        }
        .boxed()
    }

    fn discard(&self) -> BoxFuture<'_, ApiResult<()>> {
        async move {
            self.call(Op::ConfigDiscard).await?;
            Ok(())
        }
        .boxed()
    }

    fn rollback<'a>(&'a self, _user: &'a str, to: u64) -> BoxFuture<'a, ApiResult<Revision>> {
        async move {
            match self.call(Op::ConfigRollback { to: Some(to) }).await? {
                Response::Committed(o) => Ok(revision(o.revision)),
                other => Err(unexpected(other)),
            }
        }
        .boxed()
    }

    fn history(&self) -> BoxFuture<'_, ApiResult<Vec<Revision>>> {
        async move {
            match self.call(Op::ConfigHistory { limit: Some(200) }).await? {
                Response::History(h) => {
                    let mut revs: Vec<Revision> = h.into_iter().map(revision).collect();
                    revs.sort_by_key(|r| std::cmp::Reverse(r.id));
                    Ok(revs)
                }
                other => Err(unexpected(other)),
            }
        }
        .boxed()
    }

    fn diff(&self, from: u64, to: Option<u64>) -> BoxFuture<'_, ApiResult<Vec<DiffLine>>> {
        async move {
            let op = Op::ConfigDiff {
                from: Source::Revision(from),
                to: to.map_or(Source::Candidate, Source::Revision),
            };
            match self.call(op).await? {
                Response::Diff(d) => Ok(d
                    .unified
                    .lines()
                    .filter(|l| !l.starts_with("+++") && !l.starts_with("---"))
                    .map(|l| {
                        let (kind, text) = match l.split_at_checked(1) {
                            Some(("+", rest)) => (DiffKind::Added, rest),
                            Some(("-", rest)) => (DiffKind::Removed, rest),
                            Some((" ", rest)) => (DiffKind::Context, rest),
                            _ => (DiffKind::Context, l),
                        };
                        DiffLine {
                            kind,
                            text: text.to_owned(),
                        }
                    })
                    .collect()),
                other => Err(unexpected(other)),
            }
        }
        .boxed()
    }

    fn status(&self) -> BoxFuture<'_, ApiResult<SystemStatus>> {
        async move {
            let version = match self.call(Op::Status).await? {
                Response::Status(s) => format!("sensr {}", s.agent_version),
                other => return Err(unexpected(other)),
            };
            let doc = self.get("").await?;
            Ok(self.sampler.sample(&doc, &version))
        }
        .boxed()
    }

    fn nics(&self) -> BoxFuture<'_, ApiResult<Vec<sensr_ui::api::NetworkCard>>> {
        async move {
            match self.call(Op::Nics).await? {
                Response::Nics(n) => Ok(n
                    .into_iter()
                    .map(|n| sensr_ui::api::NetworkCard {
                        mac: n.pin_mac().to_owned(),
                        bus: match (&n.bus, &n.bus_path) {
                            (Some(b), Some(p)) => Some(format!("{b} {p}")),
                            (b, _) => b.clone(),
                        },
                        link: n.carrier.map(|c| (c, n.speed_mbps)),
                        name: n.name,
                        driver: n.driver,
                        assigned: n.assigned,
                    })
                    .collect()),
                other => Err(unexpected(other)),
            }
        }
        .boxed()
    }

    fn may_access(&self, url: &str) -> bool {
        self.state
            .registry
            .grants(self.caller.info.privileges.iter().map(String::as_str), url)
    }
}

/// UI logins over the API's session table.
pub struct UiSessions {
    state: Arc<AppState>,
    sampler: Arc<Sampler>,
}

impl UiSessions {
    /// Sessions for `state`.
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            sampler: Arc::new(Sampler::default()),
        }
    }
}

impl Sessions for UiSessions {
    fn login<'a>(&'a self, user: &'a str, password: &'a str) -> BoxFuture<'a, ApiResult<String>> {
        async move {
            let cred = Credential::Password {
                user: user.to_owned(),
                password: password.to_owned(),
            };
            let caller = verify(&self.state, cred, None)
                .await
                .map_err(|_| ApiError::Unauthorized)?;
            self.state
                .auth
                .open_session(caller)
                .map_err(|e| ApiError::Backend(e.message))
        }
        .boxed()
    }

    fn open<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Option<Session>> {
        let session = self.state.auth.session(token).map(|caller| Session {
            user: caller.info.user.clone(),
            backend: Arc::new(UiBackend {
                state: self.state.clone(),
                caller,
                sampler: self.sampler.clone(),
            }),
        });
        futures::future::ready(session).boxed()
    }

    fn logout<'a>(&'a self, token: &'a str) -> BoxFuture<'a, ()> {
        self.state.auth.close_session(token);
        futures::future::ready(()).boxed()
    }
}

/// Where the built UI assets live (`cargo leptos build` output: `pkg/sensr-ui.{js,wasm,css}`).
pub fn options(site_root: PathBuf) -> leptos::config::LeptosOptions {
    leptos::config::LeptosOptions::builder()
        .output_name("sensr-ui")
        .site_root(site_root.to_string_lossy().into_owned())
        .site_pkg_dir("pkg")
        .build()
}

/// The UI router for `state`.
pub fn router(state: Arc<AppState>, site_root: PathBuf) -> axum::Router {
    sensr_ui::server::router(options(site_root), Arc::new(UiSessions::new(state)))
}
