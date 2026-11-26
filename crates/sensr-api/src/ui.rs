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
    ApiError, ApiResult, Backend, ConfirmWindow, DiffKind, DiffLine, FieldError, LoginProvider,
    LoginStart, Pending, Revision, Session, Sessions, SystemStatus,
};
use sensr_ui::hoststats::Sampler;
use sensr_ui::runtime::RuntimeSection;
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
        confirm: None,
        confirm_reason: None,
    }
}

/// A commit's revision with the agent's confirm window and its reason.
fn committed(o: sensr_ipc::CommitOutcome) -> Revision {
    Revision {
        confirm: o.pending_confirm.map(|p| ConfirmWindow {
            revision: p.revision,
            deadline: u64::try_from(p.deadline_ms / 1000).unwrap_or(0),
        }),
        confirm_reason: o.confirm_reason,
        ..revision(o.revision)
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
        let alert = alert_text(&status);
        Ok(Pending {
            changed,
            confirm: status.pending_confirm.map(|p| ConfirmWindow {
                revision: p.revision,
                deadline: u64::try_from(p.deadline_ms / 1000).unwrap_or(0),
            }),
            now: now_secs(),
            alert,
        })
    }
}

/// The every-page banner: a first-boot seed that did not import, and the
/// last apply problem (a boot apply that held a daemon back, a commit that
/// was stored but not applied), one `Label: message` per line.
fn alert_text(status: &sensr_ipc::Status) -> Option<String> {
    let lines: Vec<String> = [
        status
            .seed_error
            .as_ref()
            .map(|e| format!("First-boot seed: {e}")),
        status
            .last_apply_error
            .as_ref()
            .map(|e| format!("Apply problem: {e}")),
    ]
    .into_iter()
    .flatten()
    .collect();
    (!lines.is_empty()).then(|| lines.join("\n"))
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
                Response::Committed(o) => Ok(committed(*o)),
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
                Response::Committed(o) => Ok(committed(*o)),
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

    fn scan_dir(&self) -> std::path::PathBuf {
        crate::portscan::dir()
    }

    fn scan_socket(&self) -> std::path::PathBuf {
        crate::portscan::socket()
    }

    fn guard_dir(&self) -> std::path::PathBuf {
        crate::guard::dir()
    }

    fn guard_socket(&self) -> std::path::PathBuf {
        crate::guard::socket()
    }

    fn may_access(&self, url: &str) -> bool {
        self.state
            .registry
            .grants(self.caller.info.privileges.iter().map(String::as_str), url)
    }

    fn runtime(&self, section: RuntimeSection) -> BoxFuture<'_, ApiResult<Value>> {
        async move {
            let section = match section {
                RuntimeSection::Gateways => sensr_ipc::RuntimeSection::Gateways,
                RuntimeSection::Aliases => sensr_ipc::RuntimeSection::Aliases,
                RuntimeSection::Ipv6 => sensr_ipc::RuntimeSection::Ipv6,
                RuntimeSection::Hosts => sensr_ipc::RuntimeSection::Hosts,
            };
            match self.call(Op::Runtime { section }).await? {
                Response::Value(v) => Ok(v.unwrap_or(Value::Null)),
                other => Err(unexpected(other)),
            }
        }
        .boxed()
    }

    fn host_activity(
        &self,
        mac: String,
        range: String,
        page: u32,
    ) -> BoxFuture<'_, ApiResult<sensr_ui::api::HostActivityView>> {
        async move {
            use sensr_ui::insight::{ActivityError, host_activity, local_offset};
            if !self.may_access("/api/v1/insight/top") || !self.may_access("/api/v1/hosts") {
                return Err(ApiError::Unauthorized);
            }
            if !matches!(range.as_str(), "today" | "7d") {
                return Err(ApiError::Validation(vec![FieldError::new(
                    "range",
                    "Range is today or 7d.",
                )]));
            }
            let hosts = self.runtime(RuntimeSection::Hosts).await?;
            let dir = self.insight_dir();
            let r = tokio::task::spawn_blocking(move || {
                let now = crate::insight::now();
                host_activity(&dir, hosts, &mac, &range, page, now, local_offset(now))
            })
            .await
            .map_err(|e| ApiError::Backend(e.to_string()))?;
            r.map_err(|e| match e {
                ActivityError::BadRange => {
                    ApiError::Validation(vec![FieldError::new("range", "Range is today or 7d.")])
                }
                ActivityError::UnknownHost => ApiError::NotFound("no such host".into()),
                ActivityError::Failed(m) => ApiError::Backend(m),
            })
        }
        .boxed()
    }

    fn forget_host(&self, key: String) -> BoxFuture<'_, ApiResult<()>> {
        async move {
            match self.call(Op::HostForget { key }).await? {
                Response::Value(_) => Ok(()),
                other => Err(unexpected(other)),
            }
        }
        .boxed()
    }

    fn set_host_mode(
        &self,
        mac: String,
        mode: Option<String>,
        remote: Option<std::net::IpAddr>,
    ) -> BoxFuture<'_, ApiResult<String>> {
        async move {
            use sensr_ipc::HostModeMode;
            let mode = match mode.as_deref() {
                None | Some("normal") => None,
                Some("isolated") => Some(HostModeMode::Isolated),
                Some("quarantine") => Some(HostModeMode::Quarantine),
                Some(other) => {
                    return Err(ApiError::Backend(format!("unknown host mode {other:?}")));
                }
            };
            let op = Op::HostModeSet {
                mac,
                mode,
                remote_addr: remote,
            };
            match self.call(op).await? {
                Response::Value(Some(v)) => match v.get("result").and_then(Value::as_str) {
                    Some(r) => Ok(r.to_owned()),
                    None => Err(ApiError::Backend(format!("unexpected agent reply {v}"))),
                },
                other => Err(unexpected(other)),
            }
        }
        .boxed()
    }

    fn set_host_label(
        &self,
        mac: String,
        kind: Option<String>,
        maker: Option<String>,
    ) -> BoxFuture<'_, ApiResult<String>> {
        async move {
            let kind = match kind.as_deref() {
                None | Some("") => None,
                Some(k) => Some(serde_json::from_value(Value::String(k.to_owned())).map_err(
                    |_| {
                        ApiError::Validation(vec![FieldError::new(
                            "kind",
                            format!("Unknown type {k:?}."),
                        )])
                    },
                )?),
            };
            let op = Op::HostLabelSet { mac, kind, maker };
            match self.call(op).await? {
                Response::Value(Some(v)) => match v.get("result").and_then(Value::as_str) {
                    Some(r) => Ok(r.to_owned()),
                    None => Err(ApiError::Backend(format!("unexpected agent reply {v}"))),
                },
                other => Err(unexpected(other)),
            }
        }
        .boxed()
    }

    fn set_service_override(
        &self,
        suffix: String,
        service: Option<String>,
        category: Option<String>,
    ) -> BoxFuture<'_, ApiResult<String>> {
        async move {
            let category = match category.as_deref() {
                None | Some("") => None,
                Some(c) => Some(serde_json::from_value(Value::String(c.to_owned())).map_err(
                    |_| {
                        ApiError::Validation(vec![FieldError::new(
                            "category",
                            format!("Unknown category {c:?}."),
                        )])
                    },
                )?),
            };
            let op = Op::ServiceOverrideSet {
                suffix,
                service,
                category,
            };
            match self.call(op).await? {
                Response::Value(Some(v)) => match v.get("result").and_then(Value::as_str) {
                    Some(r) => Ok(r.to_owned()),
                    None => Err(ApiError::Backend(format!("unexpected agent reply {v}"))),
                },
                other => Err(unexpected(other)),
            }
        }
        .boxed()
    }

    fn read_only(&self) -> bool {
        self.caller
            .info
            .privileges
            .iter()
            .any(|p| p == sensr_auth::acl::CONFIG_READONLY)
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
    fn login<'a>(
        &'a self,
        user: &'a str,
        password: &'a str,
        otp: Option<&'a str>,
    ) -> BoxFuture<'a, ApiResult<String>> {
        async move {
            let cred = Credential::Password {
                user: user.to_owned(),
                password: password.to_owned(),
                otp: otp.map(str::to_owned),
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

    fn passkey_register_start<'a>(
        &'a self,
        user: &'a str,
        user_uuid: &'a str,
        base: &'a str,
        exclude: &'a [String],
    ) -> BoxFuture<'a, ApiResult<Value>> {
        let result = crate::webauthn::register_start(&self.state, user_uuid, user, base, exclude);
        futures::future::ready(result.map_err(ui_oidc_error)).boxed()
    }

    fn passkey_register_finish<'a>(
        &'a self,
        user_uuid: &'a str,
        state: &'a str,
        credential: &'a Value,
        base: &'a str,
    ) -> BoxFuture<'a, ApiResult<Value>> {
        let result =
            crate::webauthn::register_finish(&self.state, user_uuid, state, credential, base);
        futures::future::ready(result.map_err(ui_oidc_error)).boxed()
    }

    fn passkey_login_start<'a>(&'a self, base: &'a str) -> BoxFuture<'a, ApiResult<Value>> {
        async move {
            crate::webauthn::login_start(&self.state, base)
                .await
                .map_err(ui_oidc_error)
        }
        .boxed()
    }

    fn passkey_login_finish<'a>(
        &'a self,
        state: &'a str,
        credential: &'a Value,
        base: &'a str,
        remote: Option<std::net::IpAddr>,
    ) -> BoxFuture<'a, ApiResult<String>> {
        async move {
            crate::webauthn::login_finish(&self.state, state, credential, base, remote)
                .await
                .map_err(ui_oidc_error)
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

    fn oidc_providers(&self) -> BoxFuture<'_, Vec<LoginProvider>> {
        async move {
            crate::oidc::providers(&self.state)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e.message, "cannot list OpenID Connect providers");
                    Vec::new()
                })
        }
        .boxed()
    }

    fn oidc_start<'a>(
        &'a self,
        provider: &'a str,
        callback: &'a str,
    ) -> BoxFuture<'a, ApiResult<String>> {
        async move {
            crate::oidc::begin(&self.state, provider, callback)
                .await
                .map_err(ui_oidc_error)
        }
        .boxed()
    }

    fn oidc_finish<'a>(
        &'a self,
        params: &'a std::collections::HashMap<String, String>,
        remote: Option<std::net::IpAddr>,
    ) -> BoxFuture<'a, ApiResult<String>> {
        async move {
            let caller = crate::oidc::finish(&self.state, params, remote)
                .await
                .map_err(ui_oidc_error)?;
            self.state
                .auth
                .open_session(caller)
                .map_err(|e| ApiError::Backend(e.message))
        }
        .boxed()
    }

    fn saml_providers(&self) -> BoxFuture<'_, Vec<LoginProvider>> {
        async move {
            crate::saml::providers(&self.state)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e.message, "cannot list SAML providers");
                    Vec::new()
                })
        }
        .boxed()
    }

    fn saml_start<'a>(
        &'a self,
        provider: &'a str,
        base: &'a str,
    ) -> BoxFuture<'a, ApiResult<LoginStart>> {
        async move {
            crate::saml::begin(&self.state, provider, base)
                .await
                .map(saml_started)
                .map_err(ui_oidc_error)
        }
        .boxed()
    }

    fn saml_finish<'a>(
        &'a self,
        provider: &'a str,
        fields: &'a std::collections::HashMap<String, String>,
        base: &'a str,
        remote: Option<std::net::IpAddr>,
    ) -> BoxFuture<'a, ApiResult<String>> {
        async move {
            let caller = crate::saml::finish(&self.state, provider, fields, base, remote)
                .await
                .map_err(ui_oidc_error)?;
            self.state
                .auth
                .open_session(caller)
                .map_err(|e| ApiError::Backend(e.message))
        }
        .boxed()
    }

    fn saml_metadata<'a>(
        &'a self,
        provider: &'a str,
        base: &'a str,
    ) -> BoxFuture<'a, ApiResult<String>> {
        async move {
            crate::saml::metadata(&self.state, provider, base)
                .await
                .map_err(ui_oidc_error)
        }
        .boxed()
    }
}

fn saml_started(started: crate::saml::Started) -> LoginStart {
    match started {
        crate::saml::Started::Redirect(url) => LoginStart::Redirect(url),
        crate::saml::Started::Form { action, fields } => LoginStart::Form { action, fields },
    }
}

/// An OIDC failure as the UI's error type: a refused login stays
/// `Unauthorized`, everything else is reported as a backend failure.
fn ui_oidc_error(e: crate::error::ApiError) -> ApiError {
    if e.status == axum::http::StatusCode::UNAUTHORIZED {
        ApiError::Unauthorized
    } else {
        ApiError::Backend(e.message)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_banner_shows_seed_and_apply_problems() {
        let mut st = sensr_ipc::Status {
            agent_version: String::new(),
            protocol: 1,
            uptime_secs: 0,
            head: None,
            applied: Some(1),
            candidate_dirty: false,
            pending_confirm: None,
            last_apply_error: None,
            seed_error: None,
        };
        assert_eq!(alert_text(&st), None);
        st.last_apply_error = Some("revision 1 applied at startup without part".into());
        assert_eq!(
            alert_text(&st).as_deref(),
            Some("Apply problem: revision 1 applied at startup without part")
        );
        st.seed_error = Some("config.xml did not validate".into());
        assert_eq!(
            alert_text(&st).unwrap().lines().collect::<Vec<_>>(),
            [
                "First-boot seed: config.xml did not validate",
                "Apply problem: revision 1 applied at startup without part"
            ]
        );
    }
}
