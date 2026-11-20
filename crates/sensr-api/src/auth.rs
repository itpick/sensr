//! Authentication (Basic `user:password` / `key:secret`, session tokens) and
//! ACL authorization, decided here before a request reaches the agent
//! (docs/PLAN.md §2.3). The agent verifies credentials (hashes never leave
//! it); this side caches the result briefly so repeated API-key requests do
//! not pay a password-hash per call.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use sensr_auth::acl::CONFIG_READONLY;
use sensr_auth::apikey;
use sensr_ipc::{AuthInfo, AuthMethod, Credential, Op, Principal};

use crate::AppState;
use crate::error::ApiError;

/// How long a verified Basic credential is trusted without asking the agent.
pub const CREDENTIAL_CACHE_TTL: Duration = Duration::from_secs(60);
/// Idle lifetime of a session token.
pub const SESSION_TTL: Duration = Duration::from_secs(4 * 3600);
const CACHE_MAX: usize = 4096;

/// The authenticated caller, available to handlers as an extension.
#[derive(Debug, Clone)]
pub struct Caller {
    /// Identity and privileges from the agent.
    pub info: AuthInfo,
    /// How they authenticated.
    pub via: AuthMethod,
}

impl Caller {
    /// The principal to send with IPC requests.
    pub fn principal(&self) -> Principal {
        Principal {
            user: self.info.user.clone(),
            via: self.via.clone(),
            impersonated_by: None,
            readonly: self.info.privileges.iter().any(|p| p == CONFIG_READONLY),
        }
    }
}

#[derive(Default)]
struct Cache {
    entries: HashMap<[u8; 32], (Caller, Instant)>,
}

/// Credential cache and session table.
#[derive(Default)]
pub struct AuthState {
    basic: Mutex<Cache>,
    sessions: Mutex<HashMap<String, (Caller, Instant)>>,
}

impl AuthState {
    fn cached(&self, key: &[u8; 32]) -> Option<Caller> {
        let cache = self.basic.lock().unwrap_or_else(|e| e.into_inner());
        cache
            .entries
            .get(key)
            .filter(|(_, at)| at.elapsed() < CREDENTIAL_CACHE_TTL)
            .map(|(c, _)| c.clone())
    }

    fn remember(&self, key: [u8; 32], caller: Caller) {
        let mut cache = self.basic.lock().unwrap_or_else(|e| e.into_inner());
        if cache.entries.len() >= CACHE_MAX {
            cache
                .entries
                .retain(|_, (_, at)| at.elapsed() < CREDENTIAL_CACHE_TTL);
            if cache.entries.len() >= CACHE_MAX {
                cache.entries.clear();
            }
        }
        cache.entries.insert(key, (caller, Instant::now()));
    }

    /// Opens a session for `caller`, returning its bearer token.
    pub fn open_session(&self, caller: Caller) -> Result<String, ApiError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "no randomness"))?;
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|_, (_, at)| at.elapsed() < SESSION_TTL);
        sessions.insert(token.clone(), (caller, Instant::now()));
        Ok(token)
    }

    /// Ends a session.
    pub fn close_session(&self, token: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(token);
    }

    /// The caller behind a live session token (refreshes its idle timer).
    pub fn session(&self, token: &str) -> Option<Caller> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        match sessions.get_mut(token) {
            Some((caller, at)) if at.elapsed() < SESSION_TTL => {
                *at = Instant::now();
                Some(caller.clone())
            }
            Some(_) => {
                sessions.remove(token);
                None
            }
            None => None,
        }
    }
}

/// The bearer token in `Authorization: Bearer …`, if any.
pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

/// OPNsense API keys are 80 base64 characters; anything else in the user
/// half of Basic auth is a login name.
fn looks_like_api_key(user: &str) -> bool {
    user.len() >= 40
        && user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// Verifies `cred` with the agent.
pub async fn verify(
    state: &AppState,
    cred: Credential,
    remote: Option<IpAddr>,
) -> Result<Caller, ApiError> {
    let via = match &cred {
        Credential::Password { .. } => AuthMethod::Password,
        Credential::ApiKey { key, .. } => AuthMethod::ApiKey { key: key.clone() },
        Credential::External { provider, .. } => AuthMethod::External {
            provider: provider.clone(),
        },
        Credential::Passkey { .. } => AuthMethod::Passkey,
    };
    // The API's own identity on the socket; the agent trusts it by peer uid.
    let me = Principal {
        user: "sensr-api".into(),
        via: AuthMethod::Unix { uid: 0 },
        impersonated_by: None,
        readonly: true,
    };
    match state
        .agent
        .call(
            me,
            Op::Authenticate {
                credential: cred,
                remote_addr: remote,
            },
        )
        .await?
    {
        sensr_ipc::Response::Authenticated(info) => Ok(Caller { info, via }),
        other => Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("unexpected reply {other:?}"),
        )),
    }
}

fn unauthorized() -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, "authentication required")
}

/// Middleware: authenticate, then authorize the request path against the
/// caller's privileges.
pub async fn require(
    State(state): State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let remote = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(a)| a.ip());
    let headers = req.headers();
    let caller = if let Some(token) = bearer(headers) {
        state.auth.session(token).ok_or_else(unauthorized)?
    } else {
        let raw = headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(unauthorized)?;
        // Key the cache by a hash of the header (and client address, which
        // group source networks depend on) so secrets are never stored.
        let mut hasher = blake3::Hasher::new();
        hasher.update(raw.as_bytes());
        hasher.update(format!("{remote:?}").as_bytes());
        let key: [u8; 32] = hasher.finalize().into();
        match state.auth.cached(&key) {
            Some(c) => c,
            None => {
                let (user, secret) = apikey::parse_basic(raw).ok_or_else(unauthorized)?;
                let cred = if looks_like_api_key(&user) {
                    Credential::ApiKey { key: user, secret }
                } else {
                    Credential::Password {
                        user,
                        password: secret,
                        otp: None,
                    }
                };
                let c = verify(&state, cred, remote).await.map_err(|e| {
                    if e.status == StatusCode::UNAUTHORIZED {
                        unauthorized()
                    } else {
                        e
                    }
                })?;
                state.auth.remember(key, c.clone());
                c
            }
        }
    };
    let path = req.uri().path();
    let allowed = state
        .registry
        .grants(caller.info.privileges.iter().map(String::as_str), path);
    if !allowed {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            format!("{} may not access {path}", caller.info.user),
        ));
    }
    req.extensions_mut().insert(caller);
    Ok(next.run(req).await)
}
