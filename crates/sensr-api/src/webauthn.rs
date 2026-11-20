//! WebAuthn passkeys for local accounts.
//!
//! The browser performs the ceremony; this module issues the challenge,
//! remembers it server-side (replay protection), and verifies the signed
//! answer against the credential stored in the user object. On success the
//! agent only has to resolve the account's groups and privileges, because the
//! assertion already proved who the user is.
//!
//! A passkey is bound to the site's domain. The relying party id is therefore
//! derived from the URL the browser used; an origin whose host is a bare IP
//! address cannot host passkeys (browsers and the library both require a
//! hostname).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sensr_ipc::Credential;
use serde_json::{Value, json};
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Url, Uuid, Webauthn, WebauthnBuilder,
};

use crate::AppState;
use crate::auth::verify;
use crate::error::ApiError;

/// How long a challenge stays valid.
const PENDING_TTL: Duration = Duration::from_secs(5 * 60);

/// One ceremony waiting for the browser.
enum Pending {
    Register {
        user: String,
        state: PasskeyRegistration,
        at: Instant,
    },
    Authenticate {
        state: PasskeyAuthentication,
        credentials: Vec<StoredPasskey>,
        at: Instant,
    },
}

/// A passkey read from the configuration and the account it belongs to.
struct StoredPasskey {
    user: String,
    cred_id: Vec<u8>,
    key: Passkey,
}

/// In-flight ceremonies. Lives in [`AppState`] so the challenge never has to
/// travel to the browser and back.
#[derive(Default)]
pub struct WebauthnFlows {
    pending: Mutex<HashMap<String, Pending>>,
}

impl WebauthnFlows {
    fn insert(&self, id: String, pending: Pending) {
        let Ok(mut map) = self.pending.lock() else {
            return;
        };
        map.retain(|_, p| match p {
            Pending::Register { at, .. } | Pending::Authenticate { at, .. } => {
                at.elapsed() < PENDING_TTL
            }
        });
        map.insert(id, pending);
    }

    fn take(&self, id: &str) -> Option<Pending> {
        let pending = self.pending.lock().ok()?.remove(id)?;
        let at = match &pending {
            Pending::Register { at, .. } | Pending::Authenticate { at, .. } => at,
        };
        (at.elapsed() < PENDING_TTL).then_some(pending)
    }

    fn discard(&self, id: &str) {
        if let Ok(mut map) = self.pending.lock() {
            map.remove(id);
        }
    }
}

fn bad_request(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_REQUEST, message)
}

fn backend(e: impl std::fmt::Display) -> ApiError {
    ApiError::new(StatusCode::BAD_GATEWAY, format!("webauthn: {e}"))
}

fn new_id() -> String {
    let mut bytes = [0u8; 24];
    if getrandom::fill(&mut bytes).is_err() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        bytes[..8].copy_from_slice(&now.to_le_bytes());
    }
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The relying party for the origin `base` (scheme and host as the browser
/// sees them). Rejects origins that have no domain, such as a bare address.
fn relying_party(base: &str) -> Result<Webauthn, ApiError> {
    let origin = Url::parse(base).map_err(|e| bad_request(format!("invalid origin: {e}")))?;
    let host = origin
        .host_str()
        .ok_or_else(|| bad_request("the origin has no host"))?;
    let rp_id = host.to_owned();
    WebauthnBuilder::new(&rp_id, &origin)
        .map_err(|_| {
            bad_request(format!(
                "passkeys need the GUI's hostname, not the address {host}"
            ))
        })?
        .rp_name("sensr")
        .build()
        .map_err(backend)
}

/// Decodes an id the browser stored (base64url, unpadded).
fn decode_id(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).ok()
}

/// Starts registration for `user_uuid`, excluding passkeys the account
/// already has so an authenticator is not enrolled twice.
pub fn register_start(
    state: &AppState,
    user_uuid: &str,
    user_name: &str,
    base: &str,
    exclude: &[String],
) -> Result<Value, ApiError> {
    let webauthn = relying_party(base)?;
    let uuid = Uuid::parse_str(user_uuid)
        .map_err(|_| bad_request(format!("{user_uuid} is not a user id")))?;
    let exclude = exclude.iter().filter_map(|id| decode_id(id)).collect();
    let (options, registration) = webauthn
        .start_passkey_registration(uuid, user_name, user_name, Some(exclude))
        .map_err(backend)?;
    let id = new_id();
    state.webauthn.insert(
        id.clone(),
        Pending::Register {
            user: user_uuid.to_owned(),
            state: registration,
            at: Instant::now(),
        },
    );
    Ok(json!({"state": id, "options": options}))
}

/// Verifies the browser's registration response and returns the credential
/// object to store in the user's `passkeys` list.
pub fn register_finish(
    state: &AppState,
    user_uuid: &str,
    id: &str,
    credential: &Value,
    base: &str,
) -> Result<Value, ApiError> {
    let webauthn = relying_party(base)?;
    let Some(Pending::Register {
        user,
        state: pending,
        ..
    }) = state.webauthn.take(id)
    else {
        return Err(bad_request("the passkey registration expired; try again"));
    };
    if user != user_uuid {
        return Err(bad_request("the passkey belongs to another account"));
    }
    let credential: RegisterPublicKeyCredential = serde_json::from_value(credential.clone())
        .map_err(|e| bad_request(format!("invalid passkey response: {e}")))?;
    let passkey = webauthn
        .finish_passkey_registration(&credential, &pending)
        .map_err(backend)?;
    let credential: webauthn_rs::prelude::Credential = passkey.into();
    serde_json::to_value(credential).map_err(backend)
}

/// Reads every registered passkey from the candidate document.
fn stored_passkeys(doc: &Value) -> Vec<StoredPasskey> {
    let Some(users) = doc
        .get("system")
        .and_then(|s| s.get("users"))
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for user in users.values() {
        let Some(name) = user.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(passkeys) = user.get("passkeys").and_then(Value::as_array) else {
            continue;
        };
        for record in passkeys {
            let Some(credential) = record.get("credential") else {
                continue;
            };
            let Ok(credential) =
                serde_json::from_value::<webauthn_rs::prelude::Credential>(credential.clone())
            else {
                continue;
            };
            let key: Passkey = credential.into();
            out.push(StoredPasskey {
                user: name.to_owned(),
                cred_id: key.cred_id().clone(),
                key,
            });
        }
    }
    out
}

/// Starts a username-less passkey login. Returns `options: null` when no
/// account has a passkey yet.
pub async fn login_start(state: &AppState, base: &str) -> Result<Value, ApiError> {
    let webauthn = relying_party(base)?;
    let doc = crate::oidc::document(state).await?;
    let credentials = stored_passkeys(&doc);
    if credentials.is_empty() {
        return Ok(json!({"state": null, "options": null}));
    }
    let keys: Vec<Passkey> = credentials.iter().map(|c| c.key.clone()).collect();
    let (options, authentication) = webauthn
        .start_passkey_authentication(&keys)
        .map_err(backend)?;
    let id = new_id();
    state.webauthn.insert(
        id.clone(),
        Pending::Authenticate {
            state: authentication,
            credentials,
            at: Instant::now(),
        },
    );
    Ok(json!({"state": id, "options": options}))
}

/// Finishes a passkey login: verifies the assertion, resolves the account
/// with the agent and opens a session. Returns the session token.
pub async fn login_finish(
    state: &AppState,
    id: &str,
    credential: &Value,
    base: &str,
    remote: Option<IpAddr>,
) -> Result<String, ApiError> {
    let webauthn = relying_party(base)?;
    let Some(Pending::Authenticate {
        state: pending,
        credentials,
        ..
    }) = state.webauthn.take(id)
    else {
        return Err(bad_request("the passkey login expired; try again"));
    };
    let credential: PublicKeyCredential = serde_json::from_value(credential.clone())
        .map_err(|e| bad_request(format!("invalid passkey response: {e}")))?;
    let result = webauthn
        .finish_passkey_authentication(&credential, &pending)
        .map_err(backend)?;
    let Some(stored) = credentials.iter().find(|c| c.cred_id == *result.cred_id()) else {
        return Err(bad_request("the passkey does not belong to this site"));
    };
    let caller = verify(
        state,
        Credential::Passkey {
            user: stored.user.clone(),
        },
        remote,
    )
    .await?;
    state
        .auth
        .open_session(caller)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.message))
}

/// Drops a pending ceremony (the browser cancelled it).
pub fn cancel(state: &AppState, id: &str) {
    state.webauthn.discard(id);
}
