//! OpenID Connect login (OPNsense Business Edition `system/auth` OIDC).
//!
//! sensr is the relying party: the provider (Zitadel, Google, Apple, any
//! standards-compliant issuer) authenticates the user, and this module checks
//! the ID token and hands the verified claims to the agent, which maps them
//! to a local group (see `sensr-agent`'s `auth::external`).
//!
//! The browser never sees a token. `begin` stores the state, nonce and PKCE
//! verifier in memory and redirects to the provider; `finish` exchanges the
//! code server-side, validates the ID token against the provider's JWKS and
//! opens a normal session. Apple's `form_post` callback is handled the same
//! way, with a client secret generated from the configured signing key.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use sensr_ipc::{ConfigPath, Credential, Op, Principal, Response, Source};
use sensr_schema::models::system::{Oidc, OidcProvider, OidcProviderKind};
use sensr_ui::api::LoginProvider;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::AppState;
use crate::auth::{Caller, verify};
use crate::error::ApiError;

/// How long an authorization may take before its state is forgotten.
const PENDING_TTL: Duration = Duration::from_secs(10 * 60);
/// How long fetched signing keys are reused.
const JWKS_TTL: Duration = Duration::from_secs(10 * 60);
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

/// In-flight authorizations and cached signing keys. Lives in [`AppState`] so
/// the API process is the only place a nonce or PKCE verifier exists.
pub struct OidcFlows {
    pending: Mutex<HashMap<String, Pending>>,
    jwks: Mutex<HashMap<String, (Vec<Jwk>, Instant)>>,
    http: reqwest::Client,
}

impl Default for OidcFlows {
    fn default() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            jwks: Mutex::new(HashMap::new()),
            http: reqwest::Client::builder()
                .timeout(HTTP_TIMEOUT)
                .user_agent(concat!("sensr/", env!("CARGO_PKG_VERSION")))
                .build()
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug)]
struct Pending {
    provider: String,
    nonce: String,
    verifier: String,
    callback: String,
    created: Instant,
}

#[derive(Debug, serde::Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
}

fn backend(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_GATEWAY, message)
}

fn unauthorized(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, message)
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Reads the whole candidate document as the API's own (read-only) identity.
/// Login happens before a user is signed in, so this cannot use a session.
async fn document(state: &AppState) -> Result<Value, ApiError> {
    let me = Principal {
        user: "sensr-api".into(),
        via: sensr_ipc::AuthMethod::Unix { uid: 0 },
        impersonated_by: None,
        readonly: true,
    };
    match state
        .agent
        .call(
            me,
            Op::ConfigGet {
                path: ConfigPath::root(),
                source: Source::Candidate,
            },
        )
        .await?
    {
        Response::Value(Some(v)) => Ok(v),
        Response::Value(None) => Ok(Value::Null),
        other => Err(backend(format!("unexpected agent reply {other:?}"))),
    }
}

/// The configured OIDC section, or its defaults.
async fn oidc(state: &AppState) -> Result<Oidc, ApiError> {
    let doc = document(state).await?;
    Ok(doc
        .pointer("/system/oidc")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default())
}

fn random_hex(bytes: usize) -> Result<String, ApiError> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf)
        .map_err(|_| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "no randomness"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// RFC 3986 unreserved characters stay; everything else is percent-encoded.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn query(params: &[(&str, &str)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

async fn discovery(state: &AppState, p: &OidcProvider) -> Result<Discovery, ApiError> {
    let issuer = p.issuer.as_str().trim_end_matches('/');
    let url = format!("{issuer}/.well-known/openid-configuration");
    let d: Discovery = state
        .oidc
        .http
        .get(&url)
        .send()
        .await
        .map_err(|e| backend(format!("cannot fetch {url}: {e}")))?
        .error_for_status()
        .map_err(|e| backend(format!("cannot fetch {url}: {e}")))?
        .json()
        .await
        .map_err(|e| backend(format!("bad discovery document at {url}: {e}")))?;
    // The issuer in the metadata must be the one we were configured with;
    // otherwise tokens from another issuer would validate.
    if d.issuer.trim_end_matches('/') != issuer {
        return Err(backend(format!(
            "discovery issuer {} does not match {}",
            d.issuer, issuer
        )));
    }
    Ok(d)
}

/// Providers offered on the login page, in name order.
pub async fn providers(state: &AppState) -> Result<Vec<LoginProvider>, ApiError> {
    let oidc = oidc(state).await?;
    Ok(oidc
        .active()
        .into_iter()
        .map(|(id, p)| LoginProvider {
            id: id.to_string(),
            name: p.name.clone(),
        })
        .collect())
}

/// Starts an authorization: returns the provider URL to redirect to.
pub async fn begin(state: &AppState, id: &str, callback: &str) -> Result<String, ApiError> {
    let oidc = oidc(state).await?;
    if !oidc.enabled {
        return Err(unauthorized("OpenID Connect is disabled"));
    }
    let p = oidc
        .provider(id)
        .filter(|p| p.enabled)
        .ok_or_else(|| unauthorized("unknown OpenID Connect provider"))?;
    let d = discovery(state, p).await?;
    let st = random_hex(24)?;
    let nonce = random_hex(16)?;
    let verifier = random_hex(32)?;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

    let scope = p.effective_scopes().join(" ");
    let mut params = vec![
        ("response_type", "code"),
        ("client_id", p.client_id.as_str()),
        ("redirect_uri", callback),
        ("scope", scope.as_str()),
        ("state", st.as_str()),
        ("nonce", nonce.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ];
    if p.kind == OidcProviderKind::Apple {
        // Apple requires form_post, which the callback route accepts.
        params.push(("response_mode", "form_post"));
    }
    let sep = if d.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    let url = format!("{}{sep}{}", d.authorization_endpoint, query(&params));

    let mut pending = state.oidc.pending.lock().unwrap_or_else(|e| e.into_inner());
    pending.retain(|_, p| p.created.elapsed() < PENDING_TTL);
    pending.insert(
        st,
        Pending {
            provider: id.to_owned(),
            nonce,
            verifier,
            callback: callback.to_owned(),
            created: Instant::now(),
        },
    );
    Ok(url)
}

/// The client secret to send, generating Apple's short-lived JWT when the
/// provider carries a signing key instead of a pasted secret.
fn client_secret(p: &OidcProvider) -> Result<Option<String>, ApiError> {
    if let Some(s) = &p.client_secret {
        return Ok(Some(s.expose().clone()));
    }
    if p.kind != OidcProviderKind::Apple {
        return Ok(None);
    }
    let (team, key_id, key) = match (&p.team_id, &p.key_id, &p.private_key) {
        (Some(t), Some(k), Some(pem)) => (t, k, pem.expose()),
        _ => return Ok(None),
    };
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(key_id.clone());
    let now = now_secs();
    let claims = serde_json::json!({
        "iss": team,
        "iat": now,
        "exp": now + 3000,
        "aud": "https://appleid.apple.com",
        "sub": p.client_id,
    });
    let key = EncodingKey::from_ec_pem(key.as_str().as_bytes())
        .map_err(|e| backend(format!("bad Apple signing key: {e}")))?;
    jsonwebtoken::encode(&header, &claims, &key)
        .map(Some)
        .map_err(|e| backend(format!("cannot sign Apple client secret: {e}")))
}

#[derive(Debug, serde::Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

async fn token(
    state: &AppState,
    p: &OidcProvider,
    d: &Discovery,
    code: &str,
    callback: &str,
    verifier: &str,
) -> Result<String, ApiError> {
    let secret = client_secret(p)?;
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", callback),
        ("code_verifier", verifier),
        ("client_id", p.client_id.as_str()),
    ];
    // Apple only accepts the secret in the body; otherwise prefer whatever
    // the provider advertises (basic is the default for confidential
    // clients).
    let methods = &d.token_endpoint_auth_methods_supported;
    let basic = p.kind != OidcProviderKind::Apple
        && secret.is_some()
        && (methods.iter().any(|m| m == "client_secret_basic") || methods.is_empty());
    if !basic && let Some(s) = &secret {
        form.push(("client_secret", s.as_str()));
    }
    let mut req = state.oidc.http.post(&d.token_endpoint).form(&form);
    if basic && let Some(s) = &secret {
        req = req.basic_auth(&p.client_id, Some(s));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| backend(format!("token request failed: {e}")))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| backend(format!("cannot read token response: {e}")))?;
    if !status.is_success() {
        // The body explains the failure (invalid_grant, …) and holds no
        // secret we did not already send.
        return Err(unauthorized(format!(
            "the provider refused the code: {status} {}",
            body.chars().take(300).collect::<String>()
        )));
    }
    let t: TokenResponse = serde_json::from_str(&body)
        .map_err(|e| backend(format!("unexpected token response: {e}")))?;
    t.id_token
        .filter(|s| !s.is_empty())
        .ok_or_else(|| backend("the token response has no id_token"))
}

async fn jwks(state: &AppState, uri: &str) -> Result<Vec<Jwk>, ApiError> {
    {
        let cache = state.oidc.jwks.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((keys, at)) = cache.get(uri)
            && at.elapsed() < JWKS_TTL
        {
            return Ok(keys.clone());
        }
    }
    let body: Value = state
        .oidc
        .http
        .get(uri)
        .send()
        .await
        .map_err(|e| backend(format!("cannot fetch signing keys: {e}")))?
        .error_for_status()
        .map_err(|e| backend(format!("cannot fetch signing keys: {e}")))?
        .json()
        .await
        .map_err(|e| backend(format!("bad JWKS at {uri}: {e}")))?;
    let keys: Vec<Jwk> = body
        .get("keys")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|k| serde_json::from_value(k.clone()).ok())
                .collect()
        })
        .unwrap_or_default();
    if keys.is_empty() {
        return Err(backend("the provider published no signing keys"));
    }
    state
        .oidc
        .jwks
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(uri.to_owned(), (keys.clone(), Instant::now()));
    Ok(keys)
}

fn algorithms() -> Vec<Algorithm> {
    vec![
        Algorithm::RS256,
        Algorithm::RS384,
        Algorithm::RS512,
        Algorithm::PS256,
        Algorithm::ES256,
        Algorithm::EdDSA,
    ]
}

/// Verifies the ID token signature, issuer, audience, lifetime and nonce;
/// returns its claims.
async fn validate_id_token(
    state: &AppState,
    p: &OidcProvider,
    d: &Discovery,
    token: &str,
    nonce: &str,
) -> Result<Value, ApiError> {
    let header =
        jsonwebtoken::decode_header(token).map_err(|_| unauthorized("malformed ID token"))?;
    if !algorithms().contains(&header.alg) {
        return Err(unauthorized("unsupported ID-token signature algorithm"));
    }
    let keys = jwks(state, &d.jwks_uri).await?;
    let candidates: Vec<&Jwk> = keys
        .iter()
        .filter(|k| match (&header.kid, &k.common.key_id) {
            (Some(want), Some(got)) => want == got,
            _ => true,
        })
        .collect();
    if candidates.is_empty() {
        return Err(unauthorized("the ID token names an unknown key"));
    }
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[p.issuer.as_str().trim_end_matches('/')]);
    validation.set_audience(&[p.client_id.as_str()]);
    validation.required_spec_claims.insert("sub".into());
    validation.leeway = 60;
    for key in candidates {
        let Ok(dk) = DecodingKey::from_jwk(key) else {
            continue;
        };
        if let Ok(data) = jsonwebtoken::decode::<Value>(token, &dk, &validation) {
            let claims = data.claims;
            if claims.get("nonce").and_then(Value::as_str) != Some(nonce) {
                return Err(unauthorized("the ID token was issued for another login"));
            }
            return Ok(claims);
        }
    }
    Err(unauthorized("the ID token signature is not valid"))
}

/// Completes an authorization: exchanges the code, validates the ID token and
/// returns the signed-in caller.
pub async fn finish(
    state: &AppState,
    params: &HashMap<String, String>,
    remote: Option<IpAddr>,
) -> Result<Caller, ApiError> {
    let st = params
        .get("state")
        .ok_or_else(|| unauthorized("the provider callback has no state"))?;
    let pending = state
        .oidc
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(st)
        .filter(|p| p.created.elapsed() < PENDING_TTL)
        .ok_or_else(|| unauthorized("the login expired; please try again"))?;
    if let Some(e) = params.get("error") {
        let desc = params.get("error_description").map_or("", String::as_str);
        return Err(unauthorized(format!("{e}: {desc}")));
    }
    let code = params
        .get("code")
        .filter(|c| !c.is_empty())
        .ok_or_else(|| unauthorized("the provider callback has no code"))?;

    let oidc = oidc(state).await?;
    let p = oidc
        .provider(&pending.provider)
        .filter(|p| p.enabled)
        .ok_or_else(|| unauthorized("the provider was removed during login"))?;
    let d = discovery(state, p).await?;
    let id_token = token(state, p, &d, code, &pending.callback, &pending.verifier).await?;
    let claims = validate_id_token(state, p, &d, &id_token, &pending.nonce).await?;
    verify(
        state,
        Credential::External {
            provider: pending.provider,
            claims: Box::new(claims),
        },
        remote,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn percent_encoding_covers_reserved_characters() {
        assert_eq!(encode("a b/c?d=e&f"), "a%20b%2Fc%3Fd%3De%26f");
        assert_eq!(
            encode("https://id.example.com/cb"),
            "https%3A%2F%2Fid.example.com%2Fcb"
        );
        assert_eq!(query(&[("a", "x y"), ("b", "~")]), "a=x%20y&b=~");
    }

    #[test]
    fn apple_secret_is_signed_with_the_configured_key() {
        // A P-256 test key (SEC1 PEM).
        let pem = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5kjWOBT+2wNkEshR\n\
dYzJXHfn1pWLuIJ7IQa8xX5T/NChRANCAAQwIkukgHD/mLtSnZp89dHStqFOtqtz\n\
hfprkzTHMcp8Ps52H8vYskJ7C0+FSL1mLyviQ2XsUqIVdL0LQ1xrybGG\n\
-----END PRIVATE KEY-----\n";
        let p = OidcProvider {
            kind: OidcProviderKind::Apple,
            enabled: true,
            name: "Apple".into(),
            issuer: "https://appleid.apple.com".parse().unwrap(),
            client_id: "com.example.sensr".into(),
            client_secret: None,
            team_id: Some("TEAM123456".into()),
            key_id: Some("KEY1234567".into()),
            private_key: Some(pem.parse::<sensr_schema::fields::Pem>().unwrap().into()),
            scopes: vec![],
            username_claim: "email".into(),
            groups_claim: None,
            allowed_groups: vec![],
            local_group: "admins".parse().unwrap(),
        };
        let secret = client_secret(&p).unwrap().unwrap();
        let header = jsonwebtoken::decode_header(&secret).unwrap();
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("KEY1234567"));
        let parts: Vec<_> = secret.split('.').collect();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "TEAM123456");
        assert_eq!(claims["sub"], "com.example.sensr");
    }
}
