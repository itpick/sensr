//! SAML 2.0 login (the OPNsense Business Edition has no equivalent).
//!
//! sensr is the service provider: the identity provider signs the assertion,
//! [`begin`] creates an `AuthnRequest` and stores the correlation state, and
//! [`finish`] validates the signed response and hands the mapped subject and
//! attributes to the agent, which applies the provider's claim→group mapping
//! (shared with OpenID Connect). The browser never sees the assertion's
//! signature check or the pending request state.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use axum::http::StatusCode;
use risaml::{
    AcsEndpoint, AssertionSignaturePolicy, AudienceValidationPolicy, AuthnRequestSigningPolicy,
    BrowserInput, Credentials, EntityId, FormField, IdpDescriptor, MetadataTrustPolicy,
    NameIdCreationPolicy, PendingAuthnRequest, RelayStateParam, ReplayPolicy,
    ResponseSignaturePolicy, Saml, SamlValidationContext, Sp, SpConfig, SpValidationPolicy,
    SsoResponse, StartSso,
};
use sensr_schema::models::system::{Saml as SamlConfig, SamlProvider};
use sensr_ui::api::LoginProvider;
use serde_json::{Map, Value};

use crate::AppState;
use crate::auth::{Caller, verify};
use crate::error::ApiError;

/// How long an authorization may take before its state is forgotten.
const PENDING_TTL: Duration = Duration::from_secs(10 * 60);

/// In-flight SAML authorizations, keyed by `RelayState`.
#[derive(Default)]
pub struct SamlFlows {
    pending: Mutex<HashMap<String, Pending>>,
}

#[derive(Debug)]
struct Pending {
    provider: String,
    request: PendingAuthnRequest,
    created: Instant,
}

/// What the browser should do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Started {
    /// Follow this URL (HTTP-Redirect binding).
    Redirect(String),
    /// POST these fields to this URL (HTTP-POST binding).
    Form {
        /// Form action.
        action: String,
        /// Hidden fields.
        fields: Vec<(String, String)>,
    },
}

fn backend(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::BAD_GATEWAY, message)
}

fn unauthorized(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, message)
}

fn config_error(e: risaml::SamlError) -> ApiError {
    backend(format!("SAML configuration is invalid: {e}"))
}

/// The configured SAML section, or its defaults.
async fn section(state: &AppState) -> Result<SamlConfig, ApiError> {
    let doc = crate::oidc::document(state).await?;
    Ok(doc
        .pointer("/system/saml")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default())
}

/// Providers offered on the login page, in name order.
pub async fn providers(state: &AppState) -> Result<Vec<LoginProvider>, ApiError> {
    let saml = section(state).await?;
    Ok(saml
        .active()
        .into_iter()
        .map(|(id, p)| LoginProvider {
            id: id.to_string(),
            name: p.name.clone(),
            start: format!("/ui/saml/start/{id}"),
        })
        .collect())
}

/// The SP configuration and the provider's parsed metadata.
fn service(
    provider: &SamlProvider,
    id: &str,
    base: &str,
) -> Result<(Saml<Sp>, IdpDescriptor), ApiError> {
    let entity = format!("{base}/ui/saml/metadata/{id}");
    // Requests are not signed, so no SP key is needed. Assertions must be
    // signed and the audience must match, which is the SP's core protection.
    let policy = SpValidationPolicy {
        assertions: AssertionSignaturePolicy::RequireSigned,
        responses: ResponseSignaturePolicy::RequireForEncryptedCbc,
        authn_requests: AuthnRequestSigningPolicy::DoNotSignForCompatibility,
        audience: AudienceValidationPolicy::Validate,
        name_id_creation: NameIdCreationPolicy::DoNotAllowCreate,
        logout: risaml::LogoutPolicy::compatibility(),
    };
    let config = SpConfig::builder(EntityId::try_new(entity).map_err(config_error)?)
        .acs_endpoint(AcsEndpoint::post(format!("{base}/ui/saml/acs/{id}")).map_err(config_error)?)
        .credentials(Credentials::default())
        .validation(policy)
        .build()
        .map_err(config_error)?;
    let sp = Saml::sp(config).map_err(config_error)?;
    let idp = IdpDescriptor::from_metadata_xml(
        provider.metadata.trim(),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
    .map_err(config_error)?;
    Ok((sp, idp))
}

/// Starts an authorization.
pub async fn begin(state: &AppState, id: &str, base: &str) -> Result<Started, ApiError> {
    let saml = section(state).await?;
    if !saml.enabled {
        return Err(unauthorized("SAML login is disabled"));
    }
    let provider = saml
        .provider(id)
        .filter(|p| p.enabled)
        .ok_or_else(|| unauthorized("unknown SAML provider"))?
        .clone();
    let (sp, idp) = service(&provider, id, base)?;

    let relay = crate::oidc::random_hex(24)?;
    let relay_param =
        RelayStateParam::try_from_option(Some(relay.clone())).map_err(config_error)?;
    // Prefer the redirect binding; fall back to POST when the provider
    // publishes only an HTTP-POST SSO endpoint.
    let started = match sp.start_sso(&idp, StartSso::redirect().relay_state(relay_param.clone())) {
        Ok(s) => s,
        Err(_) => sp
            .start_sso(&idp, StartSso::post().relay_state(relay_param))
            .map_err(config_error)?,
    };

    let action = if let Ok(url) = started.outbound.redirect_url() {
        Started::Redirect(url.to_owned())
    } else {
        let form = started.outbound.post_form().map_err(config_error)?;
        Started::Form {
            action: form.action().as_str().to_owned(),
            fields: form
                .fields()
                .iter()
                .map(|f| (f.name().to_owned(), f.value().to_owned()))
                .collect(),
        }
    };

    let mut pending = state.saml.pending.lock().unwrap_or_else(|e| e.into_inner());
    pending.retain(|_, p| p.created.elapsed() < PENDING_TTL);
    pending.insert(
        relay,
        Pending {
            provider: id.to_owned(),
            request: started.pending,
            created: Instant::now(),
        },
    );
    Ok(action)
}

/// The SP metadata the identity provider's administrator imports. It is
/// public: it carries no secret.
pub async fn metadata(state: &AppState, id: &str, base: &str) -> Result<String, ApiError> {
    let saml = section(state).await?;
    let provider = saml
        .provider(id)
        .filter(|p| p.enabled)
        .ok_or_else(|| unauthorized("unknown SAML provider"))?;
    let (sp, _) = service(provider, id, base)?;
    Ok(sp.metadata_xml().to_owned())
}

/// Completes an authorization from the ACS form fields.
pub async fn finish(
    state: &AppState,
    id: &str,
    fields: &HashMap<String, String>,
    base: &str,
    remote: Option<IpAddr>,
) -> Result<Caller, ApiError> {
    let relay = fields
        .get("RelayState")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| unauthorized("the SAML response has no RelayState"))?
        .clone();
    let pending = state
        .saml
        .pending
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&relay)
        .filter(|p| p.created.elapsed() < PENDING_TTL)
        .ok_or_else(|| unauthorized("the login expired; please try again"))?;
    if pending.provider != id {
        return Err(unauthorized("the SAML response is for another provider"));
    }

    let saml = section(state).await?;
    let provider = saml
        .provider(id)
        .filter(|p| p.enabled)
        .ok_or_else(|| unauthorized("the provider was removed during login"))?
        .clone();
    let (sp, idp) = service(&provider, id, base)?;

    let input: Vec<FormField> = fields
        .iter()
        .map(|(k, v)| FormField::new(k.as_str(), v.as_str()))
        .collect();
    // The pending request is removed above, so consuming it here is the
    // atomic replay check.
    let validation =
        SamlValidationContext::new(SystemTime::now(), ReplayPolicy::DisabledForCompatibility);
    let session = sp
        .finish_sso(
            &idp,
            &pending.request,
            BrowserInput::<SsoResponse>::post(input),
            validation,
        )
        .map_err(|e| unauthorized(format!("the SAML response was rejected: {e}")))?;

    let name_id = session.name_id().value().to_owned();
    let mut claims = Map::new();
    claims.insert("sub".into(), Value::String(name_id.clone()));
    let user_attr = provider.username_claim.trim();
    if !user_attr.is_empty() {
        let name = session
            .attributes()
            .get(user_attr)
            .and_then(|a| a.values().first())
            .map(|v| v.as_str().to_owned())
            .unwrap_or_else(|| name_id.clone());
        claims.insert(user_attr.to_owned(), Value::String(name));
    }
    if let Some(attr) = provider.groups_claim.as_deref().filter(|s| !s.is_empty()) {
        let groups: Vec<Value> = session
            .attributes()
            .get(attr)
            .map(|a| {
                a.values()
                    .iter()
                    .map(|v| Value::String(v.as_str().to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        claims.insert(attr.to_owned(), Value::Array(groups));
    }

    verify(
        state,
        sensr_ipc::Credential::External {
            provider: id.to_owned(),
            claims: Box::new(Value::Object(claims)),
        },
        remote,
    )
    .await
}
