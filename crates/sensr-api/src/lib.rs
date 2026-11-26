//! `sensr-api`, the unprivileged HTTP server (docs/PLAN.md §2.3): native
//! REST under `/api/v1`, an OPNsense compat façade under `/api/<module>/…`,
//! Basic (`user:password`, `key:secret`) and bearer-session auth, and
//! OPNsense ACL checks on every route. State lives in `sensr-agent`; this
//! process holds only sessions and a short credential cache.

pub mod agent;
pub mod auth;
pub mod compat;
pub mod error;
pub mod insight;
pub mod native;
pub mod oidc;
pub mod portscan;
pub mod saml;
pub mod tls;
pub mod ui;
pub mod webauthn;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::routing::{MethodRouter, get, post};
use sensr_auth::acl::Registry;

/// Shared server state.
pub struct AppState {
    /// Agent connections.
    pub agent: agent::AgentPool,
    /// Credential cache and sessions.
    pub auth: auth::AuthState,
    /// Privilege → URL patterns.
    pub registry: Registry,
    /// In-flight OpenID Connect authorizations and cached signing keys.
    pub oidc: oidc::OidcFlows,
    /// In-flight SAML authorizations.
    pub saml: saml::SamlFlows,
    /// In-flight WebAuthn ceremonies.
    pub webauthn: webauthn::WebauthnFlows,
}

impl AppState {
    /// State for an agent listening at `socket`.
    pub fn new(socket: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            agent: agent::AgentPool::new(socket),
            auth: auth::AuthState::default(),
            registry: Registry::builtin(),
            oidc: oidc::OidcFlows::default(),
            saml: saml::SamlFlows::default(),
            webauthn: webauthn::WebauthnFlows::default(),
        })
    }
}

type Route = (&'static str, fn() -> MethodRouter<Arc<AppState>>);

/// Every authenticated route. The ACL test (T-0368) walks this table, so a
/// route cannot be added without a privilege that covers it.
pub const ROUTES: &[Route] = &[
    ("/api/v1/status", || get(native::status)),
    ("/api/v1/status/{section}", || get(native::runtime)),
    ("/api/routes/gateway/status", || get(compat::gateway_status)),
    ("/api/v1/config/doc", || get(native::get_doc)),
    ("/api/v1/config/doc/{*path}", || {
        get(native::get_doc)
            .put(native::put_doc)
            .delete(native::delete_doc)
    }),
    ("/api/v1/config/discard", || post(native::discard)),
    ("/api/v1/config/commit", || post(native::commit)),
    ("/api/v1/config/confirm", || post(native::confirm)),
    ("/api/v1/config/rollback", || post(native::rollback)),
    ("/api/v1/config/history", || get(native::history)),
    ("/api/v1/config/diff", || get(native::diff)),
    ("/api/v1/apply/plan", || get(native::plan)),
    ("/api/v1/interfaces/nics", || get(native::nics)),
    ("/api/v1/interfaces/assign", || post(native::assign)),
    ("/api/v1/hosts", || get(native::hosts)),
    ("/api/v1/hosts/forget", || post(native::forget_host)),
    ("/api/v1/hosts/mode", || post(native::set_host_mode)),
    ("/api/v1/hosts/label", || post(native::set_host_label)),
    ("/api/v1/hosts/{mac}/activity", || {
        get(native::host_activity)
    }),
    ("/api/v1/insight/top", || get(insight::top)),
    ("/api/v1/insight/series", || get(insight::series)),
    ("/api/v1/insight/service-override", || {
        post(native::set_service_override)
    }),
    ("/api/v1/ids/alerts", || get(insight::alerts)),
    ("/api/v1/ids/signatures", || get(insight::signatures)),
    ("/api/v1/ids/stats", || get(insight::stats)),
    ("/api/v1/portscan/status", || get(portscan::status)),
    ("/api/v1/portscan/jobs", || get(portscan::jobs)),
    ("/api/v1/portscan/jobs/{id}", || get(portscan::job)),
    ("/api/v1/portscan/hosts/{mac}", || get(portscan::host)),
    ("/api/v1/portscan/start", || post(portscan::start)),
    ("/api/v1/portscan/cancel", || post(portscan::cancel)),
    ("/api/core/firmware/info", || get(compat::firmware_info)),
    ("/api/interfaces/overview/interfaces_info", || {
        get(compat::interfaces_info).post(compat::interfaces_info)
    }),
    ("/api/interfaces/overview/interfacesInfo", || {
        get(compat::interfaces_info).post(compat::interfaces_info)
    }),
    ("/api/firewall/alias/search_item", || {
        get(compat::alias_search).post(compat::alias_search)
    }),
    ("/api/firewall/alias/searchItem", || {
        get(compat::alias_search).post(compat::alias_search)
    }),
];

/// Routes reachable without credentials.
pub const PUBLIC_ROUTES: &[&str] = &["/api/v1/session"];

/// The full router.
pub fn router(state: Arc<AppState>) -> Router {
    let mut authed = Router::new();
    for (path, method) in ROUTES {
        authed = authed.route(path, method());
    }
    let authed = authed.layer(axum::middleware::from_fn_with_state(
        state.clone(),
        auth::require,
    ));
    Router::new()
        .route(
            "/api/v1/session",
            post(native::login).delete(native::logout),
        )
        .merge(authed)
        .with_state(state)
}

/// Serves on `listener` until `shutdown` resolves.
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<AppState>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    serve_with_ui(listener, state, None, shutdown).await
}

/// The API router, plus the web UI when `ui_root` (the built site with
/// `pkg/`) is given.
pub fn app(state: Arc<AppState>, ui_root: Option<PathBuf>) -> Router {
    let mut app = router(state.clone());
    if let Some(root) = ui_root {
        app = app.merge(ui::router(state, root));
    }
    app
}

/// Like [`serve`], plus the web UI when `ui_root` (the built site with `pkg/`) is given.
pub async fn serve_with_ui(
    listener: tokio::net::TcpListener,
    state: Arc<AppState>,
    ui_root: Option<PathBuf>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let app = app(state, ui_root);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(template: &str) -> String {
        template
            .split('/')
            .map(|seg| {
                if seg.starts_with("{*") {
                    "system/hostname"
                } else if seg.starts_with('{') {
                    "x"
                } else {
                    seg
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    }

    /// Every authenticated route is covered by a privilege other than
    /// `page-all` (OPNsense `dashboard-acl.sh` check 5).
    #[test]
    fn every_route_has_privilege_t0368() {
        let reg = Registry::builtin();
        for (template, _) in ROUTES {
            let url = sample(template);
            assert!(
                reg.covering(&url).is_some(),
                "route {template} ({url}) has no privilege"
            );
        }
        for p in PUBLIC_ROUTES {
            assert!(!ROUTES.iter().any(|(t, _)| t == p));
        }
    }
}
