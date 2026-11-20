//! Server-side wiring: the axum router sensr-api mounts (and the dev server runs), the
//! session gate, and the theme cookie.

use crate::actions::{CurrentUser, SESSION_COOKIE};
use crate::api::SessionsHandle;
use crate::app::{App, shell};
use axum::Router;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{Request, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use leptos::prelude::*;
use leptos_axum::{LeptosRoutes, generate_route_list};
use std::collections::HashMap;

/// Reads one cookie from a `Cookie` header value.
pub fn cookie<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == name).then_some(v)
    })
}

fn request_cookie(parts: &axum::http::request::Parts, name: &str) -> Option<String> {
    parts
        .headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|h| cookie(h, name).map(str::to_owned))
}

/// The session token of the request being rendered, if any.
pub fn session_token() -> Option<String> {
    use_context::<axum::http::request::Parts>().and_then(|p| request_cookie(&p, SESSION_COOKIE))
}

/// Theme chosen by the user: `light`, `dark`, or `None` to follow the OS.
pub fn theme() -> Option<&'static str> {
    let parts = use_context::<axum::http::request::Parts>()?;
    match request_cookie(&parts, "sensr_theme")?.as_str() {
        "light" => Some("light"),
        "dark" => Some("dark"),
        _ => None,
    }
}

/// The signed-in user for the page being rendered.
pub fn current_user() -> Option<String> {
    use_context::<axum::http::request::Parts>()
        .and_then(|p| p.extensions.get::<CurrentUser>().map(|u| u.0.clone()))
}

fn is_public(path: &str) -> bool {
    path == "/login"
        || path.starts_with("/ui/fn/login")
        || path.starts_with("/ui/oidc/")
        || path.starts_with("/ui/saml/")
        || path.starts_with("/ui/fn/passkey/login/")
        || path.starts_with("/pkg/")
        || path == "/favicon.svg"
        || path == "/passkey.js"
        || path == "/healthz"
}

async fn session_gate(
    State(sessions): State<SessionsHandle>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let token = req
        .headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|h| cookie(h, SESSION_COOKIE).map(str::to_owned));
    let session = match token {
        Some(t) => sessions.open(&t).await,
        None => None,
    };
    match session {
        Some(s) => {
            req.extensions_mut().insert(CurrentUser(s.user));
            req.extensions_mut().insert(s.backend);
            next.run(req).await
        }
        None if is_public(req.uri().path()) => next.run(req).await,
        None if req.uri().path().starts_with("/ui/fn/") => {
            (axum::http::StatusCode::UNAUTHORIZED, "session required").into_response()
        }
        None => Redirect::to("/login").into_response(),
    }
}

/// Security headers every UI response carries. The CSP allows the wasm bundle and the inline
/// hydration bootstrap Leptos emits, nothing from other origins.
async fn security_headers(req: Request<Body>, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::X_FRAME_OPTIONS,
        header::HeaderValue::from_static("DENY"),
    );
    h.insert(
        header::REFERRER_POLICY,
        header::HeaderValue::from_static("same-origin"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        header::HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; \
             style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; \
             frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
    );
    res
}

/// The wasm file cargo-leptos wrote. Current builds name it `<output>_bg.wasm`,
/// which is exactly what the generated JS fetches; older layouts name it
/// `<output>.wasm`. Both spellings are served from the file that exists: a
/// route pointing at the missing spelling would shadow the real file and the
/// browser would fail to hydrate.
fn ui_wasm(pkg_dir: &std::path::Path, output_name: &str) -> std::path::PathBuf {
    let bg = pkg_dir.join(format!("{output_name}_bg.wasm"));
    if bg.is_file() {
        bg
    } else {
        pkg_dir.join(format!("{output_name}.wasm"))
    }
}

/// The public base URL of this GUI, as the browser (or a reverse proxy in
/// front of it) sees it. OIDC redirect URIs must match what the provider has
/// registered, so forwarded headers win over the connection's own.
pub(crate) fn external_base(headers: &axum::http::HeaderMap) -> String {
    let value = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|v| !v.is_empty())
    };
    let host = value("x-forwarded-host")
        .or_else(|| value("host"))
        .unwrap_or("localhost");
    let scheme = value("x-forwarded-proto").unwrap_or_else(|| {
        if host.ends_with(":80") || host.ends_with(":8080") {
            "http"
        } else {
            "https"
        }
    });
    format!("{scheme}://{host}")
}

async fn oidc_start(
    State(sessions): State<SessionsHandle>,
    Path(provider): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let callback = format!("{}/ui/oidc/callback", external_base(&headers));
    match sessions.oidc_start(&provider, &callback).await {
        Ok(url) => Redirect::to(&url).into_response(),
        Err(e) => {
            tracing::warn!(provider, error = %e, "cannot start OpenID Connect login");
            Redirect::to("/login?failed=oidc").into_response()
        }
    }
}

/// Finishes a login. Apple posts the response (`form_post`); every other
/// provider redirects with a query string, so both routes exist.
async fn oidc_finish(
    sessions: &SessionsHandle,
    params: HashMap<String, String>,
    remote: Option<std::net::IpAddr>,
) -> Response {
    match sessions.oidc_finish(&params, remote).await {
        Ok(token) => {
            let cookie = format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict");
            let mut res = Redirect::to("/").into_response();
            match axum::http::HeaderValue::from_str(&cookie) {
                Ok(v) => {
                    res.headers_mut().insert(header::SET_COOKIE, v);
                }
                Err(_) => return Redirect::to("/login?failed=oidc").into_response(),
            }
            res
        }
        Err(e) => {
            tracing::warn!(error = %e, "OpenID Connect login failed");
            Redirect::to("/login?failed=oidc").into_response()
        }
    }
}

async fn oidc_callback_get(
    State(sessions): State<SessionsHandle>,
    Query(params): Query<HashMap<String, String>>,
    connect: Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
) -> Response {
    let remote = connect.map(|axum::extract::Extension(axum::extract::ConnectInfo(a))| a.ip());
    oidc_finish(&sessions, params, remote).await
}

async fn oidc_callback_post(
    State(sessions): State<SessionsHandle>,
    connect: Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    axum::Form(params): axum::Form<HashMap<String, String>>,
) -> Response {
    let remote = connect.map(|axum::extract::Extension(axum::extract::ConnectInfo(a))| a.ip());
    oidc_finish(&sessions, params, remote).await
}

/// An invisible page that submits the SAML POST form. Providers such as
/// Entra ID publish only the HTTP-POST SSO binding.
fn post_page(action: &str, fields: &[(String, String)]) -> String {
    fn escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
    }
    let inputs: String = fields
        .iter()
        .map(|(k, v)| {
            format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                escape(k),
                escape(v)
            )
        })
        .collect();
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Redirecting…</title></head>\
         <body><form method=\"post\" action=\"{}\">{inputs}\
         <noscript><button type=\"submit\">Continue</button></noscript></form>\
         <script>document.forms[0].submit()</script></body></html>",
        escape(action)
    )
}

async fn saml_start(
    State(sessions): State<SessionsHandle>,
    Path(provider): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    use crate::api::LoginStart;
    let base = external_base(&headers);
    match sessions.saml_start(&provider, &base).await {
        Ok(LoginStart::Redirect(url)) => Redirect::to(&url).into_response(),
        Ok(LoginStart::Form { action, fields }) => {
            axum::response::Html(post_page(&action, &fields)).into_response()
        }
        Err(e) => {
            tracing::warn!(provider, error = %e, "cannot start SAML login");
            Redirect::to("/login?failed=saml").into_response()
        }
    }
}

async fn saml_acs(
    State(sessions): State<SessionsHandle>,
    Path(provider): Path<String>,
    headers: axum::http::HeaderMap,
    connect: Option<axum::extract::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    axum::Form(fields): axum::Form<HashMap<String, String>>,
) -> Response {
    let base = external_base(&headers);
    let remote = connect.map(|axum::extract::Extension(axum::extract::ConnectInfo(a))| a.ip());
    match sessions
        .saml_finish(&provider, &fields, &base, remote)
        .await
    {
        Ok(token) => {
            let cookie = format!("{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict");
            let mut res = Redirect::to("/").into_response();
            match axum::http::HeaderValue::from_str(&cookie) {
                Ok(v) => {
                    res.headers_mut().insert(header::SET_COOKIE, v);
                }
                Err(_) => return Redirect::to("/login?failed=saml").into_response(),
            }
            res
        }
        Err(e) => {
            tracing::warn!(provider, error = %e, "SAML login failed");
            Redirect::to("/login?failed=saml").into_response()
        }
    }
}

async fn saml_metadata(
    State(sessions): State<SessionsHandle>,
    Path(provider): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    let base = external_base(&headers);
    match sessions.saml_metadata(&provider, &base).await {
        Ok(xml) => (
            [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
            xml,
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(provider, error = %e, "cannot render SAML metadata");
            (axum::http::StatusCode::NOT_FOUND, "unknown provider").into_response()
        }
    }
}

/// The complete UI: pages, server functions, static assets and the session gate.
pub fn router(options: LeptosOptions, sessions: SessionsHandle) -> Router {
    let routes = generate_route_list(App);
    let ctx_sessions = sessions.clone();
    let site = std::path::PathBuf::from(options.site_root.as_ref());
    // Static assets are mounted explicitly: the UI's catch-all route would otherwise swallow
    // them. Hashless names, so revalidate rather than cache forever.
    let pkg_dir = site.join(options.site_pkg_dir.as_ref());
    let pkg = tower_http::services::ServeDir::new(&pkg_dir);
    let wasm = ui_wasm(&pkg_dir, &options.output_name);
    let oidc = Router::new()
        .route("/ui/oidc/start/{provider}", axum::routing::get(oidc_start))
        .route(
            "/ui/oidc/callback",
            axum::routing::get(oidc_callback_get).post(oidc_callback_post),
        )
        .route("/ui/saml/start/{provider}", axum::routing::get(saml_start))
        .route("/ui/saml/acs/{provider}", axum::routing::post(saml_acs))
        .route(
            "/ui/saml/metadata/{provider}",
            axum::routing::get(saml_metadata),
        )
        .with_state(sessions.clone());
    let app = Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        // Leptos names the wasm `<output>_bg.wasm` unless LEPTOS_OUTPUT_NAME was set when the
        // *server* was compiled (cargo-leptos does that; a plain `cargo build` of sensr-api
        // does not). Serve both names from the one file cargo-leptos writes.
        .route_service(
            &format!("/{}/{}_bg.wasm", options.site_pkg_dir, options.output_name),
            tower_http::services::ServeFile::new(wasm.clone()),
        )
        .route_service(
            &format!("/{}/{}.wasm", options.site_pkg_dir, options.output_name),
            tower_http::services::ServeFile::new(wasm),
        )
        .nest_service("/pkg", pkg)
        .route_service(
            "/favicon.svg",
            tower_http::services::ServeFile::new(site.join("favicon.svg")),
        )
        .leptos_routes_with_context(
            &options,
            routes,
            move || provide_context(ctx_sessions.clone()),
            {
                let o = options.clone();
                move || shell(o.clone())
            },
        )
        .fallback(leptos_axum::file_and_error_handler(shell))
        .layer(middleware::from_fn_with_state(sessions, session_gate))
        .layer(middleware::from_fn(security_headers))
        .layer(tower_http::compression::CompressionLayer::new())
        .with_state(options);
    app.merge(oidc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cookies() {
        assert_eq!(
            cookie("a=1; sensr_session=tok; b=2", "sensr_session"),
            Some("tok")
        );
        assert_eq!(cookie("a=1", "sensr_session"), None);
        assert!(is_public("/pkg/sensr-ui.wasm") && !is_public("/ui/firewall/alias"));
    }

    #[test]
    fn wasm_alias_follows_the_file_that_exists() {
        let dir = std::env::temp_dir().join(format!("sensr-ui-wasm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("app_bg.wasm"), b"wasm").unwrap();
        assert_eq!(ui_wasm(&dir, "app"), dir.join("app_bg.wasm"));
        // A build that only ships the plain name must still serve both spellings.
        std::fs::remove_file(dir.join("app_bg.wasm")).unwrap();
        std::fs::write(dir.join("app.wasm"), b"wasm").unwrap();
        assert_eq!(ui_wasm(&dir, "app"), dir.join("app.wasm"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
