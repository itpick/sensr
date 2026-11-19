//! Server-side wiring: the axum router sensr-api mounts (and the dev server runs), the
//! session gate, and the theme cookie.

use crate::actions::{CurrentUser, SESSION_COOKIE};
use crate::api::SessionsHandle;
use crate::app::{App, shell};
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Redirect, Response};
use leptos::prelude::*;
use leptos_axum::{LeptosRoutes, generate_route_list};

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
        || path == "/ui/fn/login"
        || path.starts_with("/pkg/")
        || path == "/favicon.svg"
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
    Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        // Leptos names the wasm `<output>_bg.wasm` unless LEPTOS_OUTPUT_NAME was set when the
        // *server* was compiled (cargo-leptos does that; a plain `cargo build` of sensr-api
        // does not). Serve both names from the one file cargo-leptos writes.
        .route_service(
            &format!(
                "/{}/{}_bg.wasm",
                options.site_pkg_dir, options.output_name
            ),
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
        .with_state(options)
        .layer(middleware::from_fn_with_state(sessions, session_gate))
        .layer(middleware::from_fn(security_headers))
        .layer(tower_http::compression::CompressionLayer::new())
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
