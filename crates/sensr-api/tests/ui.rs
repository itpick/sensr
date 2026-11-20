//! The web UI served by `sensr-api` in front of a real `sensr-agent`: login through the UI,
//! server-rendered pages from agent data, and the shared session table (a UI login is a valid
//! API bearer token).

use std::os::unix::fs::MetadataExt;

use sensr_agent::applier::FakeApplier;
use sensr_agent::{Agent, Running, Settings};
use sensr_auth::password::hash_password;
use sensr_ipc::{Client, Op, Principal};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Fx {
    _dir: tempfile::TempDir,
    addr: std::net::SocketAddr,
    _agent: Running,
}

async fn start() -> Fx {
    start_with(Vec::new()).await
}

/// Starts the agent and UI with the standard seed plus `extra` config paths
/// (for example the OIDC section of a test).
async fn start_with(extra: Vec<(&str, serde_json::Value)>) -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let me = std::fs::metadata(dir.path()).unwrap().uid();
    let settings = Settings {
        trusted_uids: vec![me],
        ..Settings::default()
    };
    let agent = Agent::new(
        sensr_agent::store::in_memory(),
        FakeApplier::default(),
        settings,
    )
    .unwrap();
    agent.boot().await.unwrap();
    let socket = dir.path().join("agent.sock");
    let running = sensr_agent::start(agent, &socket, 0o600, None).unwrap();
    let mut c = Client::connect(&socket, Principal::unix("seed", 0))
        .await
        .unwrap();
    let mut seeds = vec![
        ("system.hostname", json!("fw")),
        ("system.domain", json!("example.org")),
        ("interfaces.lan.description", json!("LAN")),
        (
            "system.groups.6f0c6f9e-0000-4000-8000-000000000101",
            json!({"name": "admins", "gid": 1999, "privileges": ["page-all"]}),
        ),
        (
            "system.users.6f0c6f9e-0000-4000-8000-000000000001",
            json!({"name": "admin", "uid": 0, "groups": ["admins"],
                   "password_hash": hash_password("adminpw").unwrap()}),
        ),
        (
            "firewall.aliases.0c5e2a3e-0000-4000-a000-000000000001",
            json!({"enabled": true, "name": "nas",
                   "content": {"type": "host", "entries": ["192.168.1.10"]},
                   "description": "File server"}),
        ),
    ];
    seeds.extend(extra);
    for (path, value) in seeds {
        c.call(Op::ConfigSet {
            path: path.parse().unwrap(),
            value,
        })
        .await
        .unwrap();
    }
    c.call(Op::ConfigCommit {
        description: Some("seed".into()),
        confirm_secs: None,
    })
    .await
    .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = sensr_api::AppState::new(socket);
    let site = dir.path().join("site");
    std::fs::create_dir_all(site.join("pkg")).unwrap();
    // What cargo-leptos writes; the generated JS fetches this exact name.
    std::fs::write(site.join("pkg/sensr-ui_bg.wasm"), b"wasm-bytes").unwrap();
    tokio::spawn(sensr_api::serve_with_ui(
        listener,
        state,
        Some(site),
        std::future::pending(),
    ));
    Fx {
        _dir: dir,
        addr,
        _agent: running,
    }
}

/// One HTTP/1.1 request; returns status, raw headers and body.
async fn http(
    fx: &Fx,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, String, String) {
    let mut s = TcpStream::connect(fx.addr).await.unwrap();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n");
    for (k, v) in headers {
        req += &format!("{k}: {v}\r\n");
    }
    if !body.is_empty() {
        req += &format!("Content-Length: {}\r\n", body.len());
    }
    req += "\r\n";
    req += body;
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status: u16 = text[9..12].parse().unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    (status, head.to_owned(), body.to_owned())
}

fn session_cookie(head: &str) -> Option<String> {
    head.lines()
        .filter(|l| l.to_ascii_lowercase().starts_with("set-cookie:"))
        .find_map(|l| l.split_once(':')?.1.trim().strip_prefix("sensr_session="))
        .map(|v| v.split(';').next().unwrap_or_default().to_owned())
        .filter(|t| !t.is_empty())
}

async fn login(fx: &Fx, user: &str, pass: &str) -> (u16, String) {
    let body = format!("username={user}&password={pass}");
    let (status, head, _) = http(
        fx,
        "POST",
        "/ui/fn/login",
        &[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Accept", "text/html"),
        ],
        &body,
    )
    .await;
    (status, head)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_wasm_bundle_is_served_under_its_built_name() {
    let fx = start().await;
    // The hydration script fetches `/pkg/sensr-ui_bg.wasm`; a route mapping
    // that name to a file that does not exist broke every island's JS.
    let (status, head, body) = http(&fx, "GET", "/pkg/sensr-ui_bg.wasm", &[], "").await;
    assert_eq!(status, 200, "{head}");
    assert_eq!(body, "wasm-bytes");
    let (status, _, body) = http(&fx, "GET", "/pkg/sensr-ui.wasm", &[], "").await;
    assert_eq!(status, 200, "the plain alias must work too");
    assert_eq!(body, "wasm-bytes");
}

#[tokio::test(flavor = "multi_thread")]
async fn ui_requires_login_and_redirects() {
    let fx = start().await;
    let (status, head, _) = http(&fx, "GET", "/ui/firewall/alias", &[], "").await;
    assert_eq!(status, 303, "{head}");
    assert!(
        head.to_ascii_lowercase().contains("location: /login"),
        "{head}"
    );
    let (status, _, body) = http(&fx, "GET", "/login", &[], "").await;
    assert_eq!(status, 200);
    assert!(body.contains(r#"action="/ui/fn/login""#), "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_password_is_refused() {
    let fx = start().await;
    let (_, head) = login(&fx, "admin", "nope").await;
    assert!(session_cookie(&head).is_none(), "{head}");
    assert!(head.contains("/login?failed=1"), "{head}");
}

#[tokio::test(flavor = "multi_thread")]
async fn ui_login_renders_agent_data_and_shares_the_session() {
    let fx = start().await;
    let (_, head) = login(&fx, "admin", "adminpw").await;
    let token = session_cookie(&head).expect("session cookie");
    let cookie = format!("sensr_session={token}");

    let (status, _, body) =
        http(&fx, "GET", "/ui/firewall/alias", &[("Cookie", &cookie)], "").await;
    assert_eq!(status, 200);
    assert!(body.contains("Firewall: Aliases"), "page title");
    assert!(
        body.contains("File server"),
        "alias row from the agent's candidate document"
    );
    assert!(
        body.contains("[LAN]"),
        "menu entry for the agent's interface"
    );

    let (status, _, body) = http(
        &fx,
        "GET",
        "/ui/core/backup/history",
        &[("Cookie", &cookie)],
        "",
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        body.contains(">seed<"),
        "revision from the agent's history: {body}"
    );

    // The UI session is an API session too.
    let bearer = format!("Bearer {token}");
    let (status, _, _) = http(
        &fx,
        "GET",
        "/api/v1/status",
        &[("Authorization", &bearer)],
        "",
    )
    .await;
    assert_eq!(status, 200);

    let (_, _, _) = http(
        &fx,
        "POST",
        "/ui/fn/logout",
        &[("Cookie", &cookie), ("Accept", "text/html")],
        "",
    )
    .await;
    let (status, _, _) = http(
        &fx,
        "GET",
        "/api/v1/status",
        &[("Authorization", &bearer)],
        "",
    )
    .await;
    assert_eq!(status, 401, "logout ends the shared session");
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_pages_render_without_runtime_data() {
    // The fake applier reports no gateway monitor, feeds or prefix delegation: the pages
    // still render, saying there is nothing to show.
    let fx = start().await;
    let (_, head) = login(&fx, "admin", "adminpw").await;
    let cookie = format!("sensr_session={}", session_cookie(&head).unwrap());
    for (path, title, expect) in [
        (
            "/ui/routing/status",
            "System: Gateways: Status",
            "No gateways are monitored.",
        ),
        (
            "/ui/interfaces/overview",
            "Interfaces: Overview",
            "No interface requests a delegated prefix.",
        ),
        ("/", "Lobby: Dashboard", "No gateway data."),
        ("/ui/firewall/alias", "Firewall: Aliases", "Last updated"),
    ] {
        let (status, _, body) = http(&fx, "GET", path, &[("Cookie", &cookie)], "").await;
        assert_eq!(status, 200, "{path}");
        assert!(body.contains(title), "{path}: title");
        assert!(body.contains(expect), "{path}: {body}");
    }
}

// ---------------------------------------------------------------- OpenID Connect

/// A minimal standards-shaped identity provider: discovery, signing keys and
/// a token endpoint that mints an RS256 ID token for whatever nonce the test
/// read from the authorization redirect.
mod idp {
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde_json::{Value, json};

    use super::{Fx, http, session_cookie, start_with};

    /// A throwaway 2048-bit RSA key; its public half is [`JWKS`].
    const KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDDjvHjtFcwrtGJ\n\
2SQtDZF1IhyxaEt8ZZ1NsU4/EPHR8gQp8ImWxmS/wG41T/lJl5S4S65h2PrRbIdJ\n\
W+wOU9le+xcm8ybsKUNJrtLWTi4AibVCCldwvlAiIS33iLANAcP3SUyNyjN5O4VC\n\
7b4wrN1oVgRRgpg0JGmbqQXcZoG6Y3Bn0bSWEPSU5FPfVwdr2D/+G0ztDy4O9hOY\n\
flQMscVtHnRfiig72qOibdqjCymPaAcy7heKvCEL5pBubInhBb5tx5RBvMpG0UZF\n\
xJ3izthVfwlsp3t92eVCyW1+W3zJLBH5usAGnGg2f3Tj3Kl0yyX17q0VhJTEqQMO\n\
UFo5l2ZDAgMBAAECggEAPYiFkVYmF0Hy2fKy4OBDlD1TFPmRwwdAS3mOeuasiJij\n\
+cRfrssnWXTF2M2czay+FY1uxggdx/bjzM/5Q3rby3irjMx2w1mqfA1f9yHrdKzg\n\
FXMml2my0kJpcdmXN8iF7pIoXfcxYiS55ljjfvJtyo5CVpmGpeWNO3cgSn0QteJW\n\
KSNxc7XFbr8Zgq0JsCixu6HbYBMSPB3mr7FDGs1oElH5hV96AJg/ynNKExn+bHiA\n\
u/y+qSYyEZCmyFfYW2hrl5sxBC1XpSaRYoRZbUNhC2TEK5szB5VDEdoVRKJzgxYP\n\
JfoM86QMHyJyNjFyRpTqyg1y/E9Nr8MPGb8XD83mOQKBgQDtG+6jeW3NvLD5HuWd\n\
8SlNwzxeJW5jMUhfEXCVkqdElIc6xEer1UrSlJ41kO0kkmnAw4AxkDfTlrsdTK0e\n\
VlnAKqNJEGoMKshVDcGAHfEYgFx7grTBuj8IOVZOhEd0LceNzG7sPLYutjQ4F3bn\n\
VUvSofe/DpzEXrF/Eju5za6bawKBgQDTI4uwLGglJ+46mHAEYauQjpXGjWZa1m1L\n\
4XLSvf17evSxl4XnJ+kG1HTVnJwKzgTL2ErjbcQdffmSPfBZKMaosmaYujRJWPrd\n\
NLz1PcoWbLPf38nphKLn7Dsc24fDcM+a0FeaY5y/bG++Ug882x+k+guchjwTX0wg\n\
Xn+KVOsuiQKBgQDGlsB2trtat5FZ9aDHejbn5H9pMtyTw7Ejvs2W2O+zptrkQ4Tr\n\
zIcQfF1N7AZSvTZJtvRljq7TTsmFLrVIVXZyVsPP7CmF60dCxXStw2Ys6UWMRNrz\n\
7vPgBXXd6TiXe8hJYVH+FpNX6E8wM6bo9i29St7fbHOsnMr47OKNKlH15QKBgFyB\n\
1HAp5K9y4VPW+i1RRcQeVM0bot7l2BlI+/ANwgPaCV/ODaMLv3N4noABD/VD8qIF\n\
cDpZG3X4feJvNOE7ll7PW1hLLSF91NwagTfKDMLqeZz7BhJERMPsorGwFbmxsaQY\n\
6GkCf+j277apaXe2YhT8YR4BSk0KkeYUwTiwoCJRAoGAMHFl0EfqyPC2Zceq/NJO\n\
OybHs166ATPBNEydyWsORzdYNZpgEYDEcMNTJzj+ynasLOyKBlTP84Cyf4XnFyrj\n\
clcWLvhwkizSg5Yi4cXfNz9YU6vL9ZUAXb58mmJe0b43DBVT7RSITycsHo2v1q75\n\
mGWNlURy7cjilln3skSzPHM=\n\
-----END PRIVATE KEY-----\n";

    const JWKS: &str = r#"{"keys":[{"kty":"RSA","kid":"test-key","use":"sig","alg":"RS256","n":"w47x47RXMK7RidkkLQ2RdSIcsWhLfGWdTbFOPxDx0fIEKfCJlsZkv8BuNU_5SZeUuEuuYdj60WyHSVvsDlPZXvsXJvMm7ClDSa7S1k4uAIm1QgpXcL5QIiEt94iwDQHD90lMjcozeTuFQu2-MKzdaFYEUYKYNCRpm6kF3GaBumNwZ9G0lhD0lORT31cHa9g__htM7Q8uDvYTmH5UDLHFbR50X4ooO9qjom3aowspj2gHMu4XirwhC-aQbmyJ4QW-bceUQbzKRtFGRcSd4s7YVX8JbKd7fdnlQsltflt8ySwR-brABpxoNn9049ypdMsl9e6tFYSUxKkDDlBaOZdmQw","e":"AQAB"}]}"#;

    #[derive(Clone)]
    pub struct Idp {
        pub issuer: String,
        state: Arc<Mutex<Identity>>,
    }

    #[derive(Default)]
    struct Identity {
        nonce: String,
        email: String,
        groups: Vec<String>,
    }

    impl Idp {
        pub async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let issuer = format!("http://{}", listener.local_addr().unwrap());
            let idp = Self {
                issuer: issuer.clone(),
                state: Arc::new(Mutex::new(Identity::default())),
            };
            let app = Router::new()
                .route("/.well-known/openid-configuration", get(discovery))
                .route("/jwks", get(jwks))
                .route("/token", post(token))
                .with_state(idp.clone());
            tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            idp
        }

        pub fn set_identity(&self, nonce: &str, email: &str, groups: &[&str]) {
            let mut s = self.state.lock().unwrap();
            s.nonce = nonce.to_owned();
            s.email = email.to_owned();
            s.groups = groups.iter().map(|g| (*g).to_owned()).collect();
        }
    }

    async fn discovery(State(idp): State<Idp>) -> Json<Value> {
        Json(json!({
            "issuer": idp.issuer,
            "authorization_endpoint": format!("{}/authorize", idp.issuer),
            "token_endpoint": format!("{}/token", idp.issuer),
            "jwks_uri": format!("{}/jwks", idp.issuer),
            "response_types_supported": ["code"],
            "token_endpoint_auth_methods_supported": ["none"],
        }))
    }

    async fn jwks() -> Json<Value> {
        Json(serde_json::from_str(JWKS).unwrap())
    }

    async fn token(State(idp): State<Idp>) -> Json<Value> {
        let (nonce, email, groups) = {
            let s = idp.state.lock().unwrap();
            (s.nonce.clone(), s.email.clone(), s.groups.clone())
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key".to_owned());
        let claims = json!({
            "iss": idp.issuer,
            "aud": "sensr-test",
            "sub": "subject-1",
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
            "email": email,
            "groups": groups,
        });
        let key = EncodingKey::from_rsa_pem(KEY.as_bytes()).unwrap();
        let id_token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
        Json(json!({"id_token": id_token, "token_type": "Bearer", "expires_in": 300}))
    }

    fn location(head: &str) -> String {
        head.lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                (k.eq_ignore_ascii_case("location")).then(|| v.trim().to_owned())
            })
            .expect("redirect Location")
    }

    fn param(url: &str, name: &str) -> String {
        url.split_once('?')
            .map(|(_, q)| q)
            .unwrap_or("")
            .split('&')
            .find_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                (k == name).then(|| v.to_owned())
            })
            .unwrap_or_else(|| panic!("no {name} in {url}"))
    }

    /// Starts a login and returns the provider URL the browser would follow.
    async fn begin(fx: &Fx, provider: &str) -> String {
        let (status, head, _) =
            http(fx, "GET", &format!("/ui/oidc/start/{provider}"), &[], "").await;
        assert_eq!(status, 303, "{head}");
        location(&head)
    }

    async fn oidc_fixture(idp: &Idp, allowed: &[&str]) -> (Fx, String) {
        let provider = "6f0c6f9e-0000-4000-8000-000000000201".to_owned();
        let path = format!("system.oidc.providers.{provider}");
        let fx = start_with(vec![
            ("system.oidc.enabled", json!(true)),
            (
                path.as_str(),
                json!({
                    "kind": "generic",
                    "enabled": true,
                    "name": "Test IdP",
                    "issuer": idp.issuer,
                    "client_id": "sensr-test",
                    "username_claim": "email",
                    "groups_claim": "groups",
                    "allowed_groups": allowed,
                    "local_group": "admins",
                }),
            ),
        ])
        .await;
        (fx, provider)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oidc_login_opens_a_session_from_verified_claims() {
        let idp = Idp::start().await;
        let (fx, provider) = oidc_fixture(&idp, &["fw-admins"]).await;

        // The login page offers the configured provider.
        let (status, _, body) = http(&fx, "GET", "/login", &[], "").await;
        assert_eq!(status, 200);
        assert!(body.contains("Sign in with Test IdP"), "{body}");

        let url = begin(&fx, &provider).await;
        assert!(
            url.starts_with(&format!("{}/authorize?", idp.issuer)),
            "{url}"
        );
        // The authorization request carries a nonce and a PKCE challenge.
        assert!(url.contains("code_challenge_method=S256"), "{url}");
        let state = param(&url, "state");
        let nonce = param(&url, "nonce");

        idp.set_identity(&nonce, "ops@example.com", &["fw-admins"]);
        let (status, head, _) = http(
            &fx,
            "GET",
            &format!("/ui/oidc/callback?code=code-1&state={state}"),
            &[],
            "",
        )
        .await;
        assert_eq!(status, 303, "{head}");
        let token = session_cookie(&head).expect("the callback opens a session");
        let cookie = format!("sensr_session={token}");

        // The mapped group's privileges (page-all) work on the UI and the API.
        let (status, _, body) =
            http(&fx, "GET", "/ui/firewall/alias", &[("Cookie", &cookie)], "").await;
        assert_eq!(status, 200);
        assert!(body.contains("File server"), "{body}");
        let (status, _, _) = http(
            &fx,
            "GET",
            "/api/v1/status",
            &[("Authorization", &format!("Bearer {token}"))],
            "",
        )
        .await;
        assert_eq!(status, 200);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oidc_login_refuses_identities_outside_the_allowed_groups() {
        let idp = Idp::start().await;
        let (fx, provider) = oidc_fixture(&idp, &["fw-admins"]).await;

        let url = begin(&fx, &provider).await;
        let state = param(&url, "state");
        let nonce = param(&url, "nonce");
        idp.set_identity(&nonce, "guest@example.com", &["users"]);

        let (status, head, _) = http(
            &fx,
            "GET",
            &format!("/ui/oidc/callback?code=code-2&state={state}"),
            &[],
            "",
        )
        .await;
        assert_eq!(status, 303, "{head}");
        assert!(session_cookie(&head).is_none(), "{head}");
        assert!(
            head.to_ascii_lowercase()
                .contains("location: /login?failed=oidc"),
            "{head}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oidc_callback_rejects_an_unknown_state() {
        let idp = Idp::start().await;
        let (fx, _provider) = oidc_fixture(&idp, &[]).await;
        let (status, head, _) = http(
            &fx,
            "GET",
            "/ui/oidc/callback?code=x&state=replayed",
            &[],
            "",
        )
        .await;
        assert_eq!(status, 303, "{head}");
        assert!(session_cookie(&head).is_none(), "{head}");
    }
}
