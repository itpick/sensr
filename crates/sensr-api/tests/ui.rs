//! The web UI served by `sensr-api` in front of a real `sensr-agent`: login through the UI,
//! server-rendered pages from agent data, and the shared session table (a UI login is a valid
//! API bearer token).

use std::os::unix::fs::MetadataExt;

use sensr_agent::applier::FakeApplier;
use sensr_agent::store::MemStore;
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
    let dir = tempfile::tempdir().unwrap();
    let me = std::fs::metadata(dir.path()).unwrap().uid();
    let settings = Settings {
        trusted_uids: vec![me],
        ..Settings::default()
    };
    let agent = Agent::new(MemStore::new(), FakeApplier::default(), settings).unwrap();
    let socket = dir.path().join("agent.sock");
    let running = sensr_agent::start(agent, &socket, 0o600, None).unwrap();
    let doc = json!({
        "system": {
            "hostname": "fw",
            "domain": "example.org",
            "user": [{"name": "admin", "uid": "0", "password": hash_password("adminpw").unwrap()}],
            "group": [{"name": "admins", "member": "0", "priv": "page-all"}],
        },
        "interfaces": {"lan": {"device": "eth1", "description": "LAN",
                               "ipv4": {"mode": "static", "address": "192.168.1.1/24"}}},
        "firewall": {"aliases": {"0c5e2a3e-0000-4000-a000-000000000001": {
            "enabled": true, "name": "nas", "content": {"type": "host", "entries": ["192.168.1.10"]},
            "description": "File server"}}},
    });
    let mut c = Client::connect(&socket, Principal::unix("seed", 0))
        .await
        .unwrap();
    c.call(Op::ConfigLoad { document: doc }).await.unwrap();
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
