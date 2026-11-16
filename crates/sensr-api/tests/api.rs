//! `sensr-api` over real TCP in front of a real `sensr-agent` (in-memory
//! store, fake applier) on a temp socket.

use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use sensr_agent::applier::FakeApplier;
use sensr_agent::store::MemStore;
use sensr_agent::{Agent, Running, Settings};
use sensr_auth::apikey::{self, basic_header};
use sensr_auth::password::hash_password;
use sensr_ipc::{Client, Op, Principal};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Fx {
    _dir: tempfile::TempDir,
    addr: std::net::SocketAddr,
    admin_key: String,
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

    let key = apikey::generate().unwrap();
    let doc = json!({
        "system": {
            "hostname": "fw",
            "user": [
                {"name": "admin", "uid": "0", "password": hash_password("adminpw").unwrap(),
                 "apikeys": format!("{}|{}||script", key.key, key.secret_hash)},
                {"name": "auditor", "uid": "2000", "password": hash_password("pw").unwrap(),
                 "priv": ["user-config-readonly", "page-sensr-config", "page-sensr-status"]},
                {"name": "watcher", "uid": "2001", "password": hash_password("pw").unwrap(),
                 "priv": "page-sensr-status"},
            ],
            "group": [{"name": "admins", "member": "0", "priv": "page-all"}],
        },
        "interfaces": {
            "wan": {"if": "vtnet0", "enable": "1", "ipaddr": "dhcp"},
            "lan": {"if": "vtnet1", "enable": "1", "ipaddr": "192.168.1.1", "subnet": "24", "descr": "LAN"},
        },
        "OPNsense": {"Firewall": {"Alias": {"aliases": {"alias": [
            {"@attributes": {"uuid": "u-1"}, "enabled": "1", "name": "nas", "type": "host", "content": "192.168.1.10", "description": "NAS"},
            {"@attributes": {"uuid": "u-2"}, "enabled": "1", "name": "web_ports", "type": "port", "content": "80\n443", "description": ""},
        ]}}}},
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
    tokio::spawn(sensr_api::serve(listener, state, std::future::pending()));
    Fx {
        _dir: dir,
        addr,
        admin_key: basic_header(&key.key, &key.secret),
        _agent: running,
    }
}

/// Minimal HTTP/1.1 client: one request per connection.
async fn http(
    fx: &Fx,
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: Option<Value>,
) -> (u16, Value) {
    let mut s = TcpStream::connect(fx.addr).await.unwrap();
    let body = body.map(|b| b.to_string()).unwrap_or_default();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n");
    if let Some(a) = auth {
        req += &format!("Authorization: {a}\r\n");
    }
    if !body.is_empty() {
        req += &format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        );
    }
    req += "\r\n";
    req += &body;
    s.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8(raw).unwrap();
    let status: u16 = text[9..12].parse().unwrap();
    let (_, body) = text.split_once("\r\n\r\n").unwrap();
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

fn pw(user: &str, pass: &str) -> String {
    basic_header(user, pass)
}

#[tokio::test(flavor = "multi_thread")]
async fn requires_credentials() {
    let fx = start().await;
    assert_eq!(http(&fx, "GET", "/api/v1/status", None, None).await.0, 401);
    assert_eq!(
        http(
            &fx,
            "GET",
            "/api/v1/status",
            Some(&pw("admin", "wrong")),
            None
        )
        .await
        .0,
        401
    );
    assert_eq!(
        http(&fx, "GET", "/api/v1/status", Some(&pw("ghost", "x")), None)
            .await
            .0,
        401
    );
    assert_eq!(
        http(&fx, "GET", "/api/v1/status", Some("Bearer nope"), None)
            .await
            .0,
        401
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn set_commit_confirm_over_http() {
    let fx = start().await;
    let admin = pw("admin", "adminpw");
    let (st, v) = http(
        &fx,
        "GET",
        "/api/v1/config/doc/system/hostname?source=head",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!((st, v), (200, json!("fw")));

    let (st, v) = http(
        &fx,
        "PUT",
        "/api/v1/config/doc/system/hostname",
        Some(&admin),
        Some(json!("edge")),
    )
    .await;
    assert_eq!((st, v["dirty"].clone()), (200, json!(true)));
    let (st, d) = http(&fx, "GET", "/api/v1/config/diff", Some(&admin), None).await;
    assert_eq!(st, 200);
    assert_eq!(d["changes"][0]["path"], "system.hostname");

    let (st, plan) = http(&fx, "GET", "/api/v1/apply/plan", Some(&admin), None).await;
    assert_eq!(st, 200);
    assert!(plan["nft"].is_string());

    let (st, out) = http(
        &fx,
        "POST",
        "/api/v1/config/commit",
        Some(&admin),
        Some(json!({"description": "rename", "confirm_secs": 60})),
    )
    .await;
    assert_eq!(st, 200, "{out}");
    assert_eq!(out["revision"]["id"], 2);
    assert_eq!(out["revision"]["username"], "admin@ui");
    assert_eq!(out["pending_confirm"]["rollback_to"], 1);
    let (st, _) = http(&fx, "POST", "/api/v1/config/confirm", Some(&admin), None).await;
    assert_eq!(st, 200);
    let (st, _) = http(&fx, "POST", "/api/v1/config/confirm", Some(&admin), None).await;
    assert_eq!(st, 409);

    let (st, h) = http(
        &fx,
        "GET",
        "/api/v1/config/history?limit=1",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!((st, h.as_array().unwrap().len()), (200, 1));
    let (st, out) = http(&fx, "POST", "/api/v1/config/rollback", Some(&admin), None).await;
    assert_eq!((st, out["revision"]["id"].clone()), (200, json!(3)));
    let (_, v) = http(
        &fx,
        "GET",
        "/api/v1/config/doc/system/hostname?source=applied",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(v, "fw");
    assert_eq!(
        http(&fx, "GET", "/api/v1/config/doc/no/such", Some(&admin), None)
            .await
            .0,
        404
    );
    assert_eq!(
        http(&fx, "POST", "/api/v1/config/commit", Some(&admin), None)
            .await
            .0,
        409
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn api_key_and_sessions() {
    let fx = start().await;
    let (st, s) = http(&fx, "GET", "/api/v1/status", Some(&fx.admin_key), None).await;
    assert_eq!(st, 200);
    assert_eq!(s["head"]["id"], 1);

    let (st, login) = http(
        &fx,
        "POST",
        "/api/v1/session",
        None,
        Some(json!({"user": "admin", "password": "adminpw"})),
    )
    .await;
    assert_eq!(st, 200);
    let bearer = format!("Bearer {}", login["token"].as_str().unwrap());
    assert_eq!(
        http(&fx, "GET", "/api/v1/status", Some(&bearer), None)
            .await
            .0,
        200
    );
    assert_eq!(
        http(&fx, "DELETE", "/api/v1/session", Some(&bearer), None)
            .await
            .0,
        200
    );
    assert_eq!(
        http(&fx, "GET", "/api/v1/status", Some(&bearer), None)
            .await
            .0,
        401
    );
    let (st, _) = http(
        &fx,
        "POST",
        "/api/v1/session",
        None,
        Some(json!({"user": "admin", "password": "x"})),
    )
    .await;
    assert_eq!(st, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn privileges_are_enforced() {
    let fx = start().await;
    let auditor = pw("auditor", "pw");
    let watcher = pw("watcher", "pw");
    // Read-only privilege: reads fine, writes refused by the agent.
    assert_eq!(
        http(&fx, "GET", "/api/v1/config/doc", Some(&auditor), None)
            .await
            .0,
        200
    );
    let (st, body) = http(
        &fx,
        "PUT",
        "/api/v1/config/doc/system/hostname",
        Some(&auditor),
        Some(json!("x")),
    )
    .await;
    assert_eq!(st, 403, "{body}");
    // Status-only: the ACL stops config URLs before they reach the agent.
    assert_eq!(
        http(&fx, "GET", "/api/v1/status", Some(&watcher), None)
            .await
            .0,
        200
    );
    assert_eq!(
        http(&fx, "GET", "/api/v1/config/doc", Some(&watcher), None)
            .await
            .0,
        403
    );
    assert_eq!(
        http(&fx, "GET", "/api/core/firmware/info", Some(&watcher), None)
            .await
            .0,
        403
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn compat_read_endpoints() {
    let fx = start().await;
    let k = fx.admin_key.as_str();
    let (st, info) = http(&fx, "GET", "/api/core/firmware/info", Some(k), None).await;
    assert_eq!(st, 200);
    assert_eq!(info["product"]["product_name"], "sensr");
    assert!(info["package"].is_array());

    let (st, ifs) = http(
        &fx,
        "GET",
        "/api/interfaces/overview/interfaces_info",
        Some(k),
        None,
    )
    .await;
    assert_eq!(st, 200);
    assert_eq!(ifs["total"], 2);
    let lan = ifs["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["identifier"] == "lan")
        .unwrap();
    assert_eq!(lan["ipv4"][0]["ipaddr"], "192.168.1.1/24");
    assert_eq!(lan["description"], "LAN");
    assert_eq!(
        http(
            &fx,
            "GET",
            "/api/interfaces/overview/interfacesInfo",
            Some(k),
            None
        )
        .await
        .0,
        200
    );

    let (st, aliases) = http(
        &fx,
        "POST",
        "/api/firewall/alias/search_item",
        Some(k),
        Some(json!({"searchPhrase": "443"})),
    )
    .await;
    assert_eq!(st, 200);
    assert_eq!(aliases["total"], 1);
    assert_eq!(aliases["rows"][0]["uuid"], "u-2");
    assert_eq!(aliases["rows"][0]["content"], "80,443");
    let (_, all) = http(
        &fx,
        "GET",
        "/api/firewall/alias/search_item?rowCount=1&current=2",
        Some(k),
        None,
    )
    .await;
    assert_eq!(
        (all["total"].clone(), all["rows"][0]["name"].clone()),
        (json!(2), json!("web_ports"))
    );
}

/// API read latency through TCP + auth cache + IPC + agent, printed for the
/// record (`cargo test -- --nocapture`).
#[tokio::test(flavor = "multi_thread")]
async fn api_read_latency() {
    let fx = start().await;
    let k = fx.admin_key.clone();
    http(
        &fx,
        "GET",
        "/api/v1/config/doc/system/hostname",
        Some(&k),
        None,
    )
    .await;
    let n = 500;
    let t = Instant::now();
    for _ in 0..n {
        let (st, _) = http(
            &fx,
            "GET",
            "/api/v1/config/doc/system/hostname",
            Some(&k),
            None,
        )
        .await;
        assert_eq!(st, 200);
    }
    let per = t.elapsed() / n;
    let t = Instant::now();
    for _ in 0..n {
        http(
            &fx,
            "GET",
            "/api/interfaces/overview/interfaces_info",
            Some(&k),
            None,
        )
        .await;
    }
    let compat = t.elapsed() / n;
    eprintln!(
        "latency: api config read {per:?}, compat interfaces_info {compat:?} (new TCP connection per request)"
    );
    assert!(per < Duration::from_millis(10), "{per:?}");
}
