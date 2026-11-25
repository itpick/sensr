//! `sensr-api` over real TCP in front of a real `sensr-agent` (in-memory
//! `sensr-config` store, fake applier) on a temp socket.

use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use sensr_agent::applier::FakeApplier;
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
    applier: FakeApplier,
    socket: std::path::PathBuf,
    _agent: Running,
}

async fn start() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let me = std::fs::metadata(dir.path()).unwrap().uid();
    let settings = Settings {
        trusted_uids: vec![me],
        ..Settings::default()
    };
    let applier = FakeApplier::default();
    let agent = Agent::new(sensr_agent::store::in_memory(), applier.clone(), settings).unwrap();
    agent.boot().await.unwrap();
    let socket = dir.path().join("agent.sock");
    let running = sensr_agent::start(agent, &socket, 0o600, None).unwrap();

    let key = apikey::generate().unwrap();
    let mut c = Client::connect(&socket, Principal::unix("seed", 0))
        .await
        .unwrap();
    let uuid = |n: u32| format!("6f0c6f9e-0000-4000-8000-{n:012}");
    let mut edits = vec![
        ("system.hostname".to_owned(), json!("fw")),
        ("interfaces.lan.description".to_owned(), json!("LAN")),
    ];
    for (n, name, privileges) in [
        (1, "admins", json!(["page-all"])),
        (
            2,
            "auditors",
            json!([
                "user-config-readonly",
                "page-sensr-config",
                "page-sensr-status"
            ]),
        ),
        (3, "watchers", json!(["page-sensr-status"])),
        (4, "hostviewers", json!(["page-sensr-hosts"])),
        (
            5,
            "hostreaders",
            json!(["page-sensr-hosts", "user-config-readonly"]),
        ),
        (
            6,
            "activityviewers",
            json!(["page-sensr-hosts", "page-diagnostics-networkinsight"]),
        ),
        (
            7,
            "insightviewers",
            json!(["page-diagnostics-networkinsight"]),
        ),
        (8, "scanviewers", json!(["page-services-portscan"])),
    ] {
        edits.push((
            format!("system.groups.{}", uuid(100 + n)),
            json!({"name": name, "gid": 2000 + n, "privileges": privileges}),
        ));
    }
    for (n, name, password, group) in [
        (1, "admin", "adminpw", "admins"),
        (2, "auditor", "pw", "auditors"),
        (3, "watcher", "pw", "watchers"),
        (4, "hostviewer", "pw", "hostviewers"),
        (5, "hostreader", "pw", "hostreaders"),
        (6, "activity", "pw", "activityviewers"),
        (7, "insightonly", "pw", "insightviewers"),
        (8, "scanner", "pw", "scanviewers"),
    ] {
        let mut user = json!({"name": name, "uid": if n == 1 { 0 } else { 2000 + n },
            "password_hash": hash_password(password).unwrap(), "groups": [group]});
        if n == 1 {
            user["api_keys"] = json!([{"key": key.key, "secret_hash": key.secret_hash}]);
        }
        edits.push((format!("system.users.{}", uuid(n)), user));
    }
    edits.push((
        "firewall.aliases.0b5e0000-0000-4000-8000-000000000001".into(),
        json!({"name": "nas", "description": "NAS", "content": {"type": "host", "entries": ["192.168.1.10"]}}),
    ));
    edits.push((
        "firewall.aliases.0b5e0000-0000-4000-8000-000000000002".into(),
        json!({"name": "web_ports", "content": {"type": "port", "entries": ["80", "443"]}}),
    ));
    for (path, value) in edits {
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
    tokio::spawn(sensr_api::serve(listener, state, std::future::pending()));
    Fx {
        addr,
        admin_key: basic_header(&key.key, &key.secret),
        applier,
        socket: dir.path().join("agent.sock"),
        _dir: dir,
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
    assert_eq!(out["revision"]["id"], 3);
    assert_eq!(out["revision"]["username"], "admin@ui");
    assert_eq!(out["pending_confirm"]["rollback_to"], 2);
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
    assert_eq!((st, out["revision"]["id"].clone()), (200, json!(4)));
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
    assert_eq!(s["head"]["id"], 2);

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
    assert_eq!(
        aliases["rows"][0]["uuid"],
        "0b5e0000-0000-4000-8000-000000000002"
    );
    assert_eq!(aliases["rows"][0]["type"], "port");
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

/// The real stack validates every write against the schema: a second alias
/// with an existing name is refused with a field message, before anything
/// is staged.
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_alias_name_is_rejected() {
    let fx = start().await;
    let admin = pw("admin", "adminpw");
    let (st, body) = http(
        &fx,
        "PUT",
        "/api/v1/config/doc/firewall/aliases/0b5e0000-0000-4000-8000-000000000003",
        Some(&admin),
        Some(json!({"name": "nas", "content": {"type": "host", "entries": ["192.168.1.11"]}})),
    )
    .await;
    assert_eq!(st, 422, "{body}");
    assert_eq!(body["status"], "failed");
    let fields = body["validations"].as_object().unwrap();
    assert!(
        fields.keys().any(|k| k.contains("firewall.aliases")),
        "{body}"
    );
    let (_, status) = http(&fx, "GET", "/api/v1/status", Some(&admin), None).await;
    assert_eq!(status["candidate_dirty"], false, "nothing staged");
}

#[tokio::test(flavor = "multi_thread")]
async fn hosts_requires_privilege() {
    let fx = start().await;
    let watcher = pw("watcher", "pw");
    assert_eq!(
        http(&fx, "GET", "/api/v1/hosts", Some(&watcher), None)
            .await
            .0,
        403
    );
    let viewer = pw("hostviewer", "pw");
    let (st, body) = http(&fx, "GET", "/api/v1/hosts", Some(&viewer), None).await;
    assert_eq!(st, 200, "{body}");
    assert!(body["hosts"].is_array(), "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn host_activity_route() {
    const MAC: &str = "aa:bb:cc:00:00:09";
    let fx = start().await;
    fx.applier.state.lock().unwrap().runtime.push((
        sensr_ipc::RuntimeSection::Hosts,
        json!({"now": 100, "hosts": [{"key": MAC, "mac": MAC, "name": "kid-tablet",
            "ipv4": "192.168.1.61", "online": true, "last_seen": 99, "first_seen": 1,
            "label": {"kind": "tablet", "maker": "Samsung", "confidence": "medium",
                      "reasons": [], "by": "auto"}}]}),
    ));
    let get = |who: String, path: String| {
        let fx = &fx;
        async move { http(fx, "GET", &path, Some(&who), None).await }
    };
    let url = |mac: &str, q: &str| format!("/api/v1/hosts/{mac}/activity{q}");
    let both = pw("activity", "pw");

    let (st, body) = get(both.clone(), url(MAC, "")).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["mac"], MAC);
    assert_eq!(body["name"], "kid-tablet");
    assert_eq!(body["label"]["kind"], "tablet");
    assert_eq!(body["range"], "today");
    // no database in the test environment: empty, not an error
    assert_eq!(body["available"], false);
    assert!(body["services"].as_array().unwrap().is_empty());
    let (st, body) = get(
        both.clone(),
        url(&MAC.to_uppercase(), "?range=7d&domains_page=1"),
    )
    .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        (body["range"].as_str(), body["page"].as_u64()),
        (Some("7d"), Some(1))
    );

    // both privileges are needed
    let (st, _) = get(pw("hostviewer", "pw"), url(MAC, "")).await;
    assert_eq!(st, 403, "hosts without insight");
    let (st, _) = get(pw("insightonly", "pw"), url(MAC, "")).await;
    assert_eq!(st, 403, "insight without hosts");
    let (st, _) = get(pw("watcher", "pw"), url(MAC, "")).await;
    assert_eq!(st, 403);

    let (st, body) = get(both.clone(), url("aa:bb:cc:00:00:99", "")).await;
    assert_eq!(st, 404, "{body}");
    let (st, body) = get(both, url(MAC, "?range=1y")).await;
    assert_eq!(st, 400, "{body}");

    // the UI's backend gives the same view, under the same two privileges
    use sensr_ui::api::ApiError;
    let b = ui_backend(&fx, "activity", "pw").await;
    let v = b
        .host_activity(MAC.into(), "today".into(), 0)
        .await
        .unwrap();
    assert_eq!(
        (v.name.as_deref(), v.ipv4.as_deref()),
        (Some("kid-tablet"), Some("192.168.1.61"))
    );
    assert!(matches!(
        b.host_activity("aa:bb:cc:00:00:99".into(), "today".into(), 0)
            .await,
        Err(ApiError::NotFound(_))
    ));
    assert!(matches!(
        b.host_activity(MAC.into(), "1y".into(), 0).await,
        Err(ApiError::Validation(_))
    ));
    let b = ui_backend(&fx, "hostviewer", "pw").await;
    assert!(matches!(
        b.host_activity(MAC.into(), "today".into(), 0).await,
        Err(ApiError::Unauthorized)
    ));
}

/// The wasm bundle's copy of the category list matches the schema's.
#[test]
fn ui_category_list_matches_the_schema() {
    use sensr_schema::models::insight::Category;
    let keys: Vec<(String, &str)> = Category::ALL
        .iter()
        .map(|c| {
            let k = serde_json::to_value(c).unwrap();
            (k.as_str().unwrap().to_owned(), c.display())
        })
        .collect();
    let ui: Vec<(String, &str)> = sensr_ui::runtime::CATEGORIES
        .iter()
        .map(|(k, n)| ((*k).to_owned(), *n))
        .collect();
    assert_eq!(keys, ui);
}

#[tokio::test(flavor = "multi_thread")]
async fn status_hosts_does_not_bypass_hosts_privilege() {
    let fx = start().await;
    let watcher = pw("watcher", "pw");
    let (st, body) = http(&fx, "GET", "/api/v1/status/hosts", Some(&watcher), None).await;
    assert_eq!(st, 404, "{body}");
    assert_eq!(
        http(&fx, "GET", "/api/v1/hosts", Some(&watcher), None)
            .await
            .0,
        403
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn forget_host_readonly_forbidden() {
    let fx = start().await;
    let reader = pw("hostreader", "pw");
    let (st, body) = http(
        &fx,
        "POST",
        "/api/v1/hosts/forget",
        Some(&reader),
        Some(json!({"key": "aa:bb:cc:00:00:01"})),
    )
    .await;
    assert_eq!(st, 403, "{body}");
    // Positive control: a non-read-only holder reaches the agent, which
    // answers Conflict for an unknown host.
    let viewer = pw("hostviewer", "pw");
    let (st, body) = http(
        &fx,
        "POST",
        "/api/v1/hosts/forget",
        Some(&viewer),
        Some(json!({"key": "aa:bb:cc:00:00:01"})),
    )
    .await;
    assert_eq!(st, 409, "{body}");
}

/// The UI's backend (`UiBackend`) as `user` sees it, over the same agent.
async fn ui_backend(fx: &Fx, user: &str, password: &str) -> sensr_ui::api::BackendHandle {
    use sensr_ui::api::Sessions;
    let sessions = sensr_api::ui::UiSessions::new(sensr_api::AppState::new(fx.socket.clone()));
    let token = sessions.login(user, password, None).await.unwrap();
    sessions.open(&token).await.expect("session").backend
}

#[tokio::test(flavor = "multi_thread")]
async fn ui_backend_set_host_mode() {
    use sensr_ui::api::ApiError;
    const MAC: &str = "aa:bb:cc:00:00:02";
    let fx = start().await;
    let b = ui_backend(&fx, "hostviewer", "pw").await;
    assert_eq!(
        b.set_host_mode(MAC.into(), Some("isolated".into()), None)
            .await
            .unwrap(),
        "applied"
    );
    let applied = fx.applier.state.lock().unwrap().applied.clone();
    let modes: Vec<_> = applied
        .last()
        .unwrap()
        .firewall
        .host_modes
        .values()
        .map(|h| h.mac.to_string())
        .collect();
    assert_eq!(modes, [MAC]);

    // the remote address the UI passes is what the agent checks
    let me: std::net::IpAddr = "192.168.1.77".parse().unwrap();
    fx.applier
        .state
        .lock()
        .unwrap()
        .client_macs
        .push((me, MAC.into()));
    match b
        .set_host_mode(MAC.into(), Some("quarantine".into()), Some(me))
        .await
    {
        Err(ApiError::Conflict(m)) => assert_eq!(
            m,
            "That's the device you're using — quarantine it from another device."
        ),
        other => panic!("expected a conflict, got {other:?}"),
    }
    // from another address it goes through
    assert_eq!(
        b.set_host_mode(
            MAC.into(),
            Some("quarantine".into()),
            Some("192.168.1.78".parse().unwrap())
        )
        .await
        .unwrap(),
        "applied"
    );

    // with another change staged the mode waits for Apply
    let mut c = Client::connect(&fx.socket, Principal::unix("seed", 0))
        .await
        .unwrap();
    c.call(Op::ConfigSet {
        path: "system.hostname".parse().unwrap(),
        value: json!("fw2"),
    })
    .await
    .unwrap();
    assert_eq!(
        b.set_host_mode(MAC.into(), Some("normal".into()), None)
            .await
            .unwrap(),
        "staged"
    );
    assert!(
        b.set_host_mode(MAC.into(), Some("bogus".into()), None)
            .await
            .is_err()
    );
    // read-only users are refused by the agent
    let reader = ui_backend(&fx, "hostreader", "pw").await;
    assert!(matches!(
        reader.set_host_mode(MAC.into(), None, None).await,
        Err(ApiError::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn set_host_mode_route() {
    const MAC: &str = "aa:bb:cc:00:00:01";
    let fx = start().await;
    let viewer = pw("hostviewer", "pw");
    let set = |who: String, mode: Value| {
        let fx = &fx;
        async move {
            http(
                fx,
                "POST",
                "/api/v1/hosts/mode",
                Some(&who),
                Some(json!({"mac": MAC, "mode": mode})),
            )
            .await
        }
    };
    let (st, body) = set(viewer.clone(), json!("isolated")).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body, json!({"result": "applied"}));
    let applied = fx.applier.state.lock().unwrap().applied.clone();
    let modes: Vec<_> = applied
        .last()
        .unwrap()
        .firewall
        .host_modes
        .values()
        .map(|h| h.mac.to_string())
        .collect();
    assert_eq!(modes, [MAC]);

    // read-only config: the mode is visible but not changeable
    let (st, body) = set(pw("hostreader", "pw"), json!("quarantine")).await;
    assert_eq!(st, 403, "{body}");
    // no hosts privilege at all
    let (st, _) = set(pw("watcher", "pw"), json!("quarantine")).await;
    assert_eq!(st, 403);

    // the request comes from 127.0.0.1: quarantining that host is refused
    fx.applier
        .state
        .lock()
        .unwrap()
        .client_macs
        .push(("127.0.0.1".parse().unwrap(), MAC.into()));
    let (st, body) = set(viewer.clone(), json!("quarantine")).await;
    assert_eq!(st, 409, "{body}");
    assert!(
        body.to_string().contains("That's the device you're using"),
        "{body}"
    );

    // back to Normal, spelled `normal` or `null`
    let (st, body) = set(viewer.clone(), json!("normal")).await;
    assert_eq!((st, body), (200, json!({"result": "applied"})));
    let (st, body) = set(viewer, Value::Null).await;
    assert_eq!((st, body), (200, json!({"result": "applied"})));
    let applied = fx.applier.state.lock().unwrap().applied.clone();
    assert!(applied.last().unwrap().firewall.host_modes.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn set_host_label_route() {
    const MAC: &str = "aa:bb:cc:00:00:03";
    let fx = start().await;
    let post = |who: String, body: Value| {
        let fx = &fx;
        async move { http(fx, "POST", "/api/v1/hosts/label", Some(&who), Some(body)).await }
    };
    let labels = |fx: &Fx| {
        fx.applier
            .state
            .lock()
            .unwrap()
            .applied
            .last()
            .unwrap()
            .hosts
            .labels
            .values()
            .map(|l| (l.mac.to_string(), l.kind, l.maker.clone()))
            .collect::<Vec<_>>()
    };
    let viewer = pw("hostviewer", "pw");
    let (st, body) = post(
        viewer.clone(),
        json!({"mac": MAC, "kind": "camera", "maker": " Wyze "}),
    )
    .await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body, json!({"result": "applied"}));
    assert_eq!(
        labels(&fx),
        [(
            MAC.to_owned(),
            Some(sensr_schema::models::hosts::HostKind::Camera),
            Some("Wyze".to_owned())
        )]
    );

    // read-only config and no hosts privilege are both refused
    let body = json!({"mac": MAC, "kind": "tv"});
    let (st, b) = post(pw("hostreader", "pw"), body.clone()).await;
    assert_eq!(st, 403, "{b}");
    let (st, _) = post(pw("watcher", "pw"), body).await;
    assert_eq!(st, 403);
    // an unknown kind is a bad request, not a stored label
    let (st, _) = post(viewer.clone(), json!({"mac": MAC, "kind": "toaster"})).await;
    assert!(st == 400 || st == 422, "{st}");

    // both null clears it
    let (st, body) = post(viewer, json!({"mac": MAC, "kind": null, "maker": null})).await;
    assert_eq!((st, body), (200, json!({"result": "applied"})));
    assert!(labels(&fx).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn ui_backend_set_host_label() {
    use sensr_ui::api::ApiError;
    const MAC: &str = "aa:bb:cc:00:00:04";
    let fx = start().await;
    let b = ui_backend(&fx, "hostviewer", "pw").await;
    assert_eq!(
        b.set_host_label(MAC.into(), Some("smart_home".into()), None)
            .await
            .unwrap(),
        "applied"
    );
    let applied = fx.applier.state.lock().unwrap().applied.clone();
    assert_eq!(applied.last().unwrap().hosts.labels.len(), 1);
    // a field error, not a backend failure
    assert!(matches!(
        b.set_host_label(MAC.into(), Some("toaster".into()), None).await,
        Err(ApiError::Validation(e)) if e.len() == 1 && e[0].path == "kind"
    ));
    let reader = ui_backend(&fx, "hostreader", "pw").await;
    assert!(matches!(
        reader.set_host_label(MAC.into(), None, None).await,
        Err(ApiError::Unauthorized)
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn set_service_override_route() {
    use sensr_schema::models::insight::Category;
    let fx = start().await;
    let post = |who: String, body: Value| {
        let fx = &fx;
        async move {
            http(
                fx,
                "POST",
                "/api/v1/insight/service-override",
                Some(&who),
                Some(body),
            )
            .await
        }
    };
    let overrides = |fx: &Fx| {
        fx.applier
            .state
            .lock()
            .unwrap()
            .applied
            .last()
            .unwrap()
            .insight
            .dns
            .service_overrides
            .values()
            .map(|o| (o.suffix.clone(), o.service.clone(), o.category))
            .collect::<Vec<_>>()
    };
    let who = pw("activity", "pw");
    let (st, body) = post(
        who.clone(),
        json!({"suffix": "game-cdn.net", "service": "Fortnite", "category": "games"}),
    )
    .await;
    assert_eq!((st, body), (200, json!({"result": "applied"})));
    assert_eq!(
        overrides(&fx),
        [(
            "game-cdn.net".to_owned(),
            "Fortnite".to_owned(),
            Category::Games
        )]
    );
    // the hosts privilege alone does not cover it
    let body = json!({"suffix": "x.net", "service": "X", "category": "other"});
    let (st, _) = post(pw("hostviewer", "pw"), body.clone()).await;
    assert_eq!(st, 403);
    let (st, _) = post(pw("auditor", "pw"), body).await;
    assert_eq!(st, 403);
    let (st, _) = post(
        who.clone(),
        json!({"suffix": "x.net", "service": "X", "category": "toaster"}),
    )
    .await;
    assert!(st == 400 || st == 422, "{st}");
    // both null removes it
    let (st, body) = post(who, json!({"suffix": "game-cdn.net"})).await;
    assert_eq!((st, body), (200, json!({"result": "applied"})));
    assert!(overrides(&fx).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn ui_backend_set_service_override() {
    use sensr_ui::api::ApiError;
    let fx = start().await;
    let b = ui_backend(&fx, "activity", "pw").await;
    assert_eq!(
        b.set_service_override(
            "cdn.example.com".into(),
            Some("Example".into()),
            Some("video".into())
        )
        .await
        .unwrap(),
        "applied"
    );
    let applied = fx.applier.state.lock().unwrap().applied.clone();
    assert_eq!(
        applied.last().unwrap().insight.dns.service_overrides.len(),
        1
    );
    assert!(matches!(
        b.set_service_override("cdn.example.com".into(), Some("X".into()), Some("toaster".into()))
            .await,
        Err(ApiError::Validation(e)) if e.len() == 1 && e[0].path == "category"
    ));
    let b = ui_backend(&fx, "hostreader", "pw").await;
    assert!(matches!(
        b.set_service_override("cdn.example.com".into(), None, None)
            .await,
        Err(ApiError::Unauthorized)
    ));
}

/// Scan results and a fake `sensr-scan` socket shared by the port scanner
/// tests (the API reads its paths from one process-wide setting).
fn scan_fixture() {
    use sensr_scan::proto::{Refusal, Reply, Request, StatusView};
    use sensr_scan::store::Store;
    use sensr_scan::types::{Ident, PortRow, PortState, Proto, ScanStatus};
    use std::io::{BufRead, BufReader, Write};
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let dir = tempfile::tempdir().unwrap().keep();
        let store = Store::open(&dir.join(sensr_scan::config::DB)).unwrap();
        let ports = |ps: &[u16]| -> Vec<PortRow> {
            ps.iter()
                .map(|&port| PortRow {
                    proto: Proto::Tcp,
                    port,
                    state: PortState::Open,
                    service: None,
                    ident: Ident::default(),
                })
                .collect()
        };
        let mac = "aa:bb:cc:00:00:09";
        let j1 = store
            .begin_job(
                sensr_scan::proto::JobKind::Device,
                "192.168.1.61",
                Some(mac),
                false,
                false,
            )
            .unwrap();
        store
            .write_scan(
                j1,
                "192.168.1.61".parse().unwrap(),
                Some(mac),
                10,
                20,
                ScanStatus::Complete,
                false,
                &ports(&[80]),
            )
            .unwrap();
        store.end_job(j1, "complete", &[]).unwrap();
        let j2 = store
            .begin_job(
                sensr_scan::proto::JobKind::Device,
                "192.168.1.61",
                Some(mac),
                false,
                false,
            )
            .unwrap();
        store
            .write_scan(
                j2,
                "192.168.1.61".parse().unwrap(),
                Some(mac),
                30,
                40,
                ScanStatus::Complete,
                false,
                &ports(&[22, 80]),
            )
            .unwrap();
        store.end_job(j2, "complete", &[]).unwrap();
        let sock = dir.join("scan.sock");
        let l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut line = String::new();
                BufReader::new(&s).read_line(&mut line).unwrap();
                let reply = match serde_json::from_str::<Request>(&line).unwrap() {
                    Request::Start(r) if r.auto => Reply::Refused {
                        reason: Refusal::Invalid("auto must be false".into()),
                    },
                    Request::Start(r) if r.target == "8.8.8.8" => Reply::Refused {
                        reason: Refusal::Public,
                    },
                    Request::Start(r) if r.target == "10.0.0.0/8" => Reply::Refused {
                        reason: Refusal::TooLarge {
                            addresses: 16_777_216,
                            max: 4096,
                        },
                    },
                    Request::Start(_) => Reply::Started { job_id: 7 },
                    Request::Cancel { job_id: 5 } => Reply::Ok,
                    Request::Status => Reply::Status(StatusView {
                        running: None,
                        queue: vec![],
                    }),
                    other => panic!("unexpected {other:?}"),
                };
                let mut out = serde_json::to_vec(&reply).unwrap();
                out.push(b'\n');
                (&s).write_all(&out).unwrap();
            }
        });
        assert!(sensr_api::portscan::use_paths(dir, sock));
    });
}

#[tokio::test(flavor = "multi_thread")]
async fn portscan_reads_results() {
    scan_fixture();
    let fx = start().await;
    let who = pw("scanner", "pw");
    let get = |path: &'static str| http(&fx, "GET", path, Some(&who), None);

    let (st, body) = get("/api/v1/portscan/hosts/AA:BB:CC:00:00:09").await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["latest"]["ports"][0]["port"], 22);
    assert_eq!(body["changes"]["opened"], json!([["tcp", 22]]));
    assert_eq!(body["history"].as_array().unwrap().len(), 2);

    let (st, body) = get("/api/v1/portscan/hosts/aa:bb:cc:00:00:99").await;
    assert_eq!(st, 200, "{body}");
    assert!(body["latest"].is_null() && body["changes"].is_null());
    assert!(body["history"].as_array().unwrap().is_empty());
    assert_eq!(get("/api/v1/portscan/hosts/not-a-mac").await.0, 400);

    let (st, body) = get("/api/v1/portscan/jobs?kind=device").await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body.as_array().unwrap().len(), 2);
    let (_, body) = get("/api/v1/portscan/jobs?kind=device&limit=1").await;
    assert_eq!(body.as_array().unwrap().len(), 1);
    assert!(
        get("/api/v1/portscan/jobs?kind=range")
            .await
            .1
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(get("/api/v1/portscan/jobs?kind=nope").await.0, 400);
    assert_eq!(
        get("/api/v1/portscan/jobs?kind=device&limit=0").await.0,
        400
    );
    assert_eq!(get("/api/v1/portscan/jobs").await.0, 400);

    let (st, body) = get("/api/v1/portscan/jobs/2").await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["job"]["id"], 2);
    assert_eq!(body["scans"][0]["ports"][0]["port"], 22);
    assert_eq!(get("/api/v1/portscan/jobs/999").await.0, 404);

    let (st, body) = get("/api/v1/portscan/status").await;
    assert_eq!(st, 200, "{body}");
    assert!(body["queue"].as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn portscan_start_and_cancel() {
    scan_fixture();
    let fx = start().await;
    let who = pw("scanner", "pw");
    let post = |path: &'static str, body: Value| http(&fx, "POST", path, Some(&who), Some(body));
    let start_body =
        |target: &str| json!({"target": target, "kind": "device", "mac": "AA:BB:CC:00:00:09"});

    let (st, body) = post("/api/v1/portscan/start", start_body("192.168.1.61")).await;
    assert_eq!((st, &body), (200, &json!({"job_id": 7})));
    // `auto` is the daemon's own; a client cannot set it
    let mut b = start_body("192.168.1.61");
    b["auto"] = json!(true);
    let (st, body) = post("/api/v1/portscan/start", b).await;
    assert_eq!((st, &body), (200, &json!({"job_id": 7})));

    let (st, body) = post("/api/v1/portscan/start", start_body("8.8.8.8")).await;
    assert_eq!(st, 409, "{body}");
    assert_eq!(body["reason"], "public");
    assert!(
        body["error"].as_str().unwrap().contains("not local"),
        "{body}"
    );
    let (st, body) = post("/api/v1/portscan/start", start_body("10.0.0.0/8")).await;
    assert_eq!(st, 409, "{body}");
    assert_eq!(body["reason"]["too_large"]["max"], 4096);

    assert_eq!(
        post("/api/v1/portscan/start", json!({"kind": "device"}))
            .await
            .0,
        422
    );
    let mut b = start_body("192.168.1.61");
    b["mac"] = json!("junk");
    assert_eq!(post("/api/v1/portscan/start", b).await.0, 400);

    let (st, body) = post("/api/v1/portscan/cancel", json!({"job_id": 5})).await;
    assert_eq!((st, &body), (200, &json!({})));
}

#[tokio::test(flavor = "multi_thread")]
async fn portscan_needs_its_privilege() {
    scan_fixture();
    let fx = start().await;
    for who in [pw("watcher", "pw"), pw("insightonly", "pw")] {
        for (m, p, b) in [
            ("GET", "/api/v1/portscan/status", None),
            ("GET", "/api/v1/portscan/jobs?kind=device", None),
            ("GET", "/api/v1/portscan/hosts/aa:bb:cc:00:00:09", None),
            (
                "POST",
                "/api/v1/portscan/start",
                Some(json!({"target": "192.168.1.61", "kind": "device"})),
            ),
            (
                "POST",
                "/api/v1/portscan/cancel",
                Some(json!({"job_id": 5})),
            ),
        ] {
            assert_eq!(http(&fx, m, p, Some(&who), b).await.0, 403, "{m} {p}");
        }
    }
    let admin = pw("admin", "adminpw");
    assert_eq!(
        http(&fx, "GET", "/api/v1/portscan/status", Some(&admin), None)
            .await
            .0,
        200
    );
}
