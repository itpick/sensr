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
        (10, "guardviewers", json!(["page-services-guard"])),
        (
            11,
            "guardreaders",
            json!(["page-services-guard", "user-config-readonly"]),
        ),
        (12, "idsviewers", json!(["page-services-ids"])),
        (
            13,
            "idsguardviewers",
            json!(["page-services-ids", "page-services-guard"]),
        ),
        (8, "scanviewers", json!(["page-services-portscan"])),
        (
            9,
            "scanreaders",
            json!(["page-services-portscan", "user-config-readonly"]),
        ),
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
        (9, "scanreader", "pw", "scanreaders"),
        (10, "guarder", "pw", "guardviewers"),
        (11, "guardreader", "pw", "guardreaders"),
        (12, "idsonly", "pw", "idsviewers"),
        (13, "idsguard", "pw", "idsguardviewers"),
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
        body["error"]
            .as_str()
            .unwrap()
            .contains("outside the local networks"),
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

#[tokio::test(flavor = "multi_thread")]
async fn portscan_read_only_users_can_read_but_not_start_or_cancel() {
    scan_fixture();
    let fx = start().await;
    let who = pw("scanreader", "pw");
    let (st, body) = http(&fx, "GET", "/api/v1/portscan/status", Some(&who), None).await;
    assert_eq!(st, 200, "{body}");
    for (p, b) in [
        (
            "/api/v1/portscan/start",
            json!({"target": "192.168.1.61", "kind": "device"}),
        ),
        ("/api/v1/portscan/cancel", json!({"job_id": 5})),
    ] {
        let (st, body) = http(&fx, "POST", p, Some(&who), Some(b)).await;
        assert_eq!(st, 403, "{p}: {body}");
        assert!(
            body["message"].as_str().unwrap().contains("scanreader"),
            "{body}"
        );
    }
}

/// Guard events, a fake `sensr-guard` socket that can be taken down, and the
/// IDS alerts database, shared by the guard tests (the API reads its paths
/// from process-wide settings, so the tests that touch the daemon take turns).
struct GuardFx {
    sock: std::path::PathBuf,
}

impl GuardFx {
    /// Start (or stop) answering on the socket.
    fn daemon(&self, up: bool) {
        use sensr_guard::proto::{PackCheck, Reply, Request, RuleStatus, StatusView};
        use sensr_guard::rule::Action;
        use std::io::{BufRead, BufReader, Write};
        let _ = std::fs::remove_file(&self.sock);
        if !up {
            return;
        }
        let l = std::os::unix::net::UnixListener::bind(&self.sock).unwrap();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut line = String::new();
                BufReader::new(&s).read_line(&mut line).unwrap();
                let reply = match serde_json::from_str::<Request>(&line).unwrap() {
                    Request::Status => Reply::Status(StatusView {
                        running: true,
                        enforcing: true,
                        reason: None,
                        kill_switch: false,
                        lockdown: "none".into(),
                        packs: vec![],
                        rules: vec![
                            RuleStatus {
                                id: "no-curl".into(),
                                pack: None,
                                slot: Some(4),
                                action: Action::Alert,
                                active: true,
                                reason: None,
                                hits: 3,
                            },
                            RuleStatus {
                                id: "core-twin-a".into(),
                                pack: Some("core".into()),
                                slot: Some(8),
                                action: Action::Alert,
                                active: true,
                                reason: None,
                                hits: 0,
                            },
                            RuleStatus {
                                id: "other-twin-b".into(),
                                pack: Some("other".into()),
                                slot: Some(8),
                                action: Action::Alert,
                                active: true,
                                reason: None,
                                hits: 0,
                            },
                        ],
                        dropped_kernel: 0,
                        dropped_rate: 0,
                        dropped_blocked: 0,
                        boot_complete: true,
                    }),
                    Request::Reload => Reply::Ok,
                    Request::KillSwitch { on } => {
                        if on {
                            Reply::Ok
                        } else {
                            Reply::Error("kill switch file is read-only".into())
                        }
                    }
                    Request::CheckPacks => Reply::Packs(vec![PackCheck {
                        name: "core".into(),
                        current: Some("1".into()),
                        available: Some("2".into()),
                        installed: true,
                        error: None,
                    }]),
                };
                let mut out = serde_json::to_vec(&reply).unwrap();
                out.push(b'\n');
                (&s).write_all(&out).unwrap();
            }
        });
    }
}

async fn guard_fixture() -> (GuardFx, tokio::sync::MutexGuard<'static, ()>) {
    use sensr_flow::eve::{Alert, AlertStore, Event};
    use sensr_guard::events::{Batch, Row};
    use sensr_guard::store::Store;
    static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    static ONCE: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    let guard = LOCK.lock().await;
    let dir = ONCE.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap().keep();
        let row = |ts: i64, ts_ms: u32, hook: &str, blocked: bool, slot: u32, target: &str| Row {
            ts,
            ts_ms,
            hook: hook.into(),
            action: if blocked { "block" } else { "alert" }.into(),
            blocked,
            rule_id: slot,
            exe: "/usr/bin/curl".into(),
            target: target.into(),
            unit: "app.service".into(),
            pid: 9,
            uid: 1000,
            count: 2,
        };
        let mut st = Store::open(&dir.join(sensr_guard::config::EVENTS_DB)).unwrap();
        st.write_batch(&Batch {
            rows: vec![
                row(1000, 500, "connect", false, 4, "1.1.1.1:53"),
                row(3000, 0, "exec", true, 8, "/bin/nc"),
                row(5000, 0, "exec", false, 77, "/bin/ls"),
            ],
        })
        .unwrap();
        // IDS alerts at 2000 ms and 4000 ms (milliseconds).
        let mut a = AlertStore::open(&dir.join(sensr_flow::config::ALERTS_DB)).unwrap();
        let alert = |ts: i64, sid: u32, sig: &str| {
            Event::Alert(Box::new(Alert {
                id: 0,
                ts,
                gid: 1,
                sid,
                rev: 1,
                signature: sig.into(),
                category: "c".into(),
                severity: 2,
                action: "allowed".into(),
                proto: "TCP".into(),
                src_ip: "10.0.0.1".into(),
                src_port: Some(1),
                dest_ip: "10.0.0.2".into(),
                dest_port: Some(2),
                iface: "lan".into(),
                app_proto: String::new(),
                raw: "{}".into(),
            }))
        };
        a.write(
            &[alert(2_000_000, 1, "ET old"), alert(4_000_000, 2, "ET new")],
            None,
        )
        .unwrap();
        let sock = dir.join("guard.sock");
        assert!(sensr_api::guard::use_paths(dir.clone(), sock));
        assert!(sensr_api::insight::use_dir(dir.clone()));
        dir
    });
    let fx = GuardFx {
        sock: dir.join("guard.sock"),
    };
    fx.daemon(true);
    (fx, guard)
}

#[tokio::test(flavor = "multi_thread")]
async fn status_when_daemon_down_marks_rules_inactive() {
    let (g, _lock) = guard_fixture().await;
    let fx = start().await;
    // Two configured rules, one of them disabled.
    let mut c = Client::connect(&fx.socket, Principal::unix("seed", 0))
        .await
        .unwrap();
    for (n, enabled) in [(1, true), (2, false)] {
        c.call(Op::ConfigSet {
            path: format!("guard.rules.7e570000-0000-4000-8000-{n:012}")
                .parse()
                .unwrap(),
            value: json!({"enabled": enabled, "description": "d", "hook": "connect",
                "target": {"net": {"cidr": "10.0.0.0/8", "ports": [22]}}}),
        })
        .await
        .unwrap();
    }
    c.call(Op::ConfigCommit {
        description: Some("guard rules".into()),
        confirm_secs: None,
    })
    .await
    .unwrap();
    let who = pw("guarder", "pw");

    let (st, up) = http(&fx, "GET", "/api/v1/guard/status", Some(&who), None).await;
    assert_eq!(st, 200, "{up}");
    assert_eq!(up["running"], true);
    assert_eq!(up["rules"][0]["id"], "no-curl");
    assert_eq!(up["rules"][0]["active"], true);

    g.daemon(false);
    let (st, down) = http(&fx, "GET", "/api/v1/guard/status", Some(&who), None).await;
    assert_eq!(st, 200, "{down}");
    assert_eq!(
        (&down["running"], &down["enforcing"]),
        (&json!(false), &json!(false))
    );
    assert_eq!(down["reason"], "sensr-guard is not running");
    let rules = down["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 1, "the disabled rule is not listed: {down}");
    assert_eq!(rules[0]["id"], "7e570000-0000-4000-8000-000000000001");
    assert_eq!(rules[0]["active"], false);
    assert_eq!(rules[0]["action"], "alert");
    assert_eq!(rules[0]["reason"], "sensr-guard is not running");
    assert!(down["packs"].as_array().unwrap().is_empty());

    // Writes are 503 while it is down.
    let (st, body) = http(&fx, "POST", "/api/v1/guard/reload", Some(&who), None).await;
    assert_eq!(st, 503, "{body}");
    assert_eq!(body["message"], "sensr-guard is not running");
    // Events are still readable, with no rule ids to map slots to.
    let (st, body) = http(&fx, "GET", "/api/v1/guard/events", Some(&who), None).await;
    assert_eq!(st, 200, "{body}");
    assert!(body["rows"][2]["rule"].is_null());
}

#[tokio::test(flavor = "multi_thread")]
async fn events_filtered() {
    let (_g, _lock) = guard_fixture().await;
    let fx = start().await;
    let who = pw("guarder", "pw");
    let get = |q: &'static str| http(&fx, "GET", q, Some(&who), None);

    let (st, body) = get("/api/v1/guard/events").await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        (&body["available"], &body["total"]),
        (&json!(true), &json!(3))
    );
    let ts: Vec<_> = body["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["ts"].clone())
        .collect();
    assert_eq!(ts, [5000, 3000, 1000], "newest first");
    // slot 4 -> its rule; slot 8 is shared by two packs -> none; slot 77 unknown -> none
    assert_eq!(body["rows"][2]["rule"], "no-curl");
    assert_eq!(body["rows"][2]["rule_id"], 4);
    assert!(body["rows"][1]["rule"].is_null() && body["rows"][0]["rule"].is_null());
    assert_eq!(body["rows"][2]["count"], 2);

    let (_, body) = get("/api/v1/guard/events?hook=exec").await;
    assert_eq!(body["total"], 2);
    let (_, body) = get("/api/v1/guard/events?hook=exec&q=NC").await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["rows"][0]["target"], "/bin/nc");
    let (_, body) = get("/api/v1/guard/events?q=app.service&limit=1&offset=1").await;
    assert_eq!(body["rows"].as_array().unwrap().len(), 1);
    assert_eq!(
        (&body["rows"][0]["ts"], &body["total"]),
        (&json!(3000), &json!(3))
    );
    let (_, body) = get("/api/v1/guard/events?q=nothing-like-this").await;
    assert_eq!(
        (&body["total"], body["rows"].as_array().unwrap().len()),
        (&json!(0), 0)
    );

    assert_eq!(get("/api/v1/guard/events?hook=nope").await.0, 400);
    assert_eq!(get("/api/v1/guard/events?limit=0").await.0, 400);
    assert_eq!(get("/api/v1/guard/events?limit=1001").await.0, 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_switches_reach_the_daemon() {
    let (_g, _lock) = guard_fixture().await;
    let fx = start().await;
    let who = pw("guarder", "pw");
    let post = |p: &'static str, b: Option<Value>| http(&fx, "POST", p, Some(&who), b);
    assert_eq!(post("/api/v1/guard/reload", None).await, (200, json!({})));
    assert_eq!(
        post("/api/v1/guard/kill-switch", Some(json!({"on": true}))).await,
        (200, json!({}))
    );
    // A daemon refusal is 409 with a fixed message.
    let (st, body) = post("/api/v1/guard/kill-switch", Some(json!({"on": false}))).await;
    assert_eq!(st, 409, "{body}");
    assert_eq!(body["message"], "sensr-guard refused the request");
    assert_eq!(
        post("/api/v1/guard/kill-switch", Some(json!({}))).await.0,
        422
    );
    assert_eq!(
        post(
            "/api/v1/guard/kill-switch",
            Some(json!({"on": true, "x": 1}))
        )
        .await
        .0,
        422
    );
    let (st, body) = post("/api/v1/guard/check-packs", None).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["packs"][0]["name"], "core");
    assert_eq!(body["packs"][0]["installed"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn readonly_cannot_toggle_kill_switch() {
    let (_g, _lock) = guard_fixture().await;
    let fx = start().await;
    let who = pw("guardreader", "pw");
    let (st, body) = http(&fx, "GET", "/api/v1/guard/status", Some(&who), None).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        http(&fx, "GET", "/api/v1/guard/events", Some(&who), None)
            .await
            .0,
        200
    );
    for (p, b) in [
        ("/api/v1/guard/kill-switch", Some(json!({"on": true}))),
        ("/api/v1/guard/reload", None),
        ("/api/v1/guard/check-packs", None),
    ] {
        let (st, body) = http(&fx, "POST", p, Some(&who), b).await;
        assert_eq!(st, 403, "{p}: {body}");
        assert!(
            body["message"].as_str().unwrap().contains("guardreader"),
            "{body}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn guard_needs_its_privilege() {
    let (_g, _lock) = guard_fixture().await;
    let fx = start().await;
    for who in [
        pw("watcher", "pw"),
        pw("idsonly", "pw"),
        pw("scanner", "pw"),
    ] {
        for (m, p, b) in [
            ("GET", "/api/v1/guard/status", None),
            ("GET", "/api/v1/guard/events", None),
            ("POST", "/api/v1/guard/reload", None),
            (
                "POST",
                "/api/v1/guard/kill-switch",
                Some(json!({"on": true})),
            ),
            ("POST", "/api/v1/guard/check-packs", None),
        ] {
            assert_eq!(http(&fx, m, p, Some(&who), b).await.0, 403, "{m} {p}");
        }
    }
    let admin = pw("admin", "adminpw");
    assert_eq!(
        http(&fx, "GET", "/api/v1/guard/status", Some(&admin), None)
            .await
            .0,
        200
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_merge_guard_events_sorted_by_time() {
    let (_g, _lock) = guard_fixture().await;
    let fx = start().await;
    let both = pw("idsguard", "pw");
    let (st, body) = http(&fx, "GET", "/api/v1/ids/alerts", Some(&both), None).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(
        (&body["available"], &body["total"]),
        (&json!(true), &json!(5))
    );
    let rows = body["rows"].as_array().unwrap();
    let order: Vec<_> = rows
        .iter()
        .map(|r| (r["source"].as_str().unwrap(), r["ts"].as_i64().unwrap()))
        .collect();
    assert_eq!(
        order,
        [
            ("runtime-guard", 5_000_000),
            ("ids", 4_000_000),
            ("runtime-guard", 3_000_000),
            ("ids", 2_000_000),
            ("runtime-guard", 1_000_500),
        ]
    );
    assert_eq!(rows[1]["signature"], "ET new");
    let g = &rows[2];
    assert_eq!(g["hook"], "exec");
    assert_eq!(g["action"], "blocked");
    assert_eq!(g["severity"], 1);
    assert_eq!(g["target"], "/bin/nc");
    assert_eq!(g["category"], "runtime-guard");
    assert_eq!(rows[4]["rule"], "no-curl");

    // paging runs over the merged list
    let (_, body) = http(
        &fx,
        "GET",
        "/api/v1/ids/alerts?limit=2&offset=1",
        Some(&both),
        None,
    )
    .await;
    let order: Vec<_> = body["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["ts"].as_i64().unwrap())
        .collect();
    assert_eq!(order, [4_000_000, 3_000_000]);
    assert_eq!(body["total"], 5);
    // time range (ms) and text apply to both
    let (_, body) = http(
        &fx,
        "GET",
        "/api/v1/ids/alerts?since=2000000&until=4000000",
        Some(&both),
        None,
    )
    .await;
    let order: Vec<_> = body["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["ts"].as_i64().unwrap())
        .collect();
    assert_eq!(order, [3_000_000, 2_000_000]);
    let (_, body) = http(
        &fx,
        "GET",
        "/api/v1/ids/alerts?text=bin/nc",
        Some(&both),
        None,
    )
    .await;
    assert_eq!(body["total"], 1);
    // a signature or host filter has no guard rows
    for q in ["sid=1", "host=10.0.0.1"] {
        let (_, body) = http(
            &fx,
            "GET",
            &format!("/api/v1/ids/alerts?{q}"),
            Some(&both),
            None,
        )
        .await;
        let sources: Vec<_> = body["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["source"].clone())
            .collect();
        assert!(
            sources.iter().all(|s| s == "ids") && !sources.is_empty(),
            "{q}: {body}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_without_the_guard_privilege_stay_ids_only() {
    let (_g, _lock) = guard_fixture().await;
    let fx = start().await;
    let who = pw("idsonly", "pw");
    let (st, body) = http(&fx, "GET", "/api/v1/ids/alerts", Some(&who), None).await;
    assert_eq!(st, 200, "{body}");
    assert_eq!(body["total"], 2);
    let rows = body["rows"].as_array().unwrap();
    assert!(rows.iter().all(|r| r["source"] == "ids"));
    assert_eq!(rows[0]["signature"], "ET new");
    // and the guard privilege alone does not open the alerts
    assert_eq!(
        http(
            &fx,
            "GET",
            "/api/v1/ids/alerts",
            Some(&pw("guarder", "pw")),
            None
        )
        .await
        .0,
        403
    );
}
