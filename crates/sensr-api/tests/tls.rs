//! HTTPS: the API served with the agent's generated certificate, verified
//! against its local CA; the HTTP redirect; the listener following
//! `system.webgui.port`.

use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use sensr_agent::applier::FakeApplier;
use sensr_agent::{Agent, Running, Settings};
use sensr_api::tls;
use sensr_ipc::{Client, Op, Principal};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Fx {
    _dir: tempfile::TempDir,
    socket: std::path::PathBuf,
    state: Arc<sensr_api::AppState>,
    _agent: Running,
}

async fn start() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let me = std::fs::metadata(dir.path()).unwrap().uid();
    let settings = Settings {
        trusted_uids: vec![me],
        tls_dir: Some(dir.path().join("tls")),
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
    assert!(dir.path().join("tls/ca.pem").exists(), "created at boot");
    let state = sensr_api::AppState::new(socket.clone());
    Fx {
        _dir: dir,
        socket,
        state,
        _agent: running,
    }
}

fn client_config(ca_pem: Option<&str>) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    if let Some(pem) = ca_pem {
        for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            roots.add(c.unwrap()).unwrap();
        }
    }
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

/// `GET path` over TLS; the status line, or the handshake error.
async fn https_get(port: u16, name: &str, ca: Option<&str>, path: &str) -> Result<String, String> {
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .map_err(|e| e.to_string())?;
    let connector = tokio_rustls::TlsConnector::from(client_config(ca));
    let mut s = connector
        .connect(ServerName::try_from(name.to_owned()).unwrap(), tcp)
        .await
        .map_err(|e| e.to_string())?;
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out).await;
    Ok(String::from_utf8_lossy(&out)
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned())
}

async fn plain_get(port: u16, host: &str, path: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn https_with_the_generated_certificate() {
    let fx = start().await;
    let l = tls::fetch(&fx.state).await.unwrap();
    assert_eq!(l.certificate, "generated");
    let ca = l.ca_pem.clone().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = sensr_api::app(fx.state.clone(), None);
    let (_stop_tx, stop) = tokio::sync::watch::channel(false);
    tokio::spawn(tls::serve_https(
        listener,
        app,
        tls::shared(&l).unwrap(),
        stop,
    ));

    // Verified against the local CA, for every name the certificate covers.
    for name in ["localhost", "sensr.internal", "127.0.0.1"] {
        let status = https_get(port, name, Some(&ca), "/api/v1/status")
            .await
            .unwrap();
        assert!(status.contains(" 401 "), "{name}: {status}");
    }
    // Without the CA the handshake fails, as it must.
    let e = https_get(port, "localhost", None, "/api/v1/status")
        .await
        .unwrap_err();
    assert!(e.to_lowercase().contains("certificate"), "{e}");
    // A name the certificate does not cover fails too.
    assert!(
        https_get(port, "elsewhere.example", Some(&ca), "/")
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn untrusted_peers_cannot_fetch_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let agent = Agent::new(
        sensr_agent::store::in_memory(),
        FakeApplier::default(),
        Settings::default(),
    )
    .unwrap();
    let socket = dir.path().join("agent.sock");
    let _running = sensr_agent::start(agent, &socket, 0o600, None).unwrap();
    let mut c = Client::connect(&socket, Principal::unix("x", 0))
        .await
        .unwrap();
    let e = c.call(Op::WebListener).await.unwrap_err();
    assert!(e.to_string().contains("reserved for sensr-api"), "{e}");
}

#[tokio::test(flavor = "multi_thread")]
async fn plain_http_redirects_to_https() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (_stop_tx, stop) = tokio::sync::watch::channel(false);
    tokio::spawn(tls::serve_http(listener, tls::redirect_router(8443), stop));
    let r = plain_get(port, "fw.lan", "/ui/login?x=1").await;
    assert!(r.starts_with("HTTP/1.1 308"), "{r}");
    assert!(
        r.contains("location: https://fw.lan:8443/ui/login?x=1"),
        "{r}"
    );
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `tls::run` binds where `system.webgui` says and moves when a commit
/// changes the port.
#[tokio::test(flavor = "multi_thread")]
async fn listener_follows_the_webgui_port() {
    let fx = start().await;
    let (a, b) = (free_port(), free_port());
    let mut c = Client::connect(&fx.socket, Principal::unix("t", 0))
        .await
        .unwrap();
    let set_port = |p: u16| Op::ConfigSet {
        path: "system.webgui".parse().unwrap(),
        value: json!({"port": p.to_string(), "http_redirect": false}),
    };
    let commit = || Op::ConfigCommit {
        description: None,
        confirm_secs: None,
    };
    c.call(set_port(a)).await.unwrap();
    c.call(commit()).await.unwrap();
    let ca = tls::fetch(&fx.state).await.unwrap().ca_pem.unwrap();

    let app = sensr_api::app(fx.state.clone(), None);
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let run = tokio::spawn(tls::run(
        fx.state.clone(),
        app,
        async move {
            let _ = stop_rx.await;
        },
        Duration::from_millis(100),
    ));
    let up = |port: u16| {
        let ca = ca.clone();
        async move {
            for _ in 0..50 {
                if let Ok(s) = https_get(port, "localhost", Some(&ca), "/api/v1/status").await {
                    return Some(s);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            None
        }
    };
    assert!(up(a).await.unwrap().contains(" 401 "));

    c.call(set_port(b)).await.unwrap();
    c.call(commit()).await.unwrap();
    assert!(up(b).await.unwrap().contains(" 401 "));
    assert!(
        TcpStream::connect(("127.0.0.1", a)).await.is_err(),
        "old port closed"
    );
    let _ = stop_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), run)
        .await
        .unwrap()
        .unwrap();
}
