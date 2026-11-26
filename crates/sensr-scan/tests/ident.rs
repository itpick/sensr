#![cfg(feature = "daemon")]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sensr_scan::ident::identify;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const LO: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A TLS server with a self-signed certificate for `nas.local` that answers
/// every request with a page titled "Hi". Plain-text probes fail the
/// handshake and are dropped.
async fn tls_server() -> u16 {
    let mut params = rcgen::CertificateParams::new(vec!["nas.local".to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "nas.local");
    let kp = rcgen::KeyPair::generate().unwrap();
    let c = params.self_signed(&kp).unwrap();
    let cert = CertificateDer::from(c.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(kp.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut t) = acceptor.accept(s).await else {
                    return;
                };
                let mut buf = [0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match t.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let body = "<html><head><title>Hi</title></head></html>";
                let resp = format!(
                    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                t.write_all(resp.as_bytes()).await.ok();
                t.shutdown().await.ok();
            });
        }
    });
    port
}

#[tokio::test]
async fn ident_tls_server_cert_and_title() {
    let port = tls_server().await;
    let id = identify(LO, port, Some("https")).await.expect("identified");
    let tls = id.tls.expect("tls info");
    assert!(tls.subject.contains("nas.local"), "{tls:?}");
    assert_eq!(tls.sans, vec!["nas.local".to_string()]);
    assert!(tls.not_after > 0);
    assert_eq!(id.title.as_deref(), Some("Hi"));
}

#[tokio::test]
async fn ident_tls_server_without_hint() {
    let port = tls_server().await;
    let id = identify(LO, port, None).await.expect("identified");
    assert_eq!(
        id.tls.expect("tls info").sans,
        vec!["nas.local".to_string()]
    );
    assert_eq!(id.title.as_deref(), Some("Hi"));
}

#[tokio::test]
async fn ident_silent_listener_returns_within_budget() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    // Accept and hold every connection open without ever writing.
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            held.push(s);
        }
    });
    let t = Instant::now();
    let id = identify(LO, port, None).await;
    assert!(
        t.elapsed() < Duration::from_millis(5500),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(id, None);
}

#[tokio::test]
async fn ident_ssh_greeting() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            s.write_all(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
                .await
                .ok();
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
    let t = Instant::now();
    let id = identify(LO, port, None).await.expect("identified");
    assert_eq!(id.product.as_deref(), Some("OpenSSH"));
    assert_eq!(id.version.as_deref(), Some("9.6p1"));
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
}

#[tokio::test]
async fn ident_plain_http_server() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).await.unwrap_or(0);
                if buf[..n].starts_with(b"GET / HTTP/1.0\r\nHost: 127.0.0.1") {
                    s.write_all(
                        b"HTTP/1.0 200 OK\r\nServer: nginx/1.27\r\n\r\n<title>Router</title>",
                    )
                    .await
                    .ok();
                }
            });
        }
    });
    let id = identify(LO, port, Some("http")).await.expect("identified");
    assert_eq!(id.product.as_deref(), Some("nginx"));
    assert_eq!(id.version.as_deref(), Some("1.27"));
    assert_eq!(id.title.as_deref(), Some("Router"));
    assert_eq!(id.tls, None);
}

#[tokio::test]
async fn ident_redis_ping() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 256];
                let n = s.read(&mut buf).await.unwrap_or(0);
                if &buf[..n] == b"PING\r\n" {
                    s.write_all(b"+PONG\r\n").await.ok();
                }
            });
        }
    });
    let id = identify(LO, port, Some("redis")).await.expect("identified");
    assert_eq!(id.product.as_deref(), Some("Redis"));
}

#[tokio::test]
async fn ident_closed_port_is_none() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let t = Instant::now();
    assert_eq!(identify(LO, port, None).await, None);
    assert!(t.elapsed() < Duration::from_secs(1));
}
