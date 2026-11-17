//! HTTPS for the API and web UI (OPNsense `webgui_configure`), driven by
//! `system.webgui` of the applied document.
//!
//! - The agent hands over the listener settings and the certificate
//!   ([`Op::WebListener`]); this process cannot read the state directory.
//! - TLS is rustls (ring provider, TLS 1.2+, ALPN h2 and http/1.1). The
//!   server config is swapped in place when the certificate changes, so a
//!   new certificate needs no restart and drops no connection.
//! - With `system.webgui.interfaces` set, one listener per device is bound
//!   with `SO_BINDTODEVICE` (plus `lo`, as OPNsense binds `lo0`): the kernel
//!   delivers only connections that arrive on those devices, whatever
//!   addresses DHCP or SLAAC give them later. A device that does not exist
//!   yet is retried on the next poll.
//! - With HTTPS and the redirect on, port 80 answers with a redirect to the
//!   same host and path over HTTPS.
//!
//! The agent is polled every few seconds; a changed port, protocol or
//! device list rebinds, a changed certificate swaps the TLS config.

use std::collections::BTreeMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sensr_ipc::{Op, Principal, Response as IpcResponse, WebListener};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tower::ServiceExt as _;

use crate::AppState;

/// How often the agent is asked for the listener settings.
pub const POLL: Duration = Duration::from_secs(5);

/// A TLS server config whose certificate can be replaced while serving.
pub type SharedTls = Arc<RwLock<Arc<ServerConfig>>>;

/// Failures building the TLS configuration.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The PEM material does not parse.
    #[error("certificate material: {0}")]
    Pem(String),
    /// rustls refused the certificate or key.
    #[error("tls: {0}")]
    Rustls(#[from] rustls::Error),
}

/// A rustls server config for a PEM chain (leaf first) and key.
pub fn server_config(chain_pem: &str, key_pem: &str) -> Result<Arc<ServerConfig>, TlsError> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Pem(e.to_string()))?;
    if chain.is_empty() {
        return Err(TlsError::Pem("no certificate in the chain".into()));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
        .map_err(|e| TlsError::Pem(e.to_string()))?;
    let mut cfg =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(chain, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

/// A shareable config from the agent's listener reply.
pub fn shared(l: &WebListener) -> Result<SharedTls, TlsError> {
    Ok(Arc::new(RwLock::new(server_config(
        &l.cert_chain_pem,
        &l.key_pem,
    )?)))
}

fn swap(tls: &SharedTls, cfg: Arc<ServerConfig>) {
    *tls.write().unwrap_or_else(|e| e.into_inner()) = cfg;
}

fn current(tls: &SharedTls) -> Arc<ServerConfig> {
    tls.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Asks the agent where and how to serve.
pub async fn fetch(state: &AppState) -> Result<WebListener, String> {
    match state
        .agent
        .call(Principal::unix("sensr-api", 0), Op::WebListener)
        .await
    {
        Ok(IpcResponse::WebListener(l)) => Ok(*l),
        Ok(other) => Err(format!("unexpected reply {other:?}")),
        Err(e) => Err(e.to_string()),
    }
}

/// Binds `[::]:port` (dual stack, falling back to `0.0.0.0` where IPv6 is
/// off), optionally only for connections arriving on `device`.
pub fn bind(port: u16, device: Option<&str>) -> std::io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let v6 = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP));
    let (socket, addr) = match v6 {
        Ok(s) => {
            s.set_only_v6(false)?;
            (s, SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)))
        }
        Err(_) => (
            Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?,
            SocketAddr::from(([0, 0, 0, 0], port)),
        ),
    };
    socket.set_reuse_address(true)?;
    if let Some(dev) = device {
        bind_device(&socket, dev)?;
    }
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    TcpListener::from_std(socket.into())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bind_device(s: &socket2::Socket, dev: &str) -> std::io::Result<()> {
    s.bind_device(Some(dev.as_bytes()))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn bind_device(_: &socket2::Socket, dev: &str) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!("binding to device {dev} needs Linux"),
    ))
}

async fn serve_conn<S>(io: S, app: Router, peer: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = app.map_request(move |mut r: axum::http::Request<hyper::body::Incoming>| {
        r.extensions_mut().insert(ConnectInfo(peer));
        r
    });
    if let Err(e) = Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(TokioIo::new(io), TowerToHyperService::new(svc))
        .await
    {
        tracing::debug!(%peer, error = %e, "connection ended with an error");
    }
}

/// Serves `app` over TLS on `listener` until `stop` turns true. Each
/// handshake uses the config in `tls` at that moment.
pub async fn serve_https(
    listener: TcpListener,
    app: Router,
    tls: SharedTls,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((tcp, peer)) = accepted else { continue };
                let acceptor = tokio_rustls::TlsAcceptor::from(current(&tls));
                let app = app.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await {
                        Ok(Ok(stream)) => serve_conn(stream, app, peer).await,
                        Ok(Err(e)) => tracing::debug!(%peer, error = %e, "TLS handshake failed"),
                        Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                    }
                });
            }
            _ = stop.wait_for(|s| *s) => return,
        }
    }
}

/// Serves `app` in plain HTTP on `listener` until `stop` turns true.
pub async fn serve_http(listener: TcpListener, app: Router, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((tcp, peer)) = accepted else { continue };
                tokio::spawn(serve_conn(tcp, app.clone(), peer));
            }
            _ = stop.wait_for(|s| *s) => return,
        }
    }
}

/// The `https://` URL for a plain-HTTP request to `host` (header value,
/// maybe with a port) and `uri`.
pub fn redirect_location(host: &str, uri: &Uri, https_port: u16) -> String {
    let name = match host.strip_prefix('[') {
        // [v6]:port
        Some(rest) => format!("[{}]", rest.split(']').next().unwrap_or_default()),
        None => host.split(':').next().unwrap_or_default().to_owned(),
    };
    let port = if https_port == 443 {
        String::new()
    } else {
        format!(":{https_port}")
    };
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    format!("https://{name}{port}{path}")
}

/// A router answering everything with a redirect to HTTPS on `https_port`.
pub fn redirect_router(https_port: u16) -> Router {
    Router::new().fallback(move |headers: HeaderMap, uri: Uri| async move {
        let Some(host) = headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .filter(|h| !h.is_empty() && !h.contains(['/', '\\', ' ', '@']))
        else {
            return (StatusCode::BAD_REQUEST, "a Host header is required").into_response();
        };
        let location = redirect_location(host, &uri, https_port);
        Response::builder()
            .status(StatusCode::PERMANENT_REDIRECT)
            .header(header::LOCATION, location)
            .body(axum::body::Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    })
}

/// What decides the sockets (the certificate can change without them).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Shape {
    https: bool,
    port: u16,
    redirect_port: Option<u16>,
    devices: Vec<String>,
}

impl Shape {
    fn of(l: &WebListener) -> Shape {
        Shape {
            https: l.https,
            port: l.port,
            redirect_port: l.redirect_port,
            devices: l.devices.clone(),
        }
    }

    /// `(port, device, is_redirect)` for every socket.
    fn sockets(&self) -> Vec<(u16, Option<String>, bool)> {
        let devs: Vec<Option<String>> = if self.devices.is_empty() {
            vec![None]
        } else {
            self.devices.iter().cloned().map(Some).collect()
        };
        let mut out: Vec<_> = devs.iter().map(|d| (self.port, d.clone(), false)).collect();
        if let Some(r) = self.redirect_port {
            out.extend(devs.into_iter().map(|d| (r, d, true)));
        }
        out
    }
}

/// Bound sockets of one shape.
struct Bound {
    shape: Shape,
    stop: watch::Sender<bool>,
    tasks: BTreeMap<(u16, Option<String>), JoinHandle<()>>,
}

impl Bound {
    async fn shutdown(self) {
        let _ = self.stop.send(true);
        for (_, t) in self.tasks {
            let _ = t.await;
        }
    }
}

/// Binds every socket of `shape` not bound yet (a device may appear
/// later).
fn bind_missing(b: &mut Bound, app: &Router, tls: &SharedTls) {
    for (port, dev, redirect) in b.shape.sockets() {
        let key = (port, dev.clone());
        if b.tasks.contains_key(&key) {
            continue;
        }
        let listener = match bind(port, dev.as_deref()) {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(port, device = ?dev, error = %e, "cannot listen yet; retrying");
                continue;
            }
        };
        tracing::info!(port, device = ?dev, https = b.shape.https && !redirect, redirect, "web GUI listening");
        let stop = b.stop.subscribe();
        let task = if redirect {
            tokio::spawn(serve_http(listener, redirect_router(b.shape.port), stop))
        } else if b.shape.https {
            tokio::spawn(serve_https(listener, app.clone(), tls.clone(), stop))
        } else {
            tokio::spawn(serve_http(listener, app.clone(), stop))
        };
        b.tasks.insert(key, task);
    }
}

/// Serves `app` where the applied `system.webgui` says, following changes,
/// until `shutdown` resolves.
pub async fn run(
    state: Arc<AppState>,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    poll: Duration,
) {
    tokio::pin!(shutdown);
    let mut bound: Option<Bound> = None;
    let mut tls: Option<SharedTls> = None;
    let mut cert = String::new();
    loop {
        match fetch(&state).await {
            Ok(l) => {
                if l.cert_chain_pem != cert || tls.is_none() {
                    match server_config(&l.cert_chain_pem, &l.key_pem) {
                        Ok(cfg) => {
                            match &tls {
                                Some(t) => swap(t, cfg),
                                None => tls = Some(Arc::new(RwLock::new(cfg))),
                            }
                            cert = l.cert_chain_pem.clone();
                            tracing::info!(certificate = %l.certificate, "web GUI certificate loaded");
                        }
                        Err(e) => tracing::error!(error = %e, "web GUI certificate refused"),
                    }
                }
                let shape = Shape::of(&l);
                if bound.as_ref().is_some_and(|b| b.shape != shape)
                    && let Some(old) = bound.take()
                {
                    tracing::info!(?shape, "web GUI listener changed; rebinding");
                    old.shutdown().await;
                }
                if let Some(t) = &tls {
                    let b = bound.get_or_insert_with(|| Bound {
                        shape,
                        stop: watch::channel(false).0,
                        tasks: BTreeMap::new(),
                    });
                    bind_missing(b, &app, t);
                }
            }
            Err(e) => tracing::warn!(error = %e, "asking the agent for the web GUI listener"),
        }
        tokio::select! {
            _ = tokio::time::sleep(poll) => {}
            _ = &mut shutdown => break,
        }
    }
    if let Some(b) = bound {
        b.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirects_keep_host_and_path() {
        let uri: Uri = "/ui/login?next=%2F".parse().unwrap();
        assert_eq!(
            redirect_location("fw.lan", &uri, 443),
            "https://fw.lan/ui/login?next=%2F"
        );
        assert_eq!(
            redirect_location("192.168.1.1:80", &uri, 8443),
            "https://192.168.1.1:8443/ui/login?next=%2F"
        );
        assert_eq!(
            redirect_location("[fd00::1]:80", &"/".parse().unwrap(), 443),
            "https://[fd00::1]/"
        );
    }

    #[test]
    fn sockets_per_device_and_redirect() {
        let s = Shape {
            https: true,
            port: 443,
            redirect_port: Some(80),
            devices: vec!["lo".into(), "eth1".into()],
        };
        assert_eq!(s.sockets().len(), 4);
        let all = Shape {
            devices: vec![],
            redirect_port: None,
            ..s
        };
        assert_eq!(all.sockets(), [(443, None, false)]);
    }
}
