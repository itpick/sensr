//! `sensr-api` binary.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use sensr_api::tls;

/// The unprivileged sensr HTTP API.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Listen on this one address instead of where `system.webgui` says
    /// (development, tests). Served over HTTPS with the agent's certificate
    /// unless `--insecure-http` is given.
    #[arg(long, env = "SENSR_API_LISTEN")]
    listen: Option<SocketAddr>,
    /// With `--listen`: plain HTTP. Credentials then travel in clear; only
    /// for loopback or behind a TLS proxy.
    #[arg(long, requires = "listen")]
    insecure_http: bool,
    /// sensr-agent socket.
    #[arg(long, default_value = sensr_ipc::client::DEFAULT_SOCKET, env = "SENSR_AGENT_SOCKET")]
    socket: PathBuf,
    /// Serve the web UI from this built site directory (holds `pkg/sensr-ui.*`).
    #[arg(long, env = "SENSR_UI_ROOT")]
    ui_root: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();
    let state = sensr_api::AppState::new(args.socket.clone());
    let app = sensr_api::app(state.clone(), args.ui_root.clone());
    let shutdown = async {
        use tokio::signal::unix::{SignalKind, signal};
        let (Ok(mut term), Ok(mut int)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) else {
            return std::future::pending().await;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = int.recv() => {}
        }
    };
    let Some(addr) = args.listen else {
        tracing::info!(agent = %args.socket.display(), "sensr-api serving where system.webgui says");
        tls::run(state, app, shutdown, tls::POLL).await;
        return Ok(());
    };
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    let (stop_tx, stop) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown.await;
        let _ = stop_tx.send(true);
    });
    if args.insecure_http {
        tracing::warn!(listen = %addr, "plain HTTP: credentials travel in clear");
        tls::serve_http(listener, app, stop).await;
        return Ok(());
    }
    // The agent may still be starting.
    let listener_cfg = loop {
        match tls::fetch(&state).await {
            Ok(l) => break l,
            Err(e) => {
                tracing::warn!(error = %e, "waiting for the agent's certificate");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    };
    let cfg = tls::shared(&listener_cfg).context("loading the web GUI certificate")?;
    tracing::info!(listen = %addr, certificate = %listener_cfg.certificate, "sensr-api listening (HTTPS)");
    tls::serve_https(listener, app, cfg, stop).await;
    Ok(())
}
