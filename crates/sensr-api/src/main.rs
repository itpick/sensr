//! `sensr-api` binary.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;

/// The unprivileged sensr HTTP API.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Address to listen on. TLS termination is not built in yet; keep this
    /// on loopback or behind a TLS proxy.
    #[arg(long, default_value = "127.0.0.1:8080", env = "SENSR_API_LISTEN")]
    listen: SocketAddr,
    /// sensr-agent socket.
    #[arg(long, default_value = sensr_ipc::client::DEFAULT_SOCKET, env = "SENSR_AGENT_SOCKET")]
    socket: PathBuf,
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
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("binding {}", args.listen))?;
    tracing::info!(listen = %args.listen, agent = %args.socket.display(), "sensr-api listening");
    let state = sensr_api::AppState::new(args.socket);
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
    sensr_api::serve(listener, state, shutdown).await?;
    Ok(())
}
