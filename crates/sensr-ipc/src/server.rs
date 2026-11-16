//! The agent side: accept connections, authenticate peers by `SO_PEERCRED`,
//! dispatch requests to a [`Handler`] and pump stream frames.

use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

use crate::frame::{
    ClientBody, Envelope, FrameError, ServerBody, StreamItem, decode, read_frame_bytes, write_frame,
};
use crate::proto::{ErrorKind, IpcError, Request, Response};

/// Kernel-reported identity of the process on the other end of the socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// Effective uid.
    pub uid: u32,
    /// Effective gid.
    pub gid: u32,
    /// Process id (not available on every platform).
    pub pid: Option<i32>,
}

impl PeerCred {
    fn of(stream: &UnixStream) -> std::io::Result<Self> {
        let cred = stream.peer_cred()?;
        Ok(Self {
            uid: cred.uid(),
            gid: cred.gid(),
            pid: cred.pid(),
        })
    }
}

/// What a handler returns for one request.
pub enum Reply {
    /// A single response frame.
    Once(Response),
    /// Open a stream: the client gets [`Response::StreamOpened`], then one
    /// item frame per message until the sender drops or the client cancels.
    Stream(mpsc::Receiver<StreamItem>),
}

impl From<Response> for Reply {
    fn from(r: Response) -> Self {
        Reply::Once(r)
    }
}

impl From<Result<Response, IpcError>> for Reply {
    fn from(r: Result<Response, IpcError>) -> Self {
        Reply::Once(r.unwrap_or_else(Response::Error))
    }
}

/// Serves requests. Implemented by the agent.
pub trait Handler: Send + Sync + 'static {
    /// Handles one request from `peer`.
    fn handle(&self, peer: PeerCred, req: Request) -> impl Future<Output = Reply> + Send;
}

/// Binds the agent socket at `path` with permission bits `mode`, replacing a
/// stale socket file left by a previous run.
pub fn bind(path: &Path, mode: u32) -> std::io::Result<UnixListener> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

/// How long [`serve`] waits for in-flight requests after shutdown is
/// signalled before abandoning them.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Accepts connections until `shutdown` turns true, then lets every
/// connection finish its current request (bounded by [`SHUTDOWN_GRACE`]).
pub async fn serve<H: Handler>(
    listener: UnixListener,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let handler = handler.clone();
                    let shutdown = shutdown.clone();
                    conns.spawn(async move {
                        if let Err(e) = connection(stream, handler, shutdown).await {
                            tracing::debug!(error = %e, "ipc connection closed with error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "ipc accept failed");
                    // Back off so fd exhaustion does not become a busy loop.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
            // Reap finished connections so the set does not grow forever.
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            _ = stopped(&mut shutdown) => break,
        }
    }
    drop(listener);
    let drain = async { while conns.join_next().await.is_some() {} };
    if tokio::time::timeout(SHUTDOWN_GRACE, drain).await.is_err() {
        conns.abort_all();
    }
}

enum Incoming {
    Frame(Vec<u8>),
    Closed,
    Failed(FrameError),
}

async fn connection<H: Handler>(
    stream: UnixStream,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), FrameError> {
    let peer = PeerCred::of(&stream)?;
    let (mut rd, mut wr) = stream.into_split();

    // A dedicated reader keeps frame reads intact while the main loop
    // `select!`s between incoming frames and outgoing stream items
    // (`read_exact` is not cancel-safe).
    let (tx, mut rx) = mpsc::channel::<Incoming>(8);
    let reader = tokio::spawn(async move {
        loop {
            let msg = match read_frame_bytes(&mut rd).await {
                Ok(Some(bytes)) => Incoming::Frame(bytes),
                Ok(None) => Incoming::Closed,
                Err(e) => Incoming::Failed(e),
            };
            let last = !matches!(msg, Incoming::Frame(_));
            if tx.send(msg).await.is_err() || last {
                break;
            }
        }
    });

    let result = async {
        loop {
            let msg = tokio::select! {
                msg = rx.recv() => msg.unwrap_or(Incoming::Closed),
                _ = stopped(&mut shutdown) => return Ok(()),
            };
            let bytes = match msg {
                Incoming::Frame(bytes) => bytes,
                Incoming::Closed => return Ok(()),
                Incoming::Failed(e) => return Err(e),
            };
            let env = match decode::<ClientBody>(&bytes) {
                Ok(env) => env,
                Err(FrameError::Decode {
                    id: Some(id),
                    message,
                }) => {
                    let err = IpcError::new(ErrorKind::BadRequest, message);
                    send(&mut wr, id, ServerBody::Response(Response::Error(err))).await?;
                    continue;
                }
                Err(FrameError::Version { id, theirs }) => {
                    let err = IpcError::new(
                        ErrorKind::VersionMismatch,
                        format!(
                            "client speaks ipc v{theirs}, agent v{}",
                            crate::PROTOCOL_VERSION
                        ),
                    );
                    send(&mut wr, id, ServerBody::Response(Response::Error(err))).await?;
                    continue;
                }
                Err(e) => {
                    // No envelope: we cannot tell which request this was, so
                    // answer once with id 0 and drop the connection.
                    let err = IpcError::new(ErrorKind::BadRequest, e.to_string());
                    send(&mut wr, 0, ServerBody::Response(Response::Error(err))).await?;
                    return Err(e);
                }
            };
            let id = env.id;
            let req = match env.body {
                ClientBody::Request(req) => req,
                // Nothing is streaming on this connection; a late cancel is harmless.
                ClientBody::Cancel => continue,
            };
            match handler.handle(peer, req).await {
                Reply::Once(resp) => send(&mut wr, id, ServerBody::Response(resp)).await?,
                Reply::Stream(items) => {
                    if !pump(&mut wr, &mut rx, &mut shutdown, id, items).await? {
                        return Ok(());
                    }
                }
            }
        }
    }
    .await;
    reader.abort();
    result
}

/// Forwards stream items until the source ends, the client cancels or the
/// agent shuts down. Returns false when the connection should close.
async fn pump(
    wr: &mut OwnedWriteHalf,
    rx: &mut mpsc::Receiver<Incoming>,
    shutdown: &mut watch::Receiver<bool>,
    id: u64,
    mut items: mpsc::Receiver<StreamItem>,
) -> Result<bool, FrameError> {
    send(wr, id, ServerBody::Response(Response::StreamOpened)).await?;
    loop {
        tokio::select! {
            item = items.recv() => match item {
                Some(item) => send(wr, id, ServerBody::Item(item)).await?,
                None => {
                    send(wr, id, ServerBody::End(None)).await?;
                    return Ok(true);
                }
            },
            msg = rx.recv() => match msg {
                Some(Incoming::Frame(bytes)) => match decode::<ClientBody>(&bytes) {
                    Ok(Envelope { body: ClientBody::Cancel, id: cid, .. }) if cid == id => {
                        send(wr, id, ServerBody::End(None)).await?;
                        return Ok(true);
                    }
                    Ok(Envelope { id: other, .. }) => {
                        let err = IpcError::new(
                            ErrorKind::Conflict,
                            "a stream is open on this connection; cancel it first",
                        );
                        send(wr, other, ServerBody::Response(Response::Error(err))).await?;
                    }
                    Err(e) => return Err(e),
                },
                Some(Incoming::Failed(e)) => return Err(e),
                Some(Incoming::Closed) | None => return Ok(false),
            },
            _ = stopped(shutdown) => {
                let err = IpcError::new(ErrorKind::Internal, "agent shutting down");
                send(wr, id, ServerBody::End(Some(err))).await?;
                return Ok(false);
            }
        }
    }
}

async fn send(wr: &mut OwnedWriteHalf, id: u64, body: ServerBody) -> Result<(), FrameError> {
    write_frame(wr, &Envelope::new(id, body)).await
}

/// Resolves once shutdown is requested (or its sender is gone). Wrapping
/// `wait_for` drops its non-`Send` guard before the future completes.
async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}
