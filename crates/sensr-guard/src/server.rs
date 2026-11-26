//! The control socket: JSON lines ([`crate::proto`]), one request per line,
//! one reply per request, like sensr-scan's.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::daemon::{Backend, Daemon, Fetcher, check_packs};
use crate::proto::{Reply, Request};

/// Longest request line accepted, in bytes.
pub const MAX_LINE: u64 = 64 * 1024;
/// A connection that sends nothing for this long is closed.
pub const IDLE: Duration = Duration::from_secs(60);

/// What the socket, the event loop and the pack check share.
pub struct Shared<B: Backend> {
    daemon: Mutex<Daemon<B>>,
    fetcher: Box<dyn Fetcher>,
}

impl<B: Backend> Shared<B> {
    /// Share `daemon`, fetching packs with `fetcher`.
    pub fn new(daemon: Daemon<B>, fetcher: Box<dyn Fetcher>) -> Self {
        Self {
            daemon: Mutex::new(daemon),
            fetcher,
        }
    }

    /// The daemon, locked (a panic elsewhere does not wedge it).
    pub fn lock(&self) -> MutexGuard<'_, Daemon<B>> {
        self.daemon
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Check for pack updates (the lock is not held while downloading).
    pub fn check_packs(&self) -> Reply {
        check_packs(&self.daemon, self.fetcher.as_ref())
    }

    /// Answer one request. Blocks (map writes, downloads): async callers
    /// use `spawn_blocking`.
    pub fn handle(&self, req: &Request) -> Reply {
        match req {
            Request::CheckPacks => self.check_packs(),
            other => self.lock().handle(other),
        }
    }
}

/// Bind the socket at `path` (replacing a stale one), mode 0660: the group
/// (sensr) may connect.
pub fn bind(path: &Path) -> io::Result<UnixListener> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(l)
}

/// Serve connections until an accept fails.
pub async fn serve<B: Backend + 'static>(
    l: UnixListener,
    shared: Arc<Shared<B>>,
) -> io::Result<()> {
    loop {
        let (s, _) = l.accept().await?;
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            if let Err(e) = connection(s, shared).await {
                tracing::debug!(error = %e, "control connection ended");
            }
        });
    }
}

async fn connection<B: Backend + 'static>(s: UnixStream, shared: Arc<Shared<B>>) -> io::Result<()> {
    let (r, mut w) = s.into_split();
    let mut r = BufReader::new(r);
    let mut line = String::new();
    loop {
        line.clear();
        let mut limited = (&mut r).take(MAX_LINE);
        let Ok(n) = tokio::time::timeout(IDLE, limited.read_line(&mut line)).await else {
            return Ok(());
        };
        let n = n?;
        if n == 0 {
            return Ok(());
        }
        let too_long = !line.ends_with('\n') && n as u64 >= MAX_LINE;
        let reply = if too_long {
            Reply::Error("request too long".into())
        } else if line.trim().is_empty() {
            continue;
        } else {
            match serde_json::from_str::<Request>(&line) {
                Ok(req) => {
                    let sh = Arc::clone(&shared);
                    tokio::task::spawn_blocking(move || sh.handle(&req))
                        .await
                        .map_err(io::Error::other)?
                }
                Err(e) => Reply::Error(format!("bad request: {e}")),
            }
        };
        let mut out = serde_json::to_vec(&reply).map_err(io::Error::other)?;
        out.push(b'\n');
        w.write_all(&out).await?;
        if too_long {
            return Ok(());
        }
    }
}
