//! The control socket: JSON lines ([`crate::proto`]), one request per line,
//! one reply per request, like sensr-scan's.
//!
//! The socket is 0660 for group sensr, so anyone in the group may ask for
//! the status. Requests that change something (reload, kill switch, pack
//! check) are taken only from the uids in the trusted list (root and
//! sensr-api, which authenticates and authorises the owner), checked with
//! the peer's credentials (SO_PEERCRED).

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
    trusted: Vec<u32>,
}

/// Whether a peer with `uid` (`None`: unknown) may make `req`: status from
/// anyone who can reach the socket, everything else from `trusted` only.
pub fn authorize(req: &Request, uid: Option<u32>, trusted: &[u32]) -> Result<(), String> {
    if matches!(req, Request::Status) {
        return Ok(());
    }
    match uid {
        Some(u) if trusted.contains(&u) => Ok(()),
        Some(u) => Err(format!(
            "uid {u} is not allowed to change the guard (only root and sensr-api are)"
        )),
        None => Err("the peer's credentials are unknown: not allowed to change the guard".into()),
    }
}

impl<B: Backend> Shared<B> {
    /// Share `daemon`, fetching packs with `fetcher`. Only root may change
    /// anything until [`Self::with_trusted`] says otherwise.
    pub fn new(daemon: Daemon<B>, fetcher: Box<dyn Fetcher>) -> Self {
        Self {
            daemon: Mutex::new(daemon),
            fetcher,
            trusted: vec![0],
        }
    }

    /// The uids whose changing requests are taken.
    #[must_use]
    pub fn with_trusted(mut self, uids: Vec<u32>) -> Self {
        self.trusted = uids;
        self
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
    let uid = s.peer_cred().ok().map(|c| c.uid());
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
                Ok(req) => match authorize(&req, uid, &shared.trusted) {
                    Err(e) => {
                        tracing::warn!(?uid, request = ?req, "refused: {e}");
                        Reply::Error(e)
                    }
                    Ok(()) => {
                        let sh = Arc::clone(&shared);
                        tokio::task::spawn_blocking(move || sh.handle(&req))
                            .await
                            .map_err(io::Error::other)?
                    }
                },
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
