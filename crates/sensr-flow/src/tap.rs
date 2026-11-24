//! The dnstap socket: Unbound connects to it and streams client queries and
//! responses (Frame Streams, [`crate::dnstap`]).
//!
//! The daemon creates the socket itself, so it sets the permissions: mode
//! 0660 and group [`crate::config::DNSTAP_GROUP`] (Unbound's and the
//! daemon's users are its only members; the unit's `UMask` is 0027, so both
//! are set explicitly after `bind`). A socket file left by an earlier run is
//! removed first. Unbound reconnects after each of its restarts, and an old
//! connection may linger a moment, so several connections are served at
//! once, each on its own thread, up to [`MAX_CONNECTIONS`].
//!
//! Every data frame stamps [`Shared::last_frame`] (the staleness watch).
//! Client responses go to the daemon's main loop over a bounded channel; a
//! full channel drops the event and counts it, so a slow database never
//! blocks Unbound. Each connection buffers at most one frame.

use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::dnstap::{DnstapEvent, EventKind, Frame, FrameReader, decode};

/// Connections served at once (Unbound uses one; a restart briefly two).
pub const MAX_CONNECTIONS: usize = 4;
/// Events waiting for the main loop at most. An event is a name (≤ 253
/// bytes) and at most 32 answers (`dns::MAX_ANSWERS`, addresses or CNAME
/// targets), so about 0.5 KB typically and under 9 KB at worst: the queue
/// holds ~2 MB typically, ~36 MB at the very worst. The main loop empties
/// it every sample.
pub const QUEUE: usize = 4096;
/// Bytes read from a connection at a time.
const READ_CHUNK: usize = 16 * 1024;

/// Counters shared by the listener threads and the main loop.
#[derive(Debug, Default)]
pub struct Shared {
    /// Unix seconds of the newest data frame (0: none yet).
    pub last_frame: AtomicI64,
    /// Data frames read.
    pub frames: AtomicU64,
    /// Client responses dropped because the queue was full.
    pub dropped: AtomicU64,
    /// Connections open now.
    pub connections: AtomicUsize,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

/// Creates the socket at `path`: removes a stale one, binds, and sets mode
/// 0660 and, when `group` is given, that group.
pub fn bind(path: &Path, group: Option<&str>) -> io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(_) => {}
    }
    let l = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    if let Some(g) = group {
        set_group(path, g)?;
        // Unbound reaches the socket through its directory, which systemd
        // creates as the unit's RuntimeDirectory owned by our primary group;
        // a chgrp in ExecStartPre did not survive on the router (2026-11-24),
        // leaving Unbound unable to traverse it. We own the directory and
        // are a member of the group, so set it ourselves.
        if let Some(dir) = path.parent()
            && let Err(e) = set_group(dir, g)
        {
            tracing::warn!(dir = %dir.display(), group = g, error = %e,
                    "could not set the dnstap directory's group; Unbound may not reach the socket");
        }
    }
    Ok(l)
}

#[cfg(target_os = "linux")]
fn set_group(path: &Path, group: &str) -> io::Result<()> {
    let g = nix::unistd::Group::from_name(group)
        .map_err(io::Error::from)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("group {group}")))?;
    nix::unistd::chown(path, None, Some(g.gid)).map_err(io::Error::from)
}

#[cfg(not(target_os = "linux"))]
fn set_group(_path: &Path, group: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("setting group {group} is only done on Linux"),
    ))
}

/// Accepts connections for ever, serving each on its own thread.
pub fn serve(listener: UnixListener, tx: SyncSender<DnstapEvent>, shared: Arc<Shared>) {
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "accepting a dnstap connection");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        if shared.connections.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            tracing::warn!("too many dnstap connections; refusing one");
            continue;
        }
        shared.connections.fetch_add(1, Ordering::Relaxed);
        let (tx, conn_shared) = (tx.clone(), Arc::clone(&shared));
        let spawned = std::thread::Builder::new()
            .name("dnstap-conn".into())
            .spawn(move || {
                let r = serve_stream(stream, &tx, &conn_shared);
                conn_shared.connections.fetch_sub(1, Ordering::Relaxed);
                match r {
                    Ok(()) => tracing::info!("dnstap connection closed"),
                    Err(e) => tracing::info!(error = %e, "dnstap connection ended"),
                }
            });
        if let Err(e) = spawned {
            shared.connections.fetch_sub(1, Ordering::Relaxed);
            tracing::warn!(error = %e, "starting a dnstap connection thread");
        }
    }
}

fn serve_stream(
    stream: UnixStream,
    tx: &SyncSender<DnstapEvent>,
    shared: &Shared,
) -> io::Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    tracing::info!("dnstap connection from the resolver");
    handle(stream, tx, shared)
}

/// Reads one Frame Streams connection until it ends: answers the
/// handshake, forwards client responses, answers STOP with FINISH, and
/// closes when the reader is finished (STOP, an unusable content type, a
/// lost stream).
pub fn handle<S: Read + Write>(
    mut s: S,
    tx: &SyncSender<DnstapEvent>,
    shared: &Shared,
) -> io::Result<()> {
    let mut reader = FrameReader::default();
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        let n = match s.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let frames = reader.push(buf.get(..n).unwrap_or_default());
        for f in frames {
            let Frame::Data(d) = f else { continue };
            shared.frames.fetch_add(1, Ordering::Relaxed);
            shared.last_frame.store(now(), Ordering::Relaxed);
            let Some(ev) = decode(&d) else { continue };
            if ev.kind != EventKind::ClientResponse {
                continue;
            }
            match tx.try_send(ev) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    shared.dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Disconnected(_)) => {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "daemon stopping"));
                }
            }
        }
        if let Some(reply) = reader.reply() {
            s.write_all(&reply)?;
            s.flush()?;
        }
        if reader.finished() {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dnstap::tests::{control, data, dnstap, youtube_response};
    use crate::dnstap::{ACCEPT, CONTENT_TYPE, FINISH, READY, START, STOP};
    use std::sync::mpsc::sync_channel;

    fn read_control(s: &mut UnixStream) -> Vec<u8> {
        let mut head = [0u8; 8];
        s.read_exact(&mut head).unwrap();
        let len = u32::from_be_bytes(head[4..8].try_into().unwrap()) as usize;
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).unwrap();
        let mut f = head.to_vec();
        f.extend(body);
        f
    }

    /// One writer session: handshake, `n` responses, STOP, FINISH.
    fn session(path: &Path, n: usize) {
        let mut c = UnixStream::connect(path).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(&control(READY, &[CONTENT_TYPE])).unwrap();
        assert_eq!(read_control(&mut c), control(ACCEPT, &[CONTENT_TYPE]));
        let mut stream = control(START, &[CONTENT_TYPE]);
        for _ in 0..n {
            stream.extend(data(&dnstap(
                6,
                &[192, 168, 1, 23],
                1_700_000_000,
                &youtube_response(),
            )));
            // a client query: read, but not forwarded
            stream.extend(data(&dnstap(
                5,
                &[192, 168, 1, 23],
                1_700_000_000,
                &[0; 12],
            )));
        }
        stream.extend(control(STOP, &[]));
        // written in awkward pieces
        for chunk in stream.chunks(7) {
            c.write_all(chunk).unwrap();
        }
        assert_eq!(read_control(&mut c), control(FINISH, &[]));
        let mut rest = Vec::new();
        c.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty(), "closed after FINISH");
    }

    #[test]
    fn dnstap_socket_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dnstap.sock");
        // a socket left by an earlier run is replaced
        drop(UnixListener::bind(&path).unwrap());
        let l = bind(&path, None).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        let (tx, rx) = sync_channel(QUEUE);
        let shared = Arc::new(Shared::default());
        let s2 = Arc::clone(&shared);
        std::thread::spawn(move || serve(l, tx, s2));
        session(&path, 3);
        // Unbound restarted: a new connection is served too
        session(&path, 2);
        let got: Vec<DnstapEvent> = (0..5)
            .map(|_| rx.recv_timeout(Duration::from_secs(10)).unwrap())
            .collect();
        assert!(got.iter().all(|e| e.qname == "www.youtube.com"));
        assert!(rx.try_recv().is_err(), "queries are not forwarded");
        assert_eq!(shared.frames.load(Ordering::Relaxed), 10);
        assert!(shared.last_frame.load(Ordering::Relaxed) > 0);
        // a writer offering only another content type is answered and closed
        let mut c = UnixStream::connect(&path).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.write_all(&control(READY, &[b"protobuf:other"])).unwrap();
        assert_eq!(read_control(&mut c), control(ACCEPT, &[]));
        let mut rest = Vec::new();
        c.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    }

    #[test]
    fn a_full_queue_drops_instead_of_blocking() {
        let (tx, rx) = sync_channel(1);
        let shared = Shared::default();
        let mut stream = control(READY, &[CONTENT_TYPE]);
        stream.extend(control(START, &[CONTENT_TYPE]));
        for _ in 0..3 {
            stream.extend(data(&dnstap(6, &[10, 0, 0, 1], 5, &youtube_response())));
        }
        let mut io = Duplex(io::Cursor::new(stream), Vec::new());
        handle(&mut io, &tx, &shared).unwrap();
        assert_eq!(shared.dropped.load(Ordering::Relaxed), 2);
        assert!(rx.try_recv().is_ok());
        assert_eq!(io.1, control(ACCEPT, &[CONTENT_TYPE]));
    }

    #[test]
    fn bind_refuses_to_remove_a_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dnstap.sock");
        std::fs::write(&path, b"not a socket").unwrap();
        assert!(bind(&path, None).is_err());
        assert!(path.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bind_sets_the_group() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dnstap.sock");
        let gid = nix::unistd::getegid();
        let Some(g) = nix::unistd::Group::from_gid(gid).unwrap() else {
            return; // no name for our group in this environment
        };
        let _l = bind(&path, Some(&g.name)).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&path).unwrap().gid(), gid.as_raw());
        assert!(bind(&dir.path().join("b.sock"), Some("no-such-group-sensr")).is_err());
    }

    struct Duplex(io::Cursor<Vec<u8>>, Vec<u8>);

    impl Read for Duplex {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.0.read(b)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.1.write(b)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
