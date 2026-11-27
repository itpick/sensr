//! A blocking client for the daemon's control socket (used by the API and
//! the CLI).

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::proto::{Reply, Request};

/// Read and write timeout of [`send`]. Longer than the scanner's:
/// `CheckPacks` fetches over the network.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// Read and write timeout for quick questions such as `Status`.
pub const SHORT_TIMEOUT: Duration = Duration::from_secs(2);

/// Send one request and read its reply.
///
/// # Errors
/// The socket could not be reached, timed out after [`TIMEOUT`], closed
/// without a reply, or the reply was not valid JSON.
pub fn send(path: &Path, req: &Request) -> io::Result<Reply> {
    send_with_timeout(path, req, TIMEOUT)
}

/// Like [`send`], with `timeout` for reading and writing.
///
/// # Errors
/// As [`send`], with `timeout` in place of [`TIMEOUT`].
pub fn send_with_timeout(path: &Path, req: &Request, timeout: Duration) -> io::Result<Reply> {
    let s = UnixStream::connect(path)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    let mut line = serde_json::to_vec(req).map_err(io::Error::other)?;
    line.push(b'\n');
    (&s).write_all(&line)?;
    let mut reply = String::new();
    BufReader::new(&s).read_line(&mut reply)?;
    if reply.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "sensr-guard closed the connection without replying",
        ));
    }
    serde_json::from_str(&reply).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Like [`send_with_timeout`], but while the socket is missing or refuses
/// connections (the daemon is still starting: it binds the socket only once
/// its programs are loaded) keep trying for up to `wait`.
///
/// # Errors
/// As [`send_with_timeout`]; the last connect error once `wait` is over.
pub fn send_when_up(
    path: &Path,
    req: &Request,
    timeout: Duration,
    wait: Duration,
) -> io::Result<Reply> {
    let deadline = std::time::Instant::now() + wait;
    loop {
        match send_with_timeout(path, req, timeout) {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(100));
            }
            r => return r,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn sends_a_line_and_reads_the_reply() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let l = UnixListener::bind(&path).unwrap();
        let t = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut got = String::new();
            BufReader::new(&s).read_line(&mut got).unwrap();
            (&s).write_all(b"{\"op\":\"ok\"}\n").unwrap();
            got
        });
        let r = send(&path, &Request::KillSwitch { on: true }).unwrap();
        assert_eq!(r, Reply::Ok);
        assert_eq!(t.join().unwrap(), "{\"op\":\"kill_switch\",\"on\":true}\n");
    }

    #[test]
    fn a_short_timeout_gives_up_on_a_slow_peer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let l = UnixListener::bind(&path).unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let t = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            BufReader::new(&s).read_line(&mut String::new()).unwrap();
            rx.recv().unwrap(); // hold the connection open without replying
        });
        let started = std::time::Instant::now();
        let e = send_with_timeout(&path, &Request::Status, Duration::from_millis(100)).unwrap_err();
        assert!(
            matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{e:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        tx.send(()).unwrap();
        t.join().unwrap();
    }

    #[test]
    fn a_missing_socket_and_a_silent_peer_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let e = send(&dir.path().join("none"), &Request::Status).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        let path = dir.path().join("s.sock");
        let l = UnixListener::bind(&path).unwrap();
        let t = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            BufReader::new(&s).read_line(&mut String::new()).unwrap();
        });
        let e = send(&path, &Request::Status).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        t.join().unwrap();
    }

    #[test]
    fn waiting_for_the_socket_reaches_a_daemon_that_binds_late() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        let p2 = path.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            let l = UnixListener::bind(&p2).unwrap();
            let (s, _) = l.accept().unwrap();
            BufReader::new(&s).read_line(&mut String::new()).unwrap();
            (&s).write_all(b"{\"op\":\"ok\"}\n").unwrap();
        });
        let r = send_when_up(&path, &Request::Reload, TIMEOUT, Duration::from_secs(10)).unwrap();
        assert_eq!(r, Reply::Ok);
        t.join().unwrap();
    }

    #[test]
    fn waiting_for_the_socket_gives_up_after_the_wait() {
        let dir = tempfile::tempdir().unwrap();
        let started = std::time::Instant::now();
        let e = send_when_up(
            &dir.path().join("none"),
            &Request::Reload,
            TIMEOUT,
            Duration::from_millis(300),
        )
        .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
