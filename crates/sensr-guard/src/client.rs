//! A blocking client for the daemon's control socket (used by the API and
//! the CLI).

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::proto::{Reply, Request};

/// Read and write timeout. Longer than the scanner's: `CheckPacks` fetches
/// over the network.
pub const TIMEOUT: Duration = Duration::from_secs(30);

/// Send one request and read its reply.
///
/// # Errors
/// The socket could not be reached, timed out after [`TIMEOUT`], closed
/// without a reply, or the reply was not valid JSON.
pub fn send(path: &Path, req: &Request) -> io::Result<Reply> {
    let s = UnixStream::connect(path)?;
    s.set_read_timeout(Some(TIMEOUT))?;
    s.set_write_timeout(Some(TIMEOUT))?;
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
}
