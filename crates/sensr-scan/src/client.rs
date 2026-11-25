//! A blocking client for the daemon's control socket (used by the agent and
//! the API).

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use crate::proto::{Reply, Request};

/// Read and write timeout.
pub const TIMEOUT: Duration = Duration::from_secs(2);

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
            "sensr-scan closed the connection without replying",
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
            (&s).write_all(b"{\"op\":\"started\",\"job_id\":7}\n")
                .unwrap();
            got
        });
        assert_eq!(
            send(&path, &Request::Status).unwrap(),
            Reply::Started { job_id: 7 }
        );
        assert_eq!(t.join().unwrap(), "{\"op\":\"status\"}\n");
    }

    #[test]
    fn errors_on_silence_close_and_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.sock");
        assert!(send(&path, &Request::Status).is_err(), "no socket");

        let l = UnixListener::bind(&path).unwrap();
        let t = std::thread::spawn(move || {
            // Closes without a reply.
            drop(l.accept().unwrap());
            // Garbage.
            let (s, _) = l.accept().unwrap();
            (&s).write_all(b"nope\n").unwrap();
            // Silent past the timeout.
            let (s, _) = l.accept().unwrap();
            std::thread::sleep(TIMEOUT + Duration::from_millis(500));
            drop(s);
        });
        assert_eq!(
            send(&path, &Request::Status).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(
            send(&path, &Request::Status).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let e = send(&path, &Request::Status).unwrap_err();
        assert!(
            matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "{e:?}"
        );
        t.join().unwrap();
    }
}
