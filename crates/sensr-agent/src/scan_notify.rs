//! Automatic first-join port scans: tells the `sensr-scan` daemon about the
//! inventory's devices over its control socket
//! (docs/superpowers/specs/2026-11-25-port-scanner-design.md).
//!
//! The host collector calls [`SocketNotify::new_device`] from its poll; that
//! only queues the device, and the `sensr-scan-notify` thread does the
//! talking, so the inventory never waits on the scanner. The daemon decides
//! whether a device is scanned (one complete scan, owner-cancelled,
//! `auto_scan_new` off, excluded, disabled); the agent only reports.
//!
//! The thread sends `Known` (every current candidate) when it starts and
//! again whenever the socket answers after a failure, so devices that came
//! and went while the daemon was down or disabled are picked up. While the
//! socket is unavailable it retries every [`RETRY`]; while it answers,
//! `Known` is resent every [`RESYNC`] for scans a daemon restart lost.

use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

use sensr_scan::proto::{JobKind, KnownDevice, Reply, Request, StartReq};

use crate::hosts::ScanNotify;

/// Devices waiting for the thread; more are dropped (with a `Known` resend
/// to cover them).
pub const QUEUE: usize = 1024;
/// How often an unavailable socket is tried again.
pub const RETRY: Duration = Duration::from_secs(30);
/// How often `Known` is resent while the socket answers. Each request is
/// its own connection, so a daemon restart (every Port Scan apply restarts
/// it, emptying its queue) is otherwise invisible here.
pub const RESYNC: Duration = Duration::from_secs(600);

/// Sends one request to the daemon ([`sensr_scan::client::send`] in
/// production).
pub type Transport = Arc<dyn Fn(&Request) -> io::Result<Reply> + Send + Sync>;
/// The devices to list in `Known` (the collector's scan candidates).
pub type KnownFn = Arc<dyn Fn() -> Vec<KnownDevice> + Send + Sync>;

/// The collector's side: a bounded queue to the notifier thread. Dropping it
/// ends the thread.
pub struct SocketNotify {
    tx: SyncSender<(String, Ipv4Addr)>,
    /// Set when a device was dropped on a full queue: the thread resends
    /// `Known`, which lists it.
    resync: Arc<AtomicBool>,
}

/// The thread's side.
struct Worker {
    rx: Receiver<(String, Ipv4Addr)>,
    resync: Arc<AtomicBool>,
    transport: Transport,
    known: KnownFn,
    /// [`RETRY`] and [`RESYNC`] (shorter in tests).
    retry: Duration,
    resync_every: Duration,
}

impl SocketNotify {
    /// Notifies the daemon on [`sensr_scan::config::SOCKET`].
    pub fn system(known: KnownFn) -> Arc<Self> {
        Self::start(
            Arc::new(|r| sensr_scan::client::send(Path::new(sensr_scan::config::SOCKET), r)),
            known,
            RETRY,
            RESYNC,
        )
    }

    /// Starts the `sensr-scan-notify` thread over `transport`, retrying an
    /// unavailable socket every `retry` and resending `Known` every
    /// `resync_every` while it answers.
    pub fn start(
        transport: Transport,
        known: KnownFn,
        retry: Duration,
        resync_every: Duration,
    ) -> Arc<Self> {
        let (n, w) = Self::channel(QUEUE, transport, known, retry, resync_every);
        let r = std::thread::Builder::new()
            .name("sensr-scan-notify".into())
            .spawn(move || w.run());
        if let Err(e) = r {
            tracing::error!(error = %e, "port scan notifier not started");
        }
        Arc::new(n)
    }

    fn channel(
        cap: usize,
        transport: Transport,
        known: KnownFn,
        retry: Duration,
        resync_every: Duration,
    ) -> (Self, Worker) {
        let (tx, rx) = sync_channel(cap);
        let resync = Arc::new(AtomicBool::new(false));
        (
            Self {
                tx,
                resync: Arc::clone(&resync),
            },
            Worker {
                rx,
                resync,
                transport,
                known,
                retry,
                resync_every,
            },
        )
    }
}

impl ScanNotify for SocketNotify {
    fn new_device(&self, mac: &str, ipv4: Ipv4Addr) {
        match self.tx.try_send((mac.to_owned(), ipv4)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                // once per overflow: a first poll can bring hundreds
                if !self.resync.swap(true, Ordering::SeqCst) {
                    tracing::warn!(
                        mac,
                        "port scan notifier queue full; devices dropped, the daemon gets the full list instead"
                    );
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                tracing::debug!(mac, "port scan notifier not running");
            }
        }
    }
}

fn start_req(mac: String, ipv4: Ipv4Addr) -> Request {
    Request::Start(StartReq {
        target: ipv4.to_string(),
        kind: JobKind::Device,
        auto: true,
        mac: Some(mac),
        public_ok: false,
        confirm: false,
        include_excluded: false,
    })
}

impl Worker {
    /// Until the [`SocketNotify`] is dropped.
    fn run(self) {
        // whether the last request reached the daemon
        let mut synced = false;
        let mut next_try = Instant::now();
        loop {
            let resync = self.resync.swap(false, Ordering::SeqCst);
            if (!synced && Instant::now() >= next_try) || (synced && resync) {
                let macs = (self.known)();
                match (self.transport)(&Request::Known { macs }) {
                    Ok(_) => {
                        if !synced {
                            tracing::debug!("port scanner reached; known devices sent");
                        }
                        synced = true;
                    }
                    Err(e) => {
                        // the daemon is off unless Port Scan is enabled
                        tracing::debug!(error = %e, "port scanner unavailable");
                        synced = false;
                        next_try = Instant::now() + self.retry;
                    }
                }
            }
            let (mac, ipv4) = if synced {
                match self.rx.recv_timeout(self.resync_every) {
                    Ok(d) => d,
                    Err(RecvTimeoutError::Timeout) => {
                        self.resync.store(true, Ordering::SeqCst);
                        continue;
                    }
                    Err(RecvTimeoutError::Disconnected) => return,
                }
            } else {
                // devices arriving now are in the next `Known`
                match self
                    .rx
                    .recv_timeout(next_try.saturating_duration_since(Instant::now()))
                {
                    Ok(_) | Err(RecvTimeoutError::Timeout) => continue,
                    Err(RecvTimeoutError::Disconnected) => return,
                }
            };
            match (self.transport)(&start_req(mac.clone(), ipv4)) {
                Ok(Reply::Started { job_id }) => {
                    tracing::info!(mac, %ipv4, job_id, "automatic port scan queued");
                }
                Ok(Reply::Refused { reason }) => {
                    tracing::debug!(mac, %ipv4, ?reason, "automatic port scan refused");
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(mac, error = %e, "port scanner unavailable");
                    synced = false;
                    next_try = Instant::now() + self.retry;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const MAC: &str = "aa:bb:cc:dd:ee:01";

    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A daemon that records requests and fails while `down`.
    #[derive(Default)]
    struct Fake {
        got: Mutex<Vec<Request>>,
        down: AtomicBool,
        /// Held by a test to keep a request from being answered.
        gate: Mutex<()>,
    }

    impl Fake {
        fn transport(self: &Arc<Self>) -> Transport {
            let f = Arc::clone(self);
            Arc::new(move |r| {
                lock(&f.got).push(r.clone());
                drop(lock(&f.gate));
                if f.down.load(Ordering::SeqCst) {
                    Err(io::ErrorKind::ConnectionRefused.into())
                } else {
                    Ok(Reply::Ok)
                }
            })
        }

        fn got(&self) -> Vec<Request> {
            lock(&self.got).clone()
        }

        /// Waits up to 2 s for `n` requests.
        fn wait_for(&self, n: usize) -> Vec<Request> {
            let end = Instant::now() + Duration::from_secs(2);
            while lock(&self.got).len() < n && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(5));
            }
            self.got()
        }
    }

    fn dev(mac: &str, ip: &str) -> KnownDevice {
        KnownDevice {
            mac: mac.into(),
            ipv4: ip.parse().unwrap(),
        }
    }

    fn known(list: &Arc<Mutex<Vec<KnownDevice>>>) -> KnownFn {
        let l = Arc::clone(list);
        Arc::new(move || lock(&l).clone())
    }

    fn known_req(macs: Vec<KnownDevice>) -> Request {
        Request::Known { macs }
    }

    #[test]
    fn sends_known_at_start_then_an_auto_device_scan_per_device() {
        let fake = Arc::new(Fake::default());
        let list = Arc::new(Mutex::new(vec![dev(MAC, "192.168.1.5")]));
        let n = SocketNotify::start(
            fake.transport(),
            known(&list),
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        assert_eq!(fake.wait_for(1), [known_req(vec![dev(MAC, "192.168.1.5")])]);
        n.new_device("aa:bb:cc:dd:ee:02", "192.168.1.6".parse().unwrap());
        let got = fake.wait_for(2);
        assert_eq!(
            got[1],
            Request::Start(StartReq {
                target: "192.168.1.6".into(),
                kind: JobKind::Device,
                auto: true,
                mac: Some("aa:bb:cc:dd:ee:02".into()),
                public_ok: false,
                confirm: false,
                include_excluded: false,
            })
        );
        // the wire form the daemon reads
        let line = serde_json::to_string(&got[1]).unwrap();
        assert!(line.contains(r#""op":"start""#) && line.contains(r#""auto":true"#));
    }

    #[test]
    fn retries_while_unavailable_and_resends_known_on_reconnect() {
        let fake = Arc::new(Fake::default());
        fake.down.store(true, Ordering::SeqCst);
        let list = Arc::new(Mutex::new(Vec::new()));
        let n = SocketNotify::start(
            fake.transport(),
            known(&list),
            Duration::from_millis(30),
            Duration::from_secs(60),
        );
        // a device while down is not sent on its own ...
        lock(&list).push(dev(MAC, "192.168.1.5"));
        n.new_device(MAC, "192.168.1.5".parse().unwrap());
        let got = fake.wait_for(3);
        assert!(got.len() >= 3, "retried: {got:?}");
        assert!(
            got.iter().all(|r| matches!(r, Request::Known { .. })),
            "{got:?}"
        );
        // ... it is in the Known sent once the daemon answers
        fake.down.store(false, Ordering::SeqCst);
        let end = Instant::now() + Duration::from_secs(2);
        while fake.got().last() != Some(&known_req(vec![dev(MAC, "192.168.1.5")]))
            && Instant::now() < end
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            fake.got().last(),
            Some(&known_req(vec![dev(MAC, "192.168.1.5")]))
        );
        // and no Start for it, nor more retries, while connected
        std::thread::sleep(Duration::from_millis(100));
        let settled = fake.got();
        assert_eq!(
            settled.last(),
            Some(&known_req(vec![dev(MAC, "192.168.1.5")]))
        );
        assert!(!settled.iter().any(|r| matches!(r, Request::Start(_))));
        drop(n);
    }

    #[test]
    fn a_failed_start_is_followed_by_known() {
        let fake = Arc::new(Fake::default());
        let list = Arc::new(Mutex::new(Vec::new()));
        let n = SocketNotify::start(
            fake.transport(),
            known(&list),
            Duration::from_millis(30),
            Duration::from_secs(60),
        );
        fake.wait_for(1);
        fake.down.store(true, Ordering::SeqCst);
        lock(&list).push(dev(MAC, "192.168.1.5"));
        n.new_device(MAC, "192.168.1.5".parse().unwrap());
        fake.wait_for(2);
        fake.down.store(false, Ordering::SeqCst);
        let got = fake.wait_for(3);
        assert!(matches!(got[1], Request::Start(_)), "{got:?}");
        assert_eq!(got[2], known_req(vec![dev(MAC, "192.168.1.5")]));
    }

    #[test]
    fn a_full_queue_drops_without_blocking_and_resends_known() {
        let fake = Arc::new(Fake::default());
        let list = Arc::new(Mutex::new(vec![dev(MAC, "192.168.1.5")]));
        let (n, w) = SocketNotify::channel(
            1,
            fake.transport(),
            known(&list),
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        let t = std::thread::spawn(move || w.run());
        fake.wait_for(1);
        // the thread is stuck answering the first device ...
        let held = lock(&fake.gate);
        n.new_device("aa:bb:cc:dd:ee:02", "192.168.1.6".parse().unwrap());
        fake.wait_for(2);
        // ... one more fits the queue, the next is dropped at once
        n.new_device("aa:bb:cc:dd:ee:03", "192.168.1.7".parse().unwrap());
        n.new_device("aa:bb:cc:dd:ee:04", "192.168.1.8".parse().unwrap());
        assert!(n.resync.load(Ordering::SeqCst));
        drop(held);
        let got = fake.wait_for(4);
        let start = |mac: &str, ip: &str| start_req(mac.into(), ip.parse().unwrap());
        assert_eq!(
            got,
            [
                known_req(vec![dev(MAC, "192.168.1.5")]),
                start("aa:bb:cc:dd:ee:02", "192.168.1.6"),
                // the dropped device is covered by the full list
                known_req(vec![dev(MAC, "192.168.1.5")]),
                start("aa:bb:cc:dd:ee:03", "192.168.1.7"),
            ]
        );
        assert!(!n.resync.load(Ordering::SeqCst));
        // dropping the notifier ends the thread
        drop(n);
        t.join().unwrap();
        assert_eq!(fake.got().len(), 4);
    }

    #[test]
    fn resends_known_periodically_while_connected() {
        let fake = Arc::new(Fake::default());
        let list = Arc::new(Mutex::new(vec![dev(MAC, "192.168.1.5")]));
        let _n = SocketNotify::start(
            fake.transport(),
            known(&list),
            Duration::from_secs(60),
            Duration::from_millis(20),
        );
        let got = fake.wait_for(3);
        assert!(got.len() >= 3, "{got:?}");
        assert!(
            got.iter()
                .all(|r| *r == known_req(vec![dev(MAC, "192.168.1.5")])),
            "{got:?}"
        );
    }

    #[test]
    fn the_thread_ends_while_unavailable_too() {
        let fake = Arc::new(Fake::default());
        fake.down.store(true, Ordering::SeqCst);
        let (n, w) = SocketNotify::channel(
            4,
            fake.transport(),
            Arc::new(Vec::new),
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        let t = std::thread::spawn(move || w.run());
        fake.wait_for(1);
        drop(n);
        t.join().unwrap();
    }

    #[test]
    fn the_system_notifier_talks_to_a_real_socket() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.sock");
        let l = UnixListener::bind(&path).unwrap();
        let p = path.clone();
        let _n = SocketNotify::start(
            Arc::new(move |r| sensr_scan::client::send(&p, r)),
            Arc::new(|| vec![dev(MAC, "192.168.1.5")]),
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        let (s, _) = l.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&s).read_line(&mut line).unwrap();
        (&s).write_all(b"{\"op\":\"ok\"}\n").unwrap();
        assert_eq!(
            serde_json::from_str::<Request>(&line).unwrap(),
            known_req(vec![dev(MAC, "192.168.1.5")])
        );
    }
}
