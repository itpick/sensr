#![cfg(feature = "daemon")]
//! The daemon end to end: a [`Daemon`] serving a tempdir socket, scanning
//! listeners on 127.0.0.1.
//!
//! Test hooks: [`Daemon::with_ports`] replaces the full 65,535-port TCP order
//! and the UDP list with a few ports, and [`Daemon::with_neighbours`] /
//! `run_job`'s `neighbours` argument replace `/proc/net/arp`. Loopback is not
//! local (R4), so every config here lists `127.0.0.0/8` in `local`.

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sensr_scan::client::send;
use sensr_scan::config::{Config, Exclude, Pace};
use sensr_scan::ports::Services;
use sensr_scan::proto::{JobKind, KnownDevice, Refusal, Reply, Request, StartReq, StatusView};
use sensr_scan::queue::Job;
use sensr_scan::runner::{Ports, Progress, run_job};
use sensr_scan::server::{Daemon, serve};
use sensr_scan::store::Store;
use sensr_scan::types::{PortState, Proto, ScanStatus};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

const MAC: &str = "aa:bb:cc:00:00:01";

fn cfg() -> Config {
    Config {
        enabled: true,
        auto_scan_new: true,
        pace: Pace::Gentle,
        history: 10,
        max_range: 4096,
        exclude: vec![],
        local: vec![
            "127.0.0.0/8".parse().unwrap(),
            "192.0.2.0/24".parse().unwrap(),
        ],
        router: vec![],
    }
}

/// A TCP listener on 127.0.0.1 that greets every connection like sshd.
fn ssh_listener() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            let _ = s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n");
        }
    });
    port
}

fn ports(tcp: Vec<u16>) -> Ports {
    Ports {
        tcp: Arc::new(tcp),
        udp: Vec::new(),
    }
}

struct Harness {
    _dir: TempDir,
    sock: PathBuf,
    db: PathBuf,
    daemon: Arc<Daemon>,
}

/// A daemon on a fresh tempdir. `worker: false` leaves jobs queued.
async fn start_daemon(cfg: Config, ports: Ports, worker: bool) -> Harness {
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("scan.sock");
    let db = dir.path().join("scans.db");
    let daemon = Arc::new(
        Daemon::new(cfg, &db, Services::default())
            .unwrap()
            .with_ports(ports)
            .with_neighbours(HashMap::new),
    );
    if worker {
        daemon.spawn_worker();
    }
    let (s, d) = (sock.clone(), Arc::clone(&daemon));
    tokio::spawn(async move { serve(&s, d).await.unwrap() });
    let t = Instant::now();
    while UnixStream::connect(&sock).is_err() {
        assert!(t.elapsed() < Duration::from_secs(5), "socket never came up");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Harness {
        _dir: dir,
        sock,
        db,
        daemon,
    }
}

async fn ask(sock: &Path, req: Request) -> Reply {
    let sock = sock.to_path_buf();
    tokio::task::spawn_blocking(move || send(&sock, &req))
        .await
        .unwrap()
        .unwrap()
}

fn start(target: &str, mac: Option<&str>, auto: bool) -> Request {
    Request::Start(StartReq {
        target: target.into(),
        kind: JobKind::Device,
        auto,
        mac: mac.map(Into::into),
        public_ok: false,
        confirm: false,
        include_excluded: false,
    })
}

async fn status(sock: &Path) -> StatusView {
    match ask(sock, Request::Status).await {
        Reply::Status(s) => s,
        other => panic!("status: {other:?}"),
    }
}

async fn wait_idle(sock: &Path, limit: Duration) {
    let t = Instant::now();
    loop {
        let s = status(sock).await;
        if s.running.is_none() && s.queue.is_empty() {
            return;
        }
        assert!(t.elapsed() < limit, "still busy: {s:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn started(r: Reply) -> u64 {
    match r {
        Reply::Started { job_id } => job_id,
        other => panic!("expected Started, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn start_device_scan_completes() {
    let port = ssh_listener();
    let h = start_daemon(cfg(), ports(vec![port, 1]), true).await;
    started(ask(&h.sock, start("127.0.0.1", Some(MAC), false)).await);
    wait_idle(&h.sock, Duration::from_secs(20)).await;

    let store = Store::open_ro(&h.db).unwrap();
    let scan = store.latest_for_mac(MAC).unwrap().expect("a scan");
    assert_eq!(scan.status, ScanStatus::Complete);
    assert_eq!(scan.address, "127.0.0.1".parse::<IpAddr>().unwrap());
    let open: Vec<_> = scan
        .ports
        .iter()
        .filter(|p| p.state == PortState::Open)
        .collect();
    assert_eq!(open.len(), 1, "{:?}", scan.ports);
    assert_eq!((open[0].proto, open[0].port), (Proto::Tcp, port));
    assert_eq!(open[0].ident.product.as_deref(), Some("OpenSSH"));
    let (job, _) = store.job(scan.job_id).unwrap().unwrap();
    assert_eq!(job.status, "complete");
    assert_eq!(job.requested_by, "owner");
    assert_eq!(job.mac.as_deref(), Some(MAC));
}

#[tokio::test(flavor = "multi_thread")]
async fn unreachable_device_fails() {
    let mac = "aa:bb:cc:00:00:02";
    let h = start_daemon(cfg(), ports(vec![22]), true).await;
    started(ask(&h.sock, start("192.0.2.1", Some(mac), false)).await);
    wait_idle(&h.sock, Duration::from_secs(20)).await;

    let store = Store::open_ro(&h.db).unwrap();
    let scan = store.latest_for_mac(mac).unwrap().expect("a scan");
    assert_eq!(scan.status, ScanStatus::Failed);
    assert!(scan.ports.is_empty());
    assert!(!store.has_complete(mac).unwrap());
    assert_eq!(store.job(scan.job_id).unwrap().unwrap().0.status, "failed");
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_dedupes() {
    let port = ssh_listener();
    // No worker yet, so both starts find the first one still queued.
    let h = start_daemon(cfg(), ports(vec![port]), false).await;
    let a = started(ask(&h.sock, start("127.0.0.1", Some(MAC), true)).await);
    let b = started(ask(&h.sock, start("127.0.0.1", Some(MAC), true)).await);
    assert_eq!(a, b);
    assert_eq!(status(&h.sock).await.queue.len(), 1);

    h.daemon.spawn_worker();
    wait_idle(&h.sock, Duration::from_secs(20)).await;
    assert!(Store::open_ro(&h.db).unwrap().has_complete(MAC).unwrap());
    assert_eq!(
        ask(&h.sock, start("127.0.0.1", Some(MAC), true)).await,
        Reply::Ok
    );
    assert!(status(&h.sock).await.queue.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn manual_before_auto() {
    let h = start_daemon(cfg(), ports(vec![1]), false).await;
    let a1 = started(
        ask(
            &h.sock,
            start("127.0.0.11", Some("aa:bb:cc:00:00:11"), true),
        )
        .await,
    );
    let a2 = started(
        ask(
            &h.sock,
            start("127.0.0.12", Some("aa:bb:cc:00:00:12"), true),
        )
        .await,
    );
    let m = started(ask(&h.sock, start("127.0.0.13", None, false)).await);
    let order: Vec<u64> = status(&h.sock)
        .await
        .queue
        .iter()
        .map(|q| q.job_id)
        .collect();
    assert_eq!(order, vec![m, a1, a2]);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_keeps_partial() {
    let port = ssh_listener();
    // The listener first, then 2,000 closed ports: ~10 s at the gentle pace.
    let mut tcp = vec![port];
    tcp.extend((40_000..42_000).filter(|p| *p != port));
    let h = start_daemon(cfg(), ports(tcp), true).await;
    let id = started(ask(&h.sock, start("127.0.0.1", Some(MAC), true)).await);

    let t = Instant::now();
    loop {
        let s = status(&h.sock).await;
        if s.running
            .as_ref()
            .is_some_and(|r| r.job_id == id && r.tcp_done >= 20)
        {
            break;
        }
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "scan never got going: {s:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        ask(&h.sock, Request::Cancel { job_id: id }).await,
        Reply::Ok
    );
    wait_idle(&h.sock, Duration::from_secs(5)).await;

    let store = Store::open_ro(&h.db).unwrap();
    let scan = store.latest_for_mac(MAC).unwrap().expect("a scan");
    assert_eq!(scan.status, ScanStatus::Partial);
    assert!(
        scan.ports
            .iter()
            .any(|p| p.port == port && p.state == PortState::Open),
        "{:?}",
        scan.ports
    );
    assert_eq!(
        store.job(scan.job_id).unwrap().unwrap().0.status,
        "cancelled"
    );
    assert!(store.auto_cancelled(MAC).unwrap());

    let known = Request::Known {
        macs: vec![KnownDevice {
            mac: MAC.into(),
            ipv4: "127.0.0.1".parse().unwrap(),
        }],
    };
    assert_eq!(ask(&h.sock, known).await, Reply::Ok);
    let s = status(&h.sock).await;
    assert!(s.running.is_none() && s.queue.is_empty(), "{s:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn public_refused() {
    let h = start_daemon(cfg(), ports(vec![1]), false).await;
    assert_eq!(
        ask(&h.sock, start("8.8.8.8", None, false)).await,
        Reply::Refused {
            reason: Refusal::Public
        }
    );
    assert!(status(&h.sock).await.queue.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn excluded_needs_confirm() {
    let mut c = cfg();
    c.exclude = vec![Exclude::Addr("127.0.0.1".parse().unwrap())];
    let h = start_daemon(c, ports(vec![1]), false).await;
    assert_eq!(
        ask(&h.sock, start("127.0.0.1", None, false)).await,
        Reply::Refused {
            reason: Refusal::Excluded
        }
    );
    let mut req = StartReq {
        target: "127.0.0.1".into(),
        kind: JobKind::Device,
        auto: false,
        mac: None,
        public_ok: false,
        confirm: true,
        include_excluded: false,
    };
    started(ask(&h.sock, Request::Start(req.clone())).await);

    // Excluded by MAC too, and an auto start of it is quietly ignored.
    let mut c = cfg();
    c.exclude = vec![Exclude::Mac("AA:BB:CC:00:00:01".into())];
    let h = start_daemon(c, ports(vec![1]), false).await;
    req.confirm = false;
    req.mac = Some(MAC.into());
    assert_eq!(
        ask(&h.sock, Request::Start(req.clone())).await,
        Reply::Refused {
            reason: Refusal::Excluded
        }
    );
    req.auto = true;
    assert_eq!(ask(&h.sock, Request::Start(req)).await, Reply::Ok);
    assert!(status(&h.sock).await.queue.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn device_follows_mac() {
    let port = ssh_listener();
    let dir = TempDir::new().unwrap();
    let store = Store::open(&dir.path().join("scans.db")).unwrap();
    let req = StartReq {
        target: "127.0.0.2".into(),
        kind: JobKind::Device,
        auto: false,
        mac: Some(MAC.into()),
        public_ok: false,
        confirm: false,
        include_excluded: false,
    };
    let mut job = Job::new(&req).unwrap();
    // run_job runs a job already queued in the store (R5).
    let id = store
        .queue_job(JobKind::Device, &req.target, Some(MAC), false, false)
        .unwrap();
    job.id = u64::try_from(id).unwrap();
    let neighbours = || HashMap::from([("127.0.0.1".parse::<IpAddr>().unwrap(), MAC.to_string())]);
    let ran = run_job(
        job,
        &cfg(),
        &store,
        &Services::default(),
        &ports(vec![port]),
        &Progress::default(),
        CancellationToken::new(),
        &neighbours,
    )
    .await
    .unwrap();
    assert_eq!(ran, id);
    assert_eq!(store.job(id).unwrap().unwrap().0.status, "complete");
    let scan = store.latest_for_mac(MAC).unwrap().expect("a scan");
    assert_eq!(scan.job_id, id);
    assert_eq!(scan.address, "127.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(scan.status, ScanStatus::Complete);
    assert!(scan.ports.iter().any(|p| p.port == port));
}

// ---- beyond the brief's list ----

#[tokio::test(flavor = "multi_thread")]
async fn disabled_refuses_owner_and_ignores_auto() {
    let mut c = cfg();
    c.enabled = false;
    let h = start_daemon(c, ports(vec![1]), false).await;
    assert_eq!(
        ask(&h.sock, start("127.0.0.1", None, false)).await,
        Reply::Refused {
            reason: Refusal::Disabled
        }
    );
    assert_eq!(
        ask(&h.sock, start("127.0.0.1", Some(MAC), true)).await,
        Reply::Ok
    );
    assert!(status(&h.sock).await.queue.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_off_ignores_auto_and_known() {
    let mut c = cfg();
    c.auto_scan_new = false;
    let h = start_daemon(c, ports(vec![1]), false).await;
    assert_eq!(
        ask(&h.sock, start("127.0.0.1", Some(MAC), true)).await,
        Reply::Ok
    );
    let known = Request::Known {
        macs: vec![KnownDevice {
            mac: MAC.into(),
            ipv4: "127.0.0.1".parse().unwrap(),
        }],
    };
    assert_eq!(ask(&h.sock, known).await, Reply::Ok);
    assert!(status(&h.sock).await.queue.is_empty());
    // A person can still scan.
    started(ask(&h.sock, start("127.0.0.1", Some(MAC), false)).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn known_queues_each_new_device() {
    let h = start_daemon(cfg(), ports(vec![1]), false).await;
    let dev = |n: u8| KnownDevice {
        mac: format!("aa:bb:cc:00:01:{n:02x}"),
        ipv4: format!("127.0.1.{n}").parse().unwrap(),
    };
    let req = Request::Known {
        macs: vec![dev(1), dev(2), dev(1)],
    };
    assert_eq!(ask(&h.sock, req).await, Reply::Ok);
    let q = status(&h.sock).await.queue;
    let targets: Vec<&str> = q.iter().map(|j| j.target.as_str()).collect();
    assert_eq!(targets, ["127.0.1.1", "127.0.1.2"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_queued_auto_is_recorded() {
    let h = start_daemon(cfg(), ports(vec![1]), false).await;
    let auto = started(ask(&h.sock, start("127.0.0.1", Some(MAC), true)).await);
    let mac2 = "aa:bb:cc:00:00:22";
    let owner = started(ask(&h.sock, start("127.0.0.2", Some(mac2), false)).await);
    assert_eq!(
        ask(&h.sock, Request::Cancel { job_id: auto }).await,
        Reply::Ok
    );
    assert_eq!(
        ask(&h.sock, Request::Cancel { job_id: owner }).await,
        Reply::Ok
    );
    assert!(status(&h.sock).await.queue.is_empty());
    assert!(matches!(
        ask(&h.sock, Request::Cancel { job_id: 999 }).await,
        Reply::Refused {
            reason: Refusal::Invalid(_)
        }
    ));

    let store = Store::open_ro(&h.db).unwrap();
    assert!(store.auto_cancelled(MAC).unwrap());
    // Both rows (created at enqueue, R5) end cancelled, with no scans.
    let jobs = store.jobs(JobKind::Device, 10).unwrap();
    assert_eq!(jobs.len(), 2, "{jobs:?}");
    for j in &jobs {
        assert_eq!(j.status, "cancelled");
        assert_eq!(j.hosts_alive, 0);
    }
    assert!(
        !store.auto_cancelled(mac2).unwrap(),
        "an owner cancel does not count"
    );
    // Not re-queued automatically; Scan now still works.
    assert_eq!(
        ask(&h.sock, start("127.0.0.1", Some(MAC), true)).await,
        Reply::Ok
    );
    started(ask(&h.sock, start("127.0.0.1", Some(MAC), false)).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn range_skips_excluded() {
    let port = ssh_listener();
    let mut c = cfg();
    c.exclude = vec![Exclude::Addr("127.0.0.3".parse().unwrap())];
    let h = start_daemon(c, ports(vec![port]), true).await;
    let req = Request::Start(StartReq {
        target: "127.0.0.1-3".into(),
        kind: JobKind::Range,
        auto: false,
        mac: None,
        public_ok: false,
        confirm: false,
        include_excluded: false,
    });
    started(ask(&h.sock, req).await);
    wait_idle(&h.sock, Duration::from_secs(30)).await;

    let store = Store::open_ro(&h.db).unwrap();
    let jobs = store.jobs(JobKind::Range, 10).unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].status, "complete");
    assert_eq!(
        jobs[0].skipped,
        vec!["127.0.0.3".parse::<IpAddr>().unwrap()]
    );
    let (_, scans) = store.job(jobs[0].id).unwrap().unwrap();
    let lo = scans
        .iter()
        .find(|s| s.address == "127.0.0.1".parse::<IpAddr>().unwrap())
        .expect("127.0.0.1 scanned");
    assert_eq!(lo.status, ScanStatus::Complete);
    assert!(lo.ports.iter().any(|p| p.port == port));
    assert!(
        scans
            .iter()
            .all(|s| s.address != "127.0.0.3".parse::<IpAddr>().unwrap())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_targets_refused() {
    let h = start_daemon(cfg(), ports(vec![1]), false).await;
    for t in ["not-an-ip", "127.0.0.0/30"] {
        assert!(
            matches!(
                ask(&h.sock, start(t, None, false)).await,
                Reply::Refused {
                    reason: Refusal::Invalid(_)
                }
            ),
            "{t}"
        );
    }
    let mut c = cfg();
    c.max_range = 4;
    let h = start_daemon(c, ports(vec![1]), false).await;
    let req = Request::Start(StartReq {
        target: "127.0.0.0/24".into(),
        kind: JobKind::Range,
        auto: false,
        mac: None,
        public_ok: false,
        confirm: false,
        include_excluded: false,
    });
    assert_eq!(
        ask(&h.sock, req).await,
        Reply::Refused {
            reason: Refusal::TooLarge {
                addresses: 256,
                max: 4
            }
        }
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn socket_is_0660_and_survives_bad_json() {
    use std::io::{BufRead, BufReader};
    let h = start_daemon(cfg(), ports(vec![1]), false).await;
    let mode = std::fs::metadata(&h.sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o660);

    let sock = h.sock.clone();
    let lines = tokio::task::spawn_blocking(move || {
        let s = UnixStream::connect(&sock).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let mut w = s.try_clone().unwrap();
        w.write_all(b"{nope\n{\"op\":\"status\"}\n").unwrap();
        let mut r = BufReader::new(s);
        let mut out = Vec::new();
        for _ in 0..2 {
            let mut l = String::new();
            r.read_line(&mut l).unwrap();
            out.push(serde_json::from_str::<Reply>(&l).unwrap());
        }
        out
    })
    .await
    .unwrap();
    assert!(matches!(
        lines[0],
        Reply::Refused {
            reason: Refusal::Invalid(_)
        }
    ));
    assert!(matches!(lines[1], Reply::Status(_)));
    // The server still takes new connections.
    status(&h.sock).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_socket_file_is_replaced() {
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("scan.sock");
    std::fs::write(&sock, b"stale").unwrap();
    let daemon =
        Arc::new(Daemon::new(cfg(), &dir.path().join("scans.db"), Services::default()).unwrap());
    let s = sock.clone();
    tokio::spawn(async move { serve(&s, daemon).await.unwrap() });
    let t = Instant::now();
    while UnixStream::connect(&sock).is_err() {
        assert!(t.elapsed() < Duration::from_secs(5), "socket never came up");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    status(&sock).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn job_id_is_the_store_row() {
    let port = ssh_listener();
    let h = start_daemon(cfg(), ports(vec![port]), false).await;
    let id = started(ask(&h.sock, start("127.0.0.1", Some(MAC), true)).await);
    let sid = i64::try_from(id).unwrap();
    {
        let store = Store::open_ro(&h.db).unwrap();
        let (j, scans) = store.job(sid).unwrap().expect("row created at enqueue");
        assert_eq!(
            (j.status.as_str(), j.requested_by.as_str()),
            ("queued", "auto")
        );
        assert_eq!(j.mac.as_deref(), Some(MAC));
        assert!(scans.is_empty());
    }
    assert_eq!(status(&h.sock).await.queue[0].job_id, id);
    // A person asking for the same device takes the auto job over.
    assert_eq!(
        started(ask(&h.sock, start("127.0.0.1", Some(MAC), false)).await),
        id
    );
    h.daemon.spawn_worker();
    wait_idle(&h.sock, Duration::from_secs(20)).await;
    let store = Store::open_ro(&h.db).unwrap();
    let (j, scans) = store.job(sid).unwrap().unwrap();
    assert_eq!(
        (j.status.as_str(), j.requested_by.as_str()),
        ("complete", "owner")
    );
    assert_eq!(scans.len(), 1);
    assert_eq!(store.jobs(JobKind::Device, 10).unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn panicking_job_fails_and_worker_goes_on() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let port = ssh_listener();
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("scan.sock");
    let db = dir.path().join("scans.db");
    let first = AtomicBool::new(true);
    let daemon = Arc::new(
        Daemon::new(cfg(), &db, Services::default())
            .unwrap()
            .with_ports(ports(vec![port]))
            .with_neighbours(move || {
                assert!(
                    !first.swap(false, Ordering::SeqCst),
                    "neighbour source broke"
                );
                HashMap::new()
            }),
    );
    daemon.spawn_worker();
    let (s, d) = (sock.clone(), Arc::clone(&daemon));
    tokio::spawn(async move { serve(&s, d).await.unwrap() });
    let t = Instant::now();
    while UnixStream::connect(&sock).is_err() {
        assert!(t.elapsed() < Duration::from_secs(5));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let crashed = started(ask(&sock, start("127.0.0.1", Some(MAC), false)).await);
    wait_idle(&sock, Duration::from_secs(10)).await;
    let store = Store::open_ro(&db).unwrap();
    let crashed = i64::try_from(crashed).unwrap();
    assert_eq!(store.job(crashed).unwrap().unwrap().0.status, "failed");

    let mac = "aa:bb:cc:00:00:09";
    let next = started(ask(&sock, start("127.0.0.1", Some(mac), false)).await);
    wait_idle(&sock, Duration::from_secs(20)).await;
    let next = i64::try_from(next).unwrap();
    assert_eq!(store.job(next).unwrap().unwrap().0.status, "complete");
    assert_eq!(
        store.latest_for_mac(mac).unwrap().unwrap().status,
        ScanStatus::Complete
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_ends_when_the_database_is_gone() {
    let dir = TempDir::new().unwrap();
    let sub = dir.path().join("db");
    std::fs::create_dir(&sub).unwrap();
    let daemon = Arc::new(Daemon::new(cfg(), &sub.join("scans.db"), Services::default()).unwrap());
    std::fs::remove_dir_all(&sub).unwrap();
    let worker = daemon.spawn_worker();
    let t = Instant::now();
    while !worker.is_finished() {
        assert!(t.elapsed() < Duration::from_secs(5), "worker kept running");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    worker.join().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_start_of_the_router_is_ignored() {
    let mut c = cfg();
    c.router = vec!["127.0.0.1".parse().unwrap()];
    let h = start_daemon(c, ports(vec![1]), false).await;
    assert_eq!(
        ask(&h.sock, start("127.0.0.1", Some(MAC), true)).await,
        Reply::Ok
    );
    assert_eq!(
        ask(&h.sock, start("127.0.0.1", Some(MAC), false)).await,
        Reply::Refused {
            reason: Refusal::Excluded
        }
    );
    assert!(status(&h.sock).await.queue.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_connections_are_closed() {
    use std::io::Read;
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("scan.sock");
    let daemon = Arc::new(
        Daemon::new(cfg(), &dir.path().join("scans.db"), Services::default())
            .unwrap()
            .with_idle_timeout(Duration::from_millis(200)),
    );
    let s = sock.clone();
    tokio::spawn(async move { serve(&s, daemon).await.unwrap() });
    let t = Instant::now();
    while UnixStream::connect(&sock).is_err() {
        assert!(t.elapsed() < Duration::from_secs(5));
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let closed = tokio::task::spawn_blocking(move || {
        let mut c = UnixStream::connect(&sock).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let t = Instant::now();
        let mut b = [0u8; 1];
        let n = c.read(&mut b).unwrap();
        (n, t.elapsed())
    })
    .await
    .unwrap();
    assert_eq!(closed.0, 0, "EOF from the server");
    assert!(closed.1 < Duration::from_secs(2), "{:?}", closed.1);
}
