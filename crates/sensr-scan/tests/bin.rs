#![cfg(feature = "daemon")]
//! The `sensr-scan` binary: SIGTERM (every settings change restarts the
//! unit) keeps the running scan's results.

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sensr_scan::client::send;
use sensr_scan::config::{Config, Pace};
use sensr_scan::proto::{JobKind, Reply, Request, StartReq};
use sensr_scan::store::Store;
use sensr_scan::types::ScanStatus;
use tempfile::TempDir;

const MAC: &str = "aa:bb:cc:00:00:51";

#[test]
fn sigterm_keeps_the_running_scan_partial() {
    let dir = TempDir::new().unwrap();
    let (conf, db, sock) = (
        dir.path().join("portscan.json"),
        dir.path().join("scans.db"),
        dir.path().join("scan.sock"),
    );
    let cfg = Config {
        enabled: true,
        auto_scan_new: true,
        pace: Pace::Gentle,
        history: 10,
        max_range: 4096,
        exclude: vec![],
        local: vec!["127.0.0.0/8".parse().unwrap()],
        router: vec![],
    };
    std::fs::write(&conf, serde_json::to_vec(&cfg).unwrap()).unwrap();
    // Something open, so the scan is seen to get going.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_sensr-scan"))
        .arg("--config")
        .arg(&conf)
        .arg("--db")
        .arg(&db)
        .arg("--socket")
        .arg(&sock)
        .arg("--services")
        .arg(dir.path().join("services"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let t = Instant::now();
    let ask = |r: &Request| loop {
        if let Ok(reply) = send(&sock, r) {
            return reply;
        }
        assert!(
            t.elapsed() < Duration::from_secs(10),
            "socket never came up"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let reply = ask(&Request::Start(StartReq {
        target: "127.0.0.1".into(),
        kind: JobKind::Device,
        auto: true,
        mac: Some(MAC.into()),
        public_ok: false,
        confirm: false,
        include_excluded: false,
    }));
    let Reply::Started { job_id } = reply else {
        panic!("{reply:?}")
    };
    loop {
        let Reply::Status(s) = ask(&Request::Status) else {
            panic!("status")
        };
        if s.running.is_some_and(|r| r.tcp_done >= 50) {
            break;
        }
        assert!(
            t.elapsed() < Duration::from_secs(20),
            "scan never got going"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let term = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(term.success());
    let t = Instant::now();
    let exit = loop {
        if let Some(st) = child.try_wait().unwrap() {
            break st;
        }
        assert!(t.elapsed() < Duration::from_secs(8), "did not exit");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(exit.success(), "{exit:?}");
    drop(l);
    let store = Store::open_ro(&db).unwrap();
    let scan = store.latest_for_mac(MAC).unwrap().expect("a scan");
    assert_eq!(scan.status, ScanStatus::Partial);
    let id = i64::try_from(job_id).unwrap();
    assert_eq!(store.job(id).unwrap().unwrap().0.status, "failed");
    assert!(!store.auto_cancelled(MAC).unwrap());
}
