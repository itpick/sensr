use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::thread::ThreadId;

use super::*;
use crate::hosts::{HostEvidence, Source};

const MAC1: &str = "aa:bb:cc:dd:ee:01";
const MAC2: &str = "aa:bb:cc:dd:ee:02";
const MAC3: &str = "aa:bb:cc:dd:ee:03";
const NOW: u64 = 1_800_000_000;

fn home_router() -> Document {
    let path = format!(
        "{}/../sensr-import-opnsense/tests/golden/home-router.sensr.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect("importer golden"))
        .expect("document")
}

fn host(mac: &str, ip: &str, iface: &str, last_seen: Option<u64>) -> Host {
    Host {
        key: mac.into(),
        mac: Some(mac.into()),
        client_id: None,
        name: None,
        reserved_name: None,
        lease_hostname: None,
        interface: Some(iface.into()),
        ipv4: Some(ip.parse().unwrap()),
        ipv6: Vec::new(),
        sources: BTreeSet::from([Source::Neighbour]),
        lease: None,
        first_seen: 0,
        last_seen,
        evidence: HostEvidence::default(),
    }
}

/// The rig's mutable inventory.
type Inventory = Arc<Mutex<Vec<Host>>>;

/// A connector answering from a function.
struct FnConnector<F>(F);

impl<F: Fn(SocketAddr, Duration) -> Probe + Send + Sync> Connector for FnConnector<F> {
    fn probe(&self, addr: SocketAddr, timeout: Duration) -> Probe {
        (self.0)(addr, timeout)
    }
}

/// `open` ports accept, every other port refuses.
fn answers(open: &'static [u16]) -> Arc<dyn Connector> {
    Arc::new(FnConnector(move |a: SocketAddr, _| {
        if open.contains(&a.port()) {
            Probe::Open
        } else {
            Probe::Closed
        }
    }))
}

/// A virtual clock per thread: each thread's time starts at zero and
/// advances only by its own sleeps, so concurrent lanes add up the way
/// real ones would without anyone waiting.
#[derive(Default)]
struct LaneClock(Mutex<HashMap<ThreadId, Duration>>);

impl LaneClock {
    fn latest(&self) -> Duration {
        lock(&self.0).values().copied().max().unwrap_or_default()
    }
}

impl Clock for LaneClock {
    fn now(&self) -> Duration {
        let id = std::thread::current().id();
        lock(&self.0).get(&id).copied().unwrap_or_default()
    }
    fn sleep(&self, d: Duration) {
        let id = std::thread::current().id();
        *lock(&self.0).entry(id).or_default() += d;
    }
}

fn scanner(c: Arc<dyn Connector>) -> Scanner {
    Scanner::new(
        c,
        Arc::new(SystemClock::default()),
        None,
        CONNECT_TIMEOUT,
        PER_HOST,
    )
}

/// A service over a mutable inventory and clock.
struct Rig {
    svc: Arc<PortScan>,
    hosts: Inventory,
    now: Arc<AtomicU64>,
    dir: tempfile::TempDir,
}

impl Rig {
    fn new(scanner: Scanner, hosts: Vec<Host>) -> Self {
        Self::in_dir(scanner, hosts, tempfile::tempdir().unwrap())
    }

    fn in_dir(scanner: Scanner, hosts: Vec<Host>, dir: tempfile::TempDir) -> Self {
        let hosts = Arc::new(Mutex::new(hosts));
        let now = Arc::new(AtomicU64::new(NOW));
        let n = Arc::clone(&now);
        let svc = PortScan::new(
            scanner,
            dir.path().join("ports.json"),
            Arc::clone(&hosts) as Arc<dyn HostSource>,
            Arc::new(move || n.load(Ordering::SeqCst)),
            // a fixed UTC+1 zone
            Arc::new(|_: &str| 3600),
        );
        Self {
            svc,
            hosts,
            now,
            dir,
        }
    }

    fn apply(&self, doc: &Document) {
        self.svc
            .set_document(doc, &["192.168.1.1".parse().unwrap()]);
    }

    fn file(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("ports.json")).unwrap_or_default()
    }

    /// Scan now and wait for it.
    fn scan(&self, mac: &str) {
        self.svc.scan_now(mac).unwrap();
        let t = Instant::now();
        while self.svc.scanning(mac) {
            assert!(t.elapsed() < Duration::from_secs(20), "scan did not end");
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

/// A scan that found `open` and every other port refused.
fn complete(open: &[u16]) -> ScanOutcome {
    ScanOutcome {
        open: open.to_vec(),
        closed: (1..=u16::MAX).filter(|p| !open.contains(p)).collect(),
        filtered: BTreeSet::new(),
        answered: true,
    }
}

fn open_ports(h: &HostPorts) -> Vec<u16> {
    h.open().map(|e| e.port).collect()
}

#[test]
fn port_list_is_1_to_1024_plus_the_extras() {
    let l = port_list(&[]);
    // 554 is in both: 1045 ports
    assert_eq!(l.len(), 1024 + EXTRA_PORTS.len() - 1);
    assert_eq!(l.len(), 1045);
    assert_eq!(l.first(), Some(&1));
    assert!(l.contains(&32400) && l.contains(&554) && l.contains(&8080));
    assert!(l.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn extra_ports_capped_and_deduplicated() {
    // what the owner adds: duplicates, the built-in list, 0 and a flood
    let mut extra: Vec<u16> = vec![8081, 8081, 22, 554, 0];
    extra.extend(20_000..30_000);
    let mut doc = home_router();
    doc.hosts.portscan.extra_ports = extra;
    let v = doc.validate().to_string();
    assert!(v.contains("At most 64"), "{v}");
    assert!(v.contains("1 to 65535"), "{v}");
    // even unvalidated, the scan widens by at most 64 ports, once each
    let cleaned = doc.hosts.portscan.extra();
    assert_eq!(cleaned.len(), sensr_schema::models::hosts::MAX_EXTRA_PORTS);
    let l = port_list(&cleaned);
    assert!(l.len() <= 1024 + EXTRA_PORTS.len() + 64);
    assert!(!l.contains(&0));
    assert_eq!(l.iter().filter(|p| **p == 22).count(), 1);
    assert!(l.contains(&8081));
    // the service takes the cleaned list
    let plan = Plan::from_doc(&doc, &[]);
    assert_eq!(plan.ports, l);
}

#[test]
fn services_are_named() {
    assert_eq!(service(22), "ssh");
    assert_eq!(service(23), "telnet");
    assert_eq!(service(53), "dns");
    assert_eq!(service(80), "http");
    assert_eq!(service(443), "https");
    assert_eq!(service(554), "rtsp");
    assert_eq!(service(8080), "http-alt");
    assert_eq!(service(12345), "");
}

#[test]
fn scan_host_reports_open_ports_sorted() {
    let s = scanner(answers(&[8080, 22, 80]));
    let open = s
        .scan_host(
            "192.168.1.50".parse().unwrap(),
            &port_list(&[]),
            &BTreeSet::new(),
            &AtomicBool::new(false),
        )
        .unwrap();
    assert_eq!(open.open, [22, 80, 8080]);
    assert!(open.answered && open.filtered.is_empty());
    assert_eq!(open.closed.len(), port_list(&[]).len() - 3);
}

#[test]
fn tcp_connector_finds_open_and_closed() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let open = listener.local_addr().unwrap();
    // a port nothing listens on
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap()
    };
    let c = TcpConnector;
    assert_eq!(c.probe(open, CONNECT_TIMEOUT), Probe::Open);
    assert_eq!(c.probe(closed, CONNECT_TIMEOUT), Probe::Closed);
    // the connection was closed by the prober: the accepted end reads EOF
    use std::io::Read;
    let (mut conn, _) = listener.accept().unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut b = [0u8; 1];
    assert_eq!(conn.read(&mut b).unwrap(), 0);
}

#[test]
fn rate_limiter_spaces_attempts() {
    let clock = LaneClock::default();
    let l = RateLimiter::new(RATE_PER_SEC);
    for _ in 0..400 {
        l.acquire(&clock);
    }
    // 400 attempts at 200/s: the last starts 1.995 s after the first
    assert_eq!(clock.latest(), Duration::from_millis(1995));
}

#[test]
fn rate_limiter_holds_across_threads() {
    let l = Arc::new(RateLimiter::new(1000));
    let clock = Arc::new(SystemClock::default());
    let t = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..4 {
            let (l, clock) = (Arc::clone(&l), Arc::clone(&clock));
            s.spawn(move || {
                for _ in 0..50 {
                    l.acquire(&*clock);
                }
            });
        }
    });
    // 200 attempts at 1000/s overall: at least 199 ms
    assert!(
        t.elapsed() >= Duration::from_millis(199),
        "{:?}",
        t.elapsed()
    );
}

/// Review focus 1: a host that drops every SYN.
#[test]
fn slow_host_bounded_time() {
    let clock = Arc::new(LaneClock::default());
    let inflight = Arc::new(AtomicUsize::new(0));
    let most = Arc::new(AtomicUsize::new(0));
    let attempts = Arc::new(AtomicUsize::new(0));
    let c = {
        let (clock, inflight, most, attempts) = (
            Arc::clone(&clock),
            Arc::clone(&inflight),
            Arc::clone(&most),
            Arc::clone(&attempts),
        );
        FnConnector(move |_: SocketAddr, timeout: Duration| {
            let n = inflight.fetch_add(1, Ordering::SeqCst) + 1;
            most.fetch_max(n, Ordering::SeqCst);
            attempts.fetch_add(1, Ordering::SeqCst);
            // give other lanes a chance to overlap
            std::thread::yield_now();
            clock.sleep(timeout);
            inflight.fetch_sub(1, Ordering::SeqCst);
            Probe::Filtered
        })
    };
    let s = Scanner::new(
        Arc::new(c),
        Arc::clone(&clock) as Arc<dyn Clock>,
        None,
        CONNECT_TIMEOUT,
        PER_HOST,
    );
    let ports = port_list(&[]);
    let r = s
        .scan_host(
            "192.168.1.66".parse().unwrap(),
            &ports,
            &BTreeSet::new(),
            &AtomicBool::new(false),
        )
        .unwrap();
    // nothing answered: nothing that may close a port
    assert!(!r.answered && r.open.is_empty() && r.closed.is_empty());
    assert_eq!(r.filtered.len(), ports.len());
    assert_eq!(attempts.load(Ordering::SeqCst), ports.len());
    assert!(most.load(Ordering::SeqCst) <= PER_HOST);
    // ceil(1045 / 8) timeouts of 1.5 s: 196.5 s, about 3.3 minutes
    let bound = CONNECT_TIMEOUT * ports.len().div_ceil(PER_HOST) as u32;
    assert_eq!(bound, Duration::from_millis(196_500));
    assert_eq!(clock.latest(), bound);
    // the rate limit adds at most ports / 200 s on top
    assert!(
        bound + Duration::from_secs(ports.len() as u64) / RATE_PER_SEC < Duration::from_secs(205)
    );

    // and a fast host on another interface is done while the slow one is
    // still being scanned
    let doc = home_router();
    let slow_ip: Ipv4Addr = "192.168.1.66".parse().unwrap();
    let rig_slot: Arc<Mutex<Option<Arc<PortScan>>>> = Arc::default();
    let fast_done_first = Arc::new(AtomicBool::new(false));
    let c = {
        let (slot, seen) = (Arc::clone(&rig_slot), Arc::clone(&fast_done_first));
        let last = *ports.last().unwrap();
        FnConnector(move |a: SocketAddr, _| {
            if a.ip() != IpAddr::V4(slow_ip) {
                return if a.port() == 80 {
                    Probe::Open
                } else {
                    Probe::Closed
                };
            }
            std::thread::sleep(Duration::from_millis(2));
            if a.port() == last
                && let Some(svc) = lock(&slot).as_ref()
            {
                seen.store(svc.ports(MAC2).is_some(), Ordering::SeqCst);
            }
            Probe::Filtered
        })
    };
    let rig = Rig::new(
        Scanner::new(
            Arc::new(c),
            Arc::new(SystemClock::default()),
            None,
            Duration::from_millis(2),
            PER_HOST,
        ),
        vec![
            host(MAC1, "192.168.1.66", "lan", Some(NOW)),
            host(MAC2, "192.168.20.7", "opt1", Some(NOW)),
        ],
    );
    *lock(&rig_slot) = Some(Arc::clone(&rig.svc));
    rig.apply(&doc);
    rig.now.store(NOW + 86_400, Ordering::SeqCst);
    rig.svc.tick();
    assert!(
        fast_done_first.load(Ordering::SeqCst),
        "the fast interface waited"
    );
    assert_eq!(open_ports(&rig.svc.ports(MAC2).unwrap()), [80]);
    assert!(rig.svc.ports(MAC1).is_none());
}

/// Review focus 2: a scan overlapping a shutdown or an apply.
#[test]
fn cancelled_scan_keeps_previous_results() {
    for by_apply in [false, true] {
        let slot: Arc<Mutex<Option<Arc<PortScan>>>> = Arc::default();
        let calls = Arc::new(AtomicUsize::new(0));
        let phase2 = Arc::new(AtomicBool::new(false));
        let c = {
            let (slot, calls, phase2) =
                (Arc::clone(&slot), Arc::clone(&calls), Arc::clone(&phase2));
            FnConnector(move |a: SocketAddr, _| {
                if !phase2.load(Ordering::SeqCst) {
                    return if a.port() == 22 || a.port() == 80 {
                        Probe::Open
                    } else {
                        Probe::Closed
                    };
                }
                // the second scan: everything refused, and halfway through
                // the agent stops (or an apply lands)
                if calls.fetch_add(1, Ordering::SeqCst) == 300
                    && let Some(svc) = lock(&slot).clone()
                {
                    if by_apply {
                        let mut d = home_router();
                        d.hosts.portscan.extra_ports = vec![9999];
                        svc.set_document(&d, &[]);
                    } else {
                        svc.stop();
                    }
                }
                Probe::Closed
            })
        };
        let rig = Rig::new(
            scanner(Arc::new(c)),
            vec![host(MAC1, "192.168.1.50", "lan", Some(NOW))],
        );
        *lock(&slot) = Some(Arc::clone(&rig.svc));
        rig.apply(&home_router());
        rig.scan(MAC1);
        let before = rig.svc.ports(MAC1).unwrap();
        assert_eq!(open_ports(&before), [22, 80]);
        let file = rig.file();
        phase2.store(true, Ordering::SeqCst);
        rig.now.store(NOW + 60, Ordering::SeqCst);
        rig.svc.scan_now(MAC1).unwrap();
        let t = Instant::now();
        while rig.svc.scanning(MAC1) {
            assert!(t.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            calls.load(Ordering::SeqCst) > 300,
            "the cancel did not happen"
        );
        assert!(
            calls.load(Ordering::SeqCst) < port_list(&[]).len(),
            "nothing stopped"
        );
        // not saved as "all closed"
        assert_eq!(rig.svc.ports(MAC1).unwrap(), before, "by_apply={by_apply}");
        assert_eq!(rig.file(), file);
        if !by_apply {
            assert_eq!(rig.svc.scan_now(MAC1), Err(ScanNowError::NotReady));
        }
    }
}

/// Review focus 3: the address changes or stops answering.
#[test]
fn failed_scan_does_not_close_ports() {
    let mode = Arc::new(Mutex::new("answer"));
    let rig_hosts: Arc<Mutex<Option<Inventory>>> = Arc::default();
    let c = {
        let (mode, rig_hosts) = (Arc::clone(&mode), Arc::clone(&rig_hosts));
        FnConnector(move |a: SocketAddr, _| match *lock(&mode) {
            "answer" => {
                if [22, 554].contains(&a.port()) {
                    Probe::Open
                } else {
                    Probe::Closed
                }
            }
            "unreachable" => Probe::Unreachable,
            "silent" => Probe::Filtered,
            // the inventory moves the address to another device mid-scan,
            // which refuses everything
            _ => {
                if a.port() == 1
                    && let Some(h) = lock(&rig_hosts).as_ref()
                {
                    let mut h = lock(h);
                    h[0].ipv4 = Some("192.168.1.77".parse().unwrap());
                    h.push(host(MAC2, "192.168.1.50", "lan", Some(NOW)));
                }
                Probe::Closed
            }
        })
    };
    let rig = Rig::new(
        scanner(Arc::new(c)),
        vec![host(MAC1, "192.168.1.50", "lan", Some(NOW))],
    );
    *lock(&rig_hosts) = Some(Arc::clone(&rig.hosts));
    rig.apply(&home_router());
    rig.scan(MAC1);
    let before = rig.svc.ports(MAC1).unwrap();
    assert_eq!(open_ports(&before), [22, 554]);
    for m in ["unreachable", "silent", "moved"] {
        *lock(&mode) = m;
        rig.now.fetch_add(3600, Ordering::SeqCst);
        rig.scan(MAC1);
        assert_eq!(rig.svc.ports(MAC1).unwrap(), before, "{m}");
        assert!(rig.svc.ports(MAC2).is_none(), "{m}");
    }
    // a completed scan that is refused everywhere does close them
    *lock(&rig.hosts) = vec![host(MAC1, "192.168.1.50", "lan", Some(NOW))];
    *lock(&mode) = "answer";
    let s = Scanner::new(
        answers(&[]),
        Arc::new(SystemClock::default()),
        None,
        CONNECT_TIMEOUT,
        8,
    );
    let rig2 = Rig::in_dir(s, lock(&rig.hosts).clone(), rig.dir);
    rig2.apply(&home_router());
    rig2.now.store(NOW + 86_400, Ordering::SeqCst);
    rig2.scan(MAC1);
    let after = rig2.svc.ports(MAC1).unwrap();
    assert!(open_ports(&after).is_empty());
    assert!(
        after
            .ports
            .iter()
            .all(|e| e.closed_at == Some(NOW + 86_400))
    );
}

/// Review focus 5: scan-now spam.
#[test]
fn scan_now_spam_is_refused() {
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let c = {
        let gate = Arc::clone(&gate);
        FnConnector(move |_: SocketAddr, _| {
            let (m, cv) = &*gate;
            let mut open = lock(m);
            while !*open {
                open = cv.wait(open).unwrap_or_else(|e| e.into_inner());
            }
            Probe::Closed
        })
    };
    let rig = Rig::new(
        scanner(Arc::new(c)),
        vec![
            host(MAC1, "192.168.1.51", "lan", Some(NOW)),
            host(MAC2, "192.168.20.52", "opt1", Some(NOW)),
            host(MAC3, "192.168.30.53", "opt2", Some(NOW)),
        ],
    );
    assert_eq!(rig.svc.scan_now(MAC1), Err(ScanNowError::NotReady));
    rig.apply(&home_router());
    assert_eq!(rig.svc.scan_now(MAC1), Ok(()));
    for _ in 0..20 {
        assert_eq!(rig.svc.scan_now(MAC1), Err(ScanNowError::Busy));
        assert_eq!(
            rig.svc.scan_now(&MAC1.to_uppercase()),
            Err(ScanNowError::Busy)
        );
    }
    assert_eq!(rig.svc.scan_now(MAC2), Ok(()));
    assert_eq!(rig.svc.scan_now(MAC3), Err(ScanNowError::TooMany));
    assert!(rig.svc.scanning(MAC1) && rig.svc.scanning(MAC2) && !rig.svc.scanning(MAC3));
    // an unknown MAC is unknown even while the scan-now slots are full
    assert_eq!(
        rig.svc.scan_now("aa:bb:cc:dd:ee:99"),
        Err(ScanNowError::Unknown)
    );
    {
        let (m, cv) = &*gate;
        *lock(m) = true;
        cv.notify_all();
    }
    let t = Instant::now();
    while rig.svc.scanning(MAC1) || rig.svc.scanning(MAC2) {
        assert!(t.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(rig.svc.ports(MAC1).is_some() && rig.svc.ports(MAC2).is_some());
    rig.scan(MAC3);
    assert_eq!(
        rig.svc.scan_now("aa:bb:cc:dd:ee:99"),
        Err(ScanNowError::Unknown)
    );
}

#[test]
fn merge_marks_new_and_closed() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = PortStore::load(dir.path().join("ports.json"));
    s.merge(&MAC1.to_uppercase(), &complete(&[22, 80]), NOW);
    let h = s.get(MAC1).unwrap().clone();
    assert_eq!(h.last_scan, NOW);
    assert_eq!(open_ports(&h), [22, 80]);
    assert_eq!(h.ports[0].service, "ssh");
    assert!(h.ports.iter().all(|e| e.is_new(NOW + 3600)));
    assert!(h.ports.iter().all(|e| !e.is_new(NOW + 86_400)));

    // a day later: 22 closed, 80 still open, 23 new
    let day2 = NOW + 86_400;
    s.merge(MAC1, &complete(&[80, 23]), day2);
    let h = s.get(MAC1).unwrap();
    let by: BTreeMap<u16, &PortEntry> = h.ports.iter().map(|e| (e.port, e)).collect();
    assert_eq!(by[&22].closed_at, Some(day2));
    assert_eq!(by[&22].last_seen, NOW);
    assert_eq!(
        (by[&80].first_seen, by[&80].last_seen, by[&80].closed_at),
        (NOW, day2, None)
    );
    assert!(by[&23].is_new(day2) && !by[&80].is_new(day2));
    assert_eq!(by[&23].service, "telnet");
    assert_eq!(open_ports(h), [23, 80]);

    // closed stays closed from when it closed, and reopens
    s.merge(MAC1, &complete(&[80, 23]), day2 + 10);
    assert_eq!(s.get(MAC1).unwrap().ports[0].closed_at, Some(day2));
    s.merge(MAC1, &complete(&[22, 80, 23]), day2 + 20);
    assert_eq!(s.get(MAC1).unwrap().ports[0].closed_at, None);
    s.merge(MAC1, &complete(&[80, 23]), day2 + 30);

    // closed entries are kept 90 days
    s.prune(day2 + 30 + KEEP_SECS);
    assert!(s.get(MAC1).unwrap().ports.iter().any(|e| e.port == 22));
    s.merge(MAC1, &complete(&[80, 23]), day2 + 40 + KEEP_SECS);
    s.prune(day2 + 40 + KEEP_SECS);
    assert_eq!(open_ports(s.get(MAC1).unwrap()), [23, 80]);
    assert_eq!(s.get(MAC1).unwrap().ports.len(), 2);

    // a host not scanned for 90 days goes
    s.merge(MAC2, &complete(&[443]), NOW);
    s.prune(NOW + KEEP_SECS + 1);
    assert!(s.get(MAC2).is_none());

    // round trip through the file, and nothing temporary left
    s.persist().unwrap();
    let again = PortStore::load(dir.path().join("ports.json"));
    assert_eq!(again.get(MAC1), s.get(MAC1));
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, ["ports.json"]);
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.path().join("ports.json")).unwrap())
            .unwrap();
    assert_eq!(v["version"], 1);
    assert_eq!(v["hosts"][MAC1]["ports"][0]["port"], 23);
    assert!(v["hosts"][MAC1]["ports"][0].get("closed_at").is_none());
}

#[test]
fn ports_per_host_are_capped() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = PortStore::load(dir.path().join("ports.json"));
    let first: Vec<u16> = (1..=1000).collect();
    s.merge(MAC1, &complete(&first), NOW);
    let second: Vec<u16> = (2000..2100).collect();
    s.merge(MAC1, &complete(&second), NOW + 1);
    let h = s.get(MAC1).unwrap();
    assert_eq!(h.ports.len(), MAX_PORTS_PER_HOST);
    // every open port is kept; the rest are the latest closed
    assert_eq!(h.open().count(), 100);
    assert!(h.ports.windows(2).all(|w| w[0].port < w[1].port));
}

#[test]
fn unusable_file_is_kept_aside() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ports.json");
    std::fs::write(&p, b"{not json").unwrap();
    let s = PortStore::load(p.clone());
    assert!(s.get(MAC1).is_none());
    assert!(dir.path().join("ports.json.bad").exists());
    std::fs::write(&p, br#"{"version":9,"hosts":{}}"#).unwrap();
    let _ = PortStore::load(p.clone());
    assert!(!p.exists());
}

#[test]
fn schedule_next_run_local_time() {
    // a UTC midnight (2026-01-15)
    let midnight = 1_768_435_200;
    // UTC: 03:30 the same day, or tomorrow once it has passed
    assert_eq!(next_run(midnight, 0, (3, 30)), midnight + 12_600);
    assert_eq!(
        next_run(midnight + 12_600, 0, (3, 30)),
        midnight + 12_600 + 86_400
    );
    assert_eq!(next_run(midnight + 12_599, 0, (3, 30)), midnight + 12_600);
    // UTC+1 (Amsterdam in winter): 03:30 local is 02:30 UTC
    assert_eq!(next_run(midnight, 3600, (3, 30)), midnight + 9000);
    // UTC-8 at 20:00 UTC (12:00 local): 03:30 local tomorrow, 11:30 UTC
    assert_eq!(
        next_run(midnight + 72_000, -28_800, (3, 30)),
        midnight + 86_400 + 41_400
    );
    // UTC+5:30 at 22:00 UTC = 03:30 local the next day, exactly: a day on
    assert_eq!(
        next_run(midnight + 79_200, 19_800, (3, 30)),
        midnight + 79_200 + 86_400
    );
    assert_eq!(
        next_run(midnight + 79_199, 19_800, (3, 30)),
        midnight + 79_200
    );
    assert_eq!(next_run(midnight, 0, (0, 0)), midnight + 86_400);
    assert_eq!(parse_offset("+0530"), Some(19_800));
    assert_eq!(parse_offset("-0800"), Some(-28_800));
    assert_eq!(parse_offset("+0000"), Some(0));
    assert_eq!(parse_offset("UTC"), None);
    assert_eq!(parse_offset("+05"), None);
}

#[test]
fn tz_offset_reads_the_named_zone() {
    // where `date` and tzdata exist (the router, dev machines)
    if std::process::Command::new("date")
        .arg("+%z")
        .output()
        .is_err()
    {
        return;
    }
    assert_eq!(tz_offset("UTC"), 0);
    assert_eq!(tz_offset("Etc/GMT-5"), 18_000);
}

#[test]
fn daily_tick_runs_at_the_local_time_once() {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = {
        let calls = Arc::clone(&calls);
        FnConnector(move |a: SocketAddr, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            if a.port() == 23 {
                Probe::Open
            } else {
                Probe::Closed
            }
        })
    };
    // NOW is 2027-01-15 08:00 UTC = 09:00 at the rig's UTC+1
    let rig = Rig::new(
        scanner(Arc::new(c)),
        vec![host(MAC1, "192.168.1.50", "lan", Some(NOW))],
    );
    rig.svc.tick();
    assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing before a document");
    rig.apply(&home_router());
    rig.svc.tick();
    assert_eq!(calls.load(Ordering::SeqCst), 0, "not at start-up");
    // 03:29 local the next day: not yet; 03:30: once
    let next = next_run(NOW as i64, 3600, (3, 30)) as u64;
    rig.now.store(next - 60, Ordering::SeqCst);
    rig.svc.tick();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    rig.now.store(next, Ordering::SeqCst);
    rig.svc.tick();
    let n = port_list(&[]).len();
    assert_eq!(calls.load(Ordering::SeqCst), n);
    assert_eq!(open_ports(&rig.svc.ports(MAC1).unwrap()), [23]);
    rig.now.store(next + 3600, Ordering::SeqCst);
    rig.svc.tick();
    assert_eq!(calls.load(Ordering::SeqCst), n, "once a day");
    // off: no daily scan, scan now still works
    let mut off = home_router();
    off.hosts.portscan.enabled = false;
    rig.apply(&off);
    rig.now.store(next + 86_400, Ordering::SeqCst);
    rig.svc.tick();
    assert_eq!(calls.load(Ordering::SeqCst), n);
    rig.scan(MAC1);
    assert_eq!(calls.load(Ordering::SeqCst), 2 * n);
}

#[test]
fn a_sweep_cut_by_an_apply_resumes_with_the_rest() {
    let slot: Arc<Mutex<Option<Arc<PortScan>>>> = Arc::default();
    let per_ip: Arc<Mutex<BTreeMap<Ipv4Addr, usize>>> = Arc::default();
    let cut = Arc::new(AtomicBool::new(false));
    let c = {
        let (slot, per_ip, cut) = (Arc::clone(&slot), Arc::clone(&per_ip), Arc::clone(&cut));
        FnConnector(move |a: SocketAddr, _| {
            let IpAddr::V4(ip) = a.ip() else {
                unreachable!()
            };
            *lock(&per_ip).entry(ip).or_default() += 1;
            // the second LAN host is cut by an apply
            if ip == Ipv4Addr::new(192, 168, 1, 52)
                && a.port() == 500
                && !cut.swap(true, Ordering::SeqCst)
                && let Some(svc) = lock(&slot).clone()
            {
                let mut d = home_router();
                d.hosts.portscan.time = "04:00".into();
                svc.set_document(&d, &[]);
            }
            if a.port() == 80 {
                Probe::Open
            } else {
                Probe::Closed
            }
        })
    };
    let rig = Rig::new(
        scanner(Arc::new(c)),
        vec![
            host(MAC1, "192.168.1.51", "lan", Some(NOW)),
            host(MAC2, "192.168.1.52", "lan", Some(NOW)),
            host(MAC3, "192.168.1.53", "lan", Some(NOW)),
        ],
    );
    *lock(&slot) = Some(Arc::clone(&rig.svc));
    rig.apply(&home_router());
    rig.now.store(NOW + 86_400, Ordering::SeqCst);
    rig.svc.tick();
    assert!(cut.load(Ordering::SeqCst));
    assert!(rig.svc.ports(MAC1).is_some());
    assert!(rig.svc.ports(MAC2).is_none() && rig.svc.ports(MAC3).is_none());
    // the next tick finishes the same sweep, without MAC1 again
    rig.svc.tick();
    let n = port_list(&[]).len();
    let counts = lock(&per_ip).clone();
    assert_eq!(counts[&Ipv4Addr::new(192, 168, 1, 51)], n);
    assert!(counts[&Ipv4Addr::new(192, 168, 1, 52)] > n);
    assert_eq!(counts[&Ipv4Addr::new(192, 168, 1, 53)], n);
    assert!(rig.svc.ports(MAC2).is_some() && rig.svc.ports(MAC3).is_some());
    // and then waits for the next day
    rig.svc.tick();
    assert_eq!(lock(&per_ip)[&Ipv4Addr::new(192, 168, 1, 53)], n);
}

#[test]
fn targets_skip_quarantine_router_wan_and_stale() {
    use sensr_schema::PathAccess;
    let mut doc = home_router();
    doc.set_by_path(
        "firewall.host_modes.6d0de000-0000-4000-8000-000000000001",
        serde_json::json!({"mac": "AA:BB:CC:DD:EE:0A", "mode": "quarantine"}),
    )
    .unwrap();
    doc.set_by_path(
        "firewall.host_modes.6d0de000-0000-4000-8000-000000000002",
        serde_json::json!({"mac": "aa:bb:cc:dd:ee:0b", "mode": "isolated"}),
    )
    .unwrap();
    let plan = Plan::from_doc(&doc, &["192.168.20.200".parse().unwrap()]);
    let mut no_mac = host("id:01ff", "192.168.1.60", "lan", Some(NOW));
    no_mac.mac = None;
    let mut no_ip = host("aa:bb:cc:dd:ee:09", "192.168.1.61", "lan", Some(NOW));
    no_ip.ipv4 = None;
    let hosts = vec![
        host("AA:BB:CC:DD:EE:01", "192.168.1.50", "lan", Some(NOW - 60)),
        host(MAC2, "192.168.20.9", "opt1", Some(NOW - TARGET_SEEN_SECS)),
        // stale, never seen
        host(
            MAC3,
            "192.168.1.51",
            "lan",
            Some(NOW - TARGET_SEEN_SECS - 1),
        ),
        host("aa:bb:cc:dd:ee:04", "192.168.1.52", "lan", None),
        // WAN, and an unknown interface
        host("aa:bb:cc:dd:ee:05", "203.0.113.9", "wan", Some(NOW)),
        host("aa:bb:cc:dd:ee:06", "10.9.9.9", "nope", Some(NOW)),
        // the router itself (configured, and a live address), the subnet's
        // network and broadcast addresses
        host("aa:bb:cc:dd:ee:07", "192.168.1.1", "lan", Some(NOW)),
        host("aa:bb:cc:dd:ee:0d", "192.168.20.200", "opt1", Some(NOW)),
        host("aa:bb:cc:dd:ee:08", "192.168.1.255", "lan", Some(NOW)),
        host("aa:bb:cc:dd:ee:0c", "192.168.1.0", "lan", Some(NOW)),
        no_mac,
        no_ip,
        // quarantined (any case) is skipped; isolated is scanned
        host("aa:bb:cc:dd:ee:0a", "192.168.1.70", "lan", Some(NOW)),
        host("aa:bb:cc:dd:ee:0b", "192.168.1.71", "lan", Some(NOW)),
    ];
    let t = targets(&hosts, &plan.internal, &plan.quarantine, &plan.own, NOW);
    let got: Vec<(&str, String, &str)> = t
        .iter()
        .map(|t| (t.mac.as_str(), t.ip.to_string(), t.interface.as_str()))
        .collect();
    assert_eq!(
        got,
        [
            (MAC1, "192.168.1.50".to_owned(), "lan"),
            (MAC2, "192.168.20.9".to_owned(), "opt1"),
            ("aa:bb:cc:dd:ee:0b", "192.168.1.71".to_owned(), "lan"),
        ]
    );
    // scan now ignores the age only
    let rig = Rig::new(scanner(answers(&[])), hosts);
    rig.apply(&doc);
    assert_eq!(
        rig.svc.scan_now("aa:bb:cc:dd:ee:0a"),
        Err(ScanNowError::NotScannable)
    );
    assert_eq!(
        rig.svc.scan_now("aa:bb:cc:dd:ee:05"),
        Err(ScanNowError::NotScannable)
    );
    assert_eq!(
        rig.svc.scan_now("aa:bb:cc:dd:ee:07"),
        Err(ScanNowError::NotScannable)
    );
    rig.scan(MAC3);
    assert!(rig.svc.ports(MAC3).is_some());
}

#[test]
fn addresses_outside_the_interface_are_never_scanned() {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = {
        let calls = Arc::clone(&calls);
        FnConnector(move |_: SocketAddr, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Probe::Closed
        })
    };
    // a lease or neighbour entry claims a public address on the LAN
    let rig = Rig::new(
        scanner(Arc::new(c)),
        vec![
            host(MAC1, "8.8.8.8", "lan", Some(NOW)),
            host(MAC2, "192.168.20.5", "lan", Some(NOW)),
        ],
    );
    let doc = home_router();
    rig.apply(&doc);
    let plan = Plan::from_doc(&doc, &[]);
    let hosts = lock(&rig.hosts).clone();
    assert!(targets(&hosts, &plan.internal, &plan.quarantine, &plan.own, NOW).is_empty());
    assert_eq!(rig.svc.scan_now(MAC1), Err(ScanNowError::NotScannable));
    // another internal network's address on the wrong interface, too
    assert_eq!(rig.svc.scan_now(MAC2), Err(ScanNowError::NotScannable));
    rig.now.store(NOW + 86_400, Ordering::SeqCst);
    rig.svc.tick();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn connect_errors_map_to_probes() {
    use std::io::{Error, ErrorKind};
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    let (refused, timedout, hostdown, hostunreach, netunreach) = (61, 60, 64, 65, 51);
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "freebsd")))]
    let (refused, timedout, hostdown, hostunreach, netunreach) = (111, 110, 112, 113, 101);
    let errno = |n: i32| classify(&Error::from_raw_os_error(n));
    assert_eq!(errno(refused), Probe::Closed);
    assert_eq!(errno(timedout), Probe::Filtered);
    // an ICMP answer within the timeout: the port is closed
    assert_eq!(errno(hostunreach), Probe::Rejected);
    assert_eq!(errno(hostdown), Probe::Rejected);
    // the router cannot send: no result
    assert_eq!(errno(netunreach), Probe::Unreachable);
    assert_eq!(errno(1), Probe::Unreachable); // EPERM
    assert_eq!(errno(13), Probe::Unreachable); // EACCES
    assert_eq!(
        classify(&Error::from(ErrorKind::ConnectionReset)),
        Probe::Closed
    );
    assert_eq!(classify(&Error::from(ErrorKind::TimedOut)), Probe::Filtered);
}

#[test]
fn filtered_open_port_is_retried_and_kept() {
    let phase2 = Arc::new(AtomicBool::new(false));
    let tries: Arc<Mutex<BTreeMap<u16, usize>>> = Arc::default();
    let c = {
        let (phase2, tries) = (Arc::clone(&phase2), Arc::clone(&tries));
        FnConnector(move |a: SocketAddr, _| {
            let p = a.port();
            if !phase2.load(Ordering::SeqCst) {
                return if [22, 80, 443].contains(&p) {
                    Probe::Open
                } else {
                    Probe::Closed
                };
            }
            let n = {
                let mut t = lock(&tries);
                let n = t.entry(p).or_default();
                *n += 1;
                *n
            };
            match p {
                // a lost SYN: answers on the retry
                22 if n == 1 => Probe::Filtered,
                22 => Probe::Open,
                // silent now, twice
                80 => Probe::Filtered,
                // a never-open port that times out stays unknown
                8080 => Probe::Filtered,
                _ => Probe::Closed,
            }
        })
    };
    let rig = Rig::new(
        scanner(Arc::new(c)),
        vec![host(MAC1, "192.168.1.50", "lan", Some(NOW))],
    );
    rig.apply(&home_router());
    rig.scan(MAC1);
    assert_eq!(open_ports(&rig.svc.ports(MAC1).unwrap()), [22, 80, 443]);
    phase2.store(true, Ordering::SeqCst);
    let t2 = NOW + 7200;
    rig.now.store(t2, Ordering::SeqCst);
    rig.scan(MAC1);
    let t = lock(&tries).clone();
    assert_eq!((t[&22], t[&80], t[&443], t[&8080], t[&23]), (2, 2, 1, 1, 1));
    let h = rig.svc.ports(MAC1).unwrap();
    let by: BTreeMap<u16, &PortEntry> = h.ports.iter().map(|e| (e.port, e)).collect();
    assert_eq!((by[&22].last_seen, by[&22].closed_at), (t2, None));
    // kept as it was: still open, last seen at the first scan
    assert_eq!((by[&80].last_seen, by[&80].closed_at), (NOW, None));
    // refused: closed
    assert_eq!(by[&443].closed_at, Some(t2));
    assert!(!by.contains_key(&8080));
    assert_eq!(h.last_scan, t2);
    assert!(!h.all_filtered);
}

#[test]
fn a_host_dropping_everything_keeps_its_ports() {
    let mode = Arc::new(Mutex::new("answer"));
    let c = {
        let mode = Arc::clone(&mode);
        FnConnector(move |a: SocketAddr, _| match *lock(&mode) {
            "answer" if a.port() == 22 => Probe::Open,
            "answer" => Probe::Closed,
            "rejected" => Probe::Rejected,
            _ => Probe::Filtered,
        })
    };
    let rig = Rig::new(
        scanner(Arc::new(c)),
        vec![host(MAC1, "192.168.1.50", "lan", Some(NOW))],
    );
    rig.apply(&home_router());
    rig.scan(MAC1);
    let before = rig.svc.ports(MAC1).unwrap();
    assert_eq!(open_ports(&before), [22]);

    // not seen for 15 minutes: probably gone, nothing changes
    for m in ["filtered", "rejected"] {
        *lock(&mode) = m;
        rig.now.store(NOW + 900, Ordering::SeqCst);
        rig.scan(MAC1);
        assert_eq!(rig.svc.ports(MAC1).unwrap(), before, "{m}");
    }

    // seen a minute ago and silent: scanned, marked, ports untouched
    *lock(&mode) = "filtered";
    lock(&rig.hosts)[0].last_seen = Some(NOW + 840);
    rig.scan(MAC1);
    let h = rig.svc.ports(MAC1).unwrap();
    assert_eq!(h.last_scan, NOW + 900);
    assert!(h.all_filtered);
    assert_eq!(h.ports, before.ports);
    let v: serde_json::Value = serde_json::from_str(&rig.file()).unwrap();
    assert_eq!(v["hosts"][MAC1]["all_filtered"], true);

    // up and answering with ICMP rejects only: those close the port
    *lock(&mode) = "rejected";
    rig.now.store(NOW + 960, Ordering::SeqCst);
    rig.scan(MAC1);
    let h = rig.svc.ports(MAC1).unwrap();
    assert!(open_ports(&h).is_empty());
    assert!(!h.all_filtered);
    assert_eq!(h.ports[0].closed_at, Some(NOW + 960));
}

#[test]
fn a_missed_sweep_catches_up_after_start() {
    for (last, expect) in [(NOW - 2 * 86_400, true), (NOW - 3600, false)] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("ports.json"),
            serde_json::json!({"version": 1, "last_sweep": last, "hosts": {}}).to_string(),
        )
        .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let c = {
            let calls = Arc::clone(&calls);
            FnConnector(move |_: SocketAddr, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                Probe::Closed
            })
        };
        let rig = Rig::in_dir(
            scanner(Arc::new(c)),
            vec![host(MAC1, "192.168.1.50", "lan", Some(NOW))],
            dir,
        );
        rig.apply(&home_router());
        rig.now
            .store(NOW + CATCH_UP_DELAY_SECS - 1, Ordering::SeqCst);
        rig.svc.tick();
        assert_eq!(calls.load(Ordering::SeqCst), 0, "not during boot");
        rig.now.store(NOW + CATCH_UP_DELAY_SECS, Ordering::SeqCst);
        rig.svc.tick();
        assert_eq!(calls.load(Ordering::SeqCst) > 0, expect, "last={last}");
        if expect {
            let v: serde_json::Value = serde_json::from_str(&rig.file()).unwrap();
            assert_eq!(v["last_sweep"], NOW + CATCH_UP_DELAY_SECS);
            // once
            let n = calls.load(Ordering::SeqCst);
            rig.now.store(NOW + 3600, Ordering::SeqCst);
            rig.svc.tick();
            assert_eq!(calls.load(Ordering::SeqCst), n);
        }
    }
}

#[test]
fn load_caps_ports_per_host() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ports.json");
    let ports: Vec<serde_json::Value> = (1..=2000u16)
        .map(|port| serde_json::json!({"port": port, "first_seen": 1, "last_seen": 1}))
        .collect();
    std::fs::write(
        &p,
        serde_json::json!({"version": 1, "hosts": {MAC1: {"last_scan": 1, "ports": ports}}})
            .to_string(),
    )
    .unwrap();
    let s = PortStore::load(p);
    assert_eq!(s.get(MAC1).unwrap().ports.len(), MAX_PORTS_PER_HOST);
}
