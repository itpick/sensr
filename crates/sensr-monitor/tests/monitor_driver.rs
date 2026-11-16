//! The probe-loop driver against a scripted network, on tokio's paused
//! clock: no real time passes and no socket is opened.
//!
//! Covers: SYS-GW-001, SYS-GW-002, SYS-GW-003

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sensr_monitor::{
    Family, GatewayConfig, Monitor, MonitorError, MonitorSettings, ProbeSpec, Prober,
    ProberFactory, Reply, Status, StatusChanged,
};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep};

#[derive(Debug, Clone, Copy)]
enum Link {
    /// Replies after this delay.
    Rtt(Duration),
    /// Swallows every request.
    Dead,
}

#[derive(Default)]
struct Net {
    links: Mutex<HashMap<IpAddr, Link>>,
    refuse_open: Mutex<bool>,
    opens: AtomicUsize,
}

impl Net {
    fn set(&self, addr: IpAddr, link: Link) {
        self.links.lock().expect("lock").insert(addr, link);
    }

    fn link(&self, addr: IpAddr) -> Link {
        self.links
            .lock()
            .expect("lock")
            .get(&addr)
            .copied()
            .unwrap_or(Link::Dead)
    }
}

#[derive(Clone, Default)]
struct FakeFactory(Arc<Net>);

struct FakeProber {
    target: IpAddr,
    net: Arc<Net>,
    tx: mpsc::UnboundedSender<u16>,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<u16>>,
}

impl ProberFactory for FakeFactory {
    type Prober = FakeProber;

    fn open(&self, spec: &ProbeSpec) -> io::Result<FakeProber> {
        self.0.opens.fetch_add(1, Ordering::SeqCst);
        if *self.0.refuse_open.lock().expect("lock") {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "not permitted",
            ));
        }
        let (tx, rx) = mpsc::unbounded_channel();
        Ok(FakeProber {
            target: spec.target,
            net: Arc::clone(&self.0),
            tx,
            rx: tokio::sync::Mutex::new(rx),
        })
    }
}

impl Prober for FakeProber {
    async fn send(&self, seq: u16) -> io::Result<()> {
        if let Link::Rtt(d) = self.net.link(self.target) {
            let tx = self.tx.clone();
            tokio::spawn(async move {
                sleep(d).await;
                let _ = tx.send(seq);
            });
        }
        Ok(())
    }

    async fn recv(&self) -> io::Result<Reply> {
        let seq = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::other("closed"))?;
        Ok(Reply {
            seq,
            received: Instant::now(),
        })
    }
}

fn addr(s: &str) -> IpAddr {
    s.parse().expect("address")
}

fn gw(name: &str, target: Option<&str>) -> GatewayConfig {
    GatewayConfig::new(name, Family::Inet, target.map(addr))
}

fn setup() -> (Arc<Net>, Monitor<FakeFactory>) {
    let factory = FakeFactory::default();
    let net = Arc::clone(&factory.0);
    (net, Monitor::new(factory))
}

fn drain(rx: &mut tokio::sync::broadcast::Receiver<StatusChanged>) -> Vec<(Status, Status)> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push((ev.from, ev.to));
    }
    out
}

#[tokio::test(start_paused = true)]
async fn unmonitored_gateway_is_online_without_probing() {
    let (net, mon) = setup();
    mon.upsert(GatewayConfig {
        monitor: false,
        ..gw("WAN_DHCP", Some("192.0.2.1"))
    })
    .expect("upsert");
    sleep(Duration::from_secs(10)).await;
    let state = mon.snapshot().get("WAN_DHCP").cloned().expect("state");
    assert_eq!(state.status, Status::Online);
    assert!(!state.monitored);
    assert_eq!(state.latency_ms, None);
    assert_eq!(net.opens.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn healthy_gateway_goes_pending_then_online() {
    let (net, mon) = setup();
    net.set(addr("192.0.2.1"), Link::Rtt(Duration::from_millis(12)));
    let mut events = mon.events();
    mon.upsert(gw("WAN", Some("192.0.2.1"))).expect("upsert");
    assert_eq!(mon.snapshot().status("WAN"), Some(Status::Pending));
    sleep(Duration::from_secs(5)).await;
    let state = mon.snapshot().get("WAN").cloned().expect("state");
    assert_eq!(state.status, Status::Online);
    assert_eq!(state.latency_ms, Some(12.0));
    assert_eq!(state.loss_pct, Some(0.0));
    assert_eq!(state.monitor_address, Some(addr("192.0.2.1")));
    assert_eq!(drain(&mut events), [(Status::Pending, Status::Online)]);
}

#[tokio::test(start_paused = true)]
async fn dynamic_gateway_waits_for_its_address() {
    let (net, mon) = setup();
    net.set(addr("198.51.100.1"), Link::Rtt(Duration::from_millis(3)));
    mon.upsert(gw("WAN_DHCP", None)).expect("upsert");
    sleep(Duration::from_secs(10)).await;
    assert_eq!(mon.snapshot().status("WAN_DHCP"), Some(Status::Pending));
    assert_eq!(net.opens.load(Ordering::SeqCst), 0, "nothing to probe yet");

    mon.set_target("WAN_DHCP", Some(addr("198.51.100.1")))
        .expect("set target");
    sleep(Duration::from_secs(3)).await;
    let state = mon.snapshot().get("WAN_DHCP").cloned().expect("state");
    assert_eq!(state.status, Status::Online);
    assert_eq!(state.monitor_address, Some(addr("198.51.100.1")));

    // Lease gone: back to pending, probing stops.
    mon.set_target("WAN_DHCP", None).expect("clear target");
    assert_eq!(mon.snapshot().status("WAN_DHCP"), Some(Status::Pending));
    assert_eq!(
        mon.set_target("nope", None),
        Err(MonitorError::UnknownGateway("nope".into()))
    );
}

#[tokio::test(start_paused = true)]
async fn outage_degrades_through_loss_to_down_and_recovers() {
    let (net, mon) = setup();
    let target = addr("192.0.2.1");
    net.set(target, Link::Rtt(Duration::from_millis(10)));
    let mut events = mon.events();
    mon.upsert(gw("WAN", Some("192.0.2.1"))).expect("upsert");
    sleep(Duration::from_secs(20)).await;
    assert_eq!(mon.snapshot().status("WAN"), Some(Status::Online));
    drain(&mut events);

    net.set(target, Link::Dead);
    sleep(Duration::from_secs(30)).await;
    let state = mon.snapshot().get("WAN").cloned().expect("state");
    assert_eq!(state.status, Status::Down);
    assert!(state.loss_pct.expect("loss") > 20.0);
    // 20 % loss is "loss" only, above it is "down"; the window passes
    // through both.
    assert_eq!(
        drain(&mut events),
        [(Status::Online, Status::Loss), (Status::Loss, Status::Down)]
    );

    net.set(target, Link::Rtt(Duration::from_millis(10)));
    // The window still remembers the outage until enough good probes
    // arrive (time period 60 s): no hysteresis beyond that, like dpinger.
    sleep(Duration::from_secs(70)).await;
    assert_eq!(mon.snapshot().status("WAN"), Some(Status::Online));
}

#[tokio::test(start_paused = true)]
async fn slow_link_is_delay_then_down() {
    let (net, mon) = setup();
    let target = addr("192.0.2.9");
    net.set(target, Link::Rtt(Duration::from_millis(300)));
    mon.upsert(gw("SLOW", Some("192.0.2.9"))).expect("upsert");
    sleep(Duration::from_secs(5)).await;
    assert_eq!(mon.snapshot().status("SLOW"), Some(Status::Delay));

    net.set(target, Link::Rtt(Duration::from_millis(900)));
    sleep(Duration::from_secs(120)).await;
    assert_eq!(mon.snapshot().status("SLOW"), Some(Status::Down));
}

#[tokio::test(start_paused = true)]
async fn custom_thresholds_apply() {
    let (net, mon) = setup();
    net.set(addr("192.0.2.5"), Link::Rtt(Duration::from_millis(60)));
    mon.upsert(GatewayConfig {
        settings: MonitorSettings {
            latency_low: Duration::from_millis(20),
            latency_high: Duration::from_millis(50),
            ..MonitorSettings::default()
        },
        ..gw("LTE", Some("192.0.2.5"))
    })
    .expect("upsert");
    sleep(Duration::from_secs(3)).await;
    assert_eq!(mon.snapshot().status("LTE"), Some(Status::Down));

    let bad = GatewayConfig {
        settings: MonitorSettings {
            loss_low: 50,
            loss_high: 40,
            ..MonitorSettings::default()
        },
        ..gw("BAD", Some("192.0.2.6"))
    };
    assert!(matches!(
        mon.upsert(bad),
        Err(MonitorError::Settings(name, _)) if name == "BAD"
    ));
}

#[tokio::test(start_paused = true)]
async fn force_down_overrides_and_releases() {
    let (net, mon) = setup();
    net.set(addr("192.0.2.1"), Link::Rtt(Duration::from_millis(5)));
    mon.upsert(gw("WAN", Some("192.0.2.1"))).expect("upsert");
    mon.upsert(GatewayConfig {
        monitor: false,
        ..gw("VPN", Some("10.8.0.1"))
    })
    .expect("upsert");
    sleep(Duration::from_secs(5)).await;

    mon.set_force_down("WAN", true).expect("force");
    mon.set_force_down("VPN", true).expect("force");
    assert_eq!(mon.snapshot().status("WAN"), Some(Status::ForceDown));
    assert_eq!(mon.snapshot().status("VPN"), Some(Status::ForceDown));
    sleep(Duration::from_secs(5)).await;
    let wan = mon.snapshot().get("WAN").cloned().expect("state");
    assert_eq!(wan.status, Status::ForceDown, "stays forced while probing");
    assert_eq!(wan.latency_ms, Some(5.0), "figures keep updating");

    mon.set_force_down("WAN", false).expect("release");
    mon.set_force_down("VPN", false).expect("release");
    assert_eq!(mon.snapshot().status("VPN"), Some(Status::Online));
    sleep(Duration::from_secs(2)).await;
    assert_eq!(mon.snapshot().status("WAN"), Some(Status::Online));
}

#[tokio::test(start_paused = true)]
async fn open_failure_is_reported_and_retried() {
    let (net, mon) = setup();
    *net.refuse_open.lock().expect("lock") = true;
    net.set(addr("192.0.2.1"), Link::Rtt(Duration::from_millis(5)));
    mon.upsert(gw("WAN", Some("192.0.2.1"))).expect("upsert");
    sleep(Duration::from_secs(1)).await;
    let state = mon.snapshot().get("WAN").cloned().expect("state");
    assert_eq!(state.status, Status::Pending);
    assert_eq!(state.error.as_deref(), Some("not permitted"));

    *net.refuse_open.lock().expect("lock") = false;
    sleep(Duration::from_secs(10)).await;
    let state = mon.snapshot().get("WAN").cloned().expect("state");
    assert_eq!(state.status, Status::Online);
    assert_eq!(state.error, None);
    assert!(net.opens.load(Ordering::SeqCst) >= 2);
}

#[tokio::test(start_paused = true)]
async fn upsert_same_config_keeps_history_and_remove_forgets() {
    let (net, mon) = setup();
    net.set(addr("192.0.2.1"), Link::Rtt(Duration::from_millis(5)));
    mon.upsert(gw("WAN", Some("192.0.2.1"))).expect("upsert");
    sleep(Duration::from_secs(3)).await;
    mon.upsert(gw("WAN", Some("192.0.2.1")))
        .expect("upsert again");
    assert_eq!(
        net.opens.load(Ordering::SeqCst),
        1,
        "unchanged config: no restart"
    );
    assert_eq!(mon.snapshot().status("WAN"), Some(Status::Online));

    let mut watch = mon.subscribe();
    mon.remove("WAN").expect("remove");
    assert!(watch.has_changed().expect("watch"));
    assert!(watch.borrow_and_update().get("WAN").is_none());
    sleep(Duration::from_secs(3)).await;
    assert!(
        mon.snapshot().get("WAN").is_none(),
        "stopped loop does not resurrect it"
    );
    assert_eq!(
        mon.remove("WAN"),
        Err(MonitorError::UnknownGateway("WAN".into()))
    );
}

#[tokio::test(start_paused = true)]
async fn snapshot_serializes_for_the_api() {
    let (net, mon) = setup();
    net.set(addr("192.0.2.1"), Link::Rtt(Duration::from_millis(7)));
    mon.upsert(gw("WAN", Some("192.0.2.1"))).expect("upsert");
    mon.upsert(gw("WAN_DHCP6", None)).expect("upsert");
    sleep(Duration::from_secs(3)).await;
    let json = serde_json::to_value(mon.snapshot()).expect("json");
    let wan = &json["gateways"]["WAN"];
    assert_eq!(wan["name"], "WAN");
    assert_eq!(wan["status"], "online");
    assert_eq!(wan["monitored"], true);
    assert_eq!(wan["monitor_address"], "192.0.2.1");
    assert_eq!(wan["latency_ms"], 7.0);
    assert_eq!(wan["loss_pct"], 0.0);
    assert!(wan["last_change"].is_u64());
    assert!(wan.get("generation").is_none());
    let v6 = &json["gateways"]["WAN_DHCP6"];
    assert_eq!(v6["status"], "pending");
    assert!(v6["latency_ms"].is_null());
}
