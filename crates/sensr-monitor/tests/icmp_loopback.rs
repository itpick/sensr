//! Real ICMP / ICMPv6 echo against the loopback addresses.
//!
//! These need either a raw socket (CAP_NET_RAW / root) or an unprivileged
//! ping socket (Linux `net.ipv4.ping_group_range` covering our group, always
//! on macOS). Without either they print why and pass.
//!
//! Covers: SYS-GW-001
#![cfg(unix)]

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use sensr_monitor::{
    Family, GatewayConfig, IcmpFactory, IcmpProber, Monitor, MonitorSettings, ProbeSpec, Prober,
    Status,
};

fn spec(target: IpAddr) -> ProbeSpec {
    ProbeSpec {
        gateway: "loopback".into(),
        target,
        device: None,
        source: None,
        scope_id: None,
        data_length: 56,
        ident: IcmpFactory::next_ident(),
    }
}

/// Opens a prober or explains why the environment cannot run the test.
fn open_or_skip(target: IpAddr) -> Option<IcmpProber> {
    match IcmpProber::open(&spec(target)) {
        Ok(p) => {
            println!("{target}: using a {:?} socket", p.kind());
            Some(p)
        }
        Err(e) if skippable(&e) => {
            println!("skipping ICMP test for {target}: {e}");
            None
        }
        Err(e) => panic!("opening an ICMP socket to {target}: {e}"),
    }
}

fn skippable(e: &io::Error) -> bool {
    use io::ErrorKind::*;
    // Permission: neither raw nor ping sockets allowed. The others: a
    // sandbox without IPv6 loopback.
    matches!(
        e.kind(),
        PermissionDenied | AddrNotAvailable | NetworkUnreachable | Unsupported
    ) || e.raw_os_error() == Some(97) // EAFNOSUPPORT on Linux
        || e.raw_os_error() == Some(47) // EAFNOSUPPORT on macOS
        || e.raw_os_error() == Some(93) // EPROTONOSUPPORT on Linux
}

async fn echo(target: &str) {
    let target: IpAddr = target.parse().expect("address");
    let Some(prober) = open_or_skip(target) else {
        return;
    };
    for seq in 1..=3u16 {
        prober.send(seq).await.expect("send");
        let reply = tokio::time::timeout(Duration::from_secs(2), prober.recv())
            .await
            .expect("an echo reply from loopback within 2 s")
            .expect("recv");
        assert_eq!(reply.seq, seq);
    }
}

#[tokio::test]
async fn echo_ipv4_loopback() {
    echo("127.0.0.1").await;
}

#[tokio::test]
async fn echo_ipv6_loopback() {
    echo("::1").await;
}

#[tokio::test]
async fn monitor_reports_loopback_online() {
    let target: IpAddr = "127.0.0.1".parse().expect("address");
    if open_or_skip(target).is_none() {
        return;
    }
    let mon = Monitor::icmp();
    mon.upsert(GatewayConfig {
        settings: MonitorSettings {
            interval: Duration::from_millis(100),
            loss_interval: Duration::from_millis(300),
            time_period: Duration::from_secs(2),
            alert_interval: Duration::from_millis(100),
            ..MonitorSettings::default()
        },
        ..GatewayConfig::new("LO", Family::Inet, Some(target))
    })
    .expect("upsert");
    let mut snapshots = mon.subscribe();
    let online = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if snapshots.borrow_and_update().status("LO") == Some(Status::Online) {
                return;
            }
            snapshots.changed().await.expect("monitor alive");
        }
    })
    .await;
    let state = mon.snapshot().get("LO").cloned().expect("state");
    println!("loopback state: {state:?}");
    assert!(online.is_ok(), "loopback never came online: {state:?}");
    assert!(state.latency_ms.expect("latency") < 50.0);
}
