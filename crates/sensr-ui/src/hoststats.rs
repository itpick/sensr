//! Live host figures for the dashboard, read from procfs and sysfs (no privileges needed).
//!
//! Interface addresses are the ones the kernel holds, so a DHCP or SLAAC uplink shows what
//! it was given; the configured address is only a fallback for a link that has none.
//!
//! CPU usage and interface rates are deltas between calls, so a [`Sampler`] keeps the
//! previous counters and the last two minutes of traffic per device.

use crate::api::{InterfaceStatus, SystemStatus, TrafficSeries};
use crate::form::get_path;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

/// Samples kept per device (one per dashboard refresh, ~3 s apart).
const KEEP: usize = 40;

#[derive(Default)]
struct State {
    cpu: Option<(u64, u64)>,
    net: HashMap<String, (Instant, u64, u64)>,
    traffic: HashMap<String, VecDeque<(u64, u64)>>,
}

/// Reads host statistics, remembering counters between calls.
pub struct Sampler {
    root: PathBuf,
    state: Mutex<State>,
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new("/")
    }
}

fn read(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel)).ok()
}

fn read_u64(root: &Path, rel: &str) -> Option<u64> {
    read(root, rel)?.trim().parse().ok()
}

/// `(busy, total)` jiffies from the first line of /proc/stat.
fn cpu_times(stat: &str) -> Option<(u64, u64)> {
    let line = stat.lines().next()?.strip_prefix("cpu ")?;
    let v: Vec<u64> = line
        .split_whitespace()
        .filter_map(|x| x.parse().ok())
        .collect();
    let total: u64 = v.iter().sum();
    let idle = v.get(3)? + v.get(4).unwrap_or(&0);
    Some((total - idle, total))
}

fn meminfo(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
        .and_then(|rest| rest.split_whitespace().next()?.parse::<u64>().ok())
        .map(|kib| kib * 1024)
}

/// Local IPv4 addresses per device, `a.b.c.d/len`, from `proc/net/fib_trie` (the kernel's
/// local addresses) and `proc/net/route` (which device and subnet each one sits on).
/// Loopback is skipped; an address without a connected route (a /32 point-to-point) too.
fn live_ipv4(root: &Path) -> HashMap<String, String> {
    let mut locals: Vec<Ipv4Addr> = Vec::new();
    let mut leaf: Option<Ipv4Addr> = None;
    for line in read(root, "proc/net/fib_trie").unwrap_or_default().lines() {
        let t = line.trim_start();
        if let Some(a) = t.strip_prefix("|-- ") {
            leaf = a.trim().parse().ok();
        } else if t.starts_with("/32 host LOCAL")
            && let Some(a) = leaf.filter(|a| !a.is_loopback() && !locals.contains(a))
        {
            locals.push(a);
        }
    }
    // Connected routes: (device, network, mask). The hex fields are the kernel's
    // network-order word printed in host order, i.e. little-endian on the Pi and x86.
    let hex = |h: &str| {
        u32::from_str_radix(h, 16)
            .ok()
            .map(u32::to_le_bytes)
            .map(u32::from_be_bytes)
    };
    let routes: Vec<(String, u32, u32)> = read(root, "proc/net/route")
        .unwrap_or_default()
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (dev, dst, gw, mask) = (
                f.first()?,
                hex(f.get(1)?)?,
                hex(f.get(2)?)?,
                hex(f.get(7)?)?,
            );
            (gw == 0 && mask != 0).then(|| ((*dev).to_owned(), dst, mask))
        })
        .collect();
    let mut out = HashMap::new();
    for a in locals {
        let ip = u32::from(a);
        if let Some((dev, _, mask)) = routes
            .iter()
            .filter(|(_, dst, mask)| ip & mask == *dst)
            .max_by_key(|(_, _, mask)| mask.count_ones())
        {
            out.entry(dev.clone())
                .or_insert_with(|| format!("{a}/{}", mask.count_ones()));
        }
    }
    out
}

/// The preferred global IPv6 address per device, `addr/len`, from `proc/net/if_inet6`:
/// global scope, not tentative, deprecated or temporary; else any global one.
fn live_ipv6(root: &Path) -> HashMap<String, String> {
    const TEMPORARY: u32 = 0x01;
    const DEPRECATED: u32 = 0x20;
    const TENTATIVE: u32 = 0x40;
    let mut best: HashMap<String, (bool, String)> = HashMap::new();
    for line in read(root, "proc/net/if_inet6").unwrap_or_default().lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let [addr, _, plen, scope, flags, dev] = f[..] else {
            continue;
        };
        let (Ok(a), Ok(plen), Ok(scope), Ok(flags)) = (
            u128::from_str_radix(addr, 16).map(Ipv6Addr::from),
            u8::from_str_radix(plen, 16),
            u8::from_str_radix(scope, 16),
            u32::from_str_radix(flags, 16),
        ) else {
            continue;
        };
        if scope != 0 {
            continue;
        }
        let preferred = flags & (TEMPORARY | DEPRECATED | TENTATIVE) == 0;
        let slot = best.entry(dev.to_owned()).or_insert((false, String::new()));
        if slot.1.is_empty() || (preferred && !slot.0) {
            *slot = (preferred, format!("{a}/{plen}"));
        }
    }
    best.into_iter().map(|(d, (_, a))| (d, a)).collect()
}

impl Sampler {
    /// A sampler reading `<root>/proc` and `<root>/sys` (tests point it at a fixture tree).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            state: Mutex::new(State::default()),
        }
    }

    /// Current status. Interface names and devices come from `doc` (the sensr-schema
    /// document); counters, link state and addresses from the kernel, falling back to the
    /// configured address for a link that holds none.
    pub fn sample(&self, doc: &Value, version: &str) -> SystemStatus {
        let root = self.root.as_path();
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        let cpu_pct =
            read(root, "proc/stat")
                .and_then(|s| cpu_times(&s))
                .map_or(0.0, |(busy, total)| {
                    let pct = match st.cpu {
                        Some((b0, t0)) if total > t0 => {
                            (busy - b0) as f64 / (total - t0) as f64 * 100.0
                        }
                        _ => 0.0,
                    };
                    st.cpu = Some((busy, total));
                    pct as f32
                });
        let mem = read(root, "proc/meminfo").unwrap_or_default();
        let mem_total = meminfo(&mem, "MemTotal").unwrap_or(0);
        let mem_used = mem_total.saturating_sub(meminfo(&mem, "MemAvailable").unwrap_or(mem_total));
        let load = read(root, "proc/loadavg")
            .map(|s| {
                let v: Vec<f32> = s
                    .split_whitespace()
                    .take(3)
                    .filter_map(|x| x.parse().ok())
                    .collect();
                [
                    v.first().copied().unwrap_or(0.0),
                    v.get(1).copied().unwrap_or(0.0),
                    v.get(2).copied().unwrap_or(0.0),
                ]
            })
            .unwrap_or_default();
        let uptime_secs = read(root, "proc/uptime")
            .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
            .map_or(0, |f| f as u64);
        let cpu_model = read(root, "proc/cpuinfo")
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("model name") || l.starts_with("Model"))
                    .and_then(|l| l.split_once(':'))
                    .map(|(_, v)| v.trim().to_owned())
            })
            .unwrap_or_default();
        let cores = read(root, "proc/cpuinfo").map_or(0, |s| {
            s.lines().filter(|l| l.starts_with("processor")).count()
        });
        let kernel = read(root, "proc/sys/kernel/osrelease")
            .map_or_else(String::new, |k| format!("Linux {}", k.trim()));

        let text = |v: &Value, p: &str| {
            get_path(v, p)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let (live4, live6) = (live_ipv4(root), live_ipv6(root));
        let mut interfaces = Vec::new();
        let mut traffic = Vec::new();
        for (id, iface) in get_path(doc, "interfaces")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            let dev = text(iface, "device");
            let name = match text(iface, "description") {
                d if d.is_empty() => id.to_uppercase(),
                d => d,
            };
            let base = format!("sys/class/net/{dev}");
            let up = read(root, &format!("{base}/operstate")).is_some_and(|s| s.trim() == "up");
            let speed = read_u64(root, &format!("{base}/speed"))
                .and_then(|s| u32::try_from(s).ok())
                .filter(|s| *s > 0);
            let rx = read_u64(root, &format!("{base}/statistics/rx_bytes")).unwrap_or(0);
            let tx = read_u64(root, &format!("{base}/statistics/tx_bytes")).unwrap_or(0);
            let (rx_bps, tx_bps) = match st.net.insert(dev.clone(), (now, rx, tx)) {
                Some((t0, r0, x0)) => {
                    let dt = now.duration_since(t0).as_secs_f64().max(0.001);
                    (
                        ((rx.saturating_sub(r0)) as f64 * 8.0 / dt) as u64,
                        ((tx.saturating_sub(x0)) as f64 * 8.0 / dt) as u64,
                    )
                }
                None => (0, 0),
            };
            let hist = st.traffic.entry(dev.clone()).or_default();
            hist.push_back((rx_bps, tx_bps));
            while hist.len() > KEEP {
                hist.pop_front();
            }
            traffic.push(TrafficSeries {
                name: name.clone(),
                rx: hist.iter().map(|(r, _)| *r).collect(),
                tx: hist.iter().map(|(_, t)| *t).collect(),
            });
            let addr = |p: &str| Some(text(iface, p)).filter(|a| !a.is_empty());
            let ipv4 = live4.get(&dev).cloned().or_else(|| addr("ipv4.address"));
            let ipv6 = live6.get(&dev).cloned().or_else(|| addr("ipv6.address"));
            interfaces.push(InterfaceStatus {
                name,
                device: dev,
                up,
                speed_mbps: speed,
                ipv4,
                ipv6,
                rx_bps,
                tx_bps,
            });
        }

        SystemStatus {
            hostname: format!(
                "{}.{}",
                text(doc, "system.hostname"),
                text(doc, "system.domain")
            ),
            version: version.to_owned(),
            kernel,
            cpu_model: if cores > 0 {
                format!("{cpu_model} ({cores} cores)")
            } else {
                cpu_model
            },
            uptime_secs,
            cpu_pct,
            load,
            mem_used,
            mem_total,
            interfaces,
            gateways: Vec::new(),
            traffic,
            history: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(dir: &Path, rx: u64) {
        let w = |rel: &str, body: &str| {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        w(
            "proc/stat",
            "cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 1 1 1\n",
        );
        w(
            "proc/meminfo",
            "MemTotal:        8000000 kB\nMemFree: 1 kB\nMemAvailable:    6000000 kB\n",
        );
        w("proc/loadavg", "0.50 0.40 0.30 1/200 1234\n");
        w("proc/uptime", "3600.5 7000.0\n");
        w(
            "proc/cpuinfo",
            "processor\t: 0\nmodel name\t: Test CPU\nprocessor\t: 1\nmodel name\t: Test CPU\n",
        );
        w("proc/sys/kernel/osrelease", "6.18.4\n");
        w("sys/class/net/eth1/operstate", "up\n");
        w("sys/class/net/eth1/speed", "1000\n");
        w("sys/class/net/eth1/statistics/rx_bytes", &format!("{rx}\n"));
        w("sys/class/net/eth1/statistics/tx_bytes", "0\n");
    }

    /// Live addresses as the kernel reports them: the DHCP WAN `eth0` holds
    /// 203.0.113.45/22 (fib_trie + route) and a global v6 next to a deprecated one;
    /// the LAN `eth1` holds its static 192.168.1.1/24.
    fn live_addr_fixture(dir: &Path) {
        let w = |rel: &str, body: &str| {
            let p = dir.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        w(
            "proc/net/fib_trie",
            "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\n     +-- 127.0.0.0/8 2 0 2\n        |-- 127.0.0.1\n           /32 host LOCAL\n     +-- 192.168.1.0/24 2 0 2\n        |-- 192.168.1.0\n           /24 link UNICAST\n        |-- 192.168.1.1\n           /32 host LOCAL\n     +-- 203.0.112.0/22 2 0 2\n        |-- 203.0.112.0\n           /22 link UNICAST\n        |-- 203.0.113.45\n           /32 host LOCAL\nLocal:\n  +-- 0.0.0.0/0 3 0 5\n        |-- 203.0.113.45\n           /32 host LOCAL\n",
        );
        // Destination/Gateway/Mask are little-endian hex, as on the Pi and x86.
        w(
            "proc/net/route",
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t017000CB\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t007000CB\t00000000\t0001\t0\t0\t100\t00FCFFFF\t0\t0\t0\n\
eth1\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
        );
        w(
            "proc/net/if_inet6",
            "20010db8000000010000000000000099 02 40 00 20     eth0\n\
20010db8000000010000000000000045 02 40 00 00     eth0\n\
fe800000000000000000000000000045 02 40 20 80     eth0\n\
00000000000000000000000000000001 01 80 10 80       lo\n",
        );
        w("sys/class/net/eth0/operstate", "up\n");
    }

    #[test]
    fn dhcp_wan_shows_the_address_it_holds() {
        let dir =
            std::env::temp_dir().join(format!("sensr-ui-hoststats-live-{}", std::process::id()));
        fixture(&dir, 1_000);
        live_addr_fixture(&dir);
        let doc = json!({
            "system": {"hostname": "fw", "domain": "example.org"},
            "interfaces": {
                "wan": {"device": "eth0", "description": "WAN", "ipv4": {"mode": "dhcp"}, "ipv6": {"mode": "dhcp6"}},
                "lan": {"device": "eth1", "description": "LAN", "ipv4": {"mode": "static", "address": "192.168.1.1/24"}},
                "opt1": {"device": "eth9", "description": "SPARE", "ipv4": {"mode": "static", "address": "10.0.0.1/24"}}
            }
        });
        let s = Sampler::new(&dir);
        let st = s.sample(&doc, "test");
        let by = |n: &str| st.interfaces.iter().find(|i| i.name == n).unwrap();
        assert_eq!(by("WAN").ipv4.as_deref(), Some("203.0.113.45/22"));
        assert_eq!(
            by("WAN").ipv6.as_deref(),
            Some("2001:db8:0:1::45/64"),
            "skips deprecated and link-local"
        );
        assert_eq!(by("LAN").ipv4.as_deref(), Some("192.168.1.1/24"));
        assert_eq!(
            by("SPARE").ipv4.as_deref(),
            Some("10.0.0.1/24"),
            "a device without a live address falls back to its configured one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_procfs_and_sysfs() {
        let dir = std::env::temp_dir().join(format!("sensr-ui-hoststats-{}", std::process::id()));
        fixture(&dir, 1_000);
        let doc = json!({
            "system": {"hostname": "fw", "domain": "example.org"},
            "interfaces": {"lan": {"device": "eth1", "description": "LAN", "ipv4": {"mode": "static", "address": "192.168.1.1/24"}}}
        });
        let s = Sampler::new(&dir);
        let a = s.sample(&doc, "test");
        assert_eq!(a.hostname, "fw.example.org");
        assert_eq!(a.kernel, "Linux 6.18.4");
        assert_eq!(a.cpu_model, "Test CPU (2 cores)");
        assert_eq!((a.mem_total, a.mem_used), (8_192_000_000, 2_048_000_000));
        assert_eq!(a.uptime_secs, 3600);
        assert_eq!(a.load, [0.5, 0.4, 0.3]);
        assert!(a.interfaces[0].up);
        assert_eq!(a.interfaces[0].speed_mbps, Some(1000));
        assert_eq!(a.interfaces[0].ipv4.as_deref(), Some("192.168.1.1/24"));
        assert_eq!(a.interfaces[0].rx_bps, 0, "first sample has no rate yet");
        fixture(&dir, 2_000);
        let b = s.sample(&doc, "test");
        assert!(b.interfaces[0].rx_bps > 0);
        assert_eq!(b.traffic[0].rx.len(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cpu_counts_iowait_as_idle() {
        assert_eq!(
            cpu_times("cpu  100 0 100 700 100 0 0 0\n"),
            Some((200, 1000))
        );
    }
}
