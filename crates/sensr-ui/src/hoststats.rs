//! Live host figures for the dashboard, read from procfs and sysfs (no privileges needed).
//!
//! CPU usage and interface rates are deltas between calls, so a [`Sampler`] keeps the
//! previous counters and the last two minutes of traffic per device.

use crate::api::{InterfaceStatus, SystemStatus, TrafficSeries};
use crate::form::get_path;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
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

impl Sampler {
    /// A sampler reading `<root>/proc` and `<root>/sys` (tests point it at a fixture tree).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            state: Mutex::new(State::default()),
        }
    }

    /// Current status. Interface names, devices and configured addresses come from `doc`
    /// (the sensr-schema document); counters and link state from the kernel.
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
            interfaces.push(InterfaceStatus {
                name,
                device: dev,
                up,
                speed_mbps: speed,
                ipv4: addr("ipv4.address"),
                ipv6: addr("ipv6.address"),
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
