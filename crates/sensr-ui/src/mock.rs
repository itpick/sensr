//! In-memory [`Backend`] with a realistic small-office config, used by the dev server and the
//! tests until sensr-api's routes land.

use crate::api::*;
use crate::form::{get_path, set_path};
use futures::future::{BoxFuture, FutureExt};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

struct Commit {
    rev: Revision,
    doc: Value,
}

struct State {
    history: Vec<Commit>,
    staged: Value,
    confirm: Option<ConfirmWindow>,
    /// Revision to return to if the confirm window lapses.
    confirm_fallback: Option<u64>,
    sessions: HashMap<String, String>,
    next_token: u64,
    clock: Box<dyn Fn() -> u64 + Send>,
}

impl State {
    fn head(&self) -> &Commit {
        self.history.last().expect("history is never empty")
    }

    /// Lapses an expired confirm window: the box rolls back on its own.
    fn tick(&mut self) {
        if let (Some(w), Some(back)) = (&self.confirm, self.confirm_fallback)
            && (self.clock)() >= w.deadline
        {
            let doc = self.doc_at(back).cloned().unwrap_or(Value::Null);
            self.confirm = None;
            self.confirm_fallback = None;
            self.push(
                "system",
                &format!("Automatic rollback to revision {back}: change not confirmed in time"),
                doc,
            );
        }
    }

    fn doc_at(&self, id: u64) -> Option<&Value> {
        self.history.iter().find(|c| c.rev.id == id).map(|c| &c.doc)
    }

    fn push(&mut self, user: &str, message: &str, doc: Value) -> Revision {
        let rev = Revision {
            id: self.head().rev.id + 1,
            time: (self.clock)(),
            user: user.to_owned(),
            message: message.to_owned(),
        };
        self.staged = doc.clone();
        self.history.push(Commit {
            rev: rev.clone(),
            doc,
        });
        rev
    }

    fn changed(&self) -> Vec<String> {
        let head = &self.head().doc;
        let mut keys: Vec<String> = match (&self.staged, head) {
            (Value::Object(a), Value::Object(b)) => a
                .keys()
                .chain(b.keys())
                .filter(|k| a.get(*k) != b.get(*k))
                .cloned()
                .collect(),
            _ => vec![],
        };
        keys.sort();
        keys.dedup();
        keys
    }
}

/// The mock backend.
pub struct MockBackend {
    state: Mutex<State>,
    /// Accepted credentials.
    users: Vec<(String, String)>,
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockBackend {
    /// A mock seeded with [`seed`] and the user `root` / `sensr`.
    pub fn new() -> Self {
        Self::with_clock(Box::new(now))
    }

    /// Like [`MockBackend::new`] with an injectable clock (seconds since the epoch).
    pub fn with_clock(clock: Box<dyn Fn() -> u64 + Send>) -> Self {
        let t = clock();
        let doc = seed();
        let first = Commit {
            rev: Revision {
                id: 1,
                time: t.saturating_sub(86_400 * 3),
                user: "root".into(),
                message: "Imported config.xml from OPNsense 26.1".into(),
            },
            doc: doc.clone(),
        };
        let mut second_doc = doc.clone();
        set_path(
            &mut second_doc,
            "system.general.timezone",
            json!("Europe/Amsterdam"),
        );
        let second = Commit {
            rev: Revision {
                id: 2,
                time: t.saturating_sub(3_600 * 5),
                user: "root".into(),
                message: "System › Settings › General: timezone".into(),
            },
            doc: second_doc.clone(),
        };
        Self {
            state: Mutex::new(State {
                history: vec![first, second],
                staged: second_doc,
                confirm: None,
                confirm_fallback: None,
                sessions: HashMap::new(),
                next_token: 1,
                clock,
            }),
            users: vec![("root".into(), "sensr".into())],
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut State) -> R) -> R {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.tick();
        f(&mut s)
    }
}

fn ready<'a, T: Send + 'a>(v: T) -> BoxFuture<'a, T> {
    futures::future::ready(v).boxed()
}

fn diff_lines(a: &Value, b: &Value) -> Vec<DiffLine> {
    let a = serde_json::to_string_pretty(a).unwrap_or_default();
    let b = serde_json::to_string_pretty(b).unwrap_or_default();
    let diff = similar::TextDiff::from_lines(&a, &b);
    let mut out = Vec::new();
    for group in diff.grouped_ops(3) {
        if !out.is_empty() {
            out.push(DiffLine {
                kind: DiffKind::Context,
                text: "…".into(),
            });
        }
        for op in group {
            for change in diff.iter_changes(&op) {
                let kind = match change.tag() {
                    similar::ChangeTag::Equal => DiffKind::Context,
                    similar::ChangeTag::Insert => DiffKind::Added,
                    similar::ChangeTag::Delete => DiffKind::Removed,
                };
                out.push(DiffLine {
                    kind,
                    text: change.value().trim_end_matches('\n').to_owned(),
                });
            }
        }
    }
    out
}

impl Backend for MockBackend {
    fn get<'a>(&'a self, path: &'a str) -> BoxFuture<'a, ApiResult<Value>> {
        ready(self.with(|s| {
            if path.is_empty() {
                return Ok(s.staged.clone());
            }
            Ok(get_path(&s.staged, path).cloned().unwrap_or(Value::Null))
        }))
    }

    fn set<'a>(&'a self, path: &'a str, value: Value) -> BoxFuture<'a, ApiResult<()>> {
        ready(self.with(|s| {
            if path.is_empty() {
                return Err(ApiError::Conflict(
                    "refusing to replace the whole document".into(),
                ));
            }
            set_path(&mut s.staged, path, value);
            Ok(())
        }))
    }

    fn pending(&self) -> BoxFuture<'_, ApiResult<Pending>> {
        ready(self.with(|s| {
            Ok(Pending {
                changed: s.changed(),
                confirm: s.confirm.clone(),
                now: (s.clock)(),
            })
        }))
    }

    fn commit<'a>(
        &'a self,
        user: &'a str,
        message: &'a str,
        confirm_secs: Option<u32>,
    ) -> BoxFuture<'a, ApiResult<Revision>> {
        ready(self.with(|s| {
            if s.changed().is_empty() {
                return Err(ApiError::Conflict("nothing to apply".into()));
            }
            let before = s.head().rev.id;
            let message = if message.is_empty() {
                s.changed().join(", ")
            } else {
                message.to_owned()
            };
            let doc = s.staged.clone();
            let rev = s.push(user, &message, doc);
            match confirm_secs {
                Some(secs) => {
                    s.confirm = Some(ConfirmWindow {
                        revision: rev.id,
                        deadline: (s.clock)() + u64::from(secs),
                    });
                    s.confirm_fallback = Some(before);
                }
                None => {
                    s.confirm = None;
                    s.confirm_fallback = None;
                }
            }
            Ok(rev)
        }))
    }

    fn confirm(&self) -> BoxFuture<'_, ApiResult<()>> {
        ready(self.with(|s| {
            if s.confirm.take().is_none() {
                return Err(ApiError::Conflict("no change awaits confirmation".into()));
            }
            s.confirm_fallback = None;
            Ok(())
        }))
    }

    fn discard(&self) -> BoxFuture<'_, ApiResult<()>> {
        ready(self.with(|s| {
            s.staged = s.head().doc.clone();
            Ok(())
        }))
    }

    fn rollback<'a>(&'a self, user: &'a str, to: u64) -> BoxFuture<'a, ApiResult<Revision>> {
        ready(self.with(|s| {
            let doc = s
                .doc_at(to)
                .cloned()
                .ok_or_else(|| ApiError::NotFound(format!("revision {to}")))?;
            s.confirm = None;
            s.confirm_fallback = None;
            Ok(s.push(user, &format!("Rollback to revision {to}"), doc))
        }))
    }

    fn history(&self) -> BoxFuture<'_, ApiResult<Vec<Revision>>> {
        ready(self.with(|s| Ok(s.history.iter().rev().map(|c| c.rev.clone()).collect())))
    }

    fn diff(&self, from: u64, to: Option<u64>) -> BoxFuture<'_, ApiResult<Vec<DiffLine>>> {
        ready(self.with(|s| {
            let a = s
                .doc_at(from)
                .ok_or_else(|| ApiError::NotFound(format!("revision {from}")))?;
            let b = match to {
                Some(t) => s
                    .doc_at(t)
                    .ok_or_else(|| ApiError::NotFound(format!("revision {t}")))?,
                None => &s.staged,
            };
            Ok(diff_lines(a, b))
        }))
    }

    fn status(&self) -> BoxFuture<'_, ApiResult<SystemStatus>> {
        ready(self.with(|s| Ok(simulated_status(&s.staged, (s.clock)()))))
    }

    fn login<'a>(&'a self, user: &'a str, password: &'a str) -> BoxFuture<'a, ApiResult<String>> {
        let ok = self.users.iter().any(|(u, p)| u == user && p == password);
        ready(self.with(|s| {
            if !ok {
                return Err(ApiError::Unauthorized);
            }
            let token = format!(
                "mock-{}-{:x}",
                s.next_token,
                (s.clock)().wrapping_mul(2_654_435_761)
            );
            s.next_token += 1;
            s.sessions.insert(token.clone(), user.to_owned());
            Ok(token)
        }))
    }

    fn session<'a>(&'a self, token: &'a str) -> BoxFuture<'a, ApiResult<Option<String>>> {
        ready(self.with(|s| Ok(s.sessions.get(token).cloned())))
    }

    fn logout<'a>(&'a self, token: &'a str) -> BoxFuture<'a, ApiResult<()>> {
        ready(self.with(|s| {
            s.sessions.remove(token);
            Ok(())
        }))
    }
}

/// Smooth, deterministic pseudo-load so screenshots are stable within a minute.
fn wave(t: u64, period: u64, phase: u64) -> f64 {
    let x = ((t + phase) % period) as f64 / period as f64 * std::f64::consts::TAU;
    (x.sin() + 1.0) / 2.0
}

fn simulated_status(doc: &Value, t: u64) -> SystemStatus {
    let hostname = format!(
        "{}.{}",
        get_path(doc, "system.general.hostname")
            .and_then(Value::as_str)
            .unwrap_or("sensr"),
        get_path(doc, "system.general.domain")
            .and_then(Value::as_str)
            .unwrap_or("internal"),
    );
    let ifaces = doc
        .get("interfaces")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let interfaces: Vec<InterfaceStatus> = ifaces
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let s = |k: &str| {
                v.get(k)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let phase = i as u64 * 17;
            let scale = if s("id") == "wan" { 180e6 } else { 60e6 };
            InterfaceStatus {
                name: s("description"),
                device: s("device"),
                up: v.get("enabled").and_then(Value::as_bool).unwrap_or(false),
                speed_mbps: Some(if s("device") == "wg0" { 0 } else { 1000 }).filter(|n| *n > 0),
                ipv4: Some(s("ipv4_address"))
                    .filter(|a| !a.is_empty())
                    .or_else(|| (s("ipv4_type") == "dhcp").then(|| "203.0.113.24/24".to_owned())),
                ipv6: Some(s("ipv6_address"))
                    .filter(|a| !a.is_empty())
                    .or_else(|| {
                        (s("ipv6_type") == "dhcp6").then(|| "2001:db8:42::1/64".to_owned())
                    }),
                rx_bps: (wave(t, 60, phase) * scale) as u64,
                tx_bps: (wave(t, 45, phase + 9) * scale * 0.3) as u64,
            }
        })
        .collect();
    let traffic = interfaces
        .iter()
        .enumerate()
        .filter(|(_, i)| i.up)
        .map(|(i, iface)| {
            let phase = i as u64 * 17;
            let scale = if iface.name == "WAN" { 180e6 } else { 60e6 };
            // The newest sample equals the rate the interfaces table shows.
            let samples = |period, ph, k: f64| {
                (0..60u64)
                    .map(|s| (wave(t.saturating_sub(59 - s), period, ph) * scale * k) as u64)
                    .collect()
            };
            TrafficSeries {
                name: iface.name.clone(),
                rx: samples(60, phase, 1.0),
                tx: samples(45, phase + 9, 0.3),
            }
        })
        .collect();
    SystemStatus {
        hostname,
        version: concat!("sensr ", env!("CARGO_PKG_VERSION"), " (mock)").to_owned(),
        kernel: "Linux 6.18.4 (NixOS 26.05)".into(),
        cpu_model: "Intel(R) N100 (4 cores)".into(),
        uptime_secs: 3 * 86_400 + 4 * 3_600 + 12 * 60 + (t % 60),
        cpu_pct: (4.0 + wave(t, 30, 0) * 22.0) as f32,
        load: [0.42, 0.37, 0.31],
        mem_used: 1_310_000_000 + (wave(t, 90, 5) * 120_000_000.0) as u64,
        mem_total: 8_000_000_000,
        interfaces,
        gateways: vec![
            GatewayStatus {
                name: "WAN_DHCP".into(),
                interface: "WAN".into(),
                address: "203.0.113.1".into(),
                rtt_ms: (7.5 + wave(t, 20, 3) * 2.0) as f32,
                loss_pct: 0.0,
                health: GatewayHealth::Online,
            },
            GatewayStatus {
                name: "WAN_DHCP6".into(),
                interface: "WAN".into(),
                address: "fe80::1%eth0".into(),
                rtt_ms: (8.1 + wave(t, 25, 1) * 2.5) as f32,
                loss_pct: 0.0,
                health: GatewayHealth::Online,
            },
        ],
        traffic,
    }
}

/// The seeded document: a two-port router with WireGuard, as an imported OPNsense box looks.
pub fn seed() -> Value {
    json!({
        "system": {
            "general": {
                "hostname": "sensr",
                "domain": "home.arpa",
                "timezone": "Etc/UTC",
                "language": "en_US",
                "dns_servers": ["9.9.9.9", "2620:fe::fe"],
                "dns_allow_override": true,
                "dns_local_disabled": false
            }
        },
        "interfaces": [
            {"id": "wan", "device": "eth0", "description": "WAN", "enabled": true,
             "block_private": true, "block_bogons": true, "ipv4_type": "dhcp", "ipv4_address": "",
             "ipv4_gateway": "", "ipv6_type": "dhcp6", "ipv6_address": "", "mtu": null},
            {"id": "lan", "device": "eth1", "description": "LAN", "enabled": true,
             "block_private": false, "block_bogons": false, "ipv4_type": "static",
             "ipv4_address": "192.168.1.1/24", "ipv4_gateway": "", "ipv6_type": "track6",
             "ipv6_address": "", "mtu": null},
            {"id": "opt1", "device": "wg0", "description": "WireGuard", "enabled": true,
             "block_private": false, "block_bogons": false, "ipv4_type": "static",
             "ipv4_address": "10.10.0.1/24", "ipv4_gateway": "", "ipv6_type": "none",
             "ipv6_address": "", "mtu": 1420}
        ],
        "firewall": {
            "alias": [
                {"uuid": "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a01", "enabled": true, "name": "rfc1918", "type": "network",
                 "content": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"], "description": "Private networks"},
                {"uuid": "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a02", "enabled": true, "name": "web_ports", "type": "port",
                 "content": ["80", "443", "8080:8090"], "description": "HTTP(S)"},
                {"uuid": "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a03", "enabled": true, "name": "nas", "type": "host",
                 "content": ["192.168.1.20"], "description": "File server"},
                {"uuid": "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a04", "enabled": false, "name": "spamhaus_drop", "type": "urltable",
                 "content": ["https://www.spamhaus.org/drop/drop.txt"], "description": "Spamhaus DROP"},
                {"uuid": "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a05", "enabled": true, "name": "admins", "type": "host",
                 "content": ["192.168.1.10", "192.168.1.11"], "description": "Admin workstations"}
            ],
            "filter": [
                {"uuid": "a1e1c6f0-1d6e-4b1e-8f00-000000000001", "enabled": true, "action": "pass", "quick": true,
                 "interface": "lan", "direction": "in", "ipprotocol": "inet", "protocol": "any",
                 "source": "lan net", "source_port": "", "destination": "any", "destination_port": "",
                 "log": false, "description": "Default allow LAN to any rule"},
                {"uuid": "a1e1c6f0-1d6e-4b1e-8f00-000000000002", "enabled": true, "action": "pass", "quick": true,
                 "interface": "lan", "direction": "in", "ipprotocol": "inet6", "protocol": "any",
                 "source": "lan net", "source_port": "", "destination": "any", "destination_port": "",
                 "log": false, "description": "Default allow LAN IPv6 to any rule"},
                {"uuid": "a1e1c6f0-1d6e-4b1e-8f00-000000000003", "enabled": true, "action": "block", "quick": true,
                 "interface": "lan", "direction": "in", "ipprotocol": "inet", "protocol": "TCP",
                 "source": "lan net", "source_port": "", "destination": "any", "destination_port": "25",
                 "log": true, "description": "No direct SMTP"},
                {"uuid": "a1e1c6f0-1d6e-4b1e-8f00-000000000004", "enabled": true, "action": "pass", "quick": true,
                 "interface": "wan", "direction": "in", "ipprotocol": "inet", "protocol": "UDP",
                 "source": "any", "source_port": "", "destination": "wanip", "destination_port": "51820",
                 "log": false, "description": "WireGuard"},
                {"uuid": "a1e1c6f0-1d6e-4b1e-8f00-000000000005", "enabled": true, "action": "pass", "quick": true,
                 "interface": "wan", "direction": "in", "ipprotocol": "inet", "protocol": "TCP",
                 "source": "any", "source_port": "", "destination": "nas", "destination_port": "web_ports",
                 "log": false, "description": "NAT: web to NAS"},
                {"uuid": "a1e1c6f0-1d6e-4b1e-8f00-000000000006", "enabled": true, "action": "pass", "quick": true,
                 "interface": "wg0", "direction": "in", "ipprotocol": "inet", "protocol": "any",
                 "source": "10.10.0.0/24", "source_port": "", "destination": "rfc1918", "destination_port": "",
                 "log": false, "description": "Road warriors to LAN"},
                {"uuid": "a1e1c6f0-1d6e-4b1e-8f00-000000000007", "enabled": false, "action": "block", "quick": false,
                 "interface": "floating", "direction": "in", "ipprotocol": "inet46", "protocol": "any",
                 "source": "spamhaus_drop", "source_port": "", "destination": "any", "destination_port": "",
                 "log": true, "description": "Drop listed networks"}
            ]
        },
        "nat": {
            "source": {
                "settings": {"mode": "hybrid"},
                "rules": [
                    {"uuid": "c0ffee00-0000-4000-a000-000000000001", "enabled": true, "nonat": false, "interface": "wan",
                     "protocol": "any", "source": "10.10.0.0/24", "destination": "any", "target": "wanip",
                     "description": "WireGuard clients out"}
                ]
            },
            "destination": [
                {"uuid": "d0d0d0d0-0000-4000-a000-000000000001", "enabled": true, "interface": "wan", "protocol": "TCP",
                 "destination": "wanip", "destination_port": "443", "target": "192.168.1.20", "target_port": "443",
                 "description": "NAS HTTPS"},
                {"uuid": "d0d0d0d0-0000-4000-a000-000000000002", "enabled": false, "interface": "wan", "protocol": "TCP/UDP",
                 "destination": "wanip", "destination_port": "25565", "target": "192.168.1.30", "target_port": "",
                 "description": "Game server"}
            ]
        },
        "dhcpd": {
            "lan": {
                "settings": {"enabled": true, "range_from": "192.168.1.100", "range_to": "192.168.1.199",
                             "dns_servers": [], "gateway": "", "domain": "home.arpa", "default_lease": 7200,
                             "max_lease": 86400, "register_dns": true},
                "ranges": [
                    {"uuid": "e0000000-0000-4000-a000-000000000001", "enabled": true, "from": "192.168.1.220",
                     "to": "192.168.1.239", "description": "Guests"}
                ],
                "staticmaps": [
                    {"uuid": "f0000000-0000-4000-a000-000000000001", "mac": "52:54:00:aa:bb:01", "ipaddr": "192.168.1.20",
                     "hostname": "nas", "description": "File server"},
                    {"uuid": "f0000000-0000-4000-a000-000000000002", "mac": "52:54:00:aa:bb:02", "ipaddr": "192.168.1.21",
                     "hostname": "printer", "description": "Office printer"}
                ]
            }
        },
        "unbound": {
            "general": {"enabled": true, "port": 53, "interfaces": [], "dnssec": true,
                        "register_dhcp_leases": true, "register_dhcp_static": true,
                        "local_zone_type": "transparent"},
            "hosts": [
                {"uuid": "b0000000-0000-4000-a000-000000000001", "enabled": true, "hostname": "nas", "domain": "home.arpa",
                 "rr": "A", "server": "192.168.1.20", "mx": "", "mxprio": null, "description": "NAS"},
                {"uuid": "b0000000-0000-4000-a000-000000000002", "enabled": true, "hostname": "*", "domain": "lab.home.arpa",
                 "rr": "A", "server": "192.168.1.40", "mx": "", "mxprio": null, "description": "Lab wildcard"}
            ]
        },
        "wireguard": {
            "server": [
                {"uuid": "90000000-0000-4000-a000-000000000001", "enabled": true, "name": "wg0",
                 "pubkey": "XkqVfAIvmIb6m1w8bQzYgX2WmAZgM1pQd1kR6m0Y6Ec=",
                 "privkey": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", "port": 51820, "mtu": 1420,
                 "tunneladdress": ["10.10.0.1/24"], "dns": [], "disableroutes": false}
            ],
            "client": [
                {"uuid": "91000000-0000-4000-a000-000000000001", "enabled": true, "name": "laptop",
                 "pubkey": "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=", "psk": "",
                 "tunneladdress": ["10.10.0.2/32"], "serveraddress": "", "serverport": null,
                 "servers": ["wg0"], "keepalive": 25},
                {"uuid": "91000000-0000-4000-a000-000000000002", "enabled": true, "name": "phone",
                 "pubkey": "gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA=", "psk": "",
                 "tunneladdress": ["10.10.0.3/32"], "serveraddress": "", "serverport": null,
                 "servers": ["wg0"], "keepalive": 25}
            ]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn block<T>(f: BoxFuture<'_, T>) -> T {
        futures::executor::block_on(f)
    }

    fn mock_with_clock() -> (MockBackend, Arc<AtomicU64>) {
        let t = Arc::new(AtomicU64::new(1_000_000));
        let c = t.clone();
        (
            MockBackend::with_clock(Box::new(move || c.load(Ordering::SeqCst))),
            t,
        )
    }

    #[test]
    fn set_stages_and_commit_applies() {
        let (m, _) = mock_with_clock();
        block(m.set("system.general.hostname", json!("fw"))).unwrap();
        assert_eq!(block(m.pending()).unwrap().changed, ["system"]);
        let rev = block(m.commit("root", "rename", None)).unwrap();
        assert_eq!(rev.id, 3);
        assert!(!block(m.pending()).unwrap().dirty());
        assert_eq!(
            block(m.get("system.general.hostname")).unwrap(),
            json!("fw")
        );
        let diff = block(m.diff(2, Some(3))).unwrap();
        assert!(
            diff.iter()
                .any(|l| l.kind == DiffKind::Added && l.text.contains("\"fw\""))
        );
        assert!(
            diff.iter()
                .any(|l| l.kind == DiffKind::Removed && l.text.contains("\"sensr\""))
        );
    }

    #[test]
    fn unconfirmed_commit_rolls_back_after_deadline() {
        let (m, t) = mock_with_clock();
        block(m.set("system.general.hostname", json!("fw"))).unwrap();
        block(m.commit("root", "risky", Some(60))).unwrap();
        assert!(block(m.pending()).unwrap().confirm.is_some());
        t.fetch_add(61, Ordering::SeqCst);
        let p = block(m.pending()).unwrap();
        assert!(p.confirm.is_none());
        assert_eq!(
            block(m.get("system.general.hostname")).unwrap(),
            json!("sensr")
        );
        assert!(
            block(m.history()).unwrap()[0]
                .message
                .starts_with("Automatic rollback")
        );
    }

    #[test]
    fn confirmed_commit_stays() {
        let (m, t) = mock_with_clock();
        block(m.set("system.general.hostname", json!("fw"))).unwrap();
        block(m.commit("root", "risky", Some(60))).unwrap();
        block(m.confirm()).unwrap();
        t.fetch_add(120, Ordering::SeqCst);
        assert_eq!(
            block(m.get("system.general.hostname")).unwrap(),
            json!("fw")
        );
        assert_eq!(
            block(m.confirm()),
            Err(ApiError::Conflict("no change awaits confirmation".into()))
        );
    }

    #[test]
    fn rollback_and_discard() {
        let (m, _) = mock_with_clock();
        let r = block(m.rollback("root", 1)).unwrap();
        assert_eq!(r.id, 3);
        assert_eq!(
            block(m.get("system.general.timezone")).unwrap(),
            json!("Etc/UTC")
        );
        block(m.set("system.general.timezone", json!("Asia/Tokyo"))).unwrap();
        block(m.discard()).unwrap();
        assert!(!block(m.pending()).unwrap().dirty());
        assert!(matches!(
            block(m.rollback("root", 99)),
            Err(ApiError::NotFound(_))
        ));
    }

    #[test]
    fn sessions() {
        let (m, _) = mock_with_clock();
        assert_eq!(block(m.login("root", "nope")), Err(ApiError::Unauthorized));
        let tok = block(m.login("root", "sensr")).unwrap();
        assert_eq!(block(m.session(&tok)).unwrap().as_deref(), Some("root"));
        block(m.logout(&tok)).unwrap();
        assert_eq!(block(m.session(&tok)).unwrap(), None);
    }

    #[test]
    fn seed_rows_parse_as_their_models() {
        use crate::models::*;
        let doc = seed();
        for g in [
            GridId::Assignments,
            GridId::Aliases,
            GridId::FilterRules,
            GridId::SourceNat,
            GridId::PortForwards,
            GridId::DhcpRanges,
            GridId::StaticMaps,
            GridId::HostOverrides,
            GridId::WgInstances,
            GridId::WgPeers,
        ] {
            let loc = g.location(&None);
            let rows = get_path(&doc, &loc.list)
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("{g:?}"));
            for row in rows {
                let inputs = crate::form::to_inputs(g.meta().fields, row);
                g.apply(row, &inputs)
                    .unwrap_or_else(|e| panic!("{g:?} {row}: {e:?}"));
            }
        }
        for f in [
            FormId::SystemGeneral,
            FormId::SourceNatMode,
            FormId::DhcpSettings,
            FormId::UnboundGeneral,
        ] {
            let Location::Path(p) = f.location(&None) else {
                unreachable!()
            };
            let v = get_path(&doc, &p).unwrap();
            f.apply(v, &crate::form::to_inputs(f.fields(), v))
                .unwrap_or_else(|e| panic!("{f:?}: {e:?}"));
        }
    }

    #[test]
    fn status_reflects_config() {
        let (m, _) = mock_with_clock();
        let s = block(m.status()).unwrap();
        assert_eq!(s.hostname, "sensr.home.arpa");
        assert_eq!(s.interfaces.len(), 3);
        assert_eq!(s.traffic[0].rx.len(), 60);
    }
}
