//! In-memory [`Backend`] with a realistic small-office config, used by the dev server and the
//! tests until sensr-api's routes land.

use crate::adapt::REDACTED;
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
            "system.timezone",
            json!("Europe/Amsterdam"),
        );
        let second = Commit {
            rev: Revision {
                id: 2,
                time: t.saturating_sub(3_600 * 5),
                user: "root".into(),
                message: "system".into(),
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
            let mut v = if path.is_empty() {
                s.staged.clone()
            } else {
                get_path(&s.staged, path).cloned().unwrap_or(Value::Null)
            };
            redact(&mut v);
            Ok(v)
        }))
    }

    fn set<'a>(&'a self, path: &'a str, value: Value) -> BoxFuture<'a, ApiResult<()>> {
        ready(self.with(|s| {
            if path.is_empty() {
                return Err(ApiError::Conflict(
                    "refusing to replace the whole document".into(),
                ));
            }
            let mut value = value;
            if let Some(old) = get_path(&s.staged, path) {
                unredact(&mut value, old);
            }
            let mut candidate = s.staged.clone();
            set_path(&mut candidate, path, value);
            validate(&candidate).map_err(ApiError::Validation)?;
            s.staged = candidate;
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
}

/// Sessions over a shared [`MockBackend`]; every session edits the same document.
pub struct MockSessions(pub std::sync::Arc<MockBackend>);

impl Sessions for MockSessions {
    fn login<'a>(&'a self, user: &'a str, password: &'a str) -> BoxFuture<'a, ApiResult<String>> {
        let ok = self.0.users.iter().any(|(u, p)| u == user && p == password);
        ready(self.0.with(|s| {
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

    fn open<'a>(&'a self, token: &'a str) -> BoxFuture<'a, Option<Session>> {
        let user = self.0.with(|s| s.sessions.get(token).cloned());
        ready(user.map(|user| Session {
            user,
            backend: self.0.clone(),
        }))
    }

    fn logout<'a>(&'a self, token: &'a str) -> BoxFuture<'a, ()> {
        self.0.with(|s| s.sessions.remove(token));
        ready(())
    }
}

/// Smooth, deterministic pseudo-load so screenshots are stable within a minute.
fn wave(t: u64, period: u64, phase: u64) -> f64 {
    let x = ((t + phase) % period) as f64 / period as f64 * std::f64::consts::TAU;
    (x.sin() + 1.0) / 2.0
}

fn simulated_status(doc: &Value, t: u64) -> SystemStatus {
    let text = |p: &str, d: &str| {
        get_path(doc, p)
            .and_then(Value::as_str)
            .unwrap_or(d)
            .to_owned()
    };
    let hostname = format!(
        "{}.{}",
        text("system.hostname", "sensr"),
        text("system.domain", "internal")
    );
    let ifaces: Vec<(String, Value)> = doc
        .get("interfaces")
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    let interfaces: Vec<InterfaceStatus> = ifaces
        .iter()
        .enumerate()
        .map(|(i, (id, v))| {
            let s = |k: &str| {
                get_path(v, k)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let phase = i as u64 * 17;
            let scale = if id == "wan" { 180e6 } else { 60e6 };
            InterfaceStatus {
                name: if s("description").is_empty() {
                    id.to_uppercase()
                } else {
                    s("description")
                },
                device: s("device"),
                up: v.get("enabled").and_then(Value::as_bool).unwrap_or(true),
                speed_mbps: (!s("device").starts_with("wg")).then_some(1000),
                ipv4: match s("ipv4.mode").as_str() {
                    "static" => Some(s("ipv4.address")),
                    "dhcp" => Some("203.0.113.24/24".to_owned()),
                    _ => None,
                },
                ipv6: match s("ipv6.mode").as_str() {
                    "static" => Some(s("ipv6.address")),
                    "dhcp6" => Some("2001:db8:42::1/64".to_owned()),
                    "track" => Some("2001:db8:42:1::1/64".to_owned()),
                    _ => None,
                },
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

/// The seeded document (sensr-schema shape): the factory default plus aliases, rules, NAT,
/// DHCP reservations, host overrides and a WireGuard road-warrior setup.
pub fn seed() -> Value {
    json!({
        "schema_version": "0.1.0",
        "system": {
            "hostname": "sensr",
            "domain": "home.arpa",
            "dns_servers": ["9.9.9.9", "2620:fe::fe"],
            "dns_allow_override": true,
            "timezone": "Etc/UTC",
            "ipv6_allow": true
        },
        "interfaces": {
            "wan": {"enabled": true, "role": "wan", "description": "WAN", "device": "eth0",
                    "ipv4": {"mode": "dhcp"}, "ipv6": {"mode": "dhcp6", "prefix_delegation_len": 64},
                    "block_private": true, "block_bogons": true},
            "lan": {"enabled": true, "role": "lan", "description": "LAN", "device": "eth1",
                    "ipv4": {"mode": "static", "address": "192.168.1.1/24"},
                    "ipv6": {"mode": "track", "interface": "wan"}},
            "opt1": {"enabled": true, "role": "other", "description": "WireGuard", "device": "wg0", "mtu": 1420,
                     "ipv4": {"mode": "static", "address": "10.10.0.1/24"}, "ipv6": {"mode": "none"}}
        },
        "firewall": {
            "aliases": {
                "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a01": {"enabled": true, "name": "rfc1918",
                    "content": {"type": "network", "entries": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]},
                    "description": "Private networks"},
                "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a02": {"enabled": true, "name": "web_ports",
                    "content": {"type": "port", "entries": ["80", "443", "8080-8090"]}, "description": "HTTP(S)"},
                "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a03": {"enabled": true, "name": "nas",
                    "content": {"type": "host", "entries": ["192.168.1.20"]}, "description": "File server"},
                "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a04": {"enabled": false, "name": "spamhaus_drop",
                    "content": {"type": "url_table", "url": "https://www.spamhaus.org/drop/drop.txt"},
                    "description": "Spamhaus DROP"},
                "6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8a05": {"enabled": true, "name": "admins",
                    "content": {"type": "host", "entries": ["192.168.1.10", "192.168.1.11"]},
                    "description": "Admin workstations"}
            },
            "rules": {
                "00000000-0000-0000-0000-00005e450001": {"sequence": 1, "action": "pass", "interfaces": ["lan"],
                    "ip_protocol": "inet", "source": {"net": "net:lan"}, "description": "Default allow LAN to any rule"},
                "00000000-0000-0000-0000-00005e450002": {"sequence": 11, "action": "pass", "interfaces": ["lan"],
                    "ip_protocol": "inet6", "source": {"net": "net:lan"}, "description": "Default allow LAN IPv6 to any rule"},
                "a1e1c6f0-1d6e-4b1e-8f00-000000000003": {"sequence": 21, "action": "block", "interfaces": ["lan"],
                    "protocol": "tcp", "source": {"net": "net:lan"}, "destination": {"net": "any", "port": "25"},
                    "log": true, "description": "No direct SMTP"},
                "a1e1c6f0-1d6e-4b1e-8f00-000000000004": {"sequence": 31, "action": "pass", "interfaces": ["wan"],
                    "protocol": "udp", "destination": {"net": "addr:wan", "port": "51820"}, "description": "WireGuard"},
                "a1e1c6f0-1d6e-4b1e-8f00-000000000005": {"sequence": 41, "action": "pass", "interfaces": ["wan"],
                    "protocol": "tcp", "destination": {"net": "alias:nas", "port": "alias:web_ports"},
                    "description": "NAT: web to NAS"},
                "a1e1c6f0-1d6e-4b1e-8f00-000000000006": {"sequence": 51, "action": "pass", "interfaces": ["opt1"],
                    "source": {"net": "10.10.0.0/24"}, "destination": {"net": "alias:rfc1918"},
                    "description": "Road warriors to LAN"},
                "a1e1c6f0-1d6e-4b1e-8f00-000000000007": {"enabled": false, "sequence": 61, "action": "block",
                    "quick": false, "interfaces": [], "ip_protocol": "inet46",
                    "source": {"net": "alias:spamhaus_drop"}, "log": true, "description": "Drop listed networks"}
            }
        },
        "nat": {
            "outbound": {
                "mode": "hybrid",
                "rules": {
                    "c0ffee00-0000-4000-a000-000000000001": {"interface": "wan", "source": {"net": "10.10.0.0/24"},
                        "description": "WireGuard clients out"}
                }
            },
            "port_forwards": {
                "d0d0d0d0-0000-4000-a000-000000000001": {"interfaces": ["wan"], "protocol": "tcp",
                    "destination": {"net": "addr:wan", "port": "443"}, "target": "192.168.1.20", "target_port": "443",
                    "description": "NAS HTTPS"},
                "d0d0d0d0-0000-4000-a000-000000000002": {"enabled": false, "sequence": 2, "interfaces": ["wan"],
                    "protocol": "tcp/udp", "destination": {"net": "addr:wan", "port": "25565"},
                    "target": "192.168.1.30", "description": "Game server"}
            }
        },
        "dhcpv4": {
            "enabled": true,
            "interfaces": ["lan"],
            "subnets": {
                "00000000-0000-0000-0000-00005e450003": {"subnet": "192.168.1.0/24", "interface": "lan",
                    "pools": ["192.168.1.100-192.168.1.199", "192.168.1.220-192.168.1.239"],
                    "options": {"domain_name": "home.arpa"}}
            },
            "reservations": {
                "f0000000-0000-4000-a000-000000000001": {"subnet": "00000000-0000-0000-0000-00005e450003",
                    "client": {"hw_address": "52:54:00:aa:bb:01"}, "ip_address": "192.168.1.20",
                    "hostname": "nas", "description": "File server"},
                "f0000000-0000-4000-a000-000000000002": {"subnet": "00000000-0000-0000-0000-00005e450003",
                    "client": {"hw_address": "52:54:00:aa:bb:02"}, "ip_address": "192.168.1.21",
                    "hostname": "printer", "description": "Office printer"}
            }
        },
        "dns": {
            "enabled": true, "port": "53", "dnssec": true, "register_dhcp_leases": true,
            "register_dhcp_static": true, "local_zone_type": "transparent",
            "host_overrides": {
                "b0000000-0000-4000-a000-000000000001": {"hostname": "nas", "domain": "home.arpa",
                    "record": {"rr": "A", "address": "192.168.1.20"}, "description": "NAS"},
                "b0000000-0000-4000-a000-000000000002": {"hostname": "*", "domain": "lab.home.arpa",
                    "record": {"rr": "A", "address": "192.168.1.40"}, "description": "Lab wildcard"}
            }
        },
        "wireguard": {
            "enabled": true,
            "servers": {
                "90000000-0000-4000-a000-000000000001": {"name": "wg0", "instance": 0,
                    "public_key": "pf9Z1Xx2TJUy0rzvQFkWsWTfNszIHhUyU0PazG/IQyc=",
                    "private_key": "RFdSBMFhe6alos1D62jnPf1MOxQSfI4eWjqrjHdkgtI=",
                    "listen_port": "51820", "mtu": 1420, "tunnel_addresses": ["10.10.0.1/24"],
                    "peers": ["91000000-0000-4000-a000-000000000001", "91000000-0000-4000-a000-000000000002"]}
            },
            "peers": {
                "91000000-0000-4000-a000-000000000001": {"name": "laptop",
                    "public_key": "SgF/lLNYzsAh3k/TS8exPiMtwhP8i24yYk9rXVhvOI4=",
                    "allowed_ips": ["10.10.0.2/32"], "keepalive": 25},
                "91000000-0000-4000-a000-000000000002": {"name": "phone",
                    "public_key": "QI/cUp+b5XkhrNjwkflNQD3lZZ1tzY6kr9E3dj+KyDw=",
                    "allowed_ips": ["10.10.0.3/32"], "keepalive": 25}
            }
        }
    })
}

/// Field names whose values are secrets (sensr-schema `Secret<T>`).
const SECRET_KEYS: &[&str] = &[
    "private_key",
    "preshared_key",
    "password_hash",
    "secret_hash",
];

/// Replaces secrets with [`REDACTED`], as the API does in responses.
fn redact(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if SECRET_KEYS.contains(&k.as_str()) && x.is_string() {
                    *x = Value::String(REDACTED.into());
                } else {
                    redact(x);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(redact),
        _ => {}
    }
}

/// Puts stored secrets back where a write sent [`REDACTED`] ("unchanged").
fn unredact(new: &mut Value, old: &Value) {
    match new {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if x.as_str() == Some(REDACTED) {
                    if let Some(prev) = old.get(k) {
                        *x = prev.clone();
                    }
                } else if let Some(prev) = old.get(k) {
                    unredact(x, prev);
                }
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter_mut().enumerate() {
                if let Some(prev) = old.get(i) {
                    unredact(x, prev);
                }
            }
        }
        _ => {}
    }
}

/// Validates a whole document the way the agent does: typed parse, then cross-checks.
pub fn validate(doc: &Value) -> Result<(), Vec<FieldError>> {
    let typed: sensr_schema::Document = serde_path_to_error::deserialize(doc).map_err(|e| {
        let path = e.path().to_string();
        let msg = e.inner().to_string();
        vec![FieldError::new(
            if path == "." { String::new() } else { path },
            msg,
        )]
    })?;
    let v = typed.validate();
    if v.is_ok() {
        return Ok(());
    }
    Err(v
        .iter()
        .flat_map(|(p, errs)| {
            errs.iter()
                .map(move |e| FieldError::new(p.to_string(), e.message.clone()))
        })
        .collect())
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
        block(m.set("system.hostname", json!("fw"))).unwrap();
        assert_eq!(block(m.pending()).unwrap().changed, ["system"]);
        let rev = block(m.commit("root", "rename", None)).unwrap();
        assert_eq!(rev.id, 3);
        assert!(!block(m.pending()).unwrap().dirty());
        assert_eq!(block(m.get("system.hostname")).unwrap(), json!("fw"));
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
        block(m.set("system.hostname", json!("fw"))).unwrap();
        block(m.commit("root", "risky", Some(60))).unwrap();
        assert!(block(m.pending()).unwrap().confirm.is_some());
        t.fetch_add(61, Ordering::SeqCst);
        let p = block(m.pending()).unwrap();
        assert!(p.confirm.is_none());
        assert_eq!(block(m.get("system.hostname")).unwrap(), json!("sensr"));
        assert!(
            block(m.history()).unwrap()[0]
                .message
                .starts_with("Automatic rollback")
        );
    }

    #[test]
    fn confirmed_commit_stays() {
        let (m, t) = mock_with_clock();
        block(m.set("system.hostname", json!("fw"))).unwrap();
        block(m.commit("root", "risky", Some(60))).unwrap();
        block(m.confirm()).unwrap();
        t.fetch_add(120, Ordering::SeqCst);
        assert_eq!(block(m.get("system.hostname")).unwrap(), json!("fw"));
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
        assert_eq!(block(m.get("system.timezone")).unwrap(), json!("Etc/UTC"));
        block(m.set("system.timezone", json!("Asia/Tokyo"))).unwrap();
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
        let m = MockSessions(Arc::new(m));
        assert_eq!(block(m.login("root", "nope")), Err(ApiError::Unauthorized));
        let tok = block(m.login("root", "sensr")).unwrap();
        assert_eq!(block(m.open(&tok)).map(|s| s.user).as_deref(), Some("root"));
        block(m.logout(&tok));
        assert!(block(m.open(&tok)).is_none());
    }

    #[test]
    fn seed_is_a_valid_schema_document() {
        validate(&seed()).unwrap();
    }

    #[test]
    fn invalid_writes_are_rejected_with_schema_paths() {
        let (m, _) = mock_with_clock();
        let err = block(m.set("system.hostname", json!("not a host"))).unwrap_err();
        let ApiError::Validation(errs) = err else {
            panic!("{err:?}")
        };
        assert_eq!(errs[0].path, "system.hostname", "{errs:?}");
        assert!(!block(m.pending()).unwrap().dirty(), "nothing staged");
    }

    #[test]
    fn secrets_are_redacted_and_kept() {
        let (m, _) = mock_with_clock();
        let servers = block(m.get("wireguard.servers")).unwrap();
        let (k, srv) = servers.as_object().unwrap().iter().next().unwrap();
        assert_eq!(srv["private_key"], REDACTED);
        let mut changed = srv.clone();
        changed["mtu"] = json!(1400);
        block(m.set(&format!("wireguard.servers.{k}"), changed)).unwrap();
        let state = m.state.lock().unwrap();
        let stored =
            get_path(&state.staged, &format!("wireguard.servers.{k}.private_key")).unwrap();
        assert_ne!(stored, REDACTED, "a redacted write keeps the stored secret");
    }

    #[test]
    fn seed_rows_round_trip_through_views() {
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
            let scope = g.scope(&None);
            let store = crate::adapt::store(g, &scope, &doc);
            let (crate::adapt::Store::Map(p) | crate::adapt::Store::Array(p)) = &store;
            let items: Vec<Value> = match get_path(&doc, p).unwrap() {
                Value::Object(m) => m.values().cloned().collect(),
                Value::Array(a) => a.clone(),
                _ => unreachable!(),
            };
            assert!(!items.is_empty(), "{g:?}");
            for item in items
                .iter()
                .filter(|i| crate::adapt::in_scope(g, &scope, &doc, i))
            {
                let mut view = crate::adapt::to_view(g, &doc, item);
                view[g.meta().key] = json!("existing");
                let inputs = crate::form::to_inputs(g.meta().fields, &view);
                let parsed = g
                    .apply(&view, &inputs)
                    .unwrap_or_else(|e| panic!("{g:?} {view}: {e:?}"));
                let back = crate::adapt::from_view(g, &doc, &scope, Some(item), &parsed);
                // Unchanged views write back the same item (secrets come back as "keep").
                let mut expect = item.clone();
                redact(&mut expect);
                let mut got = back.clone();
                redact(&mut got);
                assert_eq!(strip_defaults(&got), strip_defaults(&expect), "{g:?}");
            }
        }
        for f in [
            FormId::SystemGeneral,
            FormId::Interface,
            FormId::SourceNatMode,
            FormId::DhcpSettings,
            FormId::UnboundGeneral,
        ] {
            let scope = f.scope(&None);
            let view = crate::adapt::form_to_view(f, &doc, &scope).unwrap();
            let parsed = f
                .apply(&view, &crate::form::to_inputs(f.fields(), &view))
                .unwrap_or_else(|e| panic!("{f:?}: {e:?}"));
            let mut d = doc.clone();
            crate::adapt::form_from_view(f, &mut d, &scope, &parsed).unwrap();
            validate(&d).unwrap_or_else(|e| panic!("{f:?}: {e:?}"));
        }
    }

    /// Drops keys whose value equals the schema default the view writes explicitly.
    fn strip_defaults(v: &Value) -> Value {
        let defaults = [
            ("enabled", json!(true)),
            ("not", json!(false)),
            ("quick", json!(true)),
            ("log", json!(false)),
            ("no_nat", json!(false)),
            ("disable_routes", json!(false)),
            ("block_private", json!(false)),
            ("block_bogons", json!(false)),
            ("tunnel_addresses", json!([])),
            ("dns", json!([])),
            ("direction", json!("")),
            ("direction", json!("in")),
            ("ip_protocol", json!("inet")),
            ("protocol", json!("any")),
            ("action", json!("pass")),
            ("ip_protocol", json!("")),
            ("protocol", json!("")),
            ("action", json!("")),
        ];
        match v {
            Value::Object(m) => Value::Object(
                m.iter()
                    .filter(|(k, x)| !defaults.iter().any(|(dk, dv)| dk == k && dv == *x))
                    .filter(|(k, x)| !(k.as_str() == "net" && x.as_str() == Some("any")))
                    .map(|(k, x)| (k.clone(), strip_defaults(x)))
                    .filter(|(_, x)| x.as_object().is_none_or(|o| !o.is_empty()))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    #[test]
    fn status_reflects_config() {
        let (m, _) = mock_with_clock();
        let s = block(m.status()).unwrap();
        assert_eq!(s.hostname, "sensr.home.arpa");
        assert_eq!(s.interfaces.len(), 3);
        assert_eq!(s.interfaces[1].ipv4.as_deref(), Some("192.168.1.1/24"));
        assert_eq!(s.traffic[0].rx.len(), 60);
    }
}
