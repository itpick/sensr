//! The accounting table (`inet sensr_flow`) and the parser of its listing.
//!
//! Sets are named `<kind><dir><family>`: kind `h` (local host), `a` (local
//! host . protocol . service port), `r` (remote address), `p` (local host .
//! remote address, for per-host service attribution); dir `u` (in from a
//! local interface: the local host's upload) or `d` (out to one: its
//! download); family `4` or `6`. The service port is the connection's
//! original destination port (`ct original proto-dst`), the same for both
//! directions of a connection, so replies count toward the service.

use std::collections::HashMap;

use serde_json::{Value, json};

use crate::config::FlowConfig;

/// The table.
pub const TABLE: &str = "sensr_flow";
/// Forward-hook priority: after the filter (0) and the IDS queue (10, 11),
/// so dropped packets are not counted.
pub const PRIORITY: i32 = 20;
/// Idle elements expire after this many seconds (re-created, from zero,
/// when the host or service is seen again).
pub const ELEMENT_TIMEOUT: u32 = 3600;

/// What a set counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    /// A local host.
    Host,
    /// A local host's service (protocol, port).
    App,
    /// A remote address.
    Remote,
    /// A local host and a remote address it talks to.
    Pair,
}

/// Direction from the local host's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Dir {
    /// Sent by the local host.
    Up,
    /// Received by it.
    Down,
}

const KINDS: [(Kind, char); 4] = [
    (Kind::Host, 'h'),
    (Kind::App, 'a'),
    (Kind::Remote, 'r'),
    (Kind::Pair, 'p'),
];
const DIRS: [(Dir, char); 2] = [(Dir::Up, 'u'), (Dir::Down, 'd')];
const FAMILIES: [(&str, char, &str); 2] = [("ip", '4', "ipv4_addr"), ("ip6", '6', "ipv6_addr")];

fn set_name(k: char, d: char, f: char) -> String {
    format!("{k}{d}{f}")
}

/// The accounting table for `cfg` (replaces any previous one, which resets
/// the counters; the reader treats a counter that went down as new).
pub fn ruleset(cfg: &FlowConfig) -> String {
    let local: Vec<&str> = cfg
        .interfaces
        .iter()
        .filter(|i| i.local)
        .map(|i| i.device.as_str())
        .collect();
    let table = json!({ "table": { "family": "inet", "name": TABLE } });
    let mut cmds = vec![
        json!({ "add": table.clone() }),
        json!({ "delete": table.clone() }),
        json!({ "add": table }),
        json!({ "add": { "chain": {
            "family": "inet", "table": TABLE, "name": "account", "type": "filter",
            "hook": "forward", "prio": PRIORITY, "policy": "accept" } } }),
    ];
    for (proto, f, addr) in FAMILIES {
        for (_, k) in KINDS {
            for (_, d) in DIRS {
                let ty: Value = match k {
                    'a' => json!([addr, "inet_proto", "inet_service"]),
                    'p' => json!([addr, addr]),
                    _ => json!(addr),
                };
                cmds.push(json!({ "add": { "set": {
                    "family": "inet", "table": TABLE, "name": set_name(k, d, f),
                    "type": ty, "size": cfg.max_entries,
                    "flags": ["dynamic", "timeout"], "timeout": ELEMENT_TIMEOUT,
                    "stmt": [{ "counter": null }] } } }));
            }
        }
        if local.is_empty() {
            continue;
        }
        let field = |name: &str| json!({ "payload": { "protocol": proto, "field": name } });
        for (dir, d) in DIRS {
            let (meta, own, other) = match dir {
                Dir::Up => ("iifname", "saddr", "daddr"),
                Dir::Down => ("oifname", "daddr", "saddr"),
            };
            let on_local = json!({ "match": { "op": "==",
                "left": { "meta": { "key": meta } }, "right": { "set": local } } });
            // the family test is implicit in the payload match on `inet`
            let update = |set: String, elem: Value| json!({ "set": { "op": "update", "elem": elem, "set": format!("@{set}") } });
            let rule = |expr: Vec<Value>| {
                json!({ "add": { "rule": {
                    "family": "inet", "table": TABLE, "chain": "account", "expr": expr } } })
            };
            cmds.push(rule(vec![
                on_local.clone(),
                update(set_name('h', d, f), field(own)),
                update(set_name('r', d, f), field(other)),
                update(
                    set_name('p', d, f),
                    json!({ "concat": [field(own), field(other)] }),
                ),
            ]));
            cmds.push(rule(vec![
                on_local,
                json!({ "match": { "op": "==", "left": { "meta": { "key": "l4proto" } },
                    "right": { "set": ["tcp", "udp"] } } }),
                update(
                    set_name('a', d, f),
                    json!({ "concat": [
                        field(own),
                        { "meta": { "key": "l4proto" } },
                        { "ct": { "key": "proto-dst", "dir": "original" } }
                    ] }),
                ),
            ]));
        }
    }
    json!({ "nftables": cmds }).to_string()
}

/// Removes the table if present.
pub fn removal() -> String {
    let table = json!({ "table": { "family": "inet", "name": TABLE } });
    json!({ "nftables": [ { "add": table.clone() }, { "delete": table } ] }).to_string()
}

/// One counter as listed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key {
    /// What it counts.
    pub kind: Kind,
    /// Which way.
    pub dir: Dir,
    /// The address (local host for `Host`/`App`/`Pair`, remote for `Remote`).
    pub addr: String,
    /// For `Pair`: the remote address (else empty).
    pub remote: String,
    /// For `App`: IP protocol number.
    pub proto: u8,
    /// For `App`: service port.
    pub port: u16,
}

/// Packets and bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Count {
    /// Packets.
    pub packets: u64,
    /// Bytes.
    pub bytes: u64,
}

fn proto_number(v: &Value) -> Option<u8> {
    match v {
        Value::Number(n) => n.as_u64().and_then(|n| u8::try_from(n).ok()),
        Value::String(s) => match s.as_str() {
            "tcp" => Some(6),
            "udp" => Some(17),
            "icmp" => Some(1),
            "ipv6-icmp" | "icmpv6" => Some(58),
            "sctp" => Some(132),
            other => other.parse().ok(),
        },
        _ => None,
    }
}

fn port_number(v: &Value) -> Option<u16> {
    match v {
        Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Parses `nft -j list table inet sensr_flow` into counters. Unknown sets
/// and malformed elements are skipped.
pub fn parse(listing: &[u8]) -> HashMap<Key, Count> {
    let mut out = HashMap::new();
    let Ok(v) = serde_json::from_slice::<Value>(listing) else {
        return out;
    };
    let Some(items) = v.get("nftables").and_then(Value::as_array) else {
        return out;
    };
    for item in items {
        let Some(set) = item.get("set") else { continue };
        let Some(name) = set.get("name").and_then(Value::as_str) else {
            continue;
        };
        let mut c = name.chars();
        let (Some(k), Some(d), Some(_f), None) = (c.next(), c.next(), c.next(), c.next()) else {
            continue;
        };
        let Some(kind) = KINDS.iter().find(|x| x.1 == k).map(|x| x.0) else {
            continue;
        };
        let Some(dir) = DIRS.iter().find(|x| x.1 == d).map(|x| x.0) else {
            continue;
        };
        for e in set
            .get("elem")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(e) = e.get("elem") else { continue };
            let (Some(val), Some(counter)) = (e.get("val"), e.get("counter")) else {
                continue;
            };
            let count = Count {
                packets: counter.get("packets").and_then(Value::as_u64).unwrap_or(0),
                bytes: counter.get("bytes").and_then(Value::as_u64).unwrap_or(0),
            };
            let key = match (kind, val) {
                (Kind::App, v) => {
                    let Some(parts) = v.get("concat").and_then(Value::as_array) else {
                        continue;
                    };
                    let (Some(addr), Some(proto), Some(port)) = (
                        parts.first().and_then(Value::as_str),
                        parts.get(1).and_then(proto_number),
                        parts.get(2).and_then(port_number),
                    ) else {
                        continue;
                    };
                    Key {
                        kind,
                        dir,
                        addr: addr.to_owned(),
                        remote: String::new(),
                        proto,
                        port,
                    }
                }
                (Kind::Pair, v) => {
                    let Some(parts) = v.get("concat").and_then(Value::as_array) else {
                        continue;
                    };
                    let (Some(local), Some(remote), None) = (
                        parts.first().and_then(Value::as_str),
                        parts.get(1).and_then(Value::as_str),
                        parts.get(2),
                    ) else {
                        continue;
                    };
                    Key {
                        kind,
                        dir,
                        addr: local.to_owned(),
                        remote: remote.to_owned(),
                        proto: 0,
                        port: 0,
                    }
                }
                (_, Value::String(addr)) => Key {
                    kind,
                    dir,
                    addr: addr.clone(),
                    remote: String::new(),
                    proto: 0,
                    port: 0,
                },
                _ => continue,
            };
            out.insert(key, count);
        }
    }
    out
}

/// Turns successive listings into deltas. A counter that went down (the
/// table was reloaded, or the element expired and came back) counts from
/// zero; the first listing after start is only a baseline.
#[derive(Debug, Default)]
pub struct Deltas {
    last: Option<HashMap<Key, Count>>,
}

impl Deltas {
    /// The change since the previous call.
    pub fn next(&mut self, now: HashMap<Key, Count>) -> Vec<(Key, Count)> {
        let mut out = Vec::new();
        if let Some(prev) = &self.last {
            for (k, c) in &now {
                let d = match prev.get(k) {
                    Some(p) if c.bytes >= p.bytes && c.packets >= p.packets => Count {
                        packets: c.packets - p.packets,
                        bytes: c.bytes - p.bytes,
                    },
                    _ => *c,
                };
                if d.bytes > 0 || d.packets > 0 {
                    out.push((k.clone(), d));
                }
            }
        }
        self.last = Some(now);
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Iface, Retention};

    pub(crate) fn cfg() -> FlowConfig {
        FlowConfig {
            sample_seconds: 10,
            max_entries: 65536,
            interfaces: vec![
                Iface {
                    name: "wan".into(),
                    device: "igc0".into(),
                    local: false,
                },
                Iface {
                    name: "lan".into(),
                    device: "igc1".into(),
                    local: true,
                },
            ],
            retention: Retention::default(),
        }
    }

    #[test]
    fn ruleset_has_sixteen_sets_and_eight_rules() {
        let v: Value = serde_json::from_str(&ruleset(&cfg())).unwrap();
        let cmds = v["nftables"].as_array().unwrap();
        let count = |what: &str| cmds.iter().filter(|c| c["add"].get(what).is_some()).count();
        assert_eq!(count("set"), 16);
        assert_eq!(count("rule"), 8);
        let text = v.to_string();
        assert!(text.contains(r#""right":{"set":["igc1"]}"#), "{text}");
        assert!(!text.contains("igc0"), "the WAN is not local");
        assert!(text.contains(r#""dir":"original""#));
    }

    #[test]
    fn pair_sets_rendered() {
        let v: Value = serde_json::from_str(&ruleset(&cfg())).unwrap();
        let cmds = v["nftables"].as_array().unwrap();
        for (f, addr) in [('4', "ipv4_addr"), ('6', "ipv6_addr")] {
            for d in ['u', 'd'] {
                let name = format!("p{d}{f}");
                let set = cmds
                    .iter()
                    .find_map(|c| c["add"].get("set").filter(|s| s["name"] == name.as_str()))
                    .unwrap_or_else(|| panic!("set {name}"));
                assert_eq!(set["type"], json!([addr, addr]), "{name}");
                assert_eq!(set["size"], 65536);
                assert_eq!(set["timeout"], ELEMENT_TIMEOUT);
                assert_eq!(set["flags"], json!(["dynamic", "timeout"]));
                assert_eq!(set["stmt"], json!([{ "counter": null }]));
            }
        }
        // the host rule updates the pair set with (local . remote)
        let proto = |p: &str, f: &str| json!({ "payload": { "protocol": p, "field": f } });
        for (p, f) in [("ip", '4'), ("ip6", '6')] {
            for (d, own, other) in [('u', "saddr", "daddr"), ('d', "daddr", "saddr")] {
                let want = json!({ "set": { "op": "update",
                    "elem": { "concat": [proto(p, own), proto(p, other)] },
                    "set": format!("@p{d}{f}") } });
                assert!(
                    cmds.iter().any(|c| c["add"]["rule"]["expr"]
                        .as_array()
                        .is_some_and(|e| e.contains(&want))),
                    "no pair update for p{d}{f}"
                );
            }
        }
    }

    #[test]
    fn pair_listing_parsed() {
        let listing = json!({"nftables": [
            {"metainfo": {"version": "1.1.7"}},
            {"set": {"family": "inet", "name": "pd4", "table": TABLE,
                "type": ["ipv4_addr", "ipv4_addr"],
                "elem": [
                    {"elem": {"val": {"concat": ["192.168.1.100", "142.250.1.1"]},
                        "expires": 3599, "counter": {"packets": 7, "bytes": 7000}}},
                    // malformed: one part only
                    {"elem": {"val": {"concat": ["192.168.1.100"]},
                        "counter": {"packets": 1, "bytes": 1}}},
                    // malformed: not a concatenation
                    {"elem": {"val": "192.168.1.100", "counter": {"packets": 1, "bytes": 1}}}
                ]}},
            {"set": {"family": "inet", "name": "pu6", "table": TABLE,
                "type": ["ipv6_addr", "ipv6_addr"],
                "elem": [{"elem": {"val": {"concat": ["fd00::10", "2001:db8::1"]},
                    "counter": {"packets": 2, "bytes": 150}}}]}}
        ]})
        .to_string();
        let m = parse(listing.as_bytes());
        assert_eq!(m.len(), 2, "{m:?}");
        let down = Key {
            kind: Kind::Pair,
            dir: Dir::Down,
            addr: "192.168.1.100".into(),
            remote: "142.250.1.1".into(),
            proto: 0,
            port: 0,
        };
        assert_eq!(m[&down].bytes, 7000);
        let up = m.keys().find(|k| k.dir == Dir::Up).unwrap();
        assert_eq!(
            (up.kind, up.addr.as_str(), up.remote.as_str()),
            (Kind::Pair, "fd00::10", "2001:db8::1")
        );
    }

    #[test]
    fn parses_listing_and_computes_deltas() {
        // the shape `nft -j list table` prints (nft 1.1.7)
        let listing = |bytes: u64| {
            json!({"nftables": [
                {"metainfo": {"version": "1.1.7"}},
                {"table": {"family": "inet", "name": TABLE}},
                {"set": {"family": "inet", "name": "hu4", "table": TABLE, "type": "ipv4_addr",
                    "elem": [{"elem": {"val": "192.168.1.100", "expires": 3599,
                        "counter": {"packets": 10, "bytes": bytes}}}]}},
                {"set": {"family": "inet", "name": "au4", "table": TABLE,
                    "type": ["ipv4_addr", "inet_proto", "inet_service"],
                    "elem": [{"elem": {"val": {"concat": ["192.168.1.100", "tcp", 443]},
                        "counter": {"packets": 3, "bytes": 300}}}]}},
                {"set": {"family": "inet", "name": "rd6", "table": TABLE, "type": "ipv6_addr",
                    "elem": [{"elem": {"val": "2001:db8::1", "counter": {"packets": 1, "bytes": 90}}}]}}
            ]})
            .to_string()
        };
        let m = parse(listing(1000).as_bytes());
        assert_eq!(m.len(), 3);
        let app = m.keys().find(|k| k.kind == Kind::App).unwrap();
        assert_eq!((app.proto, app.port, app.dir), (6, 443, Dir::Up));
        let mut d = Deltas::default();
        assert!(d.next(m).is_empty(), "first listing is a baseline");
        let m = parse(listing(1500).as_bytes());
        let delta = d.next(m);
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].1.bytes, 500);
        // reset (table reloaded): counts from zero
        let delta = d.next(parse(listing(200).as_bytes()));
        assert_eq!(delta[0].1.bytes, 200);
        assert!(parse(b"not json").is_empty());
    }
}
