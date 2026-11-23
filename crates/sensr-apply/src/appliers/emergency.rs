//! The emergency firewall: what the boot apply loads first on a fresh boot
//! (the kernel holds no sensr ruleset yet) and keeps until the real ruleset
//! loads: when `nft -c` rejects that ruleset, or anything before its load
//! fails, the box stays filtered. NixOS's own firewall is off on a sensr
//! box, so without it the router would forward and serve unfiltered.
//!
//! Its own table (`inet sensr_emergency`), not `inet sensr`: the alias,
//! interface and host-mode set updates address sets of `inet sensr` that
//! this ruleset does not declare, and "is `inet sensr` loaded" is how the
//! boot apply tells an agent restart (keep the running ruleset) from a fresh
//! boot. The real ruleset's load is followed by [`removal`].
//!
//! - forward: policy drop (no routing until a real ruleset loads);
//! - input: policy drop, except loopback, established/related, the ICMP
//!   and ICMPv6 essentials (ND and RA included, so IPv6 keeps working),
//!   the box's own DHCP/DHCPv6 client replies, and DHCP, DNS, NTP, SSH,
//!   HTTP and HTTPS from the LAN interfaces ([`inside`]);
//! - output: accept.

use sensr_schema::Document;
use sensr_schema::models::interfaces::{InterfaceRole, Ipv4Config, Ipv6Config};
use serde_json::{Value, json};

/// The emergency table's name (family `inet`).
pub const TABLE: &str = "sensr_emergency";

fn table() -> Value {
    json!({ "family": "inet", "name": TABLE })
}

fn chain(name: &str, policy: &str) -> Value {
    json!({ "add": { "chain": {
        "family": "inet", "table": TABLE, "name": name, "type": "filter",
        "hook": name, "prio": 0, "policy": policy } } })
}

fn rule(chain: &str, expr: Vec<Value>) -> Value {
    json!({ "add": { "rule": { "family": "inet", "table": TABLE, "chain": chain, "expr": expr } } })
}

fn is(left: Value, right: Value) -> Value {
    json!({ "match": { "op": "==", "left": left, "right": right } })
}

fn accept() -> Value {
    json!({ "accept": null })
}

fn dport(proto: &str, ports: &[u16]) -> Value {
    is(
        json!({ "payload": { "protocol": proto, "field": "dport" } }),
        json!({ "set": ports }),
    )
}

/// The devices that may reach the box's services under the emergency
/// firewall. Fails closed: only enabled interfaces with the `Lan` role, and
/// none that look like an uplink (a DHCP/DHCPv6/SLAAC client or a static
/// gateway), whatever their role says.
pub fn inside(doc: &Document) -> Vec<String> {
    doc.interfaces
        .iter()
        .filter(|(_, i)| i.enabled && i.role == InterfaceRole::Lan)
        .filter(|(_, i)| {
            let v4_uplink = match &i.ipv4 {
                Ipv4Config::Dhcp { .. } => true,
                Ipv4Config::Static { gateway, .. } => gateway.is_some(),
                _ => false,
            };
            let v6_uplink = match &i.ipv6 {
                Ipv6Config::Dhcp6 { .. } | Ipv6Config::Slaac => true,
                Ipv6Config::Static { gateway, .. } => gateway.is_some(),
                _ => false,
            };
            !v4_uplink && !v6_uplink
        })
        .map(|(_, i)| i.device.as_str().to_owned())
        .collect()
}

/// The emergency ruleset (nft JSON). `inside` are the devices that may
/// reach the box's services ([`inside`]).
pub fn ruleset(inside: &[String]) -> String {
    let mut cmds = vec![
        json!({ "metainfo": { "json_schema_version": 1 } }),
        json!({ "add": { "table": table() } }),
        json!({ "delete": { "table": table() } }),
        json!({ "add": { "table": table() } }),
        chain("input", "drop"),
        chain("forward", "drop"),
        chain("output", "accept"),
        rule(
            "input",
            vec![
                is(json!({ "meta": { "key": "iifname" } }), json!("lo")),
                accept(),
            ],
        ),
        rule(
            "input",
            vec![
                json!({ "vmap": { "key": { "ct": { "key": "state" } }, "data": { "set": [
                ["established", accept()], ["related", accept()], ["invalid", { "drop": null }]
            ] } } }),
            ],
        ),
        rule(
            "input",
            vec![
                is(
                    json!({ "payload": { "protocol": "icmp", "field": "type" } }),
                    json!({ "set": ["echo-request", "destination-unreachable",
                        "time-exceeded", "parameter-problem"] }),
                ),
                accept(),
            ],
        ),
        rule(
            "input",
            vec![
                is(
                    json!({ "payload": { "protocol": "icmpv6", "field": "type" } }),
                    json!({ "set": ["destination-unreachable", "packet-too-big",
                        "time-exceeded", "parameter-problem", "echo-request",
                        "nd-router-solicit", "nd-router-advert",
                        "nd-neighbor-solicit", "nd-neighbor-advert",
                        "mld-listener-query"] }),
                ),
                accept(),
            ],
        ),
        // the box's own DHCP clients (WAN leases, PD): replies to a
        // broadcast or multicast request are not "established"
        rule(
            "input",
            vec![
                is(
                    json!({ "payload": { "protocol": "udp", "field": "sport" } }),
                    json!(67),
                ),
                dport("udp", &[68]),
                accept(),
            ],
        ),
        rule(
            "input",
            vec![
                is(
                    json!({ "payload": { "protocol": "ip6", "field": "saddr" } }),
                    json!({ "prefix": { "addr": "fe80::", "len": 10 } }),
                ),
                dport("udp", &[546]),
                accept(),
            ],
        ),
    ];
    if !inside.is_empty() {
        let from_inside = || {
            is(
                json!({ "meta": { "key": "iifname" } }),
                json!({ "set": inside }),
            )
        };
        cmds.push(rule(
            "input",
            vec![from_inside(), dport("udp", &[53, 67, 123]), accept()],
        ));
        cmds.push(rule(
            "input",
            vec![from_inside(), dport("tcp", &[22, 53, 80, 443]), accept()],
        ));
    }
    let mut out = String::from("{\"nftables\":[");
    for (i, c) in cmds.iter().enumerate() {
        if i > 0 {
            out.push_str(",\n");
        }
        out.push_str(&c.to_string());
    }
    out.push_str("]}\n");
    out
}

/// Drops the emergency table if it is there (one transaction; a no-op
/// when it is not).
pub fn removal() -> String {
    json!({ "nftables": [
        { "add": { "table": table() } },
        { "delete": { "table": table() } },
    ] })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::{Cmd, Runner, SystemRunner};

    const GOLDEN: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden/emergency.nft.json"
    );

    fn lan() -> Vec<String> {
        vec!["igc1".into(), "igc1.20".into()]
    }

    /// The golden is kernel-checked in CI by `scripts/nft-check-goldens.sh
    /// crates/sensr-apply/tests/golden`; `SENSR_GOLDEN_UPDATE=1` rewrites it.
    #[test]
    fn emergency_ruleset_golden() {
        let got = ruleset(&lan());
        if std::env::var_os("SENSR_GOLDEN_UPDATE").is_some() {
            std::fs::write(GOLDEN, &got).unwrap();
        }
        let want = std::fs::read_to_string(GOLDEN).expect("golden (SENSR_GOLDEN_UPDATE=1)");
        assert_eq!(got, want);
        let v: Value = serde_json::from_str(&got).unwrap();
        let cmds = v["nftables"].as_array().unwrap();
        let policy = |name: &str| {
            cmds.iter()
                .find_map(|c| {
                    let ch = &c["add"]["chain"];
                    (ch["name"] == name).then(|| ch["policy"].as_str().unwrap().to_owned())
                })
                .unwrap()
        };
        assert_eq!(policy("input"), "drop");
        assert_eq!(policy("forward"), "drop");
        assert_eq!(policy("output"), "accept");
        assert!(got.contains("nd-router-advert") && got.contains("nd-neighbor-solicit"));
        assert!(!got.contains("igc0"), "the WAN gets no service ports");
        // no inside interface: nothing but the essentials
        assert!(!ruleset(&[]).contains("\"iifname\"}},\"right\":{\"set\""));
        serde_json::from_str::<Value>(&removal()).unwrap();
    }

    #[test]
    fn only_plain_lan_interfaces_are_inside() {
        use sensr_schema::PathAccess;
        let mut doc: Document = serde_json::from_str(include_str!(
            "../../../sensr-import-opnsense/tests/golden/home-router.sensr.json"
        ))
        .unwrap();
        // wan (dhcp) and opt3 (role other, wg0) are not inside
        assert_eq!(inside(&doc), ["igc1", "vlan01", "vlan02"]);
        // a LAN that is a DHCP client, a LAN with a static gateway, a LAN
        // on SLAAC: uplink-like, so closed
        doc.set_by_path(
            "interfaces.lan.ipv4",
            json!({"mode": "dhcp", "use_gateway": false}),
        )
        .unwrap();
        doc.set_by_path(
            "interfaces.opt1.ipv4",
            json!({"mode": "static", "address": "192.168.20.1/24", "gateway": "192.168.20.254"}),
        )
        .unwrap();
        doc.set_by_path("interfaces.opt2.ipv6", json!({"mode": "slaac"}))
            .unwrap();
        assert!(inside(&doc).is_empty(), "{:?}", inside(&doc));
        // disabled LANs are closed too
        let mut doc2: Document = serde_json::from_str(include_str!(
            "../../../sensr-import-opnsense/tests/golden/home-router.sensr.json"
        ))
        .unwrap();
        doc2.set_by_path("interfaces.lan.enabled", json!(false))
            .unwrap();
        assert_eq!(inside(&doc2), ["vlan01", "vlan02"]);
    }

    #[test]
    fn dhcp_client_replies_need_server_port_and_lan_gets_ntp() {
        let text = ruleset(&lan());
        assert!(text.contains(
            r#"{"payload":{"protocol":"udp","field":"sport"}},"right":67}},{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":{"set":[68]}}}"#
        ), "{text}");
        assert!(text.contains(r#""right":{"set":[53,67,123]}"#), "{text}");
    }

    /// `nft -c` on the emergency ruleset and the removal, when nft is here
    /// (needs CAP_NET_ADMIN or `unshare -rn`; skipped otherwise).
    #[test]
    fn emergency_ruleset_passes_nft_check() {
        let r = SystemRunner;
        if !r.has_program("nft") {
            eprintln!("nft not installed; skipping");
            return;
        }
        for text in [ruleset(&lan()), removal()] {
            let mut feed = |w: &mut dyn std::io::Write| w.write_all(text.as_bytes());
            let out = r
                .run(
                    &Cmd::new("nft").args(["-c", "-j", "-f", "-"]),
                    Some(&mut feed),
                )
                .unwrap();
            let err = out.stderr_text();
            if err.contains("Operation not permitted") {
                eprintln!("nft -c needs privileges; skipping");
                return;
            }
            assert!(out.success(), "{err}\n{text}");
        }
    }
}
