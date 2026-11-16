//! NAT order and translation semantics against upstream: 1:1 NAT
//! (`DNatRule`, pf `binat`/`nat`), hybrid outbound NAT (`filter.inc`: manual
//! rules at priority 100 before the automatic ones at 200) and port-forward
//! reflection (`ForwardRule`: per-rule override, global defaults, hairpin
//! helper, port ranges, alias targets, several interfaces, IPv6).
//!
//! The pf lines are what upstream's procorder tables print for the same
//! input; the nft assertions check that the lowered chains keep pf's
//! translation order (`pf_get_translation`: inbound rdr before binat,
//! outbound binat before nat).

mod common;

use std::str::FromStr;

use sensr_rules::document::{self, Runtime};
use sensr_rules::ir::IfAddr;
use sensr_schema::Document;
use sensr_schema::Uuid;
use sensr_schema::models::nat::{OneToOneRule, OutboundNatMode, PortForward, ReflectionMode};
use serde_json::{Value, json};

fn corpus() -> Document {
    let path = format!(
        "{}/../sensr-import-opnsense/tests/golden/home-router.sensr.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect("importer golden"))
        .expect("document")
}

/// The corpus without its own 1:1 rules, so each test adds what it checks.
fn home_router() -> Document {
    let mut doc = corpus();
    doc.nat.one_to_one.clear();
    doc
}

fn addr(s: &str) -> IfAddr {
    let n: ipnet::IpNet = s.parse().unwrap();
    IfAddr {
        addr: n.addr(),
        prefix_len: n.prefix_len(),
    }
}

/// What DHCP gave the WAN (sets follow later changes).
fn runtime() -> Runtime<'static> {
    let mut rt = Runtime::default();
    rt.addrs.insert("wan".into(), vec![addr("203.0.113.2/24")]);
    rt
}

const FORWARD: &str = "fc2c1c65-ad69-489b-967c-8ff95e8f2f80";

fn forward(doc: &mut Document) -> &mut PortForward {
    doc.nat
        .port_forwards
        .get_mut(&Uuid::from_str(FORWARD).unwrap())
        .unwrap()
}

fn one_to_one(v: Value) -> OneToOneRule {
    serde_json::from_value(v).unwrap()
}

struct Out {
    pf: String,
    nft: Vec<u8>,
    warnings: Vec<String>,
}

fn render(doc: &Document, rt: &Runtime<'_>) -> Out {
    let v = doc.validate();
    assert!(v.is_empty(), "{v}");
    let c = document::compile(doc, rt);
    let mut nft = Vec::new();
    let report = c.render_nft(&mut nft).expect("render");
    Out {
        pf: c.render_pf(),
        nft,
        warnings: report
            .warnings
            .iter()
            .map(|w| format!("{}: {}", w.label, w.message))
            .collect(),
    }
}

/// The NAT lines under `# [prio: N]`.
fn prio(pf: &str, n: u32) -> Vec<&str> {
    let head = format!("# [prio: {n}]");
    pf.lines()
        .skip_while(|l| *l != head)
        .skip(1)
        .take_while(|l| !l.starts_with("# [prio:"))
        .collect()
}

/// The rules of an nft chain, as compact JSON statement lists.
fn chain(nft: &[u8], name: &str) -> Vec<String> {
    let v: Value = serde_json::from_slice(nft).unwrap();
    v["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c.get("add").and_then(|a| a.get("rule")))
        .filter(|r| r["chain"] == name)
        .map(|r| {
            let mut s = r["expr"].to_string();
            if let Some(c) = r["comment"].as_str() {
                s.push_str(" # ");
                s.push_str(c);
            }
            s
        })
        .collect()
}

fn position(rows: &[String], needle: &str) -> usize {
    rows.iter()
        .position(|r| r.contains(needle))
        .unwrap_or_else(|| panic!("no row with {needle} in\n{}", rows.join("\n")))
}

fn count(rows: &[String], needle: &str) -> usize {
    rows.iter().filter(|r| r.contains(needle)).count()
}

/// The home router with three 1:1 rules: a /28 lab (binat, reflected), a
/// single host (binat) and an outbound-only mapping of the IoT VLAN.
fn with_one_to_one() -> Document {
    let mut doc = home_router();
    doc.nat.one_to_one.push(one_to_one(json!({
        "sequence": 20,
        "interface": "wan",
        "external": "203.0.113.20",
        "source": {"net": "192.168.1.20"},
        "description": "Game server",
    })));
    doc.nat.one_to_one.push(one_to_one(json!({
        "sequence": 10,
        "interface": "wan",
        "external": "203.0.113.16",
        "source": {"net": "192.168.1.32/28"},
        "reflection": "enable",
        "description": "Lab /28",
    })));
    doc.nat.one_to_one.push(one_to_one(json!({
        "sequence": 30,
        "interface": "wan",
        "type": "nat",
        "external": "203.0.113.30",
        "source": {"net": "net:opt1"},
        "destination": {"net": "198.51.100.0/24"},
        "log": true,
        "description": "IoT to vendor cloud",
    })));
    doc
}

#[test]
fn one_to_one_pf_lines_follow_dnat_rule() {
    let out = render(&with_one_to_one(), &runtime());
    common::golden_text("nat-one-to-one.pf", &out.pf);
    common::golden_json("nat-one-to-one", &out.nft);
    assert!(out.warnings.is_empty(), "{:?}", out.warnings);
    let lab = [
        // a bare external host takes the internal prefix length
        "binat on igc0 from 192.168.1.32/28 to any -> 203.0.113.16/28 # Lab /28",
        // reflection: every interface without a gateway that has IPv4
        "rdr on igc1 from {any} to {203.0.113.16/28} -> {192.168.1.32/28} bitmask # Lab /28",
        "rdr on vlan01 from {any} to {203.0.113.16/28} -> {192.168.1.32/28} bitmask # Lab /28",
        "rdr on vlan02 from {any} to {203.0.113.16/28} -> {192.168.1.32/28} bitmask # Lab /28",
        "rdr on wg0 from {any} to {203.0.113.16/28} -> {192.168.1.32/28} bitmask # Lab /28",
        // helper (global reflection source NAT): the same interfaces, then
        // the rule's own
        "nat on igc1 inet from (igc1:network) to {192.168.1.32/28} -> (igc1) port 1024:65535 # Lab /28",
        "nat on vlan01 inet from (vlan01:network) to {192.168.1.32/28} -> (vlan01) port 1024:65535 # Lab /28",
        "nat on vlan02 inet from (vlan02:network) to {192.168.1.32/28} -> (vlan02) port 1024:65535 # Lab /28",
        "nat on wg0 inet from (wg0:network) to {192.168.1.32/28} -> (wg0) port 1024:65535 # Lab /28",
        "nat on igc0 inet from (igc0:network) to {192.168.1.32/28} -> (igc0) port 1024:65535 # Lab /28",
    ];
    let lines = prio(&out.pf, 500);
    assert_eq!(lines[..lab.len()], lab);
    // the host rule is not reflected (global reflection_binat is off) but
    // still gets helper lines; the nat rule maps out only
    assert_eq!(
        lines[lab.len()],
        "binat on igc0 from 192.168.1.20 to any -> 203.0.113.20 # Game server"
    );
    assert!(
        !lines
            .iter()
            .any(|l| l.starts_with("rdr") && l.contains("Game"))
    );
    assert_eq!(
        lines.iter().filter(|l| l.contains("# Game server")).count(),
        6
    );
    assert!(lines.contains(
        &"nat log on igc0 from (vlan01:network) to 198.51.100.0/24 -> 203.0.113.30 # IoT to vendor cloud"
    ));
    // 1:1 sits between the anti-lockout no-rdr (300) and port forwards (600)
    let heads: Vec<&str> = out
        .pf
        .lines()
        .filter(|l| l.starts_with("# [prio:"))
        .collect();
    let at = |h: &str| heads.iter().position(|x| *x == h).unwrap();
    assert!(at("# [prio: 300]") < at("# [prio: 500]"));
    assert!(at("# [prio: 500]") < at("# [prio: 600]"));
}

#[test]
fn one_to_one_nft_keeps_pf_translation_order() {
    let out = render(&with_one_to_one(), &runtime());
    let post = chain(&out.nft, "nat_post");
    let pre = chain(&out.nft, "nat_pre");
    // outbound: binat before every nat rule, the CARP exemption included
    let binat_out = position(&post, "Lab /28");
    assert_eq!(binat_out, 0, "{}", post.join("\n"));
    assert!(post[0].contains(r#""oifname"}},"right":"igc0""#));
    assert!(post[0].contains(
        r#"{"snat":{"family":"ip","addr":{"prefix":{"addr":"203.0.113.16","len":28}},"flags":["netmap"],"type_flags":["prefix"]}}"#
    ));
    assert!(post[1].contains(r#"{"snat":{"family":"ip","addr":"203.0.113.20"}}"#));
    assert!(post[1].contains("Game server"));
    let carp = position(&post, r#""right":112"#);
    assert_eq!(carp, 2);
    let manual = position(&post, "Road warrior");
    let auto = position(&post, "Automatic outbound rule");
    let iot = position(&post, "IoT to vendor cloud");
    let hairpin = position(&post, "HTTPS to NAS");
    // type nat is a nat rule at 500: after manual (100) and automatic (200)
    // outbound rules, before the forward hairpins (600)
    assert!(carp < manual && manual < auto && auto < iot && iot < hairpin);
    assert!(post[iot].contains(r#""log""#));
    assert!(post[iot].contains(r#"{"snat":{"family":"ip","addr":"203.0.113.30"}}"#));
    // helper masquerade for the reflected /28, on each internal interface
    assert_eq!(count(&post, "masquerade\":null}] # Lab /28"), 5);

    // inbound: rdr rules (anti-lockout, 1:1 reflection at 500, forwards at
    // 600) first, binat last
    let lockout = position(&pre, "Anti-lockout");
    let refl = position(
        &pre,
        r#"{"dnat":{"family":"ip","addr":{"prefix":{"addr":"192.168.1.32","len":28}}"#,
    );
    let fwd = position(&pre, "HTTPS to NAS");
    assert!(lockout < refl && refl < fwd, "{}", pre.join("\n"));
    assert_eq!(count(&pre, "Lab /28"), 5); // 4 reflections + the binat
    let last = &pre[pre.len() - 2..];
    assert!(last[0].contains("Lab /28") && last[0].contains(r#""iifname"}},"right":"igc0""#));
    assert!(last[0].contains(r#""daddr"}},"right":{"prefix":{"addr":"203.0.113.16","len":28}}"#));
    assert!(last[1].contains("Game server"));
    assert!(last[1].contains(r#"{"dnat":{"family":"ip","addr":"192.168.1.20"}}"#));
    // outbound-only: no inbound translation
    assert_eq!(count(&pre, "IoT to vendor cloud"), 0);
}

#[test]
fn corpus_one_to_one_rules() {
    let out = render(&corpus(), &runtime());
    let lines = prio(&out.pf, 500);
    assert_eq!(
        lines[..2],
        [
            "binat on igc0 from 192.168.1.40 to any -> 203.0.113.40 # Game server on its own public address",
            "rdr on igc1 from {any} to {203.0.113.40} -> {192.168.1.40} bitmask # Game server on its own public address",
        ]
    );
    // the paused rule: commented out, no reflection or helper lines
    assert_eq!(
        lines.last().unwrap(),
        &"# nat log on igc0 from (vlan01:network) to 198.51.100.0/24 -> 203.0.113.50 # IoT to the vendor cloud from a fixed address (paused)"
    );
    assert_eq!(count(&chain(&out.nft, "nat_post"), "203.0.113.50"), 0);
}

#[test]
fn one_to_one_reflection_follows_global_and_rule() {
    // global reflection_binat on, the rule says disable: no rdr copies
    let mut doc = with_one_to_one();
    doc.nat.reflection.one_to_one = true;
    let lab = *doc.nat.one_to_one.keys().nth(1).unwrap();
    doc.nat.one_to_one.get_mut(&lab).unwrap().reflection =
        Some(sensr_schema::models::nat::OneToOneReflection::Disable);
    let out = render(&doc, &runtime());
    let lines = prio(&out.pf, 500);
    assert!(
        !lines
            .iter()
            .any(|l| l.starts_with("rdr") && l.contains("Lab"))
    );
    // the host rule inherits the global default now
    assert!(lines.contains(
        &"rdr on igc1 from {any} to {203.0.113.20} -> {192.168.1.20} bitmask # Game server"
    ));
    // the nat type is reflected too (upstream does not tell the types apart)
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("rdr on igc1") && l.contains("IoT"))
    );
    // reflecting a nat rule onto an interface network cannot be lowered
    assert!(
        out.warnings
            .iter()
            .any(|w| w.contains("1:1 reflection needs a literal internal address")),
        "{:?}",
        out.warnings
    );

    // helper source NAT off: no helper lines at all
    doc.nat.reflection.source_nat = false;
    let out = render(&doc, &runtime());
    assert!(
        !prio(&out.pf, 500)
            .iter()
            .any(|l| l.contains("port 1024:65535"))
    );
}

#[test]
fn disabled_one_to_one_is_commented_and_not_loaded() {
    let mut doc = home_router();
    doc.nat.one_to_one.push(one_to_one(json!({
        "enabled": false,
        "interface": "wan",
        "external": "203.0.113.20",
        "source": {"net": "192.168.1.20"},
        "reflection": "enable",
    })));
    let out = render(&doc, &runtime());
    assert_eq!(
        prio(&out.pf, 500),
        ["# binat on igc0 from 192.168.1.20 to any -> 203.0.113.20"]
    );
    assert_eq!(count(&chain(&out.nft, "nat_post"), "203.0.113.20"), 0);
}

#[test]
fn hybrid_outbound_manual_rules_precede_automatic() {
    let doc = home_router();
    assert_eq!(doc.nat.outbound.mode, OutboundNatMode::Hybrid);
    let out = render(&doc, &runtime());
    assert_eq!(
        prio(&out.pf, 100),
        [
            "nat on igc0 inet from 10.10.10.0/24 to any -> (igc0:0) port 1024:65535 # Road warrior tunnel out via WAN"
        ]
    );
    let auto = prio(&out.pf, 200);
    // per WAN: the IKE (udp/500, static-port) block, then the rest, each
    // over every gateway-less network plus loopback
    assert_eq!(auto.len(), 10);
    assert_eq!(
        auto[0],
        "nat on igc0 inet from (igc1:network) to any port 500 -> (igc0:0) static-port # Automatic outbound rule"
    );
    assert_eq!(
        auto[9],
        "nat on igc0 inet from 127.0.0.0/8 to any -> (igc0:0) port 1024:65535 # Automatic outbound rule"
    );
    let post = chain(&out.nft, "nat_post");
    assert!(post[0].contains(r#""right":112"#));
    assert!(post[1].contains("Road warrior"));
    assert!(post[1].contains(r#"{"masquerade":null}"#));
    assert_eq!(count(&post[2..12], "Automatic outbound rule"), 10);

    // automatic mode ignores the manual rule, manual mode the automatic ones
    let mut auto_doc = home_router();
    auto_doc.nat.outbound.mode = OutboundNatMode::Automatic;
    let out = render(&auto_doc, &runtime());
    assert!(prio(&out.pf, 100).is_empty());
    assert_eq!(count(&chain(&out.nft, "nat_post"), "Road warrior"), 0);
    let mut manual = home_router();
    manual.nat.outbound.mode = OutboundNatMode::Manual;
    let out = render(&manual, &runtime());
    assert!(!out.pf.contains("Automatic outbound rule"));
    assert_eq!(count(&chain(&out.nft, "nat_post"), "Road warrior"), 1);
}

/// The reflection copies (`rdr` lines) and hairpins (`nat` lines) of the
/// NAS forward.
fn forward_lines(pf: &str) -> (Vec<String>, Vec<String>) {
    let lines = prio(pf, 600);
    let own = |f: fn(&str) -> bool| {
        lines
            .iter()
            .filter(|l| f(l))
            .map(|l| l.to_string())
            .collect()
    };
    (own(|l| l.contains("rdr ")), own(|l| l.starts_with("nat ")))
}

#[test]
fn forward_reflection_purenat_and_enable_are_the_same() {
    // upstream ForwardRule treats both as "reflect"; FreeBSD's NAT+proxy
    // mode does not exist in OPNsense
    let mut doc = home_router();
    let purenat = render(&doc, &runtime());
    forward(&mut doc).reflection = Some(ReflectionMode::Enable);
    let enable = render(&doc, &runtime());
    assert_eq!(purenat.pf, enable.pf);
    assert_eq!(purenat.nft, enable.nft);
    let (rdr, nat) = forward_lines(&purenat.pf);
    assert_eq!(
        rdr,
        [
            "rdr pass on igc0 inet proto tcp from {any} to {(igc0)} port {443} -> $NAS_HOST port 443 # HTTPS to NAS reverse proxy",
            "rdr pass on igc1 inet proto tcp from {any} to {(igc0)} port {443} -> $NAS_HOST port 443 # HTTPS to NAS reverse proxy",
            "rdr pass on vlan01 inet proto tcp from {any} to {(igc0)} port {443} -> $NAS_HOST port 443 # HTTPS to NAS reverse proxy",
            "rdr pass on vlan02 inet proto tcp from {any} to {(igc0)} port {443} -> $NAS_HOST port 443 # HTTPS to NAS reverse proxy",
            "rdr pass on wg0 inet proto tcp from {any} to {(igc0)} port {443} -> $NAS_HOST port 443 # HTTPS to NAS reverse proxy",
        ]
    );
    assert_eq!(nat.len(), 5);
}

#[test]
fn forward_reflection_rule_overrides_global() {
    // global on, rule disable: only the forward itself (plus its own-
    // interface helper, which follows the global source-NAT switch)
    let mut doc = home_router();
    forward(&mut doc).reflection = Some(ReflectionMode::Disable);
    let (rdr, nat) = forward_lines(&render(&doc, &runtime()).pf.clone());
    assert_eq!(rdr.len(), 1);
    assert_eq!(
        nat,
        [
            "nat on igc0 inet proto tcp from (igc0:network) to $NAS_HOST port {443} -> (igc0) port 1024:65535 # HTTPS to NAS reverse proxy"
        ]
    );

    // global off, rule unset: no reflection
    let mut doc = home_router();
    doc.nat.reflection.port_forwards = false;
    forward(&mut doc).reflection = None;
    let (rdr, _) = forward_lines(&render(&doc, &runtime()).pf.clone());
    assert_eq!(rdr.len(), 1);

    // global off, rule purenat: reflected
    let mut doc = home_router();
    doc.nat.reflection.port_forwards = false;
    let (rdr, _) = forward_lines(&render(&doc, &runtime()).pf.clone());
    assert_eq!(rdr.len(), 5);

    // global on, rule unset: reflected
    let mut doc = home_router();
    forward(&mut doc).reflection = None;
    let (rdr, _) = forward_lines(&render(&doc, &runtime()).pf.clone());
    assert_eq!(rdr.len(), 5);
}

#[test]
fn forward_reflection_without_source_nat_has_no_hairpin() {
    let mut doc = home_router();
    doc.nat.reflection.source_nat = false;
    let out = render(&doc, &runtime());
    let (rdr, nat) = forward_lines(&out.pf);
    assert_eq!(rdr.len(), 5);
    assert!(nat.is_empty());
    assert_eq!(count(&chain(&out.nft, "nat_post"), "HTTPS to NAS"), 0);
    // the reflected copies still redirect (and mark for `rdr pass`)
    let pre = chain(&out.nft, "nat_pre");
    assert_eq!(count(&pre, "HTTPS to NAS"), 5);
    // anti-lockout: 3 ports x 2 families, then the reflected forward
    assert_eq!(count(&pre, r#""iifname"}},"right":"igc1""#), 7);
}

#[test]
fn forward_reflection_of_a_shifted_port_range() {
    let mut doc = home_router();
    let f = forward(&mut doc);
    f.destination.port = Some("8000-8002".parse().unwrap());
    f.target_port = Some("9000".parse().unwrap());
    let out = render(&doc, &runtime());
    let (rdr, nat) = forward_lines(&out.pf);
    assert_eq!(
        rdr[1],
        "rdr pass on igc1 inet proto tcp from {any} to {(igc0)} port {8000:8002} -> $NAS_HOST port 9000:9002 # HTTPS to NAS reverse proxy"
    );
    assert_eq!(
        nat[1],
        "nat on igc1 inet proto tcp from (igc1:network) to $NAS_HOST port {9000:9002} -> (igc1) port 1024:65535 # HTTPS to NAS reverse proxy"
    );
    let pre = chain(&out.nft, "nat_pre");
    // one dnat per port keeps the offset: 3 per interface, 5 interfaces
    assert_eq!(count(&pre, "HTTPS to NAS"), 15);
    assert_eq!(
        count(&pre, r#""right":8001}},{"counter":null},{"mangle"#),
        5,
        "{}",
        pre.join("\n")
    );
    let post = chain(&out.nft, "nat_post");
    assert_eq!(
        count(&post, r#""right":{"range":[9000,9002]}"#),
        5,
        "{}",
        post.join("\n")
    );
}

#[test]
fn forward_reflection_to_an_alias_pool() {
    let mut doc = home_router();
    let (_, nas) = doc
        .firewall
        .aliases
        .iter_mut()
        .find(|(_, a)| a.name.as_str() == "NAS_HOST")
        .unwrap();
    let mut v = serde_json::to_value(&*nas).unwrap();
    v["content"]["entries"] = json!(["192.168.1.10", "192.168.1.11"]);
    *nas = serde_json::from_value(v).unwrap();
    let out = render(&doc, &runtime());
    let pre = chain(&out.nft, "nat_pre");
    // round-robin over both members on every reflected interface
    assert_eq!(count(&pre, r#""numgen""#), 5, "{}", pre.join("\n"));
    let post = chain(&out.nft, "nat_post");
    assert_eq!(
        count(&post, r#""right":{"set":["192.168.1.10","192.168.1.11"]}"#),
        5,
        "{}",
        post.join("\n")
    );
}

#[test]
fn forward_reflection_on_several_interfaces() {
    // each expansion is reflected onto the gateway-less interfaces other
    // than its own (upstream does not de-duplicate across expansions)
    let mut doc = home_router();
    forward(&mut doc).interfaces = vec!["wan".parse().unwrap(), "opt2".parse().unwrap()];
    let (rdr, _) = forward_lines(&render(&doc, &runtime()).pf.clone());
    let on = |dev: &str| {
        rdr.iter()
            .filter(|l| l.contains(&format!(" on {dev} ")))
            .count()
    };
    assert_eq!(rdr.len(), 5 + 4);
    assert_eq!(on("igc0"), 1);
    assert_eq!(on("vlan02"), 2); // the opt2 forward itself, a wan reflection
    assert_eq!(on("igc1"), 2);
}

#[test]
fn forward_reflection_ipv6() {
    let mut doc = home_router();
    let f = forward(&mut doc);
    f.ip_protocol = sensr_schema::fields::IpFamily::Inet6;
    f.target = "2001:db8:1::10".parse().unwrap();
    let mut rt = runtime();
    rt.addrs
        .get_mut("wan")
        .unwrap()
        .push(addr("2001:db8::2/64"));
    rt.addrs
        .insert("lan".into(), vec![addr("2001:db8:1::1/64")]);
    let out = render(&doc, &rt);
    let (rdr, nat) = forward_lines(&out.pf);
    // only interfaces with IPv6 reflect: lan (its tracked prefix) and the
    // WireGuard tunnel; opt1 tracks too but has no address yet
    assert_eq!(
        rdr,
        [
            "rdr pass on igc0 inet6 proto tcp from {any} to {(igc0)} port {443} -> 2001:db8:1::10 port 443 # HTTPS to NAS reverse proxy",
            "rdr pass on igc1 inet6 proto tcp from {any} to {(igc0)} port {443} -> 2001:db8:1::10 port 443 # HTTPS to NAS reverse proxy",
            "rdr pass on wg0 inet6 proto tcp from {any} to {(igc0)} port {443} -> 2001:db8:1::10 port 443 # HTTPS to NAS reverse proxy",
        ]
    );
    assert_eq!(nat.len(), 3);
    let pre = chain(&out.nft, "nat_pre");
    assert!(pre.iter().any(|r| r.contains("HTTPS to NAS")
        && r.contains(r#""right":"igc1""#)
        && r.contains(r#""right":"@if_wan_a6""#)
        && r.contains(r#"{"dnat":{"family":"ip6","addr":"2001:db8:1::10","port":443}}"#)));
    let post = chain(&out.nft, "nat_post");
    assert!(post.iter().any(|r| r.contains("HTTPS to NAS")
        && r.contains(r#""right":"@if_lan_n6""#)
        && r.contains(r#""right":"2001:db8:1::10""#)));
}
