//! Rule evaluation order across priority tiers (`FilterRuleField::getPriority`):
//! floating and multi-interface rules, then interface groups (by the group's
//! sequence), then single-interface rules; `sequence` only orders rules within
//! a tier. The owner's outbound blocklists depend on it: they sit on a
//! `lan,opt1` rule with a higher sequence than "Allow LAN to any", and still
//! win.

use std::str::FromStr;

use sensr_rules::document::{self, Runtime};
use sensr_schema::Document;
use sensr_schema::Uuid;
use sensr_schema::fields::{InterfaceId, NetOrAlias};
use sensr_schema::models::firewall::{Endpoint, FilterRule, InterfaceGroup, RuleAction};

fn home_router() -> Document {
    let path = format!(
        "{}/../sensr-import-opnsense/tests/golden/home-router.sensr.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect("importer golden"))
        .expect("document")
}

fn id(s: &str) -> Uuid {
    Uuid::from_str(s).unwrap()
}

const LAN_ALLOW: &str = "1aac7ca4-2950-47cf-af32-f24f076f55a2";
const BLOCKLIST: &str = "4b0d1c55-9e1a-4f7e-8a51-0c1f2f6f1a01";
const GROUP_RULE: &str = "00000000-0000-4000-8000-00000000a001";
const LATE_GROUP_RULE: &str = "00000000-0000-4000-8000-00000000a002";

/// The home-router document with the order turned upside down by sequence:
/// "Allow LAN to any" first, the multi-interface blocklist last, plus two
/// interface-group rules in between.
fn upside_down() -> Document {
    let mut doc = home_router();
    let rules = &mut doc.firewall.rules;
    rules.get_mut(&id(LAN_ALLOW)).unwrap().sequence = 1;
    rules.get_mut(&id(BLOCKLIST)).unwrap().sequence = 9_000;
    let lan: InterfaceId = "lan".parse().unwrap();
    for (name, seq) in [("trusted", 7), ("early", 3)] {
        doc.firewall.groups.push(InterfaceGroup {
            name: name.parse().unwrap(),
            members: vec![lan.clone()],
            wireguard: false,
            sequence: seq,
            hidden: false,
            description: None,
        });
    }
    let block_to = |group: &str, net: &str, seq: u32| FilterRule {
        sequence: seq,
        action: RuleAction::Block,
        interfaces: vec![group.parse().unwrap()],
        destination: Endpoint::net(NetOrAlias::from_str(net).unwrap()),
        ..FilterRule::default()
    };
    // group "trusted" (sequence 7) comes after group "early" (sequence 3),
    // whatever the rules' own sequence numbers say; a different shape keeps
    // the two out of one verdict map, so each keeps its own label
    let mut smtp = block_to("trusted", "198.51.100.7", 2);
    smtp.protocol = sensr_schema::fields::Protocol::Tcp;
    smtp.destination.port = Some("25".parse().unwrap());
    doc.firewall.rules.insert(id(GROUP_RULE), smtp);
    doc.firewall.rules.insert(
        id(LATE_GROUP_RULE),
        block_to("early", "198.51.100.3", 8_000),
    );
    let v = doc.validate();
    assert!(v.is_empty(), "{v:?}");
    doc
}

/// Labels of the rules in `chain`, in nft order (first appearance).
fn chain_labels(json: &[u8], chain: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_slice(json).unwrap();
    let mut out: Vec<String> = Vec::new();
    for cmd in v["nftables"].as_array().unwrap() {
        let r = &cmd["add"]["rule"];
        if r["chain"] != chain {
            continue;
        }
        if let Some(c) = r["comment"].as_str()
            && !out.iter().any(|o| o == c)
        {
            out.push(c.to_owned());
        }
    }
    out
}

fn pos(labels: &[String], l: &str) -> usize {
    labels
        .iter()
        .position(|x| x == l)
        .unwrap_or_else(|| panic!("{l} not in {labels:?}"))
}

#[test]
fn tiers_before_sequence_in_the_nft_chain() {
    let doc = upside_down();
    let c = document::compile(&doc, &Runtime::default());
    let mut buf = Vec::new();
    c.render_nft(&mut buf).unwrap();
    let lan = chain_labels(&buf, "in_lan");
    // floating/multi-interface (200000) < group "early" (300003) <
    // group "trusted" (300007) < interface (400000)
    let order = [BLOCKLIST, LATE_GROUP_RULE, GROUP_RULE, LAN_ALLOW];
    let at: Vec<usize> = order.iter().map(|l| pos(&lan, l)).collect();
    assert!(at.windows(2).all(|w| w[0] < w[1]), "in_lan order {lan:?}");
    // the same multi-interface rule leads opt1's chain too
    let opt1 = chain_labels(&buf, "in_opt1");
    assert!(pos(&opt1, BLOCKLIST) < pos(&opt1, "e3d0f852-1cea-4e20-9ad7-cbe26eee9ad7"));
}

#[test]
fn tiers_before_sequence_in_the_pf_oracle() {
    let c = document::compile(&upside_down(), &Runtime::default());
    let pf = c.render_pf();
    let at = |label: &str| {
        pf.find(&format!("label \"{label}\""))
            .unwrap_or_else(|| panic!("{label} missing from\n{pf}"))
    };
    assert!(at(BLOCKLIST) < at(LATE_GROUP_RULE));
    assert!(at(LATE_GROUP_RULE) < at(GROUP_RULE));
    assert!(at(GROUP_RULE) < at(LAN_ALLOW));
    for prio in ["200000", "300003", "300007", "400000"] {
        assert!(pf.contains(&format!("# [prio: {prio}]")), "{prio}");
    }
}

#[test]
fn priority_tiers_match_get_priority() {
    let doc = upside_down();
    let fw = &doc.firewall;
    let known = |i: &InterfaceId| doc.interfaces.get(i).is_some();
    let rule = |u: &str| fw.rules.get(&id(u)).unwrap();
    assert_eq!(fw.priority(rule(BLOCKLIST), known), 200_000);
    assert_eq!(fw.priority(rule(GROUP_RULE), known), 300_007);
    assert_eq!(fw.priority(rule(LATE_GROUP_RULE), known), 300_003);
    assert_eq!(fw.priority(rule(LAN_ALLOW), known), 400_000);
    let floating = FilterRule::default();
    assert_eq!(fw.priority(&floating, known), 200_000);
    let inverted = FilterRule {
        interfaces: vec!["lan".parse().unwrap()],
        interface_not: true,
        ..FilterRule::default()
    };
    assert_eq!(fw.priority(&inverted, known), 200_000);
    let legacy_floating = FilterRule {
        interfaces: vec!["lan".parse().unwrap()],
        floating: true,
        ..FilterRule::default()
    };
    assert_eq!(fw.priority(&legacy_floating, known), 200_000);
    let nowhere = FilterRule {
        interfaces: vec!["opt9".parse().unwrap()],
        ..FilterRule::default()
    };
    assert_eq!(fw.priority(&nowhere, known), 600_000);
}

#[test]
fn wireguard_group_covers_every_instance() {
    let doc = home_router();
    let wg = doc
        .firewall
        .group(&"wireguard".parse().unwrap())
        .expect("imported wireguard group");
    assert!(wg.wireguard);
    let mut doc = doc.clone();
    doc.firewall.rules.insert(
        id(GROUP_RULE),
        FilterRule {
            interfaces: vec!["wireguard".parse().unwrap()],
            destination: Endpoint::net(NetOrAlias::from_str("198.51.100.9").unwrap()),
            action: RuleAction::Block,
            ..FilterRule::default()
        },
    );
    let c = document::compile(&doc, &Runtime::default());
    let mut buf = Vec::new();
    c.render_nft(&mut buf).unwrap();
    // opt3 is the assigned WireGuard interface (wg0)
    assert!(chain_labels(&buf, "in_opt3").contains(&GROUP_RULE.to_owned()));
    assert!(!chain_labels(&buf, "in_lan").contains(&GROUP_RULE.to_owned()));
}

#[test]
fn disabled_alias_matches_nothing() {
    let doc = home_router();
    let c = document::compile(&doc, &Runtime::default());
    // PAUSED_FEED is disabled: an empty set, not a fetch failure
    assert!(c.aliases.aliases["PAUSED_FEED"].nets.is_empty());
    assert!(!c.aliases.failed.contains("PAUSED_FEED"));
    let mut buf = Vec::new();
    c.render_nft(&mut buf).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
    let set = v["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["add"]["set"].as_object())
        .find(|s| {
            s["name"]
                .as_str()
                .is_some_and(|n| n.contains("PAUSED_FEED"))
        })
        .expect("PAUSED_FEED set");
    assert!(
        set.get("elem")
            .is_none_or(|e| e.as_array().is_some_and(|a| a.is_empty()))
    );
}
