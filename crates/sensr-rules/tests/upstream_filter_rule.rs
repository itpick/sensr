//! Upstream `Firewall/FilterRuleTest` (T-0006..T-0008): the pf oracle must be
//! byte-exact with the upstream `.conf` fixtures, and the nft renderer has a
//! sibling golden per test that CI loads with `nft -c -j -f`.

mod common;

use std::collections::BTreeMap;

use sensr_rules::conf;
use sensr_rules::conf::{Conf, Value};
use sensr_rules::ir::{FilterRule, InterfaceMap};
use sensr_rules::normalize::{self, Context};
use sensr_rules::render::{nft, pf};

/// Like upstream, rules are built directly (no registration, so no label).
fn rules(confs: &[Conf]) -> Vec<FilterRule> {
    let ifs = InterfaceMap::new();
    let aliases = BTreeMap::new();
    let ctx = Context {
        interfaces: &ifs,
        aliases: &aliases,
    };
    confs
        .iter()
        .flat_map(|c| normalize::filter_rule(c, 0, &ctx))
        .collect()
}

fn pf_text(rules: &[FilterRule]) -> String {
    let ifs = InterfaceMap::new();
    let mut out = String::new();
    for r in rules {
        pf::filter_rule(r, &ifs, &mut out);
    }
    out
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/opnsense/FilterRuleTest/{name}.conf",
        env!("CARGO_MANIFEST_DIR")
    ))
    .expect("fixture")
}

fn nft_golden(name: &str, rules: &[FilterRule]) {
    let ifs = InterfaceMap::new();
    let aliases = BTreeMap::new();
    let policy = nft::Policy {
        rules,
        interfaces: &ifs,
        aliases: &aliases,
        nat: None,
        routing: None,
        host_modes: None,
    };
    let mut buf = Vec::new();
    let report = nft::render(&policy, &nft::Options::default(), &mut buf).expect("render");
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    common::golden_json(name, &buf);
}

fn direction_rules() -> Vec<FilterRule> {
    rules(&[
        conf! {},
        conf! { "direction" => "" },
        conf! { "direction" => Value::Null },
        conf! { "direction" => "in" },
        conf! { "direction" => "out" },
        conf! { "direction" => "any" },
    ])
}

fn icmp_rules() -> Vec<FilterRule> {
    rules(&[
        conf! { "icmp-type" => "mobregreq,skip,2" },
        conf! { "icmp-type" => "skip,2" },
        conf! { "icmp-type" => "2" },
        conf! { "icmp-type" => "" },
    ])
}

fn protocol_rules() -> Vec<FilterRule> {
    rules(&[
        conf! { "protocol" => "" },
        conf! { "protocol" => "tcp" },
        conf! { "protocol" => "tcp/udp" },
        conf! { "protocol" => "skip" },
        conf! { "protocol" => "a/n" },
    ])
}

#[test]
fn pf_direction_t0006() {
    assert_eq!(pf_text(&direction_rules()), fixture("testDirection"));
}

#[test]
fn nft_direction_t0006() {
    nft_golden("direction", &direction_rules());
}

#[test]
fn pf_icmp_t0007() {
    assert_eq!(pf_text(&icmp_rules()), fixture("testIcmp"));
}

#[test]
fn nft_icmp_t0007() {
    nft_golden("icmp", &icmp_rules());
}

#[test]
fn pf_protocol_t0008() {
    assert_eq!(pf_text(&protocol_rules()), fixture("testProtocol"));
}

#[test]
fn nft_protocol_t0008() {
    nft_golden("protocol", &protocol_rules());
}
