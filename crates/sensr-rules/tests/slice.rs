//! The routing vertical slice (M-slice) ruleset: a home router with DHCP WAN,
//! static LAN, Kea on LAN, OPNsense's default LAN rules, automatic outbound
//! NAT and one reflected port forward. pf oracle + nft golden; CI loads the
//! nft golden with `nft -c -j -f`.

mod common;

use std::collections::BTreeMap;

use sensr_rules::conf;
use sensr_rules::ir::{IfAddr, Interface, InterfaceMap, V4Mode, V6Mode};
use sensr_rules::nat::{self, NatRules, OutboundMode, ReflectionDefaults};
use sensr_rules::normalize::Context;
use sensr_rules::render::{nft, pf};
use sensr_rules::ruleset::Ruleset;
use sensr_rules::system_rules::{self, SystemSettings};

fn interfaces() -> InterfaceMap {
    let mut ifs = InterfaceMap::new();
    ifs.insert(
        "wan".into(),
        Interface {
            device: "eth0".into(),
            descr: "WAN".into(),
            gateway_v4: true,
            v4: V4Mode::Dhcp,
            v6: V6Mode::Dhcp6,
            block_private: true,
            block_bogons: true,
            ..Default::default()
        },
    );
    ifs.insert(
        "lan".into(),
        Interface {
            device: "eth1".into(),
            descr: "LAN".into(),
            addrs: vec![IfAddr {
                addr: "192.168.1.1".parse().unwrap(),
                prefix_len: 24,
            }],
            v4: V4Mode::Static,
            v6: V6Mode::Track6,
            dhcp4_server: true,
            ..Default::default()
        },
    );
    ifs
}

struct Slice {
    ifs: InterfaceMap,
    filter: Ruleset,
    nat: NatRules,
}

fn build() -> Slice {
    let ifs = interfaces();
    let aliases = BTreeMap::new();
    let ctx = Context {
        interfaces: &ifs,
        aliases: &aliases,
    };
    let settings = SystemSettings {
        ssh: Some(22),
        kea4_interfaces: vec!["lan".into()],
        ..SystemSettings::default()
    };
    let mut filter = Ruleset::default();
    system_rules::register(&mut filter, &settings, &ctx);

    // OPNsense factory LAN rules (config.xml.sample)
    for fam in ["inet", "inet6"] {
        let rule = conf! {
            "type" => "pass", "interface" => "lan", "ipprotocol" => fam,
            "statetype" => "keep state",
            "descr" => format!("Default allow LAN {}to any rule", if fam == "inet6" { "IPv6 " } else { "" }),
            "source" => conf! { "network" => "lan" },
            "destination" => conf! { "any" => "" },
        };
        let mut r = rule.clone();
        r.set("label", sensr_rules::conf::calc_rule_hash(&rule));
        filter.register_filter(400_000, &r, None, &ctx);
    }

    let forward = conf! {
        "interface" => "wan", "ipprotocol" => "inet", "protocol" => "tcp",
        "destination" => conf! { "network" => "wanip", "port" => "443" },
        "target" => "192.168.1.10", "local-port" => "8443",
        "pass" => "rule", "descr" => "web server",
    };
    let mut nat_rules = NatRules::default();
    let lockout = system_rules::anti_lockout(&settings, &ctx);
    nat_rules
        .rdr
        .extend(nat::anti_lockout_nordr(lockout.as_ref(), &ctx));
    nat_rules.rdr.extend(nat::rdr_rules(
        &forward,
        600,
        ReflectionDefaults {
            port_forwards: true,
            source_nat: true,
        },
        &ctx,
    ));
    if let Some(f) = nat::forward_filter_rule(&forward) {
        filter.register_filter(500_000, &f, None, &ctx);
    }
    nat::automatic_outbound(OutboundMode::Automatic, false, &ctx, &mut nat_rules.snat);
    nat_rules.sort();
    Slice {
        ifs,
        filter,
        nat: nat_rules,
    }
}

#[test]
fn slice_pf_oracle() {
    let s = build();
    let mut rules = s.filter.rules.clone();
    rules.sort_by_key(|r| r.priority);
    let text = format!(
        "{}{}",
        pf::nat_rules(&s.nat, &s.ifs),
        pf::filter_rules(&rules, &s.ifs)
    );
    common::golden_text("slice.pf", &text);
}

#[test]
fn slice_nft() {
    let s = build();
    let aliases = BTreeMap::new();
    let policy = nft::Policy {
        rules: &s.filter.rules,
        interfaces: &s.ifs,
        aliases: &aliases,
        nat: Some(&s.nat),
    };
    let mut buf = Vec::new();
    let report = nft::render(&policy, &nft::Options::default(), &mut buf).unwrap();
    common::golden_json("slice", &buf);
    // only pf-only state features degrade; nothing is skipped
    assert!(
        report
            .warnings
            .iter()
            .all(|w| !w.message.contains("skipped")),
        "{:#?}",
        report.warnings
    );
}

#[test]
fn anti_lockout_picks_lan_and_sorts_ports() {
    let s = build();
    let aliases = BTreeMap::new();
    let ctx = Context {
        interfaces: &s.ifs,
        aliases: &aliases,
    };
    let settings = SystemSettings {
        ssh: Some(2222),
        ..SystemSettings::default()
    };
    assert_eq!(
        system_rules::anti_lockout(&settings, &ctx),
        Some(("lan".into(), vec!["80".into(), "443".into(), "2222".into()]))
    );
}

/// DHCP gives the WAN an address: only the interface sets change. The golden
/// is the ruleset followed by the update in one transaction, so `nft -c`
/// checks the update against the sets it targets.
#[test]
fn wan_address_update_is_a_set_update() {
    let s = build();
    let aliases = BTreeMap::new();
    let policy = nft::Policy {
        rules: &s.filter.rules,
        interfaces: &s.ifs,
        aliases: &aliases,
        nat: Some(&s.nat),
    };
    let mut base = Vec::new();
    nft::render(&policy, &nft::Options::default(), &mut base).unwrap();
    let mut wan = s.ifs["wan"].clone();
    wan.addrs.push(IfAddr {
        addr: "203.0.113.2".parse().unwrap(),
        prefix_len: 24,
    });
    let mut upd = Vec::new();
    nft::render_set_updates("sensr", &nft::interface_set_updates("wan", &wan), &mut upd).unwrap();
    let text = String::from_utf8(upd.clone()).unwrap();
    assert!(
        text.contains(r#"{"flush":{"set":{"family":"inet","table":"sensr","name":"if_wan_a4"}}}"#)
    );
    assert!(text.contains(r#""elem":["203.0.113.2"]"#), "{text}");
    // splice: base commands, then the update's (minus its metainfo)
    let base_s = String::from_utf8(base).unwrap();
    let upd_cmds = text
        .trim_start_matches(r#"{"nftables":[{"metainfo":{"json_schema_version":1}},"#)
        .trim_end_matches("]}");
    let combined = format!("{},{}]}}", base_s.trim_end_matches("]}"), upd_cmds);
    common::golden_json("slice-wan-update", combined.as_bytes());
}
