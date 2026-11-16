//! nft renderer goldens for each IR feature (one golden per row of
//! docs/pf-to-nft.md), all loaded by CI with `nft -c -j -f`.

mod common;

use std::collections::BTreeMap;

use sensr_rules::conf;
use sensr_rules::conf::Conf;
use sensr_rules::ir::{AliasClass, FilterRule, IfAddr, Interface, InterfaceMap, V4Mode};
use sensr_rules::normalize::{AliasInfo, Context};
use sensr_rules::render::nft::{self, Options, ResolvedAlias};
use sensr_rules::render::pf;
use sensr_rules::ruleset::Ruleset;

fn interfaces() -> InterfaceMap {
    let mut ifs = InterfaceMap::new();
    ifs.insert(
        "wan".into(),
        Interface {
            device: "eth0".into(),
            descr: "WAN".into(),
            gateway_v4: true,
            v4: V4Mode::Dhcp,
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
            addrs: vec![
                IfAddr {
                    addr: "192.168.1.1".parse().unwrap(),
                    prefix_len: 24,
                },
                IfAddr {
                    addr: "fd00:1::1".parse().unwrap(),
                    prefix_len: 64,
                },
            ],
            v4: V4Mode::Static,
            dhcp4_server: true,
            ..Default::default()
        },
    );
    ifs
}

fn aliases() -> (BTreeMap<String, AliasInfo>, BTreeMap<String, ResolvedAlias>) {
    let mut info = BTreeMap::new();
    let mut resolved = BTreeMap::new();
    info.insert(
        "admins".to_owned(),
        AliasInfo {
            class: AliasClass::Address,
            empty: false,
        },
    );
    resolved.insert(
        "admins".to_owned(),
        ResolvedAlias {
            nets: vec![
                "192.168.1.10/32".parse().unwrap(),
                "192.168.1.32/28".parse().unwrap(),
                "fd00:1::10/128".parse().unwrap(),
            ],
            ports: vec![],
        },
    );
    info.insert(
        "web".to_owned(),
        AliasInfo {
            class: AliasClass::Port,
            empty: false,
        },
    );
    resolved.insert(
        "web".to_owned(),
        ResolvedAlias {
            nets: vec![],
            ports: vec![(80, 80), (443, 443), (8000, 8099)],
        },
    );
    (info, resolved)
}

struct Fixture {
    ifs: InterfaceMap,
    info: BTreeMap<String, AliasInfo>,
    resolved: BTreeMap<String, ResolvedAlias>,
}

impl Fixture {
    fn new() -> Fixture {
        let (info, resolved) = aliases();
        Fixture {
            ifs: interfaces(),
            info,
            resolved,
        }
    }

    fn rules(&self, confs: &[(u32, Conf)]) -> Vec<FilterRule> {
        let ctx = Context {
            interfaces: &self.ifs,
            aliases: &self.info,
        };
        let mut rs = Ruleset::default();
        for (prio, c) in confs {
            rs.register_filter(*prio, c, None, &ctx);
        }
        rs.rules
    }

    fn golden(&self, name: &str, rules: &[FilterRule], opts: &Options) -> nft::Report {
        let policy = nft::Policy {
            rules,
            interfaces: &self.ifs,
            aliases: &self.resolved,
            nat: None,
        };
        let mut buf = Vec::new();
        let report = nft::render(&policy, opts, &mut buf).expect("render");
        common::golden_json(name, &buf);
        common::golden_text(&format!("{name}.pf"), &pf::filter_rules(rules, &self.ifs));
        report
    }
}

#[test]
fn addresses_aliases_and_interfaces() {
    let f = Fixture::new();
    let rules = f.rules(&[
        (
            400_000,
            conf! { "interface" => "lan", "ipprotocol" => "inet46", "from" => "lan", "to" => "any", "descr" => "LAN to any" },
        ),
        (
            400_000,
            conf! { "interface" => "lan", "protocol" => "tcp", "from" => "admins", "to" => "(self)", "to_port" => "22", "ipprotocol" => "inet46" },
        ),
        (
            400_000,
            conf! { "interface" => "lan", "protocol" => "tcp", "ipprotocol" => "inet", "to" => "lanip", "to_port" => "web", "to_not" => "1" },
        ),
        (
            400_000,
            conf! { "interface" => "wan", "type" => "block", "from" => "192.168.0.0/16", "ipprotocol" => "inet", "log" => "1" },
        ),
        (
            400_000,
            conf! { "interface" => "wan", "interfacenot" => "1", "type" => "reject", "protocol" => "tcp/udp", "to_port" => "135-139", "ipprotocol" => "inet" },
        ),
        (
            400_000,
            conf! { "interface" => "lan", "protocol" => "tcp", "tcpflags1" => "syn", "tcpflags2" => "syn,ack", "ipprotocol" => "inet" },
        ),
    ]);
    let report = f.golden("features_addresses", &rules, &Options::default());
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
}

#[test]
fn quick_first_then_non_quick_reversed() {
    let f = Fixture::new();
    let rules = f.rules(&[
        (
            1,
            conf! { "type" => "block", "ipprotocol" => "inet46", "quick" => false, "descr" => "Default deny" },
        ),
        (
            5,
            conf! { "direction" => "out", "statetype" => "keep", "quick" => false, "descr" => "let out" },
        ),
        (
            400_000,
            conf! { "interface" => "lan", "from" => "lan", "ipprotocol" => "inet" },
        ),
    ]);
    f.golden("features_quick", &rules, &Options::default());
}

/// The 07-performance-evaluation shape: many per-host rules that differ only
/// in values become one verdict-map lookup.
#[test]
fn per_host_rules_become_a_verdict_map() {
    let f = Fixture::new();
    let mut confs = Vec::new();
    for j in 0..40u32 {
        confs.push((
            400_000,
            conf! {
                "interface" => "lan",
                "type" => if j % 3 == 0 { "block" } else { "pass" },
                "ipprotocol" => "inet",
                "protocol" => if j % 2 == 0 { "udp" } else { "tcp" },
                "from" => format!("192.168.1.{}", 150 + j),
                "to" => format!("100.64.{j}.0/24"),
                "to_port" => format!("{}", 20000 + j),
            },
        ));
    }
    // same shape but overlapping the first entry: must start a new map
    confs.push((
        400_000,
        conf! { "interface" => "lan", "type" => "block", "ipprotocol" => "inet", "protocol" => "udp",
                 "from" => "192.168.1.150", "to" => "100.64.0.0/16", "to_port" => "20000" },
    ));
    let rules = f.rules(&confs);
    let report = f.golden("features_vmap", &rules, &Options::default());
    assert_eq!(report.stats.vmaps, 1, "{:?}", report.stats);
    assert_eq!(report.stats.vmap_entries, 40);
}

#[test]
fn flowtable_offload() {
    let f = Fixture::new();
    let opts = Options {
        flowtable: true,
        ..Options::default()
    };
    f.golden("features_flowtable", &[], &opts);
}
