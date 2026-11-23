//! Host modes: a MAC in `host_isolated` reaches the router and the internet
//! but no local host; a MAC in `host_quarantine` reaches only the router's
//! DHCP, DNS and NTP. Both are cut off from other local hosts in the reverse
//! direction through `host_locked_v4/v6`.

mod common;

use std::net::Ipv4Addr;

use sensr_rules::document::{self, Compiled, Runtime};
use sensr_rules::host_modes::{self, HostModeSets};
use sensr_rules::ir::{Action, Addr, Direction, FilterRule, PortMatch};
use sensr_rules::proto::ProtoMatch;
use sensr_rules::render::nft::SetContents;
use sensr_schema::Document;
use sensr_schema::fields::MacAddr;
use sensr_schema::models::firewall::{HostMode, HostModeKind};

const MAC: &str = "02:00:00:00:00:42";

fn home_router() -> Document {
    let path = format!(
        "{}/../sensr-import-opnsense/tests/golden/home-router.sensr.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect("importer golden"))
        .expect("document")
}

fn with_host(mode: HostModeKind) -> Compiled {
    let mut doc = home_router();
    doc.firewall.host_modes.push(HostMode {
        enabled: true,
        mac: MAC.parse().unwrap(),
        mode,
        description: Some("printer".parse().unwrap()),
    });
    document::compile(&doc, &Runtime::default())
}

fn from_set<'a>(c: &'a Compiled, set: &str) -> Vec<&'a FilterRule> {
    c.filter
        .iter()
        .filter(|r| r.src.addr == Addr::MacSet(set.into()))
        .collect()
}

fn internal() -> Vec<String> {
    document::internal_interfaces(&home_router())
        .into_iter()
        .map(|i| i.id)
        .collect()
}

fn port(r: &FilterRule) -> Option<PortMatch> {
    r.dst.port.clone()
}

/// 6 tcp, 17 udp, 0 tcp/udp
fn proto(r: &FilterRule) -> Option<u8> {
    match r.proto {
        ProtoMatch::One(p) => Some(p.number),
        ProtoMatch::TcpUdp => Some(0),
        ProtoMatch::Any => None,
    }
}

#[test]
fn isolated_passes_self_blocks_local_keeps_internet() {
    let c = with_host(HostModeKind::Isolated);
    let rules = from_set(&c, "host_isolated");
    assert!(!rules.is_empty());
    assert!(from_set(&c, "host_quarantine").is_empty());
    for iface in internal() {
        let on: Vec<_> = rules
            .iter()
            .filter(|r| r.interface.as_deref() == Some(iface.as_str()))
            .collect();
        assert_eq!(on[0].action, Action::Pass, "{iface}: {on:#?}");
        assert_eq!(on[0].dst.addr, Addr::SelfAddr);
        for net in internal() {
            assert!(
                on.iter().any(|r| r.action == Action::Block
                    && matches!(&r.dst.addr, Addr::IfaceNet { iface: n, .. } if *n == net)),
                "{iface}: no block to {net}"
            );
        }
    }
    for r in &rules {
        assert!(r.quick && r.enabled, "{r:#?}");
        assert_eq!(r.direction, Direction::In);
        assert_eq!(r.priority, 6);
        assert_eq!(r.reference.as_deref(), Some("ui/core/dashboard"));
        assert_ne!(r.dst.addr, Addr::Any, "the internet must fall through");
    }
    assert_eq!(c.host_modes.isolated, vec![MAC.parse::<MacAddr>().unwrap()]);
    assert!(c.host_modes.quarantine.is_empty());
}

#[test]
fn quarantine_allows_only_dhcp_dns_ntp_to_self() {
    let c = with_host(HostModeKind::Quarantine);
    let rules = from_set(&c, "host_quarantine");
    for iface in internal() {
        let on: Vec<_> = rules
            .iter()
            .filter(|r| r.interface.as_deref() == Some(iface.as_str()))
            .collect();
        let passes: Vec<(Option<u8>, Option<PortMatch>, &Addr)> = on
            .iter()
            .take_while(|r| r.action == Action::Pass)
            .map(|r| (proto(r), port(r), &r.dst.addr))
            .collect();
        let me = Addr::SelfAddr;
        let bcast = Addr::Host("255.255.255.255".parse().unwrap());
        let udp = |p, to| (Some(17), Some(PortMatch::Single(p)), to);
        let tcp_udp = |p, to| (Some(0), Some(PortMatch::Single(p)), to);
        assert_eq!(
            passes,
            [
                udp(67, &me),
                udp(67, &bcast),
                tcp_udp(53, &me),
                udp(123, &me)
            ],
            "{iface}: DHCP, DNS, NTP only"
        );
        let last = on.last().expect("rules");
        assert_eq!(on.len(), 5, "{iface}: {on:#?}");
        assert_eq!(last.action, Action::Block);
        assert_eq!(last.dst.addr, Addr::Any);
        assert!(last.proto == ProtoMatch::Any && last.dst.port.is_none());
    }
    assert!(rules.iter().all(|r| r.quick
        && r.direction == Direction::In
        && r.reference.as_deref() == Some("ui/core/dashboard")));
    assert_eq!(
        c.host_modes.quarantine,
        vec![MAC.parse::<MacAddr>().unwrap()]
    );
}

/// Review focus 1: a quarantined host must not reach the GUI, so its block
/// to (self) comes before the anti-lockout pass on the same interface.
#[test]
fn quarantine_blocks_the_gui_before_anti_lockout() {
    let c = with_host(HostModeKind::Quarantine);
    let mut order: Vec<&FilterRule> = c.filter.iter().collect();
    order.sort_by_key(|r| r.priority); // the renderer's order
    let pos = |f: &dyn Fn(&FilterRule) -> bool| order.iter().position(|r| f(r));
    let lockout = pos(&|r| r.descr == "anti-lockout rule" && r.interface.as_deref() == Some("lan"))
        .expect("anti-lockout on lan");
    let block = pos(&|r| {
        r.src.addr == Addr::MacSet("host_quarantine".into())
            && r.action == Action::Block
            && r.interface.as_deref() == Some("lan")
    })
    .expect("quarantine block on lan");
    assert!(
        block < lockout,
        "block {block} after anti-lockout {lockout}"
    );
}

fn rendered(mode: HostModeKind) -> Vec<u8> {
    let mut buf = Vec::new();
    let report = with_host(mode).render_nft(&mut buf).unwrap();
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    buf
}

fn commands(buf: &[u8]) -> Vec<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_slice(buf).unwrap();
    v["nftables"].as_array().unwrap().clone()
}

fn rules_in<'a>(cmds: &'a [serde_json::Value], chain: &str) -> Vec<&'a serde_json::Value> {
    cmds.iter()
        .filter_map(|c| c["add"]["rule"].as_object().map(|_| &c["add"]["rule"]))
        .filter(|r| r["chain"] == chain)
        .collect()
}

/// Review focus 3: the quarantine DNS pass sits in `in_lan`, which both the
/// input and the forward hook reach through `in_dispatch`.
#[test]
fn quarantine_forward_chain_passes_dns_to_router() {
    let buf = rendered(HostModeKind::Quarantine);
    let cmds = commands(&buf);
    let dns = rules_in(&cmds, "in_lan").into_iter().any(|r| {
        let e = r["expr"].to_string();
        e.contains(r#""right":"@host_quarantine""#)
            && e.contains(r#""right":53"#)
            && e.contains(r#""fib""#)
            && e.contains(r#""return""#)
    });
    assert!(dns, "no quarantine DNS pass in in_lan");
    for hook in ["input", "forward"] {
        assert!(
            rules_in(&cmds, hook).iter().any(|r| r["expr"]
                .to_string()
                .contains(r#""jump":{"target":"in_dispatch"}"#)),
            "{hook} does not reach in_dispatch"
        );
    }
    let dispatch = rules_in(&cmds, "in_dispatch")
        .iter()
        .map(|r| r["expr"].to_string())
        .collect::<String>();
    assert!(
        dispatch.contains(r#"["igc1",{"goto":{"target":"in_lan"}}]"#)
            || dispatch.contains(r#""igc1",{"goto":{"target":"in_lan"}}"#),
        "{dispatch}"
    );
    // `ether saddr` is only legal where a link-layer header exists: never in
    // output-reachable chains
    for c in rules_in(&cmds, "output")
        .into_iter()
        .chain(cmds.iter().filter_map(|c| {
            let r = &c["add"]["rule"];
            r["chain"]
                .as_str()
                .is_some_and(|n| n.starts_with("out_"))
                .then_some(r)
        }))
    {
        assert!(!c["expr"].to_string().contains("ether"), "{c}");
    }
}

/// Review focus 2: the reverse block matches only the locked hosts' own
/// addresses, which the agent fills at run time.
#[test]
fn reverse_block_targets_only_locked_addresses() {
    let sets = HostModeSets {
        isolated: vec!["02:00:00:00:00:50".parse().unwrap()],
        quarantine: vec!["02:00:00:00:00:51".parse().unwrap()],
        locked_v4: vec![
            Ipv4Addr::new(192, 168, 68, 50),
            Ipv4Addr::new(192, 168, 68, 51),
        ],
        locked_v6: Vec::new(),
        quarantine_v4: vec![Ipv4Addr::new(192, 168, 68, 51)],
        quarantine_v6: vec!["fd00::51".parse().unwrap()],
    };
    let updates = host_modes::host_mode_set_updates(&sets);
    let get = |n: &str| {
        updates
            .iter()
            .find(|(name, _)| name == n)
            .map(|(_, c)| c.clone())
            .unwrap_or_else(|| panic!("no {n} in {updates:?}"))
    };
    assert_eq!(
        get("host_locked_v4"),
        SetContents::Nets(vec![
            "192.168.68.50/32".parse().unwrap(),
            "192.168.68.51/32".parse().unwrap(),
        ])
    );
    assert_eq!(get("host_locked_v6"), SetContents::Nets(Vec::new()));
    assert_eq!(
        get("host_isolated"),
        SetContents::Macs(sets.isolated.clone())
    );
    assert_eq!(
        get("host_quarantine"),
        SetContents::Macs(sets.quarantine.clone())
    );
    assert_eq!(
        get("host_quarantine_v4"),
        SetContents::Nets(vec!["192.168.68.51/32".parse().unwrap()])
    );
    assert_eq!(
        get("host_quarantine_v6"),
        SetContents::Nets(vec!["fd00::51/128".parse().unwrap()])
    );
    assert_eq!(updates.len(), 6, "{updates:?}");

    // the compiled reverse rules: a pass from (self), then a block from any
    // source to the locked addresses, per internal interface
    let c = with_host(HostModeKind::Isolated);
    for iface in internal() {
        let rev: Vec<_> = c
            .filter
            .iter()
            .filter(|r| {
                r.dst.addr == Addr::IpSet("host_locked".into())
                    && r.interface.as_deref() == Some(iface.as_str())
            })
            .collect();
        assert_eq!(rev.len(), 2, "{iface}: {rev:#?}");
        assert_eq!(rev[0].action, Action::Pass);
        assert_eq!(rev[0].src.addr, Addr::SelfAddr);
        assert_eq!(rev[1].action, Action::Block);
        // from any: routed and tunnelled sources are blocked too
        assert_eq!(rev[1].src.addr, Addr::Any);
        assert!(rev.iter().all(|r| r.quick && r.priority == 5));
    }

    let mut out = Vec::new();
    sensr_rules::render::nft::render_set_updates("sensr", &updates, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains(r#""elem":["02:00:00:00:00:50"]"#), "{text}");
}

#[test]
fn no_host_modes_render_no_host_sets() {
    let c = document::compile(&home_router(), &Runtime::default());
    let mut buf = Vec::new();
    c.render_nft(&mut buf).unwrap();
    let text = String::from_utf8(buf).unwrap();
    assert!(!text.contains("host_"), "host-mode sets without host modes");
}

#[test]
fn a_disabled_host_mode_registers_nothing() {
    let mut doc = home_router();
    doc.firewall.host_modes.push(HostMode {
        enabled: false,
        mac: MAC.parse().unwrap(),
        mode: HostModeKind::Quarantine,
        description: None,
    });
    let c = document::compile(&doc, &Runtime::default());
    assert!(c.filter.iter().all(|r| !matches!(
        (&r.src.addr, &r.dst.addr),
        (Addr::MacSet(_), _) | (_, Addr::IpSet(_))
    )));
    assert_eq!(c.host_modes, HostModeSets::default());
}

#[test]
fn golden_isolated() {
    let buf = rendered(HostModeKind::Isolated);
    assert!(String::from_utf8_lossy(&buf).contains(MAC));
    common::golden_json("host-modes-isolated", &buf);
}

#[test]
fn golden_quarantine() {
    let buf = rendered(HostModeKind::Quarantine);
    assert!(String::from_utf8_lossy(&buf).contains(MAC));
    common::golden_json("host-modes-quarantine", &buf);
}

/// Labels are rule hashes: adding or renaming a host must not change them.
#[test]
fn labels_do_not_depend_on_the_hosts() {
    let labels = |c: &Compiled| -> Vec<String> {
        c.filter
            .iter()
            .filter(|r| r.reference.as_deref() == Some("ui/core/dashboard"))
            .map(|r| r.label.clone())
            .collect()
    };
    let one = with_host(HostModeKind::Quarantine);
    let mut doc = home_router();
    for (mac, d) in [(MAC, "renamed"), ("02:00:00:00:00:43", "second")] {
        doc.firewall.host_modes.push(HostMode {
            enabled: true,
            mac: mac.parse().unwrap(),
            mode: HostModeKind::Quarantine,
            description: Some(d.parse().unwrap()),
        });
    }
    let two = document::compile(&doc, &Runtime::default());
    assert!(!labels(&one).is_empty());
    assert_eq!(labels(&one), labels(&two));
    assert!(
        one.filter
            .iter()
            .any(|r| r.descr == "host mode quarantine: allow DNS to the router")
    );
}

/// Every host-mode rule has its own label (the log maps labels to rules).
#[test]
fn host_mode_labels_are_distinct() {
    for mode in [HostModeKind::Isolated, HostModeKind::Quarantine] {
        let c = with_host(mode);
        let mut seen = std::collections::BTreeMap::new();
        for r in c
            .filter
            .iter()
            .filter(|r| r.reference.as_deref() == Some("ui/core/dashboard"))
        {
            if let Some(other) = seen.insert(r.label.clone(), &r.descr) {
                // per-family expansions of one rule share its label
                assert_eq!(other, &r.descr, "label {} shared", r.label);
            }
        }
        let other_labels: Vec<&str> = c
            .filter
            .iter()
            .filter(|r| r.reference.as_deref() != Some("ui/core/dashboard"))
            .map(|r| r.label.as_str())
            .collect();
        assert!(seen.keys().all(|l| !other_labels.contains(&l.as_str())));
    }
}

/// The expressions of `chain`'s rules, as JSON text.
fn chain_text(cmds: &[serde_json::Value], chain: &str) -> Vec<String> {
    rules_in(cmds, chain)
        .into_iter()
        .map(|r| r["expr"].to_string())
        .collect()
}

/// Quarantine means no internet in either direction: a packet arriving on
/// the WAN for a quarantined address (a port forward, 1:1 NAT, an IPv6
/// pass) is dropped in `in_wan`, after a pass for router-sourced traffic,
/// and so is VPN ingress (`in_opt3` is WireGuard) and anything unassigned.
#[test]
fn quarantine_drops_wan_ingress_to_quarantined_addresses() {
    let c = with_host(HostModeKind::Quarantine);
    let inbound: Vec<&FilterRule> = c
        .filter
        .iter()
        .filter(|r| r.dst.addr == Addr::IpSet("host_quarantine".into()))
        .collect();
    assert_eq!(inbound.len(), 2, "{inbound:#?}");
    assert_eq!(
        (inbound[0].action, &inbound[0].src.addr),
        (Action::Pass, &Addr::SelfAddr)
    );
    assert_eq!(
        (inbound[1].action, &inbound[1].src.addr),
        (Action::Block, &Addr::Any)
    );
    for r in &inbound {
        assert!(r.quick && r.enabled && r.direction == Direction::In);
        assert_eq!(r.interface, None, "floating: every interface");
        assert_eq!(r.priority, 0, "ahead of every system and user pass");
    }

    let cmds = commands(&rendered(HostModeKind::Quarantine));
    for chain in ["in_wan", "in_opt3", "in_lan", "in__any"] {
        let rules = chain_text(&cmds, chain);
        for (set, fam) in [
            ("@host_quarantine_v4", "ip"),
            ("@host_quarantine_v6", "ip6"),
        ] {
            let to = format!(
                r#"{{"match":{{"op":"==","left":{{"payload":{{"protocol":"{fam}","field":"daddr"}}}},"right":"{set}"}}}}"#
            );
            let pass = rules
                .iter()
                .position(|e| e.contains(&to) && e.contains(r#""fib""#) && e.contains("return"));
            let drop = rules
                .iter()
                .position(|e| e.contains(&to) && e.contains(r#"{"drop":null}"#));
            let (Some(pass), Some(drop)) = (pass, drop) else {
                panic!("{chain}: no pass/drop to {set}: {rules:#?}");
            };
            assert!(pass < drop, "{chain}: the router pass comes first");
            // no other pass runs before the drop (only the router's own)
            let early: Vec<&String> = rules[..drop]
                .iter()
                .filter(|e| e.contains("return") && !e.contains("@host_quarantine_v"))
                .collect();
            assert!(
                early.is_empty(),
                "{chain}: passes before the drop: {early:#?}"
            );
        }
    }

    // `rdr pass` skips the filter chains: the forward hook drops a redirect
    // to a quarantined address before that skip
    let fwd = chain_text(&cmds, "forward");
    let skip = fwd
        .iter()
        .position(|e| e.contains(r#""ct":{"key":"mark"}"#) && e.contains("accept"))
        .expect("rdr pass skip");
    for set in ["@host_quarantine_v4", "@host_quarantine_v6"] {
        let drop = fwd
            .iter()
            .position(|e| {
                e.contains(r#""ct":{"key":"mark"}"#) && e.contains(set) && e.contains("drop")
            })
            .unwrap_or_else(|| panic!("no rdr-pass drop to {set}: {fwd:#?}"));
        assert!(drop < skip, "{set}: drop after the skip");
    }
}

/// Isolated hosts keep their inbound forwards: no rule targets the
/// quarantined addresses (the sets are declared, empty).
#[test]
fn isolated_gets_no_inbound_block() {
    let c = with_host(HostModeKind::Isolated);
    assert!(
        c.filter
            .iter()
            .all(|r| r.dst.addr != Addr::IpSet("host_quarantine".into()))
    );
    let text = String::from_utf8(rendered(HostModeKind::Isolated)).unwrap();
    let cmds = commands(text.as_bytes());
    for chain in ["in_wan", "in_opt3", "forward"] {
        assert!(
            chain_text(&cmds, chain)
                .iter()
                .all(|e| !e.contains("@host_quarantine")),
            "{chain}"
        );
    }
    assert!(text.contains(r#""name":"host_quarantine_v4""#), "declared");
}
