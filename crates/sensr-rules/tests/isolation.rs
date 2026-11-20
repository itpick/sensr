//! Device isolation: the generated rules keep the router's own services
//! reachable, block every other local network, and run ahead of the user's
//! rules so a broad "allow LAN" cannot undo them.

use sensr_rules::document::{self, Runtime};
use sensr_rules::ir::{Action, Addr, Direction};
use sensr_schema::Document;
use sensr_schema::fields::NetOrAlias;
use sensr_schema::models::firewall::{Endpoint, Isolation};

fn home_router() -> Document {
    let path = format!(
        "{}/../sensr-import-opnsense/tests/golden/home-router.sensr.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect("importer golden"))
        .expect("document")
}

fn isolate(doc: &mut Document, source: &str, enabled: bool) {
    doc.firewall.isolation.push(Isolation {
        enabled,
        interface: "lan".parse().unwrap(),
        source: Endpoint::net(NetOrAlias::from_str_checked(source)),
        description: Some("guest camera".parse().unwrap()),
    });
}

/// `NetOrAlias` has no public literal parser; go through its `FromStr`.
trait FromStrChecked {
    fn from_str_checked(s: &str) -> NetOrAlias;
}
impl FromStrChecked for NetOrAlias {
    fn from_str_checked(s: &str) -> NetOrAlias {
        use std::str::FromStr;
        NetOrAlias::from_str(s).unwrap()
    }
}

#[test]
fn isolation_allows_the_router_and_blocks_local_networks() {
    let mut doc = home_router();
    isolate(&mut doc, "192.168.1.50", true);
    let c = document::compile(&doc, &Runtime::default());

    let rules: Vec<_> = c
        .filter
        .iter()
        .filter(|r| r.descr.starts_with("guest camera"))
        .collect();
    // One pass to the firewall itself, then a block for every internal network.
    assert!(rules.len() >= 2, "{rules:#?}");
    let pass = &rules[0];
    assert_eq!(pass.action, Action::Pass);
    assert_eq!(pass.direction, Direction::In);
    assert_eq!(pass.interface.as_deref(), Some("lan"));
    assert_eq!(pass.dst.addr, Addr::SelfAddr);
    assert_eq!(pass.src.addr, Addr::Host("192.168.1.50".parse().unwrap()));
    let block = &rules[1];
    assert_eq!(block.action, Action::Block);
    assert_eq!(
        block.dst.addr,
        Addr::IfaceNet {
            iface: "lan".into(),
            link_local: false
        }
    );
    assert!(block.quick && pass.quick, "a later pass must not override");

    // The internet is not blocked: only internal networks are destinations.
    assert!(
        rules
            .iter()
            .skip(1)
            .all(|r| !matches!(r.dst.addr, Addr::Any)),
        "isolation must not block everything"
    );

    // They run before the user's rules (priority 400000 for LAN rules).
    assert!(rules.iter().all(|r| r.priority < 100_000), "{:?}", rules);
}

#[test]
fn a_disabled_policy_registers_nothing() {
    let mut doc = home_router();
    isolate(&mut doc, "192.168.1.50", false);
    let c = document::compile(&doc, &Runtime::default());
    assert!(
        !c.filter.iter().any(|r| r.descr.starts_with("guest camera")),
        "disabled policy still rendered"
    );
}

#[test]
fn isolation_can_name_an_alias() {
    use sensr_schema::models::firewall::AliasContent;
    let mut doc = home_router();
    let alias = doc
        .firewall
        .aliases
        .values()
        .find(|a| matches!(a.content, AliasContent::Host { .. }))
        .map(|a| a.name.as_str().to_owned());
    let Some(alias) = alias else {
        return; // corpus has no host alias; nothing to check
    };
    doc.firewall.isolation.push(Isolation {
        enabled: true,
        interface: "lan".parse().unwrap(),
        source: Endpoint::net(NetOrAlias::from_str_checked(&format!("alias:{alias}"))),
        description: None,
    });
    let c = document::compile(&doc, &Runtime::default());
    assert!(
        c.filter
            .iter()
            .any(|r| r.reference.as_deref() == Some("ui/firewall/isolation")),
        "no isolation rule for alias:{alias}"
    );
}
