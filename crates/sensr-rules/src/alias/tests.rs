use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;
use proptest::prelude::*;

use super::dns::tests::MockResolver;
use super::*;
use crate::ir::IfAddr;

/// Hermetic world for resolver tests; records fetches.
#[derive(Default)]
struct World {
    bodies: BTreeMap<String, String>,
    dns: MockResolver,
    fetched: RefCell<Vec<(String, Auth)>>,
    v6: Vec<IfAddr>,
    external: Vec<IpNet>,
}

impl Sources for World {
    fn fetch(&self, url: &str, auth: &Auth) -> Result<String, FetchError> {
        self.fetched
            .borrow_mut()
            .push((url.to_owned(), auth.clone()));
        self.bodies.get(url).cloned().ok_or_else(|| FetchError {
            url: url.into(),
            reason: "404".into(),
        })
    }
    fn resolver(&self) -> &dyn dns::Resolver {
        &self.dns
    }
    fn geoip(&self, cc: &str, fam: IpFamily) -> Vec<IpNet> {
        match (cc, fam) {
            ("NL", IpFamily::V4) => vec!["198.18.0.0/24".parse().unwrap()],
            ("NL", IpFamily::V6) => vec!["2001:db8:10::/48".parse().unwrap()],
            _ => vec![],
        }
    }
    fn asn(&self, asn: u32) -> Vec<IpNet> {
        if asn == 13335 {
            vec!["198.51.100.0/24".parse().unwrap()]
        } else {
            vec![]
        }
    }
    fn neighbours(&self) -> Vec<(String, IpAddr)> {
        vec![("02:00:5e:00:00:01".into(), "192.168.1.20".parse().unwrap())]
    }
    fn interface_addrs(&self, _iface: &str) -> Vec<IfAddr> {
        self.v6.clone()
    }
    fn external(&self, _name: &str) -> Vec<IpNet> {
        self.external.clone()
    }
}

fn def(name: &str, kind: AliasKind) -> AliasDef {
    AliasDef {
        name: name.into(),
        enabled: true,
        kind,
    }
}

fn raw(v: &[&str]) -> Vec<HostEntry> {
    v.iter().map(|s| HostEntry::Raw((*s).into())).collect()
}

fn nets(r: &Resolution, name: &str) -> Vec<String> {
    r.aliases[name].nets.iter().map(|n| n.to_string()).collect()
}

#[test]
fn nested_union_and_exclusion() {
    let defs = vec![
        def(
            "lan_hosts",
            AliasKind::Host(raw(&["192.168.1.10", "192.168.1.11"])),
        ),
        def(
            "office",
            AliasKind::Network(raw(&["10.0.0.0/8", "!10.9.0.0/16", "lan_hosts"])),
        ),
        def(
            "all",
            AliasKind::NetworkGroup(vec!["office".into(), "lan_hosts".into()]),
        ),
    ];
    let r = resolve_all(&defs, &World::default());
    assert!(r.errors.is_empty(), "{:?}", r.errors);
    let office = nets(&r, "office");
    assert!(
        office.contains(&"192.168.1.10/31".to_string()),
        "{office:?}"
    );
    assert!(!office.iter().any(|n| n.starts_with("10.9.")));
    assert_eq!(nets(&r, "all"), office);
}

#[test]
fn cycles_are_detected_not_followed() {
    let defs = vec![
        def("a", AliasKind::Network(raw(&["b", "10.0.0.1"]))),
        def("b", AliasKind::Network(raw(&["a"]))),
        def("c", AliasKind::Network(raw(&["10.0.0.2"]))),
    ];
    let r = resolve_all(&defs, &World::default());
    assert!(r.errors.contains(&AliasError::Cycle("a".into())));
    assert!(r.errors.contains(&AliasError::Cycle("b".into())));
    assert!(r.failed.contains("a") && r.failed.contains("b"));
    assert!(r.aliases["a"].nets.is_empty());
    assert_eq!(nets(&r, "c"), ["10.0.0.2/32"]);
}

#[test]
fn parse_drop_fixture_t0328() {
    let body = include_str!("../../tests/fixtures/urltable/drop.txt");
    let mut w = World::default();
    w.bodies
        .insert("https://lists.example/drop.txt".into(), body.into());
    let defs = vec![def(
        "drop",
        AliasKind::UrlTable {
            url: "https://lists.example/drop.txt".into(),
            auth: Auth::Bearer("t0k3n".into()),
            refresh_secs: 86_400,
            families: Families::default(),
        },
    )];
    let r = resolve_all(&defs, &w);
    assert!(r.failed.is_empty());
    // 6 networks listed, two of them adjacent and merged
    assert_eq!(nets(&r, "drop").len(), 5, "{:?}", nets(&r, "drop"));
    assert_eq!(
        w.fetched.borrow().as_slice(),
        [(
            "https://lists.example/drop.txt".to_string(),
            Auth::Bearer("t0k3n".into())
        )]
    );
}

#[test]
fn failed_fetch_marks_alias_failed() {
    let defs = vec![def(
        "gone",
        AliasKind::Url {
            urls: vec!["https://lists.example/missing".into()],
            auth: Auth::None,
            families: Families::default(),
        },
    )];
    let r = resolve_all(&defs, &World::default());
    assert!(r.failed.contains("gone"));
    assert!(matches!(r.errors[0], AliasError::Fetch(_)));
}

#[test]
fn host_names_resolve_through_dns() {
    let w = World {
        dns: MockResolver::default().a("nas.example.org", &["192.0.2.7", "2001:db8::7"]),
        ..World::default()
    };
    let defs = vec![def("nas", AliasKind::Host(raw(&["nas.example.org"])))];
    let r = resolve_all(&defs, &w);
    assert_eq!(nets(&r, "nas"), ["192.0.2.7/32", "2001:db8::7/128"]);
}

#[test]
fn every_kind_resolves() {
    let w = World {
        v6: vec![IfAddr {
            addr: "2001:fff:faaa::1".parse().unwrap(),
            prefix_len: 64,
        }],
        external: vec!["203.0.113.9/32".parse().unwrap()],
        ..World::default()
    };
    let defs = vec![
        def(
            "geo",
            AliasKind::GeoIp {
                countries: vec!["NL".into()],
                families: Families {
                    v4: true,
                    v6: false,
                },
            },
        ),
        def(
            "cf",
            AliasKind::Asn {
                asns: vec![13335],
                families: Families::default(),
            },
        ),
        def("printer", AliasKind::Mac(vec!["02:00:5E:00:00:01".into()])),
        def(
            "nas6",
            AliasKind::DynIpv6Host {
                interface: "lan".into(),
                suffixes: vec!["::1005".into()],
            },
        ),
        def("ext", AliasKind::External),
        def(
            "web",
            AliasKind::Port(vec![
                PortEntry::Range(443, 443),
                PortEntry::Range(80, 80),
                PortEntry::Alias("alt".into()),
            ]),
        ),
        def("alt", AliasKind::Port(vec![PortEntry::Range(8080, 8081)])),
    ];
    let r = resolve_all(&defs, &w);
    assert_eq!(nets(&r, "geo"), ["198.18.0.0/24"]);
    assert_eq!(nets(&r, "cf"), ["198.51.100.0/24"]);
    assert_eq!(nets(&r, "printer"), ["192.168.1.20/32"]);
    assert_eq!(nets(&r, "nas6"), ["2001:fff:faaa::1005/128"]);
    assert_eq!(nets(&r, "ext"), ["203.0.113.9/32"]);
    assert_eq!(r.aliases["web"].ports, [(80, 80), (443, 443), (8080, 8081)]);
}

#[test]
fn external_is_unmanaged_t0333() {
    assert!(!AliasKind::External.is_managed());
    assert!(AliasKind::Host(vec![]).is_managed());
    assert!(
        AliasKind::UrlTable {
            url: String::new(),
            auth: Auth::None,
            refresh_secs: 0,
            families: Families::default()
        }
        .is_managed()
    );
}

#[test]
fn schema_alias_converts() {
    let a: sensr_schema::models::firewall::Alias = serde_json::from_value(serde_json::json!({
        "name": "admins",
        "content": { "type": "host", "entries": ["192.168.1.10", "!192.168.1.11", "alias:other", "nas.example.org"] }
    }))
    .unwrap();
    let d = AliasDef::from(&a);
    let AliasKind::Host(v) = &d.kind else {
        panic!("{d:?}")
    };
    assert_eq!(v.len(), 4);
    assert!(matches!(&v[1], HostEntry::Net(t) if t.negate));
    assert!(matches!(&v[2], HostEntry::Alias { name, .. } if name == "other"));
}

proptest! {
    /// Resolution terminates and flags exactly the aliases on cycles.
    #[test]
    fn prop_alias_dag_resolution_terminates(edges in proptest::collection::vec((0usize..6, 0usize..6), 0..14)) {
        let names: Vec<String> = (0..6).map(|i| format!("a{i}")).collect();
        let defs: Vec<AliasDef> = (0..6).map(|i| {
            let mut entries = vec![HostEntry::Raw(format!("10.0.0.{i}"))];
            entries.extend(edges.iter().filter(|(f, _)| *f == i).map(|(_, t)| HostEntry::Alias { name: names[*t].clone(), exclude: false }));
            def(&names[i], AliasKind::Network(entries))
        }).collect();
        let r = resolve_all(&defs, &World::default());
        // reference: i is on a cycle iff i reaches itself
        for (i, name) in names.iter().enumerate() {
            let mut seen = std::collections::BTreeSet::new();
            let mut stack: Vec<usize> = edges.iter().filter(|(f, _)| *f == i).map(|(_, t)| *t).collect();
            let mut cyclic = false;
            while let Some(n) = stack.pop() {
                if n == i { cyclic = true; break; }
                if seen.insert(n) {
                    stack.extend(edges.iter().filter(|(f, _)| *f == n).map(|(_, t)| *t));
                }
            }
            prop_assert_eq!(r.errors.contains(&AliasError::Cycle(name.clone())), cyclic);
        }
    }
}
