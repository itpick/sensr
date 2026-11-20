//! Slice models: serde shape, defaults, validation messages and path edits.
//!
//! Covers: SYS-001, IF-001, IF-006, FW-001, FW-AL-001, NAT-001, NAT-002,
//! DHCP-KEA-001, DNS-UB-001, VPN-WG-001

use pretty_assertions::assert_eq;
use sensr_schema::models::dhcp::{ClientMatch, Pool4, Reservation4, Subnet4};
use sensr_schema::models::dns::{DnsRecord, HostOverride};
use sensr_schema::models::firewall::{Alias, FilterRule};
use sensr_schema::models::interfaces::{Ipv4Config, Ipv6Config};
use sensr_schema::models::nat::{ForwardFilter, OneToOneRule, PortForward};
use sensr_schema::models::system::{Group, OidcProvider, OidcProviderKind, User};
use sensr_schema::models::wireguard::{WgPeer, WgServer};
use sensr_schema::{Document, PathAccess, Relation, Section, Uuid, Validations};
use serde_json::json;

const KEY_A: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
const KEY_B: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

fn messages(v: &Validations, path: &str) -> Vec<String> {
    v.get(path)
        .unwrap_or_else(|| panic!("no error at {path}; got:\n{v}"))
        .iter()
        .map(|e| e.message.clone())
        .collect()
}

#[test]
fn factory_document_matches_golden_and_validates() {
    let doc = Document::factory();
    let v = doc.validate();
    assert!(v.is_ok(), "{v}");
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    let golden = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/factory.json");
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::write(golden, &text).unwrap();
    }
    assert_eq!(std::fs::read_to_string(golden).unwrap(), text);
    let back: Document = serde_json::from_str(&text).unwrap();
    assert_eq!(back, doc);
}

#[test]
fn minimal_document_fills_defaults() {
    let doc: Document = serde_json::from_value(json!({"schema_version": "0.1.0"})).unwrap();
    assert_eq!(doc, Document::default());
    assert_eq!(doc.system.hostname.as_str(), "sensr");
    assert!(doc.firewall.settings.anti_lockout);
    assert_eq!(doc.dhcpv4.valid_lifetime, 4000);
    assert_eq!(doc.dns.port.get(), 53);
}

#[test]
fn unknown_fields_rejected_everywhere() {
    for bad in [
        json!({"schema_version": "0.1.0", "bogus": 1}),
        json!({"schema_version": "0.1.0", "system": {"hostname": "a", "domain": "b", "timezone": "UTC", "x": 1}}),
        json!({"schema_version": "0.1.0", "interfaces": {"lan": {"device": "eth1", "ipv4": {"mode": "dhcp", "x": 1}}}}),
    ] {
        assert!(
            serde_json::from_value::<Document>(bad.clone()).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn interface_json_shape() {
    let doc = Document::factory();
    let lan = doc.get_by_path("interfaces.lan").unwrap();
    assert_eq!(
        lan["ipv4"],
        json!({"mode": "static", "address": "192.168.1.1/24"})
    );
    assert_eq!(
        lan["ipv6"],
        json!({"mode": "track", "interface": "wan", "prefix_id": 0})
    );
    assert_eq!(lan["qdisc"], json!({"type": "fq_codel"}));
    assert_eq!(
        doc.get_by_path("interfaces.wan.ipv4.mode").unwrap(),
        json!("dhcp")
    );
}

#[test]
fn path_edits_on_document() {
    let mut doc = Document::factory();
    doc.set_by_path_text("system.hostname", "fw1").unwrap();
    doc.set_by_path_text("interfaces.lan.ipv4.address", "10.0.0.1/24")
        .unwrap();
    doc.set_by_path_text("interfaces.lan.mtu", "1500").unwrap();
    assert_eq!(doc.system.hostname.as_str(), "fw1");
    assert_eq!(
        doc.interfaces
            .get(&"lan".parse().unwrap())
            .unwrap()
            .ipv4
            .static_net()
            .unwrap()
            .to_string(),
        "10.0.0.0/24"
    );
    assert!(
        doc.set_by_path_text("system.hostname", "not valid")
            .is_err()
    );
    assert!(
        doc.set_by_path_text("interfaces.lan.ipv4.address", "10.0.0.1/33")
            .is_err()
    );
    let rule = *doc.firewall.rules.keys().next().unwrap();
    doc.set_by_path_text(&format!("firewall.rules.{rule}.enabled"), "false")
        .unwrap();
    assert!(!doc.firewall.rules.get(&rule).unwrap().enabled);
    doc.set_by_path(
        "interfaces.opt1",
        json!({"device": "eth2", "ipv4": {"mode": "static", "address": "172.16.0.1/24"}}),
    )
    .unwrap();
    assert!(doc.validate().is_ok());
    assert_eq!(
        doc.interfaces
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>(),
        ["wan", "lan", "opt1"]
    );
}

#[test]
fn changed_sections_tracks_edits() {
    let a = Document::factory();
    let mut b = a.clone();
    assert!(a.changed_sections(&b).is_empty());
    b.system.hostname = "x".parse().unwrap();
    b.dns.dnssec = true;
    assert_eq!(a.changed_sections(&b), [Section::System, Section::Dns]);
}

#[test]
fn interface_rules() {
    let mut doc = Document::factory();
    doc.set_by_path_text("interfaces.lan.device", "eth0")
        .unwrap();
    doc.set_by_path_text("interfaces.lan.ipv4.address", "192.168.1.0/24")
        .unwrap();
    doc.set_by_path(
        "interfaces.lan.ipv6",
        json!({"mode": "track", "interface": "wan", "prefix_id": 1}),
    )
    .unwrap();
    doc.set_by_path_text("interfaces.lan.mtu", "100").unwrap();
    let v = doc.validate();
    assert_eq!(
        messages(&v, "interfaces.lan.device"),
        ["Device eth0 is already assigned to wan."]
    );
    assert_eq!(
        messages(&v, "interfaces.lan.ipv4.address"),
        ["This IPv4 address is the network address and cannot be used."]
    );
    assert_eq!(
        messages(&v, "interfaces.lan.ipv6.prefix_id"),
        ["The prefix ID must be smaller than 1 for a /64 delegation."]
    );
    assert_eq!(
        messages(&v, "interfaces.lan.mtu"),
        ["Please specify a value between 576 and 9216."]
    );

    let mut doc = Document::factory();
    doc.set_by_path("interfaces.wan.ipv6", json!({"mode": "slaac"}))
        .unwrap();
    doc.set_by_path(
        "interfaces.lan.ipv4",
        json!({"mode": "static", "address": "192.168.1.255/24"}),
    )
    .unwrap();
    let v = doc.validate();
    assert_eq!(
        messages(&v, "interfaces.lan.ipv6.interface"),
        ["The tracked interface does not request a delegated prefix."]
    );
    assert_eq!(
        messages(&v, "interfaces.lan.ipv4.address"),
        ["This IPv4 address is the broadcast address and cannot be used."]
    );
    assert!(matches!(
        doc.interfaces.get(&"wan".parse().unwrap()).unwrap().ipv6,
        Ipv6Config::Slaac
    ));
    assert!(matches!(
        doc.interfaces.get(&"wan".parse().unwrap()).unwrap().ipv4,
        Ipv4Config::Dhcp { .. }
    ));
}

#[test]
fn vlan_rules() {
    let mut doc = Document::factory();
    for (id, tag) in [("opt1", 20), ("opt2", 20)] {
        doc.set_by_path(
            &format!("interfaces.{id}"),
            json!({"device": format!("vlan.{id}"), "vlan": {"parent": "eth1", "tag": tag}}),
        )
        .unwrap();
    }
    doc.set_by_path(
        "interfaces.opt3",
        json!({"device": "eth1.0", "vlan": {"parent": "eth1.0", "tag": 0, "pcp": 9, "protocol": "802.1ad"}}),
    )
    .unwrap();
    let v = doc.validate();
    assert_eq!(
        messages(&v, "interfaces.opt2.vlan.tag"),
        ["Tag for this device must be unique (already used by opt1)."]
    );
    assert_eq!(
        messages(&v, "interfaces.opt3.vlan.tag"),
        ["Please specify a value between 1 and 4094."]
    );
    assert_eq!(
        messages(&v, "interfaces.opt3.vlan.pcp"),
        ["Please specify a value between 0 and 7."]
    );
    assert_eq!(
        messages(&v, "interfaces.opt3.vlan.parent"),
        ["A VLAN cannot be its own parent device."]
    );
    assert!(v.get("interfaces.opt1.vlan.tag").is_none());
    let back: Document = serde_json::from_value(serde_json::to_value(&doc).unwrap()).unwrap();
    assert_eq!(back, doc);
}

#[test]
fn gateway_rules() {
    let mut doc = Document::factory();
    doc.set_by_path(
        "gateways",
        json!({
            "gateways": {
                "00000000-0000-4000-8000-000000000001": {"name": "WAN_DHCP", "interface": "wan"},
                "00000000-0000-4000-8000-000000000002": {
                    "name": "WAN2", "interface": "lan", "address": "2001:db8::1",
                    "monitor": true, "weight": 11
                },
                "00000000-0000-4000-8000-000000000003": {"name": "WAN3", "interface": "nope", "family": "inet46"}
            },
            "groups": {
                "00000000-0000-4000-8000-000000000004": {
                    "name": "FAILOVER",
                    "members": [{"gateway": "WAN_DHCP", "tier": 1}, {"gateway": "GONE", "tier": 6}]
                },
                "00000000-0000-4000-8000-000000000005": {"name": "WAN_DHCP"}
            }
        }),
    )
    .unwrap();
    let rule = doc.firewall.rules.keys().next().copied().unwrap();
    doc.set_by_path_text(&format!("firewall.rules.{rule}.gateway"), "FAILOVER")
        .unwrap();
    let v = doc.validate();
    let g = |n: u8| format!("gateways.gateways.00000000-0000-4000-8000-00000000000{n}");
    assert_eq!(
        messages(&v, &format!("{}.address", g(2))),
        ["The address family of the address does not match the gateway's IP version."]
    );
    assert_eq!(
        messages(&v, &format!("{}.weight", g(2))),
        ["Please specify a value between 1 and 10."]
    );
    assert_eq!(
        messages(&v, &format!("{}.interface", g(3))),
        ["The interface does not exist."]
    );
    assert_eq!(
        messages(&v, &format!("{}.family", g(3))),
        ["A gateway is either IPv4 or IPv6."]
    );
    assert_eq!(
        messages(
            &v,
            "gateways.groups.00000000-0000-4000-8000-000000000004.members"
        ),
        [
            "Gateway GONE does not exist.",
            "Please specify a value between 1 and 5."
        ]
    );
    assert_eq!(
        messages(
            &v,
            "gateways.groups.00000000-0000-4000-8000-000000000005.name"
        ),
        ["Gateway with this name already exists."]
    );
    assert!(v.get(&format!("firewall.rules.{rule}.gateway")).is_none());
    doc.set_by_path_text(&format!("firewall.rules.{rule}.gateway"), "MISSING")
        .unwrap();
    assert_eq!(
        messages(&doc.validate(), &format!("firewall.rules.{rule}.gateway")),
        ["Gateway MISSING does not exist."]
    );
}

#[test]
fn trust_rules() {
    const PEM: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
    let mut doc = Document::factory();
    doc.set_by_path(
        "trust",
        json!({
            "authorities": {
                "00000000-0000-4000-8000-000000000001": {
                    "refid": "ca1", "description": "Root", "certificate": PEM, "serial": 2
                }
            },
            "certificates": {
                "00000000-0000-4000-8000-000000000002": {
                    "refid": "ca1", "description": "Web", "certificate": PEM,
                    "issuer": "00000000-0000-4000-8000-000000000001"
                },
                "00000000-0000-4000-8000-000000000003": {
                    "refid": "bad id", "description": "Pending",
                    "issuer": "00000000-0000-4000-8000-0000000000ff"
                }
            }
        }),
    )
    .unwrap();
    let v = doc.validate();
    let c = |n: u8| format!("trust.certificates.00000000-0000-4000-8000-00000000000{n}");
    assert_eq!(
        messages(&v, &format!("{}.refid", c(2))),
        ["This reference id is already in use."]
    );
    assert_eq!(
        messages(&v, &format!("{}.refid", c(3))),
        ["A reference id must be 1 to 64 letters or digits."]
    );
    assert_eq!(
        messages(&v, &format!("{}.issuer", c(3))),
        ["The issuing certificate authority does not exist."]
    );
    assert_eq!(
        messages(&v, &format!("{}.certificate", c(3))),
        ["A certificate or a signing request is required."]
    );
    assert!(v.get(&format!("{}.issuer", c(2))).is_none());
    assert!("not pem".parse::<sensr_schema::fields::Pem>().is_err());
    assert!(
        "-----BEGIN X-----\n-----END X-----\n-----BEGIN Y-----"
            .parse::<sensr_schema::fields::Pem>()
            .is_err()
    );
}

fn alias(name: &str, content: serde_json::Value) -> Alias {
    serde_json::from_value(json!({"name": name, "content": content})).unwrap()
}

#[test]
fn alias_rules() {
    let mut doc = Document::factory();
    let a = doc.firewall.aliases.push(alias("web", json!({"type": "host", "entries": ["10.0.0.1", "10.0.0.10-10.0.0.20", "www.example.org", "alias:ports"]})));
    doc.firewall.aliases.push(alias(
        "web",
        json!({"type": "network", "entries": ["10.0.0.0/8", "!10.1.0.0/16"]}),
    ));
    doc.firewall.aliases.push(alias(
        "ports",
        json!({"type": "port", "entries": ["80", "443", "8000-8080"]}),
    ));
    let g1 = doc.firewall.aliases.push(alias(
        "g1",
        json!({"type": "network_group", "members": ["g2"]}),
    ));
    let g2 = doc.firewall.aliases.push(alias(
        "g2",
        json!({"type": "network_group", "members": ["g1"]}),
    ));
    let v = doc.validate();
    let ids: Vec<_> = doc.firewall.aliases.keys().copied().collect();
    assert_eq!(
        messages(&v, &format!("firewall.aliases.{}.name", ids[0])),
        ["An alias with this name already exists."]
    );
    assert_eq!(
        messages(&v, &format!("firewall.aliases.{}.name", ids[1])),
        ["An alias with this name already exists."]
    );
    assert_eq!(
        messages(&v, &format!("firewall.aliases.{a}.content")),
        ["Alias ports cannot be nested here."]
    );
    for g in [g1, g2] {
        assert_eq!(
            messages(&v, &format!("firewall.aliases.{g}.content")),
            ["Alias contents may not refer back to the alias itself."]
        );
    }
    let json = serde_json::to_value(doc.firewall.aliases.get(&ids[1]).unwrap()).unwrap();
    assert_eq!(
        json["content"],
        json!({"type": "network", "entries": ["10.0.0.0/8", "!10.1.0.0/16"]})
    );
    assert!(
        serde_json::from_value::<Alias>(
            json!({"name": "x", "content": {"type": "host", "entries": ["1.2.3"]}})
        )
        .is_err()
    );
    assert!(serde_json::from_value::<Alias>(json!({"name": "x", "content": {"type": "url_table", "url": "https://example.org/l.txt", "refresh": {"days": 1}}})).is_ok());
}

#[test]
fn filter_rule_rules() {
    let mut doc = Document::factory();
    doc.firewall
        .aliases
        .push(alias("ports", json!({"type": "port", "entries": ["80"]})));
    let r = doc.firewall.rules.push(
        serde_json::from_value(json!({
            "interfaces": ["lan", "opt9"],
            "protocol": "icmp",
            "source": {"net": "alias:ports"},
            "destination": {"net": "2001:db8::/32", "port": "443"},
        }))
        .unwrap(),
    );
    let r2 = doc.firewall.rules.push(
        serde_json::from_value(json!({
            "protocol": "tcp",
            "source": {"net": "alias:missing"},
            "destination": {"net": "addr:wan", "port": "alias:missing2"},
            "interface_not": true,
        }))
        .unwrap(),
    );
    let v = doc.validate();
    let p = format!("firewall.rules.{r}");
    assert_eq!(
        messages(&v, &format!("{p}.interfaces")),
        ["Interface opt9 does not exist."]
    );
    assert_eq!(
        messages(&v, &format!("{p}.source.net")),
        ["Alias ports does not contain addresses."]
    );
    assert_eq!(
        messages(&v, &format!("{p}.destination.net")),
        ["The address family of the address does not match the rule's IP version."]
    );
    assert_eq!(
        messages(&v, &format!("{p}.destination.port")),
        ["Ports can only be specified for TCP, UDP or SCTP."]
    );
    let p = format!("firewall.rules.{r2}");
    assert_eq!(
        messages(&v, &format!("{p}.source.net")),
        ["The alias does not exist."]
    );
    assert_eq!(
        messages(&v, &format!("{p}.destination.port")),
        ["The alias does not exist."]
    );
    assert_eq!(
        messages(&v, &format!("{p}.interface_not")),
        ["Inverting the interface selection requires at least one interface."]
    );

    let rule = FilterRule::default();
    assert_eq!(
        serde_json::to_value(&rule).unwrap()["source"],
        json!({"net": "any", "not": false})
    );
    let ordered = doc.firewall.rules_in_order();
    assert_eq!(
        ordered.iter().map(|(_, r)| r.sequence).collect::<Vec<_>>(),
        [1, 1, 1, 11]
    );
}

#[test]
fn mac_alias_as_rule_source() {
    // OPNsense resolves MAC aliases to the neighbour table's addresses, so
    // "trusted Wi-Fi devices may reach the LAN" is a valid rule
    let mut doc = Document::factory();
    doc.firewall.aliases.push(alias(
        "trusted",
        json!({"type": "mac", "addresses": ["02:00:5e:10:00:0a"]}),
    ));
    let r = doc.firewall.rules.push(
        serde_json::from_value(json!({
            "interfaces": ["lan"],
            "source": {"net": "alias:trusted"},
        }))
        .unwrap(),
    );
    let v = doc.validate();
    assert!(v.is_empty(), "rule {r}: {v:?}");
}

#[test]
fn nat_rules() {
    let mut doc = Document::factory();
    let ok = doc.nat.port_forwards.push(
        serde_json::from_value(json!({
            "interfaces": ["wan"],
            "destination": {"net": "addr:wan", "port": "8443"},
            "target": "192.168.1.10",
            "target_port": "443",
        }))
        .unwrap(),
    );
    let bad = doc.nat.port_forwards.push(PortForward {
        target: "net:lan".parse().unwrap(),
        filter: ForwardFilter::Rule(Relation::new(Uuid::new_v4())),
        interfaces: vec![],
        ..doc.nat.port_forwards.get(&ok).unwrap().clone()
    });
    doc.nat.outbound.rules.push(
        serde_json::from_value(
            json!({"interface": "wan", "source": {"net": "net:lan"}, "target": "any"}),
        )
        .unwrap(),
    );
    let v = doc.validate();
    let p = format!("nat.port_forwards.{bad}");
    assert_eq!(
        messages(&v, &format!("{p}.target")),
        ["A valid redirect target IP address must be specified."]
    );
    assert_eq!(
        messages(&v, &format!("{p}.filter")),
        ["Related item not found."]
    );
    assert_eq!(
        messages(&v, &format!("{p}.interfaces")),
        ["Select at least one interface."]
    );
    assert!(v.get(&format!("nat.port_forwards.{ok}.target")).is_none());
    let snat = *doc.nat.outbound.rules.keys().next().unwrap();
    assert_eq!(
        messages(&v, &format!("nat.outbound.rules.{snat}.target")),
        ["The translation target cannot be any."]
    );
    let fwd = serde_json::to_value(doc.nat.port_forwards.get(&ok).unwrap()).unwrap();
    assert_eq!(fwd["protocol"], json!("tcp"));
    assert_eq!(fwd["filter"], json!("pass"));
    assert_eq!(
        doc.get_by_path("nat.outbound.mode").unwrap(),
        json!("automatic")
    );
}

#[test]
fn nat_one_to_one_rules() {
    let mut doc = Document::factory();
    let rule = |v: serde_json::Value| -> OneToOneRule { serde_json::from_value(v).unwrap() };
    let ok = doc.nat.one_to_one.push(rule(json!({
        "interface": "wan",
        "external": "203.0.113.0/28",
        "source": {"net": "192.168.1.16/28"},
    })));
    // a host external address takes the internal prefix
    let host = doc.nat.one_to_one.push(rule(json!({
        "interface": "wan",
        "external": "203.0.113.5",
        "source": {"net": "192.168.1.0/28"},
        "reflection": "enable",
    })));
    let size = doc.nat.one_to_one.push(rule(json!({
        "interface": "wan",
        "external": "203.0.113.0/29",
        "source": {"net": "192.168.1.0/28"},
    })));
    let alias = doc.nat.one_to_one.push(rule(json!({
        "interface": "nope",
        "external": "2001:db8::1",
        "source": {"net": "net:lan", "not": true},
        "destination": {"net": "198.51.100.0/24"},
    })));
    // type nat accepts interface networks and unequal sizes
    let nat = doc.nat.one_to_one.push(rule(json!({
        "interface": "wan",
        "type": "nat",
        "external": "203.0.113.9",
        "source": {"net": "net:lan"},
        "destination": {"net": "any", "not": true},
    })));
    let v = doc.validate();
    let p = |id: &Uuid, f: &str| format!("nat.one_to_one.{id}.{f}");
    for id in [&ok, &host] {
        assert!(
            !v.iter()
                .any(|(path, _)| path.as_str().starts_with(&format!("nat.one_to_one.{id}"))),
            "{v}"
        );
    }
    assert_eq!(
        messages(&v, &p(&size, "external")),
        ["The external and internal networks must be the same size."]
    );
    assert_eq!(
        messages(&v, &p(&alias, "interface")),
        ["The interface does not exist."]
    );
    assert_eq!(
        messages(&v, &p(&alias, "source.net")),
        [
            "A BINAT source must be an address or network; use type NAT for aliases and interface networks."
        ]
    );
    assert_eq!(
        messages(&v, &p(&alias, "source.not")),
        ["A BINAT source cannot be inverted."]
    );
    assert_eq!(
        messages(&v, &p(&alias, "destination.net")),
        ["The address family must match the external address."]
    );
    assert_eq!(
        messages(&v, &p(&nat, "destination.not")),
        ["Inverting \"any\" would match nothing; clear the inversion or choose an address."]
    );
    assert!(v.get(&p(&nat, "source.net")).is_none());
    let back = serde_json::to_value(doc.nat.one_to_one.get(&host).unwrap()).unwrap();
    assert_eq!(back["type"], json!("binat"));
    assert_eq!(back["destination"], json!({"net": "any", "not": false}));
    assert_eq!(back["reflection"], json!("enable"));
    assert_eq!(back["external"], json!("203.0.113.5"));
    let net = serde_json::to_value(doc.nat.one_to_one.get(&ok).unwrap()).unwrap();
    assert_eq!(net["external"], json!("203.0.113.0/28"));
}

#[test]
fn dhcp_rules() {
    let mut doc = Document::factory();
    let lan = *doc.dhcpv4.subnets.keys().next().unwrap();
    let mut dup = Subnet4::new("192.168.1.0/24".parse().unwrap());
    dup.pools = vec![
        "192.168.2.10-192.168.2.20".parse().unwrap(),
        "192.168.1.0/28".parse().unwrap(),
        "192.168.1.8-192.168.1.9".parse().unwrap(),
    ];
    dup.options.routers = vec!["10.0.0.1".parse().unwrap()];
    let d = doc.dhcpv4.subnets.push(dup);
    let mac = ClientMatch::HwAddress("00:11:22:33:44:55".parse().unwrap());
    let r1 = doc.dhcpv4.reservations.push(Reservation4 {
        subnet: Relation::new(lan),
        client: mac.clone(),
        ip_address: Some("192.168.1.50".parse().unwrap()),
        hostname: Some("printer".parse().unwrap()),
        description: None,
    });
    let r2 = doc.dhcpv4.reservations.push(Reservation4 {
        ip_address: Some("10.9.9.9".parse().unwrap()),
        ..doc.dhcpv4.reservations.get(&r1).unwrap().clone()
    });
    let r3 = doc.dhcpv4.reservations.push(Reservation4 {
        subnet: Relation::new(Uuid::new_v4()),
        ..doc.dhcpv4.reservations.get(&r1).unwrap().clone()
    });
    let v = doc.validate();
    for s in [lan, d] {
        assert_eq!(
            messages(&v, &format!("dhcpv4.subnets.{s}.subnet")),
            ["Subnet must be unique."]
        );
    }
    assert_eq!(
        messages(&v, &format!("dhcpv4.subnets.{d}.pools")),
        [
            "Pool 192.168.2.10-192.168.2.20 is not within subnet 192.168.1.0/24.",
            "Pool 192.168.1.8-192.168.1.9 overlaps another pool."
        ]
    );
    assert_eq!(
        messages(&v, &format!("dhcpv4.subnets.{d}.options.routers")),
        ["Router must be within the subnet."]
    );
    assert!(
        v.get(&format!("dhcpv4.reservations.{r1}.ip_address"))
            .is_none()
    );
    assert_eq!(
        messages(&v, &format!("dhcpv4.reservations.{r2}.client")),
        ["Duplicate entry exists."]
    );
    assert_eq!(
        messages(&v, &format!("dhcpv4.reservations.{r2}.ip_address")),
        ["Address not in specified subnet."]
    );
    assert_eq!(
        messages(&v, &format!("dhcpv4.reservations.{r3}.subnet")),
        ["Related subnet not found."]
    );
    let json = serde_json::to_value(doc.dhcpv4.reservations.get(&r1).unwrap()).unwrap();
    assert_eq!(json["client"], json!({"hw_address": "00:11:22:33:44:55"}));
    assert_eq!(
        "192.168.1.0/30".parse::<Pool4>().unwrap().to_string(),
        "192.168.1.0-192.168.1.3"
    );
}

#[test]
fn dns_rules() {
    let mut doc = Document::factory();
    let h: HostOverride = serde_json::from_value(json!({"hostname": "nas", "domain": "home.arpa", "record": {"rr": "A", "address": "192.168.1.5"}})).unwrap();
    assert_eq!(h.fqdn(), "nas.home.arpa");
    let a = doc.dns.host_overrides.push(h.clone());
    let b = doc.dns.host_overrides.push(h);
    let t = doc.dns.host_overrides.push(
        serde_json::from_value(
            json!({"domain": "home.arpa", "record": {"rr": "TXT", "data": ""}, "ttl": 60}),
        )
        .unwrap(),
    );
    let v = doc.validate();
    for id in [a, b] {
        assert_eq!(
            messages(&v, &format!("dns.host_overrides.{id}.record")),
            ["Duplicate entry exists."]
        );
    }
    assert_eq!(
        messages(&v, &format!("dns.host_overrides.{t}.record.data")),
        ["The TXT data must be a single non-empty line."]
    );
    assert!(matches!(
        doc.dns.host_overrides.get(&t).unwrap().record,
        DnsRecord::Txt { .. }
    ));
    assert!(
        serde_json::from_value::<HostOverride>(
            json!({"domain": "x", "record": {"rr": "A", "address": "::1"}})
        )
        .is_err()
    );
}

#[test]
fn wireguard_rules() {
    let mut doc = Document::factory();
    let peer = WgPeer {
        enabled: true,
        name: "laptop".parse().unwrap(),
        public_key: KEY_B.parse().unwrap(),
        preshared_key: None,
        allowed_ips: vec!["10.10.0.2/32".parse().unwrap()],
        endpoint: None,
        endpoint_port: None,
        keepalive: Some(25),
    };
    let p1 = doc.wireguard.peers.push(peer.clone());
    let p3 = doc.wireguard.peers.push(peer.clone());
    // Same key, different endpoint: allowed (uniqueness is over key+endpoint).
    let p2 = doc.wireguard.peers.push(WgPeer {
        allowed_ips: vec![],
        endpoint_port: Some(sensr_schema::fields::Port::new(51820).unwrap()),
        ..peer
    });
    let server: WgServer = serde_json::from_value(json!({
        "name": "wg_home", "instance": 0, "private_key": KEY_A, "listen_port": "51820",
        "tunnel_addresses": ["10.10.0.1/24"], "peers": [p1, Uuid::new_v4()], "gateway": "10.10.0.254", "mtu": 1420,
    })).unwrap();
    let s = doc.wireguard.servers.push(server);
    let v = doc.validate();
    for p in [p1, p3] {
        assert_eq!(
            messages(&v, &format!("wireguard.peers.{p}.public_key")),
            ["Public keys should be unique."]
        );
    }
    assert!(v.get(&format!("wireguard.peers.{p2}.public_key")).is_none());
    assert_eq!(
        messages(&v, &format!("wireguard.peers.{p2}.allowed_ips")),
        ["Allowed IPs are required."]
    );
    assert_eq!(
        messages(&v, &format!("wireguard.peers.{p2}.endpoint")),
        ["An endpoint port requires an endpoint address."]
    );
    assert_eq!(
        messages(&v, &format!("wireguard.servers.{s}.peers")),
        ["Related item not found."]
    );
    assert_eq!(
        messages(&v, &format!("wireguard.servers.{s}.disable_routes")),
        ["You have to enable Disable Routes option."]
    );
    let dbg = format!("{:?}", doc.wireguard.servers.get(&s).unwrap());
    assert!(!dbg.contains(KEY_A), "private key leaked into Debug: {dbg}");
}

#[test]
fn static_routes() {
    let mut doc = Document::factory();
    doc.set_by_path(
        "gateways.gateways.00000000-0000-0000-0000-0000000000a1",
        json!({"name": "WAN_GW", "interface": "wan", "address": "203.0.113.1"}),
    )
    .unwrap();
    doc.set_by_path(
        "gateways.gateways.00000000-0000-0000-0000-0000000000a6",
        json!({"name": "WAN_GW6", "interface": "wan", "family": "inet6", "address": "2001:db8::1"}),
    )
    .unwrap();
    let ok = [
        json!({"network": "10.20.0.0/16", "gateway": "WAN_GW"}),
        json!({"network": "10.30.0.0/16", "gateway": "WAN_GW6", "description": "RFC 5549 next hop"}),
        json!({"network": "2001:db8:1::/48", "gateway": "WAN_GW6"}),
    ];
    for (i, r) in ok.iter().enumerate() {
        doc.set_by_path(
            &format!("routes.routes.00000000-0000-0000-0000-00000000000{i}"),
            r.clone(),
        )
        .unwrap();
    }
    let v = doc.validate();
    assert!(v.is_ok(), "{v}");
    let bad = [
        (
            "b1",
            json!({"network": "2001:db8:2::/48", "gateway": "WAN_GW"}),
        ),
        ("b2", json!({"network": "10.40.0.0/16", "gateway": "NOPE"})),
        (
            "b3",
            json!({"network": "10.20.0.1/16", "gateway": "WAN_GW"}),
        ),
    ];
    for (k, r) in &bad {
        doc.set_by_path(
            &format!("routes.routes.00000000-0000-0000-0000-0000000000{k}"),
            r.clone(),
        )
        .unwrap();
    }
    let v = doc.validate();
    let p = |k: &str, f: &str| format!("routes.routes.00000000-0000-0000-0000-0000000000{k}.{f}");
    let gw = "Specify a valid gateway from the list matching the networks ip protocol.";
    assert_eq!(messages(&v, &p("b1", "gateway")), [gw]);
    assert_eq!(messages(&v, &p("b2", "gateway")), [gw]);
    assert_eq!(
        messages(&v, &p("b3", "network")),
        [
            "Specify a valid network matching the gateways ip protocol.".to_owned(),
            "Network 10.20.0.0/16 already has a route (item 00000000-0000-0000-0000-000000000000)."
                .to_owned()
        ]
    );
    assert!(
        !serde_json::to_string(&Document::factory())
            .unwrap()
            .contains("\"routes\""),
        "empty section is omitted"
    );
}

#[test]
fn devices_and_virtual_ips() {
    let mut doc = Document::factory();
    let set =
        |doc: &mut Document, path: &str, v: serde_json::Value| doc.set_by_path(path, v).unwrap();
    set(
        &mut doc,
        "devices.bridges.00000000-0000-0000-0000-000000000b01",
        json!({"device": "br0", "members": ["eth2", "eth3"], "stp": {"protocol": "rstp", "max_age": 20}}),
    );
    set(
        &mut doc,
        "devices.laggs.00000000-0000-0000-0000-000000000c01",
        json!({"device": "bond0", "members": ["eth4", "eth5"], "protocol": "lacp", "hash": ["l3", "l4"]}),
    );
    set(
        &mut doc,
        "devices.loopbacks.00000000-0000-0000-0000-000000000d01",
        json!({"id": 1, "description": "router id"}),
    );
    set(
        &mut doc,
        "virtual_ips.vips.00000000-0000-0000-0000-000000000e01",
        json!({"interface": "lan", "address": "192.168.1.2/24"}),
    );
    set(
        &mut doc,
        "virtual_ips.vips.00000000-0000-0000-0000-000000000e02",
        json!({"interface": "lan", "address": "192.168.1.254/24", "mode": {"mode": "carp", "vhid": 5, "password": "s3cret"}}),
    );
    let v = doc.validate();
    assert!(v.is_ok(), "{v}");
    assert!(doc.devices.defines(&"lo1".parse().unwrap()));

    set(
        &mut doc,
        "devices.bridges.00000000-0000-0000-0000-000000000b02",
        json!({"device": "bond0", "members": ["eth2", "br9"], "stp": {"edge": ["eth9"], "max_age": 2}}),
    );
    set(
        &mut doc,
        "devices.laggs.00000000-0000-0000-0000-000000000c02",
        json!({"device": "bond1", "members": ["eth5"], "primary_member": "eth6", "mtu": 100}),
    );
    set(
        &mut doc,
        "virtual_ips.vips.00000000-0000-0000-0000-000000000e03",
        json!({"interface": "opt9", "address": "192.168.1.0/24"}),
    );
    set(
        &mut doc,
        "virtual_ips.vips.00000000-0000-0000-0000-000000000e04",
        json!({"interface": "lan", "address": "192.168.1.255/24", "mode": {"mode": "carp", "vhid": 5, "password": ""}}),
    );
    set(
        &mut doc,
        "virtual_ips.vips.00000000-0000-0000-0000-000000000e05",
        json!({"interface": "lan", "address": "10.9.0.1/24", "mode": {"mode": "proxy_arp"}}),
    );
    let v = doc.validate();
    let b = "devices.bridges.00000000-0000-0000-0000-000000000b02";
    assert_eq!(
        messages(
            &v,
            "devices.laggs.00000000-0000-0000-0000-000000000c01.device"
        ),
        [format!("Device bond0 is already defined at {b}.device.")]
    );
    assert_eq!(
        messages(&v, &format!("{b}.members")),
        ["Member eth2 is already used by br0."]
    );
    assert_eq!(
        messages(&v, &format!("{b}.stp.max_age")),
        ["Please specify a value between 6 and 40."]
    );
    assert_eq!(
        messages(&v, &format!("{b}.stp")),
        ["Contains non bridge members."]
    );
    let l = "devices.laggs.00000000-0000-0000-0000-000000000c02";
    assert_eq!(
        messages(&v, &format!("{l}.members")),
        ["Members eth5 are already used in other laggs."]
    );
    assert_eq!(
        messages(&v, &format!("{l}.primary_member")),
        ["Primary member eth6 not in member list."]
    );
    let vp = |k: &str| format!("virtual_ips.vips.00000000-0000-0000-0000-000000000{k}");
    assert_eq!(
        messages(&v, &format!("{}.interface", vp("e03"))),
        ["The interface does not exist."]
    );
    assert_eq!(
        messages(&v, &format!("{}.address", vp("e03"))),
        ["You cannot use the network address."]
    );
    assert_eq!(
        messages(&v, &format!("{}.address", vp("e04"))),
        ["You cannot use the broadcast address."]
    );
    assert_eq!(
        messages(&v, &format!("{}.mode.password", vp("e04"))),
        ["You must specify a CARP password that is shared between the two VHID members."]
    );
    assert_eq!(
        messages(&v, &format!("{}.mode.vhid", vp("e04"))),
        ["VHID 5 is already used on lan."]
    );
    assert_eq!(
        messages(&v, &format!("{}.address", vp("e05"))),
        ["Only strict subnets are allowed for Proxy ARP types."]
    );
    let factory = serde_json::to_string(&Document::factory()).unwrap();
    assert!(
        !factory.contains("\"devices\"") && !factory.contains("\"virtual_ips\""),
        "empty sections are omitted"
    );
    let dbg = format!("{:?}", doc.virtual_ips);
    assert!(!dbg.contains("s3cret"), "CARP password leaked into Debug");
}

#[test]
fn dhcpv6_and_router_advertisements() {
    let mut doc = Document::factory();
    let set =
        |doc: &mut Document, path: &str, v: serde_json::Value| doc.set_by_path(path, v).unwrap();
    set(&mut doc, "dhcpv6.enabled", json!(true));
    set(&mut doc, "dhcpv6.interfaces", json!(["lan"]));
    let s1 = "00000000-0000-0000-0000-000000006001";
    let s2 = "00000000-0000-0000-0000-000000006002";
    set(
        &mut doc,
        &format!("dhcpv6.subnets.{s1}"),
        json!({"interface": "lan", "addressing": {"mode": "static", "subnet": "2001:db8:1::/64", "pools": ["2001:db8:1::1000-2001:db8:1::2000"]}}),
    );
    set(
        &mut doc,
        &format!("dhcpv6.subnets.{s2}"),
        json!({"interface": "lan", "addressing": {"mode": "dynamic_prefix"}}),
    );
    set(
        &mut doc,
        "dhcpv6.reservations.00000000-0000-0000-0000-000000006101",
        json!({"subnet": s1, "client": {"duid": "00:01:00:01"}, "ip_address": "2001:db8:1::50"}),
    );
    set(
        &mut doc,
        "router_advertisements.interfaces.00000000-0000-0000-0000-000000006201",
        json!({"interface": "lan", "mode": "assisted"}),
    );
    let v = doc.validate();
    assert!(v.is_ok(), "{v}");

    set(
        &mut doc,
        "dhcpv6.subnets.00000000-0000-0000-0000-000000006003",
        json!({"interface": "lan", "auto_options": true, "options": {"dns_servers": ["2001:db8::53"]}, "addressing": {"mode": "dynamic_prefix"}}),
    );
    set(
        &mut doc,
        "dhcpv6.subnets.00000000-0000-0000-0000-000000006004",
        json!({"interface": "wan", "addressing": {"mode": "static", "subnet": "2001:db8:2::1/64", "pools": ["2001:db8:3::1-2001:db8:3::9"]}}),
    );
    set(
        &mut doc,
        "dhcpv6.reservations.00000000-0000-0000-0000-000000006102",
        json!({"subnet": s2, "client": {"hw_address": "00:11:22:33:44:55"}}),
    );
    set(
        &mut doc,
        "dhcpv6.reservations.00000000-0000-0000-0000-000000006103",
        json!({"subnet": s1, "client": {"duid": "00:01:00:01"}, "ip_address": "2001:db8:9::1"}),
    );
    set(
        &mut doc,
        "dhcpv6.pd_pools.00000000-0000-0000-0000-000000006301",
        json!({"subnet": s1, "prefix": "2001:db8:100::/48", "delegated_len": 40}),
    );
    set(
        &mut doc,
        "router_advertisements.interfaces.00000000-0000-0000-0000-000000006202",
        json!({"interface": "lan", "prefix_from": "lan", "min_interval": 500, "nat64_prefix": "64:ff9b::/72", "default_lifetime": 100}),
    );
    let v = doc.validate();
    let sp = |k: &str, f: &str| format!("dhcpv6.subnets.00000000-0000-0000-0000-00000000{k}.{f}");
    assert_eq!(
        messages(&v, &sp("6003", "interface")),
        ["Only one dynamic prefix subnet may be configured per interface."]
    );
    assert_eq!(
        messages(&v, &sp("6003", "options.dns_servers")),
        ["DNS servers must be empty when option data autocollect is enabled."]
    );
    assert_eq!(
        messages(&v, &sp("6004", "interface")),
        ["Interface is not selected in the general settings."]
    );
    assert_eq!(
        messages(&v, &sp("6004", "addressing.subnet")),
        ["The subnet must be a network address."]
    );
    assert_eq!(
        messages(&v, &sp("6004", "addressing.pools")),
        ["Pool \"2001:db8:3::1-2001:db8:3::9\" not in specified subnet."]
    );
    let rp =
        |k: &str, f: &str| format!("dhcpv6.reservations.00000000-0000-0000-0000-00000000{k}.{f}");
    assert_eq!(
        messages(&v, &rp("6102", "subnet")),
        ["Reservations cannot be assigned to dynamic prefix subnets."]
    );
    assert_eq!(
        messages(&v, &rp("6103", "ip_address")),
        ["Address not in specified subnet."]
    );
    assert_eq!(
        messages(&v, &rp("6103", "client")),
        ["Duplicate entry exists."]
    );
    assert_eq!(
        messages(
            &v,
            "dhcpv6.pd_pools.00000000-0000-0000-0000-000000006301.delegated_len"
        ),
        ["Please specify a value between 48 and 128."]
    );
    let ra = |f: &str| {
        format!("router_advertisements.interfaces.00000000-0000-0000-0000-000000006202.{f}")
    };
    assert_eq!(
        messages(&v, &ra("interface")),
        ["Router advertisements are already configured for this interface."]
    );
    assert_eq!(
        messages(&v, &ra("prefix_from")),
        ["Constructor cannot be the same as interface."]
    );
    assert_eq!(
        messages(&v, &ra("nat64_prefix")),
        ["Prefix size must be one of 32, 40, 48, 56, 64 or 96."]
    );
    assert_eq!(
        messages(&v, &ra("min_interval")),
        ["Value cannot be greater than 450."]
    );
    assert_eq!(
        messages(&v, &ra("default_lifetime")),
        ["Value must be between 600 and 9000 seconds."]
    );
    let factory = serde_json::to_string(&Document::factory()).unwrap();
    assert!(
        !factory.contains("\"dhcpv6\"") && !factory.contains("router_advertisements"),
        "unconfigured sections are omitted"
    );
}

#[test]
fn ntp_settings() {
    let mut doc = Document::factory();
    doc.set_by_path(
        "system.time_servers",
        json!(["0.pool.ntp.org", "time.cloudflare.com"]),
    )
    .unwrap();
    doc.set_by_path(
        "ntp",
        json!({"serve": true, "listen_interfaces": ["lan"], "servers": [
        {"host": "0.pool.ntp.org", "pool": true, "iburst": true},
        {"host": "time.cloudflare.com", "nts": true, "prefer": true}
    ], "orphan_stratum": 10}),
    )
    .unwrap();
    let v = doc.validate();
    assert!(v.is_ok(), "{v}");
    assert!(
        doc.ntp
            .options(&"time.cloudflare.com".parse().unwrap())
            .unwrap()
            .nts
    );
    doc.set_by_path(
        "ntp.servers",
        json!([
            {"host": "ntp.example.org"},
            {"host": "0.pool.ntp.org", "prefer": true, "no_select": true},
            {"host": "0.pool.ntp.org"}
        ]),
    )
    .unwrap();
    doc.set_by_path("ntp.orphan_stratum", json!(16)).unwrap();
    let v = doc.validate();
    assert_eq!(
        messages(&v, "ntp.servers.0.host"),
        ["ntp.example.org is not one of the configured time servers."]
    );
    assert_eq!(
        messages(&v, "ntp.servers.1"),
        ["A server cannot be both preferred and never selected."]
    );
    assert_eq!(
        messages(&v, "ntp.servers.2.host"),
        ["Duplicate entry exists."]
    );
    assert_eq!(
        messages(&v, "ntp.orphan_stratum"),
        ["Please specify a value between 1 and 15."]
    );
    assert!(
        !serde_json::to_string(&Document::factory())
            .unwrap()
            .contains("\"ntp\"")
    );
}

#[test]
fn system_rules() {
    let mut doc = Document::factory();
    let user = User {
        name: "root".parse().unwrap(),
        uid: 0,
        description: None,
        disabled: false,
        password_hash: Some("$2y$10$abc".to_owned().into()),
        authorized_keys: vec![],
        groups: vec!["admins".parse().unwrap()],
        shell: Some("bin/sh".into()),
        api_keys: vec![],
    };
    let u1 = doc.system.users.push(user.clone());
    let u2 = doc.system.users.push(user);
    let v = doc.validate();
    for u in [u1, u2] {
        assert_eq!(
            messages(&v, &format!("system.users.{u}.name")),
            ["This username already exist."]
        );
        assert_eq!(
            messages(&v, &format!("system.users.{u}.uid")),
            ["This user ID is already in use."]
        );
        assert_eq!(
            messages(&v, &format!("system.users.{u}.groups")),
            ["Group admins does not exist."]
        );
        assert_eq!(
            messages(&v, &format!("system.users.{u}.shell")),
            ["The shell must be an absolute path."]
        );
    }
    let key = |k: &str, h: &str| sensr_schema::models::system::ApiKey {
        key: k.into(),
        secret_hash: h.to_owned().into(),
    };
    doc.system.users.get_mut(&u1).unwrap().api_keys = vec![
        key("a2V5MQ==", "$6$salt$hash"),
        key("a2V5MQ==", "plain"),
        key("bad key", "$6$x"),
    ];
    let v = doc.validate();
    assert_eq!(
        messages(&v, &format!("system.users.{u1}.api_keys.1.key")),
        ["This API key already exists."]
    );
    assert_eq!(
        messages(&v, &format!("system.users.{u1}.api_keys.1.secret_hash")),
        ["The API secret must be stored as a crypt(3) hash."]
    );
    assert_eq!(
        messages(&v, &format!("system.users.{u1}.api_keys.2.key")),
        ["An API key must be base64 text."]
    );
    assert!(
        v.get(&format!("system.users.{u1}.api_keys.0.key"))
            .is_none()
    );
    doc.system.users.get_mut(&u1).unwrap().api_keys.clear();
    doc.system.groups.push(Group {
        name: "admins".parse().unwrap(),
        gid: 1999,
        description: None,
        privileges: vec!["page-all".into()],
    });
    assert!(
        doc.validate()
            .get(&format!("system.users.{u1}.groups"))
            .is_none()
    );
}

#[test]
fn oidc_providers_validate_and_sort() {
    let mut doc = Document::factory();
    let mut p = OidcProvider {
        kind: OidcProviderKind::Generic,
        enabled: true,
        name: "Zitadel".into(),
        issuer: "https://id.example.com".parse().unwrap(),
        client_id: "client".into(),
        client_secret: None,
        team_id: None,
        key_id: None,
        private_key: None,
        scopes: vec![],
        username_claim: "email".into(),
        groups_claim: None,
        allowed_groups: vec![],
        local_group: "admins".parse().unwrap(),
    };
    let id = doc.system.oidc.providers.push(p.clone());
    // Disabled globally: nothing is offered.
    assert!(doc.system.oidc.active().is_empty());
    doc.system.oidc.enabled = true;
    let v = doc.validate();
    assert_eq!(
        messages(&v, &format!("system.oidc.providers.{id}.local_group")),
        ["Group admins does not exist."]
    );

    doc.system.groups.push(Group {
        name: "admins".parse().unwrap(),
        gid: 1999,
        description: None,
        privileges: vec!["page-all".into()],
    });
    assert!(doc.validate().is_ok());

    p.name = "Google".into();
    p.issuer = "http://accounts.example.com".parse().unwrap();
    p.client_id = " ".into();
    p.username_claim = String::new();
    let id2 = doc.system.oidc.providers.push(p);
    let v = doc.validate();
    for (path, message) in [
        (
            format!("system.oidc.providers.{id2}.issuer"),
            "The issuer must use https (http is allowed only for localhost).",
        ),
        (
            format!("system.oidc.providers.{id2}.client_id"),
            "The client id is required.",
        ),
        (
            format!("system.oidc.providers.{id2}.username_claim"),
            "A claim that carries the login name is required.",
        ),
    ] {
        assert_eq!(messages(&v, &path), [message]);
    }
    // localhost is the one plain-HTTP exception.
    doc.system.oidc.providers.get_mut(&id2).unwrap().issuer =
        "http://localhost:8080".parse().unwrap();
    assert!(
        doc.validate()
            .get(&format!("system.oidc.providers.{id2}.issuer"))
            .is_none()
    );

    // The login page gets enabled providers in name order.
    let mut names: Vec<_> = doc
        .system
        .oidc
        .active()
        .iter()
        .map(|(_, p)| p.name.clone())
        .collect();
    names.sort();
    assert_eq!(
        doc.system
            .oidc
            .active()
            .iter()
            .map(|(_, p)| &p.name)
            .collect::<Vec<_>>(),
        names.iter().collect::<Vec<_>>()
    );
    // A disabled entry never reaches the login page.
    doc.system.oidc.providers.get_mut(&id).unwrap().enabled = false;
    assert_eq!(doc.system.oidc.active().len(), 1);
}

#[test]
fn apple_provider_needs_a_complete_key_or_secret() {
    let mut doc = Document::factory();
    doc.system.groups.push(Group {
        name: "admins".parse().unwrap(),
        gid: 1999,
        description: None,
        privileges: vec!["page-all".into()],
    });
    doc.system.oidc.enabled = true;
    let p = OidcProvider {
        kind: OidcProviderKind::Apple,
        enabled: true,
        name: "Apple".into(),
        issuer: "https://appleid.apple.com".parse().unwrap(),
        client_id: "com.example.sensr".into(),
        client_secret: None,
        team_id: Some("TEAM123456".into()),
        key_id: None,
        private_key: None,
        scopes: vec![],
        username_claim: "email".into(),
        groups_claim: None,
        allowed_groups: vec![],
        local_group: "admins".parse().unwrap(),
    };
    let id = doc.system.oidc.providers.push(p);
    let v = doc.validate();
    assert_eq!(
        messages(&v, &format!("system.oidc.providers.{id}.private_key")),
        ["Apple needs the team id, key id and private key together (or a pasted client secret)."]
    );
}

/// Extracts user-facing message literals from library source (outside test
/// modules): the argument after a `ValidatorKind`, of `FieldError`
/// constructors, message constants, and literals alone on a line inside such
/// a call.
fn message_literals(src: &str) -> Vec<String> {
    let body = src.split("#[cfg(test)]").next().unwrap_or_default();
    let mut out = Vec::new();
    let mut in_call = false;
    for line in body.lines() {
        // Messages built with `format!` count; other `format!` strings
        // (captions, keys) are only picked up after a validator kind.
        let owned = line.trim().replace("format!(\"", "\"");
        let t = owned.as_str();
        let mut starts: Vec<usize> = Vec::new();
        for pat in ["syntax(\"", "callback(\"", "range(\"", "msg(\""] {
            if let Some(i) = t.find(pat) {
                starts.push(i + pat.len());
            }
        }
        if let Some(i) = t.find("ValidatorKind::")
            && let Some(j) = t[i..].find(", \"")
            && t[i + "ValidatorKind::".len()..i + j]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric())
        {
            starts.push(i + j + 3);
        }
        if t.starts_with("pub const ") && t.contains(": &str = \"") {
            starts.push(t.find('"').unwrap() + 1);
        }
        if in_call && t.starts_with('"') {
            starts.push(1);
        }
        for st in starts {
            let rest = &t[st..];
            let end = rest
                .char_indices()
                .find(|&(i, c)| c == '"' && !rest[..i].ends_with('\\'))
                .map(|(i, _)| i);
            if let Some(end) = end {
                let lit = &rest[..end];
                // Pure placeholders (`"{p}: {}"`) are formatting, and a
                // trailing placeholder is an embedded message checked on its own.
                if lit.contains(' ') && !lit.starts_with('{') && !lit.ends_with('}') {
                    out.push(lit.trim().to_owned());
                }
            }
        }
        in_call = t.ends_with("ValidatorKind::Callback,")
            || t.ends_with("ValidatorKind::Regex,")
            || t.ends_with("ValidatorKind::Constraint,")
            || t.ends_with("ValidatorKind::MinMax,")
            || t.ends_with("syntax(")
            || t.ends_with("callback(")
            || t.starts_with("&&")
            || t.ends_with("),");
    }
    out
}

#[test]
fn every_validation_message_is_a_sentence_t0361_t0362() {
    let mut all = Vec::new();
    let mut dirs = vec![std::path::PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src"
    ))];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                dirs.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                all.extend(message_literals(&std::fs::read_to_string(&p).unwrap()));
            }
        }
    }
    assert!(
        all.len() > 60,
        "scanner found too few messages: {}",
        all.len()
    );
    for m in all {
        assert!(m.ends_with('.'), "message must end with a period: {m:?}");
        assert!(
            m.starts_with(char::is_uppercase) || m.starts_with(['%', '[', '"']),
            "message must start upper-case: {m:?}"
        );
    }
}
