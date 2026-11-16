//! Slice models: serde shape, defaults, validation messages and path edits.
//!
//! Covers: SYS-001, IF-001, IF-006, FW-001, FW-AL-001, NAT-001, NAT-002,
//! DHCP-KEA-001, DNS-UB-001, VPN-WG-001

use pretty_assertions::assert_eq;
use sensr_schema::models::dhcp::{ClientMatch, Pool4, Reservation4, Subnet4};
use sensr_schema::models::dns::{DnsRecord, HostOverride};
use sensr_schema::models::firewall::{Alias, FilterRule};
use sensr_schema::models::interfaces::{Ipv4Config, Ipv6Config};
use sensr_schema::models::nat::{ForwardFilter, PortForward};
use sensr_schema::models::system::{Group, User};
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
