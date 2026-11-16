use super::*;
use crate::fixtures;

fn import(rel: &str) -> Imported<SensrDocument> {
    import_config(&fixtures::read(rel), &ImportOptions::default()).expect("parses")
}

#[test]
fn home_router_imports_with_no_unexpected_nodes() {
    let imported = import("corpus/home-router.xml");
    let report = &imported.report;
    assert!(
        report.unmapped_unexpected.is_empty(),
        "unexpected unmapped nodes:\n{report}"
    );
    assert!(report.is_clean(), "{report}");
    let problems = imported.document.validate();
    assert!(
        problems.is_empty(),
        "document does not validate: {problems:?}"
    );
}

#[test]
fn import_is_deterministic() {
    let a = import("corpus/home-router.xml");
    let b = import("corpus/home-router.xml");
    assert_eq!(a.document, b.document);
    assert_eq!(a.report, b.report);
}

/// Compare `actual` with the golden file `tests/golden/<name>`; `UPDATE_GOLDEN=1`
/// rewrites it instead.
fn golden(name: &str, actual: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (run with UPDATE_GOLDEN=1 to create it)",
            path.display()
        )
    });
    pretty_assertions::assert_eq!(expected, actual, "{name} differs from its golden file");
}

#[test]
fn corpus_reports_and_documents_match_golden() {
    for (fixture, stem) in [
        ("corpus/home-router.xml", "home-router"),
        ("corpus/multiwan.xml", "multiwan"),
        ("corpus/isc-dhcp.xml", "isc-dhcp"),
        ("corpus/fibre-passthrough.xml", "fibre-passthrough"),
        ("opnsense/Sample/config.xml", "sample"),
    ] {
        let i = import(fixture);
        golden(&format!("{stem}.import-report.txt"), &i.report.to_string());
        let json = serde_json::to_string_pretty(&i.document).unwrap() + "\n";
        golden(&format!("{stem}.sensr.json"), &json);
    }
}

fn import_str(xml: &str) -> Imported<SensrDocument> {
    import_config(xml, &ImportOptions::default()).expect("parses")
}

const IFACES: &str = "<interfaces>\
    <wan><if>em0</if><enable>1</enable><ipaddr>dhcp</ipaddr></wan>\
    <lan><if>em1</if><enable>1</enable><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>\
    </interfaces>";

#[test]
fn rule_order_follows_pf_priority_bands() {
    // Floating first, then MVC interface rules by sequence, then legacy interface
    // rules in file order (FilterRuleField::getPriority, filter_core_rules_user).
    let xml = format!(
        "<opnsense>{IFACES}\
         <filter>\
           <rule><type>pass</type><interface>lan</interface><descr>legacy-a</descr><source><any/></source><destination><any/></destination></rule>\
           <rule><type>block</type><floating>yes</floating><interface>wan,lan</interface><descr>floating</descr></rule>\
           <rule><type>pass</type><interface>lan</interface><descr>legacy-b</descr><disabled>1</disabled></rule>\
         </filter>\
         <OPNsense><Firewall><Filter><rules>\
           <rule uuid=\"00000000-0000-4000-8000-000000000002\"><enabled>1</enabled><sequence>20</sequence><action>pass</action><quick>1</quick><interface>lan</interface><source_net>lan</source_net><destination_net>any</destination_net><description>mvc-20</description></rule>\
           <rule uuid=\"00000000-0000-4000-8000-000000000001\"><enabled>1</enabled><sequence>10</sequence><action>pass</action><quick>1</quick><interface>lan</interface><source_net>lan</source_net><destination_net>lanip</destination_net><description>mvc-10</description></rule>\
         </rules></Filter></Firewall></OPNsense></opnsense>"
    );
    let i = import_str(&xml);
    let order: Vec<(u32, String, bool, bool)> = i
        .document
        .firewall
        .rules_in_order()
        .into_iter()
        .map(|(_, r)| {
            (
                r.sequence,
                r.description
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                r.enabled,
                r.quick,
            )
        })
        .collect();
    assert_eq!(
        order,
        [
            (10, "floating".into(), true, false),
            (20, "mvc-10".into(), true, true),
            (30, "mvc-20".into(), true, true),
            (40, "legacy-a".into(), true, true),
            (50, "legacy-b".into(), false, true),
        ]
    );
    let mvc10 = i
        .document
        .firewall
        .rules
        .find(|r| r.sequence == 20)
        .unwrap()
        .1;
    assert_eq!(mvc10.destination.net.to_string(), "addr:lan");
    assert!(i.report.unmapped_unexpected.is_empty(), "{}", i.report);
}

#[test]
fn equal_sequences_order_by_uuid_naturally() {
    // `sortedBy(['sequence'])` keys ties by UUID in PHP's natural order, so
    // "9…" sorts before "12…" although "1" < "9" as text.
    let rule = |uuid: &str, d: &str| {
        format!(
            "<rule uuid=\"{uuid}\"><enabled>1</enabled><sequence>1</sequence><action>pass</action><interface>lan</interface><source_net>any</source_net><destination_net>any</destination_net><description>{d}</description></rule>"
        )
    };
    let xml = format!(
        "<opnsense>{IFACES}<OPNsense><Firewall><Filter><rules>{}{}{}</rules></Filter></Firewall></OPNsense></opnsense>",
        rule("12e06f06-72e3-44dd-8f98-7c70ddc0a468", "twelve"),
        rule("9a0d1c55-9e1a-4f7e-8a51-0c1f2f6f1a01", "nine"),
        rule("A0000000-0000-4000-8000-000000000000", "upper-a"),
    );
    let i = import_str(&xml);
    let order: Vec<String> = i
        .document
        .firewall
        .rules_in_order()
        .into_iter()
        .map(|(_, r)| r.description.as_ref().unwrap().to_string())
        .collect();
    assert_eq!(order, ["nine", "twelve", "upper-a"]);
}

#[test]
fn interface_groups_import_with_their_tier() {
    let xml = "<opnsense>\
         <interfaces>\
           <wan><if>em0</if><enable>1</enable><ipaddr>dhcp</ipaddr></wan>\
           <lan><if>em1</if><enable>1</enable><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>\
           <opt1><if>em2</if><enable>1</enable><ipaddr>192.168.2.1</ipaddr><subnet>24</subnet></opt1>\
           <wireguard><internal_dynamic>1</internal_dynamic><descr>WireGuard (Group)</descr><if>wireguard</if><virtual>1</virtual><enable>1</enable><type>group</type><networks/></wireguard>\
         </interfaces>\
         <ifgroups version=\"1.0.0\"><ifgroupentry uuid=\"00000000-0000-4000-8000-0000000000aa\"><ifname>inside</ifname><members>lan,opt1</members><nogroup>0</nogroup><sequence>4</sequence><descr>Inside</descr></ifgroupentry></ifgroups>\
         <OPNsense><Firewall><Filter><rules>\
           <rule uuid=\"00000000-0000-4000-8000-000000000001\"><enabled>1</enabled><sequence>1</sequence><action>pass</action><interface>lan</interface><source_net>any</source_net><destination_net>any</destination_net><description>lan</description></rule>\
           <rule uuid=\"00000000-0000-4000-8000-000000000002\"><enabled>1</enabled><sequence>9</sequence><action>block</action><interface>inside</interface><source_net>any</source_net><destination_net>any</destination_net><description>group</description></rule>\
           <rule uuid=\"00000000-0000-4000-8000-000000000003\"><enabled>1</enabled><sequence>9</sequence><action>pass</action><interface>wireguard</interface><source_net>any</source_net><destination_net>any</destination_net><description>wireguard</description></rule>\
         </rules></Filter></Firewall></OPNsense></opnsense>";
    let i = import_str(xml);
    assert!(i.report.unmapped_unexpected.is_empty(), "{}", i.report);
    let fw = &i.document.firewall;
    let inside = fw.group(&"inside".parse().unwrap()).expect("inside");
    assert_eq!(inside.sequence, 4);
    assert_eq!(inside.members.len(), 2);
    assert!(fw.group(&"wireguard".parse().unwrap()).unwrap().wireguard);
    // groups (300000 + 0 for wireguard, + 4 for inside) before the interface rule
    let order: Vec<String> = fw
        .rules_in_order()
        .into_iter()
        .map(|(_, r)| r.description.as_ref().unwrap().to_string())
        .collect();
    assert_eq!(order, ["wireguard", "group", "lan"]);
    assert!(
        i.document.validate().is_empty(),
        "{:?}",
        i.document.validate()
    );
    // and back
    let again = import_str(&super::export_config(&i.document));
    assert_eq!(again.document.firewall.groups, i.document.firewall.groups);
}

#[test]
fn not_any_imports_as_any_with_a_warning() {
    let xml = format!(
        "<opnsense>{IFACES}<OPNsense><Firewall><Filter><rules>\
           <rule uuid=\"00000000-0000-4000-8000-000000000001\"><enabled>1</enabled><action>block</action><interface>lan</interface><source_net>lan</source_net><destination_net>any</destination_net><destination_not>1</destination_not><description>printers</description></rule>\
         </rules></Filter></Firewall></OPNsense>\
         <filter><rule><type>block</type><interface>lan</interface><source><any/><not/></source><destination><any/></destination><descr>legacy</descr></rule></filter></opnsense>"
    );
    let i = import_str(&xml);
    for r in i.document.firewall.rules.values() {
        assert!(!r.source.not && !r.destination.not, "{r:?}");
    }
    let report = i.report.to_string();
    assert_eq!(report.matches("\"not any\"").count(), 2, "{report}");
    assert!(i.document.validate().is_empty());
}

#[test]
fn unsupported_rule_settings_are_reported_not_dropped() {
    // A policy-routing gateway has no sensr equivalent yet: the rule imports, the
    // gateway leaf is reported. A rule with two source networks cannot be expressed
    // and is reported whole with an invalid-value warning.
    let xml = format!(
        "<opnsense>{IFACES}<OPNsense><Firewall><Filter><rules>\
           <rule uuid=\"00000000-0000-4000-8000-000000000001\"><enabled>1</enabled><action>pass</action><interface>lan</interface><source_net>lan</source_net><destination_net>any</destination_net><gateway>WAN2</gateway></rule>\
           <rule uuid=\"00000000-0000-4000-8000-000000000002\"><enabled>1</enabled><action>block</action><interface>lan</interface><source_net>10.0.0.0/8,lan</source_net><destination_net>any</destination_net></rule>\
         </rules></Filter></Firewall></OPNsense></opnsense>"
    );
    let i = import_str(&xml);
    assert_eq!(i.document.firewall.rules.len(), 1);
    let unexpected: Vec<&str> = i
        .report
        .unmapped_unexpected
        .iter()
        .map(|u| u.xpath.as_str())
        .collect();
    assert_eq!(
        unexpected,
        [
            "/opnsense/OPNsense/Firewall/Filter/rules/rule[@uuid='00000000-0000-4000-8000-000000000001']/gateway",
            "/opnsense/OPNsense/Firewall/Filter/rules/rule[@uuid='00000000-0000-4000-8000-000000000002']",
        ]
    );
    assert!(
        i.report
            .warnings
            .iter()
            .any(|w| w.severity == crate::Severity::Invalid
                && w.message.contains("multiple source addresses"))
    );
    assert!(!i.report.is_clean());
}

#[test]
fn isc_dhcpd_maps_to_dhcpv4() {
    let xml = format!(
        "<opnsense>{IFACES}<dhcpd><lan><enable>1</enable>\
           <range><from>192.168.1.100</from><to>192.168.1.199</to></range>\
           <dnsserver>192.168.1.1</dnsserver><domain>home.example</domain><defaultleasetime>7200</defaultleasetime>\
           <staticmap><mac>02:00:5e:00:00:01</mac><ipaddr>192.168.1.10</ipaddr><hostname>nas</hostname><descr>NAS</descr></staticmap>\
         </lan></dhcpd></opnsense>"
    );
    let i = import_str(&xml);
    let d = &i.document.dhcpv4;
    assert!(d.enabled);
    assert_eq!(d.interfaces, ["lan".parse().unwrap()]);
    let (sid, subnet) = d.subnets.iter().next().unwrap();
    assert_eq!(subnet.subnet.to_string(), "192.168.1.0/24");
    assert_eq!(subnet.pools[0].to_string(), "192.168.1.100-192.168.1.199");
    assert_eq!(subnet.valid_lifetime, Some(7200));
    assert_eq!(
        subnet.options.dns_servers,
        ["192.168.1.1".parse::<std::net::Ipv4Addr>().unwrap()]
    );
    let r = d.reservations.values().next().unwrap();
    assert_eq!(r.subnet.id(), *sid);
    assert_eq!(r.hostname.as_ref().unwrap().to_string(), "nas");
    assert!(i.report.unmapped_unexpected.is_empty(), "{}", i.report);
    assert!(
        i.document.validate().is_empty(),
        "{:?}",
        i.document.validate()
    );
    // Legacy items without uuids get stable ones.
    assert_eq!(import_str(&xml).document, i.document);
}

/// MVC BooleanFields: empty means off. A stock config writes `<dnssec/>`,
/// `<dns64/>` and `<forwarding><enabled/></forwarding>`; reading them as
/// presence flags turned DNSSEC, DNS64 and forwarding on (the router must
/// recurse), and an empty `privateaddress` keeps rebinding protection on
/// only when the list holds networks.
#[test]
fn unbound_empty_booleans_are_off() {
    let i = import_str(
        "<opnsense><OPNsense><unboundplus version=\"1.0.15\"><general><enabled>1</enabled><port>53</port><dnssec/><dns64/><regdhcp>1</regdhcp><regdhcpstatic/><stats>1</stats></general><advanced><belownxdomain>1</belownxdomain><aggressivensec>1</aggressivensec><privateaddress>10.0.0.0/8,192.168.0.0/16</privateaddress></advanced><forwarding><enabled/></forwarding><dots/><hosts/></unboundplus></OPNsense></opnsense>",
    );
    let d = &i.document.dns;
    assert!(d.enabled && d.statistics && d.register_dhcp_leases);
    assert!(!d.dnssec && !d.dns64 && !d.register_dhcp_static);
    assert!(!d.forwarding.use_system_servers, "the router recurses");
    assert!(d.tuning.harden_below_nxdomain && d.tuning.aggressive_nsec);
    assert_eq!(
        d.tuning.private_addresses,
        [
            "10.0.0.0/8".parse::<ipnet::IpNet>().unwrap(),
            "192.168.0.0/16".parse().unwrap()
        ]
    );
}

#[test]
fn device_names_can_be_mapped_to_linux() {
    let mut options = ImportOptions::default();
    options
        .devices
        .insert("em0".into(), "enp1s0".parse().unwrap());
    let i = import_config(&format!("<opnsense>{IFACES}</opnsense>"), &options).unwrap();
    let wan = i.document.interfaces.get(&"wan".parse().unwrap()).unwrap();
    assert_eq!(wan.device.as_str(), "enp1s0");
    // em1 was not mapped: kept, with a note for the assignment step.
    assert!(
        i.report
            .warnings
            .iter()
            .any(|w| w.xpath == "/opnsense/interfaces/lan/if")
    );
    assert!(
        !i.report
            .warnings
            .iter()
            .any(|w| w.xpath == "/opnsense/interfaces/wan/if")
    );
}

#[test]
fn export_then_import_is_identical() {
    for f in [
        "corpus/home-router.xml",
        "corpus/multiwan.xml",
        "corpus/isc-dhcp.xml",
        "corpus/fibre-passthrough.xml",
        "opnsense/Sample/config.xml",
    ] {
        let first = import(f);
        let xml = export_config(&first.document);
        let second = import_config(&xml, &ImportOptions::default()).expect("export parses");
        pretty_assertions::assert_eq!(first.document, second.document, "{f}: re-import differs");
        assert!(
            second.report.unmapped_unexpected.is_empty(),
            "{f}: export wrote nodes the importer does not read:\n{}",
            second.report
        );
    }
}

#[test]
fn every_fixture_imports_and_round_trips() {
    for (path, text) in fixtures::all_xml() {
        let first = import_config(&text, &ImportOptions::default())
            .unwrap_or_else(|e| panic!("{path}: {e}"));
        let second =
            import_config(&export_config(&first.document), &ImportOptions::default()).unwrap();
        pretty_assertions::assert_eq!(first.document, second.document, "{path}: re-import differs");
        if std::env::var_os("SHOW_REPORTS").is_some() {
            eprintln!(
                "==== {path}: {} unexpected",
                first.report.unmapped_unexpected.len()
            );
            for u in &first.report.unmapped_unexpected {
                eprintln!("  {}", u.xpath);
            }
        }
    }
}

proptest::proptest! {
    // The importer never panics on structurally valid XML with OPNsense-shaped
    // names and arbitrary text, and its document always exports.
    #[test]
    fn prop_import_never_panics(
        sections in proptest::collection::vec(
            (
                proptest::sample::select(vec![
                    "system", "interfaces", "filter", "nat", "dhcpd", "dnsmasq", "unbound", "vlans", "gateways", "ca", "cert",
                ]),
                proptest::collection::vec(
                    (
                        proptest::sample::select(vec![
                            "wan", "lan", "opt1", "rule", "user", "group", "vlan", "staticmap", "outbound", "if", "ipaddr",
                            "subnet", "ipaddrv6", "track6-interface", "enable", "hostname", "dnsserver", "gateway_item",
                        ]),
                        "[ -~]{0,12}",
                    ),
                    0..6,
                ),
            ),
            0..6,
        )
    ) {
        let mut xml = String::from("<opnsense>");
        for (section, children) in &sections {
            xml.push_str(&format!("<{section}>"));
            for (name, text) in children {
                let text = text.replace('&', "&amp;").replace('<', "&lt;");
                xml.push_str(&format!("<{name}>{text}</{name}>"));
            }
            xml.push_str(&format!("</{section}>"));
        }
        xml.push_str("</opnsense>");
        let imported = import_config(&xml, &ImportOptions::default()).unwrap();
        let _ = export_config(&imported.document);
    }
}

fn unexpected(i: &Imported<SensrDocument>) -> Vec<&str> {
    i.report
        .unmapped_unexpected
        .iter()
        .map(|u| u.xpath.as_str())
        .collect()
}

fn warnings(i: &Imported<SensrDocument>, severity: crate::Severity) -> Vec<(&str, &str)> {
    i.report
        .warnings
        .iter()
        .filter(|w| w.severity == severity)
        .map(|w| (w.xpath.as_str(), w.message.as_str()))
        .collect()
}

const IFACES2: &str = "<interfaces>\
    <wan><if>em0</if><enable>1</enable><ipaddr>dhcp</ipaddr></wan>\
    <lan><if>em1</if><enable>1</enable><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan>\
    <opt1><if>em2</if><enable>1</enable><ipaddr>192.168.40.1</ipaddr><subnet>24</subnet></opt1>\
    </interfaces>";

/// ISC dhcpd block for `iface` (`192.168.<n>.0/24`) with one static map.
fn isc_block(iface: &str, n: u8, enabled: bool) -> String {
    let enable = if enabled { "<enable>1</enable>" } else { "" };
    format!(
        "<{iface}>{enable}<domain>{iface}.home.example</domain>\
           <range><from>192.168.{n}.100</from><to>192.168.{n}.199</to></range>\
           <staticmap><mac>02:00:5e:00:{n:02x}:01</mac><ipaddr>192.168.{n}.10</ipaddr><hostname>host{n}</hostname><descr>Host {n}</descr></staticmap>\
         </{iface}>"
    )
}

const KEA_LAN_SUBNET: &str = "00000000-0000-4000-8000-0000000000a1";

/// Kea dhcp4 with one subnet for LAN and one reservation in it.
fn kea(enabled: bool, interfaces: &str) -> String {
    let e = u8::from(enabled);
    format!(
        "<OPNsense><Kea><dhcp4><general><enabled>{e}</enabled><interfaces>{interfaces}</interfaces><valid_lifetime>3600</valid_lifetime><fwrules>1</fwrules></general>\
           <subnets><subnet4 uuid=\"{KEA_LAN_SUBNET}\"><interface>lan</interface><subnet>192.168.1.0/24</subnet><option_data_autocollect>1</option_data_autocollect><pools>192.168.1.50-192.168.1.60</pools></subnet4></subnets>\
           <reservations><reservation uuid=\"00000000-0000-4000-8000-0000000000b1\"><subnet>{KEA_LAN_SUBNET}</subnet><ip_address>192.168.1.20</ip_address><hw_address>02:00:5e:00:00:20</hw_address><hostname>keahost</hostname></reservation></reservations>\
         </dhcp4></Kea></OPNsense>"
    )
}

fn assert_valid(i: &Imported<SensrDocument>) {
    let problems = i.document.validate();
    assert!(
        problems.is_empty(),
        "document does not validate: {problems:?}"
    );
}

#[test]
fn disabled_kea_does_not_duplicate_the_active_isc_subnets() {
    // The owner's shape: ISC on two interfaces, Kea left configured but disabled.
    let i = import("corpus/isc-dhcp.xml");
    assert!(i.report.unmapped_unexpected.is_empty(), "{}", i.report);
    assert!(i.report.is_clean(), "{}", i.report);
    assert_valid(&i);
    let d = &i.document.dhcpv4;
    assert!(d.enabled);
    assert_eq!(
        d.interfaces,
        ["lan".parse().unwrap(), "opt1".parse().unwrap()]
    );
    let nets: Vec<String> = d.subnets.values().map(|s| s.subnet.to_string()).collect();
    assert_eq!(nets, ["192.168.1.0/24", "192.168.40.0/24"]);
    assert_eq!(d.reservations.len(), 3);
    // Kea's disabled general settings did not leak into the service.
    assert_eq!(d.valid_lifetime, 4000);
    let info = warnings(&i, crate::Severity::Info);
    let kea_notes: Vec<&str> = info
        .iter()
        .filter(|(x, _)| x.starts_with("/opnsense/OPNsense/Kea/dhcp4/"))
        .map(|(x, _)| *x)
        .collect();
    assert_eq!(
        kea_notes,
        [
            "/opnsense/OPNsense/Kea/dhcp4/general",
            "/opnsense/OPNsense/Kea/dhcp4/subnets/subnet4[@uuid='5d0c6a7e-2b9f-4c41-9e3a-6f1b2c3d4e51']",
            "/opnsense/OPNsense/Kea/dhcp4/subnets/subnet4[@uuid='8a4e2f1c-7d3b-4e65-a1c9-0b2d3e4f5a62']",
            "/opnsense/OPNsense/Kea/dhcp4/reservations/reservation[@uuid='c3f1a2b4-5d6e-4f70-8192-a3b4c5d6e7f8']",
        ]
    );
}

#[test]
fn isc_static_maps_become_reservations_with_the_subnet_domain() {
    let i = import("corpus/isc-dhcp.xml");
    let d = &i.document.dhcpv4;
    let (lan_id, lan) = d
        .subnets
        .iter()
        .find(|(_, s)| s.interface == Some("lan".parse().unwrap()))
        .unwrap();
    assert_eq!(
        lan.options.domain_name.as_ref().unwrap().to_string(),
        "home.example"
    );
    assert_eq!(lan.description.as_ref().unwrap().to_string(), "LAN clients");
    // dhcpd's own default-lease-time applies when the interface sets none.
    assert_eq!(lan.valid_lifetime, Some(7200));
    let nas = d
        .reservations
        .values()
        .find(|r| r.hostname.as_ref().is_some_and(|h| h.to_string() == "nas"))
        .unwrap();
    assert_eq!(nas.subnet.id(), *lan_id);
    assert_eq!(
        nas.client,
        sensr_schema::models::dhcp::ClientMatch::HwAddress("02:00:5e:10:00:01".parse().unwrap())
    );
    assert_eq!(nas.ip_address, Some("192.168.1.10".parse().unwrap()));
    assert_eq!(nas.description.as_ref().unwrap().to_string(), "Storage box");
}

#[test]
fn active_kea_replaces_disabled_isc_blocks() {
    let xml = format!(
        "<opnsense>{IFACES2}<dhcpd>{}</dhcpd>{}</opnsense>",
        isc_block("lan", 1, false),
        kea(true, "lan")
    );
    let i = import_str(&xml);
    assert!(i.report.unmapped_unexpected.is_empty(), "{}", i.report);
    assert_valid(&i);
    let d = &i.document.dhcpv4;
    assert!(d.enabled);
    assert_eq!(d.interfaces, ["lan".parse().unwrap()]);
    assert_eq!(d.valid_lifetime, 3600);
    assert_eq!(
        d.subnets
            .keys()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        [KEA_LAN_SUBNET]
    );
    assert_eq!(d.reservations.len(), 1);
    let info = warnings(&i, crate::Severity::Info);
    assert!(
        info.iter().any(|(x, m)| *x == "/opnsense/dhcpd/lan"
            && m.contains("ISC DHCP is disabled and Kea DHCPv4 serves")
            && m.contains("192.168.1.0/24")),
        "{info:?}"
    );
    assert!(
        info.iter()
            .any(|(x, _)| *x == "/opnsense/dhcpd/lan/staticmap")
    );
}

#[test]
fn isc_and_kea_both_enabled_import_kea_for_shared_subnets_and_warn() {
    // OPNsense starts both daemons; on LAN both answer. Kea's subnet is kept, the
    // ISC-only opt1 network keeps being served.
    let xml = format!(
        "<opnsense>{IFACES2}<dhcpd>{}{}</dhcpd>{}</opnsense>",
        isc_block("lan", 1, true),
        isc_block("opt1", 40, true),
        kea(true, "lan")
    );
    let i = import_str(&xml);
    assert!(i.report.unmapped_unexpected.is_empty(), "{}", i.report);
    assert_valid(&i);
    let d = &i.document.dhcpv4;
    assert_eq!(
        d.interfaces,
        ["lan".parse().unwrap(), "opt1".parse().unwrap()]
    );
    let mut nets: Vec<String> = d.subnets.values().map(|s| s.subnet.to_string()).collect();
    nets.sort();
    assert_eq!(nets, ["192.168.1.0/24", "192.168.40.0/24"]);
    assert!(d.subnets.contains(&KEA_LAN_SUBNET.parse().unwrap()));
    // Kea's reservation plus the opt1 static map; the LAN static map went with
    // its ISC subnet.
    assert_eq!(d.reservations.len(), 2);
    let degraded = warnings(&i, crate::Severity::Degraded);
    assert!(
        degraded.iter().any(|(x, m)| *x == "/opnsense/dhcpd/lan"
            && m.contains("both Kea DHCPv4 and ISC DHCP serve 192.168.1.0/24")),
        "{degraded:?}"
    );
    assert!(
        degraded
            .iter()
            .any(|(x, _)| *x == "/opnsense/OPNsense/Kea/dhcp4/general")
    );
}

#[test]
fn all_dhcp_servers_disabled_keep_one_subnet_per_network() {
    let xml = format!(
        "<opnsense>{IFACES2}<dhcpd>{}</dhcpd>{}</opnsense>",
        isc_block("lan", 1, false),
        kea(false, "lan")
    );
    let i = import_str(&xml);
    assert_valid(&i);
    let d = &i.document.dhcpv4;
    assert!(!d.enabled);
    assert_eq!(
        d.subnets
            .keys()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        [KEA_LAN_SUBNET]
    );
    assert_eq!(d.reservations.len(), 1);
    let info = warnings(&i, crate::Severity::Info);
    assert!(
        info.iter().any(|(x, m)| *x == "/opnsense/dhcpd/lan"
            && m.contains("Kea DHCPv4 also defines 192.168.1.0/24")),
        "{info:?}"
    );
}

#[test]
fn isc_empty_form_leaves_are_consumed_and_set_ones_reported() {
    let empty = format!(
        "<opnsense>{IFACES}<dhcpd><lan><enable>1</enable>\
           <ddnsdomainalgorithm>hmac-md5</ddnsdomainalgorithm><numberoptions><item/></numberoptions>\
           <range><from>192.168.1.100</from><to>192.168.1.199</to></range>\
           <winsserver/><dnsserver/><ntpserver/>\
           <staticmap><mac>02:00:5e:00:00:01</mac><ipaddr>192.168.1.10</ipaddr><hostname>nas</hostname>\
             <winsserver/><dnsserver/><ntpserver/></staticmap>\
         </lan></dhcpd></opnsense>"
    );
    let i = import_str(&empty);
    assert!(unexpected(&i).is_empty(), "{}", i.report);

    let set = format!(
        "<opnsense>{IFACES}<dhcpd><lan><enable>1</enable>\
           <ddnsdomainalgorithm>hmac-sha512</ddnsdomainalgorithm>\
           <numberoptions><item><number>252</number><type>text</type><value>http://wpad.home.example/wpad.dat</value></item></numberoptions>\
           <range><from>192.168.1.100</from><to>192.168.1.199</to></range>\
           <staticmap><mac>02:00:5e:00:00:01</mac><ipaddr>192.168.1.10</ipaddr><hostname>nas</hostname>\
             <winsserver>192.168.1.5</winsserver><dnsserver>192.168.1.53</dnsserver><ntpserver/></staticmap>\
         </lan></dhcpd></opnsense>"
    );
    let i = import_str(&set);
    assert_eq!(
        unexpected(&i),
        [
            "/opnsense/dhcpd/lan/ddnsdomainalgorithm",
            "/opnsense/dhcpd/lan/numberoptions",
            "/opnsense/dhcpd/lan/staticmap/winsserver",
            "/opnsense/dhcpd/lan/staticmap/dnsserver",
        ]
    );
    // The reservation itself still imports.
    assert_eq!(i.document.dhcpv4.reservations.len(), 1);
}

const DNSMASQ_LEFTOVERS: &str = "<regdhcp>1</regdhcp><regdhcpstatic>1</regdhcpstatic><dhcpfirst>0</dhcpfirst>\
    <strict_order>0</strict_order><domain_needed>1</domain_needed><no_private_reverse>1</no_private_reverse>\
    <no_resolv>0</no_resolv><log_queries>0</log_queries><no_hosts>0</no_hosts><strictbind>0</strictbind>\
    <dnssec>1</dnssec><regdhcpdomain>home.example</regdhcpdomain><dns_forward_max/><cache_size>1000</cache_size>\
    <local_ttl/><add_mac/><add_subnet>0</add_subnet><strip_subnet>0</strip_subnet>\
    <dhcp><enable_ra>1</enable_ra><authoritative>1</authoritative></dhcp><no_ident>1</no_ident>";

#[test]
fn disabled_dnsmasq_leftover_settings_are_consumed() {
    let xml = format!(
        "<opnsense>{IFACES}<dnsmasq><enable>0</enable>{DNSMASQ_LEFTOVERS}<port/></dnsmasq></opnsense>"
    );
    let i = import_str(&xml);
    assert!(unexpected(&i).is_empty(), "{}", i.report);
    // No note about dnsmasq's DNS service when dnsmasq does not run.
    assert!(
        !i.report
            .warnings
            .iter()
            .any(|w| w.xpath.starts_with("/opnsense/dnsmasq")),
        "{}",
        i.report
    );
}

#[test]
fn enabled_dnsmasq_settings_stay_reported() {
    let xml = format!(
        "<opnsense>{IFACES}<dnsmasq><enable>1</enable>{DNSMASQ_LEFTOVERS}</dnsmasq></opnsense>"
    );
    let i = import_str(&xml);
    let u = unexpected(&i);
    for leaf in ["regdhcp", "dnssec", "cache_size", "no_ident"] {
        assert!(
            u.contains(&format!("/opnsense/dnsmasq/{leaf}").as_str()),
            "{leaf}: {u:?}"
        );
    }
    assert!(u.contains(&"/opnsense/dnsmasq/dhcp/enable_ra"), "{u:?}");
}

#[test]
fn kea_ddns_and_control_agent_are_accepted_at_defaults_only() {
    let at_defaults = format!(
        "<opnsense>{IFACES}<OPNsense><Kea>\
           <ctrl_agent><general><enabled>0</enabled><http_host>127.0.0.1</http_host><http_port>8000</http_port></general></ctrl_agent>\
           <ddns><general><enabled>0</enabled><manual_config/><server_ip>127.0.0.1</server_ip><server_port>53001</server_port></general></ddns>\
         </Kea></OPNsense></opnsense>"
    );
    let i = import_str(&at_defaults);
    assert!(unexpected(&i).is_empty(), "{}", i.report);

    let changed = format!(
        "<opnsense>{IFACES}<OPNsense><Kea>\
           <ctrl_agent><general><enabled>1</enabled><http_host>127.0.0.1</http_host><http_port>8001</http_port></general></ctrl_agent>\
           <ddns><general><enabled>1</enabled><manual_config>0</manual_config><server_ip>127.0.0.1</server_ip><server_port>53001</server_port></general></ddns>\
         </Kea></OPNsense></opnsense>"
    );
    let i = import_str(&changed);
    assert_eq!(
        unexpected(&i),
        [
            "/opnsense/OPNsense/Kea/ctrl_agent/general/enabled",
            "/opnsense/OPNsense/Kea/ctrl_agent/general/http_port",
            "/opnsense/OPNsense/Kea/ddns/general/enabled",
        ]
    );
}

fn wan_xml(wan: &str, extra: &str) -> String {
    format!(
        "<opnsense><interfaces><wan><if>em0</if><enable>1</enable>{wan}</wan>\
         <lan><if>em1</if><enable>1</enable><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet>\
         <ipaddrv6>track6</ipaddrv6><track6-interface>wan</track6-interface><track6-prefix-id>0</track6-prefix-id></lan>\
         </interfaces>{extra}</opnsense>"
    )
}

fn wan(i: &Imported<SensrDocument>) -> &sensr_schema::models::interfaces::Interface {
    i.document.interfaces.get(&"wan".parse().unwrap()).unwrap()
}

fn degraded(i: &Imported<SensrDocument>, needle: &str) -> bool {
    i.report
        .warnings
        .iter()
        .any(|w| w.severity == crate::Severity::Degraded && w.message.contains(needle))
}

#[test]
fn spoofed_mac_round_trips_and_names_the_client_identifier() {
    use sensr_schema::models::interfaces::{DhcpClientId, Ipv4Config};
    let i = import_str(&wan_xml(
        "<spoofmac>02:00:5e:10:20:30</spoofmac><ipaddr>dhcp</ipaddr>\
         <adv_dhcp_config_advanced>1</adv_dhcp_config_advanced>\
         <adv_dhcp_send_options>dhcp-client-identifier 01:02:00:5e:10:20:30</adv_dhcp_send_options>",
        "",
    ));
    assert_eq!(wan(&i).spoof_mac.unwrap().to_string(), "02:00:5e:10:20:30");
    let Ipv4Config::Dhcp {
        client_id,
        send_options,
        ..
    } = &wan(&i).ipv4
    else {
        panic!("dhcp")
    };
    // the identifier dhclient would build from the spoofed MAC: nothing lost
    assert_eq!(*client_id, DhcpClientId::Mac);
    assert!(send_options.is_empty());
    assert!(
        i.report
            .warnings
            .iter()
            .all(|w| w.severity != crate::Severity::Degraded),
        "{}",
        i.report
    );
    let again = import_str(&export_config(&i.document));
    assert_eq!(wan(&again), wan(&i));
}

#[test]
fn dhcp4_advanced_options_map_or_are_reported() {
    use sensr_schema::models::interfaces::{DhcpOptionValue, Ipv4Config};
    let i = import_str(&wan_xml(
        "<ipaddr>dhcp</ipaddr><dhcphostname>gw</dhcphostname><dhcphonourmtu>1</dhcphonourmtu>\
         <adv_dhcp_config_advanced>1</adv_dhcp_config_advanced>\
         <adv_dhcp_pt_timeout>30</adv_dhcp_pt_timeout>\
         <adv_dhcp_send_options>vendor-class-identifier \"acme\", user-class \"tv\", option-125 00:00:0d:e9, \
           dhcp-client-identifier \"text-id\", host-name \"{hostname}\", option-200 {mac_addr_asciiU:}</adv_dhcp_send_options>\
         <adv_dhcp_request_options>routers, domain-search, bogus-name</adv_dhcp_request_options>\
         <adv_dhcp_required_options>subnet-mask</adv_dhcp_required_options>\
         <adv_dhcp_option_modifiers>supersede domain-name \"x\"</adv_dhcp_option_modifiers>",
        "",
    ));
    let Ipv4Config::Dhcp {
        hostname,
        vendor_class,
        user_class,
        send_options,
        request_options,
        use_mtu,
        ..
    } = &wan(&i).ipv4
    else {
        panic!("dhcp")
    };
    assert_eq!(hostname.as_ref().unwrap().to_string(), "gw");
    assert_eq!(vendor_class.as_deref(), Some("acme"));
    assert_eq!(user_class, &["tv"]);
    assert_eq!(send_options.len(), 1);
    assert_eq!(send_options[0].code, 125);
    assert!(matches!(send_options[0].value, DhcpOptionValue::Hex(_)));
    assert_eq!(request_options, &[3, 119]);
    assert!(*use_mtu);
    for needle in [
        "protocol timing timeout 30",
        "client identifier",
        "{mac_addr_asciiU:}",
        "bogus-name",
        "required options",
        "option modifiers",
    ] {
        assert!(degraded(&i, needle), "{needle}: {}", i.report);
    }
    assert!(i.report.unmapped_unexpected.is_empty(), "{}", i.report);
    // advanced mode does not send the host name as client identifier
    assert!(!degraded(&i, "also sends it as the client identifier"));
    let again = import_str(&export_config(&i.document));
    assert_eq!(wan(&again).ipv4, wan(&i).ipv4);
}

#[test]
fn dhcp4_basic_mode_ignores_advanced_fields_and_notes_the_hostname_identifier() {
    let i = import_str(&wan_xml(
        "<ipaddr>dhcp</ipaddr><dhcphostname>gw</dhcphostname>\
         <adv_dhcp_pt_timeout>30</adv_dhcp_pt_timeout><adv_dhcp_send_options>user-class \"tv\"</adv_dhcp_send_options>",
        "",
    ));
    assert!(degraded(&i, "also sends it as the client identifier"));
    assert!(!degraded(&i, "protocol timing"));
    assert!(i.report.unmapped_unexpected.is_empty(), "{}", i.report);
}

#[test]
fn dhcp_vlan_priority_needs_a_vlan() {
    use sensr_schema::models::interfaces::Ipv4Config;
    let plain = import_str(&wan_xml(
        "<ipaddr>dhcp</ipaddr><dhcpvlanprio>3</dhcpvlanprio>",
        "",
    ));
    assert!(matches!(
        &wan(&plain).ipv4,
        Ipv4Config::Dhcp {
            vlan_priority: None,
            ..
        }
    ));
    assert!(degraded(&plain, "not a VLAN"));
    let xml = "<opnsense><vlans><vlan uuid=\"00000000-0000-4000-8000-0000000000aa\"><if>em0</if><tag>201</tag><vlanif>vlan0.201</vlanif></vlan></vlans>\
        <interfaces><wan><if>vlan0.201</if><enable>1</enable><ipaddr>dhcp</ipaddr><dhcpvlanprio>3</dhcpvlanprio></wan></interfaces></opnsense>";
    let tagged = import_str(xml);
    assert!(matches!(
        &wan(&tagged).ipv4,
        Ipv4Config::Dhcp {
            vlan_priority: Some(3),
            ..
        }
    ));
}

#[test]
fn dhcp6_delegation_sizes_follow_the_form() {
    use sensr_schema::models::interfaces::Ipv6Config;
    // interfaces.php: the stored value is the bits below /64
    for (bits, len) in [
        ("0", Some(64)),
        ("4", Some(60)),
        ("8", Some(56)),
        ("16", Some(48)),
        ("none", None),
    ] {
        let i = import_str(&wan_xml(
            &format!(
                "<ipaddr>dhcp</ipaddr><ipaddrv6>dhcp6</ipaddrv6><dhcp6-ia-pd-len>{bits}</dhcp6-ia-pd-len>"
            ),
            "",
        ));
        let Ipv6Config::Dhcp6 {
            prefix_delegation_len,
            ..
        } = &wan(&i).ipv6
        else {
            panic!("dhcp6")
        };
        assert_eq!(*prefix_delegation_len, len, "{bits}");
        let again = import_str(&export_config(&i.document));
        assert_eq!(wan(&again).ipv6, wan(&i).ipv6, "{bits}");
    }
}

#[test]
fn dhcp6_globals_and_client_flags_map() {
    use sensr_schema::models::interfaces::Ipv6Config;
    let i = import_str(&wan_xml(
        "<ipaddr>dhcp</ipaddr><ipaddrv6>dhcp6</ipaddrv6><dhcp6-ia-pd-len>4</dhcp6-ia-pd-len>\
         <dhcp6-ia-pd-send-hint>1</dhcp6-ia-pd-send-hint><dhcp6prefixonly>1</dhcp6prefixonly>\
         <dhcp6_rapid_commit>1</dhcp6_rapid_commit><dhcp6-prefix-id>15</dhcp6-prefix-id><dhcp6vlanprio>2</dhcp6vlanprio>",
        "<OPNsense><Interfaces><settings><dhcp6_norelease>1</dhcp6_norelease>\
         <dhcp6_duid>0:3:0:1:02:00:5e:10:20:30</dhcp6_duid></settings></Interfaces></OPNsense>",
    ));
    let Ipv6Config::Dhcp6 {
        prefix_delegation_len,
        send_prefix_hint,
        prefix_only,
        rapid_commit,
        prefix_id,
        duid,
        send_release,
    } = &wan(&i).ipv6
    else {
        panic!("dhcp6")
    };
    assert_eq!(*prefix_delegation_len, Some(60));
    assert!(*send_prefix_hint && *prefix_only && *rapid_commit);
    assert_eq!(*prefix_id, Some(15));
    assert_eq!(
        duid.as_ref().unwrap().to_string(),
        "00:03:00:01:02:00:5e:10:20:30"
    );
    assert!(!*send_release);
    assert!(degraded(&i, "DHCPv6 VLAN priority 2"));
    assert!(i.report.unmapped_unexpected.is_empty(), "{}", i.report);
    let again = import_str(&export_config(&i.document));
    assert_eq!(wan(&again).ipv6, wan(&i).ipv6);
}

#[test]
fn legacy_system_duid_is_used() {
    use sensr_schema::models::interfaces::Ipv6Config;
    let i = import_str(&wan_xml(
        "<ipaddr>dhcp</ipaddr><ipaddrv6>dhcp6</ipaddrv6><dhcp6-ia-pd-len>8</dhcp6-ia-pd-len>",
        "",
    ).replace("<opnsense>", "<opnsense><system><ipv6duid>00:01:00:01:2a:2b:2c:2d:02:00:5e:00:00:01</ipv6duid></system>"));
    let Ipv6Config::Dhcp6 { duid, .. } = &wan(&i).ipv6 else {
        panic!("dhcp6")
    };
    assert_eq!(duid.as_ref().unwrap().as_bytes().len(), 14);
}

#[test]
fn several_lans_track_one_wan_with_their_prefix_ids() {
    let i = import("corpus/fibre-passthrough.xml");
    let ids: Vec<u16> = i
        .document
        .interfaces
        .iter()
        .filter_map(|(_, x)| match &x.ipv6 {
            sensr_schema::models::interfaces::Ipv6Config::Track { prefix_id, .. } => {
                Some(*prefix_id)
            }
            _ => None,
        })
        .collect();
    assert_eq!(ids, [0, 1, 10]);
    assert!(
        i.document.validate().is_empty(),
        "{:?}",
        i.document.validate()
    );
}

#[test]
fn ipv6_allowed_follows_interfaces_settings_over_legacy() {
    let legacy_off = "<system><hostname>gw</hostname><domain>home.example</domain></system>";
    let legacy_on = "<system><hostname>gw</hostname><domain>home.example</domain><ipv6allow>1</ipv6allow></system>";
    let doc = |system: &str, extra: &str| {
        import_str(
            &wan_xml("<ipaddr>dhcp</ipaddr>", extra)
                .replace("<opnsense>", &format!("<opnsense>{system}")),
        )
    };
    // no settings section: the legacy flag decides
    assert!(!doc(legacy_off, "").document.system.ipv6_allow);
    assert!(doc(legacy_on, "").document.system.ipv6_allow);
    // the section decides when present, whatever the legacy flag says
    for (settings, allowed) in [
        ("<disableipv6>0</disableipv6>", true),
        ("<disableipv6/>", true),
        ("", true),
        ("<disableipv6>1</disableipv6>", false),
    ] {
        let extra = format!(
            "<OPNsense><Interfaces><settings>{settings}</settings></Interfaces></OPNsense>"
        );
        for system in [legacy_off, legacy_on] {
            let i = doc(system, &extra);
            assert_eq!(i.document.system.ipv6_allow, allowed, "{settings} {system}");
            assert!(i.report.unmapped_unexpected.is_empty(), "{}", i.report);
            let again = import_str(&export_config(&i.document));
            assert_eq!(again.document.system.ipv6_allow, allowed);
        }
    }

#[test]
fn legacy_one_to_one_maps_like_the_mfp1_0_4_migration() {
    // Pre-MVC configs keep 1:1 rules in `nat/onetoone` with nested
    // endpoints; the MVC rules come first, the legacy ones follow in file
    // order. The binat reflection switch still lives in `system`.
    let xml = format!(
        "<opnsense><system><enablebinatreflection>yes</enablebinatreflection></system>{IFACES}\
         <nat>\
           <onetoone><external>203.0.113.40</external><interface>wan</interface><type>binat</type>\
             <source><address>192.168.1.40</address></source><destination><any>1</any></destination>\
             <descr>legacy host</descr><natreflection>disable</natreflection></onetoone>\
           <onetoone><external>203.0.113.48</external><interface>wan</interface>\
             <source><address>192.168.1.48/29</address></source><destination><address>198.51.100.0/24</address><not>1</not></destination>\
             <disabled>1</disabled><log>1</log></onetoone>\
         </nat>\
         <OPNsense><Firewall><Filter><onetoone>\
           <rule uuid=\"00000000-0000-4000-8000-0000000011a1\"><enabled>1</enabled><log>0</log><sequence>5</sequence>\
             <interface>wan</interface><type>nat</type><source_net>lan</source_net><source_not>0</source_not>\
             <destination_net>any</destination_net><destination_not>0</destination_not><external>203.0.113.9</external>\
             <natreflection/><categories/><description>mvc</description></rule>\
         </onetoone></Filter></Firewall></OPNsense></opnsense>"
    );
    let i = import_str(&xml);
    assert!(i.report.unmapped_unexpected.is_empty(), "{}", i.report);
    let doc = &i.document;
    assert!(doc.nat.reflection.one_to_one);
    let rules: Vec<_> = doc.nat.one_to_one.values().collect();
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[0].description.as_ref().unwrap().as_str(), "mvc");
    assert_eq!(rules[0].kind, sensr_schema::models::nat::OneToOneKind::Nat);
    assert_eq!(rules[0].source.net, "net:lan".parse().unwrap());
    assert_eq!(rules[1].external, "203.0.113.40/32".parse().unwrap());
    assert_eq!(rules[1].source.net, "192.168.1.40".parse().unwrap());
    assert_eq!(
        rules[1].reflection,
        Some(sensr_schema::models::nat::OneToOneReflection::Disable)
    );
    assert!(!rules[2].enabled && rules[2].log);
    assert!(rules[2].destination.not);
    assert_eq!(
        rules.iter().map(|r| r.sequence).collect::<Vec<_>>(),
        [10, 20, 30]
    );
    // a host external with a /29 source is fine (it takes the prefix)
    assert!(doc.validate().is_empty(), "{}", doc.validate());
}

#[test]
fn webgui_listener_settings_are_imported() {
    use sensr_schema::models::system::WebProtocol;
    let doc = import("corpus/multiwan.xml").document;
    let w = &doc.system.webgui;
    assert_eq!((w.protocol, w.listen_port()), (WebProtocol::Https, 8443));
    let cert = w.certificate.expect("ssl-certref resolved");
    assert_eq!(
        doc.trust.certificates.get(&cert.id()).unwrap().refid,
        "6723f0a91b2c4"
    );

    let i = import_str(
        "<opnsense><interfaces><lan><if>igc1</if><enable>1</enable></lan></interfaces>\
         <system><webgui><protocol>http</protocol><port>8080</port>\
         <interfaces>lan</interfaces><disablehttpredirect>1</disablehttpredirect>\
         <ssl-certref>missing</ssl-certref></webgui></system></opnsense>",
    );
    let w = &i.document.system.webgui;
    assert_eq!((w.protocol, w.listen_port()), (WebProtocol::Http, 8080));
    assert_eq!(
        w.interfaces.iter().map(|i| i.as_str()).collect::<Vec<_>>(),
        ["lan"]
    );
    assert!(!w.http_redirect);
    assert!(w.certificate.is_none());
    assert!(
        i.report.to_string().contains("not in the trust store"),
        "{}",
        i.report
    );
}
