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
