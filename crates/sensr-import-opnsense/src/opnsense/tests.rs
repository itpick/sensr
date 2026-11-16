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
