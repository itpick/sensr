//! Rule-based labelling: MAC maker plus passive DHCP/mDNS evidence in,
//! maker, kind, confidence and human-readable reasons out.

use std::sync::OnceLock;

use regex::{Regex, RegexBuilder};
use sensr_schema::models::hosts::HostKind;

use crate::oui;
use Confidence::{High, Low, Medium};
use HostKind::{
    Camera, Computer, Console, Network, Phone, Printer, Server, SmartHome, Speaker, Tablet, Tv,
    Wearable,
};

/// Everything we know about one host.
#[derive(Debug, Clone, Copy, Default)]
pub struct Evidence<'a> {
    /// `aa:bb:cc:dd:ee:ff`.
    pub mac: &'a str,
    pub hostname: Option<&'a str>,
    pub dhcp_vendor: Option<&'a str>,
    pub dhcp_prl: Option<&'a str>,
    pub mdns_services: &'a [String],
    pub mdns_model: Option<&'a str>,
}

/// How sure a label is. Ordered: `Low < Medium < High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// The automatic label for a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub maker: Option<String>,
    pub kind: HostKind,
    pub confidence: Confidence,
    /// Every contributing signal, winner first.
    pub reasons: Vec<String>,
}

/// Label a host from its evidence.
pub fn classify(e: &Evidence) -> Label {
    let mac = e.mac.to_ascii_lowercase();
    if let Some((maker, kind)) = VIRTUAL_PREFIXES
        .iter()
        .find_map(|(p, m)| mac.starts_with(p).then_some((*m, HostKind::Virtual)))
    {
        return Label {
            maker: Some(maker.to_string()),
            kind,
            confidence: High,
            reasons: vec![format!("MAC maker: {maker}")],
        };
    }

    let private = oui::is_private(e.mac);
    let registered = oui::lookup(e.mac);
    let mut maker = if private {
        Some(PRIVATE_MAKER.to_string())
    } else {
        registered.map(str::to_string)
    };
    if (private || maker.is_none())
        && e.mdns_model
            .is_some_and(|m| APPLE_MODELS.iter().any(|a| starts_with_ci(m, a)))
    {
        maker = Some("Apple".to_string());
    }

    // Pushed in signal order; the stable sort below keeps that order on ties.
    let mut found: Vec<Candidate> = Vec::new();
    if let Some(model) = e.mdns_model
        && let Some(&(_, kind)) = MDNS_MODELS.iter().find(|(p, _)| starts_with_ci(model, p))
    {
        found.push((kind, High, format!("mDNS model: {model}")));
    }
    found.extend(service_candidates(e.mdns_services));
    if let Some(vendor) = e.dhcp_vendor
        && let Some(&(_, kind, conf)) = DHCP_VENDORS.iter().find(|(m, _, _)| m.matches(vendor))
    {
        found.push((kind, conf, format!("DHCP vendor class: {vendor}")));
    }
    if let Some(host) = e.hostname
        && let Some(&(_, kind, conf)) = hostname_rules().iter().find(|(re, _, _)| re.is_match(host))
    {
        found.push((kind, conf, format!("Host name: {host}")));
    }
    if let Some(prl) = e.dhcp_prl
        && let Some(&(_, os, kind, conf)) = DHCP_PRLS.iter().find(|(p, ..)| *p == prl)
    {
        found.push((kind, conf, format!("DHCP fingerprint: {os}")));
    }
    if let Some(name) = registered
        && let Some(&(_, kind, conf)) = MAKERS
            .iter()
            .find(|(names, _, _)| names.iter().any(|n| n.eq_ignore_ascii_case(name)))
    {
        found.push((kind, conf, format!("MAC maker: {name}")));
    }

    found.sort_by_key(|c| std::cmp::Reverse(c.1));
    let Some(&(kind, confidence, _)) = found.first() else {
        let (kind, reasons) = if private {
            (HostKind::Phone, vec![RANDOMISED_REASON.to_string()])
        } else {
            (HostKind::Unknown, Vec::new())
        };
        return Label {
            maker,
            kind,
            confidence: Low,
            reasons,
        };
    };
    let mut reasons: Vec<String> = Vec::with_capacity(found.len());
    for (_, _, reason) in found {
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }
    Label {
        maker,
        kind,
        confidence,
        reasons,
    }
}

type Candidate = (HostKind, Confidence, String);

const PRIVATE_MAKER: &str = "Private MAC";
const RANDOMISED_REASON: &str = "Randomised address (phones, tablets and laptops do this)";

/// Locally administered prefixes that mean a VM or container, checked first.
const VIRTUAL_PREFIXES: &[(&str, &str)] = &[("02:42:", "Docker"), ("52:54:00:", "QEMU/KVM")];

/// Apple model families; one on a private or unknown MAC makes the maker Apple.
const APPLE_MODELS: &[&str] = &[
    "iPhone",
    "iPad",
    "Mac",
    "MacBook",
    "iMac",
    "AppleTV",
    "AudioAccessory",
    "Watch",
];

/// mDNS TXT model prefixes (case-insensitive), all High.
const MDNS_MODELS: &[(&str, HostKind)] = &[
    ("iPhone", Phone),
    ("iPad", Tablet),
    ("MacBook", Computer),
    ("Mac", Computer),
    ("iMac", Computer),
    ("AppleTV", Tv),
    ("AudioAccessory", Speaker), // HomePod
    ("Watch", Wearable),
    ("Chromecast", Tv),
    ("Google TV", Tv),
    ("Google Home", Speaker),
    ("Google Nest", Speaker),
    ("Nest", Speaker),
];

/// Single mDNS service types that settle the kind on their own, all High.
const MDNS_SERVICES: &[(&str, HostKind)] = &[
    ("_ipp._tcp", Printer),
    ("_ipps._tcp", Printer),
    ("_printer._tcp", Printer),
    ("_pdl-datastream._tcp", Printer),
    ("_googlecast._tcp", Tv),
    ("_androidtvremote2._tcp", Tv),
    ("_sonos._tcp", Speaker),
    ("_spotify-connect._tcp", Speaker),
    ("_hap._tcp", SmartHome),
];

const COMPANION: &str = "_companion-link._tcp";

fn service_candidates(services: &[String]) -> Vec<Candidate> {
    let has = |want: &str| services.iter().any(|s| s.eq_ignore_ascii_case(want));
    let mut out = Vec::new();
    for svc in services {
        if let Some(&(_, kind)) = MDNS_SERVICES
            .iter()
            .find(|(n, _)| svc.eq_ignore_ascii_case(n))
        {
            out.push((kind, High, format!("mDNS service: {svc}")));
        }
    }
    // AirPlay audio alone is a speaker; iPhones, iPads and Macs also
    // advertise _raop but always with _companion-link.
    if has("_raop._tcp") && !has(COMPANION) {
        out.push((Speaker, High, "mDNS service: _raop._tcp".to_string()));
    }
    // Time Machine share on SMB: a NAS.
    if has("_smb._tcp") && has("_adisk._tcp") {
        out.push((
            Server,
            High,
            "mDNS service: _smb._tcp + _adisk._tcp".to_string(),
        ));
    }
    if has(COMPANION) {
        out.push((Phone, Medium, format!("mDNS service: {COMPANION}")));
    }
    out
}

/// How a DHCP vendor class (option 60) is matched.
enum VendorMatch {
    Exact(&'static str),
    Prefix(&'static str),
}

impl VendorMatch {
    fn matches(&self, vendor: &str) -> bool {
        match self {
            Self::Exact(s) => vendor.eq_ignore_ascii_case(s),
            Self::Prefix(p) => starts_with_ci(vendor, p),
        }
    }
}

const DHCP_VENDORS: &[(VendorMatch, HostKind, Confidence)] = &[
    (VendorMatch::Prefix("android-dhcp-"), Phone, High),
    (VendorMatch::Exact("MSFT 5.0"), Computer, High),
    (VendorMatch::Prefix("HUAWEI:"), Network, Medium),
    (VendorMatch::Exact("ubnt"), Network, Medium),
    (VendorMatch::Prefix("dhcpcd-"), Computer, Low),
    (VendorMatch::Prefix("udhcp"), Network, Low), // embedded Linux (BusyBox)
];

/// Host-name rules: case-insensitive regexes, first match wins.
const HOSTNAMES: &[(&str, HostKind, Confidence)] = &[
    // Unanchored: Apple defaults look like "Lucass-iPhone" / "Johns-iPad".
    ("iphone", Phone, Medium),
    ("ipad", Tablet, Medium),
    ("^(galaxy|sm-[a-z0-9]+|pixel|oneplus)", Phone, Medium),
    ("^(desktop|laptop)-[a-z0-9]{7}$", Computer, Medium), // Windows defaults
    ("macbook|imac|mac-?mini", Computer, Medium),
    ("^hp[0-9a-f]{6}$", Printer, Medium),
    ("^(brw|epson|canon)", Printer, Medium),
    ("^(chromecast|roku|appletv|fire-?tv)", Tv, Medium),
    (
        "^(xbox|playstation|ps[45]|nintendo|switch)",
        Console,
        Medium,
    ),
    ("^(ring|wyze|reolink|camera|cam-)", Camera, Medium),
    ("^(sonos|homepod|echo)", Speaker, Medium),
    ("^(esp|tasmota|shelly|tuya)", SmartHome, Medium),
    // Short prefixes need a separator so "apollo" / "swift-laptop" stay out.
    (
        "^((sw|ap)[-_]|(switch|unifi|usw|uap|ism-sw)([-_]|$))",
        Network,
        Medium,
    ),
    // Word boundary after the prefix so "piano" stays out.
    (
        "^(pi|rpi|raspberrypi|nas|server|node|picknode)([-_0-9]|$)",
        Server,
        Low,
    ),
];

fn hostname_rules() -> &'static [(Regex, HostKind, Confidence)] {
    static RULES: OnceLock<Vec<(Regex, HostKind, Confidence)>> = OnceLock::new();
    RULES.get_or_init(|| {
        HOSTNAMES
            .iter()
            .map(|&(pat, kind, conf)| {
                let re = RegexBuilder::new(pat)
                    .case_insensitive(true)
                    .build()
                    .expect("HOSTNAMES patterns are valid (pinned by hostname_rows)");
                (re, kind, conf)
            })
            .collect()
    })
}

/// DHCP parameter request lists (option 55) of well-known client stacks,
/// exact match. Our own data, written from the clients' documented default
/// request sets and public packet captures; not taken from any database.
const DHCP_PRLS: &[(&str, &str, HostKind, Confidence)] = &[
    // iOS and macOS send the same list, so this cannot tell phone from laptop.
    (
        "1,121,3,6,15,108,114,119,252,95,44,46",
        "Apple",
        Computer,
        Low,
    ),
    // Windows 10/11.
    (
        "1,3,6,15,31,33,43,44,46,47,119,121,249,252",
        "Windows",
        Computer,
        Medium,
    ),
    // Android 11+ (adds option 114 captive portal and 108 IPv6-only).
    (
        "1,3,6,15,26,28,51,58,59,43,114,108",
        "Android",
        Phone,
        Medium,
    ),
    // Android 10 and earlier on the framework DHCP client.
    ("1,3,6,15,26,28,51,58,59,43", "Android", Phone, Medium),
    // Older Android on dhcpcd.
    ("1,33,3,6,15,28,51,58,59", "Android", Phone, Medium),
    // ISC dhclient default request set (many Linux desktops and servers).
    (
        "1,28,2,3,15,6,119,12,44,47,26,121,42",
        "Linux",
        Computer,
        Low,
    ),
];

/// MAC makers that mostly build one kind of device. Names are the short
/// forms in `data/oui.tsv`, compared case-insensitively. Generic makers
/// (Apple, Samsung, Google, Amazon, Intel, Realtek, ...) are deliberately
/// absent: they never give a candidate.
const MAKERS: &[(&[&str], HostKind, Confidence)] = &[
    (
        &[
            "Wyze",
            "Ring",
            "Reolink",
            "Arlo",
            "Hangzhou Hikvision Digital",
            "Prama Hikvision India Private",
            "Zhejiang Dahua",
            "Zhejiang Dahua Technologyco",
            "Zhejiang Dahua Zhilian",
        ],
        Camera,
        Medium,
    ),
    (&["Sonos", "Bose"], Speaker, Medium),
    (&["Roku"], Tv, Medium),
    (&["Nintendo", "PlayStation"], Console, Medium),
    (
        &[
            "Ubiquiti",
            "TP-Link",
            "Netgear",
            "Cisco Systems",
            "Cisco Meraki",
            "Cisco-Linksys",
            "Routerboard.com",
        ],
        Network,
        Medium,
    ),
    (&["Synology", "QNAP Systems"], Server, Medium),
    (&["Brother Industries", "Seiko Epson"], Printer, Medium),
    // HP and Canon also make computers and cameras.
    (&["HP", "CANON"], Printer, Low),
    (&["Raspberry Pi"], Server, Low),
    (
        &["Espressif", "Tuya Smart", "Shelly Europe"],
        SmartHome,
        Low,
    ),
];

fn starts_with_ci(s: &str, prefix: &str) -> bool {
    s.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use HostKind::*;

    fn ev(mac: &str) -> Evidence<'_> {
        Evidence {
            mac,
            ..Evidence::default()
        }
    }

    fn short(l: &Label) -> (Option<&str>, HostKind, Confidence) {
        (l.maker.as_deref(), l.kind, l.confidence)
    }

    #[test]
    fn wyze_is_camera_medium() {
        let l = classify(&ev("7c:78:b2:14:b2:de"));
        assert_eq!(short(&l), (Some("Wyze"), Camera, Confidence::Medium));
        assert_eq!(l.reasons, vec!["MAC maker: Wyze".to_string()]);
    }

    #[test]
    fn pi_is_server_low() {
        let l = classify(&ev("b8:27:eb:7d:4e:25"));
        assert_eq!(short(&l), (Some("Raspberry Pi"), Server, Confidence::Low));
    }

    #[test]
    fn owner_network_pis_are_servers() {
        for (mac, host) in [
            ("dc:a6:32:02:8e:35", "rpi4-8GB"),
            ("2c:cf:67:11:22:33", "pi5-1"),
        ] {
            let l = classify(&Evidence {
                hostname: Some(host),
                ..ev(mac)
            });
            assert_eq!(short(&l), (Some("Raspberry Pi"), Server, Confidence::Low));
            assert_eq!(
                l.reasons,
                vec![
                    format!("Host name: {host}"),
                    "MAC maker: Raspberry Pi".into()
                ],
            );
        }
    }

    #[test]
    fn owner_network_hostnames() {
        // Unregistered (but not private) prefix so only the name counts.
        let mac = "00:00:5e:00:53:01";
        for (host, kind, conf) in [
            ("ism-sw-1-f89e280774b1", Network, Confidence::Medium),
            ("picknode-01", Server, Confidence::Low),
        ] {
            let l = classify(&Evidence {
                hostname: Some(host),
                ..ev(mac)
            });
            assert_eq!((l.kind, l.confidence), (kind, conf), "{host}");
        }
    }

    #[test]
    fn private_mac_defaults_to_phone_low() {
        let l = classify(&ev("02:cf:67:c6:7b:71"));
        assert_eq!(short(&l), (Some("Private MAC"), Phone, Confidence::Low));
        assert_eq!(
            l.reasons,
            vec!["Randomised address (phones, tablets and laptops do this)".to_string()]
        );
    }

    #[test]
    fn docker_prefix_is_virtual() {
        let l = classify(&ev("02:42:ac:11:00:02"));
        assert_eq!(short(&l), (Some("Docker"), Virtual, Confidence::High));
        let l = classify(&ev("52:54:00:12:34:56"));
        assert_eq!(short(&l), (Some("QEMU/KVM"), Virtual, Confidence::High));
    }

    #[test]
    fn chromecast_model_is_tv_high() {
        let services = vec!["_googlecast._tcp".to_string()];
        let l = classify(&Evidence {
            mdns_model: Some("Chromecast"),
            mdns_services: &services,
            ..ev("02:11:22:33:44:55")
        });
        assert_eq!((l.kind, l.confidence), (Tv, Confidence::High));
        assert_eq!(
            l.reasons,
            vec![
                "mDNS model: Chromecast".to_string(),
                "mDNS service: _googlecast._tcp".into()
            ]
        );
    }

    #[test]
    fn android_vendor_class_is_phone_high() {
        let l = classify(&Evidence {
            dhcp_vendor: Some("android-dhcp-14"),
            ..ev("02:11:22:33:44:55")
        });
        assert_eq!(short(&l), (Some("Private MAC"), Phone, Confidence::High));
        assert_eq!(
            l.reasons,
            vec!["DHCP vendor class: android-dhcp-14".to_string()]
        );
    }

    #[test]
    fn hp_printer_hostname() {
        let l = classify(&Evidence {
            hostname: Some("HPC2E1D9"),
            ..ev("00:00:5e:00:53:01")
        });
        assert_eq!((l.kind, l.confidence), (Printer, Confidence::Medium));
        assert_eq!(l.reasons, vec!["Host name: HPC2E1D9".to_string()]);
        // With an HP OUI the maker rule (low) agrees and is listed second.
        let l = classify(&Evidence {
            hostname: Some("HPC2E1D9"),
            ..ev("00:01:e6:00:00:01")
        });
        assert_eq!(short(&l), (Some("HP"), Printer, Confidence::Medium));
        assert_eq!(l.reasons.get(1).map(String::as_str), Some("MAC maker: HP"));
    }

    #[test]
    fn generic_makers_are_low_confidence() {
        let esp = classify(&ev(&mac_for("Espressif")));
        assert_eq!(esp.maker.as_deref(), Some("Espressif"));
        assert!(esp.confidence <= Confidence::Low);
        for generic in ["Samsung", "Apple", "Intel", "Realtek", "Amazon", "Google"] {
            let mac = mac_for(generic);
            let l = classify(&ev(&mac));
            assert_eq!(l.maker.as_deref(), Some(generic));
            assert_eq!(
                (l.kind, l.confidence),
                (Unknown, Confidence::Low),
                "{generic}"
            );
            assert!(l.reasons.is_empty(), "{generic}");
        }
    }

    #[test]
    fn higher_confidence_signal_wins() {
        let services = vec!["_ipp._tcp".to_string()];
        let l = classify(&Evidence {
            hostname: Some("iPhone"),
            mdns_services: &services,
            ..ev("02:11:22:33:44:55")
        });
        assert_eq!((l.kind, l.confidence), (Printer, Confidence::High));
        assert_eq!(
            l.reasons,
            vec![
                "mDNS service: _ipp._tcp".to_string(),
                "Host name: iPhone".into()
            ]
        );
    }

    #[test]
    fn ties_go_by_signal_order() {
        // DHCP vendor (network, medium) vs host name (phone, medium): vendor first.
        let l = classify(&Evidence {
            dhcp_vendor: Some("ubnt"),
            hostname: Some("pixel-7"),
            ..ev("00:00:5e:00:53:01")
        });
        assert_eq!((l.kind, l.confidence), (Network, Confidence::Medium));
        // Host name (camera, medium) vs maker (Sonos speaker, medium): name first.
        let l = classify(&Evidence {
            hostname: Some("cam-porch"),
            ..ev(&mac_for("Sonos"))
        });
        assert_eq!(l.kind, Camera);
        assert_eq!(l.reasons.len(), 2);
    }

    #[test]
    fn apple_model_sets_maker_on_private_mac() {
        let l = classify(&Evidence {
            mdns_model: Some("iPhone15,2"),
            ..ev("02:cf:67:c6:7b:71")
        });
        assert_eq!(short(&l), (Some("Apple"), Phone, Confidence::High));
        // A registered non-Apple maker is kept.
        let l = classify(&Evidence {
            mdns_model: Some("MacBookPro18,1"),
            ..ev("7c:78:b2:14:b2:de")
        });
        assert_eq!(l.maker.as_deref(), Some("Wyze"));
        assert_eq!(l.kind, Computer);
    }

    #[test]
    fn mdns_model_rows() {
        for (model, kind) in [
            ("iPhone15,2", Phone),
            ("iPad13,4", Tablet),
            ("MacBookPro18,1", Computer),
            ("Mac14,3", Computer),
            ("iMac21,1", Computer),
            ("AppleTV14,1", Tv),
            ("AudioAccessory5,1", Speaker),
            ("Watch6,1", Wearable),
            ("Chromecast", Tv),
            ("Google TV Streamer", Tv),
            ("Google Home Mini", Speaker),
            ("Google Nest Mini", Speaker),
            ("Nest Audio", Speaker),
        ] {
            let l = classify(&Evidence {
                mdns_model: Some(model),
                ..ev("00:00:5e:00:53:01")
            });
            assert_eq!((l.kind, l.confidence), (kind, Confidence::High), "{model}");
            assert_eq!(l.reasons, vec![format!("mDNS model: {model}")]);
        }
    }

    #[test]
    fn mdns_service_rows() {
        let cases: &[(&[&str], HostKind, Confidence)] = &[
            (&["_ipp._tcp"], Printer, Confidence::High),
            (&["_ipps._tcp"], Printer, Confidence::High),
            (&["_printer._tcp"], Printer, Confidence::High),
            (&["_pdl-datastream._tcp"], Printer, Confidence::High),
            (&["_googlecast._tcp"], Tv, Confidence::High),
            (&["_androidtvremote2._tcp"], Tv, Confidence::High),
            (&["_raop._tcp"], Speaker, Confidence::High),
            (&["_sonos._tcp"], Speaker, Confidence::High),
            (&["_spotify-connect._tcp"], Speaker, Confidence::High),
            (&["_hap._tcp"], SmartHome, Confidence::High),
            (&["_smb._tcp", "_adisk._tcp"], Server, Confidence::High),
            (&["_companion-link._tcp"], Phone, Confidence::Medium),
            (
                &["_raop._tcp", "_companion-link._tcp"],
                Phone,
                Confidence::Medium,
            ),
            (&["_smb._tcp"], Unknown, Confidence::Low),
            (&["_adisk._tcp"], Unknown, Confidence::Low),
        ];
        for (svcs, kind, conf) in cases {
            let services: Vec<String> = svcs.iter().map(|s| s.to_string()).collect();
            let l = classify(&Evidence {
                mdns_services: &services,
                ..ev("00:00:5e:00:53:01")
            });
            assert_eq!((l.kind, l.confidence), (*kind, *conf), "{svcs:?}");
        }
    }

    #[test]
    fn dhcp_vendor_rows() {
        for (vendor, kind, conf) in [
            ("android-dhcp-14", Phone, Confidence::High),
            ("MSFT 5.0", Computer, Confidence::High),
            (
                "dhcpcd-9.4.1:Linux-6.1.0:aarch64:Raspberry Pi",
                Computer,
                Confidence::Low,
            ),
            ("udhcp 1.36.1", Network, Confidence::Low),
            ("HUAWEI:android:P30", Network, Confidence::Medium),
            ("ubnt", Network, Confidence::Medium),
            ("something-else", Unknown, Confidence::Low),
        ] {
            let l = classify(&Evidence {
                dhcp_vendor: Some(vendor),
                ..ev("00:00:5e:00:53:01")
            });
            assert_eq!((l.kind, l.confidence), (kind, conf), "{vendor}");
        }
    }

    #[test]
    fn hostname_rows() {
        use Confidence::*;
        for (host, kind, conf) in [
            ("iPhone", Phone, Medium),
            ("Lucass-iPhone", Phone, Medium),
            ("Johns-iPad", Tablet, Medium),
            ("iPad-2", Tablet, Medium),
            ("Galaxy-S23", Phone, Medium),
            ("SM-G991B", Phone, Medium),
            ("Pixel-8", Phone, Medium),
            ("OnePlus-12", Phone, Medium),
            ("DESKTOP-AB12CD3", Computer, Medium),
            ("LAPTOP-9XYZ123", Computer, Medium),
            ("DESKTOP-AB12CD34", Unknown, Low),
            ("Lucass-MacBook-Pro", Computer, Medium),
            ("office-imac", Computer, Medium),
            ("mac-mini", Computer, Medium),
            ("macmini", Computer, Medium),
            ("HPC2E1D9", Printer, Medium),
            ("BRW0080927AFBEA", Printer, Medium),
            ("EPSON123456", Printer, Medium),
            ("Canon-MF", Printer, Medium),
            ("Chromecast-Ultra", Tv, Medium),
            ("Roku-Ultra", Tv, Medium),
            ("AppleTV", Tv, Medium),
            ("fire-tv-stick", Tv, Medium),
            ("firetv", Tv, Medium),
            ("XboxOne", Console, Medium),
            ("PlayStation5", Console, Medium),
            ("PS5-123", Console, Medium),
            ("Nintendo-Switch", Console, Medium),
            ("Ring-Doorbell", Camera, Medium),
            ("wyze-cam", Camera, Medium),
            ("Reolink-E1", Camera, Medium),
            ("camera-garage", Camera, Medium),
            ("cam-porch", Camera, Medium),
            ("Sonos-Kitchen", Speaker, Medium),
            ("HomePod", Speaker, Medium),
            ("echo-dot", Speaker, Medium),
            ("ESP_12AB34", SmartHome, Medium),
            ("tasmota-plug", SmartHome, Medium),
            ("shelly1-ABC", SmartHome, Medium),
            ("tuya-bulb", SmartHome, Medium),
            ("sw-core", Network, Medium),
            ("unifi-ap", Network, Medium),
            ("USW-24", Network, Medium),
            ("UAP-AC-Lite", Network, Medium),
            ("ap-upstairs", Network, Medium),
            ("ap_garage", Network, Medium),
            ("apollo", Unknown, Low),
            ("swift-laptop", Unknown, Low),
            ("piano", Unknown, Low),
            ("ism-sw-1-f89e280774b1", Network, Medium),
            ("pi5-1", Server, Low),
            ("rpi4-8GB", Server, Low),
            ("raspberrypi", Server, Low),
            ("nas", Server, Low),
            ("server-01", Server, Low),
            ("node3", Server, Low),
            ("picknode-01", Server, Low),
            ("lucas-thinkpad", Unknown, Low),
        ] {
            let l = classify(&Evidence {
                hostname: Some(host),
                ..ev("00:00:5e:00:53:01")
            });
            assert_eq!((l.kind, l.confidence), (kind, conf), "{host}");
        }
    }

    #[test]
    fn dhcp_prl_rows() {
        use Confidence::*;
        for (prl, kind, conf, reason) in [
            (
                "1,121,3,6,15,108,114,119,252,95,44,46",
                Computer,
                Low,
                "Apple",
            ),
            (
                "1,3,6,15,31,33,43,44,46,47,119,121,249,252",
                Computer,
                Medium,
                "Windows",
            ),
            (
                "1,3,6,15,26,28,51,58,59,43,114,108",
                Phone,
                Medium,
                "Android",
            ),
            ("1,3,6,15,26,28,51,58,59,43", Phone, Medium, "Android"),
            ("1,33,3,6,15,28,51,58,59", Phone, Medium, "Android"),
            (
                "1,28,2,3,15,6,119,12,44,47,26,121,42",
                Computer,
                Low,
                "Linux",
            ),
        ] {
            let l = classify(&Evidence {
                dhcp_prl: Some(prl),
                ..ev("00:00:5e:00:53:01")
            });
            assert_eq!((l.kind, l.confidence), (kind, conf), "{prl}");
            assert_eq!(l.reasons, vec![format!("DHCP fingerprint: {reason}")]);
        }
        let l = classify(&Evidence {
            dhcp_prl: Some("1,3,6"),
            ..ev("00:00:5e:00:53:01")
        });
        assert_eq!(l.kind, Unknown);
    }

    /// Every maker named in a rule exists in the embedded table, so a rule
    /// keyed to a name the table does not use cannot sneak back in.
    #[test]
    fn maker_rule_names_exist_in_oui_table() {
        let names: std::collections::HashSet<String> = include_str!("../data/oui.tsv")
            .lines()
            .filter_map(|l| l.split_once('\t'))
            .map(|(_, n)| n.to_ascii_lowercase())
            .collect();
        for (makers, _, _) in MAKERS {
            for m in *makers {
                assert!(
                    names.contains(&m.to_ascii_lowercase()),
                    "{m} not in oui.tsv"
                );
            }
        }
    }

    /// A MAC whose OUI resolves to `maker` in the embedded table.
    fn mac_for(maker: &str) -> String {
        let prefix = include_str!("../data/oui.tsv")
            .lines()
            .filter_map(|l| l.split_once('\t'))
            .find(|(p, n)| p.len() == 6 && *n == maker)
            .map(|(p, _)| p.to_string())
            .unwrap_or_else(|| panic!("no OUI for {maker}"));
        let mac = format!(
            "{}:{}:{}:00:00:01",
            &prefix[0..2],
            &prefix[2..4],
            &prefix[4..6]
        );
        assert_eq!(crate::oui::lookup(&mac), Some(maker), "{mac}");
        mac
    }

    #[test]
    fn maker_rows() {
        use Confidence::*;
        for (maker, kind, conf) in [
            ("Wyze", Camera, Medium),
            ("Ring", Camera, Medium),
            ("Reolink", Camera, Medium),
            ("Arlo", Camera, Medium),
            ("Hangzhou Hikvision Digital", Camera, Medium),
            ("Zhejiang Dahua", Camera, Medium),
            ("Sonos", Speaker, Medium),
            ("Bose", Speaker, Medium),
            ("Roku", Tv, Medium),
            ("Nintendo", Console, Medium),
            ("PlayStation", Console, Medium),
            ("Ubiquiti", Network, Medium),
            ("TP-Link", Network, Medium),
            ("Netgear", Network, Medium),
            ("Cisco Systems", Network, Medium),
            ("Cisco Meraki", Network, Medium),
            ("Routerboard.com", Network, Medium),
            ("Synology", Server, Medium),
            ("QNAP Systems", Server, Medium),
            ("Brother Industries", Printer, Medium),
            ("Seiko Epson", Printer, Medium),
            ("CANON", Printer, Low),
            ("HP", Printer, Low),
            ("Raspberry Pi", Server, Low),
            ("Espressif", SmartHome, Low),
            ("Tuya Smart", SmartHome, Low),
            ("Shelly Europe", SmartHome, Low),
        ] {
            let mac = mac_for(maker);
            let l = classify(&ev(&mac));
            assert_eq!(short(&l), (Some(maker), kind, conf), "{maker}");
            assert_eq!(l.reasons, vec![format!("MAC maker: {maker}")]);
        }
    }
}
