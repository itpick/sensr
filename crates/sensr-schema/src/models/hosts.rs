//! Host labels: what the router shows next to a device on the hosts page.
//! The agent guesses a maker and kind from passive evidence; entries here
//! override the guess for the one host with a given MAC address.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::array::ArrayField;
use crate::fields::{Description, MacAddr};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldPath, Validations, ValidatorKind};

/// What kind of device a host is.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum HostKind {
    /// A phone.
    Phone,
    /// A tablet.
    Tablet,
    /// A laptop or desktop computer.
    Computer,
    /// A television or streaming box.
    Tv,
    /// A smart speaker.
    Speaker,
    /// A camera.
    Camera,
    /// A printer.
    Printer,
    /// A game console.
    Console,
    /// Switches, access points and other network gear.
    Network,
    /// Smart-home devices (plugs, bulbs, sensors, hubs).
    SmartHome,
    /// A server or NAS.
    Server,
    /// A watch or other wearable.
    Wearable,
    /// A virtual machine or container.
    Virtual,
    /// Not known.
    Unknown,
}

impl HostKind {
    /// Every kind, in display order.
    pub const ALL: [HostKind; 14] = [
        Self::Phone,
        Self::Tablet,
        Self::Computer,
        Self::Tv,
        Self::Speaker,
        Self::Camera,
        Self::Printer,
        Self::Console,
        Self::Network,
        Self::SmartHome,
        Self::Server,
        Self::Wearable,
        Self::Virtual,
        Self::Unknown,
    ];

    /// The name shown to people.
    pub fn display(self) -> &'static str {
        match self {
            Self::Phone => "Phone",
            Self::Tablet => "Tablet",
            Self::Computer => "Computer",
            Self::Tv => "TV/streaming",
            Self::Speaker => "Speaker",
            Self::Camera => "Camera",
            Self::Printer => "Printer",
            Self::Console => "Game console",
            Self::Network => "Network gear",
            Self::SmartHome => "Smart home",
            Self::Server => "Server",
            Self::Wearable => "Wearable",
            Self::Virtual => "Virtual machine",
            Self::Unknown => "Unknown",
        }
    }
}

/// An owner-set maker and/or kind for the one host with this MAC address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostLabel {
    /// Whether the label is in force.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The host's MAC address.
    pub mac: MacAddr,
    /// Replaces the guessed kind when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<HostKind>,
    /// Replaces the guessed maker when set (1-64 characters, no control
    /// characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maker: Option<String>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

/// Whether the router may guess what hosts are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostFingerprint {
    /// Watch local traffic passively to guess each host's maker and kind.
    #[serde(default = "yes")]
    pub enabled: bool,
}

impl Default for HostFingerprint {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Most extra ports the owner may add to the scan.
pub const MAX_EXTRA_PORTS: usize = 64;

fn default_scan_time() -> String {
    "03:30".to_owned()
}

/// The daily TCP port scan of LAN hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PortScan {
    /// Scan every recently seen LAN host once a day.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// When the daily scan starts, `HH:MM` in the router's time zone.
    #[serde(default = "default_scan_time")]
    pub time: String,
    /// TCP ports scanned on top of 1-1024 and the built-in list (at most
    /// 64, each 1-65535).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_ports: Vec<u16>,
}

impl Default for PortScan {
    fn default() -> Self {
        Self {
            enabled: true,
            time: default_scan_time(),
            extra_ports: Vec::new(),
        }
    }
}

impl PortScan {
    /// True when nothing differs from the defaults.
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }

    /// The start time as `(hour, minute)`; `None` unless it is `H:MM` or
    /// `HH:MM` with hour 0-23 and minute 0-59.
    pub fn hour_minute(&self) -> Option<(u8, u8)> {
        let (h, m) = self.time.split_once(':')?;
        let digits = |s: &str, n: std::ops::RangeInclusive<usize>| {
            n.contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
        };
        if !digits(h, 1..=2) || !digits(m, 2..=2) {
            return None;
        }
        let (h, m) = (h.parse::<u8>().ok()?, m.parse::<u8>().ok()?);
        (h < 24 && m < 60).then_some((h, m))
    }

    /// The extra ports, sorted, without duplicates or 0, and at most
    /// [`MAX_EXTRA_PORTS`] of them (a document that failed validation
    /// still cannot widen the scan).
    pub fn extra(&self) -> Vec<u16> {
        let set: std::collections::BTreeSet<u16> = self
            .extra_ports
            .iter()
            .copied()
            .filter(|p| *p != 0)
            .collect();
        set.into_iter().take(MAX_EXTRA_PORTS).collect()
    }
}

/// The `hosts` section.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Hosts {
    /// Owner overrides keyed by MAC.
    #[serde(default, skip_serializing_if = "ArrayField::is_empty")]
    pub labels: ArrayField<HostLabel>,
    /// The guessing switch.
    #[serde(default, skip_serializing_if = "HostFingerprint::is_default")]
    pub fingerprint: HostFingerprint,
    /// The daily port scan.
    #[serde(default, skip_serializing_if = "PortScan::is_default")]
    pub portscan: PortScan,
}

impl HostFingerprint {
    /// True when nothing differs from the defaults.
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

impl Hosts {
    /// True when nothing differs from the defaults (the section is then
    /// omitted).
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

impl Validate for Hosts {
    fn validate(&self, _ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        let labels = at.join("labels");
        check::unique(
            self.labels
                .iter()
                .map(|(id, l)| (labels.join(id), Some(l.mac.to_string()))),
            "mac",
            "A host label for this MAC already exists.",
            out,
        );
        let scan = at.join("portscan");
        if self.portscan.hour_minute().is_none() {
            out.add(
                &scan.join("time"),
                ValidatorKind::Callback,
                "The scan time must be HH:MM (00:00 to 23:59).",
            );
        }
        if self.portscan.extra_ports.len() > MAX_EXTRA_PORTS {
            out.add(
                &scan.join("extra_ports"),
                ValidatorKind::Callback,
                format!("At most {MAX_EXTRA_PORTS} extra ports."),
            );
        }
        if self.portscan.extra_ports.contains(&0) {
            out.add(
                &scan.join("extra_ports"),
                ValidatorKind::Callback,
                "Each port must be 1 to 65535.",
            );
        }
        for (id, l) in &self.labels {
            if let Some(m) = &l.maker {
                let n = m.trim().chars().count();
                if !(1..=64).contains(&n) {
                    out.add(
                        &labels.join(id).join("maker"),
                        ValidatorKind::Callback,
                        "The maker must be 1 to 64 characters.",
                    );
                }
                if m.chars().any(char::is_control) {
                    out.add(
                        &labels.join(id).join("maker"),
                        ValidatorKind::Callback,
                        "The maker must not contain control characters (tabs, line breaks).",
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Document;
    use serde_json::json;

    #[test]
    fn hosts_default_is_omitted() {
        let v = serde_json::to_value(Document::default()).unwrap();
        assert!(v.get("hosts").is_none(), "{v}");
        assert!(Hosts::default().fingerprint.enabled);
        let mut d = Document::default();
        d.hosts.fingerprint.enabled = false;
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["hosts"], json!({"fingerprint": {"enabled": false}}));
    }

    const U1: &str = "6d0de000-0000-4000-8000-000000000001";
    const U2: &str = "6d0de000-0000-4000-8000-000000000002";

    #[test]
    fn host_label_round_trips() {
        let src = json!({"labels":{U1:{"mac":"aa:bb:cc:dd:ee:ff","kind":"camera","maker":"Wyze"}}});
        let h: Hosts = serde_json::from_value(src.clone()).unwrap();
        assert!(h.labels.iter().next().unwrap().1.enabled);
        let out = serde_json::to_value(&h).unwrap();
        assert_eq!(out["labels"][U1]["enabled"], true);
        assert_eq!(out["labels"][U1]["maker"], "Wyze");
        assert_eq!(serde_json::from_value::<Hosts>(out).unwrap(), h);
    }

    fn doc_with(labels: serde_json::Value) -> Document {
        let mut d = Document::factory();
        d.hosts = serde_json::from_value(json!({ "labels": labels })).unwrap();
        d
    }

    #[test]
    fn host_label_duplicate_mac_rejected() {
        let d = doc_with(json!({
            U1: {"mac":"aa:bb:cc:dd:ee:01","kind":"tv"},
            U2: {"mac":"AA:BB:CC:DD:EE:01","maker":"X"}
        }));
        let v = format!("{}", d.validate());
        assert!(
            v.contains("A host label for this MAC already exists."),
            "{v}"
        );
        let ok = doc_with(json!({U1:{"mac":"aa:bb:cc:dd:ee:01"},U2:{"mac":"aa:bb:cc:dd:ee:02"}}));
        assert!(ok.validate().is_empty());
    }

    #[test]
    fn host_label_maker_too_long_rejected() {
        let long = "a".repeat(65);
        let d = doc_with(json!({U1:{"mac":"aa:bb:cc:dd:ee:01","maker":long}}));
        assert!(format!("{}", d.validate()).contains("1 to 64"));
        let blank = doc_with(json!({U1:{"mac":"aa:bb:cc:dd:ee:01","maker":"   "}}));
        assert!(format!("{}", blank.validate()).contains("1 to 64"));
        let ok = doc_with(json!({U1:{"mac":"aa:bb:cc:dd:ee:01","maker":"a".repeat(64)}}));
        assert!(ok.validate().is_empty());
    }

    #[test]
    fn host_label_maker_control_characters_rejected() {
        for bad in ["Wy\nze", "Wy\tze", "Wyze\u{7}", "\u{1b}[31mWyze"] {
            let d = doc_with(json!({U1:{"mac":"aa:bb:cc:dd:ee:01","maker":bad}}));
            assert!(
                format!("{}", d.validate()).contains("control characters"),
                "{bad:?}"
            );
        }
        let ok = doc_with(json!({U1:{"mac":"aa:bb:cc:dd:ee:01","maker":"Pi Foundation & Co"}}));
        assert!(ok.validate().is_empty());
    }

    #[test]
    fn portscan_defaults_and_omission() {
        let h = Hosts::default();
        assert!(h.portscan.enabled);
        assert_eq!(h.portscan.time, "03:30");
        assert!(h.portscan.extra_ports.is_empty());
        assert_eq!(h.portscan.hour_minute(), Some((3, 30)));
        let mut d = Document::default();
        d.hosts.portscan.enabled = false;
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(
            v["hosts"],
            json!({"portscan": {"enabled": false, "time": "03:30"}})
        );
        let back: Hosts =
            serde_json::from_value(json!({"portscan": {"extra_ports": [8081]}})).unwrap();
        assert!(back.portscan.enabled);
        assert_eq!(back.portscan.time, "03:30");
        assert_eq!(back.portscan.extra_ports, vec![8081]);
    }

    fn doc_portscan(p: serde_json::Value) -> Document {
        let mut d = Document::factory();
        d.hosts = serde_json::from_value(json!({ "portscan": p })).unwrap();
        d
    }

    #[test]
    fn portscan_time_is_validated() {
        for ok in ["00:00", "03:30", "23:59", "9:05"] {
            let d = doc_portscan(json!({"time": ok}));
            assert!(d.validate().is_empty(), "{ok}");
        }
        for bad in [
            "24:00", "12:60", "3", "", "aa:bb", "03:30:00", " 03:30", "-1:30", "+3:30",
        ] {
            let d = doc_portscan(json!({"time": bad}));
            assert!(format!("{}", d.validate()).contains("HH:MM"), "{bad:?}");
        }
    }

    #[test]
    fn portscan_extra_ports_are_validated_and_capped() {
        // 0 is rejected, and anything over 65535 does not even parse
        let d = doc_portscan(json!({"extra_ports": [8081, 0]}));
        assert!(format!("{}", d.validate()).contains("1 to 65535"));
        assert!(
            serde_json::from_value::<Hosts>(json!({"portscan": {"extra_ports": [65536]}})).is_err()
        );
        assert!(
            serde_json::from_value::<Hosts>(json!({"portscan": {"extra_ports": [-1]}})).is_err()
        );
        let ok = doc_portscan(json!({"extra_ports": [1, 65535]}));
        assert!(ok.validate().is_empty());
        // a huge list is refused
        let many: Vec<u16> = (10_000..10_000 + MAX_EXTRA_PORTS as u16 + 1).collect();
        let d = doc_portscan(json!({ "extra_ports": many }));
        assert!(
            format!("{}", d.validate()).contains("At most"),
            "{}",
            d.validate()
        );
        let max: Vec<u16> = (10_000..10_000 + MAX_EXTRA_PORTS as u16).collect();
        assert!(
            doc_portscan(json!({ "extra_ports": max }))
                .validate()
                .is_empty()
        );
        // duplicates are allowed and collapse
        let dup = doc_portscan(json!({"extra_ports": [8081, 8081, 22]}));
        assert!(dup.validate().is_empty());
        assert_eq!(dup.hosts.portscan.extra(), vec![22, 8081]);
    }

    #[test]
    fn host_kind_display() {
        assert_eq!(HostKind::Tv.display(), "TV/streaming");
        assert_eq!(HostKind::SmartHome.display(), "Smart home");
        assert_eq!(HostKind::ALL.len(), 14);
        assert_eq!(
            serde_json::to_value(HostKind::SmartHome).unwrap(),
            json!("smart_home")
        );
    }
}
