//! Port scanner (Diagnostics > Port Scan): settings of the `sensr-scan`
//! service, which probes devices on the local networks for open ports and
//! the certificates they present. Scanning is on by default but only ever
//! starts when someone asks for it or, with `auto_scan_new`, when a device
//! first appears.

use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::array::ArrayField;
use crate::fields::{Description, MacAddr};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldPath, Validations, ValidatorKind};

/// How hard to scan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScanPace {
    /// Quiet: for small or fragile networks.
    Gentle,
    /// The default.
    #[default]
    Normal,
    /// As fast as is polite.
    Fast,
}

/// A device that is never scanned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanExclude {
    /// Whether the exclusion is in force.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The device: a MAC address or an IP address.
    pub target: String,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

/// What a [`ScanExclude::target`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanTarget {
    /// A device by MAC address.
    Mac(MacAddr),
    /// A device by IP address.
    Addr(IpAddr),
}

impl ScanExclude {
    /// The device this entry names, or `None` when `target` is neither a
    /// MAC nor an IP address.
    pub fn parsed(&self) -> Option<ScanTarget> {
        let t = self.target.trim();
        t.parse::<IpAddr>()
            .map(ScanTarget::Addr)
            .ok()
            .or_else(|| t.parse::<MacAddr>().map(ScanTarget::Mac).ok())
    }
}

fn history() -> u16 {
    10
}
fn max_range() -> u32 {
    4096
}

/// Port scanner settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Portscan {
    /// Allow scanning at all.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Scan a device automatically the first time it appears.
    #[serde(default = "yes")]
    pub auto_scan_new: bool,
    /// How hard to scan.
    #[serde(default)]
    pub pace: ScanPace,
    /// Scan results kept per target (1-100).
    #[serde(default = "history")]
    pub history: u16,
    /// Most addresses a single scan request may cover (1-65536).
    #[serde(default = "max_range")]
    pub max_range: u32,
    /// Devices that are never scanned.
    #[serde(default, skip_serializing_if = "ArrayField::is_empty")]
    pub exclude: ArrayField<ScanExclude>,
}

impl Default for Portscan {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_scan_new: true,
            pace: ScanPace::default(),
            history: history(),
            max_range: max_range(),
            exclude: ArrayField::default(),
        }
    }
}

impl Portscan {
    /// True when nothing differs from the defaults (the section is then
    /// omitted).
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

impl Validate for Portscan {
    fn validate(&self, _ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        check::range(self.history, 1..=100, &at.join("history"), out);
        check::range(self.max_range, 1..=65_536, &at.join("max_range"), out);
        let ex = at.join("exclude");
        for (id, e) in &self.exclude {
            if e.parsed().is_none() {
                out.add(
                    &ex.join(id).join("target"),
                    ValidatorKind::Callback,
                    "Please enter a MAC address or an IP address.",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Document;
    use serde_json::json;

    const U1: &str = "6d0de000-0000-4000-8000-000000000001";

    fn doc_with(o: serde_json::Value) -> Document {
        let mut d = Document::factory();
        d.portscan.exclude = serde_json::from_value(o).unwrap();
        d
    }

    #[test]
    fn defaults_deserialize_from_empty() {
        let p: Portscan = serde_json::from_str("{}").unwrap();
        assert_eq!(p, Portscan::default());
        assert!(p.is_default());
        assert!(p.enabled && p.auto_scan_new);
        assert_eq!(p.pace, ScanPace::Normal);
        assert_eq!((p.history, p.max_range), (10, 4096));
        assert!(p.exclude.is_empty());
    }

    #[test]
    fn default_section_is_omitted_from_the_document() {
        let v = serde_json::to_value(Document::default()).unwrap();
        assert!(v.get("portscan").is_none(), "{v}");
        let mut d = Document::default();
        d.portscan.enabled = false;
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(v["portscan"]["enabled"], false);
    }

    #[test]
    fn history_and_range_limits() {
        let mut d = Document::factory();
        assert!(d.validate().is_empty());
        d.portscan.history = 0;
        let v = d.validate();
        let s = format!("{v}");
        assert!(s.contains("portscan.history"), "{s}");
        assert!(s.contains("between 1 and 100"), "{s}");
        d.portscan.history = 101;
        assert!(!d.validate().is_empty());
        d.portscan.history = 100;
        d.portscan.max_range = 0;
        assert!(format!("{}", d.validate()).contains("portscan.max_range"));
        d.portscan.max_range = 65_537;
        assert!(!d.validate().is_empty());
        d.portscan.max_range = 65_536;
        assert!(d.validate().is_empty());
    }

    #[test]
    fn exclude_target_must_be_mac_or_ip() {
        let d = doc_with(json!({U1: {"target": "nonsense"}}));
        let s = format!("{}", d.validate());
        assert!(s.contains(&format!("portscan.exclude.{U1}.target")), "{s}");
        for ok in [
            "aa:bb:cc:dd:ee:ff",
            "AA-BB-CC-DD-EE-FF",
            "192.168.1.9",
            "fd00::9",
        ] {
            let d = doc_with(json!({U1: {"target": ok}}));
            assert!(d.validate().is_empty(), "{ok}");
        }
    }

    #[test]
    fn exclude_round_trips_with_enabled_default() {
        let src = json!({U1: {"target": "aa:bb:cc:dd:ee:ff", "description": "printer"}});
        let a: ArrayField<ScanExclude> = serde_json::from_value(src).unwrap();
        assert!(a.iter().next().unwrap().1.enabled);
        let out = serde_json::to_value(&a).unwrap();
        assert_eq!(out[U1]["enabled"], true);
        assert_eq!(
            serde_json::from_value::<ArrayField<ScanExclude>>(out).unwrap(),
            a
        );
    }

    #[test]
    fn pace_names_are_snake_case() {
        assert_eq!(serde_json::to_value(ScanPace::Gentle).unwrap(), "gentle");
        assert_eq!(
            serde_json::from_value::<ScanPace>(json!("fast")).unwrap(),
            ScanPace::Fast
        );
    }
}
