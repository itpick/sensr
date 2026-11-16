//! Traffic accounting (OPNsense Reporting › NetFlow + Insight; replaces
//! ntopng too). sensr counts in the kernel: nftables sets with per-element
//! counters keyed by local host and by service, read every few seconds by
//! `sensr-insight`, which keeps 1-minute, 1-hour and 1-day rollups in SQLite.
//! No packet capture, no flow export loop through localhost.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::check;
use crate::fields::InterfaceId;
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldPath, Validations};

/// How long each resolution is kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InsightRetention {
    /// Hours of 1-minute buckets (1-720).
    #[serde(default = "minute_hours")]
    pub minute_hours: u16,
    /// Days of 1-hour buckets (1-366).
    #[serde(default = "hour_days")]
    pub hour_days: u16,
    /// Days of 1-day buckets (1-3660).
    #[serde(default = "day_days")]
    pub day_days: u16,
}

fn minute_hours() -> u16 {
    48
}
fn hour_days() -> u16 {
    62
}
fn day_days() -> u16 {
    730
}

impl Default for InsightRetention {
    fn default() -> Self {
        Self {
            minute_hours: minute_hours(),
            hour_days: hour_days(),
            day_days: day_days(),
        }
    }
}

/// Traffic accounting settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Insight {
    /// Account traffic (OPNsense `Netflow/collect/enable`).
    #[serde(default)]
    pub enabled: bool,
    /// Interfaces whose hosts are accounted ("local"): traffic forwarded in
    /// from them is the host's upload, out to them its download. Empty means
    /// every interface that is not a WAN.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<InterfaceId>,
    /// Seconds between counter reads (1-300).
    #[serde(default = "sample_seconds")]
    pub sample_seconds: u16,
    /// Most hosts and most services tracked at once (each a kernel set;
    /// 256-1048576).
    #[serde(default = "max_entries")]
    pub max_entries: u32,
    /// History kept.
    #[serde(default)]
    pub retention: InsightRetention,
}

fn sample_seconds() -> u16 {
    10
}
fn max_entries() -> u32 {
    65_536
}

impl Default for Insight {
    fn default() -> Self {
        Self {
            enabled: false,
            interfaces: Vec::new(),
            sample_seconds: sample_seconds(),
            max_entries: max_entries(),
            retention: InsightRetention::default(),
        }
    }
}

impl Insight {
    /// True when nothing differs from the defaults (the section is then
    /// omitted).
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

impl Validate for Insight {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        check::interfaces(ctx, &self.interfaces, &at.join("interfaces"), out);
        check::range(
            self.sample_seconds,
            1..=300,
            &at.join("sample_seconds"),
            out,
        );
        check::range(
            self.max_entries,
            256..=1_048_576,
            &at.join("max_entries"),
            out,
        );
        let r = at.join("retention");
        check::range(
            self.retention.minute_hours,
            1..=720,
            &r.join("minute_hours"),
            out,
        );
        check::range(self.retention.hour_days, 1..=366, &r.join("hour_days"), out);
        check::range(self.retention.day_days, 1..=3660, &r.join("day_days"), out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Document;

    #[test]
    fn defaults_and_validation() {
        assert!(Insight::default().is_empty());
        assert_eq!(
            serde_json::from_str::<Insight>("{}").unwrap(),
            Insight::default()
        );
        let mut d = Document::factory();
        d.insight.enabled = true;
        assert!(d.validate().is_empty());
        d.insight.sample_seconds = 0;
        d.insight.interfaces = vec!["opt9".parse().unwrap()];
        let v = format!("{:?}", d.validate());
        assert!(v.contains("between 1 and 300") && v.contains("opt9"), "{v}");
    }
}
