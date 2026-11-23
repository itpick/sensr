//! Traffic accounting (OPNsense Reporting › NetFlow + Insight; replaces
//! ntopng too). sensr counts in the kernel: nftables sets with per-element
//! counters keyed by local host and by service, read every few seconds by
//! `sensr-insight`, which keeps 1-minute, 1-hour and 1-day rollups in SQLite.
//! No packet capture, no flow export loop through localhost.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::array::ArrayField;
use crate::fields::InterfaceId;
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldPath, Validations, ValidatorKind};

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
    /// Per-host DNS activity settings.
    #[serde(default, skip_serializing_if = "InsightDns::is_empty")]
    pub dns: InsightDns,
}

/// What kind of thing a service is, for the per-host DNS activity page.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// Streaming and video sites.
    Video,
    /// Social networks.
    Social,
    /// Games and game platforms.
    Games,
    /// Messaging and calls.
    Messaging,
    /// Music and audio.
    Music,
    /// Learning.
    Education,
    /// Shopping.
    Shopping,
    /// Apple, Google and Microsoft system traffic.
    System,
    /// Advertising and tracking.
    AdsTracking,
    /// Smart-home and IoT clouds.
    SmartHome,
    /// Anything else.
    Other,
}

impl Category {
    /// Every category, in display order.
    pub const ALL: [Category; 11] = [
        Category::Video,
        Category::Social,
        Category::Games,
        Category::Messaging,
        Category::Music,
        Category::Education,
        Category::Shopping,
        Category::System,
        Category::AdsTracking,
        Category::SmartHome,
        Category::Other,
    ];

    /// The name shown to people.
    pub fn display(self) -> &'static str {
        match self {
            Category::Video => "Video",
            Category::Social => "Social",
            Category::Games => "Games",
            Category::Messaging => "Messaging",
            Category::Music => "Music",
            Category::Education => "Education",
            Category::Shopping => "Shopping",
            Category::System => "Apple/Google/Microsoft system",
            Category::AdsTracking => "Ads & tracking",
            Category::SmartHome => "Smart home",
            Category::Other => "Other",
        }
    }
}

/// An owner-set service name and category for every domain under a suffix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceOverride {
    /// Whether the override is in force.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Domain suffix, lowercase, at least two labels (`example.com` matches
    /// it and everything under it). Matching is by longest suffix: a longer
    /// built-in suffix still beats a shorter override (an override of
    /// `google.com` does not change `classroom.google.com`; override that
    /// name too).
    pub suffix: String,
    /// Service name shown (1-48 characters, no control characters).
    pub service: String,
    /// Category the service counts under.
    pub category: Category,
}

/// Per-host DNS activity settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InsightDns {
    /// Owner overrides of the built-in service catalogue. The longest
    /// matching suffix wins; an override beats the built-in entry.
    #[serde(default, skip_serializing_if = "ArrayField::is_empty")]
    pub service_overrides: ArrayField<ServiceOverride>,
}

impl InsightDns {
    /// True when nothing differs from the defaults.
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// True for a lowercase domain suffix of at least two labels (so a bare
/// `com` is refused): dot-separated labels of 1-63
/// letters, digits and hyphens, none starting or ending with a hyphen,
/// 253 characters at most.
pub fn is_domain_suffix(s: &str) -> bool {
    s.contains('.')
        && s.len() <= 253
        && s.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
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
            dns: InsightDns::default(),
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
        let o = at.join("dns").join("service_overrides");
        check::unique(
            self.dns
                .service_overrides
                .iter()
                .map(|(id, v)| (o.join(id), Some(v.suffix.clone()))),
            "suffix",
            "An override for this suffix already exists.",
            out,
        );
        for (id, v) in &self.dns.service_overrides {
            if !is_domain_suffix(&v.suffix) {
                out.add(
                    &o.join(id).join("suffix"),
                    ValidatorKind::Callback,
                    "The suffix must be a lowercase domain such as example.com.",
                );
            }
            let n = v.service.chars().count();
            if !(1..=48).contains(&n) {
                out.add(
                    &o.join(id).join("service"),
                    ValidatorKind::Callback,
                    "The service name must be 1 to 48 characters.",
                );
            }
            if v.service.chars().any(char::is_control) {
                out.add(
                    &o.join(id).join("service"),
                    ValidatorKind::Callback,
                    "The service name must not contain control characters (tabs, line breaks).",
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

    const U1: &str = "6d0de000-0000-4000-8000-000000000001";
    const U2: &str = "6d0de000-0000-4000-8000-000000000002";

    fn doc_with(o: serde_json::Value) -> Document {
        let mut d = Document::factory();
        d.insight.dns = serde_json::from_value(json!({ "service_overrides": o })).unwrap();
        d
    }

    #[test]
    fn service_override_round_trips() {
        let src = json!({"service_overrides":{U1:{"suffix":"example.com","service":"Example","category":"ads_tracking"}}});
        let h: InsightDns = serde_json::from_value(src).unwrap();
        let first = h.service_overrides.iter().next().unwrap().1;
        assert!(first.enabled);
        assert_eq!(first.category, Category::AdsTracking);
        let out = serde_json::to_value(&h).unwrap();
        assert_eq!(out["service_overrides"][U1]["enabled"], true);
        assert_eq!(serde_json::from_value::<InsightDns>(out).unwrap(), h);
        assert!(
            doc_with(json!({U1:{"suffix":"example.com","service":"Example","category":"video"}}))
                .validate()
                .is_empty()
        );
        assert!(
            serde_json::to_value(Insight::default())
                .unwrap()
                .get("dns")
                .is_none()
        );
    }

    #[test]
    fn category_names_in_order() {
        let names: Vec<_> = Category::ALL.iter().map(|c| c.display()).collect();
        assert_eq!(
            names,
            [
                "Video",
                "Social",
                "Games",
                "Messaging",
                "Music",
                "Education",
                "Shopping",
                "Apple/Google/Microsoft system",
                "Ads & tracking",
                "Smart home",
                "Other"
            ]
        );
    }

    #[test]
    fn bad_suffix_rejected() {
        for bad in [
            "",
            "Example.com",
            "-a.com",
            "a..com",
            ".com",
            "a b.com",
            "a.com.",
        ] {
            let d = doc_with(json!({U1:{"suffix":bad,"service":"X","category":"other"}}));
            assert!(
                format!("{}", d.validate()).contains("lowercase domain"),
                "{bad:?}"
            );
        }
        let d = doc_with(json!({U1:{"suffix":"example.com","service":"","category":"other"}}));
        assert!(format!("{}", d.validate()).contains("1 to 48"));
        let d = doc_with(json!({U1:{"suffix":"example.com","service":"a\tb","category":"other"}}));
        assert!(format!("{}", d.validate()).contains("control"));
    }

    #[test]
    fn duplicate_suffix_rejected() {
        let d = doc_with(json!({
            U1: {"suffix":"example.com","service":"A","category":"other"},
            U2: {"suffix":"example.com","service":"B","category":"video"}
        }));
        assert!(format!("{}", d.validate()).contains("already exists"));
    }
}
