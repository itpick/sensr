//! Built-in service catalogue: which service (and category) a DNS name
//! belongs to, by domain suffix. The data is `data/services.tsv`
//! (`suffix<TAB>service<TAB>category`), our own list. Generic CDNs and shared
//! API hosts (cloudfront, akamai, fastly, amazonaws) are deliberately absent:
//! a name there says nothing about which service the device uses.
//!
//! Matching is on the longest suffix at a label boundary, so
//! `classroom.google.com` is Google Classroom while `mail.google.com` falls
//! back to `google.com`, and `notyoutube.com` never matches `youtube.com`.
//! Owner overrides ([`ServiceOverride`]) are merged on top and win over a
//! built-in entry with the same suffix.

use std::collections::HashMap;
use std::sync::OnceLock;

pub use sensr_schema::models::insight::{Category, ServiceOverride};

const DATA: &str = include_str!("../data/services.tsv");

/// Suffix to (service, category).
#[derive(Debug, Clone)]
pub struct Catalogue {
    map: HashMap<String, (String, Category)>,
}

fn parse_category(s: &str) -> Option<Category> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
}

/// Parse the TSV rows; a malformed row is an error naming its line.
fn parse(data: &str) -> Result<Vec<(&str, &str, Category)>, String> {
    let mut rows = Vec::new();
    for (i, line) in data.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut f = line.split('\t');
        let (Some(suffix), Some(service), Some(cat), None) =
            (f.next(), f.next(), f.next(), f.next())
        else {
            return Err(format!("line {}: expected 3 tab-separated fields", i + 1));
        };
        let category = parse_category(cat)
            .ok_or_else(|| format!("line {}: unknown category {cat:?}", i + 1))?;
        rows.push((suffix, service, category));
    }
    Ok(rows)
}

impl Catalogue {
    /// The catalogue compiled into the binary.
    pub fn builtin() -> &'static Catalogue {
        static C: OnceLock<Catalogue> = OnceLock::new();
        C.get_or_init(|| {
            let rows = parse(DATA).expect("services.tsv is well-formed (checked by tests)");
            Catalogue {
                map: rows
                    .into_iter()
                    .map(|(s, n, c)| (s.to_string(), (n.to_string(), c)))
                    .collect(),
            }
        })
    }

    /// This catalogue plus the enabled overrides. An override replaces an
    /// entry with the same suffix; longest-suffix matching still applies
    /// across the merged set.
    pub fn with_overrides(&self, o: &[ServiceOverride]) -> Catalogue {
        let mut map = self.map.clone();
        for v in o.iter().filter(|v| v.enabled) {
            map.insert(
                v.suffix.trim_end_matches('.').to_ascii_lowercase(),
                (v.service.clone(), v.category),
            );
        }
        Catalogue { map }
    }

    /// The service and category for `qname` (any case, optional trailing
    /// dot), by longest matching suffix at a label boundary.
    pub fn lookup(&self, qname: &str) -> Option<(&str, Category)> {
        let name = qname.trim_end_matches('.').to_ascii_lowercase();
        let mut rest = name.as_str();
        loop {
            if let Some((svc, cat)) = self.map.get(rest) {
                return Some((svc.as_str(), *cat));
            }
            rest = rest.split_once('.')?.1;
        }
    }

    /// Distinct service names per category (for tests and the UI legend).
    pub fn services(&self) -> impl Iterator<Item = (&str, Category)> {
        self.map.values().map(|(s, c)| (s.as_str(), *c))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn ov(suffix: &str, service: &str, category: Category) -> ServiceOverride {
        ServiceOverride {
            enabled: true,
            suffix: suffix.into(),
            service: service.into(),
            category,
        }
    }

    #[test]
    fn youtube_cdn_maps_to_youtube_video() {
        let c = Catalogue::builtin();
        for n in [
            "rr3---sn-abc.googlevideo.com",
            "i.ytimg.com",
            "youtubei.googleapis.com",
            "www.youtube.com",
            "youtu.be",
        ] {
            assert_eq!(c.lookup(n), Some(("YouTube", Category::Video)), "{n}");
        }
        assert_eq!(
            c.lookup("www.youtubekids.com"),
            Some(("YouTube Kids", Category::Video))
        );
        // The shared Google API host is not YouTube.
        assert_ne!(c.lookup("fcm.googleapis.com").map(|x| x.0), Some("YouTube"));
    }

    #[test]
    fn roblox_cdn_maps_to_roblox_games() {
        let c = Catalogue::builtin();
        for n in ["c0.rbxcdn.com", "apis.roblox.com", "x.rbx.com"] {
            assert_eq!(c.lookup(n), Some(("Roblox", Category::Games)), "{n}");
        }
    }

    #[test]
    fn suffix_matches_on_label_boundary() {
        let c = Catalogue::builtin();
        assert_eq!(c.lookup("notyoutube.com"), None);
        assert_eq!(c.lookup("youtube.com.evil.example"), None);
        assert_eq!(c.lookup("YouTube.COM.").map(|x| x.0), Some("YouTube"));
    }

    #[test]
    fn longest_suffix_wins() {
        let c = Catalogue::builtin();
        assert_eq!(
            c.lookup("classroom.google.com"),
            Some(("Google Classroom", Category::Education))
        );
        assert_eq!(
            c.lookup("www.google.com"),
            Some(("Google", Category::System))
        );
        assert_eq!(
            c.lookup("a.b.classroom.google.com").map(|x| x.0),
            Some("Google Classroom")
        );
    }

    #[test]
    fn generic_cdns_are_unmapped() {
        let c = Catalogue::builtin();
        for n in [
            "d111.cloudfront.net",
            "a1.akamaiedge.net",
            "x.fastly.net",
            "s3.amazonaws.com",
        ] {
            assert_eq!(c.lookup(n), None, "{n}");
        }
    }

    #[test]
    fn override_beats_builtin() {
        let c = Catalogue::builtin().with_overrides(&[
            ov("youtube.com", "Homework Videos", Category::Education),
            ov("example.org", "Example", Category::Games),
        ]);
        assert_eq!(
            c.lookup("www.youtube.com"),
            Some(("Homework Videos", Category::Education))
        );
        assert_eq!(
            c.lookup("a.example.org"),
            Some(("Example", Category::Games))
        );
        // Other YouTube domains keep their built-in entry.
        assert_eq!(c.lookup("i.ytimg.com").map(|x| x.0), Some("YouTube"));
        // The builtin is untouched.
        assert_eq!(
            Catalogue::builtin().lookup("www.youtube.com").map(|x| x.0),
            Some("YouTube")
        );
        // A disabled override does nothing.
        let mut off = ov("youtube.com", "Nope", Category::Other);
        off.enabled = false;
        let c = Catalogue::builtin().with_overrides(&[off]);
        assert_eq!(c.lookup("youtube.com").map(|x| x.0), Some("YouTube"));
    }

    #[test]
    fn every_category_has_services() {
        let have: HashSet<_> = Catalogue::builtin().services().map(|(_, c)| c).collect();
        for c in Category::ALL {
            if c != Category::Other {
                assert!(have.contains(&c), "{}", c.display());
            }
        }
    }

    #[test]
    fn catalogue_rows_are_valid() {
        let rows = parse(DATA).unwrap();
        assert!(rows.len() >= 150);
        let mut seen = HashSet::new();
        for (suffix, service, _) in &rows {
            assert!(
                sensr_schema::models::insight::is_domain_suffix(suffix),
                "{suffix}"
            );
            assert!(seen.insert(*suffix), "duplicate suffix {suffix}");
            let n = service.chars().count();
            assert!((1..=48).contains(&n) && !service.chars().any(char::is_control));
        }
        let services: HashSet<_> = rows.iter().map(|r| r.1).collect();
        assert!(services.len() >= 150, "{}", services.len());
        assert!(parse("a.com\tX\n").is_err());
        assert!(parse("a.com\tX\tbogus\n").is_err());
    }
}
