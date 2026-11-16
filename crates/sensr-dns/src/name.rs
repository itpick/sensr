//! Domain names as the blocklist compiler stores them.
//!
//! A list name is lower-cased and validated like OPNsense's blocklist parser
//! does (at least two labels, a real top-level label, underscores allowed in
//! labels since lists contain them). It is kept as a [`Key`]: its labels in
//! reverse order joined by `\x01`. Sorting keys puts every name right after
//! its parent domain and before any sibling (`\x01` sorts below every label
//! character), so "is this name below a blocked subtree" is a check against
//! the last subtree seen in a single pass, and lookups are binary searches.

use std::fmt;

/// Label separator inside a [`Key`].
pub const SEP: char = '\x01';

/// Maximum length of a domain name in text form (RFC 1035).
const MAX_NAME: usize = 253;

/// A validated, lower-cased domain name in reversed-label form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key(Box<str>);

impl Key {
    /// Parses a list entry (`Ads.Example.com`, `ads.example.com.`); `None`
    /// for anything that is not a plausible domain name.
    pub fn parse(name: &str) -> Option<Key> {
        let name = name.strip_suffix('.').unwrap_or(name);
        if name.is_empty() || name.len() > MAX_NAME || !name.is_ascii() {
            return None;
        }
        let lower = name.to_ascii_lowercase();
        let labels: Vec<&str> = lower.split('.').collect();
        if labels.len() < 2 || !labels.iter().all(|l| valid_label(l)) {
            return None;
        }
        let tld = labels[labels.len() - 1];
        let tld_ok = tld.starts_with("xn--")
            || (tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphanumeric()));
        // An all-numeric "top-level label" is an IP address, not a name.
        if !tld_ok || tld.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut key = String::with_capacity(lower.len());
        for (i, l) in labels.iter().rev().enumerate() {
            if i > 0 {
                key.push(SEP);
            }
            key.push_str(l);
        }
        Some(Key(key.into_boxed_str()))
    }

    /// The key text (reversed labels).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when `self` is `other` or below it.
    pub fn is_within(&self, other: &Key) -> bool {
        let (s, o) = (self.as_str(), other.as_str());
        s == o || (s.len() > o.len() && s.starts_with(o) && s[o.len()..].starts_with(SEP))
    }

    /// The parent domain's key; `None` for a single label.
    pub fn parent(&self) -> Option<&str> {
        self.as_str().rfind(SEP).map(|i| &self.as_str()[..i])
    }

    /// The name in normal form (`ads.example.com`).
    pub fn name(&self) -> String {
        let mut out = String::with_capacity(self.0.len());
        for (i, l) in self.0.rsplit(SEP).enumerate() {
            if i > 0 {
                out.push('.');
            }
            out.push_str(l);
        }
        out
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())
    }
}

fn valid_label(l: &str) -> bool {
    !l.is_empty()
        && l.len() <= 63
        && !l.starts_with('-')
        && !l.ends_with('-')
        && l.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// The key text of every ancestor of `key`, nearest first (`b.a` for
/// `c.b.a`, then `a`).
pub fn ancestors(key: &str) -> impl Iterator<Item = &str> {
    let mut cur = Some(key);
    std::iter::from_fn(move || {
        let k = cur?;
        cur = k.rfind(SEP).map(|i| &k[..i]);
        cur
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_reverses() {
        let k = Key::parse("Ads.Example.COM.").unwrap();
        assert_eq!(k.as_str(), "com\x01example\x01ads");
        assert_eq!(k.name(), "ads.example.com");
        assert_eq!(k.parent(), Some("com\x01example"));
        assert!(Key::parse("_dmarc.example.com").is_some());
        assert!(Key::parse("xn--bcher-kva.xn--p1ai").is_some());
    }

    #[test]
    fn rejects_what_opnsense_rejects() {
        for bad in [
            "",
            "localhost",
            "com",
            "0.0.0.0",
            "127.0.0.1",
            "a..b.com",
            "-a.com",
            "a-.com",
            "exa mple.com",
            "ex*.com",
            "a.c",
            "bücher.de",
        ] {
            assert!(Key::parse(bad).is_none(), "{bad:?}");
        }
        let long = format!("{}.com", "a".repeat(64));
        assert!(Key::parse(&long).is_none());
    }

    #[test]
    fn children_sort_right_after_their_parent() {
        let mut keys: Vec<Key> = ["example.com", "example-x.com", "ads.example.com", "z.com"]
            .iter()
            .map(|n| Key::parse(n).unwrap())
            .collect();
        keys.sort();
        let names: Vec<String> = keys.iter().map(Key::name).collect();
        assert_eq!(
            names,
            ["example.com", "ads.example.com", "example-x.com", "z.com"]
        );
        assert!(keys[1].is_within(&keys[0]));
        assert!(!keys[2].is_within(&keys[0]));
    }

    #[test]
    fn ancestors_nearest_first() {
        let k = Key::parse("a.b.example.com").unwrap();
        let a: Vec<&str> = ancestors(k.as_str()).collect();
        assert_eq!(a, ["com\x01example\x01b", "com\x01example", "com"]);
    }
}
