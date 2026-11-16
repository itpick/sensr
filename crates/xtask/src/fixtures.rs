//! `cargo xtask lint-fixtures` (T-0347, OPNsense `lint-xml`): every fixture
//! parses, and the synthetic corpus keeps to its conventions
//! (crates/sensr-import-opnsense/tests/fixtures/corpus/README.md): public
//! addresses only from the documentation ranges, locally administered MACs
//! with the 02:00:5e prefix. That is what keeps real router data out of the
//! repository.

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::{Context, Result, bail};
use quick_xml::Reader;
use quick_xml::events::Event;
use regex::Regex;

use crate::walk;

/// Parses `text` as XML to the end; errors on malformed or unbalanced input.
pub fn check_xml(text: &str) -> Result<()> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().check_end_names = true;
    let mut depth: usize = 0;
    let mut roots = 0;
    loop {
        match reader
            .read_event()
            .with_context(|| format!("at byte {}", reader.buffer_position()))?
        {
            Event::Start(_) => {
                if depth == 0 {
                    roots += 1;
                }
                depth += 1;
            }
            Event::Empty(_) if depth == 0 => roots += 1,
            Event::End(_) => depth = depth.saturating_sub(1),
            Event::Eof => break,
            _ => {}
        }
    }
    if depth != 0 {
        bail!("unclosed element at end of file");
    }
    if roots != 1 {
        bail!("expected one root element, found {roots}");
    }
    Ok(())
}

/// A public IPv4 address that is not in a documentation range (RFC 5737).
fn bad_v4(a: Ipv4Addr) -> bool {
    let o = a.octets();
    let doc = matches!(o, [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]);
    let special = a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_unspecified()
        || a.is_multicast()
        || a.is_broadcast()
        || o[0] == 0
        || o[0] >= 240
        // CGNAT 100.64.0.0/10 (RFC 6598).
        || (o[0] == 100 && (64..128).contains(&o[1]))
        // Benchmarking 198.18.0.0/15 (RFC 2544): bogon lists name it.
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19));
    !doc && !special
}

/// A global unicast IPv6 address outside 2001:db8::/32 (RFC 3849).
fn bad_v6(a: Ipv6Addr) -> bool {
    let s = a.segments();
    let global_unicast = (s[0] & 0xe000) == 0x2000;
    global_unicast && !(s[0] == 0x2001 && s[1] == 0x0db8)
}

/// Convention violations in one synthetic corpus file.
pub fn corpus_violations(text: &str) -> Vec<String> {
    let v4 =
        Regex::new(r"(?:^|[^0-9.])((?:\d{1,3}\.){3}\d{1,3})(?:$|[^0-9.])").expect("static regex");
    let v6 = Regex::new(r"(?i)(?:^|[^0-9a-f:])([0-9a-f]{1,4}(?::[0-9a-f]{0,4}){2,7})")
        .expect("static regex");
    let mac = Regex::new(r"(?i)\b((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\b").expect("static regex");
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let ln = n + 1;
        for c in v4.captures_iter(line) {
            if let Ok(a) = c[1].parse::<Ipv4Addr>()
                && bad_v4(a)
            {
                out.push(format!("line {ln}: public IPv4 {a} (use 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24)"));
            }
        }
        for c in mac.captures_iter(line) {
            let m = c[1].to_ascii_lowercase();
            if !m.starts_with("02:00:5e:") {
                out.push(format!("line {ln}: MAC {m} (use 02:00:5e:xx:xx:xx)"));
            }
        }
        for c in v6.captures_iter(line) {
            let s = &c[1];
            if mac.is_match(s) {
                continue;
            }
            if let Ok(a) = s.parse::<Ipv6Addr>()
                && bad_v6(a)
            {
                out.push(format!("line {ln}: public IPv6 {a} (use 2001:db8::/32)"));
            }
        }
    }
    out
}

pub fn run(root: &Path) -> Result<()> {
    let mut errors = Vec::new();
    let mut checked = 0;
    for path in walk::files(&root.join("crates"))? {
        let rel = walk::rel(root, &path);
        if !rel.contains("/tests/fixtures/") {
            continue;
        }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let parse = match ext {
            "xml" => {
                let text = fs::read_to_string(&path).with_context(|| rel.clone())?;
                let r = check_xml(&text);
                if rel.contains("/tests/fixtures/corpus/") {
                    for v in corpus_violations(&text) {
                        errors.push(format!("{rel}: {v}"));
                    }
                }
                r
            }
            "json" | "sensr" => {
                let text = fs::read_to_string(&path).with_context(|| rel.clone())?;
                serde_json::from_str::<serde_json::Value>(&text)
                    .map(drop)
                    .map_err(Into::into)
            }
            _ => continue,
        };
        checked += 1;
        if let Err(e) = parse {
            errors.push(format!("{rel}: {e:#}"));
        }
    }
    println!("lint-fixtures: {checked} fixture files checked");
    for e in &errors {
        println!("error: {e}");
    }
    if !errors.is_empty() {
        bail!("{} fixture problem(s)", errors.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_formed_xml_passes() {
        check_xml("<?xml version=\"1.0\"?>\n<opnsense><a>1</a><b/></opnsense>\n").unwrap();
    }

    #[test]
    fn malformed_xml_fails() {
        assert!(check_xml("<opnsense><a></b></opnsense>").is_err());
        assert!(check_xml("<opnsense><a>").is_err());
        assert!(check_xml("<a/><b/>").is_err());
    }

    #[test]
    fn documentation_and_private_addresses_are_fine() {
        let ok = "<ip>192.0.2.1</ip><ip>198.51.100.2</ip><ip>203.0.113.53</ip><ip>10.40.0.53</ip>\
                  <ip>192.168.1.1</ip><m>255.255.255.0</m><v6>2001:db8:10::1/64</v6><v6>fe80::1</v6>\
                  <b>198.18.0.0/15</b><mac>02:00:5e:10:00:0a</mac><t>12:34:56</t><v>1.0.6</v>";
        assert_eq!(corpus_violations(ok), Vec::<String>::new());
    }

    #[test]
    fn real_looking_data_is_flagged() {
        let v = corpus_violations(
            "<ip>8.8.8.8</ip>\n<mac>00:1b:21:aa:bb:cc</mac>\n<v6>2a00:1450::1</v6>",
        );
        assert_eq!(v.len(), 3, "{v:?}");
        assert!(v[0].contains("8.8.8.8"));
        assert!(v.iter().any(|e| e.contains("00:1b:21")));
        assert!(v.iter().any(|e| e.contains("2a00:1450::1")));
    }
}
