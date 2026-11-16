//! Blocklist file formats.
//!
//! One parser for what the curated lists publish, line by line:
//! - hosts files: `0.0.0.0 ads.example.com` (any address, several names);
//! - plain domain lists: `ads.example.com` (that name only);
//! - wildcard lists (HaGeZi, OISD `domainswild`): `*.ads.example.com` (the
//!   name and everything below it);
//! - AdBlock-style DNS filters: `||ads.example.com^` (also below it).
//!
//! `#` starts a comment anywhere (as OPNsense's parser cuts at the first
//! `#`), `!` and `[` start comment or header lines in AdBlock lists.
//! Exception rules (`@@||...`) and rules with modifiers other than
//! `$important` are skipped: they do not mean "block this name".

use std::io::BufRead;
use std::net::IpAddr;

use crate::name::Key;

/// One blocked name from a list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The name.
    pub key: Key,
    /// Also block everything below it.
    pub subtree: bool,
}

/// Counters for one parsed list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParseStats {
    /// Lines read.
    pub lines: u64,
    /// Entries produced.
    pub entries: u64,
    /// Lines that held something other than a comment but no usable name.
    pub rejected: u64,
}

/// Parses one line into zero or more entries; `None` when the line held
/// something but no usable name.
pub fn parse_line(line: &str, out: &mut impl FnMut(Entry)) -> Option<usize> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
        return Some(0);
    }
    let line = line.split('#').next().unwrap_or_default().trim();
    if line.is_empty() {
        return Some(0);
    }
    if line.starts_with("@@") {
        return Some(0);
    }
    if let Some(rest) = line.strip_prefix("||") {
        let (body, modifiers) = match rest.split_once('$') {
            Some((b, m)) => (b, Some(m)),
            None => (rest, None),
        };
        if modifiers.is_some_and(|m| m.split(',').any(|o| o.trim() != "important")) {
            return Some(0);
        }
        let name = body.strip_suffix('^').unwrap_or(body);
        return match Key::parse(name) {
            Some(key) => {
                out(Entry { key, subtree: true });
                Some(1)
            }
            None => None,
        };
    }
    let mut tokens = line.split_whitespace().peekable();
    // A hosts file line: the address first, then one or more names.
    if let Some(first) = tokens.peek()
        && first.parse::<IpAddr>().is_ok()
    {
        tokens.next();
    }
    let mut n = 0;
    let mut bad = false;
    for t in tokens {
        let (name, subtree) = match t.strip_prefix("*.") {
            Some(rest) => (rest, true),
            None => (t, false),
        };
        // Hosts files list the loopback names for the machine itself.
        if matches!(
            name,
            "localhost" | "localhost.localdomain" | "local" | "broadcasthost"
        ) {
            continue;
        }
        match Key::parse(name) {
            Some(key) => {
                out(Entry { key, subtree });
                n += 1;
            }
            None => bad = true,
        }
    }
    if n == 0 && bad { None } else { Some(n) }
}

/// Parses a whole list.
pub fn parse_reader(r: impl BufRead, mut out: impl FnMut(Entry)) -> std::io::Result<ParseStats> {
    let mut stats = ParseStats::default();
    for line in r.split(b'\n') {
        let line = line?;
        stats.lines += 1;
        // Lists are ASCII; a stray non-UTF-8 byte only spoils its own line.
        let text = String::from_utf8_lossy(&line);
        if parse_line(&text, &mut |e| {
            stats.entries += 1;
            out(e)
        })
        .is_none()
        {
            stats.rejected += 1;
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(text: &str) -> (Vec<(String, bool)>, ParseStats) {
        let mut v = Vec::new();
        let stats = parse_reader(text.as_bytes(), |e| v.push((e.key.name(), e.subtree))).unwrap();
        (v, stats)
    }

    #[test]
    fn hagezi_wildcard_format() {
        let (v, s) = entries(
            "# Title: HaGeZi's Multi PRO\n# Syntax: Domains Wildcard (without subdomains)\n#\n*.telemetry.example.com\n*.Ads.Example.NET\n",
        );
        assert_eq!(
            v,
            [
                ("telemetry.example.com".into(), true),
                ("ads.example.net".into(), true)
            ]
        );
        assert_eq!(s.rejected, 0);
    }

    #[test]
    fn hosts_files_and_plain_lists() {
        let (v, _) = entries(
            "127.0.0.1 localhost\n::1 localhost\n0.0.0.0 0.0.0.0\n0.0.0.0 a.example.com b.example.com # two\nplain.example.org\n",
        );
        assert_eq!(
            v,
            [
                ("a.example.com".into(), false),
                ("b.example.com".into(), false),
                ("plain.example.org".into(), false)
            ]
        );
    }

    #[test]
    fn adblock_dns_filters() {
        let (v, _) = entries(
            "[Adblock Plus]\n! comment\n||ads.example.com^\n||x.example.com^$important\n||y.example.com^$third-party\n@@||ok.example.com^\n",
        );
        assert_eq!(
            v,
            [
                ("ads.example.com".into(), true),
                ("x.example.com".into(), true)
            ]
        );
    }

    #[test]
    fn garbage_is_counted_not_fatal() {
        let (v, s) = entries("not a domain\n<html>\n\u{fffd}\u{fffd}\nok.example.com\n");
        assert_eq!(v, [("ok.example.com".into(), false)]);
        assert_eq!(s.lines, 4);
        assert_eq!(s.rejected, 3);
    }

    proptest::proptest! {
        #[test]
        fn never_panics(line in ".{0,300}") {
            let _ = parse_line(&line, &mut |_| {});
        }
    }
}
