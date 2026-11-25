//! Port ordering and service names.
//!
//! The scan order comes from two lists written by the sensr authors (see the
//! headers of `data/top-tcp.txt` and `data/top-udp.txt`).

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;

pub use crate::types::Proto;

const TOP_TCP: &str = include_str!("../data/top-tcp.txt");
const TOP_UDP: &str = include_str!("../data/top-udp.txt");

fn parse_ports(text: &str) -> Vec<u16> {
    let mut seen = HashSet::new();
    text.lines()
        .filter_map(|l| l.split('#').next()?.trim().parse::<u16>().ok())
        .filter(|p| *p != 0 && seen.insert(*p))
        .collect()
}

/// Every TCP port 1..=65535: the curated list first, in file order, then the
/// remainder ascending. No duplicates.
pub fn tcp_order() -> Vec<u16> {
    let mut out = parse_ports(TOP_TCP);
    let seen: HashSet<u16> = out.iter().copied().collect();
    out.extend((1..=u16::MAX).filter(|p| !seen.contains(p)));
    out
}

/// The curated UDP ports, most important first.
pub fn top_udp() -> &'static [u16] {
    static UDP: OnceLock<Vec<u16>> = OnceLock::new();
    UDP.get_or_init(|| parse_ports(TOP_UDP))
}

/// Port to service-name table in `/etc/services` format.
#[derive(Debug, Default, Clone)]
pub struct Services {
    map: HashMap<(Proto, u16), String>,
}

impl Services {
    /// Parse `/etc/services`-style text: `name port/proto [aliases] [# comment]`.
    /// Malformed lines are skipped; the first name for a port wins.
    pub fn parse(text: &str) -> Services {
        let mut map = HashMap::new();
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            let mut f = line.split_whitespace();
            let (Some(name), Some(pp)) = (f.next(), f.next()) else {
                continue;
            };
            let Some((port, proto)) = pp.split_once('/') else {
                continue;
            };
            let proto = match proto {
                "tcp" => Proto::Tcp,
                "udp" => Proto::Udp,
                _ => continue,
            };
            let Ok(port) = port.parse::<u16>() else {
                continue;
            };
            map.entry((proto, port)).or_insert_with(|| name.to_string());
        }
        Services { map }
    }

    /// Load a services file; a missing or unreadable file gives an empty table.
    pub fn load(path: &Path) -> Services {
        std::fs::read_to_string(path)
            .map(|t| Services::parse(&t))
            .unwrap_or_default()
    }

    pub fn name(&self, proto: Proto, port: u16) -> Option<&str> {
        self.map.get(&(proto, port)).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Vec<u16> {
        s.lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .filter(|l| !l.is_empty())
            .map(|l| l.parse().unwrap())
            .collect()
    }

    #[test]
    fn tcp_order_is_complete_and_unique() {
        let o = tcp_order();
        assert_eq!(o.len(), 65535);
        assert_eq!(o.iter().collect::<HashSet<_>>().len(), 65535);
        assert!(!o.contains(&0));
    }

    #[test]
    fn tcp_order_starts_with_file_order_then_ascending() {
        let o = tcp_order();
        let top = parse(TOP_TCP);
        assert!(top.len() >= 900);
        assert_eq!(&o[..top.len()], &top[..]);
        let set: HashSet<u16> = top.iter().copied().collect();
        let rest: Vec<u16> = (1..=65535).filter(|p| !set.contains(p)).collect();
        assert_eq!(&o[top.len()..], &rest[..]);
        let first: HashSet<u16> = o[..5].iter().copied().collect();
        assert!(first.is_subset(&set));
    }

    #[test]
    fn top_udp_has_essentials() {
        let u = top_udp();
        for p in [53, 123, 161, 1900, 5353] {
            assert!(u.contains(&p), "{p}");
        }
        assert!(u.len() >= 900);
        assert_eq!(u.iter().collect::<HashSet<_>>().len(), u.len());
    }

    #[test]
    fn services_parse() {
        let s =
            Services::parse("ssh 22/tcp\ndomain 53/udp # comment\n# only comment\nbad\nx y/tcp\n");
        assert_eq!(s.name(Proto::Tcp, 22), Some("ssh"));
        assert_eq!(s.name(Proto::Udp, 53), Some("domain"));
        assert_eq!(s.name(Proto::Tcp, 53), None);
    }

    #[test]
    fn services_load_file_and_missing() {
        let dir = std::env::temp_dir().join(format!("sensr-scan-svc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("services");
        std::fs::write(&f, "http\t80/tcp\twww\n").unwrap();
        assert_eq!(Services::load(&f).name(Proto::Tcp, 80), Some("http"));
        assert_eq!(Services::load(&dir.join("nope")).name(Proto::Tcp, 80), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn first_name_wins() {
        let s = Services::parse("a 80/tcp\nb 80/tcp\n");
        assert_eq!(s.name(Proto::Tcp, 80), Some("a"));
    }

    #[test]
    fn proto_serde_lowercase() {
        assert_eq!(serde_json::to_string(&Proto::Udp).unwrap(), "\"udp\"");
        assert_eq!(
            serde_json::from_str::<Proto>("\"tcp\"").unwrap(),
            Proto::Tcp
        );
    }
}
