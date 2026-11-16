//! Alias entry parsing (`BaseContentParser.iter_addresses`,
//! `net_wildcard_iterator`, `UriParser._parse_line`).

use std::net::IpAddr;

use ipnet::IpNet;

use super::ipset::{TableEntry, summarize};

/// Upstream stops expanding a wildcard after this many networks.
pub const WILDCARD_LIMIT: usize = 65_536;

/// What one alias content token turned into.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Parsed {
    /// table entries (an address range or wildcard yields several)
    Entries(Vec<TableEntry>),
    /// not an address: queued for DNS resolution
    Hostname(String),
    /// invalid and not a name (an unparsable network): dropped
    Dropped,
}

fn entry(net: IpNet, negate: bool) -> TableEntry {
    TableEntry { net, negate }
}

fn host(ip: IpAddr) -> IpNet {
    IpNet::from(ip)
}

/// Parses one host/network alias token.
///
/// - `a/<digits>`: a network (host bits allowed), or dropped when invalid;
/// - `a/<mask>` with a dotted wildcard mask: every network the wildcard
///   describes;
/// - `a-b`: the CIDR cover of the range;
/// - an address, optionally `!`-negated;
/// - anything else is a host name to resolve.
pub fn parse_entry(token: &str) -> Parsed {
    let t = token.trim();
    let (negate, bare) = match t.strip_prefix('!') {
        Some(r) => (true, r),
        None => (false, t),
    };
    if let Some((_, suffix)) = t.rsplit_once('/') {
        if !suffix.bytes().all(|b| b.is_ascii_digit()) || suffix.is_empty() {
            return match wildcard(bare) {
                Some(nets) => Parsed::Entries(nets.into_iter().map(|n| entry(n, negate)).collect()),
                None => Parsed::Dropped,
            };
        }
        return match bare.parse::<IpNet>() {
            Ok(n) => Parsed::Entries(vec![entry(n.trunc(), negate)]),
            Err(_) => Parsed::Dropped,
        };
    }
    if let Some((a, b)) = t.split_once('-')
        && let (Ok(a), Ok(b)) = (a.parse::<IpAddr>(), b.parse::<IpAddr>())
    {
        return Parsed::Entries(
            summarize(a, b)
                .into_iter()
                .map(|n| entry(n, false))
                .collect(),
        );
    }
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Parsed::Entries(vec![entry(host(ip), negate)]);
    }
    Parsed::Hostname(t.to_owned())
}

/// `net_wildcard_iterator`: `192.168.0.1/0.0.255.0` → the 256 hosts that
/// vary in the third octet. Trailing contiguous wildcard bits become the
/// prefix length; the other wildcard bits are enumerated.
pub fn wildcard(spec: &str) -> Option<Vec<IpNet>> {
    let (addr, mask) = spec.split_once('/')?;
    let addr: IpAddr = addr.parse().ok()?;
    let mask: IpAddr = mask.parse().ok()?;
    let (a, m, bits) = match (addr, mask) {
        (IpAddr::V4(a), IpAddr::V4(m)) => {
            (u128::from(u32::from(a)), u128::from(u32::from(m)), 32u32)
        }
        (IpAddr::V6(a), IpAddr::V6(m)) => (u128::from(a), u128::from(m), 128u32),
        _ => return None,
    };
    let set_bits: Vec<u32> = (0..bits).filter(|i| m >> i & 1 == 1).collect();
    let host_len = set_bits
        .iter()
        .enumerate()
        .take_while(|(pos, bit)| *pos as u32 == **bit)
        .count();
    let varying = &set_bits[host_len..];
    let prefix = (bits - host_len as u32) as u8;
    let count = 1usize
        .checked_shl(varying.len() as u32)
        .unwrap_or(usize::MAX);
    let mut out = Vec::with_capacity(count.min(WILDCARD_LIMIT));
    for combo in 0..count.min(WILDCARD_LIMIT) {
        let mut ip = a;
        for (k, bit) in varying.iter().rev().enumerate() {
            // itertools.product order: the most significant varying bit changes slowest
            let on = combo >> (varying.len() - 1 - k) & 1 == 1;
            if on {
                ip |= 1u128 << bit;
            } else {
                ip &= !(1u128 << bit);
            }
        }
        let net = match addr {
            IpAddr::V4(_) => IpNet::new(IpAddr::V4((ip as u32).into()), prefix),
            IpAddr::V6(_) => IpNet::new(IpAddr::V6(ip.into()), prefix),
        }
        .ok()?
        .trunc();
        out.push(net);
    }
    Some(out)
}

/// `UriParser._parse_line`: the first token of a list line, unless it is a
/// `//` comment. Separators are whitespace and `,;|#`.
pub fn list_line(line: &str) -> Option<&str> {
    let tok = line
        .split(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '|' | '#'))
        .next()?;
    (!tok.is_empty() && !tok.starts_with("//")).then_some(tok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn nets(p: Parsed) -> Vec<String> {
        match p {
            Parsed::Entries(v) => v.iter().map(|e| e.net.to_string()).collect(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn host_address_t0329() {
        assert_eq!(nets(parse_entry("192.168.1.1")), ["192.168.1.1/32"]);
        // not an address: queued for DNS, yields no address
        assert_eq!(
            parse_entry("192.999.1.1"),
            Parsed::Hostname("192.999.1.1".into())
        );
    }

    #[test]
    fn host_network_t0330() {
        assert_eq!(nets(parse_entry("192.168.1.0/24")), ["192.168.1.0/24"]);
        assert_eq!(parse_entry("192.168.999.0/24"), Parsed::Dropped);
    }

    #[test]
    fn wildcard_mask_expansion_t0332() {
        let Parsed::Entries(v) = parse_entry("192.168.0.0/0.0.255.0") else {
            panic!()
        };
        assert_eq!(v.len(), 256);
        assert_eq!(v[0].net.to_string(), "192.168.0.0/32");
        assert_eq!(v[255].net.to_string(), "192.168.255.0/32");
        // upstream docstring example: 172.18.161.2 / 0.1.2.7
        let w: Vec<String> = wildcard("172.18.161.2/0.1.2.7")
            .unwrap()
            .iter()
            .map(|n| n.to_string())
            .collect();
        assert_eq!(
            w,
            [
                "172.18.161.0/29",
                "172.18.163.0/29",
                "172.19.161.0/29",
                "172.19.163.0/29"
            ]
        );
    }

    #[test]
    fn ranges_and_negation() {
        assert_eq!(
            nets(parse_entry("10.0.0.1-10.0.0.2")),
            ["10.0.0.1/32", "10.0.0.2/32"]
        );
        let Parsed::Entries(v) = parse_entry("!10.0.0.0/8") else {
            panic!()
        };
        assert!(v[0].negate);
    }

    #[test]
    fn list_lines() {
        assert_eq!(list_line("1.2.3.0/24 ; SBL123"), Some("1.2.3.0/24"));
        assert_eq!(list_line("; comment"), None);
        assert_eq!(list_line("// comment"), None);
        assert_eq!(list_line("10.0.0.1,foo"), Some("10.0.0.1"));
        assert_eq!(list_line(""), None);
    }

    proptest! {
        /// A wildcard with k non-trailing bits set yields 2^k networks.
        #[test]
        fn prop_wildcard_count_is_pow2_t0332(mask in any::<u32>()) {
            let m = std::net::Ipv4Addr::from(mask);
            let v = wildcard(&format!("10.0.0.0/{m}")).unwrap();
            let set: u32 = mask.count_ones();
            let trailing = mask.trailing_ones();
            let k = set - trailing;
            prop_assert_eq!(v.len(), (1usize << k).min(WILDCARD_LIMIT));
        }

        /// Never panics on arbitrary input.
        #[test]
        fn prop_parse_entry_total(s in "\\PC{0,40}") {
            let _ = parse_entry(&s);
            let _ = list_line(&s);
        }
    }
}
