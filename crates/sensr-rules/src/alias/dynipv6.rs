//! Dynamic IPv6 host aliases (`InterfaceParser`): the interface's current
//! global prefix combined with a fixed host suffix (`::1005`), so a host
//! keeps its rule when the delegated prefix changes.

use std::net::{IpAddr, Ipv6Addr};

use crate::ir::IfAddr;

/// Global-scope approximation of Python's `IPv6Address.is_global`.
fn is_global(a: &Ipv6Addr) -> bool {
    let s = a.segments();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || (s[0] == 0x2001 && s[1] < 0x0200)
        || (s[0..5] == [0, 0, 0, 0, 0] && s[5] == 0xffff)
        || (s[0] == 0x0064 && s[1] == 0xff9b))
}

fn exploded(a: &Ipv6Addr) -> String {
    a.segments()
        .iter()
        .map(|s| format!("{s:04x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Every global address of the interface with its host part replaced by
/// `pattern` (`::1005` or `::1005/64`), in upstream's exploded notation.
/// The prefix is copied in whole 16-bit groups, as upstream does.
pub fn prefix_plus_suffix(addrs: &[IfAddr], pattern: &str) -> Vec<String> {
    let (suffix, mask) = match pattern.split_once('/') {
        Some((s, m)) => (s, m),
        None => (pattern, "128"),
    };
    let Ok(offset) = format!("0{suffix}").parse::<Ipv6Addr>() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for a in addrs {
        let IpAddr::V6(addr) = a.addr else { continue };
        if !is_global(&addr) {
            continue;
        }
        let keep = 8 - usize::from((128 - a.prefix_len.min(128)) / 16);
        let mut seg = addr.segments();
        seg[keep..].copy_from_slice(&offset.segments()[keep..]);
        out.push(format!("{}/{mask}", exploded(&Ipv6Addr::from(seg))));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_plus_host_suffix_t0327() {
        let lo0 = [
            IfAddr {
                addr: "2001:fff:faaa::4f31".parse().unwrap(),
                prefix_len: 64,
            },
            IfAddr {
                addr: "fe80::1".parse().unwrap(),
                prefix_len: 64,
            },
        ];
        assert_eq!(
            prefix_plus_suffix(&lo0, "::1005"),
            ["2001:0fff:faaa:0000:0000:0000:0000:1005/128"]
        );
    }
}
