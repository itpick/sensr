//! Address sets with pf table semantics, computed into plain CIDR lists.
//!
//! pf tables may hold negated entries (`!10.1.0.0/16`); a lookup takes the
//! longest matching prefix and fails if that entry is negated. nftables sets
//! have no negation, so the effective set is computed here: entries applied
//! shortest prefix first (add or remove), which is exactly longest-prefix
//! semantics, then emitted as a minimal CIDR cover.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use crate::ir::IpFamily;

/// Disjoint, sorted, non-adjacent inclusive ranges over one family.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Ranges(Vec<(u128, u128)>);

impl Ranges {
    /// Adds many ranges at once: one sort and one merge pass, so a 300k-entry
    /// country list costs O(n log n), not O(n²).
    fn add_all(&mut self, mut add: Vec<(u128, u128)>) {
        if add.is_empty() {
            return;
        }
        add.extend_from_slice(&self.0);
        add.sort_unstable();
        let mut out: Vec<(u128, u128)> = Vec::with_capacity(add.len());
        for (a, b) in add {
            match out.last_mut() {
                // overlapping or adjacent: extend
                Some(last) if a <= last.1.saturating_add(1) => last.1 = last.1.max(b),
                _ => out.push((a, b)),
            }
        }
        self.0 = out;
    }

    /// Removes many ranges at once (sorted sweep).
    fn remove_all(&mut self, mut rm: Vec<(u128, u128)>) {
        if rm.is_empty() || self.0.is_empty() {
            return;
        }
        rm.sort_unstable();
        let mut out = Vec::with_capacity(self.0.len());
        let mut j = 0;
        for &(a0, b) in &self.0 {
            let mut a = a0;
            // removals ending before this range are irrelevant from now on
            while j < rm.len() && rm[j].1 < a {
                j += 1;
            }
            let mut k = j;
            let mut alive = true;
            while k < rm.len() && rm[k].0 <= b {
                let (lo, hi) = rm[k];
                if lo > a {
                    out.push((a, lo - 1));
                }
                if hi >= b {
                    alive = false;
                    break;
                }
                a = a.max(hi + 1);
                k += 1;
            }
            if alive && a <= b {
                out.push((a, b));
            }
        }
        self.0 = out;
    }
}

/// An entry of a pf-style table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TableEntry {
    /// network (hosts are /32 or /128)
    pub net: IpNet,
    /// negated (`!`)
    pub negate: bool,
}

/// The effective addresses of a table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AddrSet {
    v4: Ranges,
    v6: Ranges,
}

fn bounds(n: &IpNet) -> (u128, u128) {
    match n {
        IpNet::V4(n) => (
            u128::from(u32::from(n.network())),
            u128::from(u32::from(n.broadcast())),
        ),
        IpNet::V6(n) => (u128::from(n.network()), u128::from(n.broadcast())),
    }
}

impl AddrSet {
    /// Evaluates entries with longest-prefix-match semantics.
    pub fn from_entries(entries: impl IntoIterator<Item = TableEntry>) -> AddrSet {
        let mut v: Vec<TableEntry> = entries.into_iter().collect();
        v.sort_by_key(|e| (e.net.prefix_len(), e.negate));
        let mut s = AddrSet::default();
        // Consecutive entries of the same sign commute, so each run is
        // applied in bulk; runs keep the shortest-prefix-first order.
        let mut i = 0;
        while i < v.len() {
            let negate = v[i].negate;
            let mut j = i;
            let (mut r4, mut r6) = (Vec::new(), Vec::new());
            while j < v.len() && v[j].negate == negate {
                let b = bounds(&v[j].net);
                match v[j].net {
                    IpNet::V4(_) => r4.push(b),
                    IpNet::V6(_) => r6.push(b),
                }
                j += 1;
            }
            if negate {
                s.v4.remove_all(r4);
                s.v6.remove_all(r6);
            } else {
                s.v4.add_all(r4);
                s.v6.add_all(r6);
            }
            i = j;
        }
        s
    }

    /// `true` when `ip` is in the set.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let (r, x) = match ip {
            IpAddr::V4(a) => (&self.v4, u128::from(u32::from(a))),
            IpAddr::V6(a) => (&self.v6, u128::from(a)),
        };
        r.0.iter().any(|&(a, b)| a <= x && x <= b)
    }

    /// Minimal CIDR cover, v4 first, ascending.
    pub fn to_nets(&self) -> Vec<IpNet> {
        let mut out = Vec::new();
        for &(a, b) in &self.v4.0 {
            cover(a, b, IpFamily::V4, &mut out);
        }
        for &(a, b) in &self.v6.0 {
            cover(a, b, IpFamily::V6, &mut out);
        }
        out
    }
}

/// `ipaddress.summarize_address_range`: the CIDR blocks covering `lo..=hi`.
pub fn summarize(lo: IpAddr, hi: IpAddr) -> Vec<IpNet> {
    let (a, b, fam) = match (lo, hi) {
        (IpAddr::V4(x), IpAddr::V4(y)) => (
            u128::from(u32::from(x)),
            u128::from(u32::from(y)),
            IpFamily::V4,
        ),
        (IpAddr::V6(x), IpAddr::V6(y)) => (u128::from(x), u128::from(y), IpFamily::V6),
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    if a <= b {
        cover(a, b, fam, &mut out);
    }
    out
}

fn cover(mut a: u128, b: u128, fam: IpFamily, out: &mut Vec<IpNet>) {
    let bits: u32 = match fam {
        IpFamily::V4 => 32,
        IpFamily::V6 => 128,
    };
    // `a` is aligned to 2^size, so the block end never overflows
    let end = |a: u128, size: u32| {
        if size >= 128 {
            u128::MAX
        } else {
            a + ((1u128 << size) - 1)
        }
    };
    loop {
        let mut size = if a == 0 {
            bits
        } else {
            a.trailing_zeros().min(bits)
        };
        while size > 0 && end(a, size) > b {
            size -= 1;
        }
        out.push(make_net(a, (bits - size) as u8, fam));
        let e = end(a, size);
        if e >= b {
            break;
        }
        a = e + 1;
    }
}

fn make_net(a: u128, len: u8, fam: IpFamily) -> IpNet {
    match fam {
        IpFamily::V4 => IpNet::new(IpAddr::V4(Ipv4Addr::from(a as u32)), len).expect("valid len"),
        IpFamily::V6 => IpNet::new(IpAddr::V6(Ipv6Addr::from(a)), len).expect("valid len"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn e(s: &str) -> TableEntry {
        let (neg, s) = match s.strip_prefix('!') {
            Some(r) => (true, r),
            None => (false, s),
        };
        TableEntry {
            net: s.parse().unwrap(),
            negate: neg,
        }
    }

    #[test]
    fn longest_prefix_wins() {
        let s = AddrSet::from_entries([e("10.0.0.0/8"), e("!10.1.0.0/16"), e("10.1.2.0/24")]);
        assert!(s.contains("10.9.0.1".parse().unwrap()));
        assert!(!s.contains("10.1.9.1".parse().unwrap()));
        assert!(s.contains("10.1.2.5".parse().unwrap()));
        let nets: Vec<String> = s.to_nets().iter().map(|n| n.to_string()).collect();
        assert!(nets.contains(&"10.1.2.0/24".to_string()), "{nets:?}");
        assert!(!nets.iter().any(|n| n == "10.0.0.0/8"));
    }

    #[test]
    fn summarize_matches_python() {
        let v: Vec<String> = summarize(
            "192.168.1.10".parse().unwrap(),
            "192.168.1.20".parse().unwrap(),
        )
        .iter()
        .map(|n| n.to_string())
        .collect();
        // ipaddress.summarize_address_range(192.168.1.10, 192.168.1.20)
        assert_eq!(
            v,
            [
                "192.168.1.10/31",
                "192.168.1.12/30",
                "192.168.1.16/30",
                "192.168.1.20/32"
            ]
        );
        assert_eq!(
            summarize(
                "0.0.0.0".parse().unwrap(),
                "255.255.255.255".parse().unwrap()
            )[0]
            .to_string(),
            "0.0.0.0/0"
        );
        assert_eq!(
            summarize(
                "::".parse().unwrap(),
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
            )[0]
            .to_string(),
            "::/0"
        );
    }

    proptest! {
        /// The CIDR cover contains exactly the addresses of the evaluated set.
        #[test]
        fn prop_cover_is_exact(
            entries in proptest::collection::vec((0u8..4, 0u8..255, 22u8..=32, any::<bool>()), 0..12),
            probes in proptest::collection::vec((0u8..4, any::<u8>(), any::<u8>()), 40),
        ) {
            let es: Vec<TableEntry> = entries.iter().map(|&(b, c, len, neg)| TableEntry {
                net: IpNet::new(IpAddr::V4(Ipv4Addr::new(10, b, c, 0)), len).unwrap().trunc(),
                negate: neg,
            }).collect();
            let set = AddrSet::from_entries(es.clone());
            let nets = set.to_nets();
            for (b, c, d) in probes {
                let ip = IpAddr::V4(Ipv4Addr::new(10, b, c, d));
                // reference: longest matching prefix decides
                let best = es.iter().filter(|e| e.net.contains(&ip)).max_by_key(|e| (e.net.prefix_len(), e.negate));
                let want = best.is_some_and(|e| !e.negate);
                prop_assert_eq!(set.contains(ip), want);
                prop_assert_eq!(nets.iter().any(|n| n.contains(&ip)), want);
            }
        }
    }
}
