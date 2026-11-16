//! AS-number databases for BGP ASN aliases. Understood: iptoasn.com's
//! `ip2asn` TSV (`first last asn country description`, public domain under
//! PDDL 1.0, the default source) and upstream's `network asn` lines. As with
//! countries, only the AS numbers an alias uses are stored (`AS<n>` files).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::PathBuf;

use ipnet::IpNet;
use sensr_rules::alias::ipset;

use crate::cache::write_atomic;
use crate::geo::read_nets;

/// Default ASN source (iptoasn.com, PDDL 1.0).
pub const IPTOASN_URL: &str = "https://iptoasn.com/data/ip2asn-combined.tsv.gz";

/// Parses a database body, keeping `wanted` AS numbers (all when `None`).
pub fn parse(text: &str, wanted: Option<&BTreeSet<u32>>) -> BTreeMap<u32, Vec<IpNet>> {
    let mut out: BTreeMap<u32, Vec<IpNet>> = BTreeMap::new();
    let keep = |a: u32| a != 0 && wanted.is_none_or(|w| w.contains(&a));
    for line in text.lines() {
        let f: Vec<&str> = if line.contains('\t') {
            line.split('\t').collect()
        } else {
            line.split(|c: char| c == ',' || c.is_whitespace())
                .filter(|p| !p.is_empty())
                .collect()
        };
        match f.as_slice() {
            // ip2asn: first, last, asn, …
            [lo, hi, asn, ..] if lo.parse::<IpAddr>().is_ok() => {
                let (Ok(lo), Ok(hi), Ok(asn)) = (
                    lo.parse::<IpAddr>(),
                    hi.parse::<IpAddr>(),
                    asn.trim_start_matches("AS").parse::<u32>(),
                ) else {
                    continue;
                };
                if keep(asn) && lo.is_ipv4() == hi.is_ipv4() && lo <= hi {
                    out.entry(asn).or_default().extend(ipset::summarize(lo, hi));
                }
            }
            // upstream: network asn
            [net, asn] => {
                let (Ok(net), Ok(asn)) = (
                    net.parse::<IpNet>(),
                    asn.trim_start_matches("AS").parse::<u32>(),
                ) else {
                    continue;
                };
                if keep(asn) {
                    out.entry(asn).or_default().push(net.trunc());
                }
            }
            _ => {}
        }
    }
    out
}

/// Per-AS files.
#[derive(Clone, Debug)]
pub struct AsnStore {
    dir: PathBuf,
}

impl AsnStore {
    /// Files under `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> AsnStore {
        AsnStore { dir: dir.into() }
    }

    fn path(&self, asn: u32) -> PathBuf {
        self.dir.join(format!("AS{asn}"))
    }

    /// True if `asn` was stored.
    pub fn has(&self, asn: u32) -> bool {
        self.path(asn).exists()
    }

    /// Replaces the files of `asns` (unknown ones stored empty).
    pub fn store(
        &self,
        asns: &BTreeSet<u32>,
        db: &BTreeMap<u32, Vec<IpNet>>,
    ) -> std::io::Result<usize> {
        let mut total = 0;
        for a in asns {
            let v = db.get(a).map(Vec::as_slice).unwrap_or(&[]);
            total += v.len();
            let text: String = v.iter().map(|n| format!("{n}\n")).collect();
            write_atomic(&self.path(*a), text.as_bytes())?;
        }
        Ok(total)
    }

    /// Networks of `asn`.
    pub fn lookup(&self, asn: u32) -> Vec<IpNet> {
        read_nets(&self.path(asn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip2asn_rows_and_network_lines() {
        let tsv = "198.51.100.0\t198.51.100.255\t64500\tZZ\tEXAMPLE-NET\n\
                   2001:db8::\t2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\t64500\tZZ\tEXAMPLE-NET\n\
                   203.0.113.0\t203.0.113.255\t0\tNone\tNot routed\n\
                   192.0.2.0\t192.0.2.255\t64501\tZZ\tOTHER\n";
        let w: BTreeSet<u32> = [64500].into();
        let db = parse(tsv, Some(&w));
        assert_eq!(db[&64500].len(), 2);
        assert!(!db.contains_key(&64501) && !db.contains_key(&0));
        let db = parse("198.51.100.0/24 64502\n192.0.2.0/25,64502\n", None);
        assert_eq!(db[&64502].len(), 2);
    }

    #[test]
    fn store_round_trip() {
        let d = tempfile::tempdir().unwrap();
        let s = AsnStore::new(d.path());
        let db = parse("198.51.100.0/24 64502\n", None);
        s.store(&[64502, 64999].into(), &db).unwrap();
        assert_eq!(s.lookup(64502).len(), 1);
        assert!(s.has(64999) && s.lookup(64999).is_empty());
    }
}
