//! BGP AS → networks (`BGPASN`): upstream's `asn.csv` (`network,asn` per
//! line, from the `asn.gz` "network asn" list).

use std::collections::BTreeMap;

use ipnet::IpNet;

/// Parses `network,asn` or `network asn` lines.
pub fn parse(db: &str) -> BTreeMap<u32, Vec<IpNet>> {
    let mut out: BTreeMap<u32, Vec<IpNet>> = BTreeMap::new();
    for line in db.lines() {
        let parts: Vec<&str> = line
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|p| !p.is_empty())
            .collect();
        if let [net, asn] = parts[..]
            && let (Ok(net), Ok(asn)) = (net.parse::<IpNet>(), asn.parse::<u32>())
        {
            out.entry(asn).or_default().push(net);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as13335_from_fixture_t0326() {
        let db = parse(include_str!("../../tests/fixtures/asn/asn.csv"));
        let v = &db[&13335];
        assert_eq!(v.len(), 5);
        assert_eq!(v.iter().filter(|n| matches!(n, IpNet::V6(_))).count(), 2);
        assert!(!db.contains_key(&64512));
    }
}
