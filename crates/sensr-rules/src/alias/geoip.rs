//! GeoIP databases (`GEOIP.process_zip`): MaxMind-style CSVs — a locations
//! file mapping `geoname_id` to a country code, and per-family block files
//! mapping networks to `geoname_id` — split into per-country network lists.

use std::collections::BTreeMap;

use ipnet::IpNet;

use crate::ir::IpFamily;

/// `(country, family)` → networks.
pub type CountryNets = BTreeMap<(String, IpFamily), Vec<IpNet>>;

/// Processes one database. Unknown ids and unparsable networks are skipped,
/// as upstream does.
pub fn process(locations_csv: &str, blocks: &[(IpFamily, &str)]) -> CountryNets {
    let mut codes: BTreeMap<&str, &str> = BTreeMap::new();
    for line in locations_csv.lines() {
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() > 4 && !parts[0].is_empty() && parts[0].bytes().all(|b| b.is_ascii_digit()) {
            if parts[4].len() == 2 && parts[4].chars().all(|c| c.is_ascii_alphanumeric()) {
                codes.insert(parts[0], parts[4]);
            } else if parts[2] == "EU" {
                codes.insert(parts[0], parts[2]);
            }
        }
    }
    let mut out = CountryNets::new();
    for (fam, csv) in blocks {
        for line in csv.lines() {
            let mut parts = line.split(',');
            let (Some(net), Some(id)) = (parts.next(), parts.next()) else {
                continue;
            };
            let (Some(cc), Ok(net)) = (codes.get(id), net.parse::<IpNet>()) else {
                continue;
            };
            out.entry(((*cc).to_owned(), *fam)).or_default().push(net);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nl_from_fixture_db_t0324() {
        let db = process(
            include_str!("../../tests/fixtures/geoip/locations-en.csv"),
            &[
                (
                    IpFamily::V4,
                    include_str!("../../tests/fixtures/geoip/blocks-ipv4.csv"),
                ),
                (
                    IpFamily::V6,
                    include_str!("../../tests/fixtures/geoip/blocks-ipv6.csv"),
                ),
            ],
        );
        assert_eq!(db[&("NL".to_owned(), IpFamily::V4)].len(), 4);
        assert_eq!(db[&("NL".to_owned(), IpFamily::V6)].len(), 2);
        assert_eq!(db[&("EU".to_owned(), IpFamily::V4)].len(), 1);
        assert!(!db.contains_key(&("ZZ".to_owned(), IpFamily::V4)));
    }
}
