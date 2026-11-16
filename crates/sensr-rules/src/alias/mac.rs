//! MAC aliases (`ArpCache`): the addresses the neighbour table currently
//! holds for a MAC address or MAC prefix.

use std::net::IpAddr;

/// Addresses whose MAC starts with `pattern` (case-insensitive).
pub fn lookup(neighbours: &[(String, IpAddr)], pattern: &str) -> Vec<IpAddr> {
    let p = pattern.to_ascii_lowercase();
    neighbours
        .iter()
        .filter(|(mac, _)| mac.to_ascii_lowercase().starts_with(&p))
        .map(|(_, ip)| *ip)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neighbour_table_lookup_t0325() {
        let table = vec![
            (
                "02:00:5e:10:00:01".to_owned(),
                "192.168.1.20".parse().unwrap(),
            ),
            (
                "02:00:5e:10:00:01".to_owned(),
                "fd00:1::20".parse().unwrap(),
            ),
            (
                "aa:bb:cc:00:00:02".to_owned(),
                "192.168.1.21".parse().unwrap(),
            ),
        ];
        assert_eq!(lookup(&table, "02:00:5E:10:00:01").len(), 2);
        assert_eq!(lookup(&table, "aa:bb:cc").len(), 1);
        assert!(lookup(&table, "de:ad").is_empty());
    }
}
