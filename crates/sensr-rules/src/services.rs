//! Service names accepted where OPNsense accepts a port name
//! (`getservbyname()` / `PortField::getWellKnown`).
//!
//! Only TCP/UDP services that appear in firewall configs in practice; an
//! unknown name disables the rule with a debug note, as upstream does.

/// `(name, port)`, sorted by name.
const SERVICES: &[(&str, u16)] = &[
    ("bgp", 179),
    ("cvsup", 5999),
    ("dns", 53),
    ("domain", 53),
    ("ftp", 21),
    ("ftp-data", 20),
    ("http", 80),
    ("http-alt", 8080),
    ("https", 443),
    ("imap", 143),
    ("imaps", 993),
    ("ipsec-msft", 4500),
    ("isakmp", 500),
    ("kerberos", 88),
    ("l2tp", 1701),
    ("ldap", 389),
    ("ldaps", 636),
    ("mms", 1755),
    ("ms-sql-s", 1433),
    ("ms-wbt-server", 3389),
    ("msnp", 1863),
    ("mysql", 3306),
    ("nntp", 119),
    ("ntp", 123),
    ("openvpn", 1194),
    ("pop3", 110),
    ("pop3s", 995),
    ("pptp", 1723),
    ("radius", 1812),
    ("radius-acct", 1813),
    ("sip", 5060),
    ("smtp", 25),
    ("smtps", 465),
    ("snmp", 161),
    ("snmptrap", 162),
    ("ssh", 22),
    ("submission", 587),
    ("syslog", 514),
    ("telnet", 23),
    ("tftp", 69),
    ("wireguard", 51820),
];

/// Port number of a service name (case-insensitive).
pub fn port_of(name: &str) -> Option<u16> {
    let lower = name.to_ascii_lowercase();
    SERVICES
        .binary_search_by(|(n, _)| n.cmp(&lower.as_str()))
        .ok()
        .map(|i| SERVICES[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorted_lookup() {
        assert!(SERVICES.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(port_of("HTTPS"), Some(443));
        assert_eq!(port_of("nope"), None);
    }
}
