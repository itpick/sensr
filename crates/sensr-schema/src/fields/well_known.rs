//! Frozen name tables: well-known service ports and IP protocol numbers.
//!
//! OPNsense resolves these through the host's `/etc/services` and
//! `/etc/protocols`. sensr freezes them so that validation is identical on
//! every build host and inside wasm (the UI validates with the same code).

/// Well-known TCP/UDP service names and their ports (IANA assignments).
/// Sorted by name for binary search.
pub const SERVICES: &[(&str, u16)] = &[
    ("afs3-fileserver", 7000),
    ("amqp", 5672),
    ("amqps", 5671),
    ("aol", 5190),
    ("auth", 113),
    ("avt-profile-1", 5004),
    ("bgp", 179),
    ("bootpc", 68),
    ("bootps", 67),
    ("chargen", 19),
    ("cvspserver", 2401),
    ("cvsup", 5999),
    ("daytime", 13),
    ("dhcpv6-client", 546),
    ("dhcpv6-server", 547),
    ("discard", 9),
    ("domain", 53),
    ("domain-s", 853),
    ("echo", 7),
    ("finger", 79),
    ("ftp", 21),
    ("ftp-data", 20),
    ("ftps", 990),
    ("ftps-data", 989),
    ("git", 9418),
    ("gopher", 70),
    ("hbci", 3000),
    ("http", 80),
    ("http-alt", 8080),
    ("https", 443),
    ("igmpv3lite", 465),
    ("imap", 143),
    ("imaps", 993),
    ("ipp", 631),
    ("ipsec-msft", 10000),
    ("ipsec-nat-t", 4500),
    ("irc", 194),
    ("isakmp", 500),
    ("iscsi-target", 3260),
    ("kerberos", 88),
    ("kpasswd", 464),
    ("l2f", 1701),
    ("l2tp", 1701),
    ("ldap", 389),
    ("ldaps", 636),
    ("mdns", 5353),
    ("microsoft-ds", 445),
    ("ms-sql-s", 1433),
    ("ms-streaming", 1755),
    ("ms-wbt-server", 3389),
    ("msnp", 1863),
    ("mysql", 3306),
    ("nat-stun-port", 3478),
    ("netbios-dgm", 138),
    ("netbios-ns", 137),
    ("netbios-ssn", 139),
    ("nfs", 2049),
    ("nntp", 119),
    ("nntps", 563),
    ("ntp", 123),
    ("openvpn", 1194),
    ("pop3", 110),
    ("pop3s", 995),
    ("postgresql", 5432),
    ("pptp", 1723),
    ("radius", 1812),
    ("radius-acct", 1813),
    ("rfb", 5900),
    ("rsync", 873),
    ("rtsp", 554),
    ("sieve", 4190),
    ("sip", 5060),
    ("sip-tls", 5061),
    ("smtp", 25),
    ("snmp", 161),
    ("snmptrap", 162),
    ("socks", 1080),
    ("ssh", 22),
    ("submission", 587),
    ("submissions", 465),
    ("sunrpc", 111),
    ("svn", 3690),
    ("syslog", 514),
    ("syslog-tls", 6514),
    ("telnet", 23),
    ("teredo", 3544),
    ("tftp", 69),
    ("time", 37),
    ("urd", 465),
    ("whois", 43),
    ("wins", 1512),
    ("x11", 6000),
    ("xmpp-client", 5222),
    ("xmpp-server", 5269),
];

/// IP protocol names and numbers (IANA "Assigned Internet Protocol
/// Numbers", the names used by `/etc/protocols`). Sorted by name.
pub const PROTOCOLS: &[(&str, u8)] = &[
    ("ah", 51),
    ("carp", 112),
    ("dccp", 33),
    ("egp", 8),
    ("eigrp", 88),
    ("encap", 98),
    ("esp", 50),
    ("etherip", 97),
    ("gre", 47),
    ("hip", 139),
    ("icmp", 1),
    ("idrp", 45),
    ("igmp", 2),
    ("igp", 9),
    ("ip", 0),
    ("ipcomp", 108),
    ("ipencap", 4),
    ("ipip", 94),
    ("ipv6", 41),
    ("ipv6-frag", 44),
    ("ipv6-icmp", 58),
    ("ipv6-nonxt", 59),
    ("ipv6-opts", 60),
    ("ipv6-route", 43),
    ("isis", 124),
    ("l2tp", 115),
    ("manet", 138),
    ("mobility-header", 135),
    ("mpls-in-ip", 137),
    ("ospf", 89),
    ("pfsync", 240),
    ("pim", 103),
    ("rdp", 27),
    ("rohc", 142),
    ("rsvp", 46),
    ("sctp", 132),
    ("shim6", 140),
    ("tcp", 6),
    ("udp", 17),
    ("udplite", 136),
    ("vrrp", 112),
    ("wesp", 141),
    ("xtp", 36),
];

/// Port for a well-known service name (case-insensitive).
pub fn service_port(name: &str) -> Option<u16> {
    let name = name.to_ascii_lowercase();
    SERVICES
        .binary_search_by(|(n, _)| (*n).cmp(name.as_str()))
        .ok()
        .map(|i| SERVICES[i].1)
}

/// Protocol number for an IP protocol name (case-insensitive).
pub fn protocol_number(name: &str) -> Option<u8> {
    let name = name.to_ascii_lowercase();
    PROTOCOLS
        .binary_search_by(|(n, _)| (*n).cmp(name.as_str()))
        .ok()
        .map(|i| PROTOCOLS[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_sorted_and_unique() {
        assert!(SERVICES.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(PROTOCOLS.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn lookups_ignore_case() {
        assert_eq!(service_port("HTTPS"), Some(443));
        assert_eq!(protocol_number("TCP"), Some(6));
        assert_eq!(service_port("nope"), None);
    }
}
