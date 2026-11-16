//! IP protocol numbers and their names.
//!
//! OPNsense offers every `/etc/protocols` entry with a non-zero number as a
//! rule protocol (`get_protocols()`), spelled the FreeBSD way (`carp`, not
//! Linux's `vrrp`). The table is IANA's registry as shipped by FreeBSD/macOS;
//! it is data, so names imported from `config.xml` keep resolving.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// `(name, number)` in protocol-number order.
pub const PROTOCOLS: &[(&str, u8)] = &[
    ("icmp", 1),
    ("igmp", 2),
    ("ggp", 3),
    ("ipencap", 4),
    ("st2", 5),
    ("tcp", 6),
    ("cbt", 7),
    ("egp", 8),
    ("igp", 9),
    ("bbn-rcc", 10),
    ("nvp", 11),
    ("pup", 12),
    ("argus", 13),
    ("emcon", 14),
    ("xnet", 15),
    ("chaos", 16),
    ("udp", 17),
    ("mux", 18),
    ("dcn", 19),
    ("hmp", 20),
    ("prm", 21),
    ("xns-idp", 22),
    ("trunk-1", 23),
    ("trunk-2", 24),
    ("leaf-1", 25),
    ("leaf-2", 26),
    ("rdp", 27),
    ("irtp", 28),
    ("iso-tp4", 29),
    ("netblt", 30),
    ("mfe-nsp", 31),
    ("merit-inp", 32),
    ("dccp", 33),
    ("3pc", 34),
    ("idpr", 35),
    ("xtp", 36),
    ("ddp", 37),
    ("idpr-cmtp", 38),
    ("tp++", 39),
    ("il", 40),
    ("ipv6", 41),
    ("sdrp", 42),
    ("ipv6-route", 43),
    ("ipv6-frag", 44),
    ("idrp", 45),
    ("rsvp", 46),
    ("gre", 47),
    ("dsr", 48),
    ("bna", 49),
    ("esp", 50),
    ("ah", 51),
    ("i-nlsp", 52),
    ("swipe", 53),
    ("narp", 54),
    ("mobile", 55),
    ("tlsp", 56),
    ("skip", 57),
    ("ipv6-icmp", 58),
    ("ipv6-nonxt", 59),
    ("ipv6-opts", 60),
    ("cftp", 62),
    ("sat-expak", 64),
    ("kryptolan", 65),
    ("rvd", 66),
    ("ippc", 67),
    ("sat-mon", 69),
    ("visa", 70),
    ("ipcv", 71),
    ("cpnx", 72),
    ("cphb", 73),
    ("wsn", 74),
    ("pvp", 75),
    ("br-sat-mon", 76),
    ("sun-nd", 77),
    ("wb-mon", 78),
    ("wb-expak", 79),
    ("iso-ip", 80),
    ("vmtp", 81),
    ("secure-vmtp", 82),
    ("vines", 83),
    ("ttp", 84),
    ("nsfnet-igp", 85),
    ("dgp", 86),
    ("tcf", 87),
    ("eigrp", 88),
    ("ospf", 89),
    ("sprite-rpc", 90),
    ("larp", 91),
    ("mtp", 92),
    ("ax.25", 93),
    ("ipip", 94),
    ("micp", 95),
    ("scc-sp", 96),
    ("etherip", 97),
    ("encap", 98),
    ("gmtp", 100),
    ("ifmp", 101),
    ("pnni", 102),
    ("pim", 103),
    ("aris", 104),
    ("scps", 105),
    ("qnx", 106),
    ("a/n", 107),
    ("ipcomp", 108),
    ("snp", 109),
    ("compaq-peer", 110),
    ("ipx-in-ip", 111),
    ("carp", 112),
    ("pgm", 113),
    ("l2tp", 115),
    ("ddx", 116),
    ("iatp", 117),
    ("stp", 118),
    ("srp", 119),
    ("uti", 120),
    ("smp", 121),
    ("sm", 122),
    ("ptp", 123),
    ("isis", 124),
    ("fire", 125),
    ("crtp", 126),
    ("crudp", 127),
    ("sscopmce", 128),
    ("iplt", 129),
    ("sps", 130),
    ("pipe", 131),
    ("sctp", 132),
    ("fc", 133),
    ("rsvp-e2e-ignore", 134),
    ("mobility-header", 135),
    ("udplite", 136),
    ("mpls-in-ip", 137),
    ("manet", 138),
    ("hip", 139),
    ("shim6", 140),
    ("wesp", 141),
    ("rohc", 142),
    ("pfsync", 240),
];

/// One IP protocol, remembering whether the config spelled it by number so
/// the pf oracle can print it back the same way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Protocol {
    /// IANA protocol number.
    pub number: u8,
    /// `true` when written as a number (`41`), not a name (`ipv6`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub numeric: bool,
}

impl Protocol {
    /// TCP
    pub const TCP: Protocol = Protocol::named(6);
    /// UDP
    pub const UDP: Protocol = Protocol::named(17);
    /// ICMP (IPv4)
    pub const ICMP: Protocol = Protocol::named(1);
    /// ICMPv6
    pub const ICMP6: Protocol = Protocol::named(58);
    /// CARP / VRRP
    pub const CARP: Protocol = Protocol::named(112);

    /// A protocol spelled by its name.
    pub const fn named(number: u8) -> Protocol {
        Protocol {
            number,
            numeric: false,
        }
    }

    /// The registry name, when the number has one.
    pub fn name(self) -> Option<&'static str> {
        PROTOCOLS
            .iter()
            .find(|(_, n)| *n == self.number)
            .map(|(s, _)| *s)
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.numeric, self.name()) {
            (false, Some(name)) => f.write_str(name),
            _ => write!(f, "{}", self.number),
        }
    }
}

/// A protocol name or number that is not in the registry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown protocol {0:?}")]
pub struct UnknownProtocol(pub String);

impl FromStr for Protocol {
    type Err = UnknownProtocol;

    /// Case-insensitive name, or a decimal number 1–255.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.trim().to_ascii_lowercase();
        if let Ok(n) = lower.parse::<u8>()
            && n > 0
        {
            return Ok(Protocol {
                number: n,
                numeric: true,
            });
        }
        PROTOCOLS
            .iter()
            .find(|(name, _)| *name == lower)
            .map(|(_, n)| Protocol::named(*n))
            .ok_or_else(|| UnknownProtocol(s.to_owned()))
    }
}

/// What a rule matches at layer 4.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtoMatch {
    /// No protocol restriction.
    #[default]
    Any,
    /// Exactly one protocol.
    One(Protocol),
    /// OPNsense's `TCP/UDP` choice.
    TcpUdp,
}

impl ProtoMatch {
    /// `true` when ports may be matched (TCP, UDP or both).
    pub fn has_ports(self) -> bool {
        match self {
            ProtoMatch::TcpUdp => true,
            ProtoMatch::One(p) => matches!(p.number, 6 | 17 | 33 | 132 | 136),
            ProtoMatch::Any => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_numbers() {
        assert_eq!("TCP".parse::<Protocol>().unwrap(), Protocol::TCP);
        assert_eq!("a/n".parse::<Protocol>().unwrap().number, 107);
        assert_eq!("skip".parse::<Protocol>().unwrap().number, 57);
        let p: Protocol = "41".parse().unwrap();
        assert_eq!((p.number, p.to_string()), (41, "41".to_string()));
        assert_eq!(Protocol::named(41).to_string(), "ipv6");
        assert!("0".parse::<Protocol>().is_err());
        assert!("bogus".parse::<Protocol>().is_err());
    }

    #[test]
    fn table_is_sorted_and_unique() {
        assert!(PROTOCOLS.windows(2).all(|w| w[0].1 < w[1].1));
    }
}
