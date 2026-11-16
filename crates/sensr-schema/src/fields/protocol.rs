//! IP protocol selector of a rule (OPNsense counterpart: `ProtocolField`).

use std::fmt;
use std::str::FromStr;

use super::string_serde;
use super::well_known::{PROTOCOLS, protocol_number};
use crate::validation::FieldError;

const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP: u8 = 1;
const ICMPV6: u8 = 58;

/// The protocol a rule matches. The common cases are variants so renderers
/// can match on them; everything else is [`Protocol::Other`] with its IANA
/// number. Parsing is case-insensitive (`TCP`, `tcp`), accepts names and
/// numbers, and normalises `6` to [`Protocol::Tcp`] and so on; display is
/// lower-case.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Protocol {
    /// Any protocol.
    #[default]
    Any,
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// TCP or UDP (`tcp/udp`).
    TcpUdp,
    /// ICMP (IPv4).
    Icmp,
    /// ICMPv6 (`ipv6-icmp`).
    Icmpv6,
    /// Any other protocol by number; never 1, 6, 17 or 58.
    Other(u8),
}

impl Protocol {
    /// The protocol for an IANA number.
    pub fn from_number(n: u8) -> Self {
        match n {
            TCP => Self::Tcp,
            UDP => Self::Udp,
            ICMP => Self::Icmp,
            ICMPV6 => Self::Icmpv6,
            n => Self::Other(n),
        }
    }

    /// True if the protocol carries ports (port operands are only valid then).
    pub fn has_ports(self) -> bool {
        matches!(self, Self::Tcp | Self::Udp | Self::TcpUdp) || self == Self::Other(132)
    }
}

impl FromStr for Protocol {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.to_ascii_lowercase();
        match lower.as_str() {
            "any" => return Ok(Self::Any),
            "tcp/udp" => return Ok(Self::TcpUdp),
            "icmpv6" => return Ok(Self::Icmpv6),
            _ => {}
        }
        if !lower.is_empty() && lower.bytes().all(|b| b.is_ascii_digit()) {
            return lower
                .parse::<u8>()
                .map(Self::from_number)
                .map_err(|_| FieldError::syntax("A protocol number must be between 0 and 255."));
        }
        protocol_number(&lower)
            .map(Self::from_number)
            .ok_or_else(|| FieldError::callback(format!("{s} is not a known protocol.")))
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("any"),
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
            Self::TcpUdp => f.write_str("tcp/udp"),
            Self::Icmp => f.write_str("icmp"),
            Self::Icmpv6 => f.write_str("ipv6-icmp"),
            Self::Other(n) => match PROTOCOLS.iter().find(|(_, num)| num == n) {
                Some((name, _)) => f.write_str(name),
                None => n.fmt(f),
            },
        }
    }
}
string_serde!(Protocol);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_display() {
        assert_eq!("TCP".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("6".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("TCP/UDP".parse::<Protocol>().unwrap(), Protocol::TcpUdp);
        assert_eq!("ipv6-icmp".parse::<Protocol>().unwrap(), Protocol::Icmpv6);
        assert_eq!("gre".parse::<Protocol>().unwrap(), Protocol::Other(47));
        assert_eq!(Protocol::Other(47).to_string(), "gre");
        assert_eq!(Protocol::Other(253).to_string(), "253");
        assert_eq!("vrrp".parse::<Protocol>().unwrap().to_string(), "carp");
        for bad in ["", "XX", "256", "tcp udp"] {
            assert!(bad.parse::<Protocol>().is_err(), "{bad}");
        }
    }

    #[test]
    fn ports() {
        assert!(Protocol::TcpUdp.has_ports());
        assert!(!Protocol::Icmp.has_ports());
        assert!("sctp".parse::<Protocol>().unwrap().has_ports());
    }
}
