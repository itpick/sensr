//! ICMP / ICMPv6 type names: pf's spelling (what OPNsense stores) and the
//! nftables spelling (what we render).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ir::IpFamily;

/// pf `icmp-type` names (pf.conf(5)).
const PF_ICMP4: &[(&str, u8)] = &[
    ("echorep", 0),
    ("unreach", 3),
    ("squench", 4),
    ("redir", 5),
    ("althost", 6),
    ("echoreq", 8),
    ("routeradv", 9),
    ("routersol", 10),
    ("timex", 11),
    ("paramprob", 12),
    ("timereq", 13),
    ("timerep", 14),
    ("inforeq", 15),
    ("inforep", 16),
    ("maskreq", 17),
    ("maskrep", 18),
    ("trace", 30),
    ("dataconv", 31),
    ("mobredir", 32),
    ("ipv6-where", 33),
    ("ipv6-here", 34),
    ("mobregreq", 35),
    ("mobregrep", 36),
    ("skip", 39),
    ("photuris", 40),
];

/// pf `icmp6-type` names (pf.conf(5)); aliases share numbers.
const PF_ICMP6: &[(&str, u8)] = &[
    ("unreach", 1),
    ("toobig", 2),
    ("timex", 3),
    ("paramprob", 4),
    ("echoreq", 128),
    ("echorep", 129),
    ("groupqry", 130),
    ("listqry", 130),
    ("grouprep", 131),
    ("listenrep", 131),
    ("groupterm", 132),
    ("listendone", 132),
    ("routersol", 133),
    ("routeradv", 134),
    ("neighbrsol", 135),
    ("neighbradv", 136),
    ("redir", 137),
    ("routrrenum", 138),
    ("wrureq", 139),
    ("fqdnreq", 139),
    ("niqry", 139),
    ("wrurep", 140),
    ("fqdnrep", 140),
    ("nirep", 140),
    ("mtraceresp", 200),
    ("mtrace", 201),
];

/// nftables `icmp type` keywords.
const NFT_ICMP4: &[(&str, u8)] = &[
    ("echo-reply", 0),
    ("destination-unreachable", 3),
    ("source-quench", 4),
    ("redirect", 5),
    ("echo-request", 8),
    ("router-advertisement", 9),
    ("router-solicitation", 10),
    ("time-exceeded", 11),
    ("parameter-problem", 12),
    ("timestamp-request", 13),
    ("timestamp-reply", 14),
    ("info-request", 15),
    ("info-reply", 16),
    ("address-mask-request", 17),
    ("address-mask-reply", 18),
];

/// nftables `icmpv6 type` keywords.
const NFT_ICMP6: &[(&str, u8)] = &[
    ("destination-unreachable", 1),
    ("packet-too-big", 2),
    ("time-exceeded", 3),
    ("parameter-problem", 4),
    ("echo-request", 128),
    ("echo-reply", 129),
    ("mld-listener-query", 130),
    ("mld-listener-report", 131),
    ("mld-listener-done", 132),
    ("nd-router-solicit", 133),
    ("nd-router-advert", 134),
    ("nd-neighbor-solicit", 135),
    ("nd-neighbor-advert", 136),
    ("nd-redirect", 137),
    ("router-renumbering", 138),
    ("ind-neighbor-solicit", 141),
    ("ind-neighbor-advert", 142),
    ("mld2-listener-report", 143),
];

/// One ICMP type as written in the config: a pf name or a number.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IcmpType {
    /// pf name (`echoreq`), kept verbatim for the pf oracle.
    Name(String),
    /// numeric type
    Number(u8),
}

/// A name that is neither a pf ICMP keyword nor a number.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown {family} ICMP type {name:?}")]
pub struct UnknownIcmpType {
    /// `ICMP` or `ICMPv6`
    pub family: &'static str,
    /// offending token
    pub name: String,
}

impl IcmpType {
    /// Parses one token of an OPNsense `icmptype` / `icmp6type` list.
    pub fn parse(token: &str, family: IpFamily) -> Result<IcmpType, UnknownIcmpType> {
        let t = token.trim();
        if let Ok(n) = t.parse::<u8>() {
            return Ok(IcmpType::Number(n));
        }
        let table = pf_table(family);
        if table.iter().any(|(n, _)| *n == t) {
            Ok(IcmpType::Name(t.to_owned()))
        } else {
            Err(UnknownIcmpType {
                family: family_label(family),
                name: t.to_owned(),
            })
        }
    }

    /// Numeric type for `family`.
    pub fn number(&self, family: IpFamily) -> Option<u8> {
        match self {
            IcmpType::Number(n) => Some(*n),
            IcmpType::Name(name) => pf_table(family)
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| *v),
        }
    }

    /// The nftables keyword for this type, when nft has one.
    pub fn nft_name(&self, family: IpFamily) -> Option<&'static str> {
        let n = self.number(family)?;
        let table = match family {
            IpFamily::V4 => NFT_ICMP4,
            IpFamily::V6 => NFT_ICMP6,
        };
        table.iter().find(|(_, v)| *v == n).map(|(k, _)| *k)
    }
}

impl fmt::Display for IcmpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcmpType::Name(n) => f.write_str(n),
            IcmpType::Number(n) => write!(f, "{n}"),
        }
    }
}

fn pf_table(family: IpFamily) -> &'static [(&'static str, u8)] {
    match family {
        IpFamily::V4 => PF_ICMP4,
        IpFamily::V6 => PF_ICMP6,
    }
}

fn family_label(family: IpFamily) -> &'static str {
    match family {
        IpFamily::V4 => "ICMP",
        IpFamily::V6 => "ICMPv6",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pf_names_resolve() {
        let t = IcmpType::parse("mobregreq", IpFamily::V4).unwrap();
        assert_eq!(t.number(IpFamily::V4), Some(35));
        assert_eq!(t.nft_name(IpFamily::V4), None);
        let t = IcmpType::parse("echoreq", IpFamily::V6).unwrap();
        assert_eq!(t.nft_name(IpFamily::V6), Some("echo-request"));
        assert_eq!(
            IcmpType::parse("135", IpFamily::V6)
                .unwrap()
                .nft_name(IpFamily::V6),
            Some("nd-neighbor-solicit")
        );
        assert!(IcmpType::parse("nope", IpFamily::V4).is_err());
    }
}
