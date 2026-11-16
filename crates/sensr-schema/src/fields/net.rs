//! Network-aware fields: address families, address ranges and the
//! "network or alias" operand of firewall and NAT rules (OPNsense
//! counterparts: `NetworkField`, `NetworkAliasField`).

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::names::{AliasName, InterfaceId};
use super::string_serde;
use crate::validation::FieldError;

/// Which IP versions a rule applies to (OPNsense `ipprotocol`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum IpFamily {
    /// IPv4 only (`inet`).
    #[default]
    Inet,
    /// IPv6 only (`inet6`).
    Inet6,
    /// Both (`inet46`).
    Inet46,
}

impl IpFamily {
    /// True if an address of this kind is covered by the family.
    pub fn admits(self, addr: IpAddr) -> bool {
        matches!(
            (self, addr),
            (Self::Inet46, _) | (Self::Inet, IpAddr::V4(_)) | (Self::Inet6, IpAddr::V6(_))
        )
    }
}

/// An inclusive address range `start-end` of one family, `start <= end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressRange {
    start: IpAddr,
    end: IpAddr,
}

impl AddressRange {
    /// Builds a range, rejecting mixed families and reversed bounds.
    pub fn new(start: IpAddr, end: IpAddr) -> Result<Self, FieldError> {
        match (start, end) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) if start <= end => {
                Ok(Self { start, end })
            }
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => Err(
                FieldError::callback("The start of the range must not be after its end."),
            ),
            _ => Err(FieldError::callback(
                "Both ends of a range must be of the same address family.",
            )),
        }
    }

    /// First address.
    pub fn start(&self) -> IpAddr {
        self.start
    }

    /// Last address.
    pub fn end(&self) -> IpAddr {
        self.end
    }

    /// True if `addr` lies within the range.
    pub fn contains(&self, addr: IpAddr) -> bool {
        self.start <= addr && addr <= self.end && self.start.is_ipv4() == addr.is_ipv4()
    }
}

impl FromStr for AddressRange {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (a, b) = s
            .split_once('-')
            .ok_or_else(|| FieldError::syntax("A range must be written as start-end."))?;
        let parse = |x: &str| {
            x.parse::<IpAddr>()
                .map_err(|_| FieldError::syntax("A range must consist of two valid IP addresses."))
        };
        Self::new(parse(a)?, parse(b)?)
    }
}

impl fmt::Display for AddressRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}
string_serde!(AddressRange);

/// The source/destination/target operand of a firewall or NAT rule.
///
/// Text form (unambiguous, unlike OPNsense's where `lan` may be an interface
/// or an alias):
///
/// | text            | meaning                                   | OPNsense         |
/// |-----------------|-------------------------------------------|------------------|
/// | `any`           | anything                                  | `any`            |
/// | `self`          | every address of this firewall            | `(self)`         |
/// | `net:<if>`      | the subnet(s) of an interface             | `lan`            |
/// | `addr:<if>`     | the address(es) of an interface           | `lanip`          |
/// | `alias:<name>`  | a firewall alias                          | `<name>`         |
/// | `10.0.0.0/8`    | a literal network                         | same             |
/// | `10.0.0.1`      | a literal host (stored as a /32 or /128)  | same             |
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub enum NetOrAlias {
    /// Matches everything.
    #[default]
    Any,
    /// The firewall's own addresses.
    This,
    /// The network(s) attached to an interface.
    InterfaceNet(InterfaceId),
    /// The address(es) configured on an interface.
    InterfaceAddr(InterfaceId),
    /// A firewall alias.
    Alias(AliasName),
    /// A literal network or host. Host bits are kept as written.
    Net(IpNet),
}

impl NetOrAlias {
    /// The address family a literal operand pins the rule to, if any.
    pub fn literal_family(&self) -> Option<IpFamily> {
        match self {
            Self::Net(IpNet::V4(_)) => Some(IpFamily::Inet),
            Self::Net(IpNet::V6(_)) => Some(IpFamily::Inet6),
            _ => None,
        }
    }

    /// True for [`NetOrAlias::Any`].
    pub fn is_any(&self) -> bool {
        matches!(self, Self::Any)
    }
}

impl FromStr for NetOrAlias {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "any" => return Ok(Self::Any),
            "self" | "(self)" => return Ok(Self::This),
            _ => {}
        }
        if let Some((kind, rest)) = s.split_once(':')
            && matches!(kind, "net" | "addr" | "alias")
        {
            return match kind {
                "net" => rest.parse().map(Self::InterfaceNet),
                "addr" => rest.parse().map(Self::InterfaceAddr),
                _ => rest.parse().map(Self::Alias),
            };
        }
        if let Ok(net) = s.parse::<IpNet>() {
            return Ok(Self::Net(net));
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self::Net(IpNet::from(ip)));
        }
        Err(FieldError::syntax(format!(
            "{s} is not a valid source IP address or alias."
        )))
    }
}

impl fmt::Display for NetOrAlias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("any"),
            Self::This => f.write_str("self"),
            Self::InterfaceNet(i) => write!(f, "net:{i}"),
            Self::InterfaceAddr(i) => write!(f, "addr:{i}"),
            Self::Alias(a) => write!(f, "alias:{a}"),
            Self::Net(n) if n.prefix_len() == n.max_prefix_len() => n.addr().fmt(f),
            Self::Net(n) => n.fmt(f),
        }
    }
}
string_serde!(NetOrAlias);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_or_alias_forms() {
        let cases = [
            ("any", NetOrAlias::Any),
            ("(self)", NetOrAlias::This),
            ("net:lan", NetOrAlias::InterfaceNet("lan".parse().unwrap())),
            (
                "addr:wan",
                NetOrAlias::InterfaceAddr("wan".parse().unwrap()),
            ),
            (
                "alias:web_servers",
                NetOrAlias::Alias("web_servers".parse().unwrap()),
            ),
            ("10.0.0.0/8", NetOrAlias::Net("10.0.0.0/8".parse().unwrap())),
            ("10.0.0.1", NetOrAlias::Net("10.0.0.1/32".parse().unwrap())),
            (
                "2001:db8::/32",
                NetOrAlias::Net("2001:db8::/32".parse().unwrap()),
            ),
        ];
        for (text, want) in cases {
            assert_eq!(text.parse::<NetOrAlias>().unwrap(), want, "{text}");
        }
        assert_eq!(NetOrAlias::This.to_string(), "self");
        assert_eq!(
            "10.0.0.1".parse::<NetOrAlias>().unwrap().to_string(),
            "10.0.0.1"
        );
        for bad in [
            "",
            "lan",
            "net:",
            "alias:any",
            "192.168.0.999",
            "10.0.0.0/33",
            "net:LAN",
        ] {
            assert!(bad.parse::<NetOrAlias>().is_err(), "{bad}");
        }
    }

    #[test]
    fn ranges() {
        let r: AddressRange = "192.168.1.100-192.168.1.199".parse().unwrap();
        assert!(r.contains("192.168.1.150".parse().unwrap()));
        assert!(!r.contains("192.168.1.200".parse().unwrap()));
        assert!(
            "192.168.1.200-192.168.1.100"
                .parse::<AddressRange>()
                .is_err()
        );
        assert!("192.168.1.1-::1".parse::<AddressRange>().is_err());
        assert_eq!(r.to_string(), "192.168.1.100-192.168.1.199");
    }

    #[test]
    fn family_admits() {
        assert!(IpFamily::Inet.admits("1.2.3.4".parse().unwrap()));
        assert!(!IpFamily::Inet.admits("::1".parse().unwrap()));
        assert!(IpFamily::Inet46.admits("::1".parse().unwrap()));
    }
}
