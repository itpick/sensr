//! Host and domain names (OPNsense counterpart: `HostnameField`).

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use super::string_serde;
use crate::validation::FieldError;

const MAX_LABEL: usize = 63;
const MAX_NAME: usize = 253;

/// Checks one DNS label. `underscore` admits `_` (service labels such as
/// `_sip._tcp`), which RFC 1123 host names forbid.
fn valid_label(label: &str, underscore: bool) -> bool {
    let ok = |c: char| c.is_ascii_alphanumeric() || (underscore && c == '_');
    !label.is_empty()
        && label.len() <= MAX_LABEL
        && label.chars().all(|c| ok(c) || c == '-')
        && label.chars().next().is_some_and(ok)
        && label.chars().last().is_some_and(ok)
}

fn valid_name(name: &str, underscore: bool) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name.split('.').all(|l| valid_label(l, underscore))
}

/// A single host label, e.g. the firewall's own `hostname` (`OPNsense`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hostname(String);

impl Hostname {
    /// The label as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Hostname {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if valid_label(s, false) {
            Ok(Self(s.to_owned()))
        } else {
            Err(FieldError::syntax(
                "A host name may only contain letters, digits and hyphens, must not start or end with a hyphen and is at most 63 characters.",
            ))
        }
    }
}

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
string_serde!(Hostname);

/// A domain name of one or more labels without a trailing dot, e.g.
/// `internal` or `home.example.org`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DomainName(String);

impl DomainName {
    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True when `self` equals `other` or is a subdomain of it.
    pub fn is_within(&self, other: &DomainName) -> bool {
        let (a, b) = (self.0.to_ascii_lowercase(), other.0.to_ascii_lowercase());
        a == b || a.ends_with(&format!(".{b}"))
    }
}

impl FromStr for DomainName {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if valid_name(s, false) {
            Ok(Self(s.to_owned()))
        } else {
            Err(FieldError::syntax("A valid domain must be specified."))
        }
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
string_serde!(DomainName);

/// A DNS name as blocklists and allowlists hold them: like [`DomainName`],
/// but labels may contain underscores (`_dmarc.example.com`), and it is
/// kept lower-case.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ListedName(String);

impl ListedName {
    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ListedName {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_suffix('.').unwrap_or(s);
        if valid_name(s, true) {
            Ok(Self(s.to_ascii_lowercase()))
        } else {
            Err(FieldError::syntax("A valid domain must be specified."))
        }
    }
}

impl fmt::Display for ListedName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
string_serde!(ListedName);

/// An IP address or a DNS name, e.g. a WireGuard endpoint or an NTP server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    /// A literal address.
    Ip(IpAddr),
    /// A name resolved at apply time.
    Name(DomainName),
}

impl FromStr for Host {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(ip) = s.parse() {
            return Ok(Self::Ip(ip));
        }
        // An all-numeric dotted string that failed to parse as IPv4 is a typo'd
        // address, not a name; refuse it rather than resolving "192.168.1.300".
        if s.split('.')
            .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(FieldError::syntax(
                "Please specify a valid address or host name.",
            ));
        }
        s.parse()
            .map(Self::Name)
            .map_err(|_| FieldError::syntax("Please specify a valid address or host name."))
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(ip) => ip.fmt(f),
            Self::Name(n) => n.fmt(f),
        }
    }
}
string_serde!(Host);

/// The host part of a DNS host override (OPNsense Unbound `hosts.host.hostname`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HostOverrideName {
    /// Empty: the record is for the domain itself.
    Apex,
    /// `*`: every name under the domain.
    Wildcard,
    /// A DNS name (underscores allowed), relative to the domain.
    Name(String),
}

impl FromStr for HostOverrideName {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "" => Ok(Self::Apex),
            "*" => Ok(Self::Wildcard),
            _ if valid_name(s, true) && s.parse::<IpAddr>().is_err() => {
                Ok(Self::Name(s.to_owned()))
            }
            _ => Err(FieldError::syntax("A valid hostname must be specified.")),
        }
    }
}

impl fmt::Display for HostOverrideName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Apex => Ok(()),
            Self::Wildcard => f.write_str("*"),
            Self::Name(n) => f.write_str(n),
        }
    }
}
string_serde!(HostOverrideName);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_is_one_label() {
        assert!("OPNsense".parse::<Hostname>().is_ok());
        assert!("fw-01".parse::<Hostname>().is_ok());
        for bad in ["", "-a", "a-", "a.b", "a_b", &"a".repeat(64)] {
            assert!(bad.parse::<Hostname>().is_err(), "{bad}");
        }
    }

    #[test]
    fn domain_names() {
        assert!("internal".parse::<DomainName>().is_ok());
        assert!("home.example.org".parse::<DomainName>().is_ok());
        for bad in ["", ".", "a..b", "a.", "a b", "_x.org"] {
            assert!(bad.parse::<DomainName>().is_err(), "{bad}");
        }
        let d: DomainName = "lan.Example.org".parse().unwrap();
        assert!(d.is_within(&"example.org".parse().unwrap()));
        assert!(!d.is_within(&"ample.org".parse().unwrap()));
    }

    #[test]
    fn host_prefers_ip_and_rejects_bad_dotted_quads() {
        assert_eq!(
            "10.0.0.1".parse::<Host>().unwrap(),
            Host::Ip("10.0.0.1".parse().unwrap())
        );
        assert!(matches!(
            "vpn.example.org".parse::<Host>().unwrap(),
            Host::Name(_)
        ));
        assert!("192.168.1.300".parse::<Host>().is_err());
        assert_eq!("::1".parse::<Host>().unwrap().to_string(), "::1");
    }

    #[test]
    fn host_override_names() {
        assert_eq!(
            "".parse::<HostOverrideName>().unwrap(),
            HostOverrideName::Apex
        );
        assert_eq!(
            "*".parse::<HostOverrideName>().unwrap(),
            HostOverrideName::Wildcard
        );
        assert!("_sip._tcp".parse::<HostOverrideName>().is_ok());
        assert!("10.0.0.1".parse::<HostOverrideName>().is_err());
        assert!("a b".parse::<HostOverrideName>().is_err());
    }
}
