//! TCP/UDP ports (OPNsense counterpart: `PortField`).

use std::fmt;
use std::num::NonZeroU16;
use std::str::FromStr;

use super::names::AliasName;
use super::string_serde;
use super::well_known;
use crate::validation::FieldError;

/// A port number 1..=65535. Parses digits or a well-known service name
/// (`https` → 443, case-insensitive); always displays the number, so
/// renderers never see names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Port(NonZeroU16);

impl Port {
    /// A port from a number; `None` for 0.
    pub const fn new(n: u16) -> Option<Self> {
        match NonZeroU16::new(n) {
            Some(p) => Some(Self(p)),
            None => None,
        }
    }

    /// The port number.
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl FromStr for Port {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err =
            || FieldError::syntax("Please specify a valid port number (1-65535) or service name.");
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            return s.parse::<u16>().ok().and_then(Self::new).ok_or_else(err);
        }
        well_known::service_port(s)
            .and_then(Self::new)
            .ok_or_else(err)
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
string_serde!(Port);

/// An inclusive port range, `start <= end`. Displays `start-end`, or just the
/// port when both ends are equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortRange {
    start: Port,
    end: Port,
}

impl PortRange {
    /// Builds a range; rejects `start > end`.
    pub fn new(start: Port, end: Port) -> Result<Self, FieldError> {
        if start <= end {
            Ok(Self { start, end })
        } else {
            Err(FieldError::callback(
                "The start of a port range must not be after its end.",
            ))
        }
    }

    /// First port.
    pub fn start(&self) -> Port {
        self.start
    }

    /// Last port.
    pub fn end(&self) -> Port {
        self.end
    }

    /// True for a single-port range.
    pub fn is_single(&self) -> bool {
        self.start == self.end
    }

    /// Number of ports covered.
    pub fn len(&self) -> u32 {
        u32::from(self.end.get()) - u32::from(self.start.get()) + 1
    }

    /// Never empty; present for clippy's `len_without_is_empty`.
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl From<Port> for PortRange {
    fn from(p: Port) -> Self {
        Self { start: p, end: p }
    }
}

impl FromStr for PortRange {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // `:` is pf's range separator and appears in imported configs.
        match s.split_once(['-', ':']) {
            // Service names can contain `-` (`ftp-data`); try the whole string
            // as a single port first.
            Some(_) if s.parse::<Port>().is_ok() => s.parse::<Port>().map(Self::from),
            Some((a, b)) => Self::new(a.parse()?, b.parse()?),
            None => s.parse::<Port>().map(Self::from),
        }
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_single() {
            self.start.fmt(f)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}
string_serde!(PortRange);

/// The port operand of a rule: a port, a range or a port alias. "Any port"
/// is the absence of a `PortSpec` (`Option::None`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PortSpec {
    /// One port or a range.
    Range(PortRange),
    /// A port alias, written `alias:<name>`.
    Alias(AliasName),
}

impl PortSpec {
    /// A single port.
    pub fn port(p: Port) -> Self {
        Self::Range(p.into())
    }
}

impl FromStr for PortSpec {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.strip_prefix("alias:") {
            Some(name) => name.parse().map(Self::Alias),
            None => s.parse().map(Self::Range),
        }
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Range(r) => r.fmt(f),
            Self::Alias(a) => write!(f, "alias:{a}"),
        }
    }
}
string_serde!(PortSpec);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ports_and_names() {
        assert_eq!("80".parse::<Port>().unwrap().get(), 80);
        assert_eq!("HTTPS".parse::<Port>().unwrap().get(), 443);
        for bad in ["", "0", "65536", "x1", " 80", "80 ", "8 0", "+80", "-1"] {
            assert!(bad.parse::<Port>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ranges() {
        let r: PortRange = "80-100".parse().unwrap();
        assert_eq!((r.start().get(), r.end().get(), r.len()), (80, 100, 21));
        assert_eq!(
            "1000:2000".parse::<PortRange>().unwrap().to_string(),
            "1000-2000"
        );
        assert_eq!("ftp-data".parse::<PortRange>().unwrap().to_string(), "20");
        assert_eq!(
            "http-https".parse::<PortRange>().unwrap().to_string(),
            "80-443"
        );
        assert!("100-80".parse::<PortRange>().is_err());
        assert!("999999-88888888".parse::<PortRange>().is_err());
        assert_eq!("443-443".parse::<PortRange>().unwrap().to_string(), "443");
    }

    #[test]
    fn spec() {
        assert_eq!(
            "alias:web".parse::<PortSpec>().unwrap().to_string(),
            "alias:web"
        );
        assert_eq!(
            "22".parse::<PortSpec>().unwrap(),
            PortSpec::port(Port::new(22).unwrap())
        );
        assert!("alias:1x".parse::<PortSpec>().is_err());
    }
}
