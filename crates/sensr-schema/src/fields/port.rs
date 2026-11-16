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

/// Port field options (OPNsense `PortField`): numbers, optionally service
/// names (`EnableWellKnown`), `a-b` ranges (`EnableRanges`) and port aliases
/// (`EnableAlias`, resolved by the caller into `port_aliases`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortField {
    /// Accept `any` and well-known service names.
    pub well_known: bool,
    /// Accept `a-b` ranges with `a < b`.
    pub ranges: bool,
    /// `Multiple`: comma-separated.
    pub multiple: bool,
    /// Names of port aliases that may be used.
    pub port_aliases: Vec<String>,
}

fn port_number(s: &str) -> Option<u16> {
    let ok = !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_digit())
        && !(s.len() > 1 && s.starts_with('0'));
    ok.then(|| s.parse::<u16>().ok())
        .flatten()
        .filter(|n| *n > 0)
}

impl PortField {
    fn is_well_known(item: &str) -> bool {
        item == item.to_ascii_lowercase() && well_known::service_port(item).is_some()
    }

    fn is_option(&self, item: &str) -> bool {
        if port_number(item).is_some() || self.port_aliases.iter().any(|a| a == item) {
            return true;
        }
        if self.well_known && (item == "any" || Self::is_well_known(item)) {
            return true;
        }
        self.ranges
            && item
                .split_once('-')
                .and_then(|(a, b)| Some((port_number(a)?, port_number(b)?)))
                .is_some_and(|(a, b)| a < b)
    }

    /// OPNsense `normalizedPort`: `any` → empty, a service name → its number,
    /// anything else unchanged (lists are not resolved).
    pub fn normalized(&self, value: &str) -> String {
        if value == "any" {
            return String::new();
        }
        if self.port_aliases.iter().any(|a| a == value) {
            return value.to_owned();
        }
        well_known::service_port(value)
            .filter(|_| Self::is_well_known(value))
            .map_or_else(|| value.to_owned(), |p| p.to_string())
    }

    fn message(&self) -> String {
        let mut m = String::from("Please specify a valid port number (1-65535).");
        if self.well_known {
            let names: Vec<&str> = well_known::SERVICES.iter().map(|(n, _)| *n).collect();
            m.push_str(&format!(
                " A service name is also possible ({}).",
                names.join(", ")
            ));
        }
        m
    }
}

impl super::field::FieldType for PortField {
    fn check(&self, value: &str, ctx: &super::field::Ctx<'_>) -> Vec<FieldError> {
        super::option::check_items(self.multiple, value, ctx, &self.message(), |i| {
            self.is_option(i)
        })
    }

    fn on_set(&self, value: String) -> String {
        if self.port_aliases.contains(&value) {
            return value;
        }
        let tmp = value.trim().to_lowercase();
        if self.well_known && (tmp == "any" || Self::is_well_known(&tmp)) {
            tmp
        } else {
            value
        }
    }

    fn values(&self, value: &str) -> Vec<String> {
        super::option::csv_values(value)
    }

    fn join(&self, values: &[&str]) -> String {
        super::option::csv_join(values)
    }
}

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

#[cfg(test)]
mod field_tests {
    use super::*;
    use crate::fields::field::Field;
    use crate::testing::{validate, validate_err};
    use crate::validation::ValidatorKind::*;

    fn field(well_known: bool, ranges: bool, multiple: bool) -> Field<PortField> {
        Field::new(PortField {
            well_known,
            ranges,
            multiple,
            port_aliases: Vec::new(),
        })
    }

    #[test]
    fn constructs_t0230() {
        let _ = field(false, false, false);
    }

    #[test]
    fn required_empty_t0231() {
        let mut f = field(false, false, false).required();
        f.set_value("");
        assert_eq!(validate_err(&f), Err(PresenceOf));
    }

    #[test]
    fn required_set_t0232() {
        let mut f = field(false, false, false).required();
        f.set_value("80");
        assert!(validate(&f).is_empty());
    }

    #[test]
    fn valid_values_t0233() {
        let mut f = field(true, true, false);
        for v in ["80", "443", "https", "80-100"] {
            f.set_value(v);
            assert!(validate(&f).is_empty(), "{v}");
        }
    }

    #[test]
    fn all_well_known_names_t0234() {
        let mut f = field(true, false, false);
        for name in std::iter::once("any").chain(well_known::SERVICES.iter().map(|(n, _)| *n)) {
            f.set_value(name.to_uppercase());
            assert_eq!(f.value(), name);
            assert!(validate(&f).is_empty(), "{name} should be valid");
        }
    }

    #[test]
    fn whitespace_rejected_t0235() {
        let mut f = field(false, true, false);
        for v in [
            "80 ",
            " 80",
            "1024-65535 ",
            " 1024-65535",
            "1024 -65535",
            "1024- 65535",
        ] {
            f.set_value(v);
            assert!(!validate(&f).is_empty(), "{v:?}");
        }
    }

    #[test]
    fn list_ok_t0236() {
        let mut f = field(true, true, true);
        f.set_value("80,443,https,80-100");
        assert!(validate(&f).is_empty());
    }

    #[test]
    fn range_disabled_t0237() {
        let mut f = field(true, false, true);
        f.set_value("80,443,https,80-100");
        assert!(!validate(&f).is_empty());
    }

    #[test]
    fn invalid_values_t0238() {
        let mut f = field(false, false, false);
        for v in ["x1", "x2", "999999-88888888"] {
            f.set_value(v);
            assert!(!validate(&f).is_empty(), "{v}");
        }
    }

    #[test]
    fn not_container_t0239() {
        assert!(!field(false, false, false).is_container());
    }

    #[test]
    fn normalized_port_t0240() {
        let k = PortField::default();
        for (input, want) in [
            ("any", ""),
            ("", ""),
            ("http", "80"),
            ("80", "80"),
            ("xxx", "xxx"),
            ("http,https", "http,https"),
        ] {
            assert_eq!(k.normalized(input), want, "{input}");
        }
    }

    #[test]
    fn port_aliases() {
        let mut f = Field::new(PortField {
            port_aliases: vec!["Web_Ports".into()],
            ..PortField::default()
        });
        f.set_value("Web_Ports");
        assert_eq!(f.value(), "Web_Ports");
        assert!(validate(&f).is_empty());
        assert_eq!(f.kind.normalized("Web_Ports"), "Web_Ports");
    }
}
