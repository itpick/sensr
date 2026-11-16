//! Small text-shaped fields: URLs, country codes, hex byte strings.

use std::fmt;
use std::str::FromStr;

use super::string_serde;
use crate::validation::FieldError;

/// An `http://` or `https://` URL with a non-empty host and no white space.
/// Syntax only; fetching is the alias resolver's business.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HttpUrl(String);

impl HttpUrl {
    /// The URL text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for HttpUrl {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix("https://")
            .or_else(|| s.strip_prefix("http://"))
            .ok_or_else(|| FieldError::syntax("Please enter a valid http or https URL."))?;
        let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
        if host.is_empty()
            || s.len() > 2048
            || s.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(FieldError::syntax(
                "Please enter a valid http or https URL.",
            ));
        }
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Display for HttpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
string_serde!(HttpUrl);

/// An ISO 3166-1 alpha-2 country code, upper-case (`NL`, `DE`). Parsing
/// accepts any case and checks syntax only, so imported configurations
/// keep codes the GeoIP database may know; [`CountryCode::is_assigned`]
/// and [`super::CountryField`] check the code list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    /// The code as text.
    pub fn as_str(&self) -> &str {
        // Only ASCII upper-case letters are ever stored.
        std::str::from_utf8(&self.0).unwrap_or("??")
    }
}

impl CountryCode {
    /// True for a code in the ISO 3166 table (plus `XK`, Kosovo, which
    /// OPNsense adds because the IANA list lacks it).
    pub fn is_assigned(&self) -> bool {
        super::countries::is_country(self.as_str())
    }
}

impl FromStr for CountryCode {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.as_bytes() {
            [a, b] if a.is_ascii_alphabetic() && b.is_ascii_alphabetic() => {
                Ok(Self([a.to_ascii_uppercase(), b.to_ascii_uppercase()]))
            }
            _ => Err(FieldError::syntax(
                "Please specify a valid two-letter country code.",
            )),
        }
    }
}

impl fmt::Display for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
string_serde!(CountryCode);

/// A non-empty colon-separated hex byte string, e.g. a DHCP client
/// identifier `01:02:f3`. Displays lower-case.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HexBytes(Vec<u8>);

impl HexBytes {
    /// The bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl FromStr for HexBytes {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || {
            FieldError::syntax(
                "Value must be a colon-separated hexadecimal sequence (e.g., 01:02:f3).",
            )
        };
        if s.is_empty() || s.len() > 3 * 255 {
            return Err(err());
        }
        s.split(':')
            .map(|p| {
                if p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()) {
                    u8::from_str_radix(p, 16).map_err(|_| err())
                } else {
                    Err(err())
                }
            })
            .collect::<Result<Vec<u8>, _>>()
            .map(Self)
    }
}

impl fmt::Display for HexBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(":")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
string_serde!(HexBytes);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert!("https://example.org/list.txt".parse::<HttpUrl>().is_ok());
        for bad in [
            "",
            "ftp://x",
            "https://",
            "https:///path",
            "https://a b",
            "example.org",
        ] {
            assert!(bad.parse::<HttpUrl>().is_err(), "{bad}");
        }
    }

    #[test]
    fn countries_and_hex() {
        assert_eq!("nl".parse::<CountryCode>().unwrap().to_string(), "NL");
        assert!("NLD".parse::<CountryCode>().is_err());
        assert!("N1".parse::<CountryCode>().is_err());
        assert!(!"XX".parse::<CountryCode>().unwrap().is_assigned());
        assert!("XK".parse::<CountryCode>().unwrap().is_assigned());
        assert_eq!(
            "01:02:F3".parse::<HexBytes>().unwrap().to_string(),
            "01:02:f3"
        );
        for bad in ["", "1:2", "01::02", "zz", "01:"] {
            assert!(bad.parse::<HexBytes>().is_err(), "{bad}");
        }
    }
}
