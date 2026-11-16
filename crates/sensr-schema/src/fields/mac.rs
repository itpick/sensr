//! MAC addresses (OPNsense counterpart: `MacAddressField`).

use std::fmt;
use std::str::FromStr;

use super::string_serde;
use crate::validation::FieldError;

/// A 48-bit Ethernet address. Accepts `:` or `-` separated hex pairs in any
/// case; displays lower-case with colons (the form Linux tools print).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// The six octets.
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// True for a multicast (group) address, which cannot be a NIC address.
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 1 == 1
    }

    /// True for a locally administered address (the kind used for spoofing).
    pub fn is_local(&self) -> bool {
        self.0[0] & 2 == 2
    }
}

impl FromStr for MacAddr {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || FieldError::syntax("Please enter a valid MAC address.");
        let sep = if s.contains('-') { '-' } else { ':' };
        let mut out = [0u8; 6];
        let mut parts = s.split(sep);
        for byte in &mut out {
            let p = parts.next().ok_or_else(err)?;
            if p.len() != 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(err());
            }
            *byte = u8::from_str_radix(p, 16).map_err(|_| err())?;
        }
        if parts.next().is_some() {
            return Err(err());
        }
        Ok(Self(out))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}
string_serde!(MacAddr);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_separators_and_normalises() {
        let m: MacAddr = "00:1A:2b:3c:4D:5e".parse().unwrap();
        assert_eq!(m.to_string(), "00:1a:2b:3c:4d:5e");
        assert_eq!("00-1a-2b-3c-4d-5e".parse::<MacAddr>().unwrap(), m);
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "",
            "00:1a:2b:3c:4d",
            "00:1a:2b:3c:4d:5e:6f",
            "0:1a:2b:3c:4d:5e",
            "00:1a-2b:3c:4d:5e",
            "gg:1a:2b:3c:4d:5e",
            "+0:1a:2b:3c:4d:5e",
        ] {
            assert!(bad.parse::<MacAddr>().is_err(), "{bad}");
        }
    }

    #[test]
    fn flags() {
        assert!(
            "01:00:5e:00:00:01"
                .parse::<MacAddr>()
                .unwrap()
                .is_multicast()
        );
        assert!("02:00:00:00:00:01".parse::<MacAddr>().unwrap().is_local());
    }
}
