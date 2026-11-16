//! Values that must not leak into logs or API responses.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A secret value (private key, password hash, pre-shared key).
///
/// `Debug` and `Display` redact it. It serialises as the plain value so the
/// store can persist it; the store's `config.json` export and the API replace
/// it with a reference (PLAN §2.4 item 7), and the API treats these fields as
/// write-only (OPNsense `UpdateOnlyTextField`).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    /// Wraps a value.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// The secret itself; call sites are the audit trail.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl<T: Serialize> Serialize for Secret<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Secret<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        T::deserialize(d).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_in_debug_and_display() {
        let s = Secret::new("hunter2".to_owned());
        assert_eq!(format!("{s:?} {s}"), "Secret(***) ***");
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"hunter2\"");
        assert_eq!(s.expose(), "hunter2");
    }
}
