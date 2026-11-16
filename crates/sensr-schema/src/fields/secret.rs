//! Values that must not leak into logs or API responses.

use std::cell::Cell;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// What a [`Secret`] serialises as inside [`redacted`].
pub const REDACTED: &str = "*redacted*";

thread_local! {
    static REDACT: Cell<bool> = const { Cell::new(false) };
}

/// Runs `f` with every [`Secret`] serialising as [`REDACTED`], for exports,
/// logs and API responses. Nested calls are fine; the previous mode is
/// restored even if `f` panics.
pub fn redacted<R>(f: impl FnOnce() -> R) -> R {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            REDACT.with(|r| r.set(self.0));
        }
    }
    let _restore = Restore(REDACT.with(|r| r.replace(true)));
    f()
}

/// A secret value (private key, password hash, pre-shared key).
///
/// `Debug` and `Display` redact it. It serialises as the plain value so the
/// store can persist it, except inside [`redacted`] (the `config.json`
/// export, API responses), where it becomes [`REDACTED`]; the API treats
/// these fields as write-only (OPNsense `UpdateOnlyTextField`, PLAN §2.4
/// item 7).
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

impl<T: schemars::JsonSchema> schemars::JsonSchema for Secret<T> {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        format!("Secret_{}", T::schema_name()).into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut s = T::json_schema(generator);
        s.insert("writeOnly".into(), true.into());
        s
    }
}

impl<T: Serialize> Serialize for Secret<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if REDACT.with(Cell::get) {
            s.serialize_str(REDACTED)
        } else {
            self.0.serialize(s)
        }
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
        let json = redacted(|| redacted(|| serde_json::to_string(&s).unwrap()));
        assert_eq!(json, "\"*redacted*\"");
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            "\"hunter2\"",
            "mode restored"
        );
    }
}
