//! Validation results: what went wrong, and where in the document.
//!
//! OPNsense reports model errors as a flat map from dotted field reference
//! (`general.FromEmail`, `aliases.alias.<uuid>.name`) to messages, and its
//! test harness asserts on the *kind* of validator that fired. Both shapes are
//! kept here so the compat API can reproduce the envelope and parity tests can
//! assert the kind.

use std::fmt;

use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// The class of check that rejected a value.
///
/// Mirrors the validator class names OPNsense's field tests assert on, so a
/// parity test written as "throws `MinMaxValidator`" becomes
/// `ValidatorKind::MinMax`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorKind {
    /// A required value is missing or empty.
    PresenceOf,
    /// The value does not match the field's syntax.
    Regex,
    /// A semantic check failed (unknown option, dangling reference, ...).
    Callback,
    /// A number is outside its allowed range.
    MinMax,
    /// The value is not an integer.
    Integer,
    /// The value is not a decimal number.
    Numericality,
    /// A cross-field or cross-item constraint failed.
    Constraint,
}

/// A single rejected value: the kind of check and a user-facing message.
///
/// Messages follow OPNsense's style: a full sentence, capitalised, ending
/// with a period (lint rules T-0361/T-0362).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[error("{message}")]
pub struct FieldError {
    /// Which class of check failed.
    pub kind: ValidatorKind,
    /// Human-readable explanation.
    pub message: String,
}

impl FieldError {
    /// Builds an error of the given kind.
    pub fn new(kind: ValidatorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// Syntax error (`Regex` kind).
    pub fn syntax(message: impl Into<String>) -> Self {
        Self::new(ValidatorKind::Regex, message)
    }

    /// Semantic error (`Callback` kind).
    pub fn callback(message: impl Into<String>) -> Self {
        Self::new(ValidatorKind::Callback, message)
    }

    /// Range error (`MinMax` kind).
    pub fn range(message: impl Into<String>) -> Self {
        Self::new(ValidatorKind::MinMax, message)
    }

    /// Missing-value error (`PresenceOf` kind).
    pub fn required() -> Self {
        Self::new(ValidatorKind::PresenceOf, messages::REQUIRED)
    }
}

/// Messages shared by several field types.
pub mod messages {
    /// Empty value in a required field (OPNsense's default `PresenceOf` text).
    pub const REQUIRED: &str = "A value is required.";
    /// A reference to an interface that is not configured.
    pub const UNKNOWN_INTERFACE: &str = "The interface does not exist.";
    /// A reference to an alias that is not configured.
    pub const UNKNOWN_ALIAS: &str = "The alias does not exist.";
    /// A UUID reference to an item that does not exist.
    pub const RELATION_NOT_FOUND: &str = "Related item not found.";
}

/// A dotted path into the document, e.g. `firewall.rules.<uuid>.source.net`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FieldPath(String);

impl FieldPath {
    /// The document root.
    pub fn root() -> Self {
        Self(String::new())
    }

    /// Appends one segment.
    #[must_use]
    pub fn join(&self, segment: impl fmt::Display) -> Self {
        if self.0.is_empty() {
            Self(segment.to_string())
        } else {
            Self(format!("{}.{segment}", self.0))
        }
    }

    /// The path as a dotted string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Iterates the path's segments.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('.').filter(|s| !s.is_empty())
    }
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for FieldPath {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// All validation failures of a document or model, keyed by dotted path in
/// the order they were found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Validations(IndexMap<FieldPath, Vec<FieldError>>);

impl Validations {
    /// No failures yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a failure at `path`.
    pub fn push(&mut self, path: FieldPath, error: FieldError) {
        self.0.entry(path).or_default().push(error);
    }

    /// Records a failure of `kind` with `message` at `path`.
    pub fn add(&mut self, path: &FieldPath, kind: ValidatorKind, message: impl Into<String>) {
        self.push(path.clone(), FieldError::new(kind, message));
    }

    /// True when nothing failed.
    pub fn is_ok(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of paths with at least one failure.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when nothing failed.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Failures recorded for one path.
    pub fn get(&self, path: &str) -> Option<&[FieldError]> {
        self.0.get(&FieldPath::from(path)).map(Vec::as_slice)
    }

    /// Iterates `(path, errors)` in discovery order.
    pub fn iter(&self) -> impl Iterator<Item = (&FieldPath, &[FieldError])> {
        self.0.iter().map(|(p, e)| (p, e.as_slice()))
    }

    /// Every message, flattened, as `path: message` lines (for CLI output).
    pub fn to_lines(&self) -> Vec<String> {
        self.0
            .iter()
            .flat_map(|(p, errs)| errs.iter().map(move |e| format!("{p}: {}", e.message)))
            .collect()
    }

    /// Converts to `Err(self)` when anything failed.
    pub fn into_result(self) -> Result<(), Self> {
        if self.is_ok() { Ok(()) } else { Err(self) }
    }

    /// Merges another set of failures into this one.
    pub fn extend(&mut self, other: Validations) {
        for (p, errs) in other.0 {
            self.0.entry(p).or_default().extend(errs);
        }
    }
}

impl fmt::Display for Validations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for line in self.to_lines() {
            writeln!(f, "{line}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Validations {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_join_with_dots() {
        let p = FieldPath::root().join("firewall").join("rules").join("x");
        assert_eq!(p.as_str(), "firewall.rules.x");
        assert_eq!(p.segments().collect::<Vec<_>>(), ["firewall", "rules", "x"]);
    }

    #[test]
    fn validations_group_by_path_in_order() {
        let mut v = Validations::new();
        v.add(&"b".into(), ValidatorKind::Regex, "B.");
        v.add(&"a".into(), ValidatorKind::Regex, "A.");
        v.add(&"b".into(), ValidatorKind::MinMax, "B2.");
        assert_eq!(v.len(), 2);
        assert_eq!(v.get("b").unwrap().len(), 2);
        assert_eq!(v.to_lines(), ["b: B.", "b: B2.", "a: A."]);
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.starts_with(r#"{"b":"#), "{json}");
    }
}
