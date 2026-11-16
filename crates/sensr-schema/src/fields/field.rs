//! The configurable field layer (OPNsense counterpart: `BaseField` and the
//! option setters model XMLs use: `Required`, `Default`, `Mask`,
//! `ChangeCase`, `ValidationMessage`, `Multiple`, ...).
//!
//! The typed newtypes in [`crate::fields`] are what the document stores.
//! [`Field<T>`] is for the places that see raw text first, with
//! per-instance options: the importer reading `config.xml`, the compat API
//! validating a POST body, generated UI forms. It reproduces OPNsense's
//! semantics exactly (an empty optional value is valid; validators run only on
//! a set value; the reported kinds match), which is what the parity tests pin.

use std::fmt;

use regex::{Regex, RegexBuilder};

use crate::validation::{FieldError, ValidatorKind};

/// Case folding applied when a value is set (`ChangeCase`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeCase {
    /// Upper-case on set.
    Upper,
    /// Lower-case on set.
    Lower,
}

impl ChangeCase {
    /// Applies the folding.
    pub fn apply(self, s: &str) -> String {
        match self {
            Self::Upper => s.to_uppercase(),
            Self::Lower => s.to_lowercase(),
        }
    }
}

/// A `Mask`: a PCRE-style `/pattern/flags` regular expression that a value
/// must match in full (OPNsense's `Regex` validator compares the first match
/// with the whole value).
#[derive(Clone)]
pub struct Mask {
    source: String,
    re: Regex,
}

impl fmt::Debug for Mask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mask({})", self.source)
    }
}

impl PartialEq for Mask {
    fn eq(&self, other: &Self) -> bool {
        self.source == other.source
    }
}

impl Mask {
    /// Parses `/pattern/flags` (flags `i`, `m`, `s`, `x`, `u`; `u` is the
    /// default here). A pattern without delimiters is taken as is.
    pub fn new(source: &str) -> Result<Self, regex::Error> {
        let src = source.trim();
        let (pattern, flags) = match src.chars().next() {
            Some(d) if !d.is_alphanumeric() && d != '\\' && src.len() > 1 => {
                match src[1..].rfind(d) {
                    Some(end) => (&src[1..=end], &src[end + 2..]),
                    None => (src, ""),
                }
            }
            _ => (src, ""),
        };
        let re = RegexBuilder::new(pattern)
            .case_insensitive(flags.contains('i'))
            .multi_line(flags.contains('m'))
            .dot_matches_new_line(flags.contains('s'))
            .ignore_whitespace(flags.contains('x'))
            .build()?;
        Ok(Self {
            source: source.to_owned(),
            re,
        })
    }

    /// True if the first match is the whole value.
    pub fn matches(&self, value: &str) -> bool {
        self.re.find(value).is_some_and(|m| m.as_str() == value)
    }

    /// The pattern as written.
    pub fn source(&self) -> &str {
        &self.source
    }
}

/// What a field kind may consult while validating.
#[derive(Debug, Clone, Copy)]
pub struct Ctx<'a> {
    /// The field is required.
    pub required: bool,
    /// The model's `ValidationMessage` override.
    pub message: Option<&'a str>,
}

impl Ctx<'_> {
    /// The message to report: the override if set, else `default`. A single
    /// `%s` is replaced by `content` (OPNsense `getValidationMessage`).
    pub fn msg(&self, default: &str, content: &str) -> String {
        let m = self.message.unwrap_or(default);
        if m.matches("%s").count() == 1 {
            m.replacen("%s", content, 1)
        } else {
            m.to_owned()
        }
    }

    /// An error of `kind` with the override or `default` message.
    pub fn err(&self, kind: ValidatorKind, default: &str) -> FieldError {
        FieldError::new(kind, self.msg(default, ""))
    }
}

/// The behaviour of one OPNsense field type.
pub trait FieldType {
    /// Validates a non-empty value (presence is handled by [`Field`]).
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError>;

    /// Rewrites a value as it is set (after [`ChangeCase`]); e.g. port names
    /// are lower-cased.
    fn on_set(&self, value: String) -> String {
        value
    }

    /// The case folding a type applies unless configured otherwise
    /// (`ProtocolField` upper-cases).
    fn default_change_case(&self) -> Option<ChangeCase> {
        None
    }

    /// The individual values held (empty for an unset field).
    fn values(&self, value: &str) -> Vec<String> {
        if value.is_empty() {
            Vec::new()
        } else {
            vec![value.to_owned()]
        }
    }

    /// Joins values for `set_values`; single-valued types keep the first.
    fn join(&self, values: &[&str]) -> String {
        values.first().map(|s| (*s).to_owned()).unwrap_or_default()
    }

    /// True for list-shaped types (`isList()`).
    fn is_list(&self) -> bool {
        false
    }

    /// The value a field of this type starts with.
    fn initial(&self) -> &'static str {
        ""
    }

    /// Normalises the value so it can pass validation (OPNsense
    /// `normalizeValue`): option lists drop unknown entries.
    fn normalize(&self, value: &str, _required: bool) -> String {
        value.to_owned()
    }

    /// Setting an empty value keeps the current one (write-only fields).
    fn keeps_value_on_empty(&self) -> bool {
        false
    }

    /// The value is never displayed (`Display` prints nothing).
    fn write_only(&self) -> bool {
        false
    }
}

/// A configured field of kind `T` holding a raw text value.
#[derive(Debug, Clone)]
pub struct Field<T> {
    /// The type and its options.
    pub kind: T,
    required: bool,
    change_case: Option<ChangeCase>,
    is_virtual: bool,
    message: Option<String>,
    value: String,
    default: String,
}

impl<T: FieldType> Field<T> {
    /// A field with the type's initial value, optional, not virtual.
    pub fn new(kind: T) -> Self {
        let init = kind.initial().to_owned();
        let change_case = kind.default_change_case();
        Self {
            kind,
            required: false,
            change_case,
            is_virtual: false,
            message: None,
            value: init.clone(),
            default: init,
        }
    }

    /// Marks the field required (builder form).
    #[must_use]
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Sets `Required`.
    pub fn set_required(&mut self, required: bool) {
        self.required = required;
    }

    /// True if the field is required.
    pub fn is_required(&self) -> bool {
        self.required
    }

    /// Sets `ChangeCase`.
    pub fn set_change_case(&mut self, case: ChangeCase) {
        self.change_case = Some(case);
    }

    /// Sets the `ValidationMessage` override.
    pub fn set_message(&mut self, message: impl Into<String>) {
        self.message = Some(message.into());
    }

    /// Marks the field virtual (a template node, never stored).
    pub fn set_virtual(&mut self) {
        self.is_virtual = true;
    }

    /// True if virtual.
    pub fn is_virtual(&self) -> bool {
        self.is_virtual
    }

    /// Fields are never containers; containers are model structs.
    pub fn is_container(&self) -> bool {
        false
    }

    /// Fields are never array types; arrays are [`crate::ArrayField`].
    pub fn is_array_type(&self) -> bool {
        false
    }

    /// True for list-shaped types.
    pub fn is_list(&self) -> bool {
        self.kind.is_list()
    }

    /// Sets the value (applying change case and the type's set hook).
    pub fn set_value(&mut self, value: impl fmt::Display) {
        let mut v = value.to_string();
        if v.is_empty() && self.kind.keeps_value_on_empty() {
            return;
        }
        if let Some(c) = self.change_case
            && !v.is_empty()
        {
            v = c.apply(&v);
        }
        self.value = self.kind.on_set(v);
    }

    /// Sets from several values; empty strings are dropped by list types.
    pub fn set_values<S: fmt::Display>(&mut self, values: &[S]) {
        let owned: Vec<String> = values.iter().map(ToString::to_string).collect();
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        let joined = self.kind.join(&refs);
        self.set_value(joined);
    }

    /// The stored text.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// The individual values.
    pub fn values(&self) -> Vec<String> {
        self.kind.values(&self.value)
    }

    /// Number of values (`count()`).
    pub fn count(&self) -> usize {
        self.values().len()
    }

    /// True when the text is non-empty.
    pub fn is_set(&self) -> bool {
        !self.value.is_empty()
    }

    /// PHP `empty()`: unset or `"0"`.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty() || self.value == "0"
    }

    /// True if the text equals `s`.
    pub fn is_equal(&self, s: &str) -> bool {
        self.value == s
    }

    /// Sets the default and the current value to `value`.
    pub fn set_default(&mut self, value: impl Into<String>) {
        self.default = value.into();
        self.value.clone_from(&self.default);
    }

    /// The default.
    pub fn default_value(&self) -> &str {
        &self.default
    }

    /// True if the value equals the default.
    pub fn is_default(&self) -> bool {
        self.value == self.default
    }

    /// Resets the value to the default.
    pub fn apply_default(&mut self) {
        self.value.clone_from(&self.default);
    }

    /// Applies the type's normalisation (OPNsense `normalizeValue`).
    pub fn normalize_value(&mut self) {
        self.value = self.kind.normalize(&self.value, self.required);
    }

    /// Every failure, in validator order. An unset optional field is valid;
    /// an unset required one fails with `PresenceOf` only.
    pub fn validate(&self) -> Vec<FieldError> {
        let ctx = Ctx {
            required: self.required,
            message: self.message.as_deref(),
        };
        if self.value.is_empty() {
            return if self.required {
                vec![FieldError::required()]
            } else {
                Vec::new()
            };
        }
        self.kind.check(&self.value, &ctx)
    }
}

impl<T: FieldType> fmt::Display for Field<T> {
    /// The value, except for write-only types, which display nothing.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.kind.write_only() {
            Ok(())
        } else {
            f.write_str(&self.value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        let m = Mask::new("/^[a-z]{8}$/").unwrap();
        assert!(m.matches("abcdefgh"));
        assert!(!m.matches("4bcd3fgh"));
        let m = Mask::new("/[^o,]+/").unwrap();
        assert!(m.matches("bar"));
        assert!(!m.matches("foo"), "first match must be the whole value");
        let m = Mask::new("/^[a-z]+$/i").unwrap();
        assert!(m.matches("ABC"));
        let m = Mask::new("#^a/b$#").unwrap();
        assert!(m.matches("a/b"));
        assert!(Mask::new("/(/").is_err());
    }

    /// `getDefault` / `isDefault` / `applyDefault` / `setDefault`.
    #[test]
    fn default_semantics_t0026() {
        use crate::fields::TextField;
        let mut f = Field::new(TextField::default());
        f.set_default("sample@example.com");
        assert_eq!(f.default_value(), "sample@example.com");
        assert_eq!(
            f.value(),
            "sample@example.com",
            "setDefault also sets the value"
        );
        assert!(f.is_default());
        f.set_value("other@example.com");
        assert!(!f.is_default());
        f.apply_default();
        assert!(f.is_default());
        assert_eq!(f.value(), "sample@example.com");
    }

    #[test]
    fn message_substitution() {
        let ctx = Ctx {
            required: false,
            message: Some("Option [%s] not in list."),
        };
        assert_eq!(ctx.msg("x", "o9"), "Option [o9] not in list.");
        let ctx = Ctx {
            required: false,
            message: None,
        };
        assert_eq!(ctx.msg("Plain.", "o9"), "Plain.");
    }
}
