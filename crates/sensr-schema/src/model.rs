//! Model-level traits implemented by `#[derive(SensrModel)]` (OPNsense
//! counterpart: `BaseModel`).

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::array::ArrayField;
use crate::fields::{Field, IntegerField};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldError, FieldPath, Validations};

/// What the model declares about one field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldMeta {
    /// JSON name.
    pub name: &'static str,
    /// `Required`.
    pub required: bool,
    /// `Default`, as text.
    pub default: Option<&'static str>,
    /// `ValidationMessage`.
    pub message: Option<&'static str>,
    /// `BlankDesc`.
    pub blank_desc: Option<&'static str>,
    /// `Multiple`.
    pub multiple: bool,
}

/// A configuration model: metadata, defaults and raw-text validation.
/// Implemented by `#[derive(SensrModel)]`.
pub trait SensrModel: Sized {
    /// One-line description (`<description>`).
    const DESCRIPTION: &'static str;
    /// The model version, if it is versioned on its own.
    const VERSION: Option<crate::SchemaVersion>;

    /// Field metadata in declaration order.
    fn fields() -> &'static [FieldMeta];

    /// The model with every field at its default (OPNsense: a model loaded
    /// from an empty config, T-0022).
    fn defaults() -> Self;

    /// Validates raw text for one field (by JSON name) with the model's
    /// rules and messages, before it is turned into the typed value: what the
    /// compat API does with a POSTed form value.
    fn validate_text(field: &str, text: &str) -> Vec<FieldError>;

    /// Metadata of one field.
    fn field(name: &str) -> Option<&'static FieldMeta> {
        Self::fields().iter().find(|f| f.name == name)
    }
}

/// Collection-wide checks of an item type (uniqueness), run when an
/// [`ArrayField`] of it validates. Implemented by `#[derive(SensrModel)]`.
pub trait SensrItem: Sized {
    /// Reports constraint failures across `items` at `at.<uuid>.<field>`.
    fn validate_collection(items: &ArrayField<Self>, at: &FieldPath, out: &mut Validations);
}

impl<T: Validate + SensrItem> Validate for ArrayField<T> {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        T::validate_collection(self, at, out);
        for (id, item) in self {
            item.validate(ctx, &at.join(id), out);
        }
    }
}

/// An enum's options as `(key, label)` pairs. Implemented by
/// `#[derive(SensrOptions)]`.
pub trait SensrOptions {
    /// Keys (serde names) and display labels, in declaration order.
    fn options() -> &'static [(&'static str, &'static str)];
}

fn from_text<T: DeserializeOwned>(text: &str) -> Result<T, serde_json::Error> {
    serde_json::from_value(Value::String(text.to_owned())).or_else(|e| {
        // Numbers and booleans are not strings in JSON.
        match serde_json::from_str::<Value>(text) {
            Ok(v) if !v.is_string() => serde_json::from_value(v),
            _ => Err(e),
        }
    })
}

/// Parses a `default = ".."` literal. Generated code calls this; a literal
/// that does not fit its field fails the generated defaults test.
pub fn parse_default<T: DeserializeOwned>(text: &str) -> T {
    match from_text(text) {
        Ok(v) => v,
        Err(e) => panic!("sensr default {text:?} does not parse: {e}"),
    }
}

/// Raw-text validation behind [`SensrModel::validate_text`].
pub fn validate_text<T: DeserializeOwned>(
    text: &str,
    required: bool,
    range: Option<(i64, i64)>,
    message: Option<&str>,
) -> Vec<FieldError> {
    if text.is_empty() {
        return if required {
            vec![FieldError::required()]
        } else {
            Vec::new()
        };
    }
    if let Some((min, max)) = range {
        let mut f = Field::new(IntegerField { min, max });
        if let Some(m) = message {
            f.set_message(m);
        }
        f.set_value(text);
        return f.validate();
    }
    match from_text::<T>(text) {
        Ok(_) => Vec::new(),
        Err(_) => vec![FieldError::callback(
            message.unwrap_or("Validation failed."),
        )],
    }
}
