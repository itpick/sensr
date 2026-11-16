//! Separator-delimited lists (OPNsense `CSVListField`).

use super::field::{Ctx, FieldType, Mask};
use crate::validation::{FieldError, ValidatorKind};

/// A delimited list with an optional mask over the whole string or each
/// item (`MaskPerItem`).
#[derive(Debug, Clone, PartialEq)]
pub struct CsvListField {
    /// `Mask`.
    pub mask: Option<Mask>,
    /// `MaskPerItem`: apply the mask to every item instead of the whole
    /// string.
    pub mask_per_item: bool,
    /// `FieldSeparator` (default `,`).
    pub separator: String,
}

impl Default for CsvListField {
    fn default() -> Self {
        Self {
            mask: None,
            mask_per_item: false,
            separator: ",".into(),
        }
    }
}

impl FieldType for CsvListField {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        const MSG: &str = "List validation error.";
        let Some(mask) = &self.mask else {
            return Vec::new();
        };
        if self.mask_per_item {
            if let Some(bad) = value
                .split(self.separator.as_str())
                .find(|i| !mask.matches(i))
            {
                return vec![FieldError::new(
                    ValidatorKind::Callback,
                    format!("\"{bad}\" is invalid. {}", ctx.msg(MSG, bad)),
                )];
            }
        } else if !mask.matches(value) {
            return vec![ctx.err(ValidatorKind::Callback, MSG)];
        }
        Vec::new()
    }

    fn values(&self, value: &str) -> Vec<String> {
        value
            .split(self.separator.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    }

    fn join(&self, values: &[&str]) -> String {
        values
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(&self.separator)
    }

    fn is_list(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::field::Field;
    use crate::testing::validate;

    #[test]
    fn constructs_t0125() {
        let _ = Field::new(CsvListField::default());
    }

    #[test]
    fn is_list_t0126() {
        let f = Field::new(CsvListField::default());
        assert!(!f.is_container());
        assert!(f.is_list());
    }

    #[test]
    fn values_t0127() {
        let mut f = Field::new(CsvListField::default());
        assert!(f.is_empty() && f.is_equal(""));
        assert!(f.values().is_empty());
        f.set_value("foo");
        assert!(!f.is_empty());
        f.set_value("foo,bar");
        assert!(f.is_equal("foo,bar"));
        assert_eq!(f.values(), ["foo", "bar"]);
        f.set_value("foo,,bar");
        assert!(f.is_equal("foo,,bar"), "the text is kept");
        assert_eq!(f.values(), ["foo", "bar"]);
    }

    #[test]
    fn mask_whole_vs_per_item_t0128() {
        let mut f = Field::new(CsvListField::default());
        f.set_value("bar");
        assert!(validate(&f).is_empty());
        f.kind.mask = Some(Mask::new("/[^o,]+/").unwrap());
        assert!(validate(&f).is_empty());
        f.set_value("foo");
        assert!(!validate(&f).is_empty());
        f.set_value("f,bar");
        assert!(!validate(&f).is_empty());
        f.kind.mask_per_item = true;
        assert!(validate(&f).is_empty());
        f.set_value("f,foo");
        assert_eq!(
            f.validate()[0].message,
            "\"foo\" is invalid. List validation error."
        );
    }
}
