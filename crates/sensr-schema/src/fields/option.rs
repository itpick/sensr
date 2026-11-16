//! Option lists (OPNsense `BaseListField`, `OptionField`, `CountryField`).

use indexmap::IndexMap;

use super::countries::COUNTRIES;
use super::field::{Ctx, FieldType};
use crate::validation::{FieldError, ValidatorKind};

const NOT_IN_LIST: &str = "Option [%s] not in list.";

/// One entry of an option payload as the compat API returns it
/// (`{"value": label, "selected": 0|1}`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OptionEntry {
    /// Display text.
    pub value: String,
    /// Whether the field's value includes this key.
    pub selected: bool,
}

/// Shared behaviour of list fields over a key → label table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OptionList {
    /// Keys and display labels, in display order.
    pub options: IndexMap<String, String>,
    /// `Multiple`: comma-separated keys.
    pub multiple: bool,
    /// `BlankDesc`: label of the empty choice (default `None`).
    pub blank_desc: Option<String>,
}

impl OptionList {
    /// A list from `(key, label)` pairs; an empty label shows the key.
    pub fn new<K: Into<String>, L: Into<String>>(
        options: impl IntoIterator<Item = (K, L)>,
    ) -> Self {
        Self {
            options: options
                .into_iter()
                .map(|(k, l)| {
                    let k = k.into();
                    let l = l.into();
                    let l = if l.is_empty() { k.clone() } else { l };
                    (k, l)
                })
                .collect(),
            multiple: false,
            blank_desc: None,
        }
    }

    /// Multi-select (builder form).
    #[must_use]
    pub fn multiple(mut self) -> Self {
        self.multiple = true;
        self
    }

    /// Validates `value` against `has` (the key test).
    pub(crate) fn check_with(
        &self,
        value: &str,
        ctx: &Ctx<'_>,
        has: impl Fn(&str) -> bool,
    ) -> Vec<FieldError> {
        check_items(self.multiple, value, ctx, NOT_IN_LIST, has)
    }

    /// The option payload for `value`: a blank entry first for optional
    /// single selects, then every option with its selection state.
    pub fn payload(&self, value: &str, required: bool) -> IndexMap<String, OptionEntry> {
        let selected: Vec<&str> = value.split(',').collect();
        let mut out = IndexMap::new();
        if !required && !self.multiple {
            out.insert(
                String::new(),
                OptionEntry {
                    value: self.blank_desc.clone().unwrap_or_else(|| "None".into()),
                    selected: value.is_empty(),
                },
            );
        }
        for (k, label) in &self.options {
            out.insert(
                k.clone(),
                OptionEntry {
                    value: label.clone(),
                    selected: selected.contains(&k.as_str()),
                },
            );
        }
        out
    }

    /// Keeps only known keys, in option order (OPNsense `normalizeValue`).
    pub fn normalize(&self, value: &str, required: bool) -> String {
        self.payload(value, required)
            .into_iter()
            .filter(|(_, e)| e.selected)
            .map(|(k, _)| k)
            .filter(|k| !k.is_empty())
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Validates one key, or each comma-separated key when `multiple`, with
/// `has`; one `Callback` failure per unknown key.
pub(crate) fn check_items(
    multiple: bool,
    value: &str,
    ctx: &Ctx<'_>,
    default_msg: &str,
    has: impl Fn(&str) -> bool,
) -> Vec<FieldError> {
    if multiple {
        value
            .split(',')
            .filter(|item| !has(item))
            .map(|item| FieldError::new(ValidatorKind::Callback, ctx.msg(default_msg, item)))
            .collect()
    } else if has(value) {
        Vec::new()
    } else {
        vec![FieldError::new(
            ValidatorKind::Callback,
            ctx.msg(default_msg, value),
        )]
    }
}

/// Comma-separated values, empty items dropped.
pub(crate) fn csv_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Joins non-empty values with commas.
pub(crate) fn csv_join(values: &[&str]) -> String {
    values
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(",")
}

/// A fixed option list (`OptionField`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OptionField(pub OptionList);

impl FieldType for OptionField {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        self.0
            .check_with(value, ctx, |k| self.0.options.contains_key(k))
    }

    fn values(&self, value: &str) -> Vec<String> {
        csv_values(value)
    }

    fn join(&self, values: &[&str]) -> String {
        csv_join(values)
    }

    fn normalize(&self, value: &str, required: bool) -> String {
        self.0.normalize(value, required)
    }
}

/// Country codes, optionally with `!XX` inverted entries (`CountryField`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CountryField {
    /// `Multiple`.
    pub multiple: bool,
    /// `AddInverted`: also accept `!NL` ("not NL").
    pub add_inverted: bool,
}

impl CountryField {
    fn has(&self, key: &str) -> bool {
        let code = match key.strip_prefix('!') {
            Some(c) if self.add_inverted => c,
            Some(_) => return false,
            None => key,
        };
        super::countries::is_country(code)
    }

    /// The option list (names; inverted entries labelled `(not)`).
    pub fn options(&self) -> OptionList {
        let mut list = OptionList::new(COUNTRIES.iter().map(|(c, n)| (*c, *n)));
        if self.add_inverted {
            for (c, n) in COUNTRIES {
                list.options.insert(format!("!{c}"), format!("{n} (not)"));
            }
        }
        list.multiple = self.multiple;
        list
    }
}

impl FieldType for CountryField {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        let list = OptionList {
            multiple: self.multiple,
            ..OptionList::default()
        };
        list.check_with(value, ctx, |k| self.has(k))
    }

    fn values(&self, value: &str) -> Vec<String> {
        csv_values(value)
    }

    fn join(&self, values: &[&str]) -> String {
        csv_join(values)
    }

    fn normalize(&self, value: &str, required: bool) -> String {
        self.options().normalize(value, required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::field::Field;
    use crate::testing::{validate, validate_err};
    use crate::validation::ValidatorKind::*;

    fn o12() -> OptionList {
        OptionList::new([("o1", "option1"), ("o2", "option2")])
    }

    mod option {
        use super::*;

        #[test]
        fn constructs_t0223() {
            let _ = Field::new(OptionField::default());
        }

        #[test]
        fn required_empty_t0224() {
            let mut f = Field::new(OptionField(o12())).required();
            f.set_value("");
            assert_eq!(validate_err(&f), Err(PresenceOf));
        }

        #[test]
        fn required_set_t0225() {
            let mut f = Field::new(OptionField(o12())).required();
            f.set_value("o1");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn valid_t0226() {
            let mut f = Field::new(OptionField(o12()));
            for v in ["o1", "o2"] {
                f.set_value(v);
                assert!(validate(&f).is_empty());
            }
        }

        #[test]
        fn invalid_t0227() {
            let mut f = Field::new(OptionField(o12()));
            for v in ["x1", "x2"] {
                f.set_value(v);
                assert!(!validate(&f).is_empty());
            }
            assert_eq!(f.validate()[0].message, "Option [x2] not in list.");
        }

        #[test]
        fn normalize_drops_unknown_t0228() {
            let mut f = Field::new(OptionField(OptionList::new([
                ("", "option0"),
                ("o1", "option1"),
                ("o2", "option2"),
            ])));
            assert_eq!(f.count(), 0);
            f.set_value("x1");
            assert_eq!(f.count(), 1);
            assert!(!validate(&f).is_empty());
            f.normalize_value();
            assert_eq!(f.count(), 0);
            assert!(validate(&f).is_empty());
            f.set_value("o1,o2,x2");
            assert_eq!(f.count(), 3);
            assert!(!validate(&f).is_empty());
            f.normalize_value();
            assert_eq!(f.count(), 2);
            assert!(!validate(&f).is_empty(), "two values in a single select");
            f.kind.0.multiple = true;
            f.normalize_value();
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn not_container_t0229() {
            assert!(!Field::new(OptionField::default()).is_container());
        }

        #[test]
        fn payload_shape() {
            let p = o12().payload("o2", false);
            assert_eq!(
                p.keys().map(String::as_str).collect::<Vec<_>>(),
                ["", "o1", "o2"]
            );
            assert_eq!(
                p[""],
                OptionEntry {
                    value: "None".into(),
                    selected: false
                }
            );
            assert!(p["o2"].selected);
            assert!(!o12().payload("", true).contains_key(""));
        }
    }

    mod country {
        use super::*;

        fn field(multiple: bool, add_inverted: bool) -> Field<CountryField> {
            Field::new(CountryField {
                multiple,
                add_inverted,
            })
        }

        #[test]
        fn constructs_t0115() {
            assert_eq!(
                CountryField::default().options().options.len(),
                COUNTRIES.len()
            );
        }

        #[test]
        fn required_empty_t0116() {
            let mut f = field(false, false).required();
            f.set_value("");
            assert_eq!(validate_err(&f), Err(PresenceOf));
        }

        #[test]
        fn required_set_t0117() {
            let mut f = field(false, false).required();
            f.set_value("NL");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn valid_values_t0118() {
            let mut f = field(false, false);
            for v in ["NL", "DE"] {
                f.set_value(v);
                assert!(validate(&f).is_empty());
            }
        }

        #[test]
        fn invalid_values_t0119() {
            let mut f = field(false, false);
            for v in ["XX", "YY"] {
                f.set_value(v);
                assert!(!validate(&f).is_empty());
            }
        }

        #[test]
        fn unknown_rejected_t0120() {
            let mut f = field(true, false);
            f.set_value("NL,DE,ZZ");
            assert_eq!(validate_err(&f), Err(Callback));
        }

        #[test]
        fn known_multi_ok_t0121() {
            let mut f = field(true, false);
            f.set_value("NL,DE");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn inverted_option_t0122() {
            let mut f = field(false, true);
            f.set_value("!NL");
            assert!(validate(&f).is_empty());
            let mut f = field(false, false);
            f.set_value("!NL");
            assert!(!validate(&f).is_empty());
        }

        #[test]
        fn single_rejects_list_t0123() {
            let mut f = field(false, false);
            f.set_value("NL,DE");
            assert_eq!(validate_err(&f), Err(Callback));
        }

        #[test]
        fn not_container_t0124() {
            assert!(!field(false, false).is_container());
        }
    }
}
