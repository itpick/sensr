//! Numeric fields (OPNsense `BooleanField`, `IntegerField`, `NumericField`,
//! `AutoNumberField`) and the PHP number predicates their validators use.

use super::field::{Ctx, FieldType};
use crate::validation::{FieldError, ValidatorKind};

/// PHP `is_numeric`: optional surrounding white space, sign, digits with an
/// optional fraction (or a bare fraction) and an optional exponent.
pub(crate) fn php_is_numeric(s: &str) -> bool {
    let t = s.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c'));
    let t = t.strip_prefix(['+', '-']).unwrap_or(t);
    let (mantissa, exp) = match t.find(['e', 'E']) {
        Some(i) => (&t[..i], Some(&t[i + 1..])),
        None => (t, None),
    };
    let (int, frac) = match mantissa.split_once('.') {
        Some((a, b)) => (a, Some(b)),
        None => (mantissa, None),
    };
    let digits = |x: &str| x.bytes().all(|b| b.is_ascii_digit());
    let mantissa_ok = match frac {
        Some(f) => digits(int) && digits(f) && !(int.is_empty() && f.is_empty()),
        None => !int.is_empty() && digits(int),
    };
    let exp_ok = exp.is_none_or(|e| {
        let e = e.strip_prefix(['+', '-']).unwrap_or(e);
        !e.is_empty() && digits(e)
    });
    mantissa_ok && exp_ok
}

/// PHP `filter_var(.., FILTER_VALIDATE_INT)`: optional white space and sign,
/// no leading zeros, within `i64`.
pub(crate) fn php_int(s: &str) -> Option<i64> {
    let t = s.trim();
    let body = t.strip_prefix(['+', '-']).unwrap_or(t);
    if body.is_empty()
        || !body.bytes().all(|b| b.is_ascii_digit())
        || (body.len() > 1 && body.starts_with('0'))
    {
        return None;
    }
    t.parse().ok()
}

fn min_max(value: &str, min: f64, max: f64, ctx: &Ctx<'_>, default: &str) -> Option<FieldError> {
    let ok = php_is_numeric(value)
        && value
            .trim()
            .parse::<f64>()
            .is_ok_and(|v| v >= min && v <= max);
    (!ok).then(|| ctx.err(ValidatorKind::MinMax, default))
}

/// `0` or `1`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BooleanField;

impl FieldType for BooleanField {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        if value == "0" || value == "1" {
            Vec::new()
        } else {
            vec![ctx.err(ValidatorKind::Regex, "Value should be a boolean (0,1).")]
        }
    }

    fn initial(&self) -> &'static str {
        "0"
    }
}

/// An integer within `min..=max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegerField {
    /// `MinimumValue`.
    pub min: i64,
    /// `MaximumValue`.
    pub max: i64,
}

impl Default for IntegerField {
    fn default() -> Self {
        Self {
            min: i64::MIN,
            max: i64::MAX,
        }
    }
}

const INVALID_INT: &str = "Invalid integer value.";

impl FieldType for IntegerField {
    #[allow(clippy::cast_precision_loss)]
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        let mut out = Vec::new();
        out.extend(min_max(
            value,
            self.min as f64,
            self.max as f64,
            ctx,
            INVALID_INT,
        ));
        if php_int(value).is_none() {
            out.push(ctx.err(ValidatorKind::Integer, INVALID_INT));
        }
        out
    }
}

/// A decimal number within `min..=max`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NumericField {
    /// `MinimumValue`.
    pub min: f64,
    /// `MaximumValue`.
    pub max: f64,
}

impl Default for NumericField {
    fn default() -> Self {
        Self {
            min: -99_999_999_999_999.0,
            max: 99_999_999_999_999.0,
        }
    }
}

/// OPNsense's `Numericality` pattern: digits with `,` grouping and a `.`
/// fraction, or `.` grouping and a `,` fraction.
fn numericality(s: &str) -> bool {
    let body = s.strip_prefix('-').unwrap_or(s);
    let form = |group: u8, frac: char| {
        let (int, f) = match body.split_once(frac) {
            Some((a, b)) => (a, Some(b)),
            None => (body, None),
        };
        !int.is_empty()
            && int.bytes().all(|b| b.is_ascii_digit() || b == group)
            && f.is_none_or(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()))
    };
    form(b',', '.') || form(b'.', ',')
}

impl FieldType for NumericField {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        const MSG: &str = "Invalid numeric value.";
        let mut out = Vec::new();
        out.extend(min_max(value, self.min, self.max, ctx, MSG));
        if !numericality(value) {
            out.push(ctx.err(ValidatorKind::Numericality, MSG));
        }
        out
    }
}

/// A sequence number that fills the lowest free slot of its collection
/// (`AutoNumberField`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoNumberField {
    /// `MinimumValue` (default 1).
    pub min: i64,
    /// `MaximumValue`.
    pub max: i64,
}

impl Default for AutoNumberField {
    fn default() -> Self {
        Self {
            min: 1,
            max: i64::MAX - 1,
        }
    }
}

impl AutoNumberField {
    /// The lowest number from `min` not used by `taken` (OPNsense
    /// `applyDefault`); `max + 1` when every slot is taken.
    pub fn next_free<'a>(&self, taken: impl IntoIterator<Item = &'a str>) -> i64 {
        let used: std::collections::HashSet<i64> =
            taken.into_iter().filter_map(|s| s.parse().ok()).collect();
        let mut n = self.min;
        while n <= self.max && used.contains(&n) {
            n += 1;
        }
        n
    }
}

impl FieldType for AutoNumberField {
    #[allow(clippy::cast_precision_loss)]
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        let mut out = Vec::new();
        if php_int(value).is_none() {
            out.push(ctx.err(ValidatorKind::Integer, INVALID_INT));
        }
        out.extend(min_max(
            value,
            self.min as f64,
            self.max as f64,
            ctx,
            INVALID_INT,
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::field::Field;
    use crate::testing::{validate, validate_err};
    use crate::validation::ValidatorKind::*;
    use proptest::prelude::*;

    #[test]
    fn php_predicates() {
        for ok in [
            "1", "-1", "+1", "1.5", ".5", "5.", "1e3", " 1", "1 ", "1E-3",
        ] {
            assert!(php_is_numeric(ok), "{ok}");
        }
        for bad in ["", "5x1", "e3", ".", "1e", "0x1A", "--1"] {
            assert!(!php_is_numeric(bad), "{bad}");
        }
        assert_eq!(php_int("99"), Some(99));
        assert_eq!(php_int(" -7 "), Some(-7));
        for bad in ["99.1", "5x1", "007", "", "99999999999999999999"] {
            assert_eq!(php_int(bad), None, "{bad}");
        }
    }

    mod boolean {
        use super::*;

        #[test]
        fn constructs_t0100() {
            let f = Field::new(BooleanField);
            assert_eq!(f.value(), "0");
        }

        #[test]
        fn rejects_number_t0101() {
            let mut f = Field::new(BooleanField);
            f.set_value("90");
            assert_eq!(validate_err(&f), Err(Regex));
        }

        #[test]
        fn rejects_string_t0102() {
            let mut f = Field::new(BooleanField);
            f.set_value("xx");
            assert_eq!(validate_err(&f), Err(Regex));
        }

        #[test]
        fn required_empty_t0103() {
            let mut f = Field::new(BooleanField).required();
            f.set_value("");
            assert_eq!(validate_err(&f), Err(PresenceOf));
        }

        #[test]
        fn required_set_t0104() {
            let mut f = Field::new(BooleanField).required();
            f.set_value("1");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn valid_values_t0105() {
            let mut f = Field::new(BooleanField);
            for v in ["0", "1"] {
                f.set_value(v);
                assert!(validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn not_container_t0106() {
            assert!(!Field::new(BooleanField).is_container());
        }
    }

    mod integer {
        use super::*;

        fn ranged() -> Field<IntegerField> {
            Field::new(IntegerField { min: 10, max: 100 })
        }

        #[test]
        fn constructs_t0146() {
            let _ = Field::new(IntegerField::default());
        }

        #[test]
        fn above_max_t0147() {
            let mut f = ranged();
            f.set_value("120");
            assert_eq!(validate_err(&f), Err(MinMax));
        }

        #[test]
        fn below_min_t0148() {
            let mut f = ranged();
            f.set_value("5");
            assert_eq!(validate_err(&f), Err(MinMax));
        }

        #[test]
        fn not_a_number_t0149() {
            let mut f = ranged();
            f.set_value("5x1");
            assert!(validate(&f).contains(&Integer));
        }

        #[test]
        fn decimal_rejected_t0150() {
            let mut f = ranged();
            f.set_value("99.1");
            assert!(validate(&f).contains(&Integer));
        }

        #[test]
        fn required_empty_t0151() {
            let mut f = Field::new(IntegerField::default()).required();
            f.set_value("");
            assert_eq!(validate_err(&f), Err(PresenceOf));
        }

        #[test]
        fn required_set_t0152() {
            let mut f = Field::new(IntegerField::default()).required();
            f.set_value("1");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn not_container_t0153() {
            assert!(!Field::new(IntegerField::default()).is_container());
        }

        #[test]
        fn numeric_field() {
            let mut f = Field::new(NumericField {
                min: 0.0,
                max: 10.0,
            });
            for ok in ["1", "1.5", "10"] {
                f.set_value(ok);
                assert!(validate(&f).is_empty(), "{ok}");
            }
            f.set_value("11");
            assert_eq!(validate(&f), [MinMax]);
            f.set_value("x");
            assert_eq!(validate(&f), [MinMax, Numericality]);
        }
    }

    mod auto_number {
        use super::*;

        /// Ten sibling items, as upstream builds under an ArrayField.
        fn fill(preset: &[i64]) -> Vec<Field<AutoNumberField>> {
            let mut items: Vec<Field<AutoNumberField>> = (1..=10)
                .map(|i| {
                    let mut f = Field::new(AutoNumberField::default());
                    if preset.contains(&i) {
                        f.set_value(i);
                    }
                    f
                })
                .collect();
            for i in 0..items.len() {
                if !items[i].is_set() {
                    let taken: Vec<String> = items.iter().map(|f| f.value().to_owned()).collect();
                    let next = items[i].kind.next_free(taken.iter().map(String::as_str));
                    items[i].set_value(next);
                }
            }
            items
        }

        #[test]
        fn constructs_t0089() {
            assert!(!Field::new(AutoNumberField::default()).is_set());
        }

        #[test]
        fn sequence_generated_t0090() {
            let items = fill(&[1]);
            let got: Vec<&str> = items.iter().map(Field::value).collect();
            assert_eq!(got, ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]);
        }

        #[test]
        fn fills_gaps_t0091() {
            let items = fill(&[2, 4, 7]);
            let got: Vec<&str> = items.iter().map(Field::value).collect();
            assert_eq!(got, ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]);
        }

        proptest! {
            /// Filling any preset subset yields each number once.
            #[test]
            fn prop_fill_gaps_is_bijective_t0091(mask in 0u16..1024) {
                let preset: Vec<i64> = (1..=10).filter(|i| mask & (1 << (i - 1)) != 0).collect();
                let mut got: Vec<i64> = fill(&preset).iter().map(|f| f.value().parse().unwrap()).collect();
                got.sort_unstable();
                prop_assert_eq!(got, (1..=10).collect::<Vec<_>>());
            }
        }

        #[test]
        fn not_a_number_t0092() {
            let mut f = Field::new(AutoNumberField::default());
            f.set_value("X");
            assert!(validate(&f).contains(&Integer));
        }

        #[test]
        fn out_of_range_t0093() {
            let mut f = Field::new(AutoNumberField { min: 1, max: 100 });
            for v in ["101", "0"] {
                f.set_value(v);
                assert!(validate(&f).contains(&MinMax), "{v}");
            }
        }
    }
}
