//! Text fields (OPNsense `TextField`, `StrictTextField`,
//! `UpdateOnlyTextField`, `Base64Field`, `EmailField`).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::field::{Ctx, FieldType, Mask};
use crate::validation::{FieldError, ValidatorKind};

/// Free text with optional `Mask` and character-class switches.
#[derive(Debug, Clone, PartialEq)]
pub struct TextField {
    /// `Mask`: the value must match in full.
    pub mask: Option<Mask>,
    /// `AllowSpaces` (spaces and tabs).
    pub allow_spaces: bool,
    /// `AllowNewlines` (`\n`, `\r`).
    pub allow_newlines: bool,
    /// `AllowSpecial` (`\0`, `\v`, `\f`).
    pub allow_special: bool,
}

impl Default for TextField {
    fn default() -> Self {
        Self {
            mask: None,
            allow_spaces: true,
            allow_newlines: true,
            allow_special: true,
        }
    }
}

impl TextField {
    /// `StrictTextField`: no spaces, newlines or control characters.
    pub fn strict() -> Self {
        Self {
            mask: None,
            allow_spaces: false,
            allow_newlines: false,
            allow_special: false,
        }
    }

    /// With a mask (builder form).
    #[must_use]
    pub fn with_mask(mut self, mask: Mask) -> Self {
        self.mask = Some(mask);
        self
    }

    fn check_text(&self, value: &str, ctx: &Ctx<'_>, default_msg: &str) -> Vec<FieldError> {
        let mut out = Vec::new();
        let class = if !self.allow_spaces && value.contains([' ', '\t']) {
            Some("Text may not contain spaces or tabs.")
        } else if !self.allow_newlines && value.contains(['\n', '\r']) {
            Some("Text may not contain newlines.")
        } else if !self.allow_special && value.contains(['\0', '\x0b', '\x0c']) {
            Some("Text may not contain special control characters.")
        } else {
            None
        };
        if let Some(m) = class {
            out.push(FieldError::callback(m));
        }
        if let Some(mask) = &self.mask
            && !mask.matches(value)
        {
            out.push(ctx.err(ValidatorKind::Regex, default_msg));
        }
        out
    }
}

impl FieldType for TextField {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        self.check_text(value, ctx, "Text does not validate.")
    }
}

/// Write-only text (passwords): setting an empty value keeps the old one,
/// and the value never displays (OPNsense `UpdateOnlyTextField`). The value
/// is still validated.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UpdateOnlyTextField(pub TextField);

impl FieldType for UpdateOnlyTextField {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        self.0.check(value, ctx)
    }

    fn keeps_value_on_empty(&self) -> bool {
        true
    }

    fn write_only(&self) -> bool {
        true
    }
}

/// Padded standard base64; embedded newlines allowed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Base64Field(pub TextField);

impl FieldType for Base64Field {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        let mut out = self.0.check(value, ctx);
        let flat = value.replace('\n', "");
        // Canonical form: decoding then re-encoding gives the input back.
        let canonical = STANDARD
            .decode(&flat)
            .is_ok_and(|raw| STANDARD.encode(raw) == flat);
        if !canonical {
            out.push(ctx.err(ValidatorKind::Callback, "Invalid Base64-encoded string."));
        }
        out
    }
}

/// An e-mail address `local@domain.tld` (OPNsense `EmailField`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EmailField;

/// The check `EmailField` applies, usable on its own.
pub fn is_email(s: &str) -> bool {
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    let local_ok = !local.is_empty()
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-'));
    let Some((host, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'));
    local_ok && host_ok && tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())
}

impl FieldType for EmailField {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        if is_email(value) {
            Vec::new()
        } else {
            vec![ctx.err(ValidatorKind::Callback, "Email address is invalid.")]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::field::{ChangeCase, Field};
    use crate::testing::{validate, validate_err};
    use crate::validation::ValidatorKind::*;

    fn masked(m: &str) -> Field<TextField> {
        Field::new(TextField::default().with_mask(Mask::new(m).unwrap()))
    }

    mod text {
        use super::*;

        #[test]
        fn constructs_t0255() {
            let _ = Field::new(TextField::default());
        }

        #[test]
        fn not_container_t0256() {
            assert!(!Field::new(TextField::default()).is_container());
        }

        #[test]
        fn not_array_t0257() {
            assert!(!Field::new(TextField::default()).is_array_type());
        }

        #[test]
        fn virtual_default_false_t0258() {
            assert!(!Field::new(TextField::default()).is_virtual());
        }

        #[test]
        fn virtual_set_t0259() {
            let mut f = Field::new(TextField::default());
            f.set_virtual();
            assert!(f.is_virtual());
        }

        #[test]
        fn unset_optional_t0260() {
            let f = Field::new(TextField::default());
            assert!(!f.is_required() && !f.is_set());
        }

        #[test]
        fn unset_required_t0261() {
            let f = Field::new(TextField::default()).required();
            assert!(f.is_required() && !f.is_set());
        }

        #[test]
        fn required_set_t0262() {
            let mut f = Field::new(TextField::default()).required();
            f.set_value("Not empty string value");
            assert!(f.is_set());
            assert_eq!(f.value(), "Not empty string value");
            assert_eq!(f.values(), ["Not empty string value"]);
            assert!(validate(&f).is_empty());
            assert_eq!(f.count(), 1);
        }

        #[test]
        fn required_empty_t0263() {
            let mut f = Field::new(TextField::default()).required();
            f.set_value("");
            assert_eq!(f.count(), 0);
            assert_eq!(validate_err(&f), Err(PresenceOf));
        }

        #[test]
        fn set_values_empty_t0264() {
            let mut f = Field::new(TextField::default());
            f.set_value("foo");
            f.set_values::<&str>(&[]);
            assert!(validate(&f).is_empty());
            assert!(f.values().is_empty());
        }

        #[test]
        fn mask_skips_empty_t0265() {
            let mut f = masked("/^regexpattern$/");
            f.set_value("");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn mask_fails_t0266() {
            let mut f = masked("/^[a-z]{8}$/");
            f.set_value("4bcd3fgh");
            assert!(validate(&f).contains(&Regex));
        }

        #[test]
        fn mask_ok_t0267() {
            let mut f = masked("/^[a-z]{8}$/");
            f.set_value("abcdefgh");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn numeric_string_t0268() {
            let mut f = Field::new(TextField::default());
            f.set_value("1234");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn set_values_first_wins_t0269() {
            let mut f = Field::new(TextField::default());
            f.set_values(&["nope", "1234"]);
            assert_eq!(f.value(), "nope");
            f.set_values(&[1234.to_string(), "nope".into()]);
            assert_eq!(f.value(), "1234");
            assert!(validate(&f).is_empty());
            f.set_values(&[""]);
            assert_eq!(f.value(), "");
        }

        #[test]
        fn int_mask_ok_t0270() {
            let mut f = masked("/^[0-9]{4}$/");
            f.set_value(1234);
            assert_eq!(f.value(), "1234");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn int_mask_fails_t0271() {
            let mut f = masked("/^[a-z]{4}$/");
            f.set_value(1234);
            assert_eq!(f.value(), "1234");
            assert!(validate(&f).contains(&Regex));
        }

        fn cased(case: ChangeCase, mask: Option<&str>) -> Field<TextField> {
            let mut f = match mask {
                Some(m) => masked(m),
                None => Field::new(TextField::default()),
            };
            f.set_change_case(case);
            f
        }

        #[test]
        fn change_case_upper_t0272() {
            let mut f = cased(ChangeCase::Upper, None);
            f.set_value("aB cdE fgH");
            assert_eq!(f.value(), "AB CDE FGH");
        }

        #[test]
        fn change_case_lower_t0273() {
            let mut f = cased(ChangeCase::Lower, None);
            f.set_value("aB cdE fgH");
            assert_eq!(f.value(), "ab cde fgh");
        }

        #[test]
        fn change_case_upper_alnum_t0274() {
            let mut f = cased(ChangeCase::Upper, None);
            f.set_value("igb0");
            assert_eq!(f.value(), "IGB0");
        }

        #[test]
        fn change_case_lower_alnum_t0275() {
            let mut f = cased(ChangeCase::Lower, None);
            f.set_value("1024 Gigabytes");
            assert_eq!(f.value(), "1024 gigabytes");
        }

        #[test]
        fn upper_then_mask_ok_t0276() {
            let mut f = cased(ChangeCase::Upper, Some("/^[A-Z ]{10}$/"));
            f.set_value("aB cdE fgH");
            assert_eq!(f.value(), "AB CDE FGH");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn lower_then_mask_ok_t0277() {
            let mut f = cased(ChangeCase::Lower, Some("/^[a-z ]{10}$/"));
            f.set_value("aB cdE fgH");
            assert_eq!(f.value(), "ab cde fgh");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn mask_after_case_change_t0278() {
            let mut f = cased(ChangeCase::Upper, Some("/^[a-z ]{10}$/"));
            f.set_value("ab cde fgh");
            assert!(validate(&f).contains(&Regex));
        }

        fn flags(spaces: bool, newlines: bool, special: bool) -> Field<TextField> {
            Field::new(TextField {
                mask: None,
                allow_spaces: spaces,
                allow_newlines: newlines,
                allow_special: special,
            })
        }

        #[test]
        fn spaces_default_ok_t0279() {
            let mut f = Field::new(TextField::default());
            f.set_value("foo bar\tbaz");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn spaces_disabled_t0280() {
            let mut f = flags(false, true, true);
            f.set_value("foo bar\tbaz");
            assert!(!validate(&f).is_empty());
        }

        #[test]
        fn newlines_default_ok_t0281() {
            let mut f = Field::new(TextField::default());
            f.set_value("foo\nbar\rbaz");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn newlines_disabled_t0282() {
            let mut f = flags(true, false, true);
            f.set_value("foo\nbar\rbaz");
            assert!(!validate(&f).is_empty());
        }

        #[test]
        fn special_default_ok_t0283() {
            let mut f = Field::new(TextField::default());
            f.set_value("foo\0bar\x0bbaz\x0cqux");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn special_disabled_t0284() {
            let mut f = flags(true, true, false);
            f.set_value("foo\0bar\x0bbaz\x0cqux");
            assert!(!validate(&f).is_empty());
        }
    }

    mod strict_text {
        use super::*;

        fn strict(spaces: bool, newlines: bool, special: bool) -> Field<TextField> {
            let mut k = TextField::strict();
            k.allow_spaces |= spaces;
            k.allow_newlines |= newlines;
            k.allow_special |= special;
            Field::new(k)
        }

        #[test]
        fn constructs_t0248() {
            let _ = Field::new(TextField::strict());
        }

        #[test]
        fn spaces_default_rejected_t0249() {
            let mut f = strict(false, false, false);
            f.set_value("foo bar\tbaz");
            assert!(!validate(&f).is_empty());
        }

        #[test]
        fn spaces_enabled_t0250() {
            let mut f = strict(true, false, false);
            f.set_value("foo bar\tbaz");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn newlines_default_rejected_t0251() {
            let mut f = strict(false, false, false);
            f.set_value("foo\nbar\rbaz");
            assert!(!validate(&f).is_empty());
        }

        #[test]
        fn newlines_enabled_t0252() {
            let mut f = strict(false, true, false);
            f.set_value("foo\nbar\rbaz");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn special_default_rejected_t0253() {
            let mut f = strict(false, false, false);
            f.set_value("foo\0bar\x0bbaz\x0cqux");
            assert!(!validate(&f).is_empty());
        }

        #[test]
        fn special_enabled_t0254() {
            let mut f = strict(false, false, true);
            f.set_value("foo\0bar\x0bbaz\x0cqux");
            assert!(validate(&f).is_empty());
        }
    }

    mod update_only {
        use super::*;

        #[test]
        fn constructs_t0285() {
            let _ = Field::new(UpdateOnlyTextField::default());
        }

        #[test]
        fn write_only_semantics_t0286() {
            let mut f = Field::new(UpdateOnlyTextField(
                TextField::default().with_mask(Mask::new("/^regexpattern$/").unwrap()),
            ));
            f.set_value("regexpattern");
            assert_eq!(f.to_string(), "");
            assert_eq!(f.value(), "regexpattern");
            f.set_value("");
            assert_eq!(f.to_string(), "");
            assert_eq!(f.value(), "regexpattern");
            assert!(validate(&f).is_empty());
            f.set_value("nottheregex");
            assert!(validate(&f).contains(&Regex));
        }
    }

    mod base64 {
        use super::*;

        #[test]
        fn constructs_t0094() {
            let _ = Field::new(Base64Field::default());
        }

        #[test]
        fn required_empty_t0095() {
            let mut f = Field::new(Base64Field::default()).required();
            f.set_value("");
            assert_eq!(validate_err(&f), Err(PresenceOf));
        }

        #[test]
        fn required_set_t0096() {
            let mut f = Field::new(Base64Field::default()).required();
            f.set_value("T1BOc2Vuc2U=");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn valid_values_t0097() {
            let mut f = Field::new(Base64Field::default());
            for v in ["T1BOc2Vuc2U=", "RGVjaXNv", "RGVj\naXNv"] {
                f.set_value(v);
                assert!(validate(&f).is_empty(), "{v:?}");
            }
        }

        #[test]
        fn invalid_values_t0098() {
            let mut f = Field::new(Base64Field::default());
            for v in ["!2121", "x2x", "88766-1234"] {
                f.set_value(v);
                assert!(!validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn not_container_t0099() {
            assert!(!Field::new(Base64Field::default()).is_container());
        }
    }

    mod email {
        use super::*;

        #[test]
        fn constructs_t0129() {
            let _ = Field::new(EmailField);
        }

        #[test]
        fn required_empty_t0130() {
            let mut f = Field::new(EmailField).required();
            f.set_value("");
            assert_eq!(validate_err(&f), Err(PresenceOf));
        }

        #[test]
        fn required_set_t0131() {
            let mut f = Field::new(EmailField).required();
            f.set_value("user@domain.com");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn valid_values_t0132() {
            let mut f = Field::new(EmailField);
            for v in ["user@domain.local", "user@my.domain", "uSeR@mY.doMaIN"] {
                f.set_value(v);
                assert!(validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn invalid_values_t0133() {
            let mut f = Field::new(EmailField);
            for v in [
                "xxx",
                "YY",
                "user@none",
                "user@domain.\"x",
                "user`@my.domain",
            ] {
                f.set_value(v);
                assert!(!validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn not_container_t0134() {
            assert!(!Field::new(EmailField).is_container());
        }
    }
}
