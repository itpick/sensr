//! `AllOrNoneConstraint`: either every field has data or none does.

use super::ConstraintValue;

/// True unless some fields are empty and others are not.
pub fn all_or_none(values: &[&dyn ConstraintValue]) -> bool {
    let filled = values.iter().filter(|v| !v.is_blank()).count();
    filled == 0 || filled == values.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Upstream TestModel `AllOrNone` (its message lacks a period; it is test
    /// data, not a sensr message).
    const MSG: &str = "All fields should contain data or none of them";

    fn check(a: &str, b: &str, c: &str) -> Result<(), &'static str> {
        if all_or_none(&[&a, &b, &c]) {
            Ok(())
        } else {
            Err(MSG)
        }
    }

    #[test]
    fn initial_empty_t0040() {
        assert_eq!(check("", "", ""), Ok(()));
    }

    #[test]
    fn partial_fails_t0041() {
        assert_eq!(check("", "X", ""), Err(MSG));
    }

    #[test]
    fn all_set_ok_t0042() {
        assert_eq!(check("X1", "X2", "X3"), Ok(()));
    }
}
