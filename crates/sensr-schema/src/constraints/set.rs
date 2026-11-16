//! `SetConstraint`: this field must be set when any of the related fields
//! is set (`"0"` counts as set).

use super::ConstraintValue;

/// True unless `node` is unset while one of `related` is set.
pub fn set(node: &dyn ConstraintValue, related: &[&dyn ConstraintValue]) -> bool {
    node.is_set() || !related.iter().any(|r| r.is_set())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &str = "When \"value1\" is enabled, \"value2\" is required.";

    /// Upstream TestModel `SetConstraint`: the constraint sits on `value2`
    /// with `value1` as the related field.
    fn check(value1: &str, value2: &str) -> Result<(), &'static str> {
        if set(&value2, &[&value1]) {
            Ok(())
        } else {
            Err(MSG)
        }
    }

    #[test]
    fn initial_empty_t0046() {
        assert_eq!(check("", ""), Ok(()));
    }

    #[test]
    fn one_without_other_fails_t0047() {
        assert_eq!(check("0", ""), Err(MSG));
    }

    #[test]
    fn both_set_ok_t0048() {
        assert_eq!(check("0", "0"), Ok(()));
    }
}
