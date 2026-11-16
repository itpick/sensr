//! `DependConstraint`: this field must have data when any of the related
//! fields has data (`"0"`, false count as no data).

use super::ConstraintValue;

/// True unless `node` is empty while one of `related` is not.
pub fn depend(node: &dyn ConstraintValue, related: &[&dyn ConstraintValue]) -> bool {
    !node.is_blank() || related.iter().all(|r| r.is_blank())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &str = "When \"value1\" is enabled, \"value2\" is required.";

    /// Upstream TestModel `DependConstraint`: a boolean `value1` and text
    /// `value2`, constraint on `value2`.
    fn check(value1: bool, value2: &str) -> Result<(), &'static str> {
        if depend(&value2, &[&value1]) {
            Ok(())
        } else {
            Err(MSG)
        }
    }

    #[test]
    fn initial_t0049() {
        assert_eq!(check(false, ""), Ok(()));
    }

    #[test]
    fn enabled_requires_value_t0050() {
        assert_eq!(check(true, ""), Err(MSG));
    }

    #[test]
    fn enabled_with_value_ok_t0051() {
        assert_eq!(check(true, "xxx"), Ok(()));
    }

    #[test]
    fn disabled_with_value_ok_t0052() {
        assert_eq!(check(false, "xxx"), Ok(()));
    }
}
