//! `SingleSelectConstraint`: at most one field has data (exactly one when
//! `required`).

use super::ConstraintValue;

/// True if at most one value is non-empty (and at least one if `required`).
pub fn single_select(values: &[&dyn ConstraintValue], required: bool) -> bool {
    let filled = values.iter().filter(|v| !v.is_blank()).count();
    filled <= 1 && !(required && filled == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_empty_t0043() {
        assert!(single_select(&[&"", &"", &""], false));
    }

    #[test]
    fn two_fail_t0044() {
        assert!(!single_select(&[&"x", &"x", &""], false));
    }

    #[test]
    fn one_ok_t0045() {
        assert!(single_select(&[&"", &"x", &""], false));
        assert!(!single_select(&[&"", &"", &""], true), "required needs one");
    }
}
