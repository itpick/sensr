//! `SetIfConstraint`: this field must have data when another field equals a
//! given value (e.g. an MX priority when the record type is `MX`).

use super::ConstraintValue;

/// True unless `node` is empty while `field` equals `check`.
pub fn set_if(node: &dyn ConstraintValue, field: &dyn ConstraintValue, check: &str) -> bool {
    !(node.is_blank() && field.text() == check)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_only_for_matching_value() {
        assert!(!set_if(&"", &"MX", "MX"));
        assert!(set_if(&"10", &"MX", "MX"));
        assert!(set_if(&"", &"A", "MX"));
        assert!(!set_if(&None::<u16>, &"dynipv6host", "dynipv6host"));
    }
}
