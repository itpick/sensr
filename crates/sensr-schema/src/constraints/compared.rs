//! `ComparedToFieldConstraint`: a numeric relation between two fields.

use super::ConstraintValue;

/// The relation `node <op> other` must hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    /// `>`.
    Gt,
    /// `>=`.
    Gte,
    /// `<`.
    Lt,
    /// `<=`.
    Lte,
    /// `==`.
    Eq,
    /// `!=`.
    Neq,
}

/// True if the relation holds, or cannot be checked: either value unset,
/// or neither numeric.
pub fn compared(node: &dyn ConstraintValue, op: Comparison, other: &dyn ConstraintValue) -> bool {
    if !node.is_set() || !other.is_set() {
        return true;
    }
    let (a, b) = (node.as_f64(), other.as_f64());
    if a.is_none() && b.is_none() {
        return true;
    }
    // PHP casts a non-numeric side to 0.
    let (a, b) = (a.unwrap_or(0.0), b.unwrap_or(0.0));
    match op {
        Comparison::Gt => a > b,
        Comparison::Gte => a >= b,
        Comparison::Lt => a < b,
        Comparison::Lte => a <= b,
        Comparison::Eq => (a - b).abs() < f64::EPSILON,
        Comparison::Neq => (a - b).abs() >= f64::EPSILON,
    }
}

#[cfg(test)]
mod tests {
    use super::Comparison::*;
    use super::*;

    /// Number of messages upstream's validator would report.
    fn msgs(node: Option<&str>, other: Option<&str>, op: Comparison) -> usize {
        usize::from(!compared(&node, op, &other))
    }

    #[test]
    fn lt_ok_t0053() {
        assert_eq!(msgs(Some("2"), Some("3"), Lt), 0);
    }

    #[test]
    fn lt_equal_fails_t0054() {
        assert_eq!(msgs(Some("3"), Some("3"), Lt), 1);
    }

    #[test]
    fn gt_ok_t0055() {
        assert_eq!(msgs(Some("5"), Some("3"), Gt), 0);
    }

    #[test]
    fn gt_fails_t0056() {
        assert_eq!(msgs(Some("2"), Some("3"), Gt), 1);
    }

    #[test]
    fn zero_lt_fails_t0057() {
        assert_eq!(msgs(Some("2"), Some("0"), Lt), 1);
    }

    #[test]
    fn zero_gt_fails_t0058() {
        assert_eq!(msgs(Some("0"), Some("2"), Gt), 1);
    }

    #[test]
    fn zero_lt_ok_t0059() {
        assert_eq!(msgs(Some("0"), Some("2"), Lt), 0);
    }

    #[test]
    fn zero_gt_ok_t0060() {
        assert_eq!(msgs(Some("2"), Some("0"), Gt), 0);
    }

    #[test]
    fn empty_node_skips_t0061() {
        assert_eq!(msgs(Some(""), Some("5"), Lt), 0);
    }

    #[test]
    fn empty_other_skips_t0062() {
        assert_eq!(msgs(Some("5"), Some(""), Gt), 0);
    }

    #[test]
    fn null_node_skips_t0063() {
        assert_eq!(msgs(None, Some("2"), Eq), 0);
    }

    #[test]
    fn null_other_skips_t0064() {
        assert_eq!(msgs(Some("2"), None, Eq), 0);
    }

    #[test]
    fn both_null_skip_t0065() {
        assert_eq!(msgs(None, None, Eq), 0);
    }

    #[test]
    fn other_operators() {
        assert!(compared(&3u16, Gte, &3u16) && compared(&3u16, Lte, &3u16));
        assert!(compared(&3u16, Neq, &4u16) && !compared(&3u16, Eq, &4u16));
    }
}
