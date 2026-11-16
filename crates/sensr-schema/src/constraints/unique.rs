//! `UniqueConstraint`: a field (optionally with more fields as a composite
//! key) must be unique across the items of a collection.

use std::collections::HashMap;
use std::hash::Hash;

use super::ConstraintValue;

/// Options of [`unique`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UniqueOptions {
    /// The primary field is required: empty values take part in the check
    /// (otherwise an item with an empty primary field is skipped).
    pub required: bool,
    /// Compare case-insensitively (`caseInsensitive`).
    pub case_insensitive: bool,
}

/// The ids of every item whose key repeats another item's. `items` yields
/// `(id, primary, additional key fields)`; one result per offending item,
/// as upstream reports one message per item.
pub fn unique<'a, Id: Clone + Eq + Hash>(
    items: impl IntoIterator<Item = (Id, &'a dyn ConstraintValue, Vec<&'a dyn ConstraintValue>)>,
    opts: UniqueOptions,
) -> Vec<Id> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut keyed = Vec::new();
    for (id, primary, extra) in items {
        // Every item counts towards the duplicates...
        let mut key = String::new();
        for v in std::iter::once(primary).chain(extra) {
            // A separator that cannot occur in values keeps ("a,b","c") and
            // ("a","b,c") apart.
            key.push_str("\n\0");
            key.push_str(&v.text());
        }
        if opts.case_insensitive {
            key = key.to_lowercase();
        }
        *counts.entry(key.clone()).or_default() += 1;
        // ...but only items whose primary field takes part are reported.
        if opts.required || !primary.is_blank() {
            keyed.push((id, key));
        }
    }
    keyed
        .into_iter()
        .filter(|(_, k)| counts[k] > 1)
        .map(|(id, _)| id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rows of `(field values)`; the first is the primary field.
    fn dupes(rows: &[&[&str]], opts: UniqueOptions) -> usize {
        unique(
            rows.iter().enumerate().map(|(i, r)| {
                let extra: Vec<&dyn ConstraintValue> =
                    r[1..].iter().map(|v| v as &dyn ConstraintValue).collect();
                (i, &r[0] as &dyn ConstraintValue, extra)
            }),
            opts,
        )
        .len()
    }

    const NOT_REQUIRED: UniqueOptions = UniqueOptions {
        required: false,
        case_insensitive: false,
    };
    const REQUIRED: UniqueOptions = UniqueOptions {
        required: true,
        case_insensitive: false,
    };

    #[test]
    fn duplicate_reports_each_item_t0066() {
        assert_eq!(dupes(&[&["value1"], &["value2"]], NOT_REQUIRED), 0);
        assert_eq!(
            dupes(&[&["value1"], &["value2"], &["value1"]], NOT_REQUIRED),
            2
        );
    }

    #[test]
    fn composite_key_t0067() {
        let rows: [&[&str]; 2] = [&["value1", "value2"], &["value1", "value3"]];
        assert_eq!(dupes(&rows, NOT_REQUIRED), 0);
        let rows: [&[&str]; 3] = [
            &["value1", "value2"],
            &["value1", "value3"],
            &["value1", "value2"],
        ];
        assert_eq!(dupes(&rows, NOT_REQUIRED), 2);
    }

    #[test]
    fn empty_required_toggle_t0068() {
        assert_eq!(dupes(&[&[""], &[""]], NOT_REQUIRED), 0);
        assert_eq!(dupes(&[&[""], &[""]], REQUIRED), 2);
    }

    #[test]
    fn empty_composite_required_toggle_t0069() {
        let rows: [&[&str]; 2] = [&["", ""], &["", ""]];
        assert_eq!(dupes(&rows, NOT_REQUIRED), 0);
        assert_eq!(dupes(&rows, REQUIRED), 2);
    }

    #[test]
    fn empty_primary_skips_t0070() {
        let rows: [&[&str]; 2] = [&["", "value1"], &["", "value1"]];
        assert_eq!(dupes(&rows, NOT_REQUIRED), 0);
        assert_eq!(dupes(&rows, REQUIRED), 2);
    }

    #[test]
    fn case_insensitive_t0071() {
        assert_eq!(
            dupes(
                &[&["Value1"], &["value1"]],
                UniqueOptions {
                    required: false,
                    case_insensitive: true
                }
            ),
            2
        );
    }

    #[test]
    fn case_sensitive_t0072() {
        assert_eq!(dupes(&[&["Value1"], &["value1"]], NOT_REQUIRED), 0);
    }

    #[test]
    fn separator_keeps_composites_apart() {
        let rows: [&[&str]; 2] = [&["a,b", "c"], &["a", "b,c"]];
        assert_eq!(dupes(&rows, NOT_REQUIRED), 0);
    }
}
