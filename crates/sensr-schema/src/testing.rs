//! Test helpers mirroring OPNsense's `Field_Framework_TestCase`:
//! [`validate`] returns the kinds of every failed validator, [`validate_err`]
//! the first one (what `validateThrow` raises).

use crate::fields::field::{Field, FieldType};
use crate::validation::ValidatorKind;

/// Kinds of every failed validator, in order.
pub fn validate<T: FieldType>(field: &Field<T>) -> Vec<ValidatorKind> {
    field.validate().into_iter().map(|e| e.kind).collect()
}

/// The first failure's kind, as `validateThrow` would raise it.
pub fn validate_err<T: FieldType>(field: &Field<T>) -> Result<(), ValidatorKind> {
    match validate(field).first() {
        Some(k) => Err(*k),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    /// Upstream's `testIgnore` placeholder (excluded by `phpunit.xml`); the
    /// one test allowed to be ignored.
    #[test]
    #[ignore = "mirrors upstream's @group Ignore placeholder"]
    fn helpers_compile_t0073() {}
}
