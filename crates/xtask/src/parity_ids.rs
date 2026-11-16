//! Checklist rows discharged by checks rather than by a named test: xtask
//! tasks and the gates CI runs on every PR (.github/workflows/ci.yml).
//! Add a row here only when the check named actually runs in CI.

/// (ID, what discharges it).
pub const DISCHARGED: &[(&str, &str)] = &[
    // lint-xml: every fixture XML is well-formed.
    ("T-0347", "cargo xtask lint-fixtures"),
    // lint-import: no stale imports.
    (
        "T-0370",
        "cargo clippy --workspace --all-targets -D warnings (unused_imports)",
    ),
    // lint-php: syntax check of every source.
    (
        "T-0373",
        "cargo clippy --workspace --all-targets (type-checks every target)",
    ),
    // style-php: the house style.
    ("T-0375", "cargo fmt --check + cargo clippy -D warnings"),
    // sweep-php: auto-fixable style, in check mode.
    ("T-0378", "cargo fmt --check"),
    // make test.
    ("T-0384", "cargo test --workspace"),
];
