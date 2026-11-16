//! Typed config field types, constraints and versioned migrations (OPNsense
//! counterpart: MVC `Base/FieldTypes`, `Constraints`, `Migrations`), and the
//! typed configuration models every other crate reads and writes.
//!
//! - [`fields`]: parsed newtypes (`Hostname`, `MacAddr`, `Port`, `NetOrAlias`,
//!   ...) that cannot hold invalid data.
//! - [`ArrayField`] / [`Relation`]: UUID-keyed lists and typed references.
//! - [`models`]: the configuration sections and the [`Document`] root.
//! - [`Validate`] / [`RefContext`]: whole-document validation with dotted
//!   paths ([`Validations`]).
//! - [`PathAccess`]: `get/set_by_path` on any model.

pub mod array;
pub mod fields;
pub mod models;
pub mod path;
pub mod refs;
pub mod validation;

pub use array::{ArrayField, Relation, Uuid};
pub use models::{Document, SCHEMA_VERSION, SchemaVersion, Section};
pub use path::{PathAccess, PathError};
pub use refs::{ItemKind, RefContext, Validate};
pub use validation::{FieldError, FieldPath, Validations, ValidatorKind};

/// Re-exported so dependants use the same network types.
pub use ipnet;
