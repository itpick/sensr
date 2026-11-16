//! Versioned document migrations (OPNsense counterpart: `BaseModelMigration`
//! and the `Migrations/M<x>_<y>_<z>.php` classes run by `run_migrations.php`).
//!
//! A migration is identified by the schema version it produces. Like
//! OPNsense, the runner applies every migration whose version is above the
//! document's and at most the target, in version order, and stamps the
//! document with each version as it goes. Migrations work on the JSON value
//! because an old document no longer fits today's types.
//!
//! Migrations register themselves with [`inventory`]:
//!
//! ```ignore
//! struct M0_2_0;
//! impl Migration for M0_2_0 { ... }
//! inventory::submit! { sensr_schema::migrate::Registered(&M0_2_0) }
//! ```

use serde_json::Value;

use crate::models::{SCHEMA_VERSION, SchemaVersion};

/// One step of the document schema.
pub trait Migration: Sync {
    /// The version the document has after this migration.
    fn version(&self) -> SchemaVersion;

    /// What the migration changes, for `sensr config migrate --dry-run`.
    fn description(&self) -> &'static str;

    /// Rewrites `doc` in place. Must be idempotent and must not drop objects
    /// other than the ones it means to change (ISS-C-004).
    fn migrate(&self, doc: &mut Value) -> Result<(), String>;
}

/// An inventory entry for a [`Migration`].
pub struct Registered(pub &'static dyn Migration);

inventory::collect!(Registered);

/// Every registered migration, in version order.
pub fn registered() -> Vec<&'static dyn Migration> {
    let mut v: Vec<&'static dyn Migration> = inventory::iter::<Registered>
        .into_iter()
        .map(|r| r.0)
        .collect();
    v.sort_by_key(|m| m.version());
    v
}

/// Why a document could not be migrated.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MigrateError {
    /// The document has no readable `schema_version`.
    #[error("document has no valid schema_version")]
    NoVersion,
    /// The document is newer than this build understands.
    #[error("document schema {found} is newer than supported {supported}")]
    TooNew {
        /// The document's version.
        found: SchemaVersion,
        /// The newest version this build knows.
        supported: SchemaVersion,
    },
    /// A migration failed; the document is unusable at the target version.
    #[error("migration to {version} failed: {reason}")]
    Failed {
        /// The failing step.
        version: SchemaVersion,
        /// Its explanation.
        reason: String,
    },
}

/// One applied step, for reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// Version reached.
    pub version: SchemaVersion,
    /// What changed.
    pub description: &'static str,
}

/// The `schema_version` of a JSON document.
pub fn version_of(doc: &Value) -> Result<SchemaVersion, MigrateError> {
    doc.get("schema_version")
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .ok_or(MigrateError::NoVersion)
}

/// Migrates `doc` to `target` with `migrations` (any order). On error `doc`
/// is left as it was, so callers never see a half-migrated document.
pub fn run(
    doc: &mut Value,
    migrations: &[&dyn Migration],
    target: SchemaVersion,
) -> Result<Vec<Applied>, MigrateError> {
    let current = version_of(doc)?;
    if current > target {
        return Err(MigrateError::TooNew {
            found: current,
            supported: target,
        });
    }
    let mut steps: Vec<&&dyn Migration> = migrations
        .iter()
        .filter(|m| m.version() > current && m.version() <= target)
        .collect();
    steps.sort_by_key(|m| m.version());
    let mut work = doc.clone();
    let mut applied = Vec::new();
    for m in steps {
        m.migrate(&mut work)
            .map_err(|reason| MigrateError::Failed {
                version: m.version(),
                reason,
            })?;
        if let Value::Object(o) = &mut work {
            o.insert(
                "schema_version".into(),
                Value::String(m.version().to_string()),
            );
        }
        applied.push(Applied {
            version: m.version(),
            description: m.description(),
        });
    }
    if let Value::Object(o) = &mut work {
        o.insert("schema_version".into(), Value::String(target.to_string()));
    }
    *doc = work;
    Ok(applied)
}

/// Migrates `doc` to this build's [`SCHEMA_VERSION`] with every registered
/// migration.
pub fn to_head(doc: &mut Value) -> Result<Vec<Applied>, MigrateError> {
    run(doc, &registered(), SCHEMA_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Mirrors upstream's TestModel migrations: each prefixes
    /// `general.FromEmail` with its version.
    struct Prefix(SchemaVersion, &'static str);
    impl Migration for Prefix {
        fn version(&self) -> SchemaVersion {
            self.0
        }
        fn description(&self) -> &'static str {
            "prefix FromEmail"
        }
        fn migrate(&self, doc: &mut Value) -> Result<(), String> {
            let email = doc
                .pointer_mut("/general/FromEmail")
                .ok_or("FromEmail missing")?;
            let old = email.as_str().ok_or("FromEmail not a string")?;
            *email = Value::String(format!("{}{old}", self.1));
            Ok(())
        }
    }

    static M0_0_1: Prefix = Prefix(SchemaVersion::new(0, 0, 1), "001_");
    static M1_0_0: Prefix = Prefix(SchemaVersion::new(1, 0, 0), "100_");
    static M1_0_1: Prefix = Prefix(SchemaVersion::new(1, 0, 1), "101_");

    #[test]
    fn chain_runs_in_order_and_stops_at_model_version_t0024() {
        let mut doc =
            json!({"schema_version": "0.0.0", "general": {"FromEmail": "sample@example.com"}});
        // Deliberately out of order: the runner sorts.
        let ms: [&dyn Migration; 3] = [&M1_0_1, &M1_0_0, &M0_0_1];
        let applied = run(&mut doc, &ms, SchemaVersion::new(1, 0, 0)).unwrap();
        assert_eq!(doc["general"]["FromEmail"], "100_001_sample@example.com");
        assert_eq!(doc["schema_version"], "1.0.0");
        assert_eq!(
            applied
                .iter()
                .map(|a| a.version.to_string())
                .collect::<Vec<_>>(),
            ["0.0.1", "1.0.0"]
        );
        // Already at the target: nothing runs (idempotence).
        let before = doc.clone();
        assert!(
            run(&mut doc, &ms, SchemaVersion::new(1, 0, 0))
                .unwrap()
                .is_empty()
        );
        assert_eq!(doc, before);
    }

    #[test]
    fn failure_leaves_document_untouched() {
        let mut doc = json!({"schema_version": "0.0.0", "general": {}});
        let before = doc.clone();
        let ms: [&dyn Migration; 1] = [&M0_0_1];
        let err = run(&mut doc, &ms, SchemaVersion::new(1, 0, 0)).unwrap_err();
        assert!(matches!(err, MigrateError::Failed { .. }), "{err}");
        assert_eq!(doc, before);
    }

    #[test]
    fn newer_documents_are_refused() {
        let mut doc = json!({"schema_version": "9.0.0"});
        assert!(matches!(
            run(&mut doc, &[], SCHEMA_VERSION),
            Err(MigrateError::TooNew { .. })
        ));
        assert_eq!(
            run(&mut json!({}), &[], SCHEMA_VERSION),
            Err(MigrateError::NoVersion)
        );
    }

    #[test]
    fn head_needs_no_migration() {
        let mut doc = serde_json::to_value(crate::Document::factory()).unwrap();
        assert!(to_head(&mut doc).unwrap().is_empty());
    }
}
