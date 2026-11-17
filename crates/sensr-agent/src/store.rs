//! The agent's view of `sensr-config`: opening the store and translating its
//! types and errors to the IPC vocabulary.
//!
//! [`sensr_config::Store`] is the single source of truth: revisions, the
//! applied revision and any pending commit-confirm all live in its SQLite
//! database, so they survive restarts together and can never disagree.

use std::path::{Path, PathBuf};

use sensr_config::{RevisionMeta, Store, StoreOptions};
use sensr_ipc::{RevisionId, RevisionInfo, ValidationIssue};
use sensr_schema::{Document, Validations};

/// Opens (creating with the factory document) the database at `db`,
/// exporting the redacted head to `export` after every commit. Secrets are
/// encrypted with the key in `secrets_key` when given (created on first
/// use, mode 0600).
pub fn open(
    db: &Path,
    export: Option<PathBuf>,
    secrets_key: Option<&Path>,
) -> anyhow::Result<Store> {
    use anyhow::Context;
    let secrets_key = match secrets_key {
        Some(path) => Some(
            sensr_config::SecretsKey::load_or_create(path)
                .with_context(|| format!("secrets key {}", path.display()))?,
        ),
        None => None,
    };
    let options = StoreOptions {
        export_path: export,
        secrets_key,
        ..StoreOptions::default()
    };
    Ok(Store::open_with(db, Document::factory, options)?)
}

/// An in-memory store holding the factory document (tests, `--state-dir`
/// omitted).
pub fn in_memory() -> Store {
    in_memory_with(Document::factory())
}

/// An in-memory store whose first revision is `doc`.
pub fn in_memory_with(doc: Document) -> Store {
    Store::open_in_memory(move || doc, StoreOptions::default())
        .expect("an in-memory SQLite database always opens")
}

/// IPC metadata of a stored revision.
pub fn info_of(m: &RevisionMeta) -> RevisionInfo {
    RevisionInfo {
        id: to_ipc(m.id),
        parent: m.parent.map(to_ipc),
        hash: m.hash.clone(),
        username: m.meta.username.clone(),
        time_ms: m.time_ms,
        description: m.meta.description.clone(),
        impersonated_by: m.meta.impersonated_by.clone(),
    }
}

/// A store revision number as the IPC carries it.
pub fn to_ipc(id: sensr_config::RevisionId) -> RevisionId {
    u64::try_from(id.0).unwrap_or(0)
}

/// An IPC revision number for the store (`None` if out of range, which no
/// stored revision can be).
pub fn from_ipc(id: RevisionId) -> Option<sensr_config::RevisionId> {
    i64::try_from(id).ok().map(sensr_config::RevisionId)
}

/// Schema validation results as IPC issues.
pub fn issues(v: &Validations) -> Vec<ValidationIssue> {
    v.iter()
        .flat_map(|(path, errors)| {
            errors.iter().map(move |e| ValidationIssue {
                path: path.as_str().to_owned(),
                message: e.to_string(),
            })
        })
        .collect()
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Writes `bytes` to `path` via a temp file and rename, so readers and
/// crashes never see a partial file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_from_the_factory_document_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("config.db");
        let key = dir.path().join("secrets.key");
        let s = open(&db, Some(dir.path().join("config.json")), Some(&key)).unwrap();
        let head = s.head().unwrap();
        assert_eq!(head.meta.id.0, 1);
        assert!(
            head.document
                .interfaces
                .iter()
                .any(|(id, _)| id.as_str() == "lan")
        );
        drop(s);
        let again = open(&db, None, Some(&key)).unwrap();
        assert_eq!(again.head_id().unwrap().0, 1);
        assert!(dir.path().join("config.json").exists());
    }

    #[test]
    fn revision_numbers_round_trip() {
        assert_eq!(from_ipc(7).map(to_ipc), Some(7));
        assert_eq!(from_ipc(u64::MAX), None);
    }
}
