//! First-boot seed: an OPNsense `config.xml` dropped into the seed folder
//! (`$SENSR_SEED_DIR`, the FAT partition of a freshly written image) is
//! imported once, before the boot apply (docs/PLAN.md §6).
//!
//! It is imported only onto a store that holds nothing but the factory
//! revision, so a seed left on the partition never overwrites a box that
//! has been configured since. Each seed file is imported at most once
//! (its hash is recorded); the import report is kept next to the store.

use std::path::{Path, PathBuf};

use sensr_import_opnsense::opnsense::{ImportOptions, import_config};

use crate::store::{ConfigStore, NewRevision, StoreError, write_atomic};

/// What happened to the seed folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedOutcome {
    /// No `config.xml` in the folder.
    NoSeed,
    /// This exact file was imported before.
    AlreadyImported,
    /// The store already has configuration beyond the factory revision.
    StoreNotEmpty,
    /// Imported as this revision; `clean` is false when nodes were left
    /// unmapped unexpectedly (see the report file).
    Imported {
        /// The new revision.
        revision: u64,
        /// No unexpected unmapped nodes.
        clean: bool,
        /// Where the report was written.
        report: PathBuf,
    },
}

/// Seed failures.
#[derive(Debug, thiserror::Error)]
pub enum SeedError {
    /// Reading the seed or writing the marker/report.
    #[error("seed i/o at {path}: {source}")]
    Io {
        /// File involved.
        path: PathBuf,
        /// Cause.
        source: std::io::Error,
    },
    /// The file is not a readable `config.xml`.
    #[error("seed {path} is not a readable config.xml: {message}")]
    Parse {
        /// File involved.
        path: PathBuf,
        /// Parser message.
        message: String,
    },
    /// Storing the imported document failed (e.g. it does not validate).
    #[error("storing the imported seed: {0}")]
    Store(#[from] StoreError),
}

/// Imports `<seed_dir>/config.xml` into `store` if appropriate. `state_dir`
/// holds the "already imported" marker and the report.
pub fn import_seed(
    store: &mut dyn ConfigStore,
    seed_dir: &Path,
    state_dir: &Path,
) -> Result<SeedOutcome, SeedError> {
    let path = seed_dir.join("config.xml");
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(SeedOutcome::NoSeed),
        Err(source) => return Err(SeedError::Io { path, source }),
    };
    let io = |path: &Path| {
        let path = path.to_owned();
        move |source| SeedError::Io { path, source }
    };
    let hash = blake3::hash(&bytes).to_hex().to_string();
    let marker = state_dir.join("seed-imported");
    if std::fs::read_to_string(&marker).is_ok_and(|m| m.trim() == hash) {
        return Ok(SeedOutcome::AlreadyImported);
    }
    if store.history(2)?.len() > 1 {
        std::fs::create_dir_all(state_dir).map_err(io(state_dir))?;
        write_atomic(&marker, hash.as_bytes()).map_err(io(&marker))?;
        return Ok(SeedOutcome::StoreNotEmpty);
    }
    let text = String::from_utf8(bytes).map_err(|e| SeedError::Parse {
        path: path.clone(),
        message: e.to_string(),
    })?;
    let imported =
        import_config(&text, &ImportOptions::default()).map_err(|e| SeedError::Parse {
            path: path.clone(),
            message: e.to_string(),
        })?;
    let document = serde_json::to_value(&imported.document).map_err(|e| SeedError::Parse {
        path: path.clone(),
        message: e.to_string(),
    })?;
    let info = store.commit(NewRevision {
        document,
        username: "sensr-agent@system".into(),
        description: format!("first boot: import {}", path.display()),
        impersonated_by: None,
    })?;
    std::fs::create_dir_all(state_dir).map_err(io(state_dir))?;
    let report = state_dir.join("import-report.txt");
    write_atomic(&report, imported.report.to_string().as_bytes()).map_err(io(&report))?;
    write_atomic(&marker, hash.as_bytes()).map_err(io(&marker))?;
    Ok(SeedOutcome::Imported {
        revision: info.id,
        clean: imported.report.is_clean(),
        report,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SqliteStore;

    const HOME_ROUTER: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sensr-import-opnsense/tests/fixtures/corpus/home-router.xml"
    );

    #[test]
    fn imports_once_onto_a_factory_store() {
        let seed = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let mut store = SqliteStore::in_memory().unwrap();
        assert_eq!(
            import_seed(&mut store, seed.path(), state.path()).unwrap(),
            SeedOutcome::NoSeed
        );

        std::fs::copy(HOME_ROUTER, seed.path().join("config.xml")).unwrap();
        match import_seed(&mut store, seed.path(), state.path()).unwrap() {
            SeedOutcome::Imported {
                revision, report, ..
            } => {
                assert_eq!(revision, 2);
                assert!(
                    std::fs::read_to_string(report)
                        .unwrap()
                        .contains("## mapped")
                );
            }
            other => panic!("{other:?}"),
        }
        let head = store.head().unwrap().unwrap();
        assert_eq!(head.document["interfaces"]["lan"]["device"], "igc1");
        assert_eq!(
            import_seed(&mut store, seed.path(), state.path()).unwrap(),
            SeedOutcome::AlreadyImported
        );
    }

    #[test]
    fn never_overwrites_a_configured_box() {
        let seed = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let mut store = SqliteStore::in_memory().unwrap();
        let mut doc = store.head().unwrap().unwrap().document;
        doc["system"]["hostname"] = serde_json::json!("configured");
        store
            .commit(NewRevision {
                document: doc,
                username: "root@unix".into(),
                description: "by hand".into(),
                impersonated_by: None,
            })
            .unwrap();
        std::fs::copy(HOME_ROUTER, seed.path().join("config.xml")).unwrap();
        assert_eq!(
            import_seed(&mut store, seed.path(), state.path()).unwrap(),
            SeedOutcome::StoreNotEmpty
        );
        assert_eq!(store.head().unwrap().unwrap().info.id, 2);
    }

    #[test]
    fn garbage_seed_is_an_error_and_stores_nothing() {
        let seed = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let mut store = SqliteStore::in_memory().unwrap();
        std::fs::write(seed.path().join("config.xml"), "<opnsense><unclosed>").unwrap();
        assert!(import_seed(&mut store, seed.path(), state.path()).is_err());
        assert_eq!(store.head().unwrap().unwrap().info.id, 1);
    }
}
