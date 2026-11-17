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

use sensr_config::{CommitMeta, CommitOutcome, Store, StoreError};

use crate::store::{to_ipc, write_atomic};

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
        /// Items a partial import dropped (empty for a full import).
        dropped: Vec<String>,
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
    /// Storing the imported document failed.
    #[error("storing the imported seed: {0}")]
    Store(#[from] StoreError),
    /// The imported document does not validate; nothing was stored. The
    /// full report, validation errors included, is in `report` (and in the
    /// seed folder).
    #[error("{path} does not validate ({} problem(s)); see {report}: {}", issues.len(), issues.join("; "))]
    Rejected {
        /// The seed file.
        path: PathBuf,
        /// `path: message` per problem.
        issues: Vec<String>,
        /// Where the report was written.
        report: String,
    },
}

/// What to do with a seed `config.xml` whose import does not validate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ImportMode {
    /// Import nothing; keep booting on the factory config (the safe default).
    #[default]
    Strict,
    /// Drop the items that fail validation, import the rest, and list what
    /// was dropped in the report.
    Partial,
}

fn issue_lines(v: &sensr_schema::Validations) -> Vec<String> {
    crate::store::issues(v)
        .into_iter()
        .map(|i| format!("{}: {}", i.path, i.message))
        .collect()
}

/// Writes `text` as `import-report.txt` to the state directory and, best
/// effort, to the seed folder (a FAT partition the operator can read on a
/// laptop). Returns where it landed.
fn write_report(state_dir: &Path, seed_dir: &Path, text: &str) -> Vec<PathBuf> {
    let mut written = Vec::new();
    for dir in [state_dir, seed_dir] {
        let path = dir.join("import-report.txt");
        let ok =
            std::fs::create_dir_all(dir).is_ok() && write_atomic(&path, text.as_bytes()).is_ok();
        if ok {
            written.push(path);
        } else {
            tracing::warn!(path = %path.display(), "cannot write the import report");
        }
    }
    written
}

/// Removes the collection item a validation path points into
/// (`firewall.rules.<uuid>.source` → `firewall.rules.<uuid>`), so a partial
/// import can keep everything else. Returns the removed path.
fn drop_item(doc: &mut serde_json::Value, path: &str) -> Option<String> {
    let segs: Vec<&str> = path.split('.').collect();
    for len in (2..=segs.len().min(3)).rev() {
        let (parent, key) = (&segs[..len - 1], segs[len - 1]);
        let mut cur = &mut *doc;
        for s in parent {
            cur = cur.get_mut(*s)?;
        }
        if let Some(m) = cur.as_object_mut()
            && m.remove(key).is_some()
        {
            return Some(segs[..len].join("."));
        }
    }
    None
}

/// Drops invalid items until the document validates (or nothing more can
/// be dropped). Returns the document and what was dropped, with why.
fn partial(mut doc: sensr_schema::Document) -> (sensr_schema::Document, Vec<String>) {
    let mut dropped = Vec::new();
    for _ in 0..256 {
        let v = doc.validate();
        if v.is_empty() {
            break;
        }
        let mut json = serde_json::to_value(&doc).unwrap_or_default();
        let mut progress = false;
        for i in crate::store::issues(&v) {
            if let Some(p) = drop_item(&mut json, &i.path) {
                dropped.push(format!("{p} ({}: {})", i.path, i.message));
                progress = true;
            }
        }
        match serde_json::from_value(json) {
            Ok(d) if progress => doc = d,
            _ => break,
        }
    }
    (doc, dropped)
}

/// Imports `<seed_dir>/config.xml` into `store` if appropriate. `state_dir`
/// holds the "already imported" marker and the report.
pub fn import_seed(
    store: &Store,
    seed_dir: &Path,
    state_dir: &Path,
    mode: ImportMode,
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
    if store.history(2, None)?.len() > 1 {
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
    let problems = imported.document.validate();
    let (document, dropped) = if problems.is_empty() {
        (imported.document.clone(), Vec::new())
    } else {
        let lines = issue_lines(&problems);
        for l in &lines {
            tracing::error!(seed = %path.display(), "import does not validate: {l}");
        }
        if mode == ImportMode::Strict {
            let text = format!(
                "{}\n## rejected: the import does not validate, nothing was imported\n\n{}\n\n\
                 Fix the source (or boot with partial seed import) and reboot;\n\
                 config.xml is retried on every boot until it imports.\n",
                imported.report,
                lines
                    .iter()
                    .map(|l| format!("- {l}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
            let written = write_report(state_dir, seed_dir, &text);
            return Err(SeedError::Rejected {
                path,
                issues: lines,
                report: written
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }
        let (doc, dropped) = partial(imported.document.clone());
        for d in &dropped {
            tracing::warn!(seed = %path.display(), "partial import dropped {d}");
        }
        (doc, dropped)
    };
    let outcome = store.import(
        &document,
        CommitMeta::new(
            "sensr-agent@system",
            if dropped.is_empty() {
                format!("first boot: import {}", path.display())
            } else {
                format!(
                    "first boot: partial import of {} ({} item(s) dropped)",
                    path.display(),
                    dropped.len()
                )
            },
        ),
    )?;
    let mut text = imported.report.to_string();
    if !dropped.is_empty() {
        text += &format!(
            "\n## dropped (partial import): these items did not validate\n\n{}\n",
            dropped
                .iter()
                .map(|d| format!("- {d}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    let report = write_report(state_dir, seed_dir, &text)
        .into_iter()
        .next()
        .unwrap_or_else(|| state_dir.join("import-report.txt"));
    std::fs::create_dir_all(state_dir).map_err(io(state_dir))?;
    write_atomic(&marker, hash.as_bytes()).map_err(io(&marker))?;
    let revision = match outcome {
        CommitOutcome::Committed(m) => to_ipc(m.id),
        CommitOutcome::Unchanged(id) => to_ipc(id),
    };
    Ok(SeedOutcome::Imported {
        revision,
        clean: imported.report.is_clean() && dropped.is_empty(),
        report,
        dropped,
    })
}

/// What `seed.toml` may say (PLAN §6). Unknown keys are refused so a typo
/// is reported instead of silently ignored.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedToml {
    hostname: Option<String>,
    domain: Option<String>,
    /// interface id → the card: MAC address or current kernel name
    #[serde(default)]
    interfaces: std::collections::BTreeMap<String, String>,
}

/// Applies the seed folder's `seed.toml` (hostname, domain, which card is
/// which interface) and `ifnames` (`<mac> <name>`: the interface on device
/// `<name>`, e.g. an imported OPNsense `igc0`, is bound to that card), each
/// at most once, as one revision on top of whatever `config.xml` imported.
/// Returns notes for the log; nothing is committed when nothing applies.
pub fn apply_seed_files(
    store: &Store,
    seed_dir: &Path,
    state_dir: &Path,
    nics: &[crate::ifnames::HostNic],
) -> Result<Vec<String>, SeedError> {
    let io = |path: &Path| {
        let path = path.to_owned();
        move |source| SeedError::Io { path, source }
    };
    let mut notes = Vec::new();
    let mut doc = store.head()?.document;
    let mut markers = Vec::new();
    // authorized_keys is renamed to .applied once imported (PLAN §6); the
    // image's sensr-seed-ssh-keys stopgap only copies it, never renames.
    let keys_path = seed_dir.join("authorized_keys");
    let mut rename_keys = false;
    match std::fs::read_to_string(&keys_path) {
        Ok(text) => {
            let keys =
                crate::ssh::parse_authorized_keys(&text).map_err(|message| SeedError::Parse {
                    path: keys_path.clone(),
                    message,
                })?;
            let added =
                crate::ssh::add_root_keys(&mut doc, &keys).map_err(|message| SeedError::Parse {
                    path: keys_path.clone(),
                    message,
                })?;
            notes.push(format!("authorized_keys: {added} key(s) added for root"));
            rename_keys = true;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(SeedError::Io {
                path: keys_path,
                source,
            });
        }
    }
    for name in ["seed.toml", "ifnames"] {
        let path = seed_dir.join(name);
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => return Err(SeedError::Io { path, source }),
        };
        let marker = state_dir.join(format!("{name}-applied"));
        let hash = blake3::hash(text.as_bytes()).to_hex().to_string();
        if std::fs::read_to_string(&marker).is_ok_and(|m| m.trim() == hash) {
            continue;
        }
        let parse = |message: String| SeedError::Parse {
            path: path.clone(),
            message,
        };
        if name == "seed.toml" {
            let seed: SeedToml = toml::from_str(&text).map_err(|e| parse(e.to_string()))?;
            if let Some(h) = seed.hostname {
                doc.system.hostname = h
                    .parse()
                    .map_err(|_| parse(format!("bad hostname {h:?}")))?;
            }
            if let Some(d) = seed.domain {
                doc.system.domain = d.parse().map_err(|_| parse(format!("bad domain {d:?}")))?;
            }
            for (id, card) in &seed.interfaces {
                crate::ifnames::assign(&mut doc, id, card, nics)
                    .map_err(|e| parse(format!("interfaces.{id}: {e}")))?;
                notes.push(format!("seed.toml: {id} = {card}"));
            }
        } else {
            let lines = crate::ifnames::parse_ifnames(&text).map_err(parse)?;
            for unused in crate::ifnames::apply_ifnames(&mut doc, &lines) {
                notes.push(format!("ifnames: no interface uses device {unused}"));
            }
            notes.push(format!("ifnames: {} card(s) pinned", lines.len()));
        }
        markers.push((marker, hash));
    }
    if markers.is_empty() && !rename_keys {
        return Ok(notes);
    }
    let v = doc.validate();
    if !v.is_empty() {
        return Err(SeedError::Store(StoreError::Invalid(v)));
    }
    store.import(
        &doc,
        CommitMeta::new(
            "sensr-agent@system",
            "first boot: seed.toml / ifnames / authorized_keys",
        ),
    )?;
    if rename_keys {
        let done = seed_dir.join("authorized_keys.applied");
        std::fs::rename(&keys_path, &done).map_err(io(&keys_path))?;
    }
    std::fs::create_dir_all(state_dir).map_err(io(state_dir))?;
    for (marker, hash) in markers {
        write_atomic(&marker, hash.as_bytes()).map_err(io(&marker))?;
    }
    Ok(notes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::in_memory;
    use sensr_schema::PathAccess;

    const HOME_ROUTER: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sensr-import-opnsense/tests/fixtures/corpus/home-router.xml"
    );

    #[test]
    fn imports_once_onto_a_factory_store() {
        let seed = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let store = in_memory();
        assert_eq!(
            import_seed(&store, seed.path(), state.path(), ImportMode::Strict).unwrap(),
            SeedOutcome::NoSeed
        );

        std::fs::copy(HOME_ROUTER, seed.path().join("config.xml")).unwrap();
        match import_seed(&store, seed.path(), state.path(), ImportMode::Strict).unwrap() {
            SeedOutcome::Imported {
                revision, report, ..
            } => {
                assert!(
                    seed.path().join("import-report.txt").exists(),
                    "report in the seed folder too"
                );
                assert_eq!(revision, 2);
                assert!(
                    std::fs::read_to_string(report)
                        .unwrap()
                        .contains("## mapped")
                );
            }
            other => panic!("{other:?}"),
        }
        let head = store.head().unwrap();
        assert_eq!(
            head.document.get_by_path("interfaces.lan.device").unwrap(),
            "igc1"
        );
        assert_eq!(
            import_seed(&store, seed.path(), state.path(), ImportMode::Strict).unwrap(),
            SeedOutcome::AlreadyImported
        );
    }

    #[test]
    fn never_overwrites_a_configured_box() {
        let seed = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let store = in_memory();
        let mut doc = store.head().unwrap().document;
        doc.system.hostname = "configured".parse().unwrap();
        store
            .commit(&doc, CommitMeta::new("root@unix", "by hand"))
            .unwrap();
        std::fs::copy(HOME_ROUTER, seed.path().join("config.xml")).unwrap();
        assert_eq!(
            import_seed(&store, seed.path(), state.path(), ImportMode::Strict).unwrap(),
            SeedOutcome::StoreNotEmpty
        );
        assert_eq!(store.head_id().unwrap().0, 2);
    }

    #[test]
    fn seed_toml_and_ifnames_bind_cards() {
        use crate::ifnames::HostNic;
        let nic = |name: &str, mac: &str| HostNic {
            name: name.into(),
            mac: mac.into(),
            permanent_mac: None,
            driver: None,
            bus: None,
            bus_path: None,
            speed_mbps: None,
            carrier: None,
            operstate: "up".into(),
        };
        let nics = [
            nic("end0", "2c:cf:67:00:00:01"),
            nic("enx00e04c680001", "00:e0:4c:68:00:01"),
        ];
        let seed = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let store = in_memory();
        // the OPNsense import names its cards igc0/igc1 ...
        std::fs::copy(HOME_ROUTER, seed.path().join("config.xml")).unwrap();
        import_seed(&store, seed.path(), state.path(), ImportMode::Strict).unwrap();
        // ... ifnames maps them to this Pi's cards, seed.toml names the box
        std::fs::write(
            seed.path().join("ifnames"),
            "00:e0:4c:68:00:01 igc0   # USB dongle is WAN\n2c:cf:67:00:00:01 igc1\n",
        )
        .unwrap();
        std::fs::write(seed.path().join("seed.toml"), "hostname = \"pi-gw\"\n").unwrap();
        let notes = apply_seed_files(&store, seed.path(), state.path(), &nics).unwrap();
        assert!(notes.iter().any(|n| n.contains("2 card(s)")), "{notes:?}");
        let head = store.head().unwrap().document;
        assert_eq!(head.get_by_path("system.hostname").unwrap(), "pi-gw");
        assert_eq!(
            head.get_by_path("interfaces.wan.match_mac").unwrap(),
            "00:e0:4c:68:00:01"
        );
        assert_eq!(
            head.get_by_path("interfaces.wan.device").unwrap(),
            "igc0",
            "kept"
        );
        let rev = store.head_id().unwrap();
        // applied once
        apply_seed_files(&store, seed.path(), state.path(), &nics).unwrap();
        assert_eq!(store.head_id().unwrap(), rev);

        // seed.toml by kernel name; a typo is an error that stores nothing
        let seed = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let store = in_memory();
        std::fs::write(
            seed.path().join("seed.toml"),
            "[interfaces]\nwan = \"enx00e04c680001\"\nlan = \"end0\"\n",
        )
        .unwrap();
        apply_seed_files(&store, seed.path(), state.path(), &nics).unwrap();
        let head = store.head().unwrap().document;
        assert_eq!(head.get_by_path("interfaces.lan.device").unwrap(), "lan");
        assert_eq!(
            head.get_by_path("interfaces.lan.match_mac").unwrap(),
            "2c:cf:67:00:00:01"
        );
        std::fs::write(seed.path().join("seed.toml"), "hostnmae = \"x\"\n").unwrap();
        assert!(apply_seed_files(&store, seed.path(), state.path(), &nics).is_err());
    }

    #[test]
    fn seed_authorized_keys_go_to_root_and_are_renamed() {
        let seed = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let store = in_memory();
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC8u6EM1pQBx4cCeioZw0En7NYq7SYguxI03/I6QYJwx admin@laptop";
        std::fs::write(seed.path().join("authorized_keys"), format!("{key}\n")).unwrap();
        apply_seed_files(&store, seed.path(), state.path(), &[]).unwrap();
        let doc = store.head().unwrap().document;
        let root = doc.system.users.values().find(|u| u.uid == 0).unwrap();
        assert_eq!(root.authorized_keys[0].to_string(), key);
        assert!(!seed.path().join("authorized_keys").exists());
        assert!(seed.path().join("authorized_keys.applied").exists());
        let rev = store.head_id().unwrap();
        apply_seed_files(&store, seed.path(), state.path(), &[]).unwrap();
        assert_eq!(store.head_id().unwrap(), rev, "applied once");
    }

    /// A seed that does not validate: strict imports nothing and says why
    /// in both report locations; partial imports the rest.
    #[test]
    fn invalid_seed_is_reported_strict_or_partial() {
        let text = std::fs::read_to_string(HOME_ROUTER).unwrap();
        // two aliases with one name: the import maps both, the schema
        // refuses the pair
        let broken = text.replacen("<name>RFC1918_NETS</name>", "<name>NAS_HOST</name>", 1);
        assert_ne!(broken, text, "fixture has the alias");
        let seed = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        std::fs::write(seed.path().join("config.xml"), &broken).unwrap();
        let store = in_memory();
        match import_seed(&store, seed.path(), state.path(), ImportMode::Strict) {
            Err(SeedError::Rejected { issues, .. }) => assert!(!issues.is_empty()),
            other => panic!("{other:?}"),
        }
        assert_eq!(store.head_id().unwrap().0, 1, "nothing stored");
        for dir in [seed.path(), state.path()] {
            let r = std::fs::read_to_string(dir.join("import-report.txt")).unwrap();
            assert!(r.contains("## rejected") && r.contains("## mapped"), "{r}");
        }
        assert!(
            seed.path().join("config.xml").exists(),
            "seed left in place"
        );
        assert!(
            !state.path().join("seed-imported").exists(),
            "retried next boot"
        );

        match import_seed(&store, seed.path(), state.path(), ImportMode::Partial).unwrap() {
            SeedOutcome::Imported { dropped, clean, .. } => {
                assert!(!dropped.is_empty() && !clean, "{dropped:?}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(store.head_id().unwrap().0, 2);
        let r = std::fs::read_to_string(seed.path().join("import-report.txt")).unwrap();
        assert!(r.contains("## dropped"), "{r}");
    }

    #[test]
    fn garbage_seed_is_an_error_and_stores_nothing() {
        let seed = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let store = in_memory();
        std::fs::write(seed.path().join("config.xml"), "<opnsense><unclosed>").unwrap();
        assert!(import_seed(&store, seed.path(), state.path(), ImportMode::Strict).is_err());
        assert_eq!(store.head_id().unwrap().0, 1);
    }
}
