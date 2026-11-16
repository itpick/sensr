//! Store behaviour: fallback default, commits, history, restore, diff,
//! export, events, concurrency, migrations and commit-confirm.

use std::sync::Arc;

use pretty_assertions::assert_eq;
use sensr_config::{
    CommitKind, CommitMeta, CommitOutcome, ConfirmState, PatchOp, RevisionId, Store, StoreError,
    StoreOptions,
};
use sensr_schema::migrate::Migration;
use sensr_schema::models::firewall::Alias;
use sensr_schema::{Document, PathAccess, SchemaVersion, Section};
use serde_json::{Value, json};

fn meta(d: &str) -> CommitMeta {
    CommitMeta::new("root@127.0.0.1", d)
}

fn mem() -> Store {
    Store::open_in_memory(Document::factory, StoreOptions::default()).unwrap()
}

fn renamed(doc: &Document, host: &str) -> Document {
    let mut d = doc.clone();
    d.system.hostname = host.parse().unwrap();
    d
}

#[test]
fn load_falls_back_to_default_document_t0001() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path().join("config.db"), Document::factory).unwrap();
    let head = store.head().unwrap();
    assert_eq!(head.meta.id, RevisionId(1));
    assert_eq!(head.meta.kind, CommitKind::Initial);
    assert_eq!(head.document, Document::factory());
    assert!(!head.document.firewall.rules.is_empty());
    drop(store);
    // Reopening never re-applies the default.
    let store = Store::open(dir.path().join("config.db"), Document::default).unwrap();
    assert_eq!(store.head().unwrap().document, Document::factory());
}

#[test]
fn array_items_persist_in_order_t0028() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.db");
    let store = Store::open(&path, Document::factory).unwrap();
    let mut doc = store.head().unwrap().document;
    doc.firewall.aliases.clear();
    for n in 0..10 {
        let a: Alias = serde_json::from_value(json!({"name": format!("a{n}"), "content": {"type": "port", "entries": [format!("{}", 1000 + n)]}})).unwrap();
        doc.firewall.aliases.push(a);
    }
    store.commit(&doc, meta("ten aliases")).unwrap();
    drop(store);
    let store = Store::open(&path, Document::default).unwrap();
    let names: Vec<String> = store
        .head()
        .unwrap()
        .document
        .firewall
        .aliases
        .values()
        .map(|a| a.name.to_string())
        .collect();
    assert_eq!(names, (0..10).map(|n| format!("a{n}")).collect::<Vec<_>>());
}

#[test]
fn commit_validates_and_skips_no_ops() {
    let store = mem();
    let head = store.head().unwrap();
    assert_eq!(
        store.commit(&head.document, meta("same")).unwrap(),
        CommitOutcome::Unchanged(RevisionId(1))
    );
    let mut bad = head.document.clone();
    bad.set_by_path("interfaces.lan.device", json!("eth0"))
        .unwrap();
    match store.commit(&bad, meta("bad")) {
        Err(StoreError::Invalid(v)) => assert!(v.get("interfaces.lan.device").is_some(), "{v}"),
        other => panic!("expected validation failure, got {other:?}"),
    }
    assert_eq!(store.head_id().unwrap(), RevisionId(1));
    let out = store
        .commit(&renamed(&head.document, "fw1"), meta("rename"))
        .unwrap();
    let CommitOutcome::Committed(m) = out else {
        panic!("{out:?}")
    };
    assert_eq!(
        (m.id, m.parent, m.kind),
        (RevisionId(2), Some(RevisionId(1)), CommitKind::Commit)
    );
    assert_eq!(m.meta.username, "root@127.0.0.1");
    assert_eq!(m.hash.len(), 64);
}

#[test]
fn commit_json_value() {
    let store = mem();
    let mut v = serde_json::to_value(store.head().unwrap().document).unwrap();
    v["system"]["hostname"] = json!("fromjson");
    let out = store.commit_value(&v, meta("json")).unwrap();
    assert_eq!(out.id(), RevisionId(2));
    assert_eq!(
        store.head().unwrap().document.system.hostname.as_str(),
        "fromjson"
    );
    v["bogus"] = json!(1);
    assert!(matches!(
        store.commit_value(&v, meta("bad")),
        Err(StoreError::Json(_))
    ));
    v.as_object_mut().unwrap().remove("bogus");
    v["schema_version"] = json!("9.0.0");
    assert!(matches!(
        store.commit_value(&v, meta("new")),
        Err(StoreError::Migration(_))
    ));
}

#[test]
fn optimistic_conflict_and_edit() {
    let store = mem();
    let base = store.head().unwrap();
    store
        .commit(&renamed(&base.document, "a"), meta("a"))
        .unwrap();
    let err = store
        .commit_if_head(base.meta.id, &renamed(&base.document, "b"), meta("b"))
        .unwrap_err();
    assert!(
        matches!(
            err,
            StoreError::Conflict {
                expected: RevisionId(1),
                head: RevisionId(2)
            }
        ),
        "{err}"
    );
    let out = store
        .edit(meta("edit"), |d| {
            d.set_by_path_text("system.domain", "example.org")
        })
        .unwrap();
    assert_eq!(out.id(), RevisionId(3));
    let head = store.head().unwrap().document;
    assert_eq!(
        (head.system.hostname.as_str(), head.system.domain.as_str()),
        ("a", "example.org")
    );
    let err = store
        .edit(meta("nope"), |d| {
            d.set_by_path_text("system.domain", "not valid")
        })
        .unwrap_err();
    assert!(matches!(err, StoreError::Rejected(_)), "{err}");
}

#[test]
fn restore_then_commit_yields_new_revision() {
    let store = mem();
    let base = store.head().unwrap().document;
    store.commit(&renamed(&base, "two"), meta("2")).unwrap();
    store.commit(&renamed(&base, "three"), meta("3")).unwrap();
    let r = store.restore(RevisionId(1), meta("back")).unwrap();
    let CommitOutcome::Committed(m) = r else {
        panic!()
    };
    assert_eq!(
        (m.id, m.kind, m.restored_from),
        (RevisionId(4), CommitKind::Restore, Some(RevisionId(1)))
    );
    assert_eq!(store.head().unwrap().document, base);
    store.commit(&renamed(&base, "five"), meta("5")).unwrap();
    let ids: Vec<i64> = store
        .history(100, None)
        .unwrap()
        .iter()
        .map(|m| m.id.0)
        .collect();
    assert_eq!(ids, [5, 4, 3, 2, 1]);
    assert_eq!(
        store
            .get(RevisionId(3))
            .unwrap()
            .document
            .system
            .hostname
            .as_str(),
        "three"
    );
    assert_eq!(
        store
            .history(2, Some(RevisionId(4)))
            .unwrap()
            .iter()
            .map(|m| m.id.0)
            .collect::<Vec<_>>(),
        [3, 2]
    );
    assert!(matches!(
        store.get(RevisionId(99)),
        Err(StoreError::NotFound(RevisionId(99)))
    ));
}

#[test]
fn diff_between_revisions() {
    let store = mem();
    let base = store.head().unwrap().document;
    let mut d = renamed(&base, "fw1");
    d.dns.dnssec = true;
    store.commit(&d, meta("x")).unwrap();
    let diff = store.diff(RevisionId(1), RevisionId(2)).unwrap();
    assert_eq!(diff.sections, [Section::System, Section::Dns]);
    assert_eq!(
        diff.patch,
        [
            PatchOp::Replace {
                path: "/system/hostname".into(),
                value: json!("fw1")
            },
            PatchOp::Replace {
                path: "/dns/dnssec".into(),
                value: json!(true)
            },
        ]
    );
    assert!(
        diff.text
            .contains("-    \"hostname\": \"sensr\",\n+    \"hostname\": \"fw1\","),
        "{}",
        diff.text
    );
}

#[test]
fn export_is_atomic_private_and_redacted() {
    let dir = tempfile::tempdir().unwrap();
    let export = dir.path().join("config.json");
    let store = Store::open_with(
        dir.path().join("config.db"),
        Document::factory,
        StoreOptions {
            export_path: Some(export.clone()),
            ..StoreOptions::default()
        },
    )
    .unwrap();
    let initial: Document =
        serde_json::from_str(&std::fs::read_to_string(&export).unwrap()).unwrap();
    assert_eq!(initial, Document::factory());
    let mut d = store.head().unwrap().document;
    d.set_by_path(
        "wireguard.servers.00000000-0000-0000-0000-000000000001",
        json!({"name": "wg0", "instance": 0, "private_key": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="}),
    )
    .unwrap();
    store.commit(&d, meta("wg")).unwrap();
    let text = std::fs::read_to_string(&export).unwrap();
    assert!(!text.contains("yAnz5TF"), "secret leaked into export");
    assert!(text.contains("\"private_key\": \"*redacted*\""));
    // The store itself keeps the real key.
    assert_eq!(store.head().unwrap().document, d);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&export).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty());
}

#[cfg(unix)]
#[test]
fn database_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.db");
    let store = Store::open(&path, Document::factory).unwrap();
    store
        .commit(&renamed(&store.head().unwrap().document, "x"), meta("x"))
        .unwrap();
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    let wal = dir.path().join("config.db-wal");
    if wal.exists() {
        assert_eq!(mode(&wal), 0o600);
    }
    drop(store);
    // An existing, too-open database is tightened on open.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    drop(Store::open(&path, Document::default).unwrap());
    assert_eq!(mode(&path), 0o600);
}

#[test]
fn secrets_are_stored_outside_the_documents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.db");
    let store = Store::open(&path, Document::factory).unwrap();
    let mut d = store.head().unwrap().document;
    let key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    d.set_by_path(
        "wireguard.servers.00000000-0000-0000-0000-000000000001",
        json!({"name": "wg0", "instance": 0, "private_key": key}),
    )
    .unwrap();
    store.commit(&d, meta("wg")).unwrap();
    // Changing only the secret is a change.
    let mut d2 = d.clone();
    d2.set_by_path(
        "wireguard.servers.00000000-0000-0000-0000-000000000001.private_key",
        json!("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="),
    )
    .unwrap();
    let ev = store.subscribe();
    let out = store.commit(&d2, meta("rotate")).unwrap();
    assert_eq!(out.id(), RevisionId(3));
    drop(ev);
    assert_eq!(store.get(RevisionId(2)).unwrap().document, d);
    assert_eq!(store.head().unwrap().document, d2);
    drop(store);

    let conn = rusqlite_conn(&path);
    let docs: Vec<String> = conn
        .prepare("SELECT document FROM revisions")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert!(
        docs.iter()
            .all(|d| !d.contains(key) && !d.contains("xTIBA5")),
        "key material in a revision document"
    );
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM secrets", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 2);
    // A tampered secret fails the content hash.
    conn.execute(
        "UPDATE secrets SET value = '\"AAAA\"' WHERE revision = 3",
        [],
    )
    .unwrap();
    drop(conn);
    let err = Store::open(&path, Document::default).unwrap_err();
    assert!(
        matches!(
            err,
            StoreError::Corrupt {
                id: RevisionId(3),
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn commits_are_broadcast_with_changed_sections() {
    let store = mem();
    let mut rx = store.subscribe();
    let base = store.head().unwrap().document;
    let mut d = base.clone();
    d.firewall.settings.flow_offload = true;
    store.commit(&d, meta("offload")).unwrap();
    store.commit(&d, meta("no-op")).unwrap();
    let ev = rx.try_recv().unwrap();
    assert_eq!(ev.revision.id, RevisionId(2));
    assert_eq!(ev.changed, [Section::Firewall]);
    assert!(
        rx.try_recv().is_err(),
        "unchanged commits are not broadcast"
    );
}

#[test]
fn audit_records_every_change() {
    let store = mem();
    let base = store.head().unwrap().document;
    store.commit(&renamed(&base, "x"), meta("rename")).unwrap();
    store.restore(RevisionId(1), meta("undo")).unwrap();
    store
        .record("root", "apply", Some(RevisionId(3)), "ok")
        .unwrap();
    let rows: Vec<(String, Option<i64>, String)> = store
        .audit(10)
        .unwrap()
        .into_iter()
        .map(|a| (a.action, a.revision.map(|r| r.0), a.detail))
        .collect();
    assert_eq!(
        rows,
        [
            ("apply".into(), Some(3), "ok".into()),
            ("restore".into(), Some(3), "undo (from revision 1)".into()),
            ("commit".into(), Some(2), "rename".into()),
            ("initial".into(), Some(1), "Initial configuration".into()),
        ]
    );
}

#[test]
fn concurrent_commits_serialise() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path().join("config.db"), Document::factory).unwrap());
    let base = store.head().unwrap().document;
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let store = Arc::clone(&store);
            let base = base.clone();
            std::thread::spawn(move || {
                for i in 0..10 {
                    store
                        .commit(&renamed(&base, &format!("t{t}x{i}")), meta("c"))
                        .unwrap();
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let hist = store.history(1000, None).unwrap();
    assert_eq!(hist.len(), 81);
    // A linear chain: every revision's parent is the one before it.
    for w in hist.windows(2) {
        assert_eq!(w[0].parent, Some(w[1].id));
    }
    // A second connection (another process) sees the same history.
    let other = Store::open(dir.path().join("config.db"), Document::default).unwrap();
    assert_eq!(other.head_id().unwrap(), RevisionId(81));
}

#[test]
fn tampered_revision_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.db");
    let store = Store::open(&path, Document::factory).unwrap();
    store
        .commit(&renamed(&store.head().unwrap().document, "x"), meta("x"))
        .unwrap();
    drop(store);
    let conn = rusqlite_conn(&path);
    conn.execute(
        "UPDATE revisions SET document = replace(document, '\"x\"', '\"y\"') WHERE id = 2",
        [],
    )
    .unwrap();
    drop(conn);
    let err = Store::open(&path, Document::default).unwrap_err();
    assert!(
        matches!(
            err,
            StoreError::Corrupt {
                id: RevisionId(2),
                ..
            }
        ),
        "{err}"
    );
}

fn rusqlite_conn(path: &std::path::Path) -> rusqlite::Connection {
    rusqlite::Connection::open(path).unwrap()
}

struct Rename;
impl Migration for Rename {
    fn version(&self) -> SchemaVersion {
        SchemaVersion::new(0, 2, 0)
    }
    fn description(&self) -> &'static str {
        "rename host"
    }
    fn migrate(&self, doc: &mut Value) -> Result<(), String> {
        doc["system"]["hostname"] = json!("migrated");
        Ok(())
    }
}
static RENAME: Rename = Rename;

struct Broken;
impl Migration for Broken {
    fn version(&self) -> SchemaVersion {
        SchemaVersion::new(0, 2, 0)
    }
    fn description(&self) -> &'static str {
        "always fails"
    }
    fn migrate(&self, _: &mut Value) -> Result<(), String> {
        Err("boom".into())
    }
}
static BROKEN: Broken = Broken;

#[test]
fn head_is_migrated_on_open_and_old_revisions_read_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.db");
    drop(Store::open(&path, Document::factory).unwrap());

    let opts = |m: &'static dyn Migration| StoreOptions {
        migrations: Some(vec![m]),
        target_version: SchemaVersion::new(0, 2, 0),
        ..StoreOptions::default()
    };
    let err = Store::open_with(&path, Document::default, opts(&BROKEN)).unwrap_err();
    assert!(matches!(err, StoreError::Migration(_)), "{err}");
    // Refused, and nothing was written.
    assert_eq!(
        Store::open(&path, Document::default)
            .unwrap()
            .head_id()
            .unwrap(),
        RevisionId(1)
    );

    let store = Store::open_with(&path, Document::default, opts(&RENAME)).unwrap();
    let head = store.head().unwrap();
    assert_eq!(
        (head.meta.id, head.meta.kind),
        (RevisionId(2), CommitKind::Migrate)
    );
    assert_eq!(head.meta.schema_version, SchemaVersion::new(0, 2, 0));
    assert_eq!(head.document.system.hostname.as_str(), "migrated");
    assert!(
        head.meta.meta.description.contains("0.2.0: rename host"),
        "{}",
        head.meta.meta.description
    );
    // Revision 1 is still stored at 0.1.0 but reads back migrated.
    let old = store.get(RevisionId(1)).unwrap();
    assert_eq!(old.meta.schema_version, SchemaVersion::new(0, 1, 0));
    assert_eq!(old.document.system.hostname.as_str(), "migrated");
    drop(store);
    // A build that only knows 0.1.0 refuses the newer head.
    assert!(matches!(
        Store::open(&path, Document::default),
        Err(StoreError::Migration(_))
    ));
}

#[test]
fn commit_confirm_rolls_back_unless_confirmed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.db");
    let store = Store::open(&path, Document::factory).unwrap();
    store.mark_applied(RevisionId(1), None, "agent").unwrap();
    let base = store.head().unwrap().document;
    let new = store
        .commit(&renamed(&base, "risky"), meta("risky"))
        .unwrap()
        .id();
    let pending = ConfirmState {
        pending: new,
        rollback_to: RevisionId(1),
        deadline_ms: 1,
    };
    store.mark_applied(new, Some(pending), "agent").unwrap();
    drop(store);

    // The pending state survives a restart (reboot during the window).
    let store = Store::open(&path, Document::default).unwrap();
    assert_eq!(store.pending_confirm().unwrap(), Some(pending));
    assert_eq!(store.applied().unwrap(), Some(new));
    let out = store.rollback("agent").unwrap().unwrap();
    let head = store.head().unwrap();
    assert_eq!(
        (head.meta.id, head.meta.kind, head.meta.restored_from),
        (out.id(), CommitKind::Rollback, Some(RevisionId(1)))
    );
    assert_eq!(head.document, base);
    assert_eq!(store.pending_confirm().unwrap(), None);
    assert!(store.rollback("agent").unwrap().is_none());

    // Confirmed in time: no rollback.
    let again = store
        .commit(&renamed(&base, "fine"), meta("fine"))
        .unwrap()
        .id();
    store
        .mark_applied(
            again,
            Some(ConfirmState {
                pending: again,
                rollback_to: out.id(),
                deadline_ms: i64::MAX,
            }),
            "agent",
        )
        .unwrap();
    assert_eq!(store.confirm("root").unwrap(), Some(again));
    assert!(store.rollback("agent").unwrap().is_none());
    assert_eq!(
        store.head().unwrap().document.system.hostname.as_str(),
        "fine"
    );
    let actions: Vec<String> = store
        .audit(3)
        .unwrap()
        .into_iter()
        .map(|a| a.action)
        .collect();
    assert_eq!(actions, ["confirm", "apply", "commit"]);
}
