//! The revision store.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::broadcast;

use sensr_schema::migrate::{self, Migration};
use sensr_schema::{Document, SCHEMA_VERSION, SchemaVersion, Section, Validations};

use crate::canonical::{ContentHash, canonical_json};
use crate::crypt::{SecretsKey, is_sealed};
use crate::diff::{RevisionDiff, json_diff, unified};
use crate::export::write_atomic;
use crate::schema;

/// A revision number. Revisions are numbered from 1 in commit order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RevisionId(pub i64);

impl fmt::Display for RevisionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// How a revision came about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitKind {
    /// The default document written when the store was created.
    Initial,
    /// An edit.
    Commit,
    /// A copy of an earlier revision made current again.
    Restore,
    /// Automatic return to the last confirmed revision.
    Rollback,
    /// The head brought to a newer schema version.
    Migrate,
    /// A document imported from elsewhere (OPNsense `config.xml`, a backup).
    Import,
}

impl CommitKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Initial => "initial",
            Self::Commit => "commit",
            Self::Restore => "restore",
            Self::Rollback => "rollback",
            Self::Migrate => "migrate",
            Self::Import => "import",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "initial" => Self::Initial,
            "commit" => Self::Commit,
            "restore" => Self::Restore,
            "rollback" => Self::Rollback,
            "migrate" => Self::Migrate,
            "import" => Self::Import,
            _ => return None,
        })
    }
}

/// Who made a change and why: OPNsense's revision block (`username`,
/// `description`, `impersonated_by`, `user_apitoken`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitMeta {
    /// The authenticated principal (`root@192.168.1.10`, `api:<key>`).
    pub username: String,
    /// What the change was for.
    pub description: String,
    /// The real user when acting on someone's behalf.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impersonated_by: Option<String>,
    /// The API key used, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_apitoken: Option<String>,
}

impl CommitMeta {
    /// Metadata for `username` with `description`.
    pub fn new(username: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            description: description.into(),
            impersonated_by: None,
            user_apitoken: None,
        }
    }
}

/// Everything about a revision except its document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionMeta {
    /// Number.
    pub id: RevisionId,
    /// The head this revision was committed on top of.
    pub parent: Option<RevisionId>,
    /// blake3 of the canonical JSON, hex.
    pub hash: String,
    /// Schema version the document was written with.
    pub schema_version: SchemaVersion,
    /// How it came about.
    pub kind: CommitKind,
    /// Commit time, milliseconds since the Unix epoch.
    pub time_ms: i64,
    /// For restores and rollbacks: the revision whose content was copied.
    pub restored_from: Option<RevisionId>,
    /// Who and why.
    #[serde(flatten)]
    pub meta: CommitMeta,
}

impl RevisionMeta {
    /// Commit time.
    pub fn time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(u64::try_from(self.time_ms).unwrap_or(0))
    }
}

/// A revision with its document (migrated to this build's schema if it was
/// written by an older one).
#[derive(Debug, Clone, PartialEq)]
pub struct Revision {
    /// Metadata.
    pub meta: RevisionMeta,
    /// The configuration.
    pub document: Document,
}

/// The result of a commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOutcome {
    /// A new revision was written.
    Committed(RevisionMeta),
    /// The document equals the head; nothing was written.
    Unchanged(RevisionId),
}

impl CommitOutcome {
    /// The head after the call.
    pub fn id(&self) -> RevisionId {
        match self {
            Self::Committed(m) => m.id,
            Self::Unchanged(id) => *id,
        }
    }
}

/// Broadcast after every new revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionCommitted {
    /// The new head.
    pub revision: RevisionMeta,
    /// Sections that differ from the parent; the apply engine re-renders
    /// only these.
    pub changed: Vec<Section>,
}

/// A pending commit-confirm: `pending` is applied and must be confirmed
/// before `deadline_ms`, otherwise the store rolls back to `rollback_to`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmState {
    /// The applied, unconfirmed revision.
    pub pending: RevisionId,
    /// The revision to return to.
    pub rollback_to: RevisionId,
    /// Deadline, milliseconds since the Unix epoch.
    pub deadline_ms: i64,
}

/// One audit log row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Row number.
    pub id: i64,
    /// When, milliseconds since the Unix epoch.
    pub time_ms: i64,
    /// Who.
    pub username: String,
    /// What (`commit`, `restore`, `rollback`, `confirm`, `apply`, ...).
    pub action: String,
    /// The revision involved.
    pub revision: Option<RevisionId>,
    /// Free text.
    pub detail: String,
}

/// Store failures.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database failed.
    #[error("database: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// A document could not be (de)serialised.
    #[error("document encoding: {0}")]
    Json(#[from] serde_json::Error),
    /// Writing `config.json` failed. The revision is committed; only the
    /// export is stale.
    #[error("export: {0}")]
    Export(#[from] std::io::Error),
    /// The document failed validation; nothing was written.
    #[error("validation failed:\n{0}")]
    Invalid(Validations),
    /// No such revision.
    #[error("revision {0} not found")]
    NotFound(RevisionId),
    /// The head moved since the caller read it (optimistic concurrency).
    #[error("conflict: expected head {expected}, found {head}")]
    Conflict {
        /// The head the caller based its change on.
        expected: RevisionId,
        /// The actual head.
        head: RevisionId,
    },
    /// A stored revision no longer matches its hash.
    #[error("revision {id} is corrupt: {reason}")]
    Corrupt {
        /// Which revision.
        id: RevisionId,
        /// What is wrong.
        reason: String,
    },
    /// A document could not be migrated; the store refuses to continue
    /// rather than run half-migrated (PLAN §2.4 item 5).
    #[error("migration: {0}")]
    Migration(#[from] migrate::MigrateError),
    /// The database was written by a newer build.
    #[error("database schema {found} is newer than supported {supported}")]
    TooNew {
        /// Found `user_version`.
        found: i64,
        /// Newest known.
        supported: i64,
    },
    /// An editing closure rejected the change.
    #[error("{0}")]
    Rejected(String),
}

/// Store configuration.
pub struct StoreOptions {
    /// Where to write the head as JSON after every commit; `None` to skip.
    pub export_path: Option<PathBuf>,
    /// Document migrations; `None` uses every registered one.
    pub migrations: Option<Vec<&'static dyn Migration>>,
    /// The schema version documents are migrated to (tests use older ones).
    pub target_version: SchemaVersion,
    /// Seals the secrets table at rest; `None` stores secret values in
    /// plain JSON (still out of the revision documents).
    pub secrets_key: Option<SecretsKey>,
}

impl Default for StoreOptions {
    fn default() -> Self {
        Self {
            export_path: None,
            migrations: None,
            target_version: SCHEMA_VERSION,
            secrets_key: None,
        }
    }
}

const EVENT_CAPACITY: usize = 64;
const KEY_APPLIED: &str = "applied";
const KEY_CONFIRM: &str = "confirm";

/// The configuration store. Cheap to share behind an `Arc`; all methods take
/// `&self` and serialise on an internal lock plus SQLite's write lock, so
/// concurrent commits from threads or processes form a linear history.
pub struct Store {
    conn: Mutex<Connection>,
    export_path: Option<PathBuf>,
    migrations: Vec<&'static dyn Migration>,
    target: SchemaVersion,
    events: broadcast::Sender<RevisionCommitted>,
    key: Option<SecretsKey>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("export_path", &self.export_path)
            .finish_non_exhaustive()
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

impl Store {
    /// Opens (or creates) the store at `path`. A new store starts with
    /// `default()` as revision 1 (OPNsense falls back to `config.xml.sample`
    /// the same way). If the head was written by an older schema, it is
    /// migrated and committed as a new revision before anything else.
    pub fn open(
        path: impl AsRef<Path>,
        default: impl FnOnce() -> Document,
    ) -> Result<Self, StoreError> {
        Self::open_with(path, default, StoreOptions::default())
    }

    /// [`Store::open`] with options.
    pub fn open_with(
        path: impl AsRef<Path>,
        default: impl FnOnce() -> Document,
        options: StoreOptions,
    ) -> Result<Self, StoreError> {
        let path = path.as_ref();
        restrict(path)?;
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        Self::init(conn, default, options)
    }

    /// A store that lives in memory only (tests, dry runs).
    pub fn open_in_memory(
        default: impl FnOnce() -> Document,
        options: StoreOptions,
    ) -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?, default, options)
    }

    fn init(
        mut conn: Connection,
        default: impl FnOnce() -> Document,
        options: StoreOptions,
    ) -> Result<Self, StoreError> {
        conn.busy_timeout(Duration::from_secs(10))?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let found: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if found > schema::latest() {
            return Err(StoreError::TooNew {
                found,
                supported: schema::latest(),
            });
        }
        schema::upgrade(&mut conn)?;
        let store = Self {
            conn: Mutex::new(conn),
            export_path: options.export_path,
            migrations: options.migrations.unwrap_or_else(migrate::registered),
            target: options.target_version,
            events: broadcast::channel(EVENT_CAPACITY).0,
            key: options.secrets_key,
        };
        store.seal_plain_secrets()?;
        let empty = store
            .lock()
            .query_row("SELECT COUNT(*) FROM revisions", [], |r| r.get::<_, i64>(0))?
            == 0;
        if empty {
            let doc = default();
            store.write(
                &doc,
                CommitMeta::new("(system)", "Initial configuration"),
                CommitKind::Initial,
                None,
                None,
                false,
            )?;
        } else {
            store.migrate_head()?;
            store.export_head()?;
        }
        Ok(store)
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        // A panic while holding the lock cannot leave SQLite inconsistent
        // (transactions roll back on drop), so a poisoned lock is usable.
        self.conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Receives a [`RevisionCommitted`] for every revision written after this
    /// call.
    pub fn subscribe(&self) -> broadcast::Receiver<RevisionCommitted> {
        self.events.subscribe()
    }

    /// The current head.
    pub fn head(&self) -> Result<Revision, StoreError> {
        let id = self.head_id()?;
        self.get(id)
    }

    /// The current head's number.
    pub fn head_id(&self) -> Result<RevisionId, StoreError> {
        Ok(RevisionId(self.lock().query_row(
            "SELECT MAX(id) FROM revisions",
            [],
            |r| r.get(0),
        )?))
    }

    /// A revision by number.
    pub fn get(&self, id: RevisionId) -> Result<Revision, StoreError> {
        let (meta, json) = self.read(&self.lock(), id)?;
        let document = self.decode(id, &json, meta.schema_version)?;
        Ok(Revision { meta, document })
    }

    /// Revisions newest first, at most `limit`, older than `before` if given.
    pub fn history(
        &self,
        limit: usize,
        before: Option<RevisionId>,
    ) -> Result<Vec<RevisionMeta>, StoreError> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT id, parent, hash, schema_version, kind, username, time_ms, description,
                    impersonated_by, user_apitoken, restored_from
             FROM revisions WHERE id < ?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let before = before.map_or(i64::MAX, |b| b.0);
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = stmt.query_map(params![before, limit], row_meta)?;
        rows.map(|r| r.map_err(StoreError::from).and_then(|m| m))
            .collect()
    }

    /// Validates and commits `doc` on top of the current head.
    pub fn commit(&self, doc: &Document, meta: CommitMeta) -> Result<CommitOutcome, StoreError> {
        self.write(doc, meta, CommitKind::Commit, None, None, true)
    }

    /// Like [`Store::commit`], but fails with [`StoreError::Conflict`] unless
    /// the head is still `expected` (for read-modify-write over the API).
    pub fn commit_if_head(
        &self,
        expected: RevisionId,
        doc: &Document,
        meta: CommitMeta,
    ) -> Result<CommitOutcome, StoreError> {
        self.write(doc, meta, CommitKind::Commit, Some(expected), None, true)
    }

    /// Commits a document given as JSON (the IPC and CLI carry JSON). An
    /// older `schema_version` is migrated first; the result must
    /// deserialise into a [`Document`] and validate.
    pub fn commit_value(&self, doc: &Value, meta: CommitMeta) -> Result<CommitOutcome, StoreError> {
        let mut v = doc.clone();
        migrate::run(&mut v, &self.migrations, self.target)?;
        let doc: Document = serde_json::from_value(v)?;
        self.commit(&doc, meta)
    }

    /// Commits a document from outside (importer, backup restore).
    pub fn import(&self, doc: &Document, meta: CommitMeta) -> Result<CommitOutcome, StoreError> {
        self.write(doc, meta, CommitKind::Import, None, None, true)
    }

    /// Reads the head, lets `edit` change it, and commits the result, with no
    /// other commit in between.
    pub fn edit<E: fmt::Display>(
        &self,
        meta: CommitMeta,
        edit: impl FnOnce(&mut Document) -> Result<(), E>,
    ) -> Result<CommitOutcome, StoreError> {
        // Hold the lock across read and write; `write_locked` reuses it.
        let conn = self.lock();
        let head = head_id(&conn)?;
        let (m, json) = self.read(&conn, head)?;
        let mut doc = self.decode(head, &json, m.schema_version)?;
        edit(&mut doc).map_err(|e| StoreError::Rejected(e.to_string()))?;
        self.write_locked(conn, &doc, meta, CommitKind::Commit, Some(head), None, true)
    }

    /// Makes the content of revision `id` current again as a new revision.
    /// History is never rewritten.
    pub fn restore(&self, id: RevisionId, meta: CommitMeta) -> Result<CommitOutcome, StoreError> {
        let old = self.get(id)?;
        self.write(
            &old.document,
            meta,
            CommitKind::Restore,
            None,
            Some(id),
            true,
        )
    }

    /// Structural and textual difference from revision `a` to `b`.
    pub fn diff(&self, a: RevisionId, b: RevisionId) -> Result<RevisionDiff, StoreError> {
        let (ra, rb) = (self.get(a)?, self.get(b)?);
        let (va, vb) = (redacted_value(&ra.document)?, redacted_value(&rb.document)?);
        Ok(RevisionDiff {
            patch: json_diff(&va, &vb),
            sections: ra.document.changed_sections(&rb.document),
            text: unified(&va, &vb, &format!("revision {a}"), &format!("revision {b}")),
        })
    }

    /// Appends an audit row for an event that is not a commit (apply,
    /// confirm, login, ...).
    pub fn record(
        &self,
        username: &str,
        action: &str,
        revision: Option<RevisionId>,
        detail: &str,
    ) -> Result<(), StoreError> {
        audit(&self.lock(), username, action, revision, detail)?;
        Ok(())
    }

    /// Audit rows newest first.
    pub fn audit(&self, limit: usize) -> Result<Vec<AuditEntry>, StoreError> {
        let conn = self.lock();
        let mut stmt = conn.prepare("SELECT id, time_ms, username, action, revision, detail FROM audit ORDER BY id DESC LIMIT ?1")?;
        let rows = stmt.query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |r| {
            Ok(AuditEntry {
                id: r.get(0)?,
                time_ms: r.get(1)?,
                username: r.get(2)?,
                action: r.get(3)?,
                revision: r.get::<_, Option<i64>>(4)?.map(RevisionId),
                detail: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// The revision the system is running, as recorded by the apply engine.
    pub fn applied(&self) -> Result<Option<RevisionId>, StoreError> {
        Ok(get_state(&self.lock(), KEY_APPLIED)?
            .and_then(|v| v.parse().ok())
            .map(RevisionId))
    }

    /// Records that `id` is now applied. With `confirm`, the apply is
    /// provisional: unless [`Store::confirm`] is called before the deadline,
    /// [`Store::rollback`] returns to `confirm.rollback_to`.
    pub fn mark_applied(
        &self,
        id: RevisionId,
        confirm: Option<ConfirmState>,
        username: &str,
    ) -> Result<(), StoreError> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        set_state(&tx, KEY_APPLIED, &id.0.to_string())?;
        match confirm {
            Some(c) => {
                set_state(&tx, KEY_CONFIRM, &serde_json::to_string(&c)?)?;
                audit(
                    &tx,
                    username,
                    "apply",
                    Some(id),
                    &format!(
                        "provisional, rollback to {} unless confirmed",
                        c.rollback_to
                    ),
                )?;
            }
            None => {
                tx.execute("DELETE FROM state WHERE key = ?1", [KEY_CONFIRM])?;
                audit(&tx, username, "apply", Some(id), "")?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// The pending commit-confirm, if any.
    pub fn pending_confirm(&self) -> Result<Option<ConfirmState>, StoreError> {
        Ok(match get_state(&self.lock(), KEY_CONFIRM)? {
            Some(v) => Some(serde_json::from_str(&v)?),
            None => None,
        })
    }

    /// Confirms the pending apply. Returns the confirmed revision, or `None`
    /// if nothing was pending.
    pub fn confirm(&self, username: &str) -> Result<Option<RevisionId>, StoreError> {
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pending: Option<ConfirmState> = match get_state(&tx, KEY_CONFIRM)? {
            Some(v) => Some(serde_json::from_str(&v)?),
            None => None,
        };
        if let Some(p) = pending {
            tx.execute("DELETE FROM state WHERE key = ?1", [KEY_CONFIRM])?;
            audit(&tx, username, "confirm", Some(p.pending), "")?;
        }
        tx.commit()?;
        Ok(pending.map(|p| p.pending))
    }

    /// Ends a pending commit-confirm that was not confirmed: commits the
    /// content of `rollback_to` as a new revision (kind `rollback`) and
    /// clears the pending state. The caller applies the returned head.
    /// Returns `None` when nothing was pending.
    pub fn rollback(&self, username: &str) -> Result<Option<CommitOutcome>, StoreError> {
        let Some(p) = self.pending_confirm()? else {
            return Ok(None);
        };
        self.rollback_with(CommitMeta::new(
            username,
            format!("Rollback: revision {} was not confirmed", p.pending),
        ))
    }

    /// [`Store::rollback`] with the caller's revision metadata (the agent
    /// says *why* it rolled back: timeout or restart).
    pub fn rollback_with(&self, meta: CommitMeta) -> Result<Option<CommitOutcome>, StoreError> {
        let Some(p) = self.pending_confirm()? else {
            return Ok(None);
        };
        let old = self.get(p.rollback_to)?;
        let out = self.write(
            &old.document,
            meta,
            CommitKind::Rollback,
            None,
            Some(p.rollback_to),
            false,
        )?;
        let conn = self.lock();
        conn.execute("DELETE FROM state WHERE key = ?1", [KEY_CONFIRM])?;
        Ok(Some(out))
    }

    fn seal(&self, id: RevisionId, pointer: &str, value: &str) -> Result<String, StoreError> {
        match &self.key {
            Some(k) => k
                .seal(id.0, pointer, value)
                .map_err(|reason| StoreError::Corrupt {
                    id,
                    reason: format!("sealing the secret at {pointer}: {reason}"),
                }),
            None => Ok(value.to_owned()),
        }
    }

    fn load_secrets(
        &self,
        conn: &Connection,
        id: RevisionId,
    ) -> Result<Vec<(String, String)>, StoreError> {
        let mut stmt = conn.prepare_cached(
            "SELECT pointer, value FROM secrets WHERE revision = ?1 ORDER BY pointer",
        )?;
        let rows = stmt.query_map([id.0], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (pointer, value) = row?;
            let plain = if is_sealed(&value) {
                let key = self.key.as_ref().ok_or_else(|| StoreError::Corrupt {
                    id,
                    reason: "secrets are encrypted but the store was opened without a key".into(),
                })?;
                key.open(id.0, &pointer, &value)
                    .map_err(|reason| StoreError::Corrupt { id, reason })?
            } else {
                value
            };
            out.push((pointer, plain));
        }
        Ok(out)
    }

    /// With a key, seals secret rows still stored in plain JSON (written
    /// before encryption was configured). One transaction: either every
    /// row is sealed or none.
    fn seal_plain_secrets(&self) -> Result<(), StoreError> {
        if self.key.is_none() {
            return Ok(());
        }
        let mut conn = self.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let plain: Vec<(i64, String, String)> = {
            let mut stmt = tx.prepare("SELECT revision, pointer, value FROM secrets")?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|(_, _, v): &(i64, String, String)| !is_sealed(v))
                .collect()
        };
        for (rev, pointer, value) in &plain {
            let sealed = self.seal(RevisionId(*rev), pointer, value)?;
            tx.execute(
                "UPDATE secrets SET value = ?1 WHERE revision = ?2 AND pointer = ?3",
                params![sealed, rev, pointer],
            )?;
        }
        tx.commit()?;
        if !plain.is_empty() {
            tracing::info!(
                rows = plain.len(),
                "sealed secrets stored before encryption was enabled"
            );
        }
        Ok(())
    }

    fn migrate_head(&self) -> Result<(), StoreError> {
        let conn = self.lock();
        let head = head_id(&conn)?;
        let (meta, json) = self.read(&conn, head)?;
        if meta.schema_version >= self.target {
            if meta.schema_version > self.target {
                return Err(migrate::MigrateError::TooNew {
                    found: meta.schema_version,
                    supported: self.target,
                }
                .into());
            }
            return Ok(());
        }
        let mut value: Value = serde_json::from_str(&json)?;
        let steps = migrate::run(&mut value, &self.migrations, self.target)?;
        let doc: Document = serde_json::from_value(value)?;
        let what = steps
            .iter()
            .map(|s| format!("{}: {}", s.version, s.description))
            .collect::<Vec<_>>()
            .join("; ");
        let meta = CommitMeta::new(
            "(system)",
            format!(
                "Migrated from {} to {} ({what})",
                meta.schema_version, self.target
            ),
        );
        self.write_locked(
            conn,
            &doc,
            meta,
            CommitKind::Migrate,
            Some(head),
            Some(head),
            false,
        )?;
        Ok(())
    }

    fn write(
        &self,
        doc: &Document,
        meta: CommitMeta,
        kind: CommitKind,
        expected: Option<RevisionId>,
        restored_from: Option<RevisionId>,
        validate: bool,
    ) -> Result<CommitOutcome, StoreError> {
        self.write_locked(
            self.lock(),
            doc,
            meta,
            kind,
            expected,
            restored_from,
            validate,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn write_locked(
        &self,
        mut conn: MutexGuard<'_, Connection>,
        doc: &Document,
        meta: CommitMeta,
        kind: CommitKind,
        expected: Option<RevisionId>,
        restored_from: Option<RevisionId>,
        validate: bool,
    ) -> Result<CommitOutcome, StoreError> {
        if validate {
            doc.validate().into_result().map_err(StoreError::Invalid)?;
        }
        let mut doc = doc.clone();
        doc.schema_version = self.target;
        let json = canonical_json(&doc)?;
        let hash = ContentHash::of(&json).to_hex();
        let split = crate::secrets::split(&doc)?;

        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let head: Option<(i64, String, String)> = tx
            .query_row(
                "SELECT id, hash, document FROM revisions ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let head = match head {
            Some((h, head_hash, red)) => {
                let plain = crate::secrets::join(&red, &self.load_secrets(&tx, RevisionId(h))?)
                    .map_err(|reason| StoreError::Corrupt {
                        id: RevisionId(h),
                        reason,
                    })?;
                Some((h, head_hash, plain))
            }
            None => None,
        };
        if let (Some(exp), Some((h, _, _))) = (expected, &head)
            && exp.0 != *h
        {
            return Err(StoreError::Conflict {
                expected: exp,
                head: RevisionId(*h),
            });
        }
        // Rollbacks and restores always write, so the history shows them.
        if let Some((h, head_hash, _)) = &head
            && *head_hash == hash
            && matches!(kind, CommitKind::Commit | CommitKind::Import)
        {
            return Ok(CommitOutcome::Unchanged(RevisionId(*h)));
        }
        let changed = match &head {
            Some((_, _, parent_json)) => match serde_json::from_str::<Document>(parent_json) {
                Ok(parent) => parent.changed_sections(&doc),
                // An older-schema parent: everything may have changed.
                Err(_) => Section::ALL.to_vec(),
            },
            None => Section::ALL.to_vec(),
        };
        let time_ms = now_ms();
        tx.execute(
            "INSERT INTO revisions (parent, hash, schema_version, document, kind, username, time_ms,
                                    description, impersonated_by, user_apitoken, restored_from)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                head.as_ref().map(|h| h.0),
                hash,
                doc.schema_version.to_string(),
                split.redacted,
                kind.as_str(),
                meta.username,
                time_ms,
                meta.description,
                meta.impersonated_by,
                meta.user_apitoken,
                restored_from.map(|r| r.0),
            ],
        )?;
        let id = RevisionId(tx.last_insert_rowid());
        for (pointer, value) in &split.secrets {
            let stored = self.seal(id, pointer, value)?;
            tx.execute(
                "INSERT INTO secrets (revision, pointer, value) VALUES (?1, ?2, ?3)",
                params![id.0, pointer, stored],
            )?;
        }
        let detail = match restored_from {
            Some(r) => format!("{} (from revision {r})", meta.description),
            None => meta.description.clone(),
        };
        audit(&tx, &meta.username, kind.as_str(), Some(id), &detail)?;
        tx.commit()?;
        drop(conn);

        let revision = RevisionMeta {
            id,
            parent: head.map(|h| RevisionId(h.0)),
            hash,
            schema_version: doc.schema_version,
            kind,
            time_ms,
            restored_from,
            meta,
        };
        tracing::info!(revision = %id, kind = kind.as_str(), ?changed, "configuration committed");
        self.export(&doc)?;
        // No receivers is fine: nobody is listening yet.
        let _ = self.events.send(RevisionCommitted {
            revision: revision.clone(),
            changed,
        });
        Ok(CommitOutcome::Committed(revision))
    }

    fn export_head(&self) -> Result<(), StoreError> {
        if self.export_path.is_some() {
            let head = self.head()?;
            self.export(&head.document)?;
        }
        Ok(())
    }

    fn export(&self, doc: &Document) -> Result<(), StoreError> {
        if let Some(path) = &self.export_path {
            let text = sensr_schema::fields::redacted(|| serde_json::to_string_pretty(doc))? + "\n";
            write_atomic(path, text.as_bytes())?;
        }
        Ok(())
    }

    fn read(
        &self,
        conn: &Connection,
        id: RevisionId,
    ) -> Result<(RevisionMeta, String), StoreError> {
        let row = conn
            .query_row(
                "SELECT id, parent, hash, schema_version, kind, username, time_ms, description,
                        impersonated_by, user_apitoken, restored_from, document
                 FROM revisions WHERE id = ?1",
                [id.0],
                |r| Ok((row_meta(r)?, r.get::<_, String>(11)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound(id))?;
        let (meta, red) = row;
        let meta = meta?;
        let json = crate::secrets::join(&red, &self.load_secrets(conn, id)?)
            .map_err(|reason| StoreError::Corrupt { id, reason })?;
        if ContentHash::of(&json).to_hex() != meta.hash {
            return Err(StoreError::Corrupt {
                id,
                reason: "content does not match its hash".into(),
            });
        }
        Ok((meta, json))
    }

    fn decode(
        &self,
        id: RevisionId,
        json: &str,
        version: SchemaVersion,
    ) -> Result<Document, StoreError> {
        if version == self.target {
            return serde_json::from_str(json).map_err(|e| StoreError::Corrupt {
                id,
                reason: e.to_string(),
            });
        }
        let mut value: Value = serde_json::from_str(json)?;
        migrate::run(&mut value, &self.migrations, self.target)?;
        serde_json::from_value(value).map_err(|e| StoreError::Corrupt {
            id,
            reason: e.to_string(),
        })
    }
}

/// Makes the database owner-only before SQLite touches it: revisions hold
/// secrets (private keys, password hashes). SQLite gives its `-wal` and
/// `-shm` files the database's mode, so they follow.
fn restrict(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if !path.exists() {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
        }
        for p in [
            path.to_path_buf(),
            sidecar(path, "-wal"),
            sidecar(path, "-shm"),
        ] {
            if p.exists() {
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(unix)]
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn redacted_value(doc: &Document) -> Result<Value, serde_json::Error> {
    sensr_schema::fields::redacted(|| serde_json::to_value(doc))
}

fn head_id(conn: &Connection) -> Result<RevisionId, StoreError> {
    Ok(RevisionId(conn.query_row(
        "SELECT MAX(id) FROM revisions",
        [],
        |r| r.get(0),
    )?))
}

type MetaResult = Result<RevisionMeta, StoreError>;

fn row_meta(r: &rusqlite::Row<'_>) -> rusqlite::Result<MetaResult> {
    let id = RevisionId(r.get(0)?);
    let version: String = r.get(3)?;
    let kind: String = r.get(4)?;
    let corrupt = |reason: String| StoreError::Corrupt { id, reason };
    let Ok(schema_version) = version.parse() else {
        return Ok(Err(corrupt(format!("bad schema version {version:?}"))));
    };
    let Some(kind) = CommitKind::parse(&kind) else {
        return Ok(Err(corrupt(format!("bad kind {kind:?}"))));
    };
    Ok(Ok(RevisionMeta {
        id,
        parent: r.get::<_, Option<i64>>(1)?.map(RevisionId),
        hash: r.get(2)?,
        schema_version,
        kind,
        time_ms: r.get(6)?,
        restored_from: r.get::<_, Option<i64>>(10)?.map(RevisionId),
        meta: CommitMeta {
            username: r.get(5)?,
            description: r.get(7)?,
            impersonated_by: r.get(8)?,
            user_apitoken: r.get(9)?,
        },
    }))
}

fn audit(
    conn: &Connection,
    username: &str,
    action: &str,
    revision: Option<RevisionId>,
    detail: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO audit (time_ms, username, action, revision, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![now_ms(), username, action, revision.map(|r| r.0), detail],
    )?;
    Ok(())
}

fn get_state(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT value FROM state WHERE key = ?1", [key], |r| {
        r.get(0)
    })
    .optional()
}

fn set_state(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO state (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}
