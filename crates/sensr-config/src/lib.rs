//! The config document store: revisions, history, audit and change events
//! (OPNsense counterpart: `Core/Config.php`, `config.xml` and its
//! `/conf/backup/` history, `Core/Api/BackupController.php`).
//!
//! [`Store`] keeps every committed [`Document`] as a revision in SQLite
//! (WAL): canonical JSON with secrets moved to their own table, a blake3
//! content hash over the full document and OPNsense-shaped metadata.
//! Commits validate the whole document first, never rewrite history
//! (restores are new revisions), write the head atomically to `config.json`
//! with secrets redacted, record an audit row and broadcast
//! [`RevisionCommitted`] so the apply engine re-renders only the sections that
//! changed. Commit-confirm state survives restarts, so an unconfirmed change
//! is rolled back even across a reboot.

mod canonical;
mod diff;
mod export;
mod schema;
mod secrets;
mod store;

pub use canonical::{ContentHash, canonical_json};
pub use diff::{PatchOp, RevisionDiff, json_diff};
pub use sensr_schema::Document;
pub use store::{
    AuditEntry, CommitKind, CommitMeta, CommitOutcome, ConfirmState, Revision, RevisionCommitted,
    RevisionId, RevisionMeta, Store, StoreError, StoreOptions,
};
