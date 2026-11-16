//! The SQLite schema of the store, versioned with `PRAGMA user_version`.

use rusqlite::Connection;

/// Each entry upgrades the database by one version. Append only.
const STEPS: &[&str] = &[
    // 1: revisions, audit, key/value state.
    "CREATE TABLE revisions (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        parent          INTEGER REFERENCES revisions(id),
        hash            TEXT    NOT NULL,
        schema_version  TEXT    NOT NULL,
        document        TEXT    NOT NULL,
        kind            TEXT    NOT NULL,
        username        TEXT    NOT NULL,
        time_ms         INTEGER NOT NULL,
        description     TEXT    NOT NULL,
        impersonated_by TEXT,
        user_apitoken   TEXT,
        restored_from   INTEGER REFERENCES revisions(id)
    );
    CREATE TABLE audit (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        time_ms   INTEGER NOT NULL,
        username  TEXT    NOT NULL,
        action    TEXT    NOT NULL,
        revision  INTEGER,
        detail    TEXT    NOT NULL
    );
    CREATE TABLE state (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );",
];

/// Brings the database schema up to date inside one transaction.
pub(crate) fn upgrade(conn: &mut Connection) -> rusqlite::Result<()> {
    let tx = conn.transaction()?;
    let current: usize = tx
        .query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?
        .try_into()
        .unwrap_or(0);
    for (i, sql) in STEPS.iter().enumerate().skip(current) {
        tx.execute_batch(sql)?;
        tx.pragma_update(
            None,
            "user_version",
            i64::try_from(i + 1).unwrap_or(i64::MAX),
        )?;
    }
    tx.commit()
}

/// The newest schema version this build creates.
pub(crate) fn latest() -> i64 {
    i64::try_from(STEPS.len()).unwrap_or(i64::MAX)
}
