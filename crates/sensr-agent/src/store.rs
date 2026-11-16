//! The config-store boundary.
//!
//! `sensr-config` (SQLite revisions, audit, secrets) is the real store; until
//! it lands, the agent runs on [`MemStore`] (tests) or [`JsonDirStore`] (a
//! stopgap that persists one JSON file per revision). Both implement
//! [`ConfigStore`], which is all the agent needs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sensr_ipc::{RevisionId, RevisionInfo};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Store failures.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Disk I/O.
    #[error("config store i/o at {path}: {source}")]
    Io {
        /// File involved.
        path: PathBuf,
        /// Cause.
        source: std::io::Error,
    },
    /// A stored revision does not parse.
    #[error("corrupt revision file {path}: {message}")]
    Corrupt {
        /// File involved.
        path: PathBuf,
        /// Parser message.
        message: String,
    },
}

/// What a commit stores; the store assigns id, parent, hash and time.
#[derive(Debug, Clone, PartialEq)]
pub struct NewRevision {
    /// The full document.
    pub document: Value,
    /// OPNsense-style `user@via`.
    pub username: String,
    /// Description.
    pub description: String,
    /// Operator acting through `username`.
    pub impersonated_by: Option<String>,
}

/// A stored revision with its document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredRevision {
    /// Metadata.
    pub info: RevisionInfo,
    /// The document.
    pub document: Value,
}

/// What the agent needs from a config store.
pub trait ConfigStore: Send + 'static {
    /// The newest revision.
    fn head(&self) -> Result<Option<StoredRevision>, StoreError>;
    /// A specific revision.
    fn get(&self, id: RevisionId) -> Result<Option<StoredRevision>, StoreError>;
    /// Stores a new revision on top of head.
    fn commit(&mut self, rev: NewRevision) -> Result<RevisionInfo, StoreError>;
    /// Newest-first metadata, at most `limit` entries.
    fn history(&self, limit: usize) -> Result<Vec<RevisionInfo>, StoreError>;
}

/// blake3 of the canonical JSON text: object keys sorted, compact. Key order
/// must not matter because other crates enable serde_json's
/// `preserve_order` (feature unification makes it workspace-wide).
pub fn content_hash(doc: &Value) -> String {
    let mut out = String::new();
    canonical(doc, &mut out);
    blake3::hash(out.as_bytes()).to_hex().to_string()
}

fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (n, k) in keys.into_iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                canonical(&m[k], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (n, item) in items.iter().enumerate() {
                if n > 0 {
                    out.push(',');
                }
                canonical(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn make_info(parent: Option<RevisionId>, id: RevisionId, rev: &NewRevision) -> RevisionInfo {
    RevisionInfo {
        id,
        parent,
        hash: content_hash(&rev.document),
        username: rev.username.clone(),
        time_ms: now_ms(),
        description: rev.description.clone(),
        impersonated_by: rev.impersonated_by.clone(),
    }
}

/// In-memory store for tests and ephemeral agents.
#[derive(Debug, Default)]
pub struct MemStore {
    revisions: BTreeMap<RevisionId, StoredRevision>,
}

impl MemStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ConfigStore for MemStore {
    fn head(&self) -> Result<Option<StoredRevision>, StoreError> {
        Ok(self.revisions.values().next_back().cloned())
    }

    fn get(&self, id: RevisionId) -> Result<Option<StoredRevision>, StoreError> {
        Ok(self.revisions.get(&id).cloned())
    }

    fn commit(&mut self, rev: NewRevision) -> Result<RevisionInfo, StoreError> {
        let parent = self.revisions.keys().next_back().copied();
        let id = parent.map_or(1, |p| p + 1);
        let info = make_info(parent, id, &rev);
        self.revisions.insert(
            id,
            StoredRevision {
                info: info.clone(),
                document: rev.document,
            },
        );
        Ok(info)
    }

    fn history(&self, limit: usize) -> Result<Vec<RevisionInfo>, StoreError> {
        Ok(self
            .revisions
            .values()
            .rev()
            .take(limit)
            .map(|r| r.info.clone())
            .collect())
    }
}

/// Stopgap persistent store: `<dir>/<id>.json` per revision, written
/// atomically (temp file + rename), metadata cached in memory. Replaced by
/// `sensr-config`'s SQLite store once that lands.
#[derive(Debug)]
pub struct JsonDirStore {
    dir: PathBuf,
    infos: BTreeMap<RevisionId, RevisionInfo>,
}

impl JsonDirStore {
    /// Opens (creating) the store directory and indexes existing revisions.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        let io = |source| StoreError::Io {
            path: dir.to_owned(),
            source,
        };
        std::fs::create_dir_all(dir).map_err(io)?;
        let mut infos = BTreeMap::new();
        for entry in std::fs::read_dir(dir).map_err(io)? {
            let path = entry.map_err(io)?.path();
            let is_rev = path.extension().is_some_and(|e| e == "json")
                && path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.parse::<RevisionId>().is_ok());
            if is_rev {
                let rev = read_rev(&path)?;
                infos.insert(rev.info.id, rev.info);
            }
        }
        Ok(Self {
            dir: dir.to_owned(),
            infos,
        })
    }

    fn path_of(&self, id: RevisionId) -> PathBuf {
        self.dir.join(format!("{id:010}.json"))
    }
}

fn read_rev(path: &Path) -> Result<StoredRevision, StoreError> {
    let bytes = std::fs::read(path).map_err(|source| StoreError::Io {
        path: path.to_owned(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|e| StoreError::Corrupt {
        path: path.to_owned(),
        message: e.to_string(),
    })
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

impl ConfigStore for JsonDirStore {
    fn head(&self) -> Result<Option<StoredRevision>, StoreError> {
        match self.infos.keys().next_back() {
            Some(id) => self.get(*id),
            None => Ok(None),
        }
    }

    fn get(&self, id: RevisionId) -> Result<Option<StoredRevision>, StoreError> {
        if !self.infos.contains_key(&id) {
            return Ok(None);
        }
        read_rev(&self.path_of(id)).map(Some)
    }

    fn commit(&mut self, rev: NewRevision) -> Result<RevisionInfo, StoreError> {
        let parent = self.infos.keys().next_back().copied();
        let id = parent.map_or(1, |p| p + 1);
        let info = make_info(parent, id, &rev);
        let stored = StoredRevision {
            info: info.clone(),
            document: rev.document,
        };
        let path = self.path_of(id);
        let bytes = serde_json::to_vec_pretty(&stored).map_err(|e| StoreError::Corrupt {
            path: path.clone(),
            message: e.to_string(),
        })?;
        write_atomic(&path, &bytes).map_err(|source| StoreError::Io {
            path: path.clone(),
            source,
        })?;
        self.infos.insert(id, info.clone());
        Ok(info)
    }

    fn history(&self, limit: usize) -> Result<Vec<RevisionInfo>, StoreError> {
        Ok(self.infos.values().rev().take(limit).cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rev(doc: Value) -> NewRevision {
        NewRevision {
            document: doc,
            username: "root@unix".into(),
            description: "test".into(),
            impersonated_by: None,
        }
    }

    fn exercise(store: &mut dyn ConfigStore) {
        assert!(store.head().unwrap().is_none());
        let a = store.commit(rev(json!({"a": 1}))).unwrap();
        let b = store.commit(rev(json!({"a": 2}))).unwrap();
        assert_eq!((a.id, a.parent), (1, None));
        assert_eq!((b.id, b.parent), (2, Some(1)));
        assert_ne!(a.hash, b.hash);
        assert_eq!(store.head().unwrap().unwrap().document, json!({"a": 2}));
        assert_eq!(store.get(1).unwrap().unwrap().document, json!({"a": 1}));
        assert!(store.get(9).unwrap().is_none());
        let h = store.history(10).unwrap();
        assert_eq!(h.iter().map(|i| i.id).collect::<Vec<_>>(), vec![2, 1]);
        assert_eq!(store.history(1).unwrap().len(), 1);
    }

    #[test]
    fn mem_store() {
        exercise(&mut MemStore::new());
    }

    #[test]
    fn json_dir_store_persists() {
        let dir = tempfile::tempdir().unwrap();
        exercise(&mut JsonDirStore::open(dir.path()).unwrap());
        let reopened = JsonDirStore::open(dir.path()).unwrap();
        assert_eq!(reopened.head().unwrap().unwrap().info.id, 2);
        assert_eq!(reopened.history(10).unwrap().len(), 2);
    }

    #[test]
    fn hash_is_key_order_independent() {
        let a: Value = serde_json::from_str(r#"{"x":1,"y":2}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"y":2,"x":1}"#).unwrap();
        assert_eq!(content_hash(&a), content_hash(&b));
    }
}
