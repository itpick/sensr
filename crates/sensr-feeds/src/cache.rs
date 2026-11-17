//! The last-good store: one body plus metadata per source URL, written
//! atomically, so a failed or partial fetch never replaces good contents and
//! a reboot starts from what was last loaded.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::http::Conditional;

/// Bookkeeping for one source.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    /// the source
    pub url: String,
    /// when the stored body was fetched (s since the epoch); `None`: never
    #[serde(default)]
    pub fetched_at: Option<u64>,
    /// last successful contact (200 or 304)
    #[serde(default)]
    pub checked_at: Option<u64>,
    /// last attempt, successful or not
    #[serde(default)]
    pub attempted_at: Option<u64>,
    /// why the last attempt failed (cleared by the next success)
    #[serde(default)]
    pub error: Option<String>,
    /// consecutive failures (drives the retry back-off)
    #[serde(default)]
    pub failures: u32,
    /// `ETag`
    #[serde(default)]
    pub etag: Option<String>,
    /// `Last-Modified`
    #[serde(default)]
    pub last_modified: Option<String>,
    /// stored body size
    #[serde(default)]
    pub bytes: u64,
    /// hash of the stored body, to tell a real change from a re-download
    #[serde(default)]
    pub hash: Option<String>,
}

impl Meta {
    /// Validators for a conditional request (only when a body is stored).
    pub fn conditional(&self) -> Conditional {
        if self.fetched_at.is_none() {
            return Conditional::default();
        }
        Conditional {
            etag: self.etag.clone(),
            last_modified: self.last_modified.clone(),
        }
    }
}

/// A directory of cached bodies keyed by URL.
#[derive(Clone, Debug)]
pub struct Cache {
    dir: PathBuf,
}

/// Writes `data` to `path` via a temporary file and a rename (same
/// directory), fsynced, so readers see the old or the new file, never half.
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("x")
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

impl Cache {
    /// The cache under `dir` (created on first write).
    pub fn new(dir: impl Into<PathBuf>) -> Cache {
        Cache { dir: dir.into() }
    }

    /// Root directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn key(url: &str) -> String {
        blake3::hash(url.as_bytes()).to_hex()[..32].to_owned()
    }

    fn body_path(&self, url: &str) -> PathBuf {
        self.dir
            .join("url")
            .join(format!("{}.body", Self::key(url)))
    }

    fn meta_path(&self, url: &str) -> PathBuf {
        self.dir
            .join("url")
            .join(format!("{}.json", Self::key(url)))
    }

    /// Metadata of `url` (default when never seen or unreadable).
    pub fn meta(&self, url: &str) -> Meta {
        std::fs::read(self.meta_path(url))
            .ok()
            .and_then(|b| serde_json::from_slice::<Meta>(&b).ok())
            .filter(|m| m.url == url)
            .unwrap_or_else(|| Meta {
                url: url.to_owned(),
                ..Meta::default()
            })
    }

    /// Stores metadata.
    pub fn put_meta(&self, m: &Meta) -> std::io::Result<()> {
        let json = serde_json::to_vec_pretty(m).map_err(std::io::Error::other)?;
        write_atomic(&self.meta_path(&m.url), &json)
    }

    /// The last good body of `url`.
    pub fn body(&self, url: &str) -> Option<Vec<u8>> {
        std::fs::read(self.body_path(url)).ok()
    }

    /// Stores a new good body; returns whether it differs from the old one.
    pub fn put_body(&self, m: &mut Meta, body: &[u8], now: u64) -> std::io::Result<bool> {
        let hash = blake3::hash(body).to_hex().to_string();
        let changed = m.hash.as_deref() != Some(hash.as_str());
        if changed || self.body(&m.url).is_none() {
            write_atomic(&self.body_path(&m.url), body)?;
        }
        m.hash = Some(hash);
        m.bytes = body.len() as u64;
        m.fetched_at = Some(now);
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_and_meta_round_trip() {
        let d = tempfile::tempdir().unwrap();
        let c = Cache::new(d.path());
        let url = "https://lists.example.net/a.txt";
        let mut m = c.meta(url);
        assert_eq!(m.fetched_at, None);
        assert!(c.put_body(&mut m, b"192.0.2.0/24\n", 10).unwrap());
        assert!(!c.put_body(&mut m, b"192.0.2.0/24\n", 20).unwrap());
        c.put_meta(&m).unwrap();
        assert_eq!(c.meta(url).fetched_at, Some(20));
        assert_eq!(c.body(url).unwrap(), b"192.0.2.0/24\n");
        // another URL does not see it
        assert!(c.body("https://lists.example.net/b.txt").is_none());
    }
}
