//! JSON persistence of one uplink's [`PdState`].
//!
//! RFC 9096 §3.5 asks CE routers to keep the advertised prefixes on stable
//! storage; that is what lets sensr deprecate the old prefix after a reboot
//! that came back with a new one.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::PdState;

/// Version of the on-disk format.
const FORMAT: u32 = 1;

#[derive(Serialize, Deserialize)]
struct Envelope {
    format: u32,
    state: PdState,
}

/// Errors writing the state.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Filesystem error, with the path involved.
    #[error("{path}: {source}")]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// Serialisation failed (not expected for this type).
    #[error("serialising PD state: {0}")]
    Json(#[from] serde_json::Error),
}

/// Why [`PdStore::load`] started from a fresh state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadIssue {
    /// No state file yet (first boot on this uplink).
    Missing,
    /// The file could not be read.
    Unreadable(String),
    /// The file is not valid state JSON. It was moved aside to `moved_to`
    /// (when that worked) so the next save does not destroy the evidence.
    Corrupt {
        /// The parse error.
        error: String,
        /// Where the bad file now lives.
        moved_to: Option<PathBuf>,
    },
    /// Written by a newer sensr with a format this one does not know.
    UnsupportedFormat(u32),
}

impl std::fmt::Display for LoadIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "no saved PD state"),
            Self::Unreadable(e) => write!(f, "saved PD state unreadable: {e}"),
            Self::Corrupt { error, moved_to } => {
                write!(f, "saved PD state corrupt ({error})")?;
                if let Some(p) = moved_to {
                    write!(f, ", moved to {}", p.display())?;
                }
                Ok(())
            }
            Self::UnsupportedFormat(v) => write!(f, "saved PD state has unknown format {v}"),
        }
    }
}

/// The result of [`PdStore::load`]: always a usable state, plus the reason
/// when it is a fresh one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loaded {
    /// The state to run with.
    pub state: PdState,
    /// Why the saved state was not used, if it was not.
    pub issue: Option<LoadIssue>,
}

/// The state file of one uplink, e.g. `/var/lib/sensr/state/pd/wan.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdStore {
    path: PathBuf,
}

impl PdStore {
    /// A store at `path`; nothing is touched until load or save.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The state file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn sibling(&self, suffix: &str) -> PathBuf {
        let mut name = self
            .path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_else(|| "pd".into());
        name.push(suffix);
        self.path.with_file_name(name)
    }

    /// Load the saved state. Never fails: a missing, unreadable or corrupt
    /// file yields a fresh state and the reason. A loaded state is marked
    /// unconfirmed, so the first observation either renews the saved prefix
    /// or deprecates it as changed.
    pub fn load(&self) -> Loaded {
        let fresh = |issue| Loaded {
            state: PdState::new(),
            issue: Some(issue),
        };
        let bytes = match fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return fresh(LoadIssue::Missing),
            Err(e) => return fresh(LoadIssue::Unreadable(e.to_string())),
        };
        // Check the format before the body so a newer layout is reported as
        // such and not as corruption.
        #[derive(Deserialize)]
        struct Head {
            format: u32,
        }
        match serde_json::from_slice::<Head>(&bytes) {
            Ok(h) if h.format != FORMAT => return fresh(LoadIssue::UnsupportedFormat(h.format)),
            _ => {}
        }
        match serde_json::from_slice::<Envelope>(&bytes) {
            Ok(env) => {
                let mut state = env.state;
                state.mark_unconfirmed();
                Loaded { state, issue: None }
            }
            Err(e) => {
                let aside = self.sibling(".corrupt");
                let moved_to = fs::rename(&self.path, &aside).ok().map(|()| aside);
                fresh(LoadIssue::Corrupt {
                    error: e.to_string(),
                    moved_to,
                })
            }
        }
    }

    /// Save atomically: write a temporary file next to the target, fsync
    /// it, rename it over the target, fsync the directory. A crash leaves
    /// either the old or the new file, never a torn one.
    pub fn save(&self, state: &PdState) -> Result<(), StoreError> {
        let io_err = |path: &Path| {
            let path = path.to_path_buf();
            move |source| StoreError::Io { path, source }
        };
        let dir = match self.path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
            _ => PathBuf::from("."),
        };
        fs::create_dir_all(&dir).map_err(io_err(&dir))?;
        let mut body = serde_json::to_vec_pretty(&Envelope {
            format: FORMAT,
            state: state.clone(),
        })?;
        body.push(b'\n');
        let tmp = self.sibling(".tmp");
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(io_err(&tmp))?;
        f.write_all(&body).map_err(io_err(&tmp))?;
        f.sync_all().map_err(io_err(&tmp))?;
        drop(f);
        fs::rename(&tmp, &self.path).map_err(io_err(&self.path))?;
        // The rename is durable only once the directory entry is.
        File::open(&dir)
            .and_then(|d| d.sync_all())
            .map_err(io_err(&dir))?;
        Ok(())
    }
}
