//! Filesystem helpers shared by the tasks.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The repository root: two levels above this crate's manifest.
pub fn repo_root() -> Result<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .context("xtask is not inside crates/ of a workspace")
}

/// Every regular file under `dir`, recursively, sorted, skipping `.git` and
/// `target`. A missing `dir` yields nothing.
pub fn files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let entries = match fs::read_dir(&d) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("reading {}", d.display())),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let ty = entry.file_type()?;
            if ty.is_dir() {
                let name = entry.file_name();
                if name != ".git" && name != "target" {
                    stack.push(path);
                }
            } else if ty.is_file() {
                out.push(path);
            }
        }
    }
    out.sort();
    Ok(out)
}

/// `path` relative to `base`, with `/` separators.
pub fn rel(base: &Path, path: &Path) -> String {
    let r = path.strip_prefix(base).unwrap_or(path);
    r.components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}
