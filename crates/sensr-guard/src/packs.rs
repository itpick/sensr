//! Packs: a manifest plus one linked BPF object plus default rules.
//!
//! The built-in `core` pack is trusted without a signature. Packs delivered
//! between releases are `.tar.zst` archives with a detached minisign
//! signature from a key in the image's key list
//! (`nix/pi5/guard-keys/README.md`). [`install`] verifies, unpacks into a
//! temporary directory, checks the manifest, and only then renames the
//! directory into place and swaps the `current` symlink, so a failed or
//! interrupted install never changes what [`resolve`] returns. The previous
//! version stays on disk as the last good one; older ones are pruned.
//!
//! [`Manifest`] parsing needs no features; verification and install are
//! behind `packs` (on with `daemon`).
//!
//! The manifest format is the one `nix/packages/sensr-guard-bpf.nix` writes:
//! `rules` names the pack's rules file (`rules.json`, a JSON array of
//! [`Rule`]); [`read_rules`] loads it.

use std::path::{Path, PathBuf};

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::rule::Rule;

/// The manifest file name inside a pack.
pub const MANIFEST_FILE: &str = "manifest.json";
/// The rules file name inside a pack.
pub const RULES_FILE: &str = "rules.json";
/// The object suffix; a pack has exactly one.
pub const OBJECT_SUFFIX: &str = ".bpf.o";

/// A pack's manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Pack name (`[a-z0-9_-]+`).
    pub name: String,
    /// Pack version.
    pub version: Version,
    /// The oldest sensr that can run the pack.
    pub min_sensr: Version,
    /// Object file names (exactly one `*.bpf.o`).
    pub programs: Vec<String>,
    /// File name of the pack's default rules.
    pub rules: String,
}

/// Why a pack was refused.
#[derive(Debug, thiserror::Error)]
pub enum PackError {
    /// The signature does not verify.
    #[error("pack signature does not verify")]
    BadSignature,
    /// The signature was made by a key that is not in the key list.
    #[error("pack is signed by a key that is not trusted")]
    UnknownKey,
    /// The pack needs a newer sensr.
    #[error("pack needs sensr {need}, this is {have}")]
    TooNew {
        /// `min_sensr` of the pack.
        need: Version,
        /// The running version.
        have: Version,
    },
    /// The manifest lists a program the archive does not contain.
    #[error("pack lacks program {0}")]
    MissingProgram(String),
    /// Installing would replace a newer version.
    #[error("pack {new} is older than the installed {current}")]
    Downgrade {
        /// The installed version.
        current: Version,
        /// The offered version.
        new: Version,
    },
    /// The archive or manifest is malformed or unsafe.
    #[error("pack is corrupt: {0}")]
    Corrupt(String),
    /// Filesystem failure while installing.
    #[error("pack install failed: {0}")]
    Io(#[from] std::io::Error),
}

fn corrupt(why: impl Into<String>) -> PackError {
    PackError::Corrupt(why.into())
}

impl Manifest {
    /// Parse and sanity-check a manifest.
    pub fn parse(bytes: &[u8]) -> Result<Self, PackError> {
        let m: Manifest =
            serde_json::from_slice(bytes).map_err(|e| corrupt(format!("manifest: {e}")))?;
        let safe = |s: &str| {
            !s.is_empty()
                && !s.starts_with('.')
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        };
        let name_ok = !m.name.is_empty()
            && m.name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'));
        if !name_ok {
            return Err(corrupt(format!("bad pack name {:?}", m.name)));
        }
        if !m.programs.iter().all(|p| safe(p)) || !safe(&m.rules) {
            return Err(corrupt("manifest names an unsafe file"));
        }
        Ok(m)
    }
}

/// Read a pack's default rules from its directory.
pub fn read_rules(dir: &Path, manifest: &Manifest) -> Result<Vec<Rule>, PackError> {
    let bytes = std::fs::read(dir.join(&manifest.rules))?;
    serde_json::from_slice(&bytes).map_err(|e| corrupt(format!("rules: {e}")))
}

/// Where [`resolve`] found a pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackSource {
    /// Installed from a signed archive.
    Installed(Version),
    /// Built into the image.
    Builtin,
}

/// A pack whose contents were verified (or, for the built-in pack, read
/// once from the image). The loader loads from these bytes, never from the
/// disk again, so nothing can change between the check and the load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPack {
    /// Pack name.
    pub name: String,
    /// Pack version.
    pub version: Version,
    /// Where it came from.
    pub source: PackSource,
    /// Why a newer choice was passed over (revoked key, too new, damaged
    /// files), if one was.
    pub fallback_reason: Option<String>,
    /// The manifest.
    pub manifest: Manifest,
    /// The one BPF object.
    pub object: Vec<u8>,
    /// The pack's default rules.
    pub rules: Vec<Rule>,
}

/// Read a pack directory once: manifest, its one object, and the rules.
/// Every entry must be a regular file (no symlinks). Used for the built-in
/// pack, which is trusted without a signature.
pub fn read_pack_dir(dir: &Path) -> Result<VerifiedPack, PackError> {
    let read = |name: &str| -> Result<Vec<u8>, PackError> {
        let p = dir.join(name);
        if !std::fs::symlink_metadata(&p)?.is_file() {
            return Err(corrupt(format!("{} is not a regular file", p.display())));
        }
        Ok(std::fs::read(&p)?)
    };
    let manifest = Manifest::parse(&read(MANIFEST_FILE)?)?;
    let [program] = manifest.programs.as_slice() else {
        return Err(corrupt("a pack has exactly one .bpf.o"));
    };
    let object = read(program)?;
    let rules = serde_json::from_slice(&read(&manifest.rules)?)
        .map_err(|e| corrupt(format!("rules: {e}")))?;
    Ok(VerifiedPack {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        source: PackSource::Builtin,
        fallback_reason: None,
        manifest,
        object,
        rules,
    })
}

/// The result of an install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackStatus {
    /// Pack name.
    pub name: String,
    /// The installed (now current) version.
    pub version: Version,
    /// Its directory.
    pub dir: PathBuf,
    /// The version that was current before, kept as the last good (`None`
    /// if there was none or the same version was reinstalled).
    pub previous: Option<Version>,
}

#[cfg(feature = "packs")]
pub use install::{PublicKey, archive_manifest, install, load_keys, resolve, verify};

#[cfg(feature = "packs")]
mod install {
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::path::Path;

    pub use minisign_verify::PublicKey;
    use minisign_verify::{Error as SigError, Signature};
    use semver::Version;

    use super::{
        MANIFEST_FILE, Manifest, OBJECT_SUFFIX, PackError, PackSource, PackStatus, RULES_FILE,
        Rule, VerifiedPack, corrupt, read_pack_dir,
    };

    /// Archives (packed and unpacked) larger than this are refused.
    const MAX_UNPACKED: u64 = 16 * 1024 * 1024;
    /// The verified archive and its signature, kept in each version dir.
    const ARCHIVE_FILE: &str = "pack.tar.zst";
    const SIG_FILE: &str = "pack.minisig";

    /// Load every `*.pub` file in `dir` (one minisign public key each).
    pub fn load_keys(dir: &Path) -> Result<Vec<PublicKey>, PackError> {
        let mut paths: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "pub"))
            .collect();
        paths.sort();
        paths
            .iter()
            .map(|p| {
                PublicKey::from_file(p).map_err(|e| corrupt(format!("key {}: {e}", p.display())))
            })
            .collect()
    }

    /// Check `sig` (minisign signature text) over `archive` against `keys`.
    pub fn verify(archive: &[u8], sig: &str, keys: &[PublicKey]) -> Result<(), PackError> {
        let sig = Signature::decode(sig).map_err(|_| PackError::BadSignature)?;
        let mut known_key = false;
        for key in keys {
            match key.verify(archive, &sig, false) {
                Ok(()) => return Ok(()),
                Err(SigError::UnexpectedKeyId) => {}
                Err(_) => known_key = true,
            }
        }
        Err(if known_key {
            PackError::BadSignature
        } else {
            PackError::UnknownKey
        })
    }

    type Files = BTreeMap<String, Vec<u8>>;

    /// Unpack the archive into memory, refusing anything but the pack's
    /// regular files at the top level.
    fn unpack(archive: &[u8]) -> Result<Files, PackError> {
        if archive.len() as u64 > MAX_UNPACKED {
            return Err(corrupt("archive too large"));
        }
        let dec = zstd::stream::read::Decoder::new(archive)
            .map_err(|e| corrupt(format!("zstd: {e}")))?
            .take(MAX_UNPACKED + 1);
        let mut tar = tar::Archive::new(dec);
        let mut files = BTreeMap::new();
        let mut total = 0u64;
        for entry in tar.entries().map_err(|e| corrupt(format!("tar: {e}")))? {
            let mut entry = entry.map_err(|e| corrupt(format!("tar: {e}")))?;
            if !entry.header().entry_type().is_file() {
                return Err(corrupt("archive holds something other than regular files"));
            }
            let path = entry
                .path()
                .map_err(|e| corrupt(format!("tar path: {e}")))?;
            let mut comps = path.components();
            let name = match (comps.next(), comps.next()) {
                (Some(std::path::Component::Normal(n)), None) => n
                    .to_str()
                    .ok_or_else(|| corrupt("non-UTF-8 file name"))?
                    .to_owned(),
                _ => return Err(corrupt(format!("unsafe path {}", path.display()))),
            };
            drop(path);
            if name != MANIFEST_FILE && name != RULES_FILE && !name.ends_with(OBJECT_SUFFIX) {
                return Err(corrupt(format!("unexpected file {name}")));
            }
            let mut data = Vec::new();
            entry
                .read_to_end(&mut data)
                .map_err(|e| corrupt(format!("tar read: {e}")))?;
            total += data.len() as u64;
            if total > MAX_UNPACKED {
                return Err(corrupt("archive unpacks too large"));
            }
            if files.insert(name.clone(), data).is_some() {
                return Err(corrupt(format!("duplicate file {name}")));
            }
        }
        Ok(files)
    }

    /// An archive's manifest, unpacked in memory (nothing is verified or
    /// written: callers [`verify`] first).
    pub fn archive_manifest(archive: &[u8]) -> Result<Manifest, PackError> {
        let files = unpack(archive)?;
        Manifest::parse(
            files
                .get(MANIFEST_FILE)
                .ok_or_else(|| corrupt("no manifest.json"))?,
        )
    }

    /// The manifest-level checks shared by install and resolve.
    fn check(files: &Files, current_sensr: &Version) -> Result<Manifest, PackError> {
        let manifest = Manifest::parse(
            files
                .get(MANIFEST_FILE)
                .ok_or_else(|| corrupt("no manifest.json"))?,
        )?;
        if manifest.min_sensr > *current_sensr {
            return Err(PackError::TooNew {
                need: manifest.min_sensr,
                have: current_sensr.clone(),
            });
        }
        for p in &manifest.programs {
            if !files.contains_key(p) || !p.ends_with(OBJECT_SUFFIX) {
                return Err(PackError::MissingProgram(p.clone()));
            }
        }
        let objects = files.keys().filter(|n| n.ends_with(OBJECT_SUFFIX)).count();
        if objects != 1 || manifest.programs.len() != 1 {
            return Err(corrupt("a pack has exactly one .bpf.o"));
        }
        if manifest.rules != RULES_FILE {
            return Err(corrupt("rules file must be rules.json"));
        }
        let rules = files
            .get(RULES_FILE)
            .ok_or_else(|| corrupt("the archive lacks rules.json"))?;
        serde_json::from_slice::<Vec<Rule>>(rules).map_err(|e| corrupt(format!("rules: {e}")))?;
        Ok(manifest)
    }

    fn random_suffix() -> Result<String, PackError> {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(b.iter().map(|x| format!("{x:02x}")).collect())
    }

    fn sync_dir(dir: &Path) -> std::io::Result<()> {
        std::fs::File::open(dir)?.sync_all()
    }

    fn write_synced(path: &Path, data: &[u8]) -> std::io::Result<()> {
        let mut f = std::fs::File::create(path)?;
        f.write_all(data)?;
        f.sync_all()
    }

    /// Verify and install a pack archive; see the module docs. Nothing on
    /// disk changes unless every check passes. A version older than the
    /// current one is refused unless `allow_downgrade`.
    pub fn install(
        archive: &[u8],
        sig: &str,
        keys: &[PublicKey],
        state_dir: &Path,
        current_sensr: &Version,
        allow_downgrade: bool,
    ) -> Result<PackStatus, PackError> {
        verify(archive, sig, keys)?;
        let files = unpack(archive)?;
        let manifest = check(&files, current_sensr)?;

        let root = state_dir.join("packs").join(&manifest.name);
        std::fs::create_dir_all(&root)?;
        let lock = std::fs::File::create(root.join(".lock"))?;
        lock.lock()?;

        // The current version counts only if it still verifies; an
        // unverifiable one neither blocks a downgrade nor is kept as last
        // good.
        let previous = current_dir(&root).and_then(|name| {
            match check_dir(&root.join(&name), &manifest.name, keys, current_sensr) {
                Ok(c) => Some((name, c.manifest.version)),
                Err(e) => {
                    eprintln!("sensr-guard: current pack {name} does not verify: {e}");
                    None
                }
            }
        });
        let previous_version = previous.as_ref().map(|(_, v)| v.clone());
        if let Some(cur) = &previous_version
            && manifest.version < *cur
            && !allow_downgrade
        {
            return Err(PackError::Downgrade {
                current: cur.clone(),
                new: manifest.version,
            });
        }

        // A fresh directory per install: reinstalling a version never
        // touches the directory `current` points at.
        let version = manifest.version.to_string();
        let dir_name = if root.join(&version).exists() {
            format!("{version}~{}", random_suffix()?)
        } else {
            version
        };
        let dest = root.join(&dir_name);
        let tmp = root.join(format!(".tmp-{}", random_suffix()?));
        let mut swapped = false;
        let staged = (|| -> Result<(), PackError> {
            std::fs::create_dir(&tmp)?;
            for (name, data) in &files {
                write_synced(&tmp.join(name), data)?;
            }
            write_synced(&tmp.join(ARCHIVE_FILE), archive)?;
            write_synced(&tmp.join(SIG_FILE), sig.as_bytes())?;
            sync_dir(&tmp)?;
            std::fs::rename(&tmp, &dest)?;
            sync_dir(&root)?;
            let link_tmp = root.join(format!(".link-{}", random_suffix()?));
            std::os::unix::fs::symlink(&dir_name, &link_tmp)?;
            if let Err(e) = std::fs::rename(&link_tmp, root.join("current")) {
                let _ = std::fs::remove_file(&link_tmp);
                return Err(e.into());
            }
            swapped = true;
            Ok(())
        })();
        if let Err(e) = staged {
            let _ = std::fs::remove_dir_all(&tmp);
            // `current` was not moved, so the new directory is unused.
            let _ = std::fs::remove_dir_all(&dest);
            return Err(e);
        }
        debug_assert!(swapped);
        // The swap happened: a failing fsync now is only a durability
        // warning. `dest` is what `current` points at and is never removed.
        if let Err(e) = sync_dir(&root) {
            eprintln!(
                "sensr-guard: fsync of {} failed after install: {e}",
                root.display()
            );
        }

        let previous_good = previous_version.filter(|p| *p != manifest.version);
        prune(
            &root,
            &Keep {
                current: &dir_name,
                version: &manifest.version,
                previous_dir: previous.map(|(d, _)| d),
            },
            &manifest.name,
            keys,
            current_sensr,
        );
        Ok(PackStatus {
            name: manifest.name,
            version: manifest.version,
            dir: dest,
            previous: previous_good,
        })
    }

    /// The directory name `current` points at (one plain component).
    fn current_dir(root: &Path) -> Option<String> {
        let target = std::fs::read_link(root.join("current")).ok()?;
        let mut comps = target.components();
        match (comps.next(), comps.next()) {
            (Some(std::path::Component::Normal(n)), None) => Some(n.to_str()?.to_owned()),
            _ => None,
        }
    }

    /// Version directories (not dot-files), newest first by the version in
    /// their manifest; a directory whose manifest does not parse has `None`.
    fn version_dirs(root: &Path) -> Vec<(String, Option<Version>)> {
        let Ok(rd) = std::fs::read_dir(root) else {
            return Vec::new();
        };
        let mut out: Vec<(String, Option<Version>)> = rd
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| {
                let name = e.file_name().to_str()?.to_owned();
                if name.starts_with('.') {
                    return None;
                }
                let v = std::fs::read(e.path().join(MANIFEST_FILE))
                    .ok()
                    .and_then(|b| Manifest::parse(&b).ok())
                    .map(|m| m.version);
                Some((name, v))
            })
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));
        out
    }

    struct Keep<'a> {
        current: &'a str,
        version: &'a Version,
        previous_dir: Option<String>,
    }

    /// Keep the new current and the last good (verified like `resolve`
    /// does); drop the rest, directories with an unparseable manifest, and
    /// the leftovers of interrupted installs. Best effort; the caller holds
    /// the lock.
    fn prune(root: &Path, keep: &Keep, name: &str, keys: &[PublicKey], current_sensr: &Version) {
        if let Ok(rd) = std::fs::read_dir(root) {
            for e in rd.filter_map(Result::ok) {
                let n = e.file_name().to_string_lossy().into_owned();
                if n.starts_with(".tmp-") {
                    let _ = std::fs::remove_dir_all(e.path());
                } else if n.starts_with(".link-") {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        let dirs = version_dirs(root);
        let good = |n: &str, v: &Option<Version>| {
            v.as_ref().is_some_and(|v| v != keep.version)
                && n != keep.current
                && check_dir(&root.join(n), name, keys, current_sensr).is_ok()
        };
        // The last good: the directory that was current, unless it is the
        // same version (a reinstall); then the newest other version that
        // still verifies.
        let last_good = keep
            .previous_dir
            .as_ref()
            .filter(|d| dirs.iter().any(|(n, v)| n == *d && good(n, v)))
            .cloned()
            .or_else(|| {
                dirs.iter()
                    .find(|(n, v)| good(n, v))
                    .map(|(n, _)| n.clone())
            });
        for (n, _) in dirs {
            if n != keep.current && Some(&n) != last_good.as_ref() {
                let _ = std::fs::remove_dir_all(root.join(n));
            }
        }
    }

    /// A version directory that passed [`check_dir`]: the signed archive's
    /// own entries.
    struct Checked {
        manifest: Manifest,
        files: Files,
    }

    /// Cap on a stored signature (a minisign signature is about 300 bytes).
    const MAX_SIG: u64 = 4096;

    /// Re-check an installed version directory against the current key
    /// list and running sensr: the stored archive must verify, the manifest
    /// must fit this sensr, and the on-disk files must be regular files
    /// byte-identical to the archive's. The caller uses the archive's bytes,
    /// not the disk's.
    fn check_dir(
        dir: &Path,
        name: &str,
        keys: &[PublicKey],
        current_sensr: &Version,
    ) -> Result<Checked, PackError> {
        let regular = |p: &Path| -> Result<(), PackError> {
            if std::fs::symlink_metadata(p)?.is_file() {
                Ok(())
            } else {
                Err(corrupt(format!("{} is not a regular file", p.display())))
            }
        };
        let mut archive = Vec::new();
        regular(&dir.join(ARCHIVE_FILE))?;
        std::fs::File::open(dir.join(ARCHIVE_FILE))?
            .take(MAX_UNPACKED + 1)
            .read_to_end(&mut archive)?;
        let mut sig = String::new();
        regular(&dir.join(SIG_FILE))?;
        std::fs::File::open(dir.join(SIG_FILE))?
            .take(MAX_SIG + 1)
            .read_to_string(&mut sig)?;
        if sig.len() as u64 > MAX_SIG {
            return Err(PackError::BadSignature);
        }
        verify(&archive, &sig, keys)?;
        let files = unpack(&archive)?;
        let manifest = check(&files, current_sensr)?;
        if manifest.name != name {
            return Err(corrupt("pack name does not match its directory"));
        }
        for (file, data) in &files {
            regular(&dir.join(file))?;
            if std::fs::read(dir.join(file))? != *data {
                return Err(corrupt(format!("{file} differs from the signed archive")));
            }
        }
        for e in std::fs::read_dir(dir)? {
            let n = e?.file_name().to_string_lossy().into_owned();
            if !files.contains_key(&n) && n != ARCHIVE_FILE && n != SIG_FILE {
                return Err(corrupt(format!("unexpected file {n} on disk")));
            }
        }
        Ok(Checked { manifest, files })
    }

    /// The pack for `name`, with its contents in memory: the installed
    /// `current` version if its stored archive still verifies against
    /// `keys` (so a revoked key stops it), it still fits `current_sensr`,
    /// and its files are intact; else the newest other installed version
    /// that does (any older version that still verifies is acceptable; there
    /// is no version floor); else the built-in pack (read once, regular
    /// files only). The bytes come from the verified archive, so the loader
    /// never reads the disk again. The reason a better choice was passed
    /// over is in `fallback_reason`.
    pub fn resolve(
        name: &str,
        builtin_dir: &Path,
        state_dir: &Path,
        keys: &[PublicKey],
        current_sensr: &Version,
    ) -> Result<VerifiedPack, PackError> {
        let root = state_dir.join("packs").join(name);
        // A shared lock keeps an install from pruning under us.
        let _lock = std::fs::File::open(root.join(".lock")).ok().inspect(|f| {
            let _ = f.lock_shared();
        });
        let current = current_dir(&root);
        let mut candidates: Vec<String> = current.iter().cloned().collect();
        candidates.extend(
            version_dirs(&root)
                .into_iter()
                .map(|(n, _)| n)
                .filter(|n| Some(n) != current.as_ref()),
        );
        let mut reason = None;
        for dir_name in candidates {
            match check_dir(&root.join(&dir_name), name, keys, current_sensr) {
                Ok(c) => {
                    let object = c
                        .files
                        .get(&c.manifest.programs[0])
                        .cloned()
                        .ok_or_else(|| corrupt("object vanished"))?;
                    let rules = serde_json::from_slice(&c.files[RULES_FILE])
                        .map_err(|e| corrupt(format!("rules: {e}")))?;
                    return Ok(VerifiedPack {
                        name: c.manifest.name.clone(),
                        version: c.manifest.version.clone(),
                        source: PackSource::Installed(c.manifest.version.clone()),
                        fallback_reason: reason,
                        manifest: c.manifest,
                        object,
                        rules,
                    });
                }
                Err(e) => {
                    reason.get_or_insert_with(|| format!("installed pack {dir_name}: {e}"));
                }
            }
        }
        let mut builtin = read_pack_dir(&builtin_dir.join(name))?;
        builtin.fallback_reason = reason;
        Ok(builtin)
    }
}

#[cfg(all(test, feature = "packs"))]
mod tests {
    use super::*;
    use minisign::KeyPair;

    struct Keys {
        kp: KeyPair,
        public: PublicKey,
    }

    fn keys() -> Keys {
        let kp = KeyPair::generate_unencrypted_keypair().unwrap();
        let public = PublicKey::decode(&kp.pk.to_box().unwrap().to_string()).unwrap();
        Keys { kp, public }
    }

    fn sign(k: &Keys, data: &[u8]) -> String {
        minisign::sign(Some(&k.kp.pk), &k.kp.sk, data, None, None)
            .unwrap()
            .to_string()
    }

    const RULES: &str = r#"[{"id":"p-1","enabled":true,"hook":"exec","target":{"path_prefix":"/tmp"},"action":"alert"}]"#;

    fn manifest(version: &str, min: &str, programs: &[&str]) -> String {
        serde_json::json!({"name":"extra","version":version,"min_sensr":min,
            "programs":programs,"rules":"rules.json"})
        .to_string()
    }

    fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, name, *data).unwrap();
        }
        zstd::encode_all(&b.into_inner().unwrap()[..], 3).unwrap()
    }

    fn pack(version: &str, min: &str) -> Vec<u8> {
        let m = manifest(version, min, &["extra.bpf.o"]);
        archive(&[
            ("manifest.json", m.as_bytes()),
            ("extra.bpf.o", b"\x7fELF"),
            ("rules.json", RULES.as_bytes()),
        ])
    }

    /// Resolve "extra" with a built-in "extra" pack under `st/builtin`.
    fn res(st: &Path, keys: &[PublicKey], sensr: &str) -> VerifiedPack {
        let b = st.join("builtin/extra");
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(
            b.join("manifest.json"),
            manifest("0.0.1", "0.0.0", &["extra.bpf.o"]),
        )
        .unwrap();
        std::fs::write(b.join("extra.bpf.o"), b"builtin").unwrap();
        std::fs::write(b.join("rules.json"), "[]").unwrap();
        resolve("extra", &st.join("builtin"), st, keys, &v(sensr)).unwrap()
    }

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn manifest_parses_what_the_nix_derivation_writes() {
        let m = Manifest::parse(
            br#"{"name":"core","version":"0.1.0","min_sensr":"0.0.0","programs":["core.bpf.o"],"rules":"rules.json"}"#,
        )
        .unwrap();
        assert_eq!(m.version, v("0.1.0"));
        assert!(Manifest::parse(br#"{"name":"../x","version":"1.0.0","min_sensr":"0.0.0","programs":[],"rules":"rules.json"}"#).is_err());
    }

    #[test]
    fn good_signature_installs() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        let a = pack("1.0.0", "0.1.0");
        let s = install(
            &a,
            &sign(&k, &a),
            std::slice::from_ref(&k.public),
            st.path(),
            &v("0.2.0"),
            false,
        )
        .unwrap();
        assert_eq!(s.version, v("1.0.0"));
        let r = res(st.path(), std::slice::from_ref(&k.public), "0.2.0");
        assert_eq!(r.source, PackSource::Installed(v("1.0.0")));
        assert_eq!(r.object, b"\x7fELF");
        assert_eq!(r.rules[0].id, "p-1");
        assert_eq!(r.manifest.name, "extra");
    }

    #[test]
    fn wrong_key_refused() {
        let (k, other, st) = (keys(), keys(), tempfile::tempdir().unwrap());
        let a = pack("1.0.0", "0.1.0");
        let e = install(
            &a,
            &sign(&k, &a),
            &[other.public],
            st.path(),
            &v("1.0.0"),
            false,
        )
        .unwrap_err();
        assert!(matches!(e, PackError::UnknownKey), "{e:?}");
        assert!(!st.path().join("packs").exists());
    }

    #[test]
    fn tampered_archive_refused() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        let mut a = pack("1.0.0", "0.1.0");
        let s = sign(&k, &a);
        *a.last_mut().unwrap() ^= 1;
        let e = install(
            &a,
            &s,
            std::slice::from_ref(&k.public),
            st.path(),
            &v("1.0.0"),
            false,
        )
        .unwrap_err();
        assert!(matches!(e, PackError::BadSignature), "{e:?}");
    }

    #[test]
    fn too_new_refused_and_current_kept() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        let ks = [k.public.clone()];
        let a = pack("1.0.0", "0.1.0");
        install(&a, &sign(&k, &a), &ks, st.path(), &v("0.2.0"), false).unwrap();
        let b = pack("2.0.0", "9.0.0");
        let e = install(&b, &sign(&k, &b), &ks, st.path(), &v("0.2.0"), false).unwrap_err();
        assert!(matches!(e, PackError::TooNew { .. }), "{e:?}");
        let r = res(st.path(), &ks, "0.2.0");
        assert_eq!(r.source, PackSource::Installed(v("1.0.0")));
        assert!(!st.path().join("packs/extra/2.0.0").exists());
    }

    #[test]
    fn missing_program_refused() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        let m = manifest("1.0.0", "0.1.0", &["gone.bpf.o"]);
        let a = archive(&[
            ("manifest.json", m.as_bytes()),
            ("extra.bpf.o", b"x"),
            ("rules.json", RULES.as_bytes()),
        ]);
        let e = install(
            &a,
            &sign(&k, &a),
            std::slice::from_ref(&k.public),
            st.path(),
            &v("1.0.0"),
            false,
        )
        .unwrap_err();
        assert!(
            matches!(e, PackError::MissingProgram(ref p) if p == "gone.bpf.o"),
            "{e:?}"
        );
    }

    #[test]
    fn resolve_falls_back_to_builtin() {
        let st = tempfile::tempdir().unwrap();
        let r = res(st.path(), &[], "1.0.0");
        assert_eq!(r.source, PackSource::Builtin);
        assert_eq!(r.object, b"builtin");
        assert_eq!(r.fallback_reason, None);
        // A missing built-in pack is an error, not a panic.
        assert!(
            resolve(
                "core",
                Path::new("/nonexistent"),
                st.path(),
                &[],
                &v("1.0.0")
            )
            .is_err()
        );
    }

    #[test]
    fn resolve_ignores_a_damaged_current() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        let a = pack("1.0.0", "0.1.0");
        let s = install(
            &a,
            &sign(&k, &a),
            std::slice::from_ref(&k.public),
            st.path(),
            &v("1.0.0"),
            false,
        )
        .unwrap();
        std::fs::remove_file(s.dir.join("extra.bpf.o")).unwrap();
        assert_eq!(
            res(st.path(), std::slice::from_ref(&k.public), "1.0.0").source,
            PackSource::Builtin
        );
    }

    #[test]
    fn unsafe_archives_refused() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        let m = manifest("1.0.0", "0.1.0", &["extra.bpf.o"]);
        let base = |extra: (&str, &[u8])| {
            archive(&[
                ("manifest.json", m.as_bytes()),
                ("extra.bpf.o", b"x"),
                ("rules.json", RULES.as_bytes()),
                extra,
            ])
        };
        for bad in [base(("evil.sh", b"x")), base(("sub/extra2.bpf.o", b"x"))] {
            let e = install(
                &bad,
                &sign(&k, &bad),
                std::slice::from_ref(&k.public),
                st.path(),
                &v("1.0.0"),
                false,
            )
            .unwrap_err();
            assert!(matches!(e, PackError::Corrupt(_)), "{e:?}");
        }
        // `..` and absolute paths are written raw (the tar builder refuses them).
        for name in ["../manifest.json", "/etc/passwd"] {
            let mut raw = vec![0u8; 512];
            raw[..name.len()].copy_from_slice(name.as_bytes());
            raw[100..107].copy_from_slice(b"0000644");
            raw[124..135].copy_from_slice(b"00000000000");
            raw[156] = b'0';
            raw[257..263].copy_from_slice(b"ustar\0");
            raw[148..156].copy_from_slice(b"        ");
            let sum: u32 = raw.iter().map(|b| u32::from(*b)).sum();
            raw[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
            raw.extend(vec![0u8; 1024]);
            let a = zstd::encode_all(&raw[..], 3).unwrap();
            let e = install(
                &a,
                &sign(&k, &a),
                std::slice::from_ref(&k.public),
                st.path(),
                &v("1.0.0"),
                false,
            )
            .unwrap_err();
            assert!(matches!(e, PackError::Corrupt(_)), "{name}: {e:?}");
        }
        // Symlink entry.
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_cksum();
        b.append_link(&mut h, "extra.bpf.o", "/etc/passwd").unwrap();
        let a = zstd::encode_all(&b.into_inner().unwrap()[..], 3).unwrap();
        let e = install(
            &a,
            &sign(&k, &a),
            std::slice::from_ref(&k.public),
            st.path(),
            &v("1.0.0"),
            false,
        )
        .unwrap_err();
        assert!(matches!(e, PackError::Corrupt(_)), "{e:?}");
        assert!(!st.path().join("packs/extra/1.0.0").exists());
    }

    #[test]
    fn upgrades_keep_last_good_and_prune_older() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        let ks = [k.public.clone()];
        for ver in ["1.0.0", "1.1.0", "1.2.0"] {
            let a = pack(ver, "0.1.0");
            let s = install(&a, &sign(&k, &a), &ks, st.path(), &v("1.0.0"), false).unwrap();
            assert_eq!(s.version, v(ver));
        }
        let root = st.path().join("packs/extra");
        assert!(!root.join("1.0.0").exists());
        assert!(root.join("1.1.0").is_dir() && root.join("1.2.0").is_dir());
        assert_eq!(
            std::fs::read_link(root.join("current")).unwrap(),
            PathBuf::from("1.2.0")
        );
        // Reinstalling the current version is fine and keeps the last good.
        let a = pack("1.2.0", "0.1.0");
        let s = install(&a, &sign(&k, &a), &ks, st.path(), &v("1.0.0"), false).unwrap();
        assert_eq!(s.previous, None, "nothing was replaced");
        assert!(root.join("1.1.0").is_dir());
        let mut names: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != ".lock")
            .collect();
        names.sort();
        assert_eq!(names.len(), 3, "{names:?}");
        let cur = std::fs::read_link(root.join("current")).unwrap();
        assert!(cur.to_str().unwrap().starts_with("1.2.0~"), "{cur:?}");
        assert!(
            root.join(&cur).join("extra.bpf.o").is_file(),
            "current never dangles"
        );
    }

    #[test]
    fn keys_load_from_a_directory_of_pub_files() {
        let (k, d) = (keys(), tempfile::tempdir().unwrap());
        std::fs::write(
            d.path().join("a.pub"),
            k.kp.pk.to_box().unwrap().to_string(),
        )
        .unwrap();
        std::fs::write(d.path().join("notes.txt"), "ignored").unwrap();
        assert_eq!(load_keys(d.path()).unwrap().len(), 1);
    }

    fn installed(k: &Keys, st: &Path, ver: &str, min: &str) -> PackStatus {
        let a = pack(ver, min);
        install(
            &a,
            &sign(k, &a),
            std::slice::from_ref(&k.public),
            st,
            &v("1.0.0"),
            false,
        )
        .unwrap()
    }

    /// Install signed by `k`, trusting `ks`.
    fn installed_ks(k: &Keys, ks: &[PublicKey], st: &Path, ver: &str) {
        let a = pack(ver, "0.1.0");
        install(&a, &sign(k, &a), ks, st, &v("1.0.0"), false).unwrap();
    }

    #[test]
    fn revoked_key_falls_back_to_last_good_then_builtin() {
        let (k1, k2, st) = (keys(), keys(), tempfile::tempdir().unwrap());
        let both = [k1.public.clone(), k2.public.clone()];
        installed_ks(&k1, &both, st.path(), "1.0.0");
        installed_ks(&k2, &both, st.path(), "1.1.0");
        let r = res(st.path(), &both, "1.0.0");
        assert_eq!(r.source, PackSource::Installed(v("1.1.0")));
        assert_eq!(r.fallback_reason, None);
        // k2 revoked: back to the 1.0.0 signed by k1.
        let r = res(st.path(), std::slice::from_ref(&k1.public), "1.0.0");
        assert_eq!(r.source, PackSource::Installed(v("1.0.0")));
        assert!(r.fallback_reason.is_some());
        // Both revoked: built-in.
        let r = res(st.path(), &[], "1.0.0");
        assert_eq!(r.source, PackSource::Builtin);
        assert!(r.fallback_reason.unwrap().contains("not trusted"));
    }

    #[test]
    fn min_sensr_above_the_running_version_falls_back() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        installed(&k, st.path(), "1.0.0", "0.1.0");
        installed(&k, st.path(), "1.1.0", "0.5.0");
        let ks = [k.public];
        let r = res(st.path(), &ks, "0.2.0");
        assert_eq!(r.source, PackSource::Installed(v("1.0.0")));
        assert!(r.fallback_reason.unwrap().contains("needs sensr"));
        let r = res(st.path(), &ks, "0.0.1");
        assert_eq!(r.source, PackSource::Builtin);
    }

    #[test]
    fn modified_or_truncated_object_on_disk_falls_back() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        installed(&k, st.path(), "1.0.0", "0.1.0");
        let s = installed(&k, st.path(), "1.1.0", "0.1.0");
        let ks = [k.public];
        for bad in [&b"evil"[..], &b""[..]] {
            std::fs::write(s.dir.join("extra.bpf.o"), bad).unwrap();
            let r = res(st.path(), &ks, "1.0.0");
            assert_eq!(r.source, PackSource::Installed(v("1.0.0")));
            assert!(r.fallback_reason.unwrap().contains("differs"));
        }
        // An extra object dropped next to the pack is refused too.
        std::fs::write(s.dir.join("extra.bpf.o"), b"\x7fELF").unwrap();
        std::fs::write(s.dir.join("more.bpf.o"), b"x").unwrap();
        let r = res(st.path(), &ks, "1.0.0");
        assert_eq!(r.source, PackSource::Installed(v("1.0.0")));
    }

    #[test]
    fn failed_install_keeps_current() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        installed(&k, st.path(), "1.0.0", "0.1.0");
        let m = manifest("1.1.0", "0.1.0", &["gone.bpf.o"]);
        let a = archive(&[
            ("manifest.json", m.as_bytes()),
            ("extra.bpf.o", b"x"),
            ("rules.json", RULES.as_bytes()),
        ]);
        let e = install(
            &a,
            &sign(&k, &a),
            std::slice::from_ref(&k.public),
            st.path(),
            &v("1.0.0"),
            false,
        )
        .unwrap_err();
        assert!(matches!(e, PackError::MissingProgram(_)));
        let r = res(st.path(), std::slice::from_ref(&k.public), "1.0.0");
        assert_eq!(r.source, PackSource::Installed(v("1.0.0")));
    }

    #[test]
    fn downgrades_need_allow_downgrade() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        let ks = [k.public.clone()];
        installed(&k, st.path(), "1.1.0", "0.1.0");
        let a = pack("1.0.0", "0.1.0");
        let sg = sign(&k, &a);
        let e = install(&a, &sg, &ks, st.path(), &v("1.0.0"), false).unwrap_err();
        assert!(matches!(e, PackError::Downgrade { .. }), "{e:?}");
        let r = res(st.path(), &ks, "1.0.0");
        assert_eq!(r.source, PackSource::Installed(v("1.1.0")));
        let s = install(&a, &sg, &ks, st.path(), &v("1.0.0"), true).unwrap();
        assert_eq!(s.version, v("1.0.0"));
        assert_eq!(s.previous, Some(v("1.1.0")));
        let r = res(st.path(), &ks, "1.0.0");
        assert_eq!(r.source, PackSource::Installed(v("1.0.0")));
    }

    #[test]
    fn oversized_archives_and_leftovers() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        let big = vec![0u8; 17 * 1024 * 1024];
        let a = archive(&[("manifest.json", b"{}"), ("extra.bpf.o", &big)]);
        let e = install(
            &a,
            &sign(&k, &a),
            std::slice::from_ref(&k.public),
            st.path(),
            &v("1.0.0"),
            false,
        )
        .unwrap_err();
        assert!(matches!(e, PackError::Corrupt(_)), "{e:?}");
        // Interrupted-install leftovers are pruned by the next install.
        installed(&k, st.path(), "1.0.0", "0.1.0");
        let root = st.path().join("packs/extra");
        std::fs::create_dir(root.join(".tmp-dead")).unwrap();
        std::os::unix::fs::symlink("1.0.0", root.join(".link-dead")).unwrap();
        installed(&k, st.path(), "1.1.0", "0.1.0");
        assert!(!root.join(".tmp-dead").exists());
        assert!(std::fs::symlink_metadata(root.join(".link-dead")).is_err());
    }

    #[test]
    fn concurrent_installs_serialize() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        let ks = [k.public.clone()];
        let jobs: Vec<_> = ["1.0.0", "1.1.0", "1.2.0", "1.3.0"]
            .iter()
            .map(|ver| {
                let a = pack(ver, "0.1.0");
                let sg = sign(&k, &a);
                (a, sg)
            })
            .collect();
        std::thread::scope(|sc| {
            for (a, sg) in &jobs {
                let (ks, d) = (&ks, st.path());
                sc.spawn(move || {
                    install(a, sg, ks, d, &v("1.0.0"), true).unwrap();
                });
            }
        });
        let r = res(st.path(), &ks, "1.0.0");
        assert!(matches!(r.source, PackSource::Installed(_)), "{r:?}");
        let dirs = std::fs::read_dir(st.path().join("packs/extra"))
            .unwrap()
            .filter(|e| {
                !e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with('.')
            })
            .count();
        assert_eq!(dirs, 3, "two versions + current");
    }

    #[test]
    fn builtin_pack_rejects_symlinked_files() {
        let st = tempfile::tempdir().unwrap();
        res(st.path(), &[], "1.0.0");
        let b = st.path().join("builtin/extra");
        std::fs::remove_file(b.join("extra.bpf.o")).unwrap();
        std::fs::write(st.path().join("elsewhere"), b"x").unwrap();
        std::os::unix::fs::symlink(st.path().join("elsewhere"), b.join("extra.bpf.o")).unwrap();
        let e = read_pack_dir(&b).unwrap_err();
        assert!(matches!(e, PackError::Corrupt(_)), "{e:?}");
    }

    #[test]
    fn symlinked_object_on_disk_falls_back_and_bytes_come_from_the_archive() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        installed(&k, st.path(), "1.0.0", "0.1.0");
        let s = installed(&k, st.path(), "1.1.0", "0.1.0");
        let ks = [k.public];
        // The verified bytes are the archive's, whatever the disk holds.
        let r = res(st.path(), &ks, "1.0.0");
        assert_eq!(r.version, v("1.1.0"));
        assert_eq!(r.object, b"\x7fELF");
        // A symlink with identical content is still refused.
        std::fs::remove_file(s.dir.join("extra.bpf.o")).unwrap();
        std::fs::write(st.path().join("same"), b"\x7fELF").unwrap();
        std::os::unix::fs::symlink(st.path().join("same"), s.dir.join("extra.bpf.o")).unwrap();
        let r = res(st.path(), &ks, "1.0.0");
        assert_eq!(r.version, v("1.0.0"));
        assert!(r.fallback_reason.unwrap().contains("not a regular file"));
    }

    #[test]
    fn oversized_signature_is_refused_on_resolve() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        let s = installed(&k, st.path(), "1.0.0", "0.1.0");
        std::fs::write(s.dir.join("pack.minisig"), vec![b'a'; 10_000]).unwrap();
        let r = res(st.path(), std::slice::from_ref(&k.public), "1.0.0");
        assert_eq!(r.source, PackSource::Builtin);
    }

    #[test]
    fn unverifiable_current_does_not_block_a_downgrade_or_count_as_last_good() {
        let (k1, k2, st) = (keys(), keys(), tempfile::tempdir().unwrap());
        let both = [k1.public.clone(), k2.public.clone()];
        installed_ks(&k1, &both, st.path(), "1.0.0");
        installed_ks(&k2, &both, st.path(), "2.0.0");
        // k2 is revoked: installing 1.5.0 (older than the unverifiable 2.0.0)
        // is not a downgrade.
        let a = pack("1.5.0", "0.1.0");
        let ks = [k1.public.clone()];
        let s = install(&a, &sign(&k1, &a), &ks, st.path(), &v("1.0.0"), false).unwrap();
        assert_eq!(s.previous, None);
        let root = st.path().join("packs/extra");
        assert!(!root.join("2.0.0").exists(), "unverifiable dir is not kept");
        assert!(
            root.join("1.0.0").is_dir(),
            "verified older one is last good"
        );
        assert!(root.join("1.5.0").is_dir());
    }

    #[test]
    fn unparseable_version_dirs_are_pruned() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        installed(&k, st.path(), "1.0.0", "0.1.0");
        let junk = st.path().join("packs/extra/junk");
        std::fs::create_dir(&junk).unwrap();
        std::fs::write(junk.join("manifest.json"), "{").unwrap();
        installed(&k, st.path(), "1.1.0", "0.1.0");
        assert!(!junk.exists());
    }
}
