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

/// A resolved pack directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackDir {
    /// The directory to hand to the loader.
    pub path: PathBuf,
    /// Where it came from.
    pub source: PackSource,
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
    /// The version that was current before, kept as the last good.
    pub previous: Option<Version>,
}

/// The pack directory for `name`: the installed `current` version if it is
/// intact (manifest parses, matches its directory, objects present),
/// otherwise the built-in pack. Signatures were checked at install time.
pub fn resolve(name: &str, builtin_dir: &Path, state_dir: &Path) -> PackDir {
    if let Some((path, version)) = installed_current(name, state_dir) {
        return PackDir {
            path,
            source: PackSource::Installed(version),
        };
    }
    PackDir {
        path: builtin_dir.join(name),
        source: PackSource::Builtin,
    }
}

fn pack_root(state_dir: &Path, name: &str) -> PathBuf {
    state_dir.join("packs").join(name)
}

fn current_version(root: &Path) -> Option<Version> {
    let target = std::fs::read_link(root.join("current")).ok()?;
    // Only a plain sibling directory name is accepted.
    let mut comps = target.components();
    match (comps.next(), comps.next()) {
        (Some(std::path::Component::Normal(n)), None) => Version::parse(n.to_str()?).ok(),
        _ => None,
    }
}

fn installed_current(name: &str, state_dir: &Path) -> Option<(PathBuf, Version)> {
    let root = pack_root(state_dir, name);
    let version = current_version(&root)?;
    let dir = root.join(version.to_string());
    let manifest = Manifest::parse(&std::fs::read(dir.join(MANIFEST_FILE)).ok()?).ok()?;
    if manifest.name != name || manifest.version != version {
        return None;
    }
    let objects_ok = manifest.programs.iter().all(|p| dir.join(p).is_file());
    (objects_ok && dir.join(&manifest.rules).is_file()).then_some((dir, version))
}

#[cfg(feature = "packs")]
pub use install::{PublicKey, install, load_keys, verify};

#[cfg(feature = "packs")]
mod install {
    use std::collections::BTreeMap;
    use std::io::Read;
    use std::path::Path;

    pub use minisign_verify::PublicKey;
    use minisign_verify::{Error as SigError, Signature};
    use semver::Version;

    use super::{
        MANIFEST_FILE, Manifest, OBJECT_SUFFIX, PackError, PackStatus, RULES_FILE, Rule, corrupt,
        current_version, pack_root,
    };

    /// Unpacked archives larger than this are refused.
    const MAX_UNPACKED: u64 = 256 * 1024 * 1024;
    /// Versions kept on disk: the current one and the last good.
    const KEEP: usize = 2;

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

    /// Unpack the archive into memory, refusing anything but the pack's
    /// regular files at the top level.
    fn unpack(archive: &[u8]) -> Result<BTreeMap<String, Vec<u8>>, PackError> {
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

    fn random_suffix() -> Result<String, PackError> {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(b.iter().map(|x| format!("{x:02x}")).collect())
    }

    /// Verify and install a pack archive; see the module docs. Nothing on
    /// disk changes unless every check passes.
    pub fn install(
        archive: &[u8],
        sig: &str,
        keys: &[PublicKey],
        state_dir: &Path,
        current_sensr: &Version,
    ) -> Result<PackStatus, PackError> {
        verify(archive, sig, keys)?;
        let files = unpack(archive)?;
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
        let objects = files.keys().filter(|n| n.ends_with(OBJECT_SUFFIX)).count();
        if objects != 1 || manifest.programs.len() != 1 {
            return Err(corrupt("a pack has exactly one .bpf.o"));
        }
        for p in &manifest.programs {
            if !files.contains_key(p) || !p.ends_with(OBJECT_SUFFIX) {
                return Err(PackError::MissingProgram(p.clone()));
            }
        }
        let rules = files
            .get(&manifest.rules)
            .ok_or_else(|| corrupt("manifest names a rules file the archive lacks"))?;
        serde_json::from_slice::<Vec<Rule>>(rules).map_err(|e| corrupt(format!("rules: {e}")))?;
        if manifest.rules != RULES_FILE {
            return Err(corrupt("rules file must be rules.json"));
        }

        let root = pack_root(state_dir, &manifest.name);
        std::fs::create_dir_all(&root)?;
        let previous = current_version(&root);
        let version = manifest.version.to_string();
        let dest = root.join(&version);

        let tmp = root.join(format!(".tmp-{}", random_suffix()?));
        std::fs::create_dir(&tmp)?;
        let staged = (|| -> Result<(), PackError> {
            for (name, data) in &files {
                std::fs::write(tmp.join(name), data)?;
            }
            // Re-installing the current version replaces it in one rename
            // of the symlink target below; any other stale copy goes first.
            if previous.as_ref() != Some(&manifest.version) && dest.exists() {
                std::fs::remove_dir_all(&dest)?;
            }
            if dest.exists() {
                // Same version as current: stage next to it and swap names.
                let old = root.join(format!(".old-{}", random_suffix()?));
                std::fs::rename(&dest, &old)?;
                std::fs::rename(&tmp, &dest)?;
                std::fs::remove_dir_all(&old)?;
            } else {
                std::fs::rename(&tmp, &dest)?;
            }
            let link_tmp = root.join(format!(".link-{}", random_suffix()?));
            std::os::unix::fs::symlink(&version, &link_tmp)?;
            std::fs::rename(&link_tmp, root.join("current"))?;
            Ok(())
        })();
        if let Err(e) = staged {
            let _ = std::fs::remove_dir_all(&tmp);
            return Err(e);
        }

        let previous_good = previous.filter(|p| *p != manifest.version);
        prune(&root, &manifest.version, previous_good.as_ref());
        Ok(PackStatus {
            name: manifest.name,
            version: manifest.version,
            dir: dest,
            previous: previous_good,
        })
    }

    /// Keep the new current and the last good; drop older versions and
    /// leftovers of interrupted installs. Best effort.
    fn prune(root: &Path, current: &Version, previous: Option<&Version>) {
        let Ok(rd) = std::fs::read_dir(root) else {
            return;
        };
        let mut versions: Vec<Version> = Vec::new();
        for e in rd.filter_map(Result::ok) {
            let name = e.file_name().to_string_lossy().into_owned();
            match Version::parse(&name) {
                Ok(v) if e.path().is_dir() => versions.push(v),
                Ok(_) => {}
                Err(_) if name.starts_with(".tmp-") || name.starts_with(".old-") => {
                    let _ = std::fs::remove_dir_all(e.path());
                }
                Err(_) => {}
            }
        }
        versions.sort();
        versions.reverse();
        let mut keep = vec![current.clone()];
        if let Some(p) = previous.filter(|p| **p != *current) {
            keep.push(p.clone());
        }
        for v in versions {
            if keep.contains(&v) {
                continue;
            }
            if keep.len() < KEEP {
                keep.push(v);
            } else {
                let _ = std::fs::remove_dir_all(root.join(v.to_string()));
            }
        }
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
        let s = install(&a, &sign(&k, &a), &[k.public], st.path(), &v("0.2.0")).unwrap();
        assert_eq!(s.version, v("1.0.0"));
        let r = resolve("extra", Path::new("/nonexistent"), st.path());
        assert_eq!(r.source, PackSource::Installed(v("1.0.0")));
        assert!(r.path.join("extra.bpf.o").is_file());
        let m = Manifest::parse(&std::fs::read(r.path.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(read_rules(&r.path, &m).unwrap()[0].id, "p-1");
    }

    #[test]
    fn wrong_key_refused() {
        let (k, other, st) = (keys(), keys(), tempfile::tempdir().unwrap());
        let a = pack("1.0.0", "0.1.0");
        let e = install(&a, &sign(&k, &a), &[other.public], st.path(), &v("1.0.0")).unwrap_err();
        assert!(matches!(e, PackError::UnknownKey), "{e:?}");
        assert!(!st.path().join("packs").exists());
    }

    #[test]
    fn tampered_archive_refused() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        let mut a = pack("1.0.0", "0.1.0");
        let s = sign(&k, &a);
        *a.last_mut().unwrap() ^= 1;
        let e = install(&a, &s, &[k.public], st.path(), &v("1.0.0")).unwrap_err();
        assert!(matches!(e, PackError::BadSignature), "{e:?}");
    }

    #[test]
    fn too_new_refused_and_current_kept() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        let ks = [k.public.clone()];
        let a = pack("1.0.0", "0.1.0");
        install(&a, &sign(&k, &a), &ks, st.path(), &v("0.2.0")).unwrap();
        let b = pack("2.0.0", "9.0.0");
        let e = install(&b, &sign(&k, &b), &ks, st.path(), &v("0.2.0")).unwrap_err();
        assert!(matches!(e, PackError::TooNew { .. }), "{e:?}");
        let r = resolve("extra", Path::new("/x"), st.path());
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
        let e = install(&a, &sign(&k, &a), &[k.public], st.path(), &v("1.0.0")).unwrap_err();
        assert!(
            matches!(e, PackError::MissingProgram(ref p) if p == "gone.bpf.o"),
            "{e:?}"
        );
    }

    #[test]
    fn resolve_falls_back_to_builtin() {
        let st = tempfile::tempdir().unwrap();
        let r = resolve("core", Path::new("/b"), st.path());
        assert_eq!(
            r,
            PackDir {
                path: PathBuf::from("/b/core"),
                source: PackSource::Builtin
            }
        );
    }

    #[test]
    fn resolve_ignores_a_damaged_current() {
        let (k, st) = (keys(), tempfile::tempdir().unwrap());
        let a = pack("1.0.0", "0.1.0");
        let s = install(&a, &sign(&k, &a), &[k.public], st.path(), &v("1.0.0")).unwrap();
        std::fs::remove_file(s.dir.join("extra.bpf.o")).unwrap();
        assert_eq!(
            resolve("extra", Path::new("/b"), st.path()).source,
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
            let s = install(&a, &sign(&k, &a), &ks, st.path(), &v("1.0.0")).unwrap();
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
        let s = install(&a, &sign(&k, &a), &ks, st.path(), &v("1.0.0")).unwrap();
        assert_eq!(s.previous, None, "nothing was replaced");
        assert!(root.join("1.1.0").is_dir());
        let leftovers = std::fs::read_dir(&root).unwrap().count();
        assert_eq!(leftovers, 3, "1.1.0, 1.2.0, current");
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
}
