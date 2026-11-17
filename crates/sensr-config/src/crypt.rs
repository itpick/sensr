//! Encryption at rest for the secrets table (PLAN §2.4 item 7).
//!
//! Secret values are sealed with XChaCha20-Poly1305 under a 256-bit key kept
//! in its own root-only file, outside the database. A copy of `config.db`
//! (a backup, a support bundle, a lost SD card image without the key file)
//! then holds no usable key material. Each value is bound to its revision
//! and JSON pointer as associated data, so ciphertexts cannot be moved
//! between slots. Rows written before a key was configured stay readable
//! (plain JSON) and are sealed the next time the store opens with a key.

use std::fmt;
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

/// Prefix of a sealed value: format version 1.
const SEALED: &str = "enc1:";
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// The key that seals the secrets table.
#[derive(Clone)]
pub struct SecretsKey([u8; KEY_LEN]);

impl fmt::Debug for SecretsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretsKey(***)")
    }
}

impl SecretsKey {
    /// A key from raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// A fresh random key.
    pub fn generate() -> std::io::Result<Self> {
        let mut k = [0u8; KEY_LEN];
        getrandom::fill(&mut k).map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(Self(k))
    }

    /// Reads the key at `path` (64 hex digits), creating it with mode 0600
    /// when it does not exist. A key file readable by group or others is
    /// refused rather than used.
    pub fn load_or_create(path: &Path) -> std::io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                check_mode(path)?;
                let bytes = decode_hex(text.trim())
                    .filter(|b| b.len() == KEY_LEN)
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("{} does not hold a 256-bit hex key", path.display()),
                        )
                    })?;
                let mut k = [0u8; KEY_LEN];
                k.copy_from_slice(&bytes);
                Ok(Self(k))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = Self::generate()?;
                write_new(path, format!("{}\n", encode_hex(&key.0)).as_bytes())?;
                Ok(key)
            }
            Err(e) => Err(e),
        }
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(&self.0.into())
    }

    /// Seals `plain` for slot (`revision`, `pointer`).
    pub(crate) fn seal(&self, revision: i64, pointer: &str, plain: &str) -> Result<String, String> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
        let aad = aad(revision, pointer);
        let ct = self
            .cipher()
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plain.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|e| e.to_string())?;
        Ok(format!("{SEALED}{}{}", encode_hex(&nonce), encode_hex(&ct)))
    }

    /// Opens a value sealed by [`SecretsKey::seal`] for the same slot.
    pub(crate) fn open(
        &self,
        revision: i64,
        pointer: &str,
        sealed: &str,
    ) -> Result<String, String> {
        let hex = sealed.strip_prefix(SEALED).ok_or("not a sealed value")?;
        let raw = decode_hex(hex).ok_or("sealed value is not hex")?;
        if raw.len() < NONCE_LEN {
            return Err("sealed value is truncated".into());
        }
        let (nonce, ct) = raw.split_at(NONCE_LEN);
        let mut n = [0u8; NONCE_LEN];
        n.copy_from_slice(nonce);
        let aad = aad(revision, pointer);
        let plain = self
            .cipher()
            .decrypt(&XNonce::from(n), Payload { msg: ct, aad: &aad })
            .map_err(|_| "the secret does not open with this key (wrong key or tampered row)")?;
        String::from_utf8(plain).map_err(|e| e.to_string())
    }
}

/// True for a value written by [`SecretsKey::seal`].
pub(crate) fn is_sealed(value: &str) -> bool {
    value.starts_with(SEALED)
}

fn aad(revision: i64, pointer: &str) -> Vec<u8> {
    format!("sensr-secret:{revision}:{pointer}").into_bytes()
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(unix)]
fn check_mode(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} is accessible to group or others (mode {:o}); refusing to use it",
                path.display(),
                mode & 0o777
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_mode(_: &Path) -> std::io::Result<()> {
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_and_opens_bound_to_the_slot() {
        let k = SecretsKey::generate().unwrap();
        let s = k.seal(3, "/a/b", "\"hunter2\"").unwrap();
        assert!(is_sealed(&s) && !s.contains("hunter2"));
        assert_eq!(k.open(3, "/a/b", &s).unwrap(), "\"hunter2\"");
        assert!(k.open(4, "/a/b", &s).is_err(), "other revision");
        assert!(k.open(3, "/a/c", &s).is_err(), "other pointer");
        let other = SecretsKey::generate().unwrap();
        assert!(other.open(3, "/a/b", &s).is_err(), "other key");
        assert_ne!(s, k.seal(3, "/a/b", "\"hunter2\"").unwrap(), "fresh nonce");
    }

    #[test]
    fn key_file_is_created_private_and_reloaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys/secrets.key");
        let a = SecretsKey::load_or_create(&path).unwrap();
        let b = SecretsKey::load_or_create(&path).unwrap();
        assert_eq!(a.0, b.0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(SecretsKey::load_or_create(&path).is_err());
        }
        assert_eq!(format!("{a:?}"), "SecretsKey(***)");
    }
}
