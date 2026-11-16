//! Key material fields: WireGuard keys and SSH public keys.

use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use super::string_serde;
use crate::validation::FieldError;

/// A WireGuard key (private, public or pre-shared): 32 bytes, written as
/// 44 characters of padded standard base64.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WgKey([u8; 32]);

impl WgKey {
    /// The raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wraps raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for WgKey {
    // Keys appear in debug output of whole documents; print only a prefix so a
    // private key never lands in a log in full.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = self.to_string();
        write!(f, "WgKey({}...)", &text[..8])
    }
}

impl FromStr for WgKey {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || FieldError::syntax("A WireGuard key must be 32 bytes encoded as base64.");
        if s.len() != 44 {
            return Err(err());
        }
        let bytes = STANDARD.decode(s).map_err(|_| err())?;
        let key: [u8; 32] = bytes.try_into().map_err(|_| err())?;
        Ok(Self(key))
    }
}

impl fmt::Display for WgKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&STANDARD.encode(self.0))
    }
}
string_serde!(WgKey);

/// One line of an OpenSSH `authorized_keys` file: `type base64 [comment]`,
/// without options. The key blob must decode and name the same type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SshPublicKey {
    algorithm: String,
    blob: String,
    comment: Option<String>,
}

const SSH_KEY_TYPES: &[&str] = &[
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "sk-ssh-ed25519@openssh.com",
    "ssh-dss",
    "ssh-ed25519",
    "ssh-rsa",
];

impl SshPublicKey {
    /// The key type, e.g. `ssh-ed25519`.
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// The trailing comment, if any.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }
}

impl FromStr for SshPublicKey {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = |m: &str| FieldError::syntax(m.to_owned());
        if s.contains(['\n', '\r', '\0']) {
            return Err(err("An SSH key must be a single line."));
        }
        let mut parts = s.trim().splitn(3, char::is_whitespace);
        let algorithm = parts.next().unwrap_or_default();
        let blob = parts.next().unwrap_or_default();
        let comment = parts.next().map(str::trim).filter(|c| !c.is_empty());
        if !SSH_KEY_TYPES.contains(&algorithm) {
            return Err(err("Unsupported SSH key type."));
        }
        let raw = STANDARD
            .decode(blob)
            .map_err(|_| err("The SSH key data is not valid base64."))?;
        // The blob starts with the type as an SSH string (u32 length + bytes).
        let named = raw
            .get(..4)
            .map(|l| u32::from_be_bytes([l[0], l[1], l[2], l[3]]) as usize)
            .and_then(|len| raw.get(4..4usize.checked_add(len)?));
        if named != Some(algorithm.as_bytes()) {
            return Err(err("The SSH key data does not match its type."));
        }
        Ok(Self {
            algorithm: algorithm.to_owned(),
            blob: blob.to_owned(),
            comment: comment.map(str::to_owned),
        })
    }
}

impl fmt::Display for SshPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.algorithm, self.blob)?;
        if let Some(c) = &self.comment {
            write!(f, " {c}")?;
        }
        Ok(())
    }
}
string_serde!(SshPublicKey);

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";

    #[test]
    fn wg_keys() {
        let k: WgKey = KEY.parse().unwrap();
        assert_eq!(k.to_string(), KEY);
        assert_eq!(format!("{k:?}"), "WgKey(yAnz5TF+...)");
        for bad in [
            "",
            "abc",
            &KEY[..43],
            &format!("{KEY}A"),
            "!Anz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
        ] {
            assert!(bad.parse::<WgKey>().is_err(), "{bad}");
        }
    }

    #[test]
    fn ssh_keys() {
        let blob = STANDARD
            .encode([&[0, 0, 0, 11][..], b"ssh-ed25519", &[0, 0, 0, 32], &[7; 32]].concat());
        let line = format!("ssh-ed25519 {blob} admin@laptop");
        let k: SshPublicKey = line.parse().unwrap();
        assert_eq!(k.algorithm(), "ssh-ed25519");
        assert_eq!(k.comment(), Some("admin@laptop"));
        assert_eq!(k.to_string(), line);
        assert!(
            format!("ssh-rsa {blob}").parse::<SshPublicKey>().is_err(),
            "type mismatch"
        );
        assert!("ssh-ed25519 !!!".parse::<SshPublicKey>().is_err());
        assert!(
            format!("ssh-ed25519 {blob}\nssh-ed25519 {blob}")
                .parse::<SshPublicKey>()
                .is_err()
        );
    }
}
