//! OPNsense-style API keys: a public `key` and a `secret`, each the base64
//! of 60 random bytes, presented as HTTP Basic `key:secret`. Only the key and
//! a SHA-512-crypt (`$6$`) hash of the secret are stored, the same format
//! OPNsense writes, so keys survive import and export unchanged.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha_crypt::{PasswordHash, PasswordHasher, PasswordVerifier, ShaCrypt};

/// A freshly generated key pair. The clear secret exists only here and must
/// be shown to the user once.
#[derive(Clone, PartialEq, Eq)]
pub struct NewApiKey {
    /// Public key (80 base64 characters).
    pub key: String,
    /// Clear secret (80 base64 characters).
    pub secret: String,
    /// What to store: SHA-512-crypt of `secret`.
    pub secret_hash: String,
}

impl std::fmt::Debug for NewApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewApiKey")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// Key generation failed (RNG unavailable).
#[derive(Debug, thiserror::Error)]
#[error("api key generation failed: {0}")]
pub struct KeyGenError(String);

fn random_b64() -> Result<String, KeyGenError> {
    let mut bytes = [0u8; 60];
    getrandom::fill(&mut bytes).map_err(|e| KeyGenError(e.to_string()))?;
    Ok(STANDARD.encode(bytes))
}

/// Generates a new key pair.
pub fn generate() -> Result<NewApiKey, KeyGenError> {
    let key = random_b64()?;
    let secret = random_b64()?;
    let secret_hash = ShaCrypt::default()
        .hash_password(secret.as_bytes())
        .map_err(|e| KeyGenError(e.to_string()))?
        .to_string();
    Ok(NewApiKey {
        key,
        secret,
        secret_hash,
    })
}

/// Checks a presented secret against its stored hash: SHA-crypt (`$6$`,
/// `$5$`) as OPNsense stores it, or any password hash
/// [`crate::password::verify_password`] understands.
pub fn verify_secret(secret: &str, stored: &str) -> bool {
    if stored.starts_with("$6$") || stored.starts_with("$5$") {
        return PasswordHash::new(stored).ok().is_some_and(|h| {
            ShaCrypt::default()
                .verify_password(secret.as_bytes(), &h)
                .is_ok()
        });
    }
    crate::password::verify_password(secret, stored)
}

/// Decodes an `Authorization: Basic …` header value into `(user, secret)`.
/// Works for both `username:password` and `key:secret`.
pub fn parse_basic(header: &str) -> Option<(String, String)> {
    let (scheme, b64) = header.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let raw = STANDARD.decode(b64.trim()).ok()?;
    let raw = String::from_utf8(raw).ok()?;
    let (user, secret) = raw.split_once(':')?;
    Some((user.to_owned(), secret.to_owned()))
}

/// Encodes `user:secret` as an `Authorization` header value.
pub fn basic_header(user: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{user}:{secret}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_have_opnsense_shape() {
        let k = generate().unwrap();
        assert_eq!(k.key.len(), 80);
        assert_eq!(k.secret.len(), 80);
        assert!(k.secret_hash.starts_with("$6$"));
        assert!(verify_secret(&k.secret, &k.secret_hash));
        assert!(!verify_secret(&k.key, &k.secret_hash));
        assert!(!format!("{k:?}").contains(&k.secret));
    }

    /// Reference vector from the SHA-crypt specification (Drepper, 2007).
    #[test]
    fn sha512_crypt_reference_vector() {
        let stored = "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1";
        assert!(verify_secret("Hello world!", stored));
        assert!(!verify_secret("Hello world", stored));
    }

    #[test]
    fn basic_round_trip() {
        let h = basic_header("key+/=", "se:cret");
        assert_eq!(parse_basic(&h), Some(("key+/=".into(), "se:cret".into())));
        assert_eq!(parse_basic("Bearer abc"), None);
        assert_eq!(parse_basic("Basic !!!"), None);
        assert_eq!(parse_basic("Basic"), None);
    }
}
