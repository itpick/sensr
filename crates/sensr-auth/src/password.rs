//! Local password hashes.
//!
//! New hashes are argon2id PHC strings. bcrypt (`$2y$`, OPNsense's
//! `password_hash()` default) is verified so users imported from a
//! `config.xml` can log in unchanged; [`needs_rehash`] tells the caller to
//! upgrade such a hash after a successful login.

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};

/// Hashing failed (only on RNG or parameter errors).
#[derive(Debug, thiserror::Error)]
#[error("password hashing failed: {0}")]
pub struct HashError(String);

/// Hashes `password` as an argon2id PHC string with a random salt.
pub fn hash_password(password: &str) -> Result<String, HashError> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| HashError(e.to_string()))
}

/// Checks `password` against a stored argon2 or bcrypt hash. Unknown or
/// malformed hashes never verify.
pub fn verify_password(password: &str, stored: &str) -> bool {
    if stored.starts_with("$argon2") {
        return PasswordHash::new(stored).ok().is_some_and(|h| {
            Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        });
    }
    if is_bcrypt(stored) {
        return bcrypt::verify(password, stored).unwrap_or(false);
    }
    false
}

/// True when `stored` is not an argon2id hash and should be replaced by
/// [`hash_password`] at the next successful login.
pub fn needs_rehash(stored: &str) -> bool {
    !stored.starts_with("$argon2id$")
}

fn is_bcrypt(s: &str) -> bool {
    ["$2a$", "$2b$", "$2x$", "$2y$"]
        .iter()
        .any(|p| s.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_round_trip() {
        let h = hash_password("opnsense").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("opnsense", &h));
        assert!(!verify_password("OPNsense", &h));
        assert!(!needs_rehash(&h));
    }

    #[test]
    fn salts_differ() {
        assert_ne!(hash_password("x").unwrap(), hash_password("x").unwrap());
    }

    /// The root hash in upstream's ACL fixture is bcrypt of `opnsense`, the
    /// factory default password.
    #[test]
    fn imported_bcrypt_hash_verifies() {
        let stored = "$2y$10$YRVoF4SgskIsrXOvOQjGieB9XqHPRra9R7d80B3BZdbY/j21TwBfS";
        assert!(verify_password("opnsense", stored));
        assert!(!verify_password("wrong", stored));
        assert!(needs_rehash(stored));
    }

    #[test]
    fn garbage_never_verifies() {
        for stored in ["", "plain", "$argon2id$broken", "$2y$xx", "$6$salt$hash"] {
            assert!(!verify_password("", stored));
            assert!(!verify_password("plain", stored));
        }
    }
}
