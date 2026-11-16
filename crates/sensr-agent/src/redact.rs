//! Secrets never leave the agent (docs/PLAN.md §2.4 item 7).
//!
//! Reads, diffs and plans replace secret fields with `***` plus a short
//! keyed digest, so an operator can see *that* a secret changed but not its
//! value, and the digest cannot be brute-forced offline (the key is random
//! per agent process). Writes treat any `***…` value at a secret field as
//! "keep the stored value" (OPNsense `UpdateOnlyTextField` semantics), so a
//! client can read an object, edit another field and write it back.

use std::sync::OnceLock;

use serde_json::Value;

/// Field names that hold secrets, in both the OPNsense array view and the
/// typed `sensr-schema` document.
const SECRET_KEYS: &[&str] = &[
    "apikeys",
    "bindpw",
    "ldap_bindpw",
    "otp_seed",
    "password",
    "password_hash",
    "pre_shared_key",
    "presharedkey",
    "private_key",
    "privkey",
    "prv",
    "psk",
    "radius_secret",
    "secret",
    "secret_hash",
];

/// Prefix of every redacted value.
pub const MARKER: &str = "***";

fn is_secret(key: &str) -> bool {
    SECRET_KEYS.contains(&key)
}

fn digest_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        if getrandom::fill(&mut key).is_err() {
            // No RNG: fall back to something API clients cannot predict
            // without access to the host.
            key = *blake3::hash(
                format!("{}:{}", crate::store::now_ms(), std::process::id()).as_bytes(),
            )
            .as_bytes();
        }
        key
    })
}

fn mask(v: &Value) -> Value {
    if v.is_null() || v.as_str().is_some_and(str::is_empty) {
        // "No secret set" is not secret.
        return v.clone();
    }
    let digest = blake3::keyed_hash(digest_key(), v.to_string().as_bytes());
    Value::String(format!("{MARKER}{}", &digest.to_hex()[..8]))
}

/// A copy of `v` with every secret field masked.
pub fn redacted(v: &Value) -> Value {
    let mut out = v.clone();
    redact(&mut out);
    out
}

/// Masks every secret field in place.
pub fn redact(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, child) in m.iter_mut() {
                if is_secret(k) && !child.is_object() && !child.is_array() {
                    *child = mask(child);
                } else if is_secret(k) {
                    // A structured secret (e.g. a list of key/secret pairs):
                    // keep the shape, mask the leaves.
                    mask_leaves(child);
                } else {
                    redact(child);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact),
        _ => {}
    }
}

fn mask_leaves(v: &mut Value) {
    match v {
        Value::Object(m) => {
            for (k, child) in m.iter_mut() {
                // Public halves stay readable.
                if k == "key" || k == "name" || k == "descr" {
                    continue;
                }
                mask_leaves(child);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(mask_leaves),
        leaf => *leaf = mask(leaf),
    }
}

/// Where `new` carries a masked placeholder for a secret, put back the value
/// from `old` at the same position (or drop the placeholder when there is
/// none, so `***` can never be stored as a secret).
pub fn restore(new: &mut Value, old: Option<&Value>) {
    match new {
        Value::Object(m) => {
            let keys: Vec<String> = m.keys().cloned().collect();
            for k in keys {
                let prev = old.and_then(|o| o.get(&k));
                let child = m.get_mut(&k).expect("key listed above");
                if is_placeholder(child) {
                    match prev {
                        Some(p) => *child = p.clone(),
                        None => {
                            m.remove(&k);
                        }
                    }
                } else {
                    restore(child, prev);
                }
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                restore(item, old.and_then(|o| o.get(i)));
            }
        }
        _ => {}
    }
}

fn is_placeholder(v: &Value) -> bool {
    v.as_str().is_some_and(|s| s.starts_with(MARKER))
}

/// True when `v` is a masked placeholder (used for a bare-value `set` on a
/// secret path).
pub fn is_masked(v: &Value) -> bool {
    is_placeholder(v)
}

/// True when the last segment of a path names a secret field.
pub fn is_secret_path(path: &sensr_ipc::ConfigPath) -> bool {
    matches!(
        path.segments().last(),
        Some(sensr_ipc::path::Segment::Key(k)) if is_secret(k)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn masks_secrets_keeps_structure_and_public_halves() {
        let doc = json!({
            "system": {"user": [{"name": "root", "password": "$2y$10$abc", "apikeys": "k|$6$x|1|d"}]},
            "wireguard": {"server": {"privkey": "PRIV", "pubkey": "PUB"}},
            "typed": {"api_keys": [{"key": "K", "secret_hash": "$6$y"}], "password_hash": null},
        });
        let r = redacted(&doc);
        let pw = r["system"]["user"][0]["password"].as_str().unwrap();
        assert!(pw.starts_with(MARKER) && pw.len() == 11, "{pw}");
        assert!(
            r["system"]["user"][0]["apikeys"]
                .as_str()
                .unwrap()
                .starts_with(MARKER)
        );
        assert!(
            r["wireguard"]["server"]["privkey"]
                .as_str()
                .unwrap()
                .starts_with(MARKER)
        );
        assert_eq!(r["wireguard"]["server"]["pubkey"], "PUB");
        assert_eq!(r["typed"]["api_keys"][0]["key"], "K");
        assert!(
            r["typed"]["api_keys"][0]["secret_hash"]
                .as_str()
                .unwrap()
                .starts_with(MARKER)
        );
        assert_eq!(r["typed"]["password_hash"], Value::Null);
        assert!(!r.to_string().contains("abc"));
        assert!(!r.to_string().contains("PRIV"));
    }

    #[test]
    fn changed_secrets_get_different_markers() {
        let a = redacted(&json!({"psk": "one"}));
        let b = redacted(&json!({"psk": "two"}));
        assert_ne!(a, b);
        assert_eq!(a, redacted(&json!({"psk": "one"})));
    }

    #[test]
    fn placeholders_restore_stored_values() {
        let old = json!({"user": [{"name": "root", "password": "HASH"}], "psk": "P"});
        let mut new = redacted(&old);
        new["user"][0]["name"] = json!("admin");
        restore(&mut new, Some(&old));
        assert_eq!(
            new,
            json!({"user": [{"name": "admin", "password": "HASH"}], "psk": "P"})
        );

        let mut fresh = json!({"psk": "***deadbeef"});
        restore(&mut fresh, None);
        assert_eq!(fresh, json!({}));
    }
}
