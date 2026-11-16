//! Secrets never leave the agent (docs/PLAN.md §2.4 item 7).
//!
//! Which fields are secret is decided by the schema: every
//! [`Secret`](sensr_schema::fields::Secret) field of the typed document, found
//! by serialising it once plainly and once in
//! [`redacted`](sensr_schema::fields::redacted) mode and comparing. Field
//! names play no part, so a new secret in the schema is masked without
//! touching this module, and a field that merely happens to be called
//! `password` is not.
//!
//! Reads, diffs and plans replace secret values with `***` plus a short
//! keyed digest, so an operator can see *that* a secret changed but not its
//! value, and the digest cannot be brute-forced offline (the key is random
//! per agent process). Writes treat a `***…` value at a secret field as
//! "keep the stored value" (OPNsense `UpdateOnlyTextField` semantics), so a
//! client can read an object, edit another field and write it back.

use std::sync::OnceLock;

use sensr_schema::Document;
use sensr_schema::fields::{REDACTED, redacted};
use serde_json::Value;

/// Prefix of every masked value.
pub const MARKER: &str = "***";

/// A document as JSON plus the JSON pointers of its secret values.
#[derive(Debug, Clone, PartialEq)]
pub struct View {
    /// The plain document.
    pub value: Value,
    /// RFC 6901 pointers to every set secret, in document order.
    pub secrets: Vec<String>,
}

impl View {
    /// The document and where its secrets are.
    pub fn of(doc: &Document) -> View {
        let value = serde_json::to_value(doc).unwrap_or(Value::Null);
        let red = redacted(|| serde_json::to_value(doc)).unwrap_or(Value::Null);
        let mut secrets = Vec::new();
        collect(&value, &red, &mut String::new(), &mut secrets);
        View { value, secrets }
    }

    /// The document with every secret masked.
    pub fn masked(&self) -> Value {
        let mut out = self.value.clone();
        for p in &self.secrets {
            if let Some(slot) = out.pointer_mut(p) {
                *slot = mask(slot);
            }
        }
        out
    }
}

/// The document as JSON with every secret masked.
pub fn masked(doc: &Document) -> Value {
    View::of(doc).masked()
}

fn escape(seg: &str) -> String {
    seg.replace('~', "~0").replace('/', "~1")
}

fn collect(plain: &Value, red: &Value, path: &mut String, out: &mut Vec<String>) {
    match (plain, red) {
        (Value::Object(p), Value::Object(r)) => {
            for (k, pv) in p {
                if let Some(rv) = r.get(k) {
                    let len = path.len();
                    path.push('/');
                    path.push_str(&escape(k));
                    collect(pv, rv, path, out);
                    path.truncate(len);
                }
            }
        }
        (Value::Array(p), Value::Array(r)) => {
            for (i, (pv, rv)) in p.iter().zip(r).enumerate() {
                let len = path.len();
                path.push_str(&format!("/{i}"));
                collect(pv, rv, path, out);
                path.truncate(len);
            }
        }
        (p, Value::String(r)) if r == REDACTED && p.as_str() != Some(REDACTED) => {
            out.push(path.clone());
        }
        _ => {}
    }
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

/// True for a masked placeholder as [`View::masked`] writes them.
pub fn is_placeholder(v: &Value) -> bool {
    v.as_str().is_some_and(|s| s.starts_with(MARKER))
}

/// Puts the stored secret back wherever `new` carries a placeholder at a
/// position that held a secret in `old`.
pub fn restore(new: &mut Value, old: &View) {
    for p in &old.secrets {
        if let Some(slot) = new.pointer_mut(p)
            && is_placeholder(slot)
            && let Some(stored) = old.value.pointer(p)
        {
            *slot = stored.clone();
        }
    }
}

/// Removes placeholders the schema says sit in secret fields but that have
/// no stored value behind them (a new object written back with its masked
/// secrets), so `***` is never stored as a secret. Returns whether anything
/// was removed; the caller decodes again.
pub fn drop_unbacked(new: &mut Value, decoded: &Document) -> bool {
    let view = View::of(decoded);
    let mut removed = false;
    for p in view.secrets.iter().rev() {
        if new.pointer(p).is_some_and(is_placeholder)
            && let Some((parent, key)) = p.rsplit_once('/')
            && let Some(Value::Object(m)) = new.pointer_mut(parent)
        {
            m.remove(&key.replace("~1", "/").replace("~0", "~"));
            removed = true;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensr_schema::PathAccess;
    use serde_json::json;

    const WG: &str = "wireguard.servers.00000000-0000-0000-0000-000000000001";
    const KEY: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";

    fn with_wg() -> Document {
        let mut doc = Document::factory();
        doc.set_by_path(
            WG,
            json!({"name": "wg0", "instance": 0, "private_key": KEY}),
        )
        .unwrap();
        doc
    }

    #[test]
    fn schema_decides_what_is_secret() {
        let doc = with_wg();
        let view = View::of(&doc);
        assert_eq!(
            view.secrets,
            ["/wireguard/servers/00000000-0000-0000-0000-000000000001/private_key"]
        );
        let m = view.masked();
        let masked = m.pointer(&view.secrets[0]).unwrap().as_str().unwrap();
        assert!(masked.starts_with(MARKER) && masked.len() == 11, "{masked}");
        assert!(!m.to_string().contains(KEY));
        // Public fields with secret-sounding names are not masked: only the
        // schema's Secret fields are.
        assert_eq!(m["system"]["hostname"], view.value["system"]["hostname"]);
    }

    #[test]
    fn changed_secrets_get_different_markers() {
        let a = masked(&with_wg());
        let mut other = with_wg();
        other
            .set_by_path(
                &format!("{WG}.private_key"),
                json!("cGBP0J1mfVpNsoN9dpzlnVRl0mW7Lnm0iQCw1ImeLHA="),
            )
            .unwrap();
        let b = masked(&other);
        assert_ne!(a, b);
        assert_eq!(a, masked(&with_wg()));
    }

    #[test]
    fn placeholders_restore_stored_values_and_unbacked_ones_are_dropped() {
        let doc = with_wg();
        let old = View::of(&doc);
        let mut new = old.masked();
        new["system"]["hostname"] = json!("edge");
        restore(&mut new, &old);
        assert_eq!(
            new.pointer(&old.secrets[0]).unwrap(),
            &json!(KEY),
            "write-back keeps the key"
        );

        // A new user written with a masked hash: the placeholder is dropped
        // instead of being stored as the hash.
        let mut fresh = View::of(&Document::factory()).value;
        fresh["system"]["users"]["00000000-0000-0000-0000-0000000000aa"] =
            json!({"name": "bob", "uid": 2001, "password_hash": "***deadbeef"});
        let decoded: Document = serde_json::from_value(fresh.clone()).unwrap();
        assert!(drop_unbacked(&mut fresh, &decoded));
        assert!(
            fresh["system"]["users"]["00000000-0000-0000-0000-0000000000aa"]
                .get("password_hash")
                .is_none()
        );
        // A description that merely starts with *** is data, not a mask.
        let mut text = View::of(&Document::factory()).value;
        text["system"]["users"]["00000000-0000-0000-0000-0000000000ab"] =
            json!({"name": "eve", "uid": 2002, "description": "***stars***"});
        let decoded: Document = serde_json::from_value(text.clone()).unwrap();
        assert!(!drop_unbacked(&mut text, &decoded));
    }
}
