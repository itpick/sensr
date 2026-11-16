//! Keeping secrets out of the revision documents.
//!
//! A revision's `document` column holds the document with every
//! [`sensr_schema::fields::Secret`] replaced by the redaction marker; the
//! values live in the `secrets` table keyed by revision and JSON pointer. So
//! reading history, diffing or exporting rows never handles key material,
//! and the secrets table can get its own protection (PLAN §2.4 item 7).
//! The content hash still covers the full document, secrets included.

use serde_json::Value;

use sensr_schema::Document;
use sensr_schema::fields::{REDACTED, redacted};

/// The document split into redacted canonical JSON and `(pointer, value)`
/// secrets.
pub(crate) struct Split {
    pub redacted: String,
    pub secrets: Vec<(String, String)>,
}

fn escape(seg: &str) -> String {
    seg.replace('~', "~0").replace('/', "~1")
}

fn collect(plain: &Value, red: &Value, path: &mut String, out: &mut Vec<(String, String)>) {
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
        (p, Value::String(r)) if r == REDACTED && p != &Value::String(REDACTED.to_owned()) => {
            out.push((path.clone(), p.to_string()));
        }
        _ => {}
    }
}

/// Splits `doc` into redacted JSON and its secrets.
pub(crate) fn split(doc: &Document) -> Result<Split, serde_json::Error> {
    let plain = serde_json::to_value(doc)?;
    let red = redacted(|| serde_json::to_value(doc))?;
    let mut secrets = Vec::new();
    collect(&plain, &red, &mut String::new(), &mut secrets);
    Ok(Split {
        redacted: serde_json::to_string(&red)?,
        secrets,
    })
}

/// Puts `secrets` back into redacted JSON, giving the canonical document
/// text. Fails if a pointer does not lead to a redaction marker.
pub(crate) fn join(redacted_json: &str, secrets: &[(String, String)]) -> Result<String, String> {
    if secrets.is_empty() {
        return Ok(redacted_json.to_owned());
    }
    let mut v: Value = serde_json::from_str(redacted_json).map_err(|e| e.to_string())?;
    for (pointer, value) in secrets {
        let slot = v
            .pointer_mut(pointer)
            .ok_or_else(|| format!("secret at {pointer} has no place in the document"))?;
        if slot != &Value::String(REDACTED.to_owned()) {
            return Err(format!(
                "secret at {pointer} does not replace a redaction marker"
            ));
        }
        *slot = serde_json::from_str(value).map_err(|e| e.to_string())?;
    }
    serde_json::to_string(&v).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::canonical_json;
    use sensr_schema::PathAccess;
    use serde_json::json;

    #[test]
    fn split_then_join_is_identity() {
        let mut doc = Document::factory();
        doc.set_by_path(
            "wireguard.servers.00000000-0000-0000-0000-000000000001",
            json!({"name": "wg0", "instance": 0, "private_key": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="}),
        )
        .unwrap();
        let s = split(&doc).unwrap();
        assert!(!s.redacted.contains("yAnz5TF"));
        assert_eq!(s.secrets.len(), 1);
        assert_eq!(
            s.secrets[0].0,
            "/wireguard/servers/00000000-0000-0000-0000-000000000001/private_key"
        );
        assert_eq!(
            join(&s.redacted, &s.secrets).unwrap(),
            canonical_json(&doc).unwrap()
        );
        assert!(join(&s.redacted, &[("/system/hostname".into(), "\"x\"".into())]).is_err());
        assert!(join(&s.redacted, &[("/nope".into(), "\"x\"".into())]).is_err());
    }

    #[test]
    fn no_secrets_no_rows() {
        let doc = Document::factory();
        let s = split(&doc).unwrap();
        assert!(s.secrets.is_empty());
        assert_eq!(s.redacted, canonical_json(&doc).unwrap());
    }
}
