//! Dotted-path access to any model (OPNsense `getNodeByReference` /
//! `setNodeByReference`).
//!
//! Paths name struct fields, map keys (interface ids) and array item UUIDs:
//! `interfaces.lan.ipv4.address`, `firewall.rules.<uuid>.enabled`. Edits go
//! through `serde_json::Value` and back through the typed deserializer, so a
//! path edit can never produce a document the types would not accept; unknown
//! fields are rejected because every model denies them.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Why a path operation failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// A segment does not exist (or descends into a scalar).
    #[error("{0} not found")]
    NotFound(String),
    /// The new value does not fit the field's type.
    #[error("invalid value for {path}: {reason}")]
    Invalid {
        /// The path being set.
        path: String,
        /// The deserializer's explanation.
        reason: String,
    },
    /// The path is empty.
    #[error("an empty path names the whole document")]
    Empty,
}

fn split(path: &str) -> Result<Vec<&str>, PathError> {
    let segs: Vec<&str> = path.split('.').filter(|s| !s.is_empty()).collect();
    if segs.is_empty() {
        Err(PathError::Empty)
    } else {
        Ok(segs)
    }
}

fn walk<'v>(mut v: &'v Value, segs: &[&str]) -> Result<&'v Value, PathError> {
    for (i, seg) in segs.iter().enumerate() {
        v = match v {
            Value::Object(m) => m.get(*seg),
            Value::Array(a) => seg.parse::<usize>().ok().and_then(|n| a.get(n)),
            _ => None,
        }
        .ok_or_else(|| PathError::NotFound(segs[..=i].join(".")))?;
    }
    Ok(v)
}

fn walk_mut<'v>(mut v: &'v mut Value, segs: &[&str]) -> Result<&'v mut Value, PathError> {
    for (i, seg) in segs.iter().enumerate() {
        v = match v {
            Value::Object(m) => m.get_mut(*seg),
            Value::Array(a) => seg.parse::<usize>().ok().and_then(|n| a.get_mut(n)),
            _ => None,
        }
        .ok_or_else(|| PathError::NotFound(segs[..=i].join(".")))?;
    }
    Ok(v)
}

/// Like [`walk_mut`], but creates missing intermediate objects, so a path
/// can reach into a section or optional struct that is omitted while empty.
/// The typed deserialisation afterwards rejects anything invented this way
/// that the model does not have.
fn walk_mut_create<'v>(mut v: &'v mut Value, segs: &[&str]) -> Result<&'v mut Value, PathError> {
    for (i, seg) in segs.iter().enumerate() {
        v = match v {
            Value::Object(m) => Some(
                m.entry((*seg).to_owned())
                    .or_insert_with(|| Value::Object(serde_json::Map::new())),
            ),
            Value::Array(a) => seg.parse::<usize>().ok().and_then(|n| a.get_mut(n)),
            Value::Null => {
                *v = Value::Object(serde_json::Map::new());
                match v {
                    Value::Object(m) => Some(
                        m.entry((*seg).to_owned())
                            .or_insert_with(|| Value::Object(serde_json::Map::new())),
                    ),
                    _ => None,
                }
            }
            _ => None,
        }
        .ok_or_else(|| PathError::NotFound(segs[..=i].join(".")))?;
    }
    Ok(v)
}

/// Dotted-path reads and edits, available on every serialisable model.
pub trait PathAccess: Serialize + DeserializeOwned {
    /// The JSON value at `path`; an empty path returns the whole model.
    fn get_by_path(&self, path: &str) -> Result<Value, PathError> {
        let root = serde_json::to_value(self).map_err(|e| PathError::Invalid {
            path: path.to_owned(),
            reason: e.to_string(),
        })?;
        let segs: Vec<&str> = path.split('.').filter(|s| !s.is_empty()).collect();
        walk(&root, &segs).cloned()
    }

    /// Replaces the value at `path`. Missing segments are created (an unset
    /// optional field, a new map key or item UUID, a section omitted while
    /// empty); the result must deserialise, so unknown fields and ill-typed
    /// values are rejected and `self` is left unchanged.
    fn set_by_path(&mut self, path: &str, value: Value) -> Result<(), PathError> {
        let segs = split(path)?;
        let mut root = serde_json::to_value(&*self).map_err(|e| invalid(path, e))?;
        let (last, parent) = segs.split_last().ok_or(PathError::Empty)?;
        match walk_mut_create(&mut root, parent)? {
            Value::Object(m) => {
                m.insert((*last).to_owned(), value);
            }
            Value::Array(a) => {
                let slot = last
                    .parse::<usize>()
                    .ok()
                    .and_then(|n| a.get_mut(n))
                    .ok_or_else(|| PathError::NotFound(path.to_owned()))?;
                *slot = value;
            }
            _ => return Err(PathError::NotFound(path.to_owned())),
        }
        *self = serde_json::from_value(root).map_err(|e| invalid(path, e))?;
        Ok(())
    }

    /// Like [`PathAccess::set_by_path`] but takes command-line text: JSON if
    /// it parses and fits, otherwise the text as a string (so `fw1`, `"fw1"`
    /// and, for a host name field, `123` all work).
    fn set_by_path_text(&mut self, path: &str, text: &str) -> Result<(), PathError> {
        match serde_json::from_str::<Value>(text) {
            Ok(v @ Value::String(_)) => self.set_by_path(path, v),
            Ok(v) => self
                .set_by_path(path, v)
                .or_else(|_| self.set_by_path(path, Value::String(text.to_owned()))),
            Err(_) => self.set_by_path(path, Value::String(text.to_owned())),
        }
    }

    /// Removes the value at `path`: unsets an optional field or deletes a
    /// map entry / array item. Fails (leaving `self` unchanged) if the result
    /// would not deserialise, e.g. for a required field.
    fn unset_by_path(&mut self, path: &str) -> Result<(), PathError> {
        let segs = split(path)?;
        let mut root = serde_json::to_value(&*self).map_err(|e| invalid(path, e))?;
        let (last, parent) = segs.split_last().ok_or(PathError::Empty)?;
        match walk_mut(&mut root, parent)? {
            Value::Object(m) => {
                m.shift_remove(*last)
                    .ok_or_else(|| PathError::NotFound(path.to_owned()))?;
            }
            Value::Array(a) => match last.parse::<usize>() {
                Ok(n) if n < a.len() => {
                    a.remove(n);
                }
                _ => return Err(PathError::NotFound(path.to_owned())),
            },
            _ => return Err(PathError::NotFound(path.to_owned())),
        }
        *self = serde_json::from_value(root).map_err(|e| invalid(path, e))?;
        Ok(())
    }
}

fn invalid(path: &str, e: serde_json::Error) -> PathError {
    PathError::Invalid {
        path: path.to_owned(),
        reason: e.to_string(),
    }
}

impl<T: Serialize + DeserializeOwned> PathAccess for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::array::ArrayField;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct General {
        #[serde(rename = "FromEmail")]
        from_email: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mtu: Option<u16>,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Item {
        number: u32,
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TestModel {
        general: General,
        items: ArrayField<Item>,
    }

    fn model() -> TestModel {
        TestModel {
            general: General {
                from_email: "sample@example.com".into(),
                mtu: None,
            },
            items: (1..=3).map(|number| Item { number }).collect(),
        }
    }

    #[test]
    fn set_by_reference_found_t0033() {
        let mut m = model();
        m.set_by_path("general.FromEmail", json!("x@example.com"))
            .unwrap();
        assert_eq!(m.general.from_email, "x@example.com");
        assert_eq!(
            m.get_by_path("general.FromEmail").unwrap(),
            json!("x@example.com")
        );
    }

    #[test]
    fn set_by_reference_not_found_t0034() {
        let mut m = model();
        let before = m.clone();
        assert!(matches!(
            m.set_by_path("general.nope.deeper", json!(1)),
            Err(PathError::Invalid { .. })
        ));
        assert_eq!(
            m.set_by_path("general.FromEmail.deeper", json!(1)),
            Err(PathError::NotFound("general.FromEmail.deeper".into()))
        );
        assert!(matches!(
            m.set_by_path("general.nope", json!(1)),
            Err(PathError::Invalid { .. })
        ));
        assert_eq!(m, before, "failed edits leave the model unchanged");
    }

    #[test]
    fn unknown_field_error_t0027() {
        let mut m = model();
        let err = m.set_by_path("general.FromEmails", json!("a")).unwrap_err();
        assert!(err.to_string().contains("FromEmails"), "{err}");
    }

    #[test]
    fn set_get_scalar_t0025() {
        let mut m = model();
        m.set_by_path_text("general.mtu", "1500").unwrap();
        assert_eq!(m.general.mtu, Some(1500));
        m.set_by_path_text("general.FromEmail", "123").unwrap();
        assert_eq!(m.general.from_email, "123");
        m.unset_by_path("general.mtu").unwrap();
        assert_eq!(m.general.mtu, None);
        assert!(
            m.unset_by_path("general.FromEmail").is_err(),
            "required field"
        );
    }

    #[test]
    fn set_nodes_by_reference_t0036() {
        let mut m = model();
        let ids: Vec<_> = m.items.keys().copied().collect();
        for (n, id) in ids.iter().enumerate() {
            m.set_by_path(&format!("items.{id}.number"), json!(100 + n))
                .unwrap();
        }
        assert!(m.items.values().all(|i| i.number > 99));
        assert_eq!(
            m.items.keys().copied().collect::<Vec<_>>(),
            ids,
            "order kept"
        );
        m.unset_by_path(&format!("items.{}", ids[1])).unwrap();
        assert_eq!(m.items.len(), 2);
    }
}
