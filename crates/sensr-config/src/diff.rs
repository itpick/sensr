//! Revision diffs: a JSON Patch (RFC 6902) between two documents plus a
//! unified text diff of their pretty-printed form.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use similar::TextDiff;

use sensr_schema::Section;

/// One JSON Patch operation. Paths are RFC 6901 pointers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum PatchOp {
    /// A value that exists only in the newer document.
    Add {
        /// Where.
        path: String,
        /// New value.
        value: Value,
    },
    /// A value that exists only in the older document.
    Remove {
        /// Where.
        path: String,
    },
    /// A value that differs.
    Replace {
        /// Where.
        path: String,
        /// New value.
        value: Value,
    },
}

impl PatchOp {
    /// The pointer the operation touches.
    pub fn path(&self) -> &str {
        match self {
            Self::Add { path, .. } | Self::Remove { path } | Self::Replace { path, .. } => path,
        }
    }
}

/// What changed between two revisions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RevisionDiff {
    /// Structural changes, older → newer.
    pub patch: Vec<PatchOp>,
    /// Top-level sections that differ.
    pub sections: Vec<Section>,
    /// `diff -u` of the pretty-printed documents.
    pub text: String,
}

fn escape(seg: &str) -> String {
    seg.replace('~', "~0").replace('/', "~1")
}

/// Computes a JSON Patch turning `a` into `b`. Objects are compared key by
/// key; arrays element by element (with trailing adds/removes), which suits
/// the store because list items live in UUID-keyed objects.
pub fn json_diff(a: &Value, b: &Value) -> Vec<PatchOp> {
    let mut ops = Vec::new();
    walk(a, b, &mut String::new(), &mut ops);
    ops
}

fn walk(a: &Value, b: &Value, path: &mut String, ops: &mut Vec<PatchOp>) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for (k, va) in x {
                let len = path.len();
                path.push('/');
                path.push_str(&escape(k));
                match y.get(k) {
                    Some(vb) => walk(va, vb, path, ops),
                    None => ops.push(PatchOp::Remove { path: path.clone() }),
                }
                path.truncate(len);
            }
            for (k, vb) in y {
                if !x.contains_key(k) {
                    ops.push(PatchOp::Add {
                        path: format!("{path}/{}", escape(k)),
                        value: vb.clone(),
                    });
                }
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            for (i, (va, vb)) in x.iter().zip(y).enumerate() {
                let len = path.len();
                path.push_str(&format!("/{i}"));
                walk(va, vb, path, ops);
                path.truncate(len);
            }
            // Remove from the end so earlier indices stay valid when applied.
            for i in (y.len()..x.len()).rev() {
                ops.push(PatchOp::Remove {
                    path: format!("{path}/{i}"),
                });
            }
            for (i, vb) in y.iter().enumerate().skip(x.len()) {
                ops.push(PatchOp::Add {
                    path: format!("{path}/{i}"),
                    value: vb.clone(),
                });
            }
        }
        _ if a == b => {}
        _ => ops.push(PatchOp::Replace {
            path: if path.is_empty() {
                String::new()
            } else {
                path.clone()
            },
            value: b.clone(),
        }),
    }
}

/// `diff -u` between two pretty-printed JSON values.
pub(crate) fn unified(a: &Value, b: &Value, a_name: &str, b_name: &str) -> String {
    let pa = serde_json::to_string_pretty(a).unwrap_or_default() + "\n";
    let pb = serde_json::to_string_pretty(b).unwrap_or_default() + "\n";
    TextDiff::from_lines(&pa, &pb)
        .unified_diff()
        .context_radius(3)
        .header(a_name, b_name)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn patch_ops() {
        let a = json!({"a": 1, "b": {"c": [1, 2, 3]}, "gone": true, "x/y": 1});
        let b = json!({"a": 2, "b": {"c": [1, 5]}, "new": null, "x/y": 2});
        assert_eq!(
            json_diff(&a, &b),
            vec![
                PatchOp::Replace {
                    path: "/a".into(),
                    value: json!(2)
                },
                PatchOp::Replace {
                    path: "/b/c/1".into(),
                    value: json!(5)
                },
                PatchOp::Remove {
                    path: "/b/c/2".into()
                },
                PatchOp::Remove {
                    path: "/gone".into()
                },
                PatchOp::Replace {
                    path: "/x~1y".into(),
                    value: json!(2)
                },
                PatchOp::Add {
                    path: "/new".into(),
                    value: json!(null)
                },
            ]
        );
        assert!(json_diff(&a, &a).is_empty());
        assert_eq!(
            json_diff(&json!(1), &json!(2)),
            vec![PatchOp::Replace {
                path: String::new(),
                value: json!(2)
            }]
        );
    }

    #[test]
    fn unified_text() {
        let t = unified(&json!({"a": 1}), &json!({"a": 2}), "r1", "r2");
        assert!(t.starts_with("--- r1\n+++ r2\n"), "{t}");
        assert!(t.contains("-  \"a\": 1\n+  \"a\": 2\n"), "{t}");
    }
}
