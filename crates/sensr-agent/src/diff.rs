//! Document differences for `sensr config diff` and the API.

use sensr_ipc::path::Segment;
use sensr_ipc::{Change, ConfigPath, Diff};
use serde_json::Value;

/// Structured changes plus a unified diff of the pretty-printed documents.
pub fn diff(before: &Value, after: &Value, before_label: &str, after_label: &str) -> Diff {
    let mut changes = Vec::new();
    walk(&mut Vec::new(), before, after, &mut changes);
    let unified = if changes.is_empty() {
        String::new()
    } else {
        unified_text(&pretty(before), &pretty(after), before_label, after_label)
    };
    Diff { changes, unified }
}

/// A unified diff of two texts (empty when equal).
pub fn unified_text(before: &str, after: &str, before_label: &str, after_label: &str) -> String {
    if before == after {
        return String::new();
    }
    similar::TextDiff::from_lines(before, after)
        .unified_diff()
        .context_radius(3)
        .header(before_label, after_label)
        .to_string()
}

fn pretty(v: &Value) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap_or_default();
    s.push('\n');
    s
}

fn path_of(segs: &[Segment]) -> ConfigPath {
    let text = segs
        .iter()
        .map(|s| match s {
            Segment::Key(k) => k.clone(),
            Segment::Index(i) => i.to_string(),
        })
        .collect::<Vec<_>>()
        .join(".");
    // Segments came from a document, so they are valid unless a key holds
    // characters paths cannot spell; fall back to the parent path then.
    text.parse().unwrap_or_default()
}

fn walk(at: &mut Vec<Segment>, a: &Value, b: &Value, out: &mut Vec<Change>) {
    match (a, b) {
        (Value::Object(ma), Value::Object(mb)) => {
            let keys: std::collections::BTreeSet<&String> = ma.keys().chain(mb.keys()).collect();
            for k in keys {
                at.push(Segment::Key(k.clone()));
                match (ma.get(k), mb.get(k)) {
                    (Some(x), Some(y)) => walk(at, x, y, out),
                    (x, y) => out.push(Change {
                        path: path_of(at),
                        before: x.cloned(),
                        after: y.cloned(),
                    }),
                }
                at.pop();
            }
        }
        (Value::Array(la), Value::Array(lb)) if la.len() == lb.len() => {
            for (i, (x, y)) in la.iter().zip(lb).enumerate() {
                at.push(Segment::Index(i));
                walk(at, x, y, out);
                at.pop();
            }
        }
        _ if a == b => {}
        _ => out.push(Change {
            path: path_of(at),
            before: Some(a.clone()),
            after: Some(b.clone()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reports_leaf_changes_and_unified_text() {
        let a = json!({"system": {"hostname": "fw", "domain": "lan"}, "list": [1, 2]});
        let b = json!({"system": {"hostname": "edge"}, "list": [1, 3], "new": true});
        let d = diff(&a, &b, "head", "candidate");
        let paths: Vec<String> = d.changes.iter().map(|c| c.path.to_string()).collect();
        assert_eq!(paths, ["list.1", "new", "system.domain", "system.hostname"]);
        assert_eq!(d.changes[2].after, None);
        assert_eq!(d.changes[1].before, None);
        assert!(d.unified.starts_with("--- head\n+++ candidate\n"));
        assert!(d.unified.contains("-    \"hostname\": \"fw\""));
        assert!(d.unified.contains("+    \"hostname\": \"edge\""));
    }

    #[test]
    fn equal_documents_have_no_diff() {
        let a = json!({"a": [1, {"b": 2}]});
        assert_eq!(diff(&a, &a, "x", "y"), Diff::default());
    }

    #[test]
    fn resized_list_is_one_change() {
        let d = diff(&json!({"l": [1]}), &json!({"l": [1, 2]}), "a", "b");
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].path.to_string(), "l");
    }
}
