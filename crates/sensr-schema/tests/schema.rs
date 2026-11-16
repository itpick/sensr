//! JSON Schema export of the document (the contract UI forms, the compat
//! layer and `xtask lint-schema` read).

use sensr_schema::Document;
use serde_json::Value;

fn defs(schema: &Value) -> &serde_json::Map<String, Value> {
    schema["$defs"].as_object().expect("$defs")
}

/// Every option set in the schema: `enum` arrays, and `oneOf` lists whose
/// branches are constants (unit enums) or objects tagged by a constant
/// property (internally tagged enums). Returns `(location, keys)`.
fn option_sets(v: &Value, at: &str, out: &mut Vec<(String, Vec<String>)>) {
    match v {
        Value::Object(m) => {
            if let Some(Value::Array(e)) = m.get("enum") {
                out.push((at.to_owned(), e.iter().map(ToString::to_string).collect()));
            }
            if let Some(Value::Array(branches)) = m.get("oneOf") {
                let keys: Vec<String> = branches
                    .iter()
                    .filter_map(|b| {
                        b.get("const").map(ToString::to_string).or_else(|| {
                            b.get("properties")?
                                .as_object()?
                                .values()
                                .find_map(|p| p.get("const").map(ToString::to_string))
                        })
                    })
                    .collect();
                if keys.len() == branches.len() {
                    out.push((at.to_owned(), keys));
                }
            }
            for (k, x) in m {
                option_sets(x, &format!("{at}/{k}"), out);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                option_sets(x, &format!("{at}/{i}"), out);
            }
        }
        _ => {}
    }
}

#[test]
fn document_schema_covers_the_slice() {
    let schema = Document::json_schema();
    assert_eq!(schema["title"], "Document");
    for def in [
        "Interface",
        "Ipv4Config",
        "Ipv6Config",
        "FilterRule",
        "Alias",
        "AliasContent",
        "PortForward",
        "Subnet4",
        "Reservation4",
        "HostOverride",
        "WgServer",
        "WgPeer",
        "User",
    ] {
        assert!(defs(&schema).contains_key(def), "missing $defs/{def}");
    }
    let text = schema.to_string();
    assert!(
        text.contains("\"writeOnly\":true"),
        "secrets are write-only"
    );
    assert!(
        text.contains("\"format\":\"uuid\""),
        "array keys and relations are UUIDs"
    );
}

/// lint-model rule 9 equivalent: option keys within one set are distinct.
#[test]
fn option_keys_unique_t0356() {
    let schema = Document::json_schema();
    let mut all = Vec::new();
    option_sets(&schema, "", &mut all);
    assert!(all.len() >= 10, "found {} option sets", all.len());
    for (at, keys) in all {
        let mut seen = std::collections::HashSet::new();
        for k in keys {
            assert!(seen.insert(k.clone()), "{at}: duplicate option {k}");
        }
    }
}

/// The factory document is an instance of its schema at least structurally:
/// every top-level section the document serialises is a schema property.
#[test]
fn factory_document_sections_are_in_schema() {
    let schema = Document::json_schema();
    let doc = serde_json::to_value(Document::factory()).unwrap();
    let props = schema["properties"].as_object().unwrap();
    for k in doc.as_object().unwrap().keys() {
        assert!(props.contains_key(k), "section {k} missing from schema");
    }
}
