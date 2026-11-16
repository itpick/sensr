//! The "array" view of a config tree, as `Config::toArray()` / `fromArray()` build it.
//!
//! Legacy OPNsense code (and configd templates) sees `config.xml` as nested PHP
//! arrays: an element with child elements becomes a map, a leaf becomes a string,
//! and repeated siblings — or tags on a force list such as [`listtags`] — become
//! lists. sensr's mappers work on the [`Element`] tree directly; this view exists for
//! parity with those semantics (T-0002, T-0320, T-0321) and for rendering unmapped
//! subtrees in the import report the way an OPNsense user would recognise them.
//!
//! [`listtags`]: crate::listtags

use crate::tree::{Attribute, Element, Node};

/// Key under which an element's own attributes are stored.
pub const ATTRIBUTES_KEY: &str = "@attributes";

/// An ordered PHP-array-like value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A leaf's character data.
    Text(String),
    /// Ordered key/value pairs (a PHP associative array).
    Map(Vec<(String, Value)>),
    /// A list of values (a PHP array with integer keys).
    List(Vec<Value>),
}

impl Value {
    /// Look up `key` in a map; `None` for non-maps.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn get_mut(map: &mut [(String, Value)], key: &str) -> Option<usize> {
        map.iter().position(|(k, _)| k == key)
    }
}

/// Build the array view of `node`. `force_list` names tags that must become a list
/// even when they occur once (OPNsense passes `listtags()` or a per-caller set).
pub fn to_array(node: &Element, force_list: &dyn Fn(&str) -> bool) -> Value {
    let mut result: Vec<(String, Value)> = Vec::new();
    if !node.attributes.is_empty() {
        result.push((ATTRIBUTES_KEY.into(), attributes_value(&node.attributes)));
    }
    for child in node.elements() {
        let name = child.name.clone();
        let existing = Value::get_mut(&mut result, &name);
        if child.has_element_children() {
            let value = to_array(child, force_list);
            match existing {
                Some(i) => push_repeated(&mut result[i].1, value),
                None if force_list(&name) => result.push((name, Value::List(vec![value]))),
                None => result.push((name, value)),
            }
        } else {
            let text = child.text();
            match existing {
                Some(i) => push_repeated(&mut result[i].1, Value::Text(text)),
                None => {
                    if force_list(&name) {
                        // A forced leaf with blank content is an empty list, so `<item/>`
                        // means "no items" rather than "one empty item".
                        let items = if text.trim().is_empty() {
                            Vec::new()
                        } else {
                            vec![Value::Text(text)]
                        };
                        result.push((name.clone(), Value::List(items)));
                    } else {
                        result.push((name.clone(), Value::Text(text)));
                    }
                    if !child.attributes.is_empty() {
                        result.push((
                            format!("{name}{ATTRIBUTES_KEY}"),
                            attributes_value(&child.attributes),
                        ));
                    }
                }
            }
        }
    }
    Value::Map(result)
}

/// The second occurrence of a tag turns the first one into a list.
fn push_repeated(slot: &mut Value, value: Value) {
    match slot {
        Value::List(items) => items.push(value),
        other => {
            let first = std::mem::replace(other, Value::List(Vec::new()));
            *other = Value::List(vec![first, value]);
        }
    }
}

fn attributes_value(attrs: &[Attribute]) -> Value {
    Value::Map(
        attrs
            .iter()
            .map(|a| (a.name.clone(), Value::Text(a.value.clone())))
            .collect(),
    )
}

/// Rebuild an element named `name` from an array view (`Config::fromArray()`):
/// map keys become child elements, list entries repeat the parent key's tag, and
/// `@attributes` / `<tag>@attributes` keys restore attributes.
pub fn from_array(name: &str, value: &Value) -> Element {
    let mut element = Element::new(name);
    fill(&mut element, value, name);
    element
}

fn fill(node: &mut Element, value: &Value, parent_tag: &str) {
    match value {
        Value::Text(t) => node.set_text(t.clone()),
        Value::List(items) => {
            for item in items {
                let child = node.push_element(Element::new(parent_tag));
                fill(child, item, parent_tag);
            }
        }
        Value::Map(entries) => {
            for (key, v) in entries {
                if key.trim().is_empty() {
                    continue;
                }
                if key == ATTRIBUTES_KEY {
                    set_attributes(node, v);
                } else if let Some(orig) = key.strip_suffix(ATTRIBUTES_KEY) {
                    if let Some(target) = node.child_mut(orig) {
                        set_attributes(target, v);
                    }
                } else if let Value::List(_) = v {
                    // A list repeats `key` directly under this node.
                    fill(node, v, key);
                } else {
                    let child = node.push_element(Element::new(key.clone()));
                    fill(child, v, key);
                }
            }
        }
    }
}

fn set_attributes(node: &mut Element, attrs: &Value) {
    if let Value::Map(entries) = attrs {
        for (k, v) in entries {
            if let Value::Text(t) = v {
                node.set_attribute(k.clone(), t.clone());
            }
        }
    }
}

/// Whether a child of `parent` named `name` is list-shaped under OPNsense's rules:
/// it is on the force list, or it occurs more than once.
pub fn is_list_child(parent: &Element, name: &str, force_list: &dyn Fn(&str) -> bool) -> bool {
    force_list(name) || parent.children_named(name).nth(1).is_some()
}

/// Whether `node` contains only elements (no character data), i.e. is a container.
pub fn is_container(node: &Element) -> bool {
    node.children
        .iter()
        .all(|n| !matches!(n, Node::Text(_) | Node::CData(_)))
        && node.has_element_children()
}
