//! Addresses into the config document as they travel over the wire.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One step of a [`ConfigPath`]: an object key or a list index.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Segment {
    /// An object member name (`[A-Za-z0-9_@-]+`; `@` for the importer's
    /// `@attributes` keys).
    Key(String),
    /// A zero-based list position.
    Index(usize),
}

/// A validated path into the config document, e.g. `system.hostname` or
/// `interfaces.lan.ipaddr`. The empty path (written `/` or ``) is the root.
///
/// Accepted spellings: dotted (`system.hostname`), slash (`/system/hostname`)
/// and either with numeric list indices (`filter.rule.0.descr`). The canonical
/// [`Display`](fmt::Display) form is dotted, and `/` for the root.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct ConfigPath(Vec<Segment>);

impl From<ConfigPath> for String {
    fn from(p: ConfigPath) -> Self {
        p.to_string()
    }
}

impl TryFrom<String> for ConfigPath {
    type Error = PathError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// Why a path string was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// Two separators in a row, or a trailing separator.
    #[error("empty segment in config path")]
    EmptySegment,
    /// A segment containing something other than `[A-Za-z0-9_-]`.
    #[error("invalid character {0:?} in config path segment")]
    InvalidChar(char),
}

impl ConfigPath {
    /// The document root.
    pub fn root() -> Self {
        Self(Vec::new())
    }

    /// True for the document root.
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// The path's segments, outermost first.
    pub fn segments(&self) -> &[Segment] {
        &self.0
    }

    /// The parent path and the last segment, or `None` for the root.
    pub fn split_last(&self) -> Option<(ConfigPath, &Segment)> {
        let (last, parent) = self.0.split_last()?;
        Some((ConfigPath(parent.to_vec()), last))
    }

    /// Looks the path up in `doc`.
    pub fn lookup<'a>(&self, doc: &'a Value) -> Option<&'a Value> {
        self.0.iter().try_fold(doc, |node, seg| match (seg, node) {
            (Segment::Key(k), Value::Object(map)) => map.get(k),
            (Segment::Index(i), Value::Array(list)) => list.get(*i),
            // OPNsense list semantics: a numeric segment may also name an
            // object member whose key happens to be digits.
            (Segment::Index(i), Value::Object(map)) => map.get(&i.to_string()),
            _ => None,
        })
    }

    /// Sets the value at the path in `doc`, creating intermediate objects.
    /// Fails when an intermediate node is a scalar or a list index is out of
    /// range (append with index == len is allowed).
    pub fn assign(&self, doc: &mut Value, value: Value) -> Result<(), AssignError> {
        let Some((last, parents)) = self.0.split_last() else {
            *doc = value;
            return Ok(());
        };
        let mut node = doc;
        for (depth, seg) in parents.iter().enumerate() {
            node = child_mut(node, seg, true)
                .ok_or_else(|| AssignError::NotAContainer(ConfigPath(self.0[..=depth].to_vec())))?;
        }
        if node.is_null() {
            *node = Value::Object(Default::default());
        }
        match (last, node) {
            (Segment::Key(k), Value::Object(map)) => {
                map.insert(k.clone(), value);
                Ok(())
            }
            (Segment::Index(i), Value::Array(list)) if *i < list.len() => {
                list[*i] = value;
                Ok(())
            }
            (Segment::Index(i), Value::Array(list)) if *i == list.len() => {
                list.push(value);
                Ok(())
            }
            (Segment::Index(i), Value::Object(map)) => {
                map.insert(i.to_string(), value);
                Ok(())
            }
            _ => Err(AssignError::NotAContainer(self.clone())),
        }
    }

    /// Removes the value at the path, returning it.
    pub fn remove(&self, doc: &mut Value) -> Option<Value> {
        let (last, parents) = self.0.split_last()?;
        let mut node = doc;
        for seg in parents {
            node = child_mut(node, seg, false)?;
        }
        match (last, node) {
            (Segment::Key(k), Value::Object(map)) => map.remove(k),
            (Segment::Index(i), Value::Array(list)) if *i < list.len() => Some(list.remove(*i)),
            (Segment::Index(i), Value::Object(map)) => map.remove(&i.to_string()),
            _ => None,
        }
    }
}

fn child_mut<'a>(node: &'a mut Value, seg: &Segment, create: bool) -> Option<&'a mut Value> {
    if create && node.is_null() {
        *node = Value::Object(Default::default());
    }
    match (seg, node) {
        (Segment::Key(k), Value::Object(map)) => {
            if create {
                Some(map.entry(k.clone()).or_insert(Value::Null))
            } else {
                map.get_mut(k)
            }
        }
        (Segment::Index(i), Value::Array(list)) => list.get_mut(*i),
        (Segment::Index(i), Value::Object(map)) => map.get_mut(&i.to_string()),
        _ => None,
    }
}

/// Why [`ConfigPath::assign`] failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AssignError {
    /// The node at this path is a scalar (or the index is out of range).
    #[error("cannot set a child of {0}: not an object or list (or index out of range)")]
    NotAContainer(ConfigPath),
}

impl FromStr for ConfigPath {
    type Err = PathError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.strip_prefix('/').unwrap_or(s);
        if trimmed.is_empty() {
            return Ok(Self::root());
        }
        let sep = if s.starts_with('/') { '/' } else { '.' };
        trimmed
            .split(sep)
            .map(|seg| {
                if seg.is_empty() {
                    return Err(PathError::EmptySegment);
                }
                if let Some(bad) = seg
                    .chars()
                    .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '@')))
                {
                    return Err(PathError::InvalidChar(bad));
                }
                Ok(match seg.parse::<usize>() {
                    // Leading zeros stay keys so `001` round-trips verbatim.
                    Ok(i) if !(seg.len() > 1 && seg.starts_with('0')) => Segment::Index(i),
                    _ => Segment::Key(seg.to_owned()),
                })
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

impl fmt::Display for ConfigPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("/");
        }
        for (n, seg) in self.0.iter().enumerate() {
            if n > 0 {
                f.write_str(".")?;
            }
            match seg {
                Segment::Key(k) => f.write_str(k)?,
                Segment::Index(i) => write!(f, "{i}")?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn p(s: &str) -> ConfigPath {
        s.parse().unwrap()
    }

    #[test]
    fn parses_dotted_slash_and_root() {
        assert_eq!(p("system.hostname"), p("/system/hostname"));
        assert!(p("/").is_root());
        assert!(p("").is_root());
        assert_eq!(p("filter.rule.0").to_string(), "filter.rule.0");
        assert_eq!(p("/").to_string(), "/");
    }

    #[test]
    fn rejects_bad_paths() {
        assert_eq!("a..b".parse::<ConfigPath>(), Err(PathError::EmptySegment));
        assert_eq!("a.".parse::<ConfigPath>(), Err(PathError::EmptySegment));
        assert_eq!(
            "a b".parse::<ConfigPath>(),
            Err(PathError::InvalidChar(' '))
        );
    }

    #[test]
    fn serializes_as_dotted_string() {
        assert_eq!(serde_json::to_string(&p("a.b.0")).unwrap(), r#""a.b.0""#);
        assert_eq!(
            serde_json::from_str::<ConfigPath>(r#""/a/b""#).unwrap(),
            p("a.b")
        );
        assert!(serde_json::from_str::<ConfigPath>(r#""a..b""#).is_err());
    }

    #[test]
    fn lookup_assign_remove() {
        let mut doc = json!({"system": {"hostname": "fw"}, "list": [1, 2]});
        assert_eq!(p("system.hostname").lookup(&doc), Some(&json!("fw")));
        assert_eq!(p("list.1").lookup(&doc), Some(&json!(2)));
        p("system.domain").assign(&mut doc, json!("lan")).unwrap();
        p("new.deep.key").assign(&mut doc, json!(true)).unwrap();
        p("list.2").assign(&mut doc, json!(3)).unwrap();
        assert_eq!(doc["new"]["deep"]["key"], json!(true));
        assert_eq!(doc["list"], json!([1, 2, 3]));
        assert!(p("system.hostname.x").assign(&mut doc, json!(1)).is_err());
        assert!(p("list.9").assign(&mut doc, json!(1)).is_err());
        assert_eq!(p("system.domain").remove(&mut doc), Some(json!("lan")));
        assert_eq!(p("system.domain").lookup(&doc), None);
    }

    proptest::proptest! {
        #[test]
        fn display_parse_round_trip(segs in proptest::collection::vec("[a-z_][a-z0-9_-]{0,8}|[1-9][0-9]{0,3}", 0..6)) {
            let s = segs.join(".");
            let path: ConfigPath = s.parse().unwrap();
            let shown = path.to_string();
            proptest::prop_assert_eq!(path, shown.parse::<ConfigPath>().unwrap());
        }

        #[test]
        fn parse_never_panics(s in ".{0,64}") {
            let _ = s.parse::<ConfigPath>();
        }
    }
}
