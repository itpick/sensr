//! OPNsense's internal rule key space, as PHP-shaped values.
//!
//! Upstream builds every rule (system, legacy `filter/rule`, plugin) as a PHP
//! associative array in a private key space (`type`, `direction`, `from`,
//! `to_port`, `icmp-type`, …) and only later normalises it. Two things depend
//! on the *exact* PHP shape of that array, value types included:
//!
//! - the rule label (`Util::calcRuleHash`, md5 of `json_encode` after a
//!   `ksort`), which SIEMs and dashboards key on;
//! - the differential pf oracle (`render::pf`).
//!
//! So sensr keeps this layer as data ([`Conf`]) and converts it to the typed IR
//! in [`crate::normalize`]. Typed (MVC) rules from `sensr-schema` skip this
//! layer: their label is their UUID.

use std::cmp::Ordering;
use std::fmt::Write as _;

use md5::{Digest, Md5};

/// A PHP value as it appears in a rule array. Floats are deliberately absent:
/// no rule field uses them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `null`
    Null,
    /// `true` / `false`
    Bool(bool),
    /// PHP `int`
    Int(i64),
    /// PHP `string`
    Str(String),
    /// PHP array (list or map)
    Array(Conf),
}

impl Value {
    /// PHP `empty()`: `null`, `false`, `0`, `""`, `"0"` and `[]` are empty.
    pub fn is_empty(&self) -> bool {
        match self {
            Value::Null => true,
            Value::Bool(b) => !b,
            Value::Int(i) => *i == 0,
            Value::Str(s) => s.is_empty() || s == "0",
            Value::Array(a) => a.is_empty(),
        }
    }

    /// String view of a scalar the way PHP would interpolate it; arrays have
    /// none.
    pub fn as_text(&self) -> Option<String> {
        match self {
            Value::Null => Some(String::new()),
            Value::Bool(true) => Some("1".into()),
            Value::Bool(false) => Some(String::new()),
            Value::Int(i) => Some(i.to_string()),
            Value::Str(s) => Some(s.clone()),
            Value::Array(_) => None,
        }
    }
}

impl Value {
    /// `json_decode($json, true)` of one value. Non-integral numbers become
    /// strings: rule fields never hold floats.
    pub fn from_json(v: &serde_json::Value) -> Value {
        use serde_json::Value as J;
        match v {
            J::Null => Value::Null,
            J::Bool(b) => Value::Bool(*b),
            J::Number(n) => n
                .as_i64()
                .map(Value::Int)
                .unwrap_or_else(|| Value::Str(n.to_string())),
            J::String(s) => Value::Str(s.clone()),
            J::Array(a) => Value::Array(Conf::list(a.iter().map(Value::from_json))),
            J::Object(o) => {
                let mut c = Conf::default();
                for (k, v) in o {
                    c.set(k, Value::from_json(v));
                }
                Value::Array(c)
            }
        }
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Str(s.to_owned())
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Str(s)
    }
}
impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}
impl From<i64> for Value {
    fn from(i: i64) -> Self {
        Value::Int(i)
    }
}
impl From<u16> for Value {
    fn from(i: u16) -> Self {
        Value::Int(i64::from(i))
    }
}
impl From<Conf> for Value {
    fn from(c: Conf) -> Self {
        Value::Array(c)
    }
}

/// A PHP array key. PHP folds decimal-integer strings (`"5"`) into int keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    /// integer key
    Int(i64),
    /// string key
    Str(String),
}

impl Key {
    /// Builds a key the way PHP does for `$a["…"]`.
    pub fn new(s: &str) -> Key {
        match s.parse::<i64>() {
            // PHP only folds canonical decimal forms ("5", "-5"), not "05" or "+5".
            Ok(i) if i.to_string() == s => Key::Int(i),
            _ => Key::Str(s.to_owned()),
        }
    }

    fn as_string(&self) -> String {
        match self {
            Key::Int(i) => i.to_string(),
            Key::Str(s) => s.clone(),
        }
    }
}

/// An ordered PHP array.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Conf(Vec<(Key, Value)>);

/// Builds a [`Conf`] from `key => value` pairs, PHP-literal style.
#[macro_export]
macro_rules! conf {
    () => { $crate::conf::Conf::default() };
    ($($k:expr => $v:expr),+ $(,)?) => {{
        let mut c = $crate::conf::Conf::default();
        $( c.set($k, $v); )+
        c
    }};
}

impl Conf {
    /// Number of entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` when there are no entries.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// A PHP list (`[a, b]`) from values.
    pub fn list<I, V>(items: I) -> Conf
    where
        I: IntoIterator<Item = V>,
        V: Into<Value>,
    {
        Conf(
            items
                .into_iter()
                .enumerate()
                .map(|(i, v)| (Key::Int(i as i64), v.into()))
                .collect(),
        )
    }

    /// `$a[$k] = $v`: replaces in place (keeping position) or appends.
    pub fn set(&mut self, key: &str, value: impl Into<Value>) {
        let key = Key::new(key);
        let value = value.into();
        match self.0.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = value,
            None => self.0.push((key, value)),
        }
    }

    /// `$a[$k] ?? null`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        let key = Key::new(key);
        self.0.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// `unset($a[$k])`.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let key = Key::new(key);
        let pos = self.0.iter().position(|(k, _)| *k == key)?;
        Some(self.0.remove(pos).1)
    }

    /// `empty($a[$k])`.
    pub fn is_empty_at(&self, key: &str) -> bool {
        self.get(key).is_none_or(Value::is_empty)
    }

    /// `isset($a[$k])` (present and not null).
    pub fn isset(&self, key: &str) -> bool {
        !matches!(self.get(key), None | Some(Value::Null))
    }

    /// Scalar text at `key`, `None` when missing, null or an array.
    pub fn text(&self, key: &str) -> Option<String> {
        match self.get(key)? {
            Value::Null | Value::Array(_) => None,
            v => v.as_text(),
        }
    }

    /// Nested array at `key`.
    pub fn array(&self, key: &str) -> Option<&Conf> {
        match self.get(key)? {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Iterates entries in order.
    pub fn iter(&self) -> impl Iterator<Item = (&Key, &Value)> {
        self.0.iter().map(|(k, v)| (k, v))
    }

    /// `array_merge($self, $over)` for string-keyed arrays: later values win,
    /// keys keep the position of their first appearance, int keys renumber.
    pub fn merged_with(&self, over: &Conf) -> Conf {
        let mut out = Conf::default();
        let mut next = 0;
        for (k, v) in self.0.iter().chain(over.0.iter()) {
            match k {
                Key::Int(_) => {
                    out.0.push((Key::Int(next), v.clone()));
                    next += 1;
                }
                Key::Str(s) => out.set(s, v.clone()),
            }
        }
        out
    }

    /// PHP 8 `ksort()` with default flags (stable).
    pub fn ksort(&mut self) {
        self.0.sort_by(|(a, _), (b, _)| php_key_cmp(a, b));
    }

    fn is_list(&self) -> bool {
        self.0
            .iter()
            .enumerate()
            .all(|(i, (k, _))| *k == Key::Int(i as i64))
    }

    /// The array PHP's `json_decode($json, true)` yields (object key order as
    /// `serde_json` keeps it; `calcRuleHash` sorts anyway).
    pub fn from_json(v: &serde_json::Value) -> Option<Conf> {
        match Value::from_json(v) {
            Value::Array(c) => Some(c),
            _ => None,
        }
    }

    /// PHP `json_encode($a)` with default flags.
    pub fn json_encode(&self) -> String {
        let mut out = String::new();
        encode_array(self, &mut out);
        out
    }
}

/// PHP 8 comparison of array keys under `SORT_REGULAR`.
fn php_key_cmp(a: &Key, b: &Key) -> Ordering {
    match (a, b) {
        (Key::Int(x), Key::Int(y)) => x.cmp(y),
        (Key::Str(x), Key::Str(y)) => match (numeric(x), numeric(y)) {
            (Some(p), Some(q)) => p.partial_cmp(&q).unwrap_or(Ordering::Equal),
            _ => x.as_bytes().cmp(y.as_bytes()),
        },
        // PHP 8: int vs numeric string compares numerically, otherwise as strings.
        (Key::Int(x), Key::Str(y)) => match numeric(y) {
            Some(q) => (*x as f64).partial_cmp(&q).unwrap_or(Ordering::Equal),
            None => x.to_string().as_bytes().cmp(y.as_bytes()),
        },
        (Key::Str(_), Key::Int(_)) => php_key_cmp(b, a).reverse(),
    }
}

fn numeric(s: &str) -> Option<f64> {
    let t = s.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    if t.is_empty() || t.contains(|c: char| c.is_ascii_alphabetic() && c != 'e' && c != 'E') {
        return None;
    }
    t.trim_end().parse::<f64>().ok().filter(|f| f.is_finite())
}

fn encode_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => {
            let _ = write!(out, "{i}");
        }
        Value::Str(s) => encode_str(s, out),
        Value::Array(a) => encode_array(a, out),
    }
}

fn encode_array(a: &Conf, out: &mut String) {
    if a.is_list() {
        out.push('[');
        for (i, (_, v)) in a.0.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            encode_value(v, out);
        }
        out.push(']');
    } else {
        out.push('{');
        for (i, (k, v)) in a.0.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            encode_str(&k.as_string(), out);
            out.push(':');
            encode_value(v, out);
        }
        out.push('}');
    }
}

/// PHP's default string escaping: `/` is escaped, everything outside ASCII
/// becomes lowercase `\uXXXX` UTF-16 units.
fn encode_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '/' => out.push_str("\\/"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e && c != '\u{7f}' => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `Util::calcRuleHash`: the md5 label OPNsense gives rules without one.
///
/// `updated`, `created` and `descr` are excluded so edits to metadata keep the
/// label; keys are sorted at the top level and one level down.
pub fn calc_rule_hash(rule: &Conf) -> String {
    let mut r = rule.clone();
    for k in ["updated", "created", "descr"] {
        r.remove(k);
    }
    r.ksort();
    for (_, v) in r.0.iter_mut() {
        if let Value::Array(a) = v {
            a.ksort();
        }
    }
    let digest = Md5::digest(r.json_encode().as_bytes());
    let mut hex = String::with_capacity(32);
    for b in digest {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_encode_matches_php_escaping() {
        let c = conf! { "a" => "x/y", "d" => "é\u{1F600}\u{1}" };
        // Recorded with php 8.4: json_encode(["a"=>"x/y","d"=>"é😀\x01"])
        assert_eq!(
            c.json_encode(),
            "{\"a\":\"x\\/y\",\"d\":\"\\u00e9\\ud83d\\ude00\\u0001\"}"
        );
    }

    #[test]
    fn json_encode_lists_and_maps() {
        let c = conf! { "l" => Conf::list(["a", "b"]), "e" => Conf::default(), "n" => Value::Null };
        assert_eq!(c.json_encode(), r#"{"l":["a","b"],"e":[],"n":null}"#);
    }

    #[test]
    fn numeric_string_keys_fold_to_int() {
        let mut c = Conf::default();
        c.set("0", "a");
        c.set("1", "b");
        assert_eq!(c.json_encode(), r#"["a","b"]"#);
        c.set("05", "c");
        assert_eq!(c.json_encode(), r#"{"0":"a","1":"b","05":"c"}"#);
    }

    #[test]
    fn array_merge_keeps_first_position_later_value() {
        let d = conf! { "type" => "pass", "log" => false };
        let r = conf! { "descr" => "x", "type" => "block" };
        assert_eq!(
            d.merged_with(&r),
            conf! { "type" => "block", "log" => false, "descr" => "x" }
        );
    }

    #[test]
    fn php_empty_semantics() {
        for v in [
            Value::Null,
            Value::Bool(false),
            Value::Int(0),
            "".into(),
            "0".into(),
            Value::Array(Conf::default()),
        ] {
            assert!(v.is_empty(), "{v:?}");
        }
        for v in [Value::Bool(true), Value::Int(1), "00".into(), " ".into()] {
            assert!(!v.is_empty(), "{v:?}");
        }
    }

    #[test]
    fn label_matches_upstream_calc_rule_hash() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/calc_rule_hash.json")).unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let rule = Conf::from_json(&case["rule"]).unwrap();
            assert_eq!(
                calc_rule_hash(&rule),
                case["label"].as_str().unwrap(),
                "{rule:?}"
            );
        }
    }

    proptest::proptest! {
        /// Same rule content in any key order (and any metadata) → same label.
        #[test]
        fn prop_label_stable(
            entries in proptest::collection::btree_map("[a-z#_-]{1,8}", "[ -~]{0,6}", 0..8),
            descr in "[ -~]{0,10}",
            seed in proptest::prelude::any::<u64>(),
        ) {
            let mut fwd = Conf::default();
            for (k, v) in &entries {
                fwd.set(k, v.as_str());
            }
            let mut keys: Vec<_> = entries.keys().collect();
            // deterministic shuffle from the seed
            let n = keys.len();
            for i in (1..n).rev() {
                keys.swap(i, (seed as usize).wrapping_mul(31).wrapping_add(i) % (i + 1));
            }
            let mut shuffled = Conf::default();
            for k in keys {
                shuffled.set(k, entries[k].as_str());
            }
            shuffled.set("descr", descr.as_str());
            shuffled.set("updated", conf! { "time" => "1" });
            proptest::prop_assert_eq!(calc_rule_hash(&fwd), calc_rule_hash(&shuffled));
        }
    }

    #[test]
    fn ksort_php8_regular() {
        let mut c = conf! { "type" => 1i64, "10" => 1i64, "9" => 1i64, "#ref" => 1i64, "Z" => 1i64, "a" => 1i64 };
        c.ksort();
        let keys: Vec<String> = c.iter().map(|(k, _)| k.as_string()).collect();
        // Recorded with php 8.4 ksort().
        assert_eq!(keys, ["#ref", "9", "10", "Z", "a", "type"]);
    }
}
