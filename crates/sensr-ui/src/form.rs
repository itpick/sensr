//! Form metadata and the string ⇄ JSON conversion behind `<SettingsForm<T>>` and grid dialogs.
//!
//! A model describes its fields once ([`FormModel::fields`]); the same description renders the
//! inputs, parses what the user typed (with per-field messages for bad input), and feeds the
//! model's own cross-field [`FormModel::validate`]. Both the browser island and the server run
//! this code, so a submit gets instant feedback and the server never trusts the browser.

use crate::api::FieldError;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

/// How a field is edited and parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// Free text.
    Text,
    /// Write-only secret: rendered empty, left unchanged when submitted empty.
    Secret,
    /// Integer within bounds.
    Number {
        /// Inclusive minimum.
        min: i64,
        /// Inclusive maximum.
        max: i64,
    },
    /// Boolean checkbox.
    Checkbox,
    /// One of a fixed set of `(value, label)` options.
    Select(&'static [(&'static str, &'static str)]),
    /// One of a set known only at run time (e.g. the assigned interfaces).
    Choice(ChoiceSet),
    /// Any number of a fixed set of options, shown in labelled groups; stored as a JSON array.
    MultiSelect(&'static [OptGroup]),
    /// One value per line, stored as a JSON array of strings.
    Lines,
    /// One IP address (v4 or v6).
    Ip,
    /// One IPv4 address.
    Ipv4,
    /// An address with prefix length, e.g. `192.168.1.1/24`.
    Cidr,
    /// One CIDR per line.
    CidrLines,
    /// One IP address per line.
    IpLines,
    /// One domain name per line.
    HostnameLines,
    /// One name per line as blocklists hold them: like a domain name, but labels may contain
    /// underscores (`_dmarc.example.com`) and a trailing dot is dropped.
    ListedNameLines,
    /// Multi-line free text.
    TextArea,
    /// Hostname label(s): letters, digits, `-` and `.`.
    Hostname,
    /// Ethernet MAC address.
    Mac,
}

/// A labelled group of `(value, label)` options for [`FieldKind::MultiSelect`].
pub type OptGroup = (&'static str, &'static [(&'static str, &'static str)]);

/// Option lists computed from the current document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ChoiceSet {
    /// Assigned interfaces.
    Interfaces,
    /// "Floating" plus the assigned interfaces (filter rules).
    RuleInterfaces,
    /// The host's network cards (by MAC) plus devices that are not cards
    /// (VLANs, WireGuard), for Interfaces › Assignments.
    Devices,
}

/// Runtime option lists, `(value, label)`, per set.
pub type Choices = std::collections::BTreeMap<ChoiceSet, Vec<(String, String)>>;

/// One field of a form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpec {
    /// Dot-separated path into the model's JSON.
    pub path: &'static str,
    /// Label shown next to the input.
    pub label: &'static str,
    /// Help text under the input; empty for none.
    pub help: &'static str,
    /// Input and parser.
    pub kind: FieldKind,
    /// Empty input is an error.
    pub required: bool,
}

impl FieldSpec {
    /// An optional field.
    pub const fn new(path: &'static str, label: &'static str, kind: FieldKind) -> Self {
        Self {
            path,
            label,
            help: "",
            kind,
            required: false,
        }
    }

    /// Marks the field required.
    pub const fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Adds help text.
    pub const fn help(mut self, help: &'static str) -> Self {
        self.help = help;
        self
    }

    /// The DOM id for this field's input inside a form with id `form`.
    pub fn dom_id(&self, form: &str) -> String {
        format!("{form}--{}", self.path.replace('.', "-"))
    }
}

/// A model edited through a generated form.
pub trait FormModel:
    Serialize + DeserializeOwned + Default + Clone + Send + Sync + 'static
{
    /// Field descriptions in display order.
    fn fields() -> &'static [FieldSpec];

    /// Cross-field checks after every field parsed.
    fn validate(&self) -> Vec<FieldError> {
        Vec::new()
    }
}

/// Raw input values keyed by field path.
pub type Inputs = BTreeMap<String, String>;

/// Reads `path` (dot-separated) from `value`.
pub fn get_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(value, |v, key| v.get(key))
}

/// Writes `new` at `path`, creating intermediate objects.
pub fn set_path(value: &mut Value, path: &str, new: Value) {
    let mut cur = value;
    let mut keys = path.split('.').peekable();
    while let Some(key) = keys.next() {
        if !cur.is_object() {
            *cur = Value::Object(Map::new());
        }
        let Value::Object(map) = cur else {
            unreachable!("just made it an object")
        };
        if keys.peek().is_none() {
            map.insert(key.to_owned(), new);
            return;
        }
        cur = map.entry(key.to_owned()).or_insert(Value::Null);
    }
}

/// Renders the current value of every field as the string its input shows.
pub fn to_inputs(fields: &[FieldSpec], value: &Value) -> Inputs {
    fields
        .iter()
        .map(|f| {
            let v = get_path(value, f.path).unwrap_or(&Value::Null);
            let s = match (f.kind, v) {
                (FieldKind::Secret, _) => String::new(),
                (FieldKind::Checkbox, Value::Bool(b)) => b.to_string(),
                (FieldKind::Checkbox, _) => "false".to_owned(),
                (_, Value::Array(items)) => items
                    .iter()
                    .map(scalar_to_string)
                    .collect::<Vec<_>>()
                    .join("\n"),
                (_, other) => scalar_to_string(other),
            };
            (f.path.to_owned(), s)
        })
        .collect()
}

fn scalar_to_string(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn lines(s: &str) -> impl Iterator<Item = &str> {
    s.split(['\n', ','])
        .map(str::trim)
        .filter(|l| !l.is_empty())
}

fn parse_cidr(s: &str) -> bool {
    match s.split_once('/') {
        Some((addr, len)) => match (addr.parse::<IpAddr>(), len.parse::<u8>()) {
            (Ok(IpAddr::V4(_)), Ok(l)) => l <= 32,
            (Ok(IpAddr::V6(_)), Ok(l)) => l <= 128,
            _ => false,
        },
        None => false,
    }
}

/// Letters, digits and hyphens in dot-separated labels of at most 63 characters.
pub fn is_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// A name as blocklists hold it: [`is_hostname`] with underscores allowed, an optional
/// trailing dot.
pub fn is_listed_name(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    is_hostname(&s.replace('_', "a"))
}

fn is_mac(s: &str) -> bool {
    let parts: Vec<_> = s.split([':', '-']).collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Parses one field's raw input into JSON, or explains why it cannot.
pub fn parse_field(spec: &FieldSpec, raw: &str) -> Result<Value, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        if spec.required && !matches!(spec.kind, FieldKind::Checkbox) {
            return Err("This field is required.".to_owned());
        }
        return Ok(match spec.kind {
            FieldKind::Checkbox => Value::Bool(false),
            FieldKind::Lines
            | FieldKind::CidrLines
            | FieldKind::IpLines
            | FieldKind::HostnameLines
            | FieldKind::ListedNameLines
            | FieldKind::MultiSelect(_) => Value::Array(vec![]),
            FieldKind::Number { .. } => Value::Null,
            _ => Value::String(String::new()),
        });
    }
    let each = |check: fn(&str) -> bool, what: &str| -> Result<Value, String> {
        let mut out = Vec::new();
        for l in lines(raw) {
            if !check(l) {
                return Err(format!("\u{201c}{l}\u{201d} is not a valid {what}."));
            }
            out.push(Value::String(l.to_owned()));
        }
        Ok(Value::Array(out))
    };
    match spec.kind {
        FieldKind::Text | FieldKind::TextArea | FieldKind::Secret => {
            Ok(Value::String(raw.to_owned()))
        }
        FieldKind::Number { min, max } => match raw.parse::<i64>() {
            Ok(n) if (min..=max).contains(&n) => Ok(Value::from(n)),
            Ok(_) => Err(format!("Enter a number between {min} and {max}.")),
            Err(_) => Err("Enter a whole number.".to_owned()),
        },
        FieldKind::Checkbox => Ok(Value::Bool(matches!(raw, "true" | "on" | "1" | "yes"))),
        // Membership is the backend's call: the list may have changed since the page loaded.
        FieldKind::Choice(_) => {
            if raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                Ok(Value::String(raw.to_owned()))
            } else {
                Err("Choose one of the listed options.".to_owned())
            }
        }
        FieldKind::Select(options) => {
            if options.iter().any(|(v, _)| *v == raw) {
                Ok(Value::String(raw.to_owned()))
            } else {
                Err("Choose one of the listed options.".to_owned())
            }
        }
        FieldKind::MultiSelect(groups) => {
            let mut out = Vec::new();
            for l in lines(raw) {
                if !groups
                    .iter()
                    .any(|(_, opts)| opts.iter().any(|(v, _)| *v == l))
                {
                    return Err("Choose from the listed options.".to_owned());
                }
                out.push(Value::String(l.to_owned()));
            }
            Ok(Value::Array(out))
        }
        FieldKind::HostnameLines => each(is_hostname, "domain name"),
        FieldKind::ListedNameLines => each(is_listed_name, "domain name"),
        FieldKind::Lines => Ok(Value::Array(
            lines(raw).map(|l| Value::String(l.to_owned())).collect(),
        )),
        FieldKind::Ip => raw
            .parse::<IpAddr>()
            .map(|_| Value::String(raw.to_owned()))
            .map_err(|_| "Enter a valid IPv4 or IPv6 address.".to_owned()),
        FieldKind::Ipv4 => raw
            .parse::<Ipv4Addr>()
            .map(|_| Value::String(raw.to_owned()))
            .map_err(|_| "Enter a valid IPv4 address.".to_owned()),
        FieldKind::Cidr => {
            if parse_cidr(raw) {
                Ok(Value::String(raw.to_owned()))
            } else {
                Err("Enter an address with prefix length, e.g. 192.168.1.1/24.".to_owned())
            }
        }
        FieldKind::CidrLines => each(parse_cidr, "network (address/prefix)"),
        FieldKind::IpLines => each(|s| s.parse::<IpAddr>().is_ok(), "IP address"),
        FieldKind::Hostname => {
            if is_hostname(raw) {
                Ok(Value::String(raw.to_owned()))
            } else {
                Err("Use letters, digits, hyphens and dots only.".to_owned())
            }
        }
        FieldKind::Mac => {
            if is_mac(raw) {
                Ok(Value::String(raw.to_lowercase().replace('-', ":")))
            } else {
                Err("Enter a MAC address like 00:11:22:33:44:55.".to_owned())
            }
        }
    }
}

/// Applies `inputs` over `base` and returns the validated model, or every field error found.
///
/// Fields missing from `inputs` keep their value from `base`; an empty secret keeps the stored
/// secret (secrets are never sent to the browser).
pub fn apply_inputs<T: FormModel>(base: &Value, inputs: &Inputs) -> Result<T, Vec<FieldError>> {
    // Start from the model's defaults so a partial stored object still deserializes.
    let mut value = serde_json::to_value(T::default()).unwrap_or(Value::Object(Map::new()));
    if let (Value::Object(into), Value::Object(from)) = (&mut value, base) {
        for (k, v) in from {
            into.insert(k.clone(), v.clone());
        }
    }
    let mut errors = Vec::new();
    for spec in T::fields() {
        let Some(raw) = inputs.get(spec.path) else {
            continue;
        };
        if spec.kind == FieldKind::Secret && raw.trim().is_empty() {
            let stored = get_path(&value, spec.path).and_then(Value::as_str);
            if spec.required && stored.is_none_or(str::is_empty) {
                errors.push(FieldError::new(spec.path, "This field is required."));
            }
            continue;
        }
        match parse_field(spec, raw) {
            Ok(v) => set_path(&mut value, spec.path, v),
            Err(msg) => errors.push(FieldError::new(spec.path, msg)),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    let model: T = serde_json::from_value(value)
        .map_err(|e| vec![FieldError::new("", format!("Invalid input: {e}"))])?;
    let errors = model.validate();
    if errors.is_empty() {
        Ok(model)
    } else {
        Err(errors)
    }
}

/// Model JSON with secret fields blanked, for sending to the browser.
pub fn redact<T: FormModel>(value: &Value) -> Value {
    let mut v = value.clone();
    for spec in T::fields() {
        if spec.kind == FieldKind::Secret && get_path(&v, spec.path).is_some() {
            set_path(&mut v, spec.path, Value::String(String::new()));
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
    struct Demo {
        name: String,
        port: Option<u16>,
        on: bool,
        nets: Vec<String>,
        key: String,
    }

    const DEMO: &[FieldSpec] = &[
        FieldSpec::new("name", "Name", FieldKind::Hostname).required(),
        FieldSpec::new("port", "Port", FieldKind::Number { min: 1, max: 65535 }),
        FieldSpec::new("on", "On", FieldKind::Checkbox),
        FieldSpec::new("nets", "Nets", FieldKind::CidrLines),
        FieldSpec::new("key", "Key", FieldKind::Secret),
    ];

    impl FormModel for Demo {
        fn fields() -> &'static [FieldSpec] {
            DEMO
        }
        fn validate(&self) -> Vec<FieldError> {
            if self.on && self.nets.is_empty() {
                vec![FieldError::new("nets", "Needed when on.")]
            } else {
                vec![]
            }
        }
    }

    fn inputs(pairs: &[(&str, &str)]) -> Inputs {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn round_trips_through_inputs() {
        let model = Demo {
            name: "fw".into(),
            port: Some(51820),
            on: true,
            nets: vec!["10.0.0.0/24".into(), "fd00::/64".into()],
            key: "s3cret".into(),
        };
        let value = serde_json::to_value(&model).unwrap();
        let shown = to_inputs(DEMO, &value);
        assert_eq!(shown["nets"], "10.0.0.0/24\nfd00::/64");
        assert_eq!(shown["key"], "", "secrets are never rendered");
        let back: Demo = apply_inputs(&value, &shown).unwrap();
        assert_eq!(back, model, "empty secret keeps the stored one");
    }

    #[test]
    fn reports_every_bad_field_by_path() {
        let errs = apply_inputs::<Demo>(
            &json!({}),
            &inputs(&[("name", ""), ("port", "70000"), ("nets", "10.0.0.0/33")]),
        )
        .unwrap_err();
        let paths: Vec<_> = errs.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["name", "port", "nets"]);
    }

    #[test]
    fn runs_cross_field_validation_after_parsing() {
        let errs = apply_inputs::<Demo>(&json!({}), &inputs(&[("name", "a"), ("on", "true")]))
            .unwrap_err();
        assert_eq!(errs, [FieldError::new("nets", "Needed when on.")]);
    }

    #[test]
    fn set_path_creates_objects() {
        let mut v = json!(null);
        set_path(&mut v, "a.b.c", json!(1));
        assert_eq!(v, json!({"a": {"b": {"c": 1}}}));
        assert_eq!(get_path(&v, "a.b.c"), Some(&json!(1)));
    }

    #[test]
    fn multi_select_keeps_listed_values_only() {
        const GROUPS: &[OptGroup] = &[
            ("A", &[("a1", "One"), ("a2", "Two")]),
            ("B", &[("b1", "Three")]),
        ];
        let spec = FieldSpec::new("lists", "Lists", FieldKind::MultiSelect(GROUPS));
        assert_eq!(parse_field(&spec, "a2\nb1"), Ok(json!(["a2", "b1"])));
        assert_eq!(parse_field(&spec, ""), Ok(json!([])));
        assert!(parse_field(&spec, "a1\nnope").is_err());
        let spec = FieldSpec::new("d", "Domains", FieldKind::HostnameLines);
        assert_eq!(
            parse_field(&spec, "a.example\nb.example"),
            Ok(json!(["a.example", "b.example"]))
        );
        assert!(parse_field(&spec, "not a domain").is_err());
        assert!(parse_field(&spec, "_dmarc.example").is_err());
        let spec = FieldSpec::new("b", "Block", FieldKind::ListedNameLines);
        assert_eq!(
            parse_field(&spec, "_dmarc.example"),
            Ok(json!(["_dmarc.example"]))
        );
        assert!(parse_field(&spec, "bad name").is_err());
    }

    #[test]
    fn validators() {
        assert!(is_hostname("fw-1.example.org"));
        assert!(!is_hostname("-bad"));
        assert!(is_mac("00:11:22:aa:BB:cc"));
        assert!(!is_mac("00:11:22:aa:BB"));
        assert!(parse_cidr("2001:db8::/32"));
        assert!(!parse_cidr("2001:db8::"));
    }
}
