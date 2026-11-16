//! `#[derive(SensrModel)]` on a Rust twin of upstream's
//! `tests/OPNsense/Base/BaseModel/TestModel` (OPNsense, BSD-2-Clause).

use pretty_assertions::assert_eq;
use sensr_schema::{
    ArrayField, Document, FieldPath, PathAccess, SensrModel, SensrOptions, Validate, Validations,
    ValidatorKind,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, SensrModel)]
#[sensr(description = "General settings")]
#[serde(deny_unknown_fields)]
struct General {
    #[serde(rename = "FromEmail")]
    #[sensr(required, default = "sample@example.com")]
    from_email: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, SensrModel)]
#[sensr(description = "Array item")]
#[serde(deny_unknown_fields)]
struct Item {
    #[sensr(
        required,
        range(min = 1, max = 65535),
        message = "Not a valid number.",
        unique(with(optfield), message = "Number should be unique.")
    )]
    number: u32,
    #[serde(default)]
    optfield: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, SensrModel)]
#[sensr(description = "All or none")]
#[serde(deny_unknown_fields)]
struct AllOrNone {
    #[sensr(all_or_none(
        with(value2, value3),
        message = "All fields should contain data or none of them."
    ))]
    value1: String,
    value2: String,
    value3: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, SensrModel)]
#[sensr(description = "Single select")]
#[serde(deny_unknown_fields)]
struct SingleSelect {
    #[sensr(single_select(with(value2, value3), message = "Only one option could be selected."))]
    value1: String,
    value2: String,
    value3: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, SensrModel)]
#[sensr(description = "Depend constraint")]
#[serde(deny_unknown_fields)]
struct Depend {
    #[sensr(required, default = "false")]
    value1: bool,
    #[sensr(depend(
        with(value1),
        message = "When \"value1\" is enabled, \"value2\" is required."
    ))]
    value2: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, SensrModel)]
#[sensr(description = "Set constraint")]
#[serde(deny_unknown_fields)]
struct SetC {
    value1: String,
    #[sensr(set(
        with(value1),
        message = "When \"value1\" is enabled, \"value2\" is required."
    ))]
    value2: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, SensrModel)]
#[sensr(description = "RecursiveModel test", version = "1.0.0")]
#[serde(deny_unknown_fields)]
struct TestModel {
    #[sensr(nested)]
    general: General,
    #[sensr(nested)]
    arraytypes: ArrayField<Item>,
    #[serde(rename = "AllOrNone")]
    #[sensr(nested)]
    all_or_none: AllOrNone,
    #[serde(rename = "SingleSelect")]
    #[sensr(nested)]
    single_select: SingleSelect,
    #[serde(rename = "DependConstraint")]
    #[sensr(nested)]
    depend: Depend,
    #[serde(rename = "SetConstraint")]
    #[sensr(nested)]
    set: SetC,
}

impl Default for General {
    fn default() -> Self {
        Self::defaults()
    }
}

impl Default for Depend {
    fn default() -> Self {
        Self::defaults()
    }
}

fn validate(m: &TestModel) -> Validations {
    let mut out = Validations::new();
    m.validate(&Document::default(), &FieldPath::root(), &mut out);
    out
}

fn with_items(n: u32) -> TestModel {
    let mut m = TestModel::defaults();
    for number in 1..=n {
        m.arraytypes.push(Item {
            number,
            optfield: String::new(),
        });
    }
    m
}

#[test]
fn test_model_constructs_empty_t0022() {
    let m = TestModel::defaults();
    assert_eq!(m.general.from_email, "sample@example.com");
    assert!(m.arraytypes.is_empty());
    assert_eq!(TestModel::DESCRIPTION, "RecursiveModel test");
    assert_eq!(TestModel::VERSION.unwrap().to_string(), "1.0.0");
}

#[test]
fn container_present_t0023() {
    let m = TestModel::defaults();
    assert!(m.get_by_path("general").unwrap().is_object());
    assert_eq!(
        m.get_by_path("general.FromEmail").unwrap(),
        json!("sample@example.com")
    );
}

#[test]
fn validate_ok_t0031() {
    assert!(validate(&with_items(10)).is_ok());
}

#[test]
fn validate_integer_message_t0032() {
    let errs = Item::validate_text("number", "XXX");
    assert_eq!(
        errs.iter().map(|e| e.kind).collect::<Vec<_>>(),
        [ValidatorKind::MinMax, ValidatorKind::Integer]
    );
    assert!(errs.iter().all(|e| e.message == "Not a valid number."));
    assert!(Item::validate_text("number", "80").is_empty());
    assert_eq!(Item::validate_text("number", "").len(), 1, "required");
    let mut m = with_items(1);
    let id = *m.arraytypes.keys().next().unwrap();
    m.arraytypes.get_mut(&id).unwrap().number = 70000;
    let v = validate(&m);
    assert_eq!(
        v.get(&format!("arraytypes.{id}.number")).unwrap()[0].message,
        "Not a valid number."
    );
}

#[test]
fn model_duplicate_message_t0038() {
    let mut m = with_items(9);
    let ids: Vec<_> = m.arraytypes.keys().copied().take(2).collect();
    for id in &ids {
        m.arraytypes.get_mut(id).unwrap().number = 999;
    }
    let v = validate(&m);
    for id in &ids {
        assert_eq!(
            v.get(&format!("arraytypes.{id}.number")).unwrap()[0].message,
            "Number should be unique."
        );
    }
    assert_eq!(v.len(), 2);
}

#[test]
fn model_ok_t0039() {
    let mut m = with_items(9);
    for (n, (_, item)) in m.arraytypes.iter_mut().enumerate() {
        item.number = u32::try_from(n).unwrap() + 2;
    }
    assert!(validate(&m).is_ok());
}

#[test]
fn constraints_through_the_model() {
    let mut m = TestModel::defaults();
    m.all_or_none.value2 = "X".into();
    m.single_select.value1 = "x".into();
    m.single_select.value2 = "x".into();
    m.depend.value1 = true;
    m.set.value1 = "0".into();
    let v = validate(&m);
    assert_eq!(
        v.get("AllOrNone.value1").unwrap()[0].message,
        "All fields should contain data or none of them."
    );
    assert_eq!(
        v.get("SingleSelect.value1").unwrap()[0].message,
        "Only one option could be selected."
    );
    assert_eq!(
        v.get("DependConstraint.value2").unwrap()[0].message,
        "When \"value1\" is enabled, \"value2\" is required."
    );
    assert_eq!(
        v.get("SetConstraint.value2").unwrap()[0].message,
        "When \"value1\" is enabled, \"value2\" is required."
    );
}

#[test]
fn metadata() {
    let f = Item::field("number").unwrap();
    assert!(f.required);
    assert_eq!(f.message, Some("Not a valid number."));
    assert_eq!(
        General::field("FromEmail").unwrap().default,
        Some("sample@example.com")
    );
    assert!(Item::field("nope").is_none());
    assert_eq!(
        Item::validate_text("nope", "x")[0].message,
        "Unknown field nope."
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SensrOptions)]
#[serde(rename_all = "snake_case")]
enum AliasKind {
    #[sensr(label = "Host(s)")]
    Host,
    #[sensr(label = "URL Table (IPs)")]
    UrlTable,
}

#[test]
fn option_labels() {
    assert_eq!(
        AliasKind::options(),
        [("host", "Host(s)"), ("url_table", "URL Table (IPs)")]
    );
}
