//! Configurable fields whose options come from the rest of the
//! configuration (OPNsense `InterfaceField`, `NetworkAliasField`,
//! `ModelRelationField`, `CertificateField`, `AuthenticationServerField`,
//! `AuthGroupField`, `VirtualIPField`).
//!
//! OPNsense reads the live `config.xml` inside the field. Here the option
//! sources are passed in as plain records, so the same code serves the
//! importer (records straight from the XML tree), the compat API (records
//! from the typed [`crate::Document`]) and tests (hand-written fixtures).

use std::cmp::Ordering;

use indexmap::IndexMap;

use super::field::{Ctx, FieldType, Mask};
use super::network::{is_ip, is_subnet};
use super::option::{OptionEntry, OptionList, check_items, csv_join, csv_values};
use crate::validation::FieldError;

/// PHP `natcasesort` order: case-insensitive, digit runs compared by value.
pub fn natcasecmp(a: &str, b: &str) -> Ordering {
    let (a, b) = (a.to_lowercase(), b.to_lowercase());
    let (mut x, mut y) = (a.as_bytes(), b.as_bytes());
    loop {
        match (x.first(), y.first()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(c), Some(d)) if c.is_ascii_digit() && d.is_ascii_digit() => {
                let n = x.iter().take_while(|c| c.is_ascii_digit()).count();
                let m = y.iter().take_while(|c| c.is_ascii_digit()).count();
                let (da, db) = (&x[..n], &y[..m]);
                let strip = |d: &[u8]| -> usize {
                    d.iter()
                        .take_while(|c| **c == b'0')
                        .count()
                        .min(d.len().saturating_sub(1))
                };
                let (ta, tb) = (&da[strip(da)..], &db[strip(db)..]);
                let ord = ta.len().cmp(&tb.len()).then_with(|| ta.cmp(tb));
                if ord != Ordering::Equal {
                    return ord;
                }
                x = &x[n..];
                y = &y[m..];
            }
            (Some(c), Some(d)) => {
                if c != d {
                    return c.cmp(d);
                }
                x = &x[1..];
                y = &y[1..];
            }
        }
    }
}

fn sorted_list(mut items: Vec<(String, String)>) -> OptionList {
    items.sort_by(|a, b| natcasecmp(&a.1, &b.1));
    OptionList::new(items)
}

/// A record with named text fields, e.g. one `<interfaces>` child or
/// `<vip>` of `config.xml`. Missing fields read as `"0"` in filters, as
/// OPNsense does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record {
    /// The record's key (`lan`, a UUID, ...).
    pub key: String,
    /// Child values by tag name.
    pub fields: IndexMap<String, String>,
}

impl Record {
    /// A record from `(name, value)` pairs.
    pub fn new<K: Into<String>, V: Into<String>>(
        key: impl Into<String>,
        fields: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        Self {
            key: key.into(),
            fields: fields
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    /// A field's value, if present.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }

    /// True if the field is present and not PHP-empty (`""`, `"0"`).
    pub fn truthy(&self, name: &str) -> bool {
        self.get(name).is_some_and(|v| !v.is_empty() && v != "0")
    }

    /// True if every filter regex matches its field (`"0"` when missing).
    pub fn matches(&self, filters: &IndexMap<String, Mask>) -> bool {
        filters
            .iter()
            .all(|(k, re)| re.matches_partial(self.get(k).unwrap_or("0")))
    }
}

/// Which dynamic interfaces an [`InterfaceOptions`] list includes
/// (`AllowDynamic`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AllowDynamic {
    /// Never (`N`, default).
    #[default]
    No,
    /// Always (`Y`).
    Yes,
    /// Only when they have an address (`S`).
    WithAddress,
}

/// The parent-device relationships `AddParentDevices` needs: LAGG members
/// and VLAN parents, as `(parent device, child device)` pairs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParentDevices(pub Vec<(String, String)>);

/// Options of an `InterfaceField`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct InterfaceOptions {
    /// `Filters`: field name → regex that must match.
    pub filters: IndexMap<String, Mask>,
    /// `AddParentDevices`: offer LAGG/VLAN parents not assigned themselves.
    pub add_parent_devices: bool,
    /// `AllowDynamic`.
    pub allow_dynamic: AllowDynamic,
}

impl InterfaceOptions {
    /// The option list for `interfaces` (records keyed by `lan`, `wan`,
    /// `opt1`, with `if`, `descr`, `enable`, `ipaddr`, `internal_dynamic`, ...).
    pub fn build(&self, interfaces: &[Record], parents: &ParentDevices) -> OptionList {
        let mut all: Vec<Record> = Vec::new();
        for r in interfaces {
            let dynamic = r.truthy("internal_dynamic");
            match self.allow_dynamic {
                AllowDynamic::No if dynamic => continue,
                AllowDynamic::WithAddress
                    if dynamic && !r.truthy("ipaddr") && !r.truthy("ipaddrv6") =>
                {
                    continue;
                }
                _ => {}
            }
            all.push(r.clone());
        }
        if self.add_parent_devices {
            let assigned = |dev: &str| all.iter().find(|r| r.get("if") == Some(dev));
            let mut by_parent: IndexMap<&str, Vec<&str>> = IndexMap::new();
            for (parent, child) in &parents.0 {
                by_parent
                    .entry(parent.as_str())
                    .or_default()
                    .push(child.as_str());
            }
            let extra: Vec<Record> = by_parent
                .into_iter()
                .filter(|(parent, _)| assigned(parent).is_none())
                .map(|(parent, children)| {
                    let enabled = children
                        .iter()
                        .any(|c| assigned(c).is_some_and(|r| r.truthy("enable")));
                    Record::new(
                        parent,
                        [
                            (
                                "enable",
                                if enabled {
                                    "1".to_owned()
                                } else {
                                    "0".to_owned()
                                },
                            ),
                            ("descr", format!("[{parent}]")),
                            ("if", parent.to_owned()),
                        ],
                    )
                })
                .collect();
            all.extend(extra);
        }
        sorted_list(
            all.into_iter()
                .filter(|r| r.matches(&self.filters))
                .map(|r| {
                    let label = r
                        .get("descr")
                        .filter(|d| !d.is_empty())
                        .map_or_else(|| r.key.to_uppercase(), str::to_owned);
                    (r.key, label)
                })
                .collect(),
        )
    }
}

/// An option list with OPNsense list-field validation (the kind behind
/// interface, certificate, authentication server, group and VIP fields).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListField(pub OptionList);

impl FieldType for ListField {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        self.0
            .check_with(value, ctx, |k| self.0.options.contains_key(k))
    }

    fn values(&self, value: &str) -> Vec<String> {
        csv_values(value)
    }

    fn join(&self, values: &[&str]) -> String {
        csv_join(values)
    }

    fn normalize(&self, value: &str, required: bool) -> String {
        self.0.normalize(value, required)
    }
}

/// Authentication server choices: the built-in `Local Database` plus the
/// configured servers, filtered (`AuthenticationServerField`).
pub fn auth_server_options(servers: &[Record], filters: &IndexMap<String, Mask>) -> OptionList {
    let local = Record::new(
        "Local Database",
        [("name", "Local Database"), ("type", "local")],
    );
    sorted_list(
        std::iter::once(&local)
            .chain(servers)
            .filter(|r| r.matches(filters))
            .map(|r| {
                let name = r.get("name").unwrap_or(&r.key).to_owned();
                (name.clone(), name)
            })
            .collect(),
    )
}

/// Group choices keyed by gid (`AuthGroupField`).
pub fn auth_group_options(groups: &[Record]) -> OptionList {
    sorted_list(
        groups
            .iter()
            .map(|g| {
                (
                    g.get("gid").unwrap_or_default().to_owned(),
                    g.get("name").unwrap_or_default().to_owned(),
                )
            })
            .collect(),
    )
}

/// What a `CertificateField` lists (`Type`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CertKind {
    /// `<cert>` entries.
    #[default]
    Cert,
    /// `<ca>` entries, except OCSP signers.
    Ca,
    /// `<crl>` entries.
    Crl,
}

/// Certificate choices keyed by `refid` (`CertificateField`); `items` are
/// the entries of the selected kind.
pub fn certificate_options(kind: CertKind, items: &[Record]) -> OptionList {
    sorted_list(
        items
            .iter()
            .filter(|c| !(kind == CertKind::Ca && c.get("x509_extensions") == Some("ocsp")))
            .map(|c| {
                (
                    c.get("refid").unwrap_or_default().to_owned(),
                    c.get("descr").unwrap_or_default().to_owned(),
                )
            })
            .collect(),
    )
}

/// Virtual IP choices (`VirtualIPField`): `types` is the `Type` filter
/// (`*`, or a comma list of modes); keys are the subnet, or the item UUID
/// (`record.key`) with `mvc_key`. `interface_descr` names interfaces in the
/// captions.
pub fn virtual_ip_options(
    vips: &[Record],
    types: &str,
    mvc_key: bool,
    interface_descr: impl Fn(&str) -> Option<String>,
) -> OptionList {
    let wanted: Vec<&str> = types.split(',').collect();
    sorted_list(
        vips.iter()
            .filter(|v| types == "*" || wanted.contains(&v.get("mode").unwrap_or_default()))
            .map(|v| {
                let subnet = v.get("subnet").unwrap_or_default();
                let iface = v.get("interface").unwrap_or_default();
                let iface = interface_descr(iface).unwrap_or_else(|| iface.to_owned());
                let descr = v.get("descr").unwrap_or_default();
                let caption = match v.get("vhid").filter(|x| !x.is_empty()) {
                    Some(vhid) => format!("[{subnet}] {descr} on {iface} (vhid {vhid})"),
                    None => format!("[{subnet}] {descr} on {iface}"),
                };
                let key = if mvc_key {
                    v.key.clone()
                } else {
                    subnet.to_owned()
                };
                (key, caption)
            })
            .collect(),
    )
}

/// Address operands of rules (`NetworkAliasField`): `any`, `(self)`, each
/// interface's net (`lan`) and address (`lanip`, not for virtual
/// interfaces), every non-port alias, and any literal address or subnet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkAliasField {
    /// The named options.
    pub list: OptionList,
}

impl NetworkAliasField {
    /// Builds the options from interface records (`descr`, `virtual`) and
    /// `(alias name, alias type)` pairs.
    pub fn new(interfaces: &[Record], aliases: &[(String, String)]) -> Self {
        let mut items = vec![
            ("any".to_owned(), "any".to_owned()),
            ("(self)".to_owned(), "This Firewall".to_owned()),
        ];
        for r in interfaces {
            let descr = r
                .get("descr")
                .filter(|d| !d.is_empty())
                .map_or_else(|| r.key.to_uppercase(), str::to_owned);
            items.push((r.key.clone(), format!("{descr} net")));
            if r.get("virtual").is_none() {
                items.push((format!("{}ip", r.key), format!("{descr} address")));
            }
        }
        for (name, kind) in aliases {
            if kind != "port" {
                items.push((name.clone(), name.clone()));
            }
        }
        Self {
            list: OptionList::new(items),
        }
    }

    /// Builds the options from a typed document.
    pub fn from_document(doc: &crate::Document) -> Self {
        let ifaces: Vec<Record> = doc
            .interfaces
            .iter()
            .map(|(id, i)| {
                Record::new(
                    id.as_str(),
                    [(
                        "descr",
                        i.description
                            .as_ref()
                            .map(|d| d.as_str().to_owned())
                            .unwrap_or_default(),
                    )],
                )
            })
            .collect();
        let aliases: Vec<(String, String)> = doc
            .firewall
            .aliases
            .values()
            .map(|a| {
                let t = serde_json::to_value(a.content.alias_type())
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default();
                (a.name.to_string(), t)
            })
            .collect();
        Self::new(&ifaces, &aliases)
    }
}

impl FieldType for NetworkAliasField {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        check_items(
            self.list.multiple,
            value,
            ctx,
            "%s is not a valid source IP address or alias.",
            |k| is_ip(k) || is_subnet(k) || self.list.options.contains_key(k),
        )
    }

    fn values(&self, value: &str) -> Vec<String> {
        csv_values(value)
    }

    fn join(&self, values: &[&str]) -> String {
        csv_join(values)
    }
}

/// References to items of another model by UUID (`ModelRelationField`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ModelRelationField {
    /// UUID → display text. Ordered by display text unless `sorted`.
    pub list: OptionList,
    /// `Sorted`: keep model order, and list selected items first, in the
    /// order they were selected.
    pub sorted: bool,
}

impl ModelRelationField {
    /// Options from `(uuid, display)` pairs in model order.
    pub fn new(items: impl IntoIterator<Item = (String, String)>, sorted: bool) -> Self {
        let items: Vec<(String, String)> = items.into_iter().collect();
        let list = if sorted {
            OptionList::new(items)
        } else {
            sorted_list(items)
        };
        Self { list, sorted }
    }

    /// The option payload (`getNodeData`): with `sorted`, the selected items
    /// first in selection order, then the rest.
    pub fn payload(&self, value: &str, required: bool) -> IndexMap<String, OptionEntry> {
        let base = self.list.payload(value, required);
        if !self.sorted {
            return base;
        }
        let mut out = IndexMap::new();
        if let Some(blank) = base.get("") {
            out.insert(String::new(), blank.clone());
        }
        let order = value
            .split(',')
            .chain(self.list.options.keys().map(String::as_str));
        for k in order {
            if let Some(e) = base.get(k)
                && !k.is_empty()
                && !out.contains_key(k)
            {
                out.insert(k.to_owned(), e.clone());
            }
        }
        out
    }
}

impl FieldType for ModelRelationField {
    fn check(&self, value: &str, ctx: &Ctx<'_>) -> Vec<FieldError> {
        self.list
            .check_with(value, ctx, |k| self.list.options.contains_key(k))
    }

    fn values(&self, value: &str) -> Vec<String> {
        csv_values(value)
    }

    fn join(&self, values: &[&str]) -> String {
        csv_join(values)
    }

    fn normalize(&self, value: &str, required: bool) -> String {
        self.list.normalize(value, required)
    }
}

#[cfg(test)]
mod tests {
    //! Fixture data below reproduces the `config.xml` files under upstream's
    //! `mvc/tests/app/models/OPNsense/Base/FieldTypes/*Test/` (OPNsense,
    //! BSD-2-Clause) as records.

    use super::*;
    use crate::fields::field::Field;
    use crate::testing::{validate, validate_err};
    use crate::validation::ValidatorKind::*;

    #[test]
    fn natural_case_order() {
        let mut v = vec!["opt10", "OPT2", "lan", "Opt1"];
        v.sort_by(|a, b| natcasecmp(a, b));
        assert_eq!(v, ["lan", "Opt1", "OPT2", "opt10"]);
        assert_eq!(natcasecmp("a01", "a1"), Ordering::Equal);
    }

    fn list_field(list: OptionList, multiple: bool) -> Field<ListField> {
        let mut l = list;
        l.multiple = multiple;
        Field::new(ListField(l))
    }

    mod auth_server {
        use super::*;

        fn servers() -> Vec<Record> {
            vec![
                Record::new("testcase 1", [("name", "testcase 1"), ("type", "test")]),
                Record::new("testcase 2", [("name", "testcase 2"), ("type", "test")]),
            ]
        }

        fn opts() -> OptionList {
            auth_server_options(&servers(), &IndexMap::new())
        }

        #[test]
        fn fixture_loads_t0074() {
            assert_eq!(opts().options.len(), 3);
        }

        #[test]
        fn local_db_present_t0075() {
            assert!(opts().options.contains_key("Local Database"));
        }

        #[test]
        fn config_items_present_t0076() {
            assert!(
                opts().options.contains_key("testcase 1")
                    && opts().options.contains_key("testcase 2")
            );
        }

        #[test]
        fn unknown_rejected_t0077() {
            let mut f = list_field(opts(), true);
            f.set_value("testcase 1,testcase 2,testcase X");
            assert_eq!(validate_err(&f), Err(Callback));
        }

        #[test]
        fn known_multi_ok_t0078() {
            let mut f = list_field(opts(), true);
            f.set_value("testcase 1,testcase 2,Local Database");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn single_rejects_list_t0079() {
            let mut f = list_field(opts(), false);
            f.set_value("testcase 1,testcase 2,Local Database");
            assert_eq!(validate_err(&f), Err(Callback));
        }

        #[test]
        fn single_ok_t0080() {
            let mut f = list_field(opts(), false);
            f.set_value("testcase 1");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn not_container_t0081() {
            assert!(!list_field(opts(), false).is_container());
        }

        #[test]
        fn filters_apply() {
            let filters: IndexMap<String, Mask> =
                [("type".to_owned(), Mask::new("/^local$/").unwrap())]
                    .into_iter()
                    .collect();
            let o = auth_server_options(&servers(), &filters);
            assert_eq!(o.options.keys().collect::<Vec<_>>(), ["Local Database"]);
        }
    }

    mod auth_group {
        use super::*;

        fn opts() -> OptionList {
            auth_group_options(&[
                Record::new("100", [("gid", "100"), ("name", "group 1")]),
                Record::new("101", [("gid", "101"), ("name", "group 2")]),
                Record::new("102", [("gid", "102"), ("name", "group 3")]),
            ])
        }

        #[test]
        fn fixture_loads_t0082() {
            assert_eq!(opts().options.len(), 3);
        }

        #[test]
        fn config_items_present_t0083() {
            assert!(opts().options.contains_key("100"));
        }

        #[test]
        fn unknown_rejected_t0084() {
            let mut f = list_field(opts(), true);
            f.set_value("100,103,101");
            assert_eq!(validate_err(&f), Err(Callback));
        }

        #[test]
        fn empty_elements_dropped_t0085() {
            let mut f = list_field(opts(), true);
            f.set_values(&["101", "100"]);
            assert!(f.is_equal("101,100"));
            assert_eq!(f.values(), ["101", "100"]);
            assert!(validate(&f).is_empty());
            f.set_value("101,,100");
            assert!(f.is_equal("101,,100"));
            assert_eq!(f.values(), ["101", "100"]);
            f.set_values(&["101", "", "100"]);
            assert!(f.is_equal("101,100"));
            assert_eq!(f.values(), ["101", "100"]);
        }

        #[test]
        fn single_rejects_list_t0086() {
            let mut f = list_field(opts(), false);
            f.set_value("100,101");
            assert_eq!(validate_err(&f), Err(Callback));
        }

        #[test]
        fn single_ok_t0087() {
            let mut f = list_field(opts(), false);
            f.set_value("100");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn not_container_t0088() {
            assert!(!list_field(opts(), false).is_container());
        }
    }

    mod cert_ref {
        use super::*;

        fn certs() -> Vec<Record> {
            vec![
                Record::new("", [("refid", "5537f364ba123"), ("descr", "cert 1")]),
                Record::new("", [("refid", "55c382ee6020f"), ("descr", "cert 2")]),
            ]
        }

        fn cas() -> Vec<Record> {
            vec![
                Record::new("", [("refid", "1537f364ba123"), ("descr", "ca 1")]),
                Record::new("", [("refid", "15c382ee6020f"), ("descr", "ca 2")]),
                Record::new(
                    "",
                    [
                        ("refid", "ocsp1"),
                        ("descr", "ocsp signer"),
                        ("x509_extensions", "ocsp"),
                    ],
                ),
            ]
        }

        fn opts() -> OptionList {
            certificate_options(CertKind::Cert, &certs())
        }

        #[test]
        fn fixture_loads_t0107() {
            assert_eq!(opts().options.len(), 2);
        }

        #[test]
        fn cert_options_t0108() {
            assert!(opts().options.contains_key("5537f364ba123"));
        }

        #[test]
        fn ca_options_t0109() {
            let o = certificate_options(CertKind::Ca, &cas());
            assert!(
                o.options.contains_key("1537f364ba123") && o.options.contains_key("15c382ee6020f")
            );
            assert!(
                !o.options.contains_key("ocsp1"),
                "OCSP signers are not CAs to choose"
            );
        }

        #[test]
        fn unknown_rejected_t0110() {
            let mut f = list_field(opts(), true);
            f.set_value("testcase 1,testcase 2,testcase X");
            assert_eq!(validate_err(&f), Err(Callback));
        }

        #[test]
        fn known_multi_ok_t0111() {
            let mut f = list_field(opts(), true);
            f.set_value("5537f364ba123,55c382ee6020f");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn single_rejects_list_t0112() {
            let mut f = list_field(opts(), false);
            f.set_value("5537f364ba123,55c382ee6020f");
            assert_eq!(validate_err(&f), Err(Callback));
        }

        #[test]
        fn single_ok_t0113() {
            let mut f = list_field(opts(), false);
            f.set_value("5537f364ba123");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn not_container_t0114() {
            assert!(!list_field(opts(), false).is_container());
        }
    }

    fn interface_records() -> Vec<Record> {
        vec![
            Record::new(
                "wan",
                [
                    ("if", "if001"),
                    ("descr", "WAN"),
                    ("enable", "1"),
                    ("ipaddr", "dhcp"),
                ],
            ),
            Record::new("lan", [("if", "if002"), ("descr", "LAN"), ("enable", "1")]),
            Record::new(
                "opt1",
                [("if", "if003"), ("descr", "OPT1"), ("enable", "1")],
            ),
            Record::new(
                "enc0",
                [
                    ("internal_dynamic", "1"),
                    ("enable", "1"),
                    ("if", "enc0"),
                    ("descr", "IPsec"),
                    ("type", "none"),
                    ("virtual", "1"),
                ],
            ),
        ]
    }

    mod iface_ref {
        use super::*;

        fn parents() -> ParentDevices {
            ParentDevices(vec![
                ("if004".into(), "lagg0".into()),
                ("if005".into(), "lagg0".into()),
                ("if006".into(), "if006_vlan4".into()),
            ])
        }

        fn opts(o: InterfaceOptions) -> OptionList {
            o.build(&interface_records(), &parents())
        }

        #[test]
        fn fixture_loads_t0154() {
            assert_eq!(
                opts(InterfaceOptions::default()).options.len(),
                3,
                "enc0 is dynamic"
            );
        }

        #[test]
        fn config_items_present_t0155() {
            let o = opts(InterfaceOptions::default());
            assert!(o.options.contains_key("lan") && o.options.contains_key("wan"));
        }

        #[test]
        fn parents_excluded_by_default_t0156() {
            let mut f = list_field(opts(InterfaceOptions::default()), false);
            f.set_value("if006");
            assert_eq!(validate_err(&f), Err(Callback));
        }

        #[test]
        fn parents_included_t0157() {
            let o = opts(InterfaceOptions {
                add_parent_devices: true,
                ..InterfaceOptions::default()
            });
            assert!(o.options.contains_key("if006"));
            assert_eq!(o.options["if006"], "[if006]");
        }

        #[test]
        fn regex_filters_t0158() {
            let filters: IndexMap<String, Mask> = [
                ("ipaddr".to_owned(), Mask::new("/^((?!dhcp).)*$/").unwrap()),
                ("enable".to_owned(), Mask::new("/^(?!0).*$/").unwrap()),
            ]
            .into_iter()
            .collect();
            let o = opts(InterfaceOptions {
                filters,
                ..InterfaceOptions::default()
            });
            assert!(o.options.contains_key("lan") && o.options.contains_key("opt1"));
            assert!(!o.options.contains_key("wan"));
        }

        #[test]
        fn unknown_rejected_t0159() {
            let mut f = list_field(opts(InterfaceOptions::default()), true);
            f.set_value("lan,wan,opt99");
            assert_eq!(validate_err(&f), Err(Callback));
        }

        #[test]
        fn known_multi_ok_t0160() {
            let mut f = list_field(opts(InterfaceOptions::default()), true);
            f.set_value("lan,opt1");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn single_rejects_list_t0161() {
            let mut f = list_field(opts(InterfaceOptions::default()), false);
            f.set_value("lan,opt1");
            assert_eq!(validate_err(&f), Err(Callback));
        }

        #[test]
        fn single_ok_t0162() {
            let mut f = list_field(opts(InterfaceOptions::default()), false);
            f.set_value("lan");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn not_container_t0163() {
            assert!(!list_field(opts(InterfaceOptions::default()), false).is_container());
        }

        #[test]
        fn dynamic_modes() {
            let all = InterfaceOptions {
                allow_dynamic: AllowDynamic::Yes,
                ..InterfaceOptions::default()
            };
            assert!(opts(all).options.contains_key("enc0"));
            let with_addr = InterfaceOptions {
                allow_dynamic: AllowDynamic::WithAddress,
                ..InterfaceOptions::default()
            };
            assert!(!opts(with_addr).options.contains_key("enc0"));
        }
    }

    mod net_or_alias {
        use super::*;

        fn field() -> Field<NetworkAliasField> {
            let aliases: Vec<(String, String)> = [
                ("geoip_NL", "geoip"),
                ("network_alias", "network"),
                ("external_alias", "external"),
                ("host_alias", "host"),
                ("urltable_alias", "urltable"),
                ("port_alias", "port"),
            ]
            .into_iter()
            .map(|(a, b)| (a.to_owned(), b.to_owned()))
            .collect();
            Field::new(NetworkAliasField::new(&interface_records(), &aliases))
        }

        #[test]
        fn fixture_loads_t0204() {
            // any, (self), 4 nets, 3 addresses (enc0 is virtual), 5 aliases.
            assert_eq!(field().kind.list.options.len(), 14);
        }

        #[test]
        fn builtin_tokens_t0205() {
            let mut f = field();
            for v in ["any", "(self)"] {
                f.set_value(v);
                assert!(validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn interface_and_alias_tokens_t0206() {
            let mut f = field();
            for v in [
                "opt1",
                "opt1ip",
                "geoip_NL",
                "network_alias",
                "external_alias",
                "host_alias",
                "urltable_alias",
            ] {
                f.set_value(v);
                assert!(validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn literal_networks_ok_t0207() {
            let mut f = field();
            for v in [
                "192.168.0.1",
                "192.168.0.1/24",
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                "2001::/32",
            ] {
                f.set_value(v);
                assert!(validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn literal_networks_bad_t0208() {
            let mut f = field();
            for v in [
                "192.168.0.999",
                "192.168.0.1/64",
                "2001:0db8:85a3:0000:0000:8a2e:0370:xxxx",
                "2001::/300",
            ] {
                f.set_value(v);
                assert!(!validate(&f).is_empty(), "{v}");
            }
        }

        #[test]
        fn virtual_iface_and_port_alias_rejected_t0209() {
            let mut f = field();
            for v in ["enc0ip", "port_alias"] {
                f.set_value(v);
                assert!(!validate(&f).is_empty(), "{v}");
            }
            assert_eq!(
                f.validate()[0].message,
                "port_alias is not a valid source IP address or alias."
            );
        }

        #[test]
        fn not_container_t0210() {
            assert!(!field().is_container());
        }

        #[test]
        fn from_document() {
            let k = NetworkAliasField::from_document(&crate::Document::factory());
            for key in ["any", "(self)", "wan", "wanip", "lan", "lanip"] {
                assert!(k.list.options.contains_key(key), "{key}");
            }
        }
    }

    mod vip_ref {
        use super::*;

        fn vips() -> Vec<Record> {
            vec![
                Record::new(
                    "u1",
                    [
                        ("type", "network"),
                        ("subnet_bits", "24"),
                        ("mode", "ipalias"),
                        ("interface", "lan"),
                        ("descr", "test_vip_1"),
                        ("subnet", "172.11.1.0"),
                    ],
                ),
                Record::new(
                    "u2",
                    [
                        ("type", "network"),
                        ("subnet_bits", "24"),
                        ("mode", "other"),
                        ("interface", "wan"),
                        ("descr", "test_vip_2"),
                        ("subnet", "10.207.0.1"),
                    ],
                ),
                Record::new(
                    "u3",
                    [
                        ("type", "single"),
                        ("subnet_bits", "24"),
                        ("mode", "carp"),
                        ("interface", "lan"),
                        ("descr", "test_vip_3"),
                        ("subnet", "10.100.0.10"),
                        ("vhid", "9"),
                    ],
                ),
                Record::new(
                    "u4",
                    [
                        ("type", "single"),
                        ("subnet_bits", "24"),
                        ("mode", "carp"),
                        ("interface", "wan"),
                        ("descr", "test_vip_4"),
                        ("subnet", "10.100.0.11"),
                        ("vhid", "9"),
                    ],
                ),
            ]
        }

        fn descr(i: &str) -> Option<String> {
            match i {
                "lan" => Some("LAN".into()),
                "wan" => Some("WAN".into()),
                _ => None,
            }
        }

        fn opts(t: &str) -> OptionList {
            virtual_ip_options(&vips(), t, false, descr)
        }

        #[test]
        fn fixture_loads_t0287() {
            assert_eq!(opts("*").options.len(), 4);
        }

        #[test]
        fn filter_carp_t0288() {
            let o = opts("carp");
            assert!(o.options.contains_key("10.100.0.10") && !o.options.contains_key("172.11.1.0"));
            assert_eq!(
                o.options["10.100.0.10"],
                "[10.100.0.10] test_vip_3 on LAN (vhid 9)"
            );
        }

        #[test]
        fn filter_ipalias_t0289() {
            let o = opts("ipalias");
            assert!(o.options.contains_key("172.11.1.0") && !o.options.contains_key("10.207.0.1"));
        }

        #[test]
        fn filter_other_t0290() {
            let o = opts("other");
            assert!(!o.options.contains_key("172.11.1.0") && o.options.contains_key("10.207.0.1"));
        }

        #[test]
        fn not_container_t0291() {
            assert!(!list_field(opts("*"), false).is_container());
            assert!(
                virtual_ip_options(&vips(), "carp", true, descr)
                    .options
                    .contains_key("u3"),
                "MVC keys are UUIDs"
            );
        }
    }

    mod relation {
        use super::*;

        const IDS: [&str; 6] = [
            "5ea2a35c-b02b-485a-912b-d077e639bf9f",
            "48bea3c9-c563-4885-a593-dea0a6af2e1e",
            "d1e7eda3-f940-42d9-8dfa-db7b1264b6e1",
            "4d0e2835-7a19-4a19-8c23-e12383827594",
            "60e1bc02-6817-4940-bbd3-61d0cf439a8a",
            "3bf8fc9c-6f36-4821-9944-ed7dfed50ad6",
        ];

        fn field(multiple: bool, blank: Option<&str>) -> Field<ModelRelationField> {
            let mut k = ModelRelationField::new(
                IDS.iter()
                    .enumerate()
                    .map(|(i, id)| ((*id).to_owned(), (i + 1).to_string())),
                false,
            );
            k.list.multiple = multiple;
            k.list.blank_desc = blank.map(str::to_owned);
            Field::new(k)
        }

        fn keys(f: &Field<ModelRelationField>) -> Vec<String> {
            f.kind
                .payload(f.value(), f.is_required())
                .into_keys()
                .collect()
        }

        fn pos(keys: &[String], k: &str) -> usize {
            keys.iter().position(|x| x == k).unwrap()
        }

        #[test]
        fn fixture_loads_t0181() {
            assert_eq!(field(false, None).kind.list.options.len(), 6);
        }

        #[test]
        fn single_ok_t0182() {
            let mut f = field(false, None);
            f.set_value(IDS[0]);
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn single_rejects_list_t0183() {
            let mut f = field(false, None);
            f.set_value(format!("{},{}", IDS[0], IDS[4]));
            assert_eq!(validate(&f), [Callback]);
        }

        #[test]
        fn none_optional_ok_t0184() {
            let mut f = field(false, None);
            f.set_value("");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn none_required_fails_t0185() {
            let mut f = field(false, None).required();
            f.set_value("");
            assert_eq!(validate(&f), [PresenceOf]);
        }

        #[test]
        fn empty_element_in_multi_fails_t0186() {
            let mut f = field(true, None);
            f.set_value(format!("'',{}", IDS[0]));
            assert_eq!(validate(&f), [Callback]);
        }

        #[test]
        fn blank_desc_empty_ok_t0187() {
            let mut f = field(true, Some("No selection."));
            f.set_value("");
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn blank_desc_unknown_fails_t0188() {
            let mut f = field(true, Some("No selection."));
            f.set_value("Not an option");
            assert_eq!(validate(&f), [Callback]);
        }

        #[test]
        fn blank_desc_single_ok_t0189() {
            let mut f = field(true, Some("No selection."));
            f.set_value(IDS[2]);
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn blank_desc_option_payload_t0190() {
            let mut f = field(false, Some("No selection."));
            f.set_value("");
            let p = f.kind.payload(f.value(), false);
            assert_eq!(
                p[""],
                OptionEntry {
                    value: "No selection.".into(),
                    selected: true
                }
            );
        }

        #[test]
        fn blank_desc_default_none_t0191() {
            let mut f = field(false, Some(""));
            // An empty BlankDesc falls back to "None", as upstream.
            f.kind.list.blank_desc = f.kind.list.blank_desc.filter(|b| !b.is_empty());
            f.set_value("");
            let p = f.kind.payload(f.value(), false);
            assert_eq!(
                p[""],
                OptionEntry {
                    value: "None".into(),
                    selected: true
                }
            );
        }

        #[test]
        fn bad_uuid_fails_t0192() {
            let mut f = field(false, None);
            f.set_value(format!("XX{}", IDS[0]));
            assert_eq!(validate(&f), [Callback]);
        }

        #[test]
        fn multi_ok_t0193() {
            let mut f = field(true, None);
            f.set_value(format!("{},{}", IDS[3], IDS[0]));
            assert!(validate(&f).is_empty());
        }

        #[test]
        fn multi_one_bad_fails_t0194() {
            let mut f = field(true, None);
            f.set_value(format!("x{},{}", IDS[3], IDS[0]));
            assert_eq!(validate(&f), [Callback]);
        }

        #[test]
        fn explicit_single_rejects_list_t0195() {
            let mut f = field(false, None);
            f.set_value(format!("{},{}", IDS[3], IDS[0]));
            assert_eq!(validate(&f), [Callback]);
        }

        #[test]
        fn sorted_selected_first_t0196() {
            let mut f = field(true, None);
            f.set_value(format!("{},{}", IDS[3], IDS[0]));
            let k = keys(&f);
            assert_eq!((pos(&k, IDS[0]), pos(&k, IDS[3])), (0, 3));
            f.kind.sorted = true;
            let k = keys(&f);
            assert_eq!((pos(&k, IDS[3]), pos(&k, IDS[0])), (0, 1));
        }

        #[test]
        fn sorted_none_unchanged_t0197() {
            let mut f = field(false, None);
            f.set_value("");
            let k = keys(&f);
            assert_eq!((pos(&k, ""), pos(&k, IDS[3])), (0, 4));
            f.kind.sorted = true;
            let k = keys(&f);
            assert_eq!((pos(&k, ""), pos(&k, IDS[3])), (0, 4));
        }

        #[test]
        fn sorted_with_empty_element_t0198() {
            let mut f = field(true, None);
            f.set_value(format!("{},''", IDS[3]));
            let k = keys(&f);
            assert_eq!(
                (pos(&k, IDS[1]), pos(&k, IDS[4]), pos(&k, IDS[3])),
                (1, 4, 3)
            );
            f.kind.sorted = true;
            let k = keys(&f);
            assert_eq!(
                (pos(&k, IDS[1]), pos(&k, IDS[4]), pos(&k, IDS[3])),
                (2, 4, 0)
            );
        }

        #[test]
        fn sorted_all_selected_t0199() {
            let mut f = field(true, None);
            f.set_value(IDS.join(","));
            let want: Vec<String> = IDS.iter().map(|s| (*s).to_owned()).collect();
            assert_eq!(keys(&f), want);
            f.kind.sorted = true;
            assert_eq!(keys(&f), want);
        }

        #[test]
        fn sorted_some_ordered_t0200() {
            let mut f = field(true, None);
            f.set_value(format!("{},{},{},", IDS[2], IDS[3], IDS[4]));
            let want: Vec<String> = IDS.iter().map(|s| (*s).to_owned()).collect();
            assert_eq!(keys(&f), want);
            f.kind.sorted = true;
            let k = keys(&f);
            let got: Vec<usize> = IDS.iter().map(|id| pos(&k, id)).collect();
            assert_eq!(got, [3, 4, 0, 1, 2, 5]);
        }

        #[test]
        fn sorted_some_unordered_t0201() {
            let mut f = field(true, None);
            f.set_value(format!("{},{},{},", IDS[4], IDS[1], IDS[3]));
            f.kind.sorted = true;
            let k = keys(&f);
            let got: Vec<usize> = IDS.iter().map(|id| pos(&k, id)).collect();
            assert_eq!(got, [3, 1, 4, 2, 0, 5]);
        }

        #[test]
        fn sorted_ignores_invalid_t0202() {
            let mut f = field(true, None);
            f.set_value(format!(
                "{},d3adb33f-c563-4885-a593-dea0a6af2e1e,{},",
                IDS[4], IDS[3]
            ));
            f.kind.sorted = true;
            let k = keys(&f);
            let got: Vec<usize> = IDS.iter().map(|id| pos(&k, id)).collect();
            assert_eq!(got, [2, 3, 4, 1, 0, 5]);
        }

        #[test]
        fn not_container_t0203() {
            assert!(!field(false, None).is_container());
        }
    }
}
