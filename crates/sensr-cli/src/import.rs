//! The importer boundary for `sensr import opnsense`.
//!
//! Today the document is OPNsense's own array view of `config.xml`
//! (`Config::toArray()`, from `sensr-import-opnsense`): lossless and in the
//! shape the agent's auth and the preview planner read. Once the typed
//! section mappers and `sensr-config`'s `Document` land, [`OpnsenseImporter`]
//! switches to them and the report lists mapped/unmapped nodes; callers only
//! see [`ConfigImporter`].

use anyhow::Context;
use sensr_import_opnsense::listtags::is_list_tag;
use sensr_import_opnsense::view::{self, Value as ArrayValue};
use serde_json::{Map, Value};

/// The result of importing one file.
#[derive(Debug, Clone, PartialEq)]
pub struct Imported {
    /// The sensr document to stage.
    pub document: Value,
    /// Human-readable import report.
    pub report: String,
    /// True when nothing needs the operator's attention.
    pub clean: bool,
}

/// Turns a foreign config file into a sensr document.
pub trait ConfigImporter {
    /// Imports `bytes`.
    fn import(&self, bytes: &[u8]) -> anyhow::Result<Imported>;
}

/// OPNsense `config.xml` importer.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpnsenseImporter;

fn to_json(v: &ArrayValue) -> Value {
    match v {
        ArrayValue::Text(t) => Value::String(t.clone()),
        ArrayValue::List(items) => Value::Array(items.iter().map(to_json).collect()),
        ArrayValue::Map(pairs) => {
            let mut m = Map::new();
            for (k, v) in pairs {
                m.insert(k.clone(), to_json(v));
            }
            Value::Object(m)
        }
    }
}

impl ConfigImporter for OpnsenseImporter {
    fn import(&self, bytes: &[u8]) -> anyhow::Result<Imported> {
        let doc = sensr_import_opnsense::parse_bytes(bytes).context("not a readable config.xml")?;
        anyhow::ensure!(
            doc.root.name == "opnsense",
            "root element is <{}>, expected <opnsense>",
            doc.root.name
        );
        let document = to_json(&view::to_array(&doc.root, &is_list_tag));
        let sections: Vec<&String> = document
            .as_object()
            .map(|m| m.keys().filter(|k| !k.contains('@')).collect())
            .unwrap_or_default();
        let mut report = format!(
            "imported {} top-level sections as OPNsense's array view: {}\n",
            sections.len(),
            sections
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        report.push_str(
            "note: typed section mappers are not wired into the CLI yet; every node was \
             carried over verbatim, nothing was dropped or reinterpreted.\n",
        );
        Ok(Imported {
            document,
            report,
            clean: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_lists_and_leaves() {
        let xml = br#"<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw</hostname>
    <user><name>root</name><uid>0</uid></user>
  </system>
  <filter>
    <rule uuid="a"><type>pass</type></rule>
    <rule uuid="b"><type>block</type></rule>
  </filter>
</opnsense>"#;
        let out = OpnsenseImporter.import(xml).unwrap();
        let d = &out.document;
        assert_eq!(d["system"]["hostname"], "fw");
        // `user` is on the always-list table even when it occurs once.
        assert_eq!(d["system"]["user"][0]["name"], "root");
        assert_eq!(d["filter"]["rule"][1]["type"], "block");
        assert_eq!(d["filter"]["rule"][0]["@attributes"]["uuid"], "a");
        assert!(out.report.contains("2 top-level sections"));
    }

    #[test]
    fn rejects_non_opnsense_documents() {
        assert!(OpnsenseImporter.import(b"<pfsense/>").is_err());
        assert!(OpnsenseImporter.import(b"not xml <").is_err());
    }
}
