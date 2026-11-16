//! The importer boundary for `sensr import opnsense`.
//!
//! `config.xml` goes through `sensr-import-opnsense`'s section mappers into
//! the typed `sensr-schema` document; the report lists what was mapped, what
//! was deliberately left behind and anything nobody understood, each by
//! XPath. Callers only see [`ConfigImporter`].

use std::collections::BTreeMap;

use anyhow::Context;
use sensr_import_opnsense::opnsense::{ImportOptions, import_config};
use sensr_schema::fields::DeviceName;
use serde_json::Value;

/// The result of importing one file.
#[derive(Debug, Clone, PartialEq)]
pub struct Imported {
    /// The sensr document to stage (typed document as JSON).
    pub document: Value,
    /// Human-readable import report.
    pub report: String,
    /// True when nothing unexpected was left unmapped.
    pub clean: bool,
}

/// Turns a foreign config file into a sensr document.
pub trait ConfigImporter {
    /// Imports `bytes`.
    fn import(&self, bytes: &[u8]) -> anyhow::Result<Imported>;
}

/// OPNsense `config.xml` importer.
#[derive(Debug, Default, Clone)]
pub struct OpnsenseImporter {
    /// FreeBSD device → Linux device renames (`igc0=enp1s0`).
    pub devices: BTreeMap<String, DeviceName>,
}

impl OpnsenseImporter {
    /// Parses `--device FREEBSD=LINUX` arguments.
    pub fn with_devices(pairs: &[String]) -> anyhow::Result<Self> {
        let mut devices = BTreeMap::new();
        for p in pairs {
            let (from, to) = p.split_once('=').with_context(|| {
                format!("--device {p:?}: expected FREEBSD=LINUX, e.g. igc0=enp1s0")
            })?;
            let to: DeviceName = to
                .parse()
                .map_err(|e| anyhow::anyhow!("--device {p:?}: {e}"))?;
            devices.insert(from.to_owned(), to);
        }
        Ok(Self { devices })
    }
}

impl ConfigImporter for OpnsenseImporter {
    fn import(&self, bytes: &[u8]) -> anyhow::Result<Imported> {
        let text = std::str::from_utf8(bytes).context("config.xml is not UTF-8")?;
        let options = ImportOptions {
            devices: self.devices.clone(),
        };
        let imported = import_config(text, &options).context("not a readable config.xml")?;
        let document =
            serde_json::to_value(&imported.document).context("encoding the imported document")?;
        Ok(Imported {
            document,
            clean: imported.report.is_clean(),
            report: imported.report.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME_ROUTER: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../sensr-import-opnsense/tests/fixtures/corpus/home-router.xml"
    );

    #[test]
    fn imports_the_home_router_corpus_file() {
        let bytes = std::fs::read(HOME_ROUTER).unwrap();
        let out = OpnsenseImporter::default().import(&bytes).unwrap();
        let doc: sensr_schema::Document = serde_json::from_value(out.document.clone()).unwrap();
        assert!(doc.interfaces.get(&"lan".parse().unwrap()).is_some());
        assert!(
            out.report.starts_with("# sensr import report"),
            "{}",
            out.report
        );
    }

    #[test]
    fn device_renames_are_validated() {
        assert!(OpnsenseImporter::with_devices(&["igc0=enp1s0".into()]).is_ok());
        assert!(OpnsenseImporter::with_devices(&["igc0".into()]).is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(OpnsenseImporter::default().import(b"not xml <").is_err());
        assert!(OpnsenseImporter::default().import(&[0xff, 0xfe]).is_err());
    }
}
