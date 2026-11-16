//! Test-only access to `tests/fixtures/`.

use std::path::{Path, PathBuf};

/// The fixtures directory.
pub fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Read a fixture by its path relative to `tests/fixtures/`.
pub fn read(rel: &str) -> String {
    let path = dir().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Every `*.xml` fixture as `(relative path, contents)`, sorted by path.
pub fn all_xml() -> Vec<(String, String)> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(base, &path, out);
            } else if path.extension().is_some_and(|e| e == "xml") {
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                let text = std::fs::read_to_string(&path).unwrap();
                out.push((rel, text));
            }
        }
    }
    let base = dir();
    let mut out = Vec::new();
    walk(&base, &base, &mut out);
    out
}

/// Fixtures written by hand or by a tool other than OPNsense's `Config::save()`, so not
/// in the canonical byte form. Everything else must round-trip byte-exactly.
// The upstream field-type fixtures use 4-space indentation; the service test config has
// `<rule></rule>` and an indented closing root tag.
const NON_CANONICAL: &[&str] = &[
    "opnsense/AuthGroupFieldTest/config.xml",
    "opnsense/AuthenticationServerFieldTest/config.xml",
    "opnsense/CertificateFieldTest/config.xml",
    "opnsense/InterfaceFieldTest/config.xml",
    "opnsense/NetworkAliasFieldTest/config.xml",
    "opnsense/ServiceTests/config.xml",
    "opnsense/VirtualIPFieldTest/config.xml",
];

/// Whether the fixture at `rel` is in OPNsense's canonical saved form.
pub fn is_canonical(rel: &str) -> bool {
    !NON_CANONICAL.contains(&rel)
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-0347: lint-xml — every fixture XML is well-formed (and loadable by the importer).
    #[test]
    fn lint_fixtures_t0347() {
        let all = all_xml();
        assert!(
            all.len() >= 14,
            "fixture corpus went missing: {}",
            all.len()
        );
        for (path, text) in all {
            if let Err(e) = crate::xml::parse(&text) {
                panic!("{path}: {e}");
            }
        }
    }
}
