//! The import report: what was mapped, what was deliberately left behind, what
//! nobody understood, and what was imported with a caveat — every entry located by
//! an XPath into the original `config.xml`.
//!
//! The importer never drops a node silently (PLAN §1): anything no mapper consumed
//! lands in [`ImportReport::unmapped_expected`] (known and harmless, e.g. FreeBSD-only
//! tunables) or [`ImportReport::unmapped_unexpected`] (a gap in sensr), with the
//! original XML kept so nothing is lost.

use std::fmt;

/// One mapped section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapped {
    /// Where in `config.xml`.
    pub xpath: String,
    /// Which mapper took it.
    pub mapper: &'static str,
}

/// One node no mapper consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unmapped {
    /// Where in `config.xml`.
    pub xpath: String,
    /// Why it is expected to be unmapped (only for expected entries).
    pub reason: Option<&'static str>,
    /// The node as OPNsense would write it, so it can be inspected or carried along.
    pub xml: String,
}

/// How serious a warning is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Imported, with a note (e.g. a value normalised).
    Info,
    /// Imported with reduced fidelity (e.g. a pf feature nftables cannot express).
    Degraded,
    /// A value was invalid and not imported.
    Invalid,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Degraded => "degraded",
            Severity::Invalid => "invalid",
        })
    }
}

/// A caveat attached to a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    /// Where in `config.xml`.
    pub xpath: String,
    /// How serious.
    pub severity: Severity,
    /// What happened, for a human.
    pub message: String,
}

/// The full report of one import.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Sections taken by a mapper.
    pub mapped: Vec<Mapped>,
    /// Nodes left unmapped on purpose.
    pub unmapped_expected: Vec<Unmapped>,
    /// Nodes no mapper understood: each is a gap to close.
    pub unmapped_unexpected: Vec<Unmapped>,
    /// Caveats on imported values.
    pub warnings: Vec<Warning>,
}

impl ImportReport {
    /// Whether the import is complete: nothing unexpected left behind and no value rejected.
    pub fn is_clean(&self) -> bool {
        self.unmapped_unexpected.is_empty()
            && self.warnings.iter().all(|w| w.severity < Severity::Invalid)
    }
}

/// The golden-file text form (`import-report.txt`): stable ordering, one entry per line.
impl fmt::Display for ImportReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "# sensr import report")?;
        writeln!(f)?;
        writeln!(f, "## mapped ({})", self.mapped.len())?;
        for m in &self.mapped {
            writeln!(f, "{}  <- {}", m.xpath, m.mapper)?;
        }
        writeln!(f)?;
        writeln!(
            f,
            "## unmapped, expected ({})",
            self.unmapped_expected.len()
        )?;
        for u in &self.unmapped_expected {
            writeln!(f, "{}  ({})", u.xpath, u.reason.unwrap_or("expected"))?;
        }
        writeln!(f)?;
        writeln!(
            f,
            "## unmapped, unexpected ({})",
            self.unmapped_unexpected.len()
        )?;
        for u in &self.unmapped_unexpected {
            writeln!(f, "{}", u.xpath)?;
        }
        writeln!(f)?;
        writeln!(f, "## warnings ({})", self.warnings.len())?;
        for w in &self.warnings {
            writeln!(f, "[{}] {}: {}", w.severity, w.xpath, w.message)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_form_lists_every_category() {
        let report = ImportReport {
            mapped: vec![Mapped {
                xpath: "/opnsense/system".into(),
                mapper: "system",
            }],
            unmapped_expected: vec![Unmapped {
                xpath: "/opnsense/rrd".into(),
                reason: Some("RRD graphs are replaced by sensr-monitor"),
                xml: "<rrd/>".into(),
            }],
            unmapped_unexpected: vec![Unmapped {
                xpath: "/opnsense/foo".into(),
                reason: None,
                xml: "<foo/>".into(),
            }],
            warnings: vec![Warning {
                xpath: "/opnsense/filter/rule[2]/os".into(),
                severity: Severity::Degraded,
                message: "OS fingerprint match dropped".into(),
            }],
        };
        assert!(!report.is_clean());
        let text = report.to_string();
        assert!(text.contains("/opnsense/system  <- system"));
        assert!(text.contains("/opnsense/rrd  (RRD graphs"));
        assert!(text.contains("## unmapped, unexpected (1)\n/opnsense/foo\n"));
        assert!(text.contains("[degraded] /opnsense/filter/rule[2]/os: OS fingerprint"));
    }
}
