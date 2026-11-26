//! Shared data types that compile with no features enabled.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::proto::JobKind;

/// Transport protocol of a scanned port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

/// What a probe learned about a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

/// What identification learned about an open port. Every text field is
/// sanitised with [`sanitize`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Ident {
    /// Software or device, e.g. `"OpenSSH"` or `"Linux nas 6.1"`.
    pub product: Option<String>,
    pub version: Option<String>,
    /// A human name: page title, device or host name.
    pub title: Option<String>,
    pub tls: Option<TlsInfo>,
    /// Other text worth showing, e.g. a banner line or status.
    pub banner: Option<String>,
}

/// The certificate a TLS service presented.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TlsInfo {
    pub subject: String,
    pub sans: Vec<String>,
    pub issuer: String,
    /// Expiry, Unix seconds.
    pub not_after: i64,
}

/// Longest text kept in an [`Ident`] field, in bytes.
pub const TEXT_MAX: usize = 256;

/// Captured bytes to display text: invalid UTF-8 replaced, whitespace
/// controls (tab, CR, LF, ...) turned into spaces, other control characters
/// dropped, runs of spaces and of U+FFFD collapsed to one, trimmed, and cut to
/// [`TEXT_MAX`] bytes on a character boundary.
#[must_use]
pub fn sanitize(b: &[u8]) -> String {
    let mut out = String::new();
    for c in String::from_utf8_lossy(b).chars() {
        let c = if c.is_whitespace() { ' ' } else { c };
        let repeat = (c == ' ' || c == char::REPLACEMENT_CHARACTER) && out.ends_with(c);
        if c.is_control() || repeat || (c == ' ' && out.is_empty()) {
            continue;
        }
        if out.len() + c.len_utf8() > TEXT_MAX {
            break;
        }
        out.push(c);
    }
    while out.ends_with(' ') {
        out.pop();
    }
    out
}

/// How a stored scan of one address ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    /// Every probe finished.
    Complete,
    /// Some probes finished before the scan stopped.
    Partial,
    /// A person stopped it.
    Cancelled,
    /// It could not run.
    Failed,
}

impl ScanStatus {
    /// The text stored in the database.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
}

impl std::str::FromStr for ScanStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "complete" => Ok(Self::Complete),
            "partial" => Ok(Self::Partial),
            "cancelled" => Ok(Self::Cancelled),
            "failed" => Ok(Self::Failed),
            other => Err(format!("unknown scan status {other:?}")),
        }
    }
}

/// One port of a stored scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRow {
    pub proto: Proto,
    pub port: u16,
    pub state: PortState,
    /// Service name from the port table, e.g. `"ssh"`.
    pub service: Option<String>,
    pub ident: Ident,
}

/// A stored scan of one address, with its ports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanView {
    pub id: i64,
    pub job_id: i64,
    pub address: IpAddr,
    pub mac: Option<String>,
    /// Unix seconds.
    pub started: i64,
    /// Unix seconds.
    pub finished: i64,
    pub status: ScanStatus,
    /// Every port of the range was probed ("all ports" mode).
    pub all_open: bool,
    pub ports: Vec<PortRow>,
}

/// A stored scan job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobView {
    pub id: i64,
    pub kind: JobKind,
    pub target: String,
    /// `"auto"` or `"owner"`.
    pub requested_by: String,
    /// Unix seconds.
    pub started: i64,
    /// Unix seconds; `None` while running.
    pub finished: Option<i64>,
    /// `"queued"`, `"running"`, `"complete"`, `"cancelled"` or `"failed"`.
    pub status: String,
    /// Addresses left out of the job (excluded or not local).
    pub skipped: Vec<IpAddr>,
    /// Addresses that were alive and scanned.
    pub hosts_alive: u32,
    /// The device's MAC, for device jobs.
    pub mac: Option<String>,
}

/// Open ports that differ from the previous complete scan.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Changes {
    pub opened: Vec<(Proto, u16)>,
    pub closed: Vec<(Proto, u16)>,
    /// Open in both, but product, version, title, certificate or banner differ.
    pub changed: Vec<(Proto, u16)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_drops_controls_and_collapses_space() {
        assert_eq!(sanitize(b"  a\x00b\r\n\tc \x1b[0m "), "ab c [0m");
        assert_eq!(sanitize(b"\xff ok"), "\u{fffd} ok");
        assert_eq!(sanitize(b"\xff\xfe\xff ok \xff"), "\u{fffd} ok \u{fffd}");
        assert_eq!(sanitize(b""), "");
    }

    #[test]
    fn sanitize_caps_on_char_boundary() {
        let s = "é".repeat(200); // 400 bytes
        let t = sanitize(s.as_bytes());
        assert_eq!(t.len(), TEXT_MAX);
        assert!(t.chars().all(|c| c == 'é'));
        let t = sanitize(format!("a{s}").as_bytes());
        assert_eq!(t.len(), TEXT_MAX - 1);
    }

    #[test]
    fn ident_serde_round_trip() {
        let i = Ident {
            product: Some("p".into()),
            tls: Some(TlsInfo {
                subject: "CN=x".into(),
                sans: vec!["x".into()],
                issuer: "CN=ca".into(),
                not_after: 1_700_000_000,
            }),
            ..Ident::default()
        };
        let j = serde_json::to_string(&i).unwrap();
        assert_eq!(serde_json::from_str::<Ident>(&j).unwrap(), i);
    }
}
