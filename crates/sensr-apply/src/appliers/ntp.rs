//! NTP: `ntp.toml` for ntpd-rs, rendered from a typed model.
//!
//! OPNsense runs ntpd whenever time servers are configured (`ntpd.inc`
//! `ntpd_enabled()`): it keeps the firewall's clock and, unless `noserve` is
//! set, answers clients on every interface or only on the selected ones.
//! sensr does the same with ntpd-rs, a memory-safe NTP daemon that also
//! speaks NTS. Behaviour kept from OPNsense:
//!
//! - names under `.pool.ntp.org` (or flagged as pools) are pools;
//! - the daemon never gives up on a large clock step (`tinker panic 0`), so
//!   a box that boots far off (a Pi without an RTC battery) still syncs;
//! - one usable source is enough (ntpd's `minsane 1`): ntpd-rs's default of
//!   three agreeing sources would leave the clock unsteered whenever fewer
//!   answer, e.g. two of three configured servers being down; with several
//!   it still picks the largest agreeing group;
//! - with listen interfaces, only their addresses and loopback are bound.
//!
//! ntpd-rs has no per-source `prefer` or `iburst` (its 16 s initial poll is
//! burst-like already); a `noselect` source is left out, since ntpd-rs cannot
//! query a source without using it. Client requests are rate limited the way
//! ntpd's `limited` + `kod` does (a kiss-o'-death `RATE` to clients polling
//! more than once a second).

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use sensr_schema::fields::Host;
use serde::Serialize;

use crate::cmd::{Cmd, CmdError, Runner};

/// The NTP port.
pub const NTP_PORT: u16 = 123;

/// Where the daemon's observation socket lives (`ntp-ctl status` reads it
/// from the config).
pub const OBSERVATION_SOCKET: &str = "/run/ntpd-rs/observe";

/// How a source is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceMode {
    /// One server.
    Server,
    /// A DNS name resolving to several servers.
    Pool,
    /// One server, authenticated with Network Time Security.
    Nts,
    /// A pool of NTS servers (experimental in ntpd-rs).
    NtsPool,
}

/// A time source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// Address or name.
    pub host: Host,
    /// How it is reached.
    pub mode: SourceMode,
}

/// Servers taken from one pool.
const POOL_COUNT: usize = 4;

/// The NTP input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpModel {
    /// Upstream sources, in configuration order.
    pub sources: Vec<Source>,
    /// Sockets to answer clients on; empty: client only.
    pub listen: Vec<SocketAddr>,
    /// Stratum to serve the local clock at while no source is synchronised
    /// (OPNsense orphan stratum); `None`: refuse to serve unsynchronised time.
    pub local_stratum: Option<u8>,
    /// Observation socket for `ntp-ctl`.
    pub observation_path: PathBuf,
}

/// Model errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NtpError {
    /// The orphan stratum is outside 1-15.
    #[error("local stratum {0} is outside 1-15")]
    Stratum(u8),
    /// TOML serialisation failed.
    #[error("rendering ntp.toml: {0}")]
    Toml(String),
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Toml<'a> {
    observability: Observability<'a>,
    #[serde(rename = "source", skip_serializing_if = "Vec::is_empty")]
    sources: Vec<TomlSource>,
    #[serde(rename = "server", skip_serializing_if = "Vec::is_empty")]
    servers: Vec<TomlServer>,
    synchronization: Synchronization,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Observability<'a> {
    log_level: &'static str,
    observation_path: &'a Path,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct TomlSource {
    mode: SourceMode,
    address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    count: Option<usize>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct TomlServer {
    listen: String,
    rate_limiting_cache_size: u32,
    rate_limiting_cutoff_ms: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
struct Synchronization {
    minimum_agreeing_sources: usize,
    single_step_panic_threshold: &'static str,
    startup_step_panic_threshold: Thresholds,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_stratum: Option<u8>,
}

#[derive(Serialize)]
struct Thresholds {
    forward: &'static str,
    backward: &'static str,
}

impl NtpModel {
    /// `ntp.toml`.
    pub fn render(&self) -> Result<String, NtpError> {
        if let Some(s) = self.local_stratum
            && !(1..=15).contains(&s)
        {
            return Err(NtpError::Stratum(s));
        }
        let doc = Toml {
            observability: Observability {
                log_level: "warn",
                observation_path: &self.observation_path,
            },
            sources: self
                .sources
                .iter()
                .map(|s| TomlSource {
                    mode: s.mode,
                    address: s.host.to_string(),
                    count: matches!(s.mode, SourceMode::Pool | SourceMode::NtsPool)
                        .then_some(POOL_COUNT),
                })
                .collect(),
            servers: self
                .listen
                .iter()
                .map(|a| TomlServer {
                    listen: a.to_string(),
                    rate_limiting_cache_size: 4096,
                    rate_limiting_cutoff_ms: 1000,
                })
                .collect(),
            synchronization: Synchronization {
                minimum_agreeing_sources: 1,
                single_step_panic_threshold: "inf",
                startup_step_panic_threshold: Thresholds {
                    forward: "inf",
                    backward: "inf",
                },
                local_stratum: self.local_stratum,
            },
        };
        let body = toml::to_string(&doc).map_err(|e| NtpError::Toml(e.to_string()))?;
        Ok(format!(
            "# Rendered by sensr; changes are overwritten.\n{body}"
        ))
    }
}

/// The wildcard listener: one dual-stack socket answers IPv4 and IPv6.
pub fn wildcard() -> SocketAddr {
    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), NTP_PORT)
}

/// Run `ntp-ctl validate -c <file>`: `Ok(None)` when ntpd-rs is not
/// installed, `Ok(Some(""))` when the file is accepted, else its message.
pub fn check(runner: &dyn Runner, file: &Path) -> Result<Option<String>, CmdError> {
    if !runner.has_program("ntp-ctl") {
        return Ok(None);
    }
    let out = runner.run(
        &Cmd::new("ntp-ctl").arg("validate").arg("-c").arg(file),
        None,
    )?;
    Ok(Some(if out.success() {
        String::new()
    } else {
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            out.stderr_text()
        )
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appliers::convert::tests::slice_models;
    use crate::cmd::SystemRunner;

    fn model() -> NtpModel {
        slice_models().ntp.expect("fixture has time servers")
    }

    #[test]
    fn ntp_toml_golden() {
        let m = model();
        let out = m.render().unwrap();
        assert_eq!(out, m.render().unwrap(), "deterministic");
        insta::assert_snapshot!(out);
    }

    #[test]
    fn client_only_has_no_server_section() {
        let mut m = model();
        m.listen.clear();
        assert!(!m.render().unwrap().contains("[[server]]"));
    }

    #[test]
    fn stratum_out_of_range_is_rejected() {
        let mut m = model();
        m.local_stratum = Some(16);
        assert_eq!(m.render(), Err(NtpError::Stratum(16)));
    }

    #[test]
    fn real_checker_accepts_the_rendered_file() {
        let r = SystemRunner;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("ntp.toml");
        std::fs::write(&f, model().render().unwrap()).unwrap();
        match check(&r, &f).unwrap() {
            None => eprintln!("ntp-ctl not installed; skipping"),
            Some(msg) => assert!(msg.is_empty(), "{msg}"),
        }
    }
}
