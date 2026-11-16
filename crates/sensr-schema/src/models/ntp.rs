//! The NTP service (OPNsense `ntpd` section, Services › Network Time;
//! served by ntpd-rs on sensr). The upstream servers themselves are
//! `system.time_servers`; this section holds how they are used and whether
//! the firewall serves time.

use std::collections::HashSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::check;
use crate::fields::{Host, InterfaceId};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldPath, Validations, ValidatorKind};

/// Per-server flags (OPNsense `prefer`, `noselect`, `iburst`, `ispool`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NtpServerOptions {
    /// The server, as listed in `system.time_servers`.
    pub host: Host,
    /// Prefer this source.
    #[serde(default)]
    pub prefer: bool,
    /// Query but never select (monitoring only).
    #[serde(default)]
    pub no_select: bool,
    /// Burst on start for fast synchronisation.
    #[serde(default)]
    pub iburst: bool,
    /// The name is a pool resolving to several servers.
    #[serde(default)]
    pub pool: bool,
    /// Use Network Time Security (ntpd-rs; no OPNsense equivalent).
    #[serde(default)]
    pub nts: bool,
}

/// NTP settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Ntp {
    /// Answer time queries from clients.
    #[serde(default)]
    pub serve: bool,
    /// Interfaces to serve on; empty means all (OPNsense `interface`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listen_interfaces: Vec<InterfaceId>,
    /// Flags for individual servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<NtpServerOptions>,
    /// Keep serving at this stratum when every source is lost (1-15).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orphan_stratum: Option<u8>,
    /// Refuse queries that would reveal state (OPNsense `query` unset).
    #[serde(default)]
    pub allow_query: bool,
}

impl Ntp {
    /// True when nothing differs from the defaults (the section is then
    /// omitted).
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Options for `host`, if any are set.
    pub fn options(&self, host: &Host) -> Option<&NtpServerOptions> {
        self.servers.iter().find(|o| &o.host == host)
    }
}

impl Ntp {
    /// Validates against the configured `time_servers`.
    pub fn validate_with(
        &self,
        time_servers: &[Host],
        ctx: &dyn RefContext,
        at: &FieldPath,
        out: &mut Validations,
    ) {
        check::interfaces(
            ctx,
            &self.listen_interfaces,
            &at.join("listen_interfaces"),
            out,
        );
        let mut seen = HashSet::new();
        for (i, o) in self.servers.iter().enumerate() {
            let p = at.join("servers").join(i);
            if !time_servers.contains(&o.host) {
                out.add(
                    &p.join("host"),
                    ValidatorKind::Callback,
                    format!("{} is not one of the configured time servers.", o.host),
                );
            }
            if !seen.insert(&o.host) {
                out.add(
                    &p.join("host"),
                    ValidatorKind::Constraint,
                    "Duplicate entry exists.",
                );
            }
            if o.prefer && o.no_select {
                out.add(
                    &p,
                    ValidatorKind::Callback,
                    "A server cannot be both preferred and never selected.",
                );
            }
        }
        if let Some(s) = self.orphan_stratum {
            check::range(s, 1..=15, &at.join("orphan_stratum"), out);
        }
    }
}

impl Validate for Ntp {
    /// Validation without the server list (`Document::validate` passes it via
    /// [`Ntp::validate_with`]).
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        let hosts: Vec<Host> = self.servers.iter().map(|o| o.host.clone()).collect();
        self.validate_with(&hosts, ctx, at, out);
    }
}
