//! Recursive DNS resolver settings and host overrides (OPNsense
//! `Unbound/Unbound.xml`; legacy `unbound` host/domain overrides are
//! translated by the importer).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::array::ArrayField;
use crate::fields::{Description, DomainName, HostOverrideName, InterfaceId, Port};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldPath, Validations, ValidatorKind};

/// Unbound `local-zone` type for the system domain: how names without local
/// data are answered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LocalZoneType {
    /// Answer local data, resolve everything else normally.
    #[default]
    Transparent,
    /// Like transparent, and also resolve other types of names that have
    /// local data.
    Typetransparent,
    /// Answer local data only; NXDOMAIN otherwise.
    Static,
    /// Answer local data; REFUSED otherwise.
    Refuse,
    /// Answer local data; drop otherwise.
    Deny,
    /// Answer every name under the zone with the zone apex data.
    Redirect,
    /// Like transparent, logging the client.
    Inform,
    /// Like deny, logging the client.
    InformDeny,
    /// No default local zone.
    Nodefault,
    /// Resolve normally, ignoring local data.
    AlwaysTransparent,
    /// Always REFUSED.
    AlwaysRefuse,
    /// Always NXDOMAIN.
    AlwaysNxdomain,
}

/// The recursive resolver.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DnsResolver {
    /// Run the resolver.
    #[serde(default)]
    pub enabled: bool,
    /// Listen port.
    #[serde(default = "dns_port")]
    pub port: Port,
    /// Interfaces to answer on; empty means all.
    #[serde(default)]
    pub listen_interfaces: Vec<InterfaceId>,
    /// Interfaces to send queries from; empty means all.
    #[serde(default)]
    pub outgoing_interfaces: Vec<InterfaceId>,
    /// Validate DNSSEC.
    #[serde(default)]
    pub dnssec: bool,
    /// Synthesize AAAA records for IPv4-only names.
    #[serde(default)]
    pub dns64: bool,
    /// Register DHCP leases by host name.
    #[serde(default)]
    pub register_dhcp_leases: bool,
    /// Register DHCP static reservations.
    #[serde(default)]
    pub register_dhcp_static: bool,
    /// Domain for registered leases; `None` uses `system.domain`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp_domain: Option<DomainName>,
    /// Local zone behaviour.
    #[serde(default)]
    pub local_zone_type: LocalZoneType,
    /// Forward queries instead of recursing.
    #[serde(default)]
    pub forwarding: Forwarding,
    /// Static records.
    #[serde(default)]
    pub host_overrides: ArrayField<HostOverride>,
}

fn dns_port() -> Port {
    Port::new(53).expect("non-zero")
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self {
            enabled: false,
            port: dns_port(),
            listen_interfaces: Vec::new(),
            outgoing_interfaces: Vec::new(),
            dnssec: false,
            dns64: false,
            register_dhcp_leases: false,
            register_dhcp_static: false,
            dhcp_domain: None,
            local_zone_type: LocalZoneType::Transparent,
            forwarding: Forwarding::default(),
            host_overrides: ArrayField::new(),
        }
    }
}

/// Query forwarding (Unbound forward zones / OPNsense "Query Forwarding" and
/// "DNS over TLS").
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Forwarding {
    /// Forward everything to `system.dns_servers` (OPNsense forwarding mode).
    #[serde(default)]
    pub use_system_servers: bool,
    /// Explicit upstreams, optionally per domain.
    #[serde(default)]
    pub servers: ArrayField<Forwarder>,
}

/// One upstream server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Forwarder {
    /// Use this upstream.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Only for names under this domain; `None` for everything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<DomainName>,
    /// Server address.
    pub address: IpAddr,
    /// Server port; `None` for 53 (or 853 with TLS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<Port>,
    /// Name to verify in the server's certificate; enables DNS over TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_name: Option<DomainName>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

/// The data of a host override.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "rr", rename_all = "UPPERCASE", deny_unknown_fields)]
pub enum DnsRecord {
    /// IPv4 address.
    A {
        /// Address.
        address: Ipv4Addr,
    },
    /// IPv6 address.
    Aaaa {
        /// Address.
        address: Ipv6Addr,
    },
    /// Mail exchanger.
    Mx {
        /// Preference (lower first).
        priority: u16,
        /// Mail server host.
        host: DomainName,
    },
    /// Text.
    Txt {
        /// Record text.
        data: String,
    },
}

/// A static DNS record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostOverride {
    /// Serve the record.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Host part (empty for the domain itself, `*` for a wildcard).
    #[serde(default = "apex")]
    pub hostname: HostOverrideName,
    /// Domain.
    pub domain: DomainName,
    /// Record data.
    pub record: DnsRecord,
    /// TTL in seconds; `None` for the resolver default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

fn apex() -> HostOverrideName {
    HostOverrideName::Apex
}

impl HostOverride {
    /// The full name (`host.domain`, or `domain` for the apex).
    pub fn fqdn(&self) -> String {
        match &self.hostname {
            HostOverrideName::Apex => self.domain.to_string(),
            h => format!("{h}.{}", self.domain),
        }
    }
}

impl Validate for DnsResolver {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        check::interfaces(
            ctx,
            &self.listen_interfaces,
            &at.join("listen_interfaces"),
            out,
        );
        check::interfaces(
            ctx,
            &self.outgoing_interfaces,
            &at.join("outgoing_interfaces"),
            out,
        );
        let hosts = at.join("host_overrides");
        for (id, h) in &self.host_overrides {
            let p = hosts.join(id);
            if let Some(ttl) = h.ttl {
                check::range(ttl, 0..=2_147_483_647, &p.join("ttl"), out);
            }
            if let DnsRecord::Txt { data } = &h.record
                && (data.is_empty() || data.contains(['\n', '\r']))
            {
                out.add(
                    &p.join("record").join("data"),
                    ValidatorKind::Regex,
                    "The TXT data must be a single non-empty line.",
                );
            }
        }
        check::unique(
            self.host_overrides
                .iter()
                .filter(|(_, h)| {
                    h.enabled && matches!(h.record, DnsRecord::A { .. } | DnsRecord::Aaaa { .. })
                })
                .map(|(id, h)| {
                    (
                        hosts.join(id),
                        Some((h.fqdn().to_ascii_lowercase(), h.record.clone())),
                    )
                }),
            "record",
            "Duplicate entry exists.",
            out,
        );
    }
}
