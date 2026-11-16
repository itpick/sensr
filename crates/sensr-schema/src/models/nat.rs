//! NAT: outbound (source) NAT and port forwards (OPNsense `nat/outbound`,
//! `Firewall/Filter.xml` `snatrules`, `Firewall/DNat.xml` `nat/rule`).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::firewall::{Endpoint, FilterRule, validate_match};
use super::{check, yes};
use crate::array::{ArrayField, Relation};
use crate::fields::{
    Description, InterfaceId, IpFamily, NetOrAlias, PortRange, PortSpec, Protocol,
};
use crate::refs::{ItemKind, RefContext, Validate};
use crate::validation::{FieldPath, Validations, ValidatorKind, messages};

/// All NAT configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Nat {
    /// Source NAT.
    #[serde(default)]
    pub outbound: OutboundNat,
    /// Destination NAT (port forwards).
    #[serde(default)]
    pub port_forwards: ArrayField<PortForward>,
    /// NAT reflection defaults.
    #[serde(default)]
    pub reflection: Reflection,
}

/// How outbound NAT rules are produced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OutboundNatMode {
    /// Masquerade every internal network out of every WAN interface.
    #[default]
    Automatic,
    /// Automatic rules plus `rules`, which take precedence.
    Hybrid,
    /// Only `rules` (OPNsense "advanced").
    Manual,
    /// No source NAT.
    Disabled,
}

/// Outbound NAT.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutboundNat {
    /// Rule generation mode.
    #[serde(default)]
    pub mode: OutboundNatMode,
    /// Manual rules (used in hybrid and manual modes).
    #[serde(default)]
    pub rules: ArrayField<SourceNatRule>,
}

/// A manual outbound NAT rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceNatRule {
    /// Disabled rules are kept but not loaded.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Exempt matching traffic from NAT instead of translating it.
    #[serde(default)]
    pub no_nat: bool,
    /// Evaluation order key.
    #[serde(default = "one")]
    pub sequence: u32,
    /// Egress interface.
    pub interface: InterfaceId,
    /// Address families.
    #[serde(default)]
    pub ip_protocol: IpFamily,
    /// Protocol.
    #[serde(default)]
    pub protocol: Protocol,
    /// Original source.
    #[serde(default)]
    pub source: Endpoint,
    /// Destination.
    #[serde(default)]
    pub destination: Endpoint,
    /// Translated source address; `None` means the egress interface's address
    /// (masquerade).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<NetOrAlias>,
    /// Translated source port(s).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<PortRange>,
    /// Keep the original source port.
    #[serde(default)]
    pub static_port: bool,
    /// Log matches.
    #[serde(default)]
    pub log: bool,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

/// Per-rule NAT reflection override (OPNsense `natreflection`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReflectionMode {
    /// Reflect with source NAT so internal clients reach the forward by its
    /// public address.
    Enable,
    /// Reflect without source NAT (only works across interfaces).
    Purenat,
    /// Never reflect.
    Disable,
}

/// Global NAT reflection defaults (OPNsense `Filter.xml` `settings.nat`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Reflection {
    /// Reflect port forwards.
    #[serde(default = "yes")]
    pub port_forwards: bool,
    /// Add source NAT so reflected replies come back through the firewall.
    #[serde(default)]
    pub source_nat: bool,
}

impl Default for Reflection {
    fn default() -> Self {
        Self {
            port_forwards: true,
            source_nat: false,
        }
    }
}

/// Which filter rule admits a port forward's traffic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ForwardFilter {
    /// Pass the forwarded traffic implicitly (OPNsense "pass").
    #[default]
    Pass,
    /// A linked filter rule kept in sync with the forward.
    Rule(Relation<FilterRule>),
    /// No rule: the operator writes one.
    None,
}

/// A port forward (destination NAT).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PortForward {
    /// Disabled forwards are kept but not loaded.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Evaluation order key.
    #[serde(default = "one")]
    pub sequence: u32,
    /// Exempt matching traffic from redirection (OPNsense `nordr`).
    #[serde(default)]
    pub no_rdr: bool,
    /// Ingress interfaces.
    pub interfaces: Vec<InterfaceId>,
    /// Address families.
    #[serde(default)]
    pub ip_protocol: IpFamily,
    /// Protocol.
    #[serde(default = "tcp")]
    pub protocol: Protocol,
    /// Original source.
    #[serde(default)]
    pub source: Endpoint,
    /// Original destination (usually `addr:wan` and the public port).
    pub destination: Endpoint,
    /// Internal host to redirect to (an address or a host alias).
    pub target: NetOrAlias,
    /// Internal port (start of the range); `None` keeps the original port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_port: Option<PortSpec>,
    /// Log matches.
    #[serde(default)]
    pub log: bool,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
    /// Reflection override; `None` follows [`Reflection`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reflection: Option<ReflectionMode>,
    /// How the forwarded traffic is admitted by the filter.
    #[serde(default)]
    pub filter: ForwardFilter,
}

fn one() -> u32 {
    1
}

fn tcp() -> Protocol {
    Protocol::Tcp
}

impl Validate for Nat {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        let rules = at.join("outbound").join("rules");
        for (id, r) in &self.outbound.rules {
            let p = rules.join(id);
            check::interface(ctx, &r.interface, &p.join("interface"), out);
            validate_match(
                ctx,
                r.ip_protocol,
                r.protocol,
                [("source", &r.source), ("destination", &r.destination)],
                &p,
                out,
            );
            if let Some(t) = &r.target {
                check::net_or_alias(ctx, t, &p.join("target"), out);
                if matches!(t, NetOrAlias::Any) {
                    out.add(
                        &p.join("target"),
                        ValidatorKind::Callback,
                        "The translation target cannot be any.",
                    );
                }
            }
            if r.target_port.is_some() && !r.protocol.has_ports() {
                out.add(
                    &p.join("target_port"),
                    ValidatorKind::Callback,
                    "Ports can only be specified for TCP, UDP or SCTP.",
                );
            }
        }

        let fwds = at.join("port_forwards");
        for (id, f) in &self.port_forwards {
            let p = fwds.join(id);
            if f.interfaces.is_empty() {
                out.add(
                    &p.join("interfaces"),
                    ValidatorKind::PresenceOf,
                    "Select at least one interface.",
                );
            }
            check::interfaces(ctx, &f.interfaces, &p.join("interfaces"), out);
            validate_match(
                ctx,
                f.ip_protocol,
                f.protocol,
                [("source", &f.source), ("destination", &f.destination)],
                &p,
                out,
            );
            let tp = p.join("target");
            check::net_or_alias(ctx, &f.target, &tp, out);
            match &f.target {
                NetOrAlias::Any | NetOrAlias::This | NetOrAlias::InterfaceNet(_) => {
                    out.add(
                        &tp,
                        ValidatorKind::Callback,
                        "A valid redirect target IP address must be specified.",
                    );
                }
                NetOrAlias::Net(n) if n.prefix_len() != n.max_prefix_len() => {
                    out.add(
                        &tp,
                        ValidatorKind::Callback,
                        "A valid redirect target IP address must be specified.",
                    );
                }
                _ => {}
            }
            if let Some(port) = &f.target_port {
                if f.protocol.has_ports() {
                    check::port_spec(ctx, port, &p.join("target_port"), out);
                } else {
                    out.add(
                        &p.join("target_port"),
                        ValidatorKind::Callback,
                        "Ports can only be specified for TCP, UDP or SCTP.",
                    );
                }
            }
            if let ForwardFilter::Rule(r) = f.filter
                && !ctx.has_item(ItemKind::FilterRule, &r.id())
            {
                out.add(
                    &p.join("filter"),
                    ValidatorKind::Callback,
                    messages::RELATION_NOT_FOUND,
                );
            }
        }
    }
}
