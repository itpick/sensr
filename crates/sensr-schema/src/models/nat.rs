//! NAT: outbound (source) NAT, port forwards and 1:1 NAT (OPNsense
//! `nat/outbound`, `Firewall/Filter.xml` `snatrules` and `onetoone`,
//! `Firewall/DNat.xml` `nat/rule`).

use ipnet::IpNet;
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
    /// 1:1 (static) NAT.
    #[serde(default, skip_serializing_if = "ArrayField::is_empty")]
    pub one_to_one: ArrayField<OneToOneRule>,
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
    /// Add source NAT so reflected replies come back through the firewall
    /// (port forwards and 1:1 rules).
    #[serde(default)]
    pub source_nat: bool,
    /// Reflect 1:1 rules (OPNsense `reflection_binat`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub one_to_one: bool,
}

impl Default for Reflection {
    fn default() -> Self {
        Self {
            port_forwards: true,
            source_nat: false,
            one_to_one: false,
        }
    }
}

/// What a 1:1 rule translates (OPNsense `type`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OneToOneKind {
    /// Both ways: outbound sources become `external`, inbound traffic to
    /// `external` reaches the internal network (pf `binat`). Networks map
    /// prefix-preserving, so both must be the same size.
    #[default]
    Binat,
    /// Outbound only: matching sources leave as `external` (pf `nat`).
    Nat,
}

/// Per-rule 1:1 reflection override (OPNsense `natreflection`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OneToOneReflection {
    /// Internal clients reach the mapping by its external address.
    Enable,
    /// Never reflect.
    Disable,
}

/// An address operand without ports (1:1 rules match addresses only).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddressMatch {
    /// Address operand.
    #[serde(default)]
    pub net: NetOrAlias,
    /// Match everything except `net`.
    #[serde(default)]
    pub not: bool,
}

/// A 1:1 NAT rule (OPNsense `Filter.xml` `onetoone`, legacy `nat/onetoone`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OneToOneRule {
    /// Disabled rules are kept but not loaded.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Evaluation order key.
    #[serde(default = "one")]
    pub sequence: u32,
    /// The (external) interface the mapping applies on.
    pub interface: InterfaceId,
    /// Bidirectional or outbound only.
    #[serde(default, rename = "type")]
    pub kind: OneToOneKind,
    /// External address or network. A host with an internal network takes
    /// the internal network's prefix length (`203.0.113.5` with
    /// `10.0.0.0/24` maps `10.0.0.x` to `203.0.113.x`).
    #[serde(with = "host_or_net")]
    #[schemars(with = "String")]
    pub external: IpNet,
    /// Internal address or network (the original source).
    pub source: AddressMatch,
    /// Peers the mapping applies to; usually any.
    #[serde(default)]
    pub destination: AddressMatch,
    /// Log matches.
    #[serde(default)]
    pub log: bool,
    /// Reflection override; `None` follows [`Reflection::one_to_one`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reflection: Option<OneToOneReflection>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
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

        let one = at.join("one_to_one");
        for (id, r) in &self.one_to_one {
            r.validate(ctx, &one.join(id), out);
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

impl OneToOneRule {
    fn validate(&self, ctx: &dyn RefContext, p: &FieldPath, out: &mut Validations) {
        check::interface(ctx, &self.interface, &p.join("interface"), out);
        let ext_family = match self.external {
            IpNet::V4(_) => IpFamily::Inet,
            IpNet::V6(_) => IpFamily::Inet6,
        };
        for (field, m) in [("source", &self.source), ("destination", &self.destination)] {
            let at = p.join(field);
            check::net_or_alias(ctx, &m.net, &at.join("net"), out);
            if m.not && m.net.is_any() {
                out.add(
                    &at.join("not"),
                    ValidatorKind::Callback,
                    "Inverting \"any\" would match nothing; clear the inversion or choose an address.",
                );
            }
            if let Some(f) = m.net.literal_family()
                && f != ext_family
            {
                out.add(
                    &at.join("net"),
                    ValidatorKind::Callback,
                    "The address family must match the external address.",
                );
            }
        }
        if self.kind == OneToOneKind::Binat {
            // pf takes a single literal network as the binat source (no
            // tables, interfaces or inversion) and maps it bit for bit.
            let src = p.join("source");
            match &self.source.net {
                NetOrAlias::Net(n) => {
                    let host = self.external.prefix_len() == self.external.max_prefix_len();
                    if !host && self.external.prefix_len() != n.prefix_len() {
                        out.add(
                            &p.join("external"),
                            ValidatorKind::Callback,
                            "The external and internal networks must be the same size.",
                        );
                    }
                }
                _ => out.add(
                    &src.join("net"),
                    ValidatorKind::Callback,
                    "A BINAT source must be an address or network; use type NAT for aliases and interface networks.",
                ),
            }
            if self.source.not {
                out.add(
                    &src.join("not"),
                    ValidatorKind::Callback,
                    "A BINAT source cannot be inverted.",
                );
            }
        }
    }
}

/// An address or network as text: hosts are written without a prefix
/// length (`203.0.113.5`), networks with one.
mod host_or_net {
    use std::net::IpAddr;

    use ipnet::IpNet;
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S: Serializer>(n: &IpNet, s: S) -> Result<S::Ok, S::Error> {
        if n.prefix_len() == n.max_prefix_len() {
            s.collect_str(&n.addr())
        } else {
            s.collect_str(n)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<IpNet, D::Error> {
        let t = String::deserialize(d)?;
        let t = t.trim();
        if let Ok(ip) = t.parse::<IpAddr>() {
            return Ok(IpNet::from(ip));
        }
        t.parse::<IpNet>()
            .map_err(|_| de::Error::custom(format!("{t:?} is not an IP address or network")))
    }
}
