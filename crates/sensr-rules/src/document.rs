//! A whole `sensr-schema` [`Document`] → the ruleset the agent loads.
//!
//! Typed rules are serialised into upstream's internal key space the way
//! the OPNsense MVC models do (`FilterRuleContainerField::serialize`, the
//! DNat node content), then go through the same normalisation as system and
//! legacy rules — one set of semantics, and the pf oracle covers typed rules
//! too.

use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;

use ipnet::IpNet;
use sensr_schema::Document;
use sensr_schema::fields::{IpFamily as SchemaFamily, NetOrAlias, PortSpec, Protocol};
use sensr_schema::models::firewall::{self as fw, Direction, RuleAction, StateType};
use sensr_schema::models::interfaces::{InterfaceRole, Ipv4Config, Ipv6Config};
use sensr_schema::models::nat::{self as sn, ForwardFilter, OutboundNatMode, ReflectionMode};

use crate::alias::{self, AliasDef, Resolution, Sources};
use crate::conf;
use crate::conf::{Conf, Value};
use crate::ir::{FilterRule, IfAddr, Interface, InterfaceMap, IpFamily, V4Mode, V6Mode};
use crate::nat::{self, NatRules, OutboundMode, ReflectionDefaults};
use crate::normalize::Context;
use crate::render::{nft, pf};
use crate::ruleset::Ruleset;
use crate::system_rules::{self, SystemSettings};

/// Run-time facts the configuration does not hold.
#[derive(Default)]
pub struct Runtime<'a> {
    /// addresses learned at run time (DHCP WAN, SLAAC, tracked prefixes) per
    /// logical interface
    pub addrs: BTreeMap<String, Vec<IfAddr>>,
    /// alias data sources; `None` resolves only configuration-local aliases
    pub sources: Option<&'a dyn Sources>,
}

/// Everything needed to render, plus what went wrong on the way.
#[derive(Clone, Debug, Default)]
pub struct Compiled {
    /// logical interfaces
    pub interfaces: InterfaceMap,
    /// filter rules in registration order
    pub filter: Vec<FilterRule>,
    /// NAT rules
    pub nat: NatRules,
    /// alias resolution
    pub aliases: Resolution,
    /// render options from the firewall settings
    pub options: nft::Options,
}

impl Compiled {
    /// The render input.
    pub fn policy(&self) -> nft::Policy<'_> {
        nft::Policy {
            rules: &self.filter,
            interfaces: &self.interfaces,
            aliases: &self.aliases.aliases,
            nat: Some(&self.nat),
        }
    }

    /// Writes the nft JSON document.
    pub fn render_nft<W: io::Write>(&self, out: &mut W) -> io::Result<nft::Report> {
        nft::render(&self.policy(), &self.options, out)
    }

    /// The pf oracle text (NAT then filter, as `/tmp/rules.debug`).
    pub fn render_pf(&self) -> String {
        let mut rules = self.filter.clone();
        rules.sort_by_key(|r| r.priority);
        format!(
            "{}{}",
            pf::nat_rules(&self.nat, &self.interfaces),
            pf::filter_rules(&rules, &self.interfaces)
        )
    }
}

/// No outside world: every fetch fails, so URL/GeoIP/… aliases are reported
/// as failed and the agent keeps their previous contents.
struct Offline(OfflineDns);
struct OfflineDns;

impl alias::dns::Resolver for OfflineDns {
    fn query(
        &self,
        name: &str,
        _: alias::dns::RecordType,
    ) -> Result<Vec<alias::dns::Record>, alias::dns::DnsError> {
        Err(alias::dns::DnsError::Other(format!("offline: {name}")))
    }
}

impl Sources for Offline {
    fn fetch(&self, url: &str, _: &alias::Auth) -> Result<String, alias::FetchError> {
        Err(alias::FetchError {
            url: url.into(),
            reason: "offline".into(),
        })
    }
    fn resolver(&self) -> &dyn alias::dns::Resolver {
        &self.0
    }
    fn geoip(&self, _: &str, _: IpFamily) -> Vec<IpNet> {
        Vec::new()
    }
    fn asn(&self, _: u32) -> Vec<IpNet> {
        Vec::new()
    }
    fn neighbours(&self) -> Vec<(String, IpAddr)> {
        Vec::new()
    }
    fn interface_addrs(&self, _: &str) -> Vec<IfAddr> {
        Vec::new()
    }
    fn external(&self, _: &str) -> Vec<IpNet> {
        Vec::new()
    }
}

fn interfaces(doc: &Document, rt: &Runtime<'_>) -> InterfaceMap {
    let dhcp4: Vec<&str> = if doc.dhcpv4.enabled {
        doc.dhcpv4.interfaces.iter().map(|i| i.as_str()).collect()
    } else {
        Vec::new()
    };
    let mut map = InterfaceMap::new();
    for (id, i) in doc.interfaces.iter().filter(|(_, i)| i.enabled) {
        let name = id.as_str().to_owned();
        let mut addrs = Vec::new();
        let (v4, gw4) = match &i.ipv4 {
            Ipv4Config::None => (V4Mode::None, false),
            Ipv4Config::Dhcp { use_gateway, .. } => (V4Mode::Dhcp, *use_gateway),
            Ipv4Config::Static { address, gateway } => {
                addrs.push(IfAddr {
                    addr: IpAddr::V4(address.addr()),
                    prefix_len: address.prefix_len(),
                });
                (V4Mode::Static, gateway.is_some())
            }
        };
        let (v6, gw6) = match &i.ipv6 {
            Ipv6Config::None => (V6Mode::None, false),
            Ipv6Config::Dhcp6 { .. } => (V6Mode::Dhcp6, true),
            Ipv6Config::Slaac => (V6Mode::Slaac, true),
            Ipv6Config::Track { .. } => (V6Mode::Track6, false),
            Ipv6Config::Static { address, gateway } => {
                addrs.push(IfAddr {
                    addr: IpAddr::V6(address.addr()),
                    prefix_len: address.prefix_len(),
                });
                (V6Mode::Static, gateway.is_some())
            }
        };
        if let Some(learned) = rt.addrs.get(&name) {
            for a in learned {
                if !addrs.contains(a) {
                    addrs.push(*a);
                }
            }
        }
        let descr = match &i.description {
            Some(d) => d.as_str().to_owned(),
            None => name.to_uppercase(),
        };
        map.insert(
            name.clone(),
            Interface {
                device: i.device.as_str().to_owned(),
                descr,
                addrs,
                // a WAN role always has an upstream gateway, even before DHCP answers
                gateway_v4: gw4 || (i.role == InterfaceRole::Wan && v4 != V4Mode::None),
                gateway_v6: gw6,
                r#virtual: false,
                block_bogons: i.block_bogons,
                block_private: i.block_private,
                v4,
                v6,
                dhcp4_server: dhcp4.contains(&name.as_str()),
                dhcp6_server: false,
            },
        );
    }
    for s in doc.wireguard.servers.values().filter(|s| s.enabled) {
        let dev = format!("wg{}", s.instance);
        let tunnel: Vec<IfAddr> = s
            .tunnel_addresses
            .iter()
            .map(|n| IfAddr {
                addr: n.addr(),
                prefix_len: n.prefix_len(),
            })
            .collect();
        // an assigned WireGuard interface has the instance's tunnel addresses
        if let Some(i) = map.values_mut().find(|i| i.device == dev) {
            for a in tunnel {
                if !i.addrs.contains(&a) {
                    i.addrs.push(a);
                }
            }
            continue;
        }
        // unassigned instances still carry traffic on wg<N>
        map.insert(
            dev.clone(),
            Interface {
                device: dev.clone(),
                descr: s.name.as_str().to_owned(),
                addrs: s
                    .tunnel_addresses
                    .iter()
                    .map(|n| IfAddr {
                        addr: n.addr(),
                        prefix_len: n.prefix_len(),
                    })
                    .collect(),
                r#virtual: true,
                ..Interface::default()
            },
        );
    }
    map
}

/// `NetOrAlias` as the MVC models store it (`source_net`).
fn net_token(n: &NetOrAlias) -> String {
    match n {
        NetOrAlias::Any => "any".into(),
        NetOrAlias::This => "(self)".into(),
        NetOrAlias::InterfaceNet(i) => i.as_str().to_owned(),
        NetOrAlias::InterfaceAddr(i) => format!("{}ip", i.as_str()),
        NetOrAlias::Alias(a) => a.as_str().to_owned(),
        NetOrAlias::Net(n) if n.prefix_len() == n.max_prefix_len() => n.addr().to_string(),
        NetOrAlias::Net(n) => n.to_string(),
    }
}

fn port_token(p: &PortSpec) -> String {
    match p {
        PortSpec::Range(r) if r.is_single() => r.start().get().to_string(),
        PortSpec::Range(r) => format!("{}-{}", r.start().get(), r.end().get()),
        PortSpec::Alias(a) => a.as_str().to_owned(),
    }
}

fn proto_token(p: Protocol) -> Option<String> {
    Some(match p {
        Protocol::Any => return None,
        Protocol::Tcp => "TCP".into(),
        Protocol::Udp => "UDP".into(),
        Protocol::TcpUdp => "TCP/UDP".into(),
        Protocol::Icmp => "ICMP".into(),
        Protocol::Icmpv6 => "IPV6-ICMP".into(),
        Protocol::Other(n) => n.to_string(),
    })
}

fn family_token(f: SchemaFamily) -> &'static str {
    match f {
        SchemaFamily::Inet => "inet",
        SchemaFamily::Inet6 => "inet6",
        SchemaFamily::Inet46 => "inet46",
    }
}

/// `FilterRuleContainerField::serialize` for a typed rule, with its
/// `getPriority()`.
pub fn filter_conf(uuid: &str, r: &fw::FilterRule, doc: &Document) -> (u32, Conf) {
    let mut c = conf! {
        "label" => uuid,
        "interface" => r.interfaces.iter().map(|i| i.as_str()).collect::<Vec<_>>().join(","),
        "interfacenot" => r.interface_not,
        "direction" => match r.direction { Direction::In => "in", Direction::Out => "out", Direction::Any => "any" },
        "ipprotocol" => family_token(r.ip_protocol),
        "log" => r.log,
        "quick" => r.quick,
        "statetype" => match r.state_type {
            StateType::Keep => "keep",
            StateType::Sloppy => "sloppy",
            StateType::Modulate => "modulate",
            StateType::Synproxy => "synproxy",
            StateType::None => "none",
        },
    };
    if let Some(p) = proto_token(r.protocol) {
        c.set("protocol", p);
    }
    for (tag, ep) in [("from", &r.source), ("to", &r.destination)] {
        if !ep.net.is_any() || ep.port.is_some() {
            c.set(tag, net_token(&ep.net));
            if ep.not {
                c.set(&format!("{tag}_not"), true);
            }
            if let Some(p) = &ep.port {
                c.set(&format!("{tag}_port"), port_token(p));
            }
        }
    }
    c.set("disabled", !r.enabled);
    c.set(
        "descr",
        r.description
            .as_ref()
            .map(|d| d.as_str().to_owned())
            .unwrap_or_default(),
    );
    c.set(
        "type",
        match r.action {
            RuleAction::Pass => "pass",
            RuleAction::Block => "block",
            RuleAction::Reject => "reject",
        },
    );
    let floating = r.interfaces.len() != 1 || r.interface_not;
    if floating {
        c.set("floating", true);
    }
    let known = |i: &sensr_schema::fields::InterfaceId| doc.interfaces.get(i).is_some();
    let prio = if !r.interfaces.is_empty() && !r.interfaces.iter().any(known) {
        600_000
    } else if floating {
        200_000
    } else {
        400_000
    };
    (prio, c)
}

fn endpoint_conf(ep: &fw::Endpoint) -> Conf {
    let mut c = conf! {};
    if ep.net.is_any() {
        c.set("any", true);
    } else {
        c.set("network", net_token(&ep.net));
    }
    if ep.not {
        c.set("not", true);
    }
    if let Some(p) = &ep.port {
        c.set("port", port_token(p));
    }
    c
}

/// A typed port forward as the DNat model's node content, and the
/// reflection defaults that apply to it.
pub fn forward_conf(f: &sn::PortForward, global: &sn::Reflection) -> (Conf, ReflectionDefaults) {
    let mut c = conf! {
        "disabled" => !f.enabled,
        "nordr" => f.no_rdr,
        "interface" => f.interfaces.iter().map(|i| i.as_str()).collect::<Vec<_>>().join(","),
        "ipprotocol" => family_token(f.ip_protocol),
        "source" => endpoint_conf(&f.source),
        "destination" => endpoint_conf(&f.destination),
        "target" => net_token(&f.target),
        "log" => f.log,
        "descr" => f.description.as_ref().map(|d| d.as_str().to_owned()).unwrap_or_default(),
        "pass" => match f.filter { ForwardFilter::Pass => "pass", ForwardFilter::Rule(_) | ForwardFilter::None => "" },
    };
    if let Some(p) = proto_token(f.protocol) {
        c.set("protocol", p);
    }
    if let Some(p) = &f.target_port {
        c.set("local-port", port_token(p));
    }
    let defaults = match f.reflection {
        // the schema's per-rule choice decides the helper too
        Some(ReflectionMode::Enable) => {
            c.set("natreflection", "enable");
            c.set("enablenatreflectionhelper", true);
            ReflectionDefaults::default()
        }
        Some(ReflectionMode::Purenat) => {
            c.set("natreflection", "purenat");
            ReflectionDefaults::default()
        }
        Some(ReflectionMode::Disable) => {
            c.set("natreflection", "disable");
            ReflectionDefaults::default()
        }
        None => ReflectionDefaults {
            port_forwards: global.port_forwards,
            source_nat: global.source_nat,
        },
    };
    (c, defaults)
}

/// A typed outbound rule as the legacy `nat/outbound/rule` array.
pub fn snat_conf(r: &sn::SourceNatRule) -> Conf {
    let mut c = conf! {
        "disabled" => !r.enabled,
        "nonat" => r.no_nat,
        "interface" => r.interface.as_str(),
        "ipprotocol" => family_token(r.ip_protocol),
        "source" => endpoint_conf(&fw::Endpoint { port: None, ..r.source.clone() }),
        "destination" => endpoint_conf(&fw::Endpoint { port: None, ..r.destination.clone() }),
        "log" => r.log,
        "staticnatport" => r.static_port,
        "descr" => r.description.as_ref().map(|d| d.as_str().to_owned()).unwrap_or_default(),
    };
    if let Some(p) = proto_token(r.protocol) {
        c.set("protocol", p);
    }
    if let Some(p) = &r.source.port {
        c.set("sourceport", port_token(p));
    }
    if let Some(p) = &r.destination.port {
        c.set("dstport", port_token(p));
    }
    if let Some(t) = &r.target {
        c.set("target", net_token(t));
    }
    if let Some(p) = &r.target_port {
        let v: Value = if p.is_single() {
            p.start().get().to_string().into()
        } else {
            format!("{}-{}", p.start().get(), p.end().get()).into()
        };
        c.set("natport", v);
    }
    c
}

/// Compiles a document.
pub fn compile(doc: &Document, rt: &Runtime<'_>) -> Compiled {
    let ifs = interfaces(doc, rt);
    let defs: Vec<AliasDef> = doc.firewall.aliases.values().map(AliasDef::from).collect();
    let alias_index = alias::index(&defs);
    let offline = Offline(OfflineDns);
    let aliases = alias::resolve_all(&defs, rt.sources.unwrap_or(&offline));
    let ctx = Context {
        interfaces: &ifs,
        aliases: &alias_index,
    };

    let fs = &doc.firewall.settings;
    let settings = SystemSettings {
        ipv6_allowed: doc.system.ipv6_allow,
        log_default_pass: fs.log_default_pass,
        log_default_block: fs.log_default_block,
        anti_lockout: fs.anti_lockout,
        ssh: doc.system.ssh.enabled.then(|| doc.system.ssh.port.get()),
        kea4_interfaces: if doc.dhcpv4.enabled && doc.dhcpv4.firewall_rules {
            doc.dhcpv4
                .interfaces
                .iter()
                .map(|i| i.as_str().to_owned())
                .collect()
        } else {
            Vec::new()
        },
        ..SystemSettings::default()
    };

    let mut rs = Ruleset::default();
    system_rules::register(&mut rs, &settings, &ctx);
    for (uuid, r) in doc.firewall.rules_in_order() {
        let (prio, c) = filter_conf(&uuid.to_string(), r, doc);
        rs.register_filter(prio, &c, None, &ctx);
    }

    let mut nat_rules = NatRules::default();
    let mode = match doc.nat.outbound.mode {
        OutboundNatMode::Automatic => OutboundMode::Automatic,
        OutboundNatMode::Hybrid => OutboundMode::Hybrid,
        OutboundNatMode::Manual => OutboundMode::Manual,
        OutboundNatMode::Disabled => OutboundMode::Disabled,
    };
    if nat::manual_outbound_applies(mode) {
        let mut rules: Vec<_> = doc.nat.outbound.rules.values().collect();
        rules.sort_by_key(|r| r.sequence);
        for r in rules {
            nat_rules
                .snat
                .extend(nat::snat_rules(&snat_conf(r), 100, &ctx));
        }
    }
    nat::automatic_outbound(mode, false, &ctx, &mut nat_rules.snat);
    let lockout = system_rules::anti_lockout(&settings, &ctx);
    nat_rules
        .rdr
        .extend(nat::anti_lockout_nordr(lockout.as_ref(), &ctx));
    let mut fwds: Vec<_> = doc.nat.port_forwards.values().collect();
    fwds.sort_by_key(|f| f.sequence);
    for f in fwds {
        let (c, defaults) = forward_conf(f, &doc.nat.reflection);
        nat_rules
            .rdr
            .extend(nat::rdr_rules(&c, 600, defaults, &ctx));
    }
    nat_rules.sort();

    Compiled {
        interfaces: ifs,
        filter: rs.rules,
        nat: nat_rules,
        aliases,
        options: nft::Options {
            flowtable: fs.flow_offload,
            ..nft::Options::default()
        },
    }
}
