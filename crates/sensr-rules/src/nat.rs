//! Outbound NAT, port forwards and 1:1 NAT (`SNatRule`, `ForwardRule`,
//! `DNatRule`, `filter_auto_source_nat`, `filter_auto_destination_nat`).
//!
//! The same two-layer approach as filter rules: upstream's rule arrays are
//! normalised into typed [`SnatRule`] / [`RdrRule`]s (reflection copies
//! included), which render to pf text for the oracle and lower to the
//! `nat_pre` / `nat_post` chains of the nft table.

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::conf;
use crate::conf::{Conf, Value};
use crate::ir::{Addr, Endpoint, InterfaceMap, IpFamily, PortMatch};
use crate::normalize::{self, Context};
use crate::proto::ProtoMatch;

/// Outbound NAT mode (`nat/outbound/mode`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutboundMode {
    /// automatic rules only
    #[default]
    Automatic,
    /// manual rules first, then automatic ones
    Hybrid,
    /// manual rules only (`advanced`)
    Manual,
    /// no outbound NAT
    Disabled,
}

impl OutboundMode {
    fn manual_rules(self) -> bool {
        matches!(self, OutboundMode::Hybrid | OutboundMode::Manual)
    }

    fn automatic_rules(self) -> bool {
        matches!(self, OutboundMode::Automatic | OutboundMode::Hybrid)
    }
}

/// Where outbound NAT translates to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnatTarget {
    /// no translation (`no nat`)
    NoNat,
    /// the first address of an interface (`(em0:0)`): masquerade
    Interface(String),
    /// one address
    Host(IpAddr),
    /// a pool network
    Net(IpNet),
    /// a pool alias (round-robin)
    Alias(String),
}

/// One expanded outbound NAT rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnatRule {
    /// priority band
    pub priority: u32,
    /// description
    pub descr: String,
    /// rendered at all
    pub enabled: bool,
    /// normalisation notes
    pub debug: Vec<String>,
    /// log translations
    pub log: bool,
    /// egress interface
    pub interface: Option<String>,
    /// family
    pub family: Option<IpFamily>,
    /// protocol
    pub proto: ProtoMatch,
    /// source (port in `src.port`)
    pub src: Endpoint,
    /// destination (port in `dst.port`)
    pub dst: Endpoint,
    /// translation
    pub target: SnatTarget,
    /// explicit translation port(s)
    pub target_port: Option<PortMatch>,
    /// keep the source port (`static-port`)
    pub static_port: bool,
}

/// One expanded port forward (pf `rdr`), possibly a reflection copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RdrRule {
    /// priority band
    pub priority: u32,
    /// description
    pub descr: String,
    /// rendered at all
    pub enabled: bool,
    /// normalisation notes
    pub debug: Vec<String>,
    /// `no rdr`: exempt matching traffic from later redirects
    pub nordr: bool,
    /// `rdr pass`: translated traffic skips the filter
    pub pass: bool,
    /// log
    pub log: bool,
    /// ingress interface
    pub interface: Option<String>,
    /// family
    pub family: Option<IpFamily>,
    /// protocol
    pub proto: ProtoMatch,
    /// source
    pub src: Endpoint,
    /// destination
    pub dst: Endpoint,
    /// redirect target
    pub target: Option<Addr>,
    /// redirect port(s)
    pub local_port: Option<PortMatch>,
    /// add hairpin source NAT on `interface` (`enablenatreflectionhelper`)
    pub helper: bool,
    /// interface whose rule this is a reflection copy of
    pub reflected_from: Option<String>,
}

/// NAT settings that act as defaults (`Plugin::$systemDefaults['forward']`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReflectionDefaults {
    /// reflect port forwards (`reflection_dnat`)
    pub port_forwards: bool,
    /// hairpin source NAT for reflected forwards (`reflection_snat`)
    pub source_nat: bool,
}

/// 1:1 NAT flavour (`type`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StaticKind {
    /// pf `binat`: both directions, prefix-preserving
    #[default]
    Binat,
    /// pf `nat`: outbound only
    Nat,
}

/// Which of the lines a 1:1 rule expands to (`DNatRule` rule types).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaticPart {
    /// the mapping itself (`binat` / `nat`)
    Map(StaticKind),
    /// reflection: redirect internal clients that use the external address
    /// (`rdr … bitmask` on an interface without a gateway)
    Reflection,
    /// reflection helper: source NAT so the internal host answers through
    /// the firewall
    Helper,
}

/// One expanded 1:1 NAT line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticRule {
    /// priority band
    pub priority: u32,
    /// description
    pub descr: String,
    /// rendered at all
    pub enabled: bool,
    /// normalisation notes
    pub debug: Vec<String>,
    /// log translations
    pub log: bool,
    /// what this line does
    pub part: StaticPart,
    /// interface the line applies on
    pub interface: Option<String>,
    /// family, explicit on helper lines only (as upstream prints it)
    pub family: Option<IpFamily>,
    /// internal side (`from` of the mapping)
    pub internal: Endpoint,
    /// peers (`to` of the mapping)
    pub peer: Endpoint,
    /// external address or network, prefix already taken from `internal`
    /// when it was a bare host
    pub external: Addr,
}

impl StaticRule {
    /// The family the line works in: explicit, or that of a literal address.
    pub fn effective_family(&self) -> Option<IpFamily> {
        self.family.or_else(|| {
            [&self.external, &self.internal.addr, &self.peer.addr]
                .into_iter()
                .find_map(|a| match a {
                    Addr::Host(ip) => Some(IpFamily::of(ip)),
                    Addr::Net(n) => Some(IpFamily::of(&n.addr())),
                    _ => None,
                })
        })
    }
}

/// All NAT rules of a ruleset.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NatRules {
    /// port forwards in priority order
    pub rdr: Vec<RdrRule>,
    /// outbound rules in priority order
    pub snat: Vec<SnatRule>,
    /// 1:1 NAT lines in priority order
    pub static_nat: Vec<StaticRule>,
}

impl NatRules {
    /// Sorts the lists by priority (stable), as `Plugin::outputNatRules`.
    pub fn sort(&mut self) {
        self.rdr.sort_by_key(|r| r.priority);
        self.snat.sort_by_key(|r| r.priority);
        self.static_nat.sort_by_key(|r| r.priority);
    }
}

/// 1:1 reflection settings that act as defaults
/// (`Plugin::$systemDefaults['nat']`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticDefaults {
    /// reflect 1:1 rules (`reflection_binat`)
    pub reflection: bool,
    /// helper source NAT (`reflection_snat`)
    pub helper: bool,
}

/// `DNatRule::parseNatRules` for one registered 1:1 rule array: the
/// mapping, its reflection redirects, then its helper source NAT lines.
pub fn static_rules(
    conf: &Conf,
    priority: u32,
    defaults: StaticDefaults,
    ctx: &Context<'_>,
) -> Vec<StaticRule> {
    let mut base = conf.clone();
    // registerStaticNatRule: array_merge(defaults, conf); the model omits
    // empty values, so an empty key takes the default
    if defaults.reflection && base.is_empty_at("natreflection") {
        base.set("natreflection", "enable");
    }
    if defaults.helper && base.is_empty_at("enablenatreflectionhelper") {
        base.set("enablenatreflectionhelper", true);
    }
    normalize::move_address_fields(&mut base);
    let kind = match base.text("type").as_deref() {
        Some("nat") => StaticKind::Nat,
        _ => StaticKind::Binat,
    };
    let mut out = Vec::new();
    for (from, to, iface, fam) in normalize::expansions(&base) {
        let mut notes = Notes {
            debug: Vec::new(),
            enabled: base.is_empty_at("disabled"),
        };
        let internal = endpoint(&base, ("from", ""), fam, from.as_deref(), ctx, &mut notes);
        let peer = endpoint(&base, ("to", ""), fam, to.as_deref(), ctx, &mut notes);
        let Notes {
            mut debug,
            mut enabled,
        } = notes;
        if let Some(i) = &iface
            && !ctx.interfaces.get(i).is_some_and(|x| !x.device.is_empty())
        {
            debug.push(format!("Interface {i} not found"));
            enabled = false;
        }
        let external = match base.text("external").filter(|t| !t.is_empty()) {
            None => Addr::Any,
            Some(t) if ctx.aliases.contains_key(&t) => Addr::Alias(t),
            Some(t) => match t.parse::<IpAddr>() {
                // a bare host takes the internal network's prefix length
                Ok(ip) => match &internal.addr {
                    Addr::Net(n) => IpNet::new(ip, n.prefix_len())
                        .map(Addr::Net)
                        .unwrap_or(Addr::Host(ip)),
                    _ => Addr::Host(ip),
                },
                Err(_) => match t.parse::<IpNet>() {
                    Ok(n) => Addr::Net(n),
                    Err(_) => {
                        debug.push(format!("Invalid address {t}"));
                        enabled = false;
                        Addr::Invalid(t)
                    }
                },
            },
        };
        let map = StaticRule {
            priority,
            descr: base.text("descr").unwrap_or_default(),
            enabled,
            debug,
            log: !base.is_empty_at("log"),
            part: StaticPart::Map(kind),
            interface: iface.clone(),
            family: fam,
            internal,
            peer,
            external,
        };
        let v4 = match map.effective_family() {
            Some(f) => f == IpFamily::V4,
            None => false,
        };
        let has = |name: &str| {
            ctx.interfaces
                .get(name)
                .is_some_and(|i| i.has_family(if v4 { IpFamily::V4 } else { IpFamily::V6 }))
        };
        // reflectionInterfaces(): no gateway, not the rule's own, not loopback
        let others: Vec<String> = ctx
            .interfaces
            .iter()
            .filter(|(name, i)| {
                !i.gateway_v4
                    && !i.gateway_v6
                    && iface.as_deref() != Some(name.as_str())
                    && name.as_str() != "loopback"
            })
            .map(|(n, _)| n.clone())
            .collect();
        let live = map.enabled;
        let reflect = base.text("natreflection").as_deref() == Some("enable");
        let helper = !base.is_empty_at("enablenatreflectionhelper");
        out.push(map.clone());
        if live && reflect {
            for name in others.iter().filter(|n| has(n)) {
                out.push(StaticRule {
                    part: StaticPart::Reflection,
                    interface: Some(name.clone()),
                    debug: Vec::new(),
                    ..map.clone()
                });
            }
        }
        if live && helper {
            for name in others.iter().chain(iface.iter()).filter(|n| has(n)) {
                out.push(StaticRule {
                    part: StaticPart::Helper,
                    interface: Some(name.clone()),
                    family: Some(if v4 { IpFamily::V4 } else { IpFamily::V6 }),
                    debug: Vec::new(),
                    ..map.clone()
                });
            }
        }
    }
    out
}

/// What normalising one expansion found wrong.
struct Notes {
    debug: Vec<String>,
    enabled: bool,
}

fn endpoint(
    rule: &Conf,
    (tag, port_key): (&str, &str),
    fam: Option<IpFamily>,
    tok: Option<&str>,
    ctx: &Context<'_>,
    n: &mut Notes,
) -> Endpoint {
    let addr = match normalize::map_address(tok, fam, ctx, &mut n.debug, tag, false) {
        Ok(a) => a,
        Err(a) => {
            n.enabled = false;
            a
        }
    };
    let negate = addr != Addr::Any && !rule.is_empty_at(&format!("{tag}_not"));
    let port = match rule.get(port_key) {
        Some(v) if !matches!(v, Value::Null) => match normalize::map_port(v, ctx, &mut n.debug) {
            Ok(p) => p,
            Err(()) => {
                n.enabled = false;
                None
            }
        },
        _ => None,
    };
    Endpoint { addr, negate, port }
}

fn proto_of(rule: &Conf, debug: &mut Vec<String>, enabled: &mut bool) -> ProtoMatch {
    match normalize::parse_proto(rule, None) {
        Ok(p) => p,
        Err(e) => {
            debug.push(e);
            *enabled = false;
            ProtoMatch::Any
        }
    }
}

/// `SNatRule::parseNatRules` for one registered rule array.
pub fn snat_rules(conf: &Conf, priority: u32, ctx: &Context<'_>) -> Vec<SnatRule> {
    let mut base = conf.clone();
    normalize::move_address_fields(&mut base);
    let mut out = Vec::new();
    for (from, to, iface, fam) in normalize::expansions(&base) {
        let mut notes = Notes {
            debug: Vec::new(),
            enabled: base.is_empty_at("disabled"),
        };
        let src = endpoint(
            &base,
            ("from", "sourceport"),
            fam,
            from.as_deref(),
            ctx,
            &mut notes,
        );
        let dst = endpoint(
            &base,
            ("to", "dstport"),
            fam,
            to.as_deref(),
            ctx,
            &mut notes,
        );
        let Notes {
            mut debug,
            mut enabled,
        } = notes;
        if let Some(i) = &iface
            && !ctx.interfaces.get(i).is_some_and(|x| !x.device.is_empty())
        {
            debug.push(format!("Interface {i} not found"));
            enabled = false;
        }
        let proto = proto_of(&base, &mut debug, &mut enabled);
        let nonat = !base.is_empty_at("nonat");
        let target = if nonat {
            SnatTarget::NoNat
        } else {
            match base.text("target").filter(|t| !t.is_empty()) {
                None => match &iface {
                    Some(i) if ctx.interfaces.contains_key(i) => SnatTarget::Interface(i.clone()),
                    _ => {
                        debug.push("SNAT / target missing".into());
                        enabled = false;
                        SnatTarget::NoNat
                    }
                },
                Some(t) if t == "other-subnet" => {
                    let ip = base.text("targetip").unwrap_or_default();
                    let len = base.text("targetip_subnet").unwrap_or_default();
                    match format!("{ip}/{len}").parse::<IpNet>() {
                        Ok(n) => SnatTarget::Net(n),
                        Err(_) => {
                            debug.push("SNAT / invalid target subnet".into());
                            enabled = false;
                            SnatTarget::NoNat
                        }
                    }
                }
                Some(t) if ctx.aliases.contains_key(&t) => {
                    let pool = base.text("poolopts").unwrap_or_default();
                    if !pool.is_empty() && !pool.starts_with("round-robin") {
                        debug.push("SNAT / pool type not round-robin".into());
                        enabled = false;
                    }
                    SnatTarget::Alias(t)
                }
                Some(t) => match t.strip_suffix("ip") {
                    Some(i) if ctx.interfaces.contains_key(i) => SnatTarget::Interface(i.into()),
                    _ => match t.parse::<IpAddr>() {
                        Ok(ip) => SnatTarget::Host(ip),
                        Err(_) => match t.parse::<IpNet>() {
                            Ok(n) => SnatTarget::Net(n),
                            Err(_) => {
                                debug.push("SNAT / target missing".into());
                                enabled = false;
                                SnatTarget::NoNat
                            }
                        },
                    },
                },
            }
        };
        let static_port = !base.is_empty_at("staticnatport");
        let target_port = if static_port || nonat {
            None
        } else {
            match base.get("natport") {
                Some(v) if !v.is_empty() => match normalize::map_port(v, ctx, &mut debug) {
                    Ok(p) => p,
                    Err(()) => {
                        enabled = false;
                        None
                    }
                },
                _ => None,
            }
        };
        out.push(SnatRule {
            priority,
            descr: base.text("descr").unwrap_or_default(),
            enabled,
            debug,
            log: !base.is_empty_at("log"),
            interface: iface,
            family: fam,
            proto,
            src,
            dst,
            target,
            target_port,
            static_port,
        });
    }
    out
}

/// `ForwardRule::parseRdrRules` for one registered rule array: the rule
/// itself, then its reflection copies.
pub fn rdr_rules(
    conf: &Conf,
    priority: u32,
    defaults: ReflectionDefaults,
    ctx: &Context<'_>,
) -> Vec<RdrRule> {
    let mut base = conf.clone();
    // registerDestinationNatRule: defaults fill empty keys only
    if defaults.port_forwards && base.is_empty_at("natreflection") {
        base.set("natreflection", "enable");
    }
    if defaults.source_nat && base.is_empty_at("enablenatreflectionhelper") {
        base.set("enablenatreflectionhelper", true);
    }
    normalize::move_address_fields(&mut base);
    let mut out = Vec::new();
    for (from, to, iface, fam) in normalize::expansions(&base) {
        let mut notes = Notes {
            debug: Vec::new(),
            enabled: base.is_empty_at("disabled"),
        };
        let src = endpoint(
            &base,
            ("from", "from_port"),
            fam,
            from.as_deref(),
            ctx,
            &mut notes,
        );
        let dst = endpoint(
            &base,
            ("to", "to_port"),
            fam,
            to.as_deref(),
            ctx,
            &mut notes,
        );
        let Notes {
            mut debug,
            mut enabled,
        } = notes;
        if let Some(i) = &iface
            && !ctx.interfaces.get(i).is_some_and(|x| !x.device.is_empty())
        {
            debug.push(format!("Interface {i} not found"));
            enabled = false;
        }
        let proto = proto_of(&base, &mut debug, &mut enabled);
        let nordr = !base.is_empty_at("nordr");
        let pass =
            !nordr && !base.is_empty_at("pass") && base.text("pass").as_deref() != Some("rule");
        let target = match base.text("target").filter(|t| !t.is_empty()) {
            None => {
                if !nordr {
                    debug.push("Missing target".into());
                    enabled = false;
                }
                None
            }
            Some(t) => {
                match normalize::map_address(Some(&t), fam, ctx, &mut debug, "target", false) {
                    Ok(a @ (Addr::Host(_) | Addr::Net(_) | Addr::Alias(_))) => Some(a),
                    _ => {
                        debug.push("Invalid target".into());
                        enabled = false;
                        None
                    }
                }
            }
        };
        let mut local_port = None;
        if proto.has_ports()
            && let Some(lp) = base.get("local-port").filter(|v| !v.is_empty())
        {
            match normalize::map_port(lp, ctx, &mut debug) {
                Ok(Some(PortMatch::Alias(a))) => {
                    if dst.port != Some(PortMatch::Alias(a.clone())) {
                        local_port = Some(PortMatch::Alias(a));
                    }
                }
                Ok(Some(PortMatch::Single(p))) => {
                    local_port = Some(match dst.port {
                        Some(PortMatch::Range(lo, hi)) => PortMatch::Range(
                            p,
                            (u32::from(p) + u32::from(hi - lo)).min(65535) as u16,
                        ),
                        _ => PortMatch::Single(p),
                    });
                }
                Ok(other) => local_port = other,
                Err(()) => enabled = false,
            }
        }
        let rule = RdrRule {
            priority,
            descr: base.text("descr").unwrap_or_default(),
            enabled,
            debug,
            nordr,
            pass,
            log: !base.is_empty_at("log"),
            interface: iface.clone(),
            family: fam,
            proto,
            src,
            dst,
            target,
            local_port,
            helper: false,
            reflected_from: None,
        };

        let mut interfaces = vec![iface.clone()];
        let reflect = matches!(
            base.text("natreflection").as_deref(),
            Some("purenat" | "enable")
        );
        if rule.enabled && !rule.nordr && reflect {
            let v4 = rule.family != Some(IpFamily::V6) && is_v4(&rule);
            for (name, i) in ctx.interfaces {
                let own = iface.as_deref() == Some(name.as_str());
                let has = if v4 {
                    i.has_family(IpFamily::V4)
                } else {
                    i.has_family(IpFamily::V6)
                };
                if !i.gateway_v4 && !i.gateway_v6 && !own && name != "loopback" && has {
                    interfaces.push(Some(name.clone()));
                }
            }
        }
        let helper = rule.enabled
            && !rule.nordr
            && !base.is_empty_at("enablenatreflectionhelper")
            // upstream also wants an address on it right now; sensr's sets
            // follow addresses at run time, so the device is enough
            && iface
                .as_ref()
                .and_then(|i| ctx.interfaces.get(i))
                .is_some_and(|i| !i.device.is_empty());
        for (k, i) in interfaces.into_iter().enumerate() {
            let mut r = rule.clone();
            r.helper = helper;
            if k > 0 {
                r.reflected_from = iface.clone();
            }
            r.interface = i;
            out.push(r);
        }
    }
    out
}

/// `Rule::isIpV4` for rules without an explicit family.
fn is_v4(r: &RdrRule) -> bool {
    match r.family {
        Some(f) => f == IpFamily::V4,
        None => [
            &r.src.addr,
            &r.dst.addr,
            r.target.as_ref().unwrap_or(&Addr::Any),
        ]
        .iter()
        .any(|a| match a {
            Addr::Host(ip) => ip.is_ipv4(),
            Addr::Net(n) => n.addr().is_ipv4(),
            _ => false,
        }),
    }
}

/// `pf_get_default_nat_outbound_networks`: networks of interfaces without a
/// gateway, plus loopback.
pub fn default_outbound_networks(ifs: &InterfaceMap) -> Vec<String> {
    let mut v: Vec<String> = ifs
        .iter()
        .filter(|(_, i)| i.has_family(IpFamily::V4) && !i.gateway_v4)
        .map(|(n, _)| n.clone())
        .collect();
    v.push("127.0.0.0/8".into());
    v
}

/// Registers the automatic outbound rules (`filter_auto_source_nat`).
pub fn automatic_outbound(
    mode: OutboundMode,
    log: bool,
    ctx: &Context<'_>,
    out: &mut Vec<SnatRule>,
) {
    if !mode.automatic_rules() {
        return;
    }
    let networks = default_outbound_networks(ctx.interfaces);
    for (wan, i) in ctx.interfaces {
        // upstream skips OpenVPN devices that drop a router file instead
        if i.device.starts_with("ovpn") || !i.gateway_v4 {
            continue;
        }
        for dstport in [Some(500i64), None] {
            for net in &networks {
                let c = conf! {
                    "descr" => "Automatic outbound rule",
                    "destination" => conf! { "any" => true },
                    "dstport" => dstport.map_or(Value::Null, Value::Int),
                    "interface" => wan.as_str(),
                    "ipprotocol" => "inet",
                    "log" => log,
                    "staticnatport" => dstport.is_some(),
                    "source" => conf! { "network" => net.as_str() },
                };
                out.extend(snat_rules(&c, 200, ctx));
            }
        }
    }
}

/// Manual outbound rules apply only in hybrid and manual mode.
pub fn manual_outbound_applies(mode: OutboundMode) -> bool {
    mode.manual_rules()
}

/// `filter_auto_destination_nat`: no redirects for the anti-lockout ports
/// on the lockout interface's own address.
pub fn anti_lockout_nordr(
    lockout: Option<&(String, Vec<String>)>,
    ctx: &Context<'_>,
) -> Vec<RdrRule> {
    let Some((iface, ports)) = lockout else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for port in ports {
        let c = conf! {
            "descr" => "Anti-lockout; prevent redirects for protected ports to this interface address",
            "destination" => conf! { "network" => format!("{iface}ip"), "port" => port.as_str() },
            "interface" => iface.as_str(),
            "nordr" => true,
            "protocol" => "tcp",
            "#ref" => "ui/firewall/settings#settings-filter",
        };
        out.extend(rdr_rules(&c, 300, ReflectionDefaults::default(), ctx));
    }
    out
}

/// The automatic filter rule of a port forward whose filter association is
/// "rule" (`filter.lib.inc`: registered at priority 500000).
pub fn forward_filter_rule(conf: &Conf) -> Option<Conf> {
    if !conf.is_empty_at("disabled") || conf.text("pass").as_deref() != Some("rule") {
        return None;
    }
    let mut dst = conf! {};
    let target = conf.text("target").unwrap_or_default();
    if target.is_empty() {
        let net = conf
            .array("destination")
            .and_then(|d| d.text("network"))
            .unwrap_or_default();
        dst.set("network", net);
    } else {
        dst.set("network", target);
    }
    let dport = conf
        .array("destination")
        .and_then(|d| d.text("port"))
        .unwrap_or_default();
    let local = conf.text("local-port").unwrap_or_default();
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !dport.is_empty() && digits(&local) {
        let mut p = local.clone();
        if let Some((a, b)) = dport.split_once('-')
            && digits(a)
            && digits(b)
        {
            let (a, b, l): (u32, u32, u32) = (
                a.parse().unwrap_or(0),
                b.parse().unwrap_or(0),
                local.parse().unwrap_or(0),
            );
            p = format!("{local}-{}", (b.saturating_sub(a) + l).min(65535));
        }
        dst.set("port", p);
    } else if !local.is_empty() {
        dst.set("port", local);
    } else if !dport.is_empty() {
        dst.set("port", dport);
    }
    Some(conf! {
        "ipprotocol" => conf.get("ipprotocol").cloned().unwrap_or(Value::Null),
        "interface" => conf.get("interface").cloned().unwrap_or(Value::Null),
        "protocol" => conf.get("protocol").cloned().unwrap_or(Value::Null),
        "source" => conf.get("source").cloned().unwrap_or(Value::Null),
        "destination" => dst,
        "log" => conf.get("log").cloned().unwrap_or(Value::Null),
        "descr" => conf.get("descr").cloned().unwrap_or(Value::Null),
    })
}
