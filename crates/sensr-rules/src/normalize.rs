//! OPNsense internal rule arrays ([`Conf`]) → expanded typed [`FilterRule`]s.
//!
//! Behaviour follows upstream's `Rule::reader()`, `Rule::mapAddressInfo()`
//! and `FilterRule::parseFilterRules()`: multi-valued fields expand to their
//! cartesian product (from × to × interface × family), names map to
//! interfaces, aliases or literals, and anything unmappable disables the
//! rule with a debug note instead of failing the whole ruleset.

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::conf::{Conf, Value};
use crate::icmp::IcmpType;
use crate::ir::{
    Action, Addr, AliasClass, Direction, Endpoint, FilterRule, InterfaceMap, IpFamily, PortMatch,
    State, StateKind, TcpFlags,
};
use crate::proto::{ProtoMatch, Protocol};
use crate::services;

/// What an alias name refers to, for normalisation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AliasInfo {
    /// address or port alias
    pub class: AliasClass,
    /// alias has no content (port aliases without content are invalid)
    pub empty: bool,
}

/// Everything a rule may refer to by name.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    /// logical interfaces
    pub interfaces: &'a InterfaceMap,
    /// alias names
    pub aliases: &'a BTreeMap<String, AliasInfo>,
}

impl Context<'_> {
    fn is_port_alias(&self, name: &str) -> bool {
        self.aliases
            .get(name)
            .is_some_and(|a| a.class == AliasClass::Port && !a.empty)
    }

    fn is_address_alias(&self, name: &str) -> bool {
        self.aliases
            .get(name)
            .is_some_and(|a| a.class == AliasClass::Address)
    }

    fn has_device(&self, iface: &str) -> bool {
        self.interfaces
            .get(iface)
            .is_some_and(|i| !i.device.is_empty())
    }
}

/// Splits an upstream comma list; empty → one `None` slot.
fn split(conf: &Conf, key: &str) -> Vec<Option<String>> {
    match conf.text(key) {
        Some(s) if !s.is_empty() && s != "0" => s.split(',').map(|p| Some(p.to_owned())).collect(),
        _ => vec![None],
    }
}

/// `legacyMoveAddressFields`: GUI-style `source`/`destination` arrays to the
/// flat `from`/`to` keys.
pub(crate) fn move_address_fields(rule: &mut Conf) {
    let proto = rule
        .text("protocol")
        .unwrap_or_default()
        .to_ascii_lowercase();
    for (tag, target) in [("source", "from"), ("destination", "to")] {
        let Some(node) = rule.array(tag).cloned() else {
            continue;
        };
        if node.is_empty() {
            continue;
        }
        let value = if !node.is_empty_at("network") {
            node.get("network").cloned().unwrap_or(Value::Null)
        } else if !node.is_empty_at("address") {
            node.get("address").cloned().unwrap_or(Value::Null)
        } else {
            "any".into()
        };
        rule.set(target, value);
        rule.set(&format!("{target}_not"), !node.is_empty_at("not"));
        if matches!(proto.as_str(), "tcp" | "udp" | "tcp/udp") && !node.is_empty_at("port") {
            rule.set(
                &format!("{target}_port"),
                node.get("port").cloned().unwrap_or(Value::Null),
            );
        }
    }
}

fn parse_host_or_net(s: &str) -> Option<Addr> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(Addr::Host(ip));
    }
    let (a, len) = s.split_once('/')?;
    if len.is_empty() || !len.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let ip: IpAddr = a.parse().ok()?;
    let len: u8 = len.parse().ok()?;
    IpNet::new(ip, len).ok().map(Addr::Net)
}

/// One address token → IR, following `mapAddressInfo` precedence.
/// `filter` marks filter rules, whose IPv6 interface networks also match
/// link-local.
pub(crate) fn map_address(
    token: Option<&str>,
    fam: Option<IpFamily>,
    ctx: &Context<'_>,
    debug: &mut Vec<String>,
    tag: &str,
    filter: bool,
) -> Result<Addr, Addr> {
    let Some(t) = token.filter(|t| !t.is_empty()) else {
        return Ok(Addr::Any);
    };
    if let Some(name) = t.strip_prefix('<').and_then(|x| x.strip_suffix('>')) {
        return Ok(Addr::Table(name.to_owned()));
    }
    if let Some(inner) = t.strip_prefix('(').and_then(|x| x.strip_suffix(')')) {
        if inner == "self" {
            return Ok(Addr::SelfAddr);
        }
        return Ok(Addr::Device(inner.to_owned()));
    }
    match t {
        "any" => return Ok(Addr::Any),
        "(self)" => return Ok(Addr::SelfAddr),
        _ => {}
    }
    if ctx.is_address_alias(t) {
        return Ok(Addr::Alias(t.to_owned()));
    }
    if ctx.has_device(t) {
        return Ok(Addr::IfaceNet {
            iface: t.to_owned(),
            link_local: filter && fam == Some(IpFamily::V6),
        });
    }
    if let Some(base) = t.strip_suffix("ip") {
        let is_named = base == "wan"
            || base == "lan"
            || base
                .strip_prefix("opt")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if is_named && ctx.has_device(base) {
            return Ok(Addr::IfaceAddr(base.to_owned()));
        }
    }
    match parse_host_or_net(t) {
        Some(a) => Ok(a),
        None => {
            debug.push(format!("Unable to convert address, see {tag} for details"));
            Err(Addr::Invalid(t.to_owned()))
        }
    }
}

/// Port field → IR. `Ok(None)` is "any".
pub(crate) fn map_port(
    raw: &Value,
    ctx: &Context<'_>,
    debug: &mut Vec<String>,
) -> Result<Option<PortMatch>, ()> {
    let Some(text) = raw.as_text() else {
        return Ok(None);
    };
    let mut port = text.replace('-', ":");
    let has_lo_any = port.contains("any:");
    let has_hi_any = port.contains(":any");
    if has_lo_any ^ has_hi_any {
        port = port.replace("any", if has_hi_any { "65535" } else { "1" });
    }
    if port == "any" || port.is_empty() {
        return Ok(None);
    }
    // PHP empty("0"): upstream leaves port 0 untouched, pf matches port 0
    if port == "0" {
        return Ok(Some(PortMatch::Single(0)));
    }
    if ctx.is_port_alias(&port) {
        return Ok(Some(PortMatch::Alias(port)));
    }
    if let Some(p) = parse_port_spec(&port) {
        return Ok(Some(p));
    }
    match services::port_of(&text) {
        Some(p) => Ok(Some(PortMatch::Single(p))),
        None => {
            debug.push(format!("Unable to map port {port}, config error?"));
            Err(())
        }
    }
}

/// `Util::isPort`: `n` or `lo:hi` with `lo < hi`, names allowed per part.
fn parse_port_spec(s: &str) -> Option<PortMatch> {
    let part = |p: &str| -> Option<u16> {
        if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) {
            p.parse::<u16>().ok().filter(|n| *n > 0)
        } else {
            services::port_of(p)
        }
    };
    match s.split(':').collect::<Vec<_>>()[..] {
        [one] => part(one).map(PortMatch::Single),
        [lo, hi] => {
            let (lo, hi) = (part(lo)?, part(hi)?);
            (lo < hi).then_some(PortMatch::Range(lo, hi))
        }
        _ => None,
    }
}

fn parse_flags(rule: &Conf) -> Option<TcpFlags> {
    if !rule.is_empty_at("tcpflags_any") {
        return Some(TcpFlags::Any);
    }
    if rule.is_empty_at("tcpflags2") {
        return None;
    }
    let letters = |key: &str| -> String {
        rule.text(key)
            .unwrap_or_default()
            .to_ascii_uppercase()
            .split(',')
            .filter_map(|f| f.chars().next())
            // CWR is the only flag whose letter is not its initial
            .map(|c| if c == 'C' { 'W' } else { c })
            .collect()
    };
    Some(TcpFlags::Test {
        set: letters("tcpflags1"),
        mask: letters("tcpflags2"),
    })
}

fn parse_state(rule: &Conf) -> Option<State> {
    let st = rule.text("statetype").filter(|s| !s.is_empty())?;
    let kind = match st.as_str() {
        "none" => StateKind::None,
        "sloppy state" | "sloppy" => StateKind::Sloppy,
        other => match other.split(' ').next().unwrap_or("keep") {
            "modulate" => StateKind::Modulate,
            "synproxy" => StateKind::Synproxy,
            _ => StateKind::Keep,
        },
    };
    let mut options = Vec::new();
    if kind != StateKind::None {
        if !rule.is_empty_at("nopfsync") {
            options.push("no-sync".to_owned());
        }
        for tag in ["max", "max-src-nodes", "max-src-conn", "max-src-states"] {
            if let Some(v) = rule.text(tag).filter(|v| !v.is_empty() && v != "0") {
                options.push(format!("{tag} {v}"));
            }
        }
        if let Some(v) = rule
            .text("statetimeout")
            .filter(|v| !v.is_empty() && v != "0")
        {
            options.push(format!("tcp.established {v}"));
        }
        for (tag, kw) in [
            ("udp-first", "udp.first"),
            ("udp-multiple", "udp.multiple"),
            ("udp-single", "udp.single"),
        ] {
            if let Some(v) = rule.text(tag).filter(|v| !v.is_empty() && v != "0") {
                options.push(format!("{kw} {v}"));
            }
        }
    }
    Some(State { kind, options })
}

fn parse_icmp_list(s: &str, fam: IpFamily, debug: &mut Vec<String>) -> Result<Vec<IcmpType>, ()> {
    let mut out = Vec::new();
    for tok in s.split(',').filter(|t| !t.is_empty()) {
        match IcmpType::parse(tok, fam) {
            Ok(t) => out.push(t),
            Err(e) => {
                debug.push(e.to_string());
                return Err(());
            }
        }
    }
    Ok(out)
}

/// The cartesian product upstream's `reader()` walks: from × to ×
/// interface × family, in that nesting order.
pub(crate) type Expansion = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<IpFamily>,
);

/// Expansions of an (address-moved) rule array.
pub(crate) fn expansions(base: &Conf) -> Vec<Expansion> {
    let interfaces = split(base, "interface");
    let froms = split(base, "from");
    let tos = split(base, "to");
    let families: Vec<Option<IpFamily>> = match base.text("ipprotocol").as_deref() {
        Some("inet46") => vec![Some(IpFamily::V4), Some(IpFamily::V6)],
        Some("inet") => vec![Some(IpFamily::V4)],
        Some("inet6") => vec![Some(IpFamily::V6)],
        _ => vec![None],
    };
    let mut out = Vec::new();
    for from in &froms {
        for to in &tos {
            for iface in &interfaces {
                for fam in &families {
                    out.push((from.clone(), to.clone(), iface.clone(), *fam));
                }
            }
        }
    }
    out
}

/// `protocol` → IR; ICMP in an IPv6 rule is ICMPv6.
pub(crate) fn parse_proto(rule: &Conf, fam: Option<IpFamily>) -> Result<ProtoMatch, String> {
    let Some(p) = rule
        .text("protocol")
        .map(|p| p.to_ascii_lowercase())
        .filter(|p| !p.is_empty() && p != "any")
    else {
        return Ok(ProtoMatch::Any);
    };
    if p == "tcp/udp" {
        return Ok(ProtoMatch::TcpUdp);
    }
    let mut pr = p.parse::<Protocol>().map_err(|e| e.to_string())?;
    if fam == Some(IpFamily::V6) && pr == Protocol::ICMP {
        pr = Protocol::ICMP6;
    }
    Ok(ProtoMatch::One(pr))
}

/// Normalises one rule array registered at `priority` (labels are assigned by
/// the caller, see [`crate::ruleset`]).
pub fn filter_rule(conf: &Conf, priority: u32, ctx: &Context<'_>) -> Vec<FilterRule> {
    let mut base = conf.clone();
    move_address_fields(&mut base);
    expansions(&base)
        .into_iter()
        .map(|(from, to, iface, fam)| {
            expand_one(
                &base,
                priority,
                ctx,
                from.as_deref(),
                to.as_deref(),
                iface.as_deref(),
                fam,
            )
        })
        .collect()
}

fn expand_one(
    rule: &Conf,
    priority: u32,
    ctx: &Context<'_>,
    from: Option<&str>,
    to: Option<&str>,
    iface: Option<&str>,
    fam: Option<IpFamily>,
) -> FilterRule {
    let mut debug = Vec::new();
    let mut enabled = rule.is_empty_at("disabled");

    let mut endpoint = |tok: Option<&str>, tag: &str, debug: &mut Vec<String>| -> Endpoint {
        let addr = match map_address(tok, fam, ctx, debug, tag, true) {
            Ok(a) => a,
            Err(a) => {
                enabled = false;
                a
            }
        };
        let negate = addr != Addr::Any && !rule.is_empty_at(&format!("{tag}_not"));
        let port = match rule.get(&format!("{tag}_port")) {
            Some(v) if !matches!(v, Value::Null) => match map_port(v, ctx, debug) {
                Ok(p) => p,
                Err(()) => {
                    enabled = false;
                    None
                }
            },
            _ => None,
        };
        Endpoint { addr, negate, port }
    };
    let src = endpoint(from, "from", &mut debug);
    let dst = endpoint(to, "to", &mut debug);

    if let Some(i) = iface
        && !ctx.has_device(i)
    {
        debug.push(format!("Interface {i} not found"));
        enabled = false;
    }

    let action = match rule.text("type").as_deref() {
        None | Some("") | Some("pass") => Action::Pass,
        Some("block") => Action::Block,
        Some("reject") => Action::Reject,
        Some(other) => {
            debug.push(format!("Unsupported rule type {other}"));
            enabled = false;
            Action::Block
        }
    };
    let direction = match rule.text("direction").as_deref() {
        None | Some("") | Some("in") => Direction::In,
        Some("out") => Direction::Out,
        Some("any") => Direction::Any,
        Some(other) => {
            debug.push(format!("Unsupported direction {other}"));
            enabled = false;
            Direction::In
        }
    };
    let quick = match rule.get("quick") {
        Some(v) => !v.is_empty(),
        None => !rule.isset("floating"),
    };

    let proto_text = rule
        .text("protocol")
        .map(|p| p.to_ascii_lowercase())
        .filter(|p| !p.is_empty() && p != "any");
    let proto = match parse_proto(rule, fam) {
        Ok(p) => p,
        Err(e) => {
            debug.push(e);
            enabled = false;
            ProtoMatch::Any
        }
    };

    // ICMP types: the GUI fields apply only to the matching family; internal
    // rules may set the pf-level keys directly.
    let is_icmp = matches!(proto_text.as_deref(), Some("icmp" | "ipv6-icmp"));
    let mut icmp_src = rule.text("icmp-type").filter(|s| !s.is_empty());
    let mut icmp6_src = rule.text("icmp6-type").filter(|s| !s.is_empty());
    if is_icmp {
        match fam {
            Some(IpFamily::V4) => {
                if let Some(t) = rule.text("icmptype").filter(|s| !s.is_empty()) {
                    icmp_src = Some(t);
                }
            }
            Some(IpFamily::V6) => {
                if let Some(t) = rule.text("icmp6type").filter(|s| !s.is_empty()) {
                    icmp6_src = Some(t);
                }
            }
            None => {}
        }
    }
    let mut icmp_types = Vec::new();
    if let Some(s) = icmp_src {
        match parse_icmp_list(&s, IpFamily::V4, &mut debug) {
            Ok(v) => icmp_types = v,
            Err(()) => enabled = false,
        }
    }
    let mut icmp6_types = Vec::new();
    if let Some(s) = icmp6_src {
        match parse_icmp_list(&s, IpFamily::V6, &mut debug) {
            Ok(v) => icmp6_types = v,
            Err(()) => enabled = false,
        }
    }

    let tcp_flags = (proto == ProtoMatch::One(Protocol::TCP))
        .then(|| parse_flags(rule))
        .flatten();
    let state = (action == Action::Pass)
        .then(|| parse_state(rule))
        .flatten();
    let gateway = (action == Action::Pass)
        .then(|| rule.text("gateway").filter(|g| !g.is_empty()))
        .flatten();
    if action != Action::Pass && !rule.is_empty_at("gateway") {
        debug.push("Gateway not allowed for non-pass rules".into());
    }
    let set_prio = rule.text("set-prio").filter(|s| !s.is_empty()).map(|p| {
        match rule.text("set-prio-low").filter(|s| !s.is_empty()) {
            Some(low) => format!("({p}, {low})"),
            None => p,
        }
    });

    FilterRule {
        priority,
        label: rule.text("label").unwrap_or_default(),
        descr: rule.text("descr").unwrap_or_default(),
        reference: rule.text("#ref").filter(|s| !s.is_empty()),
        enabled,
        debug,
        action,
        direction,
        quick,
        log: !rule.is_empty_at("log"),
        interface: iface.map(str::to_owned),
        interface_not: !rule.is_empty_at("interfacenot"),
        family: fam,
        proto,
        src,
        dst,
        icmp_types,
        icmp6_types,
        tcp_flags,
        state,
        allow_opts: !rule.is_empty_at("allowopts"),
        gateway,
        tag: rule.text("tag").filter(|s| !s.is_empty()),
        tagged: rule.text("tagged").filter(|s| !s.is_empty()),
        set_prio,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conf;
    use crate::ir::{IfAddr, Interface};

    fn ctx_fixture() -> (InterfaceMap, BTreeMap<String, AliasInfo>) {
        let mut ifs = InterfaceMap::new();
        ifs.insert(
            "lan".into(),
            Interface {
                device: "eth1".into(),
                descr: "LAN".into(),
                addrs: vec![IfAddr {
                    addr: "192.168.1.1".parse().unwrap(),
                    prefix_len: 24,
                }],
                ..Default::default()
            },
        );
        let mut al = BTreeMap::new();
        al.insert(
            "web".into(),
            AliasInfo {
                class: AliasClass::Port,
                empty: false,
            },
        );
        al.insert(
            "admins".into(),
            AliasInfo {
                class: AliasClass::Address,
                empty: false,
            },
        );
        (ifs, al)
    }

    #[test]
    fn cartesian_expansion_order() {
        let (ifs, al) = ctx_fixture();
        let ctx = Context {
            interfaces: &ifs,
            aliases: &al,
        };
        let r =
            conf! { "from" => "10.0.0.1,10.0.0.2", "to" => "lan,lanip", "ipprotocol" => "inet46" };
        let out = filter_rule(&r, 1, &ctx);
        assert_eq!(out.len(), 8);
        assert_eq!(out[0].src.addr, Addr::Host("10.0.0.1".parse().unwrap()));
        assert_eq!(
            out[1].dst.addr,
            Addr::IfaceNet {
                iface: "lan".into(),
                link_local: true
            }
        );
        assert_eq!(out[2].dst.addr, Addr::IfaceAddr("lan".into()));
        assert_eq!(out[7].family, Some(IpFamily::V6));
    }

    #[test]
    fn unknown_things_disable_with_debug() {
        let (ifs, al) = ctx_fixture();
        let ctx = Context {
            interfaces: &ifs,
            aliases: &al,
        };
        let r = conf! { "interface" => "opt9", "from" => "nonsense", "protocol" => "tcp", "to_port" => "nope" };
        let [rule] = &filter_rule(&r, 1, &ctx)[..] else {
            panic!()
        };
        assert!(!rule.enabled);
        assert_eq!(
            rule.debug,
            [
                "Unable to convert address, see from for details",
                "Unable to map port nope, config error?",
                "Interface opt9 not found"
            ]
        );
    }

    #[test]
    fn ports_aliases_and_any_bounds() {
        let (ifs, al) = ctx_fixture();
        let ctx = Context {
            interfaces: &ifs,
            aliases: &al,
        };
        let cases = [
            ("80", Some(PortMatch::Single(80))),
            ("80-90", Some(PortMatch::Range(80, 90))),
            ("80:any", Some(PortMatch::Range(80, 65535))),
            ("any-80", Some(PortMatch::Range(1, 80))),
            ("any", None),
            ("web", Some(PortMatch::Alias("web".into()))),
            ("https", Some(PortMatch::Single(443))),
        ];
        for (input, want) in cases {
            let r = conf! { "protocol" => "tcp", "to_port" => input };
            let [rule] = &filter_rule(&r, 1, &ctx)[..] else {
                panic!()
            };
            assert_eq!(rule.dst.port, want, "{input}");
            assert!(rule.enabled, "{input}");
        }
    }

    #[test]
    fn gui_source_destination_arrays() {
        let (ifs, al) = ctx_fixture();
        let ctx = Context {
            interfaces: &ifs,
            aliases: &al,
        };
        let r = conf! {
            "protocol" => "TCP",
            "source" => conf!{ "address" => "admins", "not" => "1" },
            "destination" => conf!{ "network" => "lanip", "port" => "443" },
        };
        let [rule] = &filter_rule(&r, 1, &ctx)[..] else {
            panic!()
        };
        assert_eq!(rule.src.addr, Addr::Alias("admins".into()));
        assert!(rule.src.negate);
        assert_eq!(rule.dst.addr, Addr::IfaceAddr("lan".into()));
        assert_eq!(rule.dst.port, Some(PortMatch::Single(443)));
        assert_eq!(rule.proto, ProtoMatch::One(Protocol::TCP));
    }

    #[test]
    fn icmp_in_v6_becomes_icmp6() {
        let (ifs, al) = ctx_fixture();
        let ctx = Context {
            interfaces: &ifs,
            aliases: &al,
        };
        let r = conf! { "protocol" => "icmp", "ipprotocol" => "inet46", "icmptype" => "echoreq", "icmp6type" => "135" };
        let out = filter_rule(&r, 1, &ctx);
        assert_eq!(out[0].proto, ProtoMatch::One(Protocol::ICMP));
        assert_eq!(out[0].icmp_types, [IcmpType::Name("echoreq".into())]);
        assert!(out[0].icmp6_types.is_empty());
        assert_eq!(out[1].proto, ProtoMatch::One(Protocol::ICMP6));
        assert_eq!(out[1].icmp6_types, [IcmpType::Number(135)]);
    }
}
