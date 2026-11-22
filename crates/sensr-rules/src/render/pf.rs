//! pf text renderer — the differential test oracle.
//!
//! sensr never loads pf. This renderer exists so the IR can be compared
//! byte-for-byte with what OPNsense writes to `/tmp/rules.debug` for the same
//! input, which proves normalisation understood the semantics before the nft
//! renderer translates them.

use std::fmt::Write as _;

use crate::ir::{Action, Addr, Direction, Endpoint, FilterRule, InterfaceMap, StateKind, TcpFlags};
use crate::proto::ProtoMatch;

/// Upstream's pf label limit.
const LABEL_MAX: usize = 63;

/// Renders one expanded rule as upstream's `ruleToText` would, including the
/// trailing newline and a preceding `#debug:` line when normalisation logged.
///
/// Host-mode rules (source `Addr::MacSet`) are nft-only: pf gets one comment
/// line naming the rule and no rule body.
pub fn filter_rule(rule: &FilterRule, ifs: &InterfaceMap, out: &mut String) {
    if matches!(rule.src.addr, Addr::MacSet(_)) {
        let _ = writeln!(
            out,
            "# host mode (nft-only): {}",
            rule.descr.replace(['\r', '\n'], "")
        );
        return;
    }
    if !rule.debug.is_empty() {
        let _ = writeln!(out, "#debug:{}", rule.debug.join("|"));
    }
    let mut parts: Vec<String> = Vec::with_capacity(16);
    let mut push = |s: String| {
        let t = s.trim();
        if !t.is_empty() {
            parts.push(t.to_owned());
        }
    };
    if !rule.enabled {
        push("#".into());
    }
    push(
        match rule.action {
            Action::Pass => "pass",
            Action::Block => "block",
            Action::Reject => "block return",
        }
        .into(),
    );
    push(
        match rule.direction {
            Direction::In => "in",
            Direction::Out => "out",
            Direction::Any => "",
        }
        .into(),
    );
    if rule.log {
        push("log".into());
    }
    if rule.quick {
        push("quick".into());
    }
    if let Some(i) = &rule.interface {
        let prefix = if rule.interface_not { "on  ! " } else { "on " };
        match ifs.get(i).filter(|x| !x.device.is_empty()) {
            Some(x) => push(format!("{prefix}{}", x.device)),
            None => push(format!("{prefix}##{i}##")),
        }
    }
    if let Some(f) = rule.family {
        push(f.pf().into());
    }
    match rule.proto {
        ProtoMatch::Any => {}
        ProtoMatch::TcpUdp => push("proto {tcp udp}".into()),
        ProtoMatch::One(p) => {
            let name = p.to_string();
            if name.contains('/') || name == "skip" {
                push(format!("proto \"{name}\""));
            } else {
                push(format!("proto {name}"));
            }
        }
    }
    endpoint("from", &rule.src, ifs, &mut push);
    endpoint("to", &rule.dst, ifs, &mut push);
    if !rule.icmp_types.is_empty() {
        let list: Vec<String> = rule
            .icmp_types
            .iter()
            .map(|t| {
                let s = t.to_string();
                if s == "skip" { "\"skip\"".into() } else { s }
            })
            .collect();
        push(format!("icmp-type {{{}}}", list.join(",")));
    }
    if !rule.icmp6_types.is_empty() {
        let list: Vec<String> = rule.icmp6_types.iter().map(ToString::to_string).collect();
        push(format!("icmp6-type {{{}}}", list.join(",")));
    }
    match &rule.tcp_flags {
        Some(TcpFlags::Any) => push("flags any".into()),
        Some(TcpFlags::Test { set, mask }) => push(format!("flags {set}/{mask}")),
        None => {}
    }
    if let Some(st) = &rule.state {
        let kw = match st.kind {
            StateKind::Keep | StateKind::Sloppy => "keep",
            StateKind::Modulate => "modulate",
            StateKind::Synproxy => "synproxy",
            StateKind::None => "no",
        };
        // upstream keeps the trailing blanks of the flag-like options
        let mut opts: Vec<String> = Vec::new();
        if st.kind == StateKind::Sloppy {
            opts.push("sloppy ".into());
        }
        opts.extend(st.options.iter().map(|o| {
            if o == "no-sync" {
                "no-sync ".to_owned()
            } else {
                o.clone()
            }
        }));
        if opts.is_empty() {
            push(format!("{kw} state"));
        } else {
            push(format!("{kw} state ( {} )", opts.join(" ")));
        }
    }
    if let Some(p) = &rule.set_prio {
        push(format!("set prio {p}"));
    }
    if let Some(t) = &rule.tag {
        push(format!("tag {t}"));
    }
    if let Some(t) = &rule.tagged {
        push(format!("tagged {t}"));
    }
    if rule.allow_opts {
        push("allow-opts".into());
    }
    if !rule.label.is_empty() {
        let label: String = rule.label.chars().take(LABEL_MAX).collect();
        push(format!("label \"{label}\""));
    }
    if !rule.descr.is_empty() {
        push(format!("# {}", rule.descr.replace(['\r', '\n'], "")));
    }
    out.push_str(&parts.join(" "));
    out.push('\n');
}

/// `from {…} port {…}` / `to …`; aliases are never wrapped in braces.
fn endpoint(kw: &str, ep: &Endpoint, ifs: &InterfaceMap, push: &mut impl FnMut(String)) {
    let mut a = addr_text(&ep.addr, ifs);
    if ep.negate {
        a = format!("!{a}");
    }
    push(curly(kw, &a));
    if let Some(p) = &ep.port {
        push(curly("port", &p.to_string()));
    }
}

fn curly(kw: &str, v: &str) -> String {
    if v.contains('$') {
        format!("{kw} {v}")
    } else {
        format!("{kw} {{{v}}}")
    }
}

fn addr_text(a: &Addr, ifs: &InterfaceMap) -> String {
    let dev = |i: &str| {
        ifs.get(i)
            .map(|x| x.device.clone())
            .unwrap_or_else(|| format!("##{i}##"))
    };
    match a {
        Addr::Any => "any".into(),
        Addr::SelfAddr => "(self)".into(),
        Addr::Host(ip) => ip.to_string(),
        Addr::Net(n) => n.to_string(),
        Addr::Alias(n) => format!("${n}"),
        Addr::Table(t) => format!("<{t}>"),
        Addr::IfaceNet { iface, link_local } => {
            let base = format!("({}:network)", dev(iface));
            if *link_local {
                format!("{base},fe80::/10")
            } else {
                base
            }
        }
        Addr::IfaceAddr(i) => format!("({})", dev(i)),
        Addr::Device(d) => format!("({d})"),
        // nft-only; filter_rule never renders a body for these
        Addr::MacSet(s) => format!("##{s}##"),
        // upstream json_encode()s the unparsable value into the output
        Addr::Invalid(s) => serde_json::to_string(s).unwrap_or_default(),
    }
}

/// Renders a whole filter section the way `Plugin::outputFilterRules` does:
/// one `# [prio: N]` header per priority.
pub fn filter_rules<'a>(
    rules: impl IntoIterator<Item = &'a FilterRule>,
    ifs: &InterfaceMap,
) -> String {
    let mut out = String::new();
    let mut last = None;
    for r in rules {
        if last != Some(r.priority) {
            let _ = writeln!(out, "# [prio: {}]", r.priority);
            last = Some(r.priority);
        }
        filter_rule(r, ifs, &mut out);
    }
    out
}

fn dev_of(i: &Option<String>, ifs: &InterfaceMap) -> Option<String> {
    i.as_ref().map(|i| {
        ifs.get(i)
            .filter(|x| !x.device.is_empty())
            .map(|x| x.device.clone())
            .unwrap_or_else(|| format!("##{i}##"))
    })
}

fn proto_text(p: ProtoMatch) -> Option<String> {
    match p {
        ProtoMatch::Any => None,
        ProtoMatch::TcpUdp => Some("proto {tcp udp}".into()),
        ProtoMatch::One(p) => {
            let name = p.to_string();
            Some(if name.contains('/') || name == "skip" {
                format!("proto \"{name}\"")
            } else {
                format!("proto {name}")
            })
        }
    }
}

fn plain_addr(ep: &Endpoint, ifs: &InterfaceMap) -> String {
    let a = addr_text(&ep.addr, ifs);
    if ep.negate { format!("!{a}") } else { a }
}

/// One port forward as `ForwardRule::__toString` renders it: the `rdr` line,
/// then the reflection helper `nat` line when enabled.
pub fn rdr_rule(r: &crate::nat::RdrRule, ifs: &InterfaceMap, out: &mut String) {
    if !r.debug.is_empty() {
        let _ = writeln!(out, "#debug:{}", r.debug.join("|"));
    }
    let mut parts: Vec<String> = Vec::new();
    let mut push = |s: String| {
        let t = s.trim();
        if !t.is_empty() {
            parts.push(t.to_owned());
        }
    };
    if !r.enabled {
        push("#".into());
    }
    push(if r.nordr { "no rdr" } else { "rdr" }.into());
    if r.pass {
        push("pass".into());
    }
    if r.log {
        push("log".into());
    }
    if let Some(d) = dev_of(&r.interface, ifs) {
        push(format!("on {d}"));
    }
    if let Some(f) = r.family {
        push(f.pf().into());
    }
    if let Some(p) = proto_text(r.proto) {
        push(p);
    }
    endpoint("from", &r.src, ifs, &mut push);
    endpoint("to", &r.dst, ifs, &mut push);
    if let Some(t) = &r.target {
        push(format!("-> {}", addr_text(t, ifs)));
    }
    if let Some(p) = &r.local_port {
        push(format!("port {p}"));
    }
    if !r.descr.is_empty() {
        push(format!("# {}", r.descr.replace(['\r', '\n'], "")));
    }
    out.push_str(&parts.join(" "));
    out.push('\n');

    if !r.helper {
        return;
    }
    let mut parts: Vec<String> = Vec::new();
    let mut push = |s: String| {
        let t = s.trim();
        if !t.is_empty() {
            parts.push(t.to_owned());
        }
    };
    if !r.enabled {
        push("#".into());
    }
    push("nat".into());
    let dev = dev_of(&r.interface, ifs);
    if let Some(d) = &dev {
        push(format!("on {d}"));
    }
    if let Some(f) = r.family {
        push(f.pf().into());
    }
    if let Some(p) = proto_text(r.proto) {
        push(p);
    }
    if let Some(d) = &dev {
        push(format!("from ({d}:network)"));
    }
    if let Some(t) = &r.target {
        push(curly("to", &addr_text(t, ifs)));
    }
    if let Some(p) = &r.local_port {
        push(curly("port", &p.to_string()));
    }
    if let Some(d) = &dev {
        push(format!("-> ({d})"));
    }
    push("port 1024:65535".into());
    if !r.descr.is_empty() {
        push(format!("# {}", r.descr.replace(['\r', '\n'], "")));
    }
    out.push_str(&parts.join(" "));
    out.push('\n');
}

/// One outbound rule as `SNatRule::__toString` renders it.
pub fn snat_rule(r: &crate::nat::SnatRule, ifs: &InterfaceMap, out: &mut String) {
    use crate::nat::SnatTarget;
    if !r.debug.is_empty() {
        let _ = writeln!(out, "#debug:{}", r.debug.join("|"));
    }
    let mut parts: Vec<String> = Vec::new();
    let mut push = |s: String| {
        let t = s.trim();
        if !t.is_empty() {
            parts.push(t.to_owned());
        }
    };
    if !r.enabled {
        push("#".into());
    }
    let nonat = r.target == SnatTarget::NoNat;
    push(if nonat { "no nat" } else { "nat" }.into());
    if r.log {
        push("log".into());
    }
    if let Some(d) = dev_of(&r.interface, ifs) {
        push(format!("on {d}"));
    }
    if let Some(f) = r.family {
        push(f.pf().into());
    }
    if let Some(p) = proto_text(r.proto) {
        push(p);
    }
    push(format!("from {}", plain_addr(&r.src, ifs)));
    if let Some(p) = &r.src.port {
        push(format!("port {p}"));
    }
    push(format!("to {}", plain_addr(&r.dst, ifs)));
    if let Some(p) = &r.dst.port {
        push(format!("port {p}"));
    }
    match &r.target {
        SnatTarget::NoNat => {}
        SnatTarget::Interface(i) => {
            let d = dev_of(&Some(i.clone()), ifs).unwrap_or_default();
            push(format!("-> ({d}:0)"));
        }
        SnatTarget::Host(ip) => push(format!("-> {ip}")),
        SnatTarget::Net(n) => push(format!("-> {n}")),
        SnatTarget::Alias(a) => push(format!("-> ${a}")),
    }
    if !nonat && !r.static_port {
        match &r.target_port {
            Some(p) => push(format!("port {p}")),
            None => push("port 1024:65535".into()),
        }
    }
    if r.static_port && !nonat {
        push("static-port".into());
    }
    if !r.descr.is_empty() {
        push(format!("# {}", r.descr.replace(['\r', '\n'], "")));
    }
    out.push_str(&parts.join(" "));
    out.push('\n');
}

/// One 1:1 NAT line as `DNatRule::__toString` renders it (`nat`,
/// `nat_rdr` and `nat_refl` rule types).
pub fn static_rule(r: &crate::nat::StaticRule, ifs: &InterfaceMap, out: &mut String) {
    use crate::nat::{StaticKind, StaticPart};
    if !r.debug.is_empty() {
        let _ = writeln!(out, "#debug:{}", r.debug.join("|"));
    }
    let mut parts: Vec<String> = Vec::new();
    let mut push = |s: String| {
        let t = s.trim();
        if !t.is_empty() {
            parts.push(t.to_owned());
        }
    };
    if !r.enabled {
        push("#".into());
    }
    // the external address is printed as configured, also when invalid
    let external = match &r.external {
        Addr::Any => None,
        Addr::Invalid(t) => Some(t.clone()),
        a => Some(addr_text(a, ifs)),
    };
    let dev = dev_of(&r.interface, ifs);
    match &r.part {
        StaticPart::Map(kind) => {
            push(
                match kind {
                    StaticKind::Binat => "binat",
                    StaticKind::Nat => "nat",
                }
                .into(),
            );
            if r.log {
                push("log".into());
            }
            if let Some(d) = &dev {
                push(format!("on {d}"));
            }
            push(format!("from {}", plain_addr(&r.internal, ifs)));
            push(format!("to {}", plain_addr(&r.peer, ifs)));
            if let Some(e) = external {
                push(format!("-> {e}"));
            }
        }
        StaticPart::Reflection => {
            push("rdr".into());
            if let Some(d) = &dev {
                push(format!("on {d}"));
            }
            push(curly("from", &plain_addr(&r.peer, ifs)));
            if let Some(e) = external {
                push(curly("to", &e));
            }
            push(format!(
                "{} bitmask",
                curly("->", &plain_addr(&r.internal, ifs))
            ));
        }
        StaticPart::Helper => {
            push("nat".into());
            if let Some(d) = &dev {
                push(format!("on {d}"));
            }
            if let Some(f) = r.family {
                push(f.pf().into());
            }
            if let Some(d) = &dev {
                push(format!("from ({d}:network)"));
            }
            push(curly("to", &plain_addr(&r.internal, ifs)));
            if let Some(d) = &dev {
                push(format!("-> ({d})"));
            }
            push("port 1024:65535".into());
        }
    }
    if !r.descr.is_empty() {
        push(format!("# {}", r.descr.replace(['\r', '\n'], "")));
    }
    out.push_str(&parts.join(" "));
    out.push('\n');
}

/// The NAT section as `Plugin::outputNatRules` orders it: by priority, one
/// header per priority, rdr and nat rules of one priority in registration
/// order (port forwards are registered after outbound rules).
pub fn nat_rules(nat: &crate::nat::NatRules, ifs: &InterfaceMap) -> String {
    let mut prios: Vec<u32> = nat
        .snat
        .iter()
        .map(|r| r.priority)
        .chain(nat.rdr.iter().map(|r| r.priority))
        .chain(nat.static_nat.iter().map(|r| r.priority))
        .collect();
    prios.sort_unstable();
    prios.dedup();
    let mut out = String::new();
    for p in prios {
        let _ = writeln!(out, "# [prio: {p}]");
        // pf.inc registers 1:1 rules before filter.inc registers the rest
        for r in nat.static_nat.iter().filter(|r| r.priority == p) {
            static_rule(r, ifs, &mut out);
        }
        for r in nat.snat.iter().filter(|r| r.priority == p) {
            snat_rule(r, ifs, &mut out);
        }
        for r in nat.rdr.iter().filter(|r| r.priority == p) {
            rdr_rule(r, ifs, &mut out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_set_rule_is_a_comment_only() {
        let rule = FilterRule {
            action: Action::Block,
            quick: true,
            src: Endpoint {
                addr: Addr::MacSet("host_isolated".into()),
                ..Endpoint::default()
            },
            descr: "host mode isolated: block local\nnetworks".into(),
            ..FilterRule::default()
        };
        let mut out = String::new();
        filter_rule(&rule, &InterfaceMap::new(), &mut out);
        assert_eq!(
            out,
            "# host mode (nft-only): host mode isolated: block localnetworks\n"
        );
    }
}
