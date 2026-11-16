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
pub fn filter_rule(rule: &FilterRule, ifs: &InterfaceMap, out: &mut String) {
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
