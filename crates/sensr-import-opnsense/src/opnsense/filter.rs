//! Filter rules: legacy `filter/rule` (the `firewall-legacy` pages) and MVC
//! `OPNsense/Firewall/Filter/rules/rule`, merged into one ordered list.
//!
//! OPNsense evaluates rules in priority bands (`FilterRuleField::getPriority()`,
//! `filter_core_rules_user()`): floating rules (no single interface, or an inverted
//! interface match) at 200000, interface rules at 400000. Within a band the MVC rules
//! come first, sorted by `sequence`, then the legacy rules in file order
//! (`plugins_firewall()` registers before `filter_core_rules_user()`). sensr has a
//! single `sequence`, so the importer flattens that order into it.

use std::cell::RefCell;

use sensr_schema::fields::{InterfaceId, Protocol};
use sensr_schema::models::firewall::{Direction, Endpoint, FilterRule, RuleAction, StateType};
use sensr_schema::{Document, Uuid};

use super::common::{
    description, family, interface_id, item_uuid, list, operand, port_operand, translate,
};
use crate::mapper::{MapContext, Mapper};
use crate::report::Severity;
use crate::tree::{Document as XmlDocument, Element};

/// Gap between imported sequence numbers, leaving room to insert rules later.
pub const SEQUENCE_STEP: u32 = 10;

#[derive(Default)]
pub struct FilterMapper {
    staged: RefCell<Vec<Staged>>,
}

struct Staged {
    band: u32,
    origin: u8,
    key: u64,
    id: Uuid,
    rule: FilterRule,
}

/// MVC rule fields whose empty/default value means "off" and has no sensr
/// counterpart to set.
const MVC_DEFAULTS: &[(&str, &str)] = &[
    ("state-policy", ""),
    ("received-on-not", "0"),
    ("received-on", ""),
    ("icmptype", ""),
    ("icmp6type", ""),
    ("divert-to", ""),
    ("gateway", ""),
    ("replyto", ""),
    ("disablereplyto", "0"),
    ("allowopts", "0"),
    ("nosync", "0"),
    ("nopfsync", "0"),
    ("statetimeout", ""),
    ("udp-first", ""),
    ("udp-multiple", ""),
    ("udp-single", ""),
    ("max-src-nodes", ""),
    ("max-src-states", ""),
    ("max-src-conn", ""),
    ("max", ""),
    ("max-src-conn-rate", ""),
    ("max-src-conn-rates", ""),
    ("max-pkt-rate-number", ""),
    ("max-pkt-rate-seconds", ""),
    ("overload", ""),
    ("adaptivestart", ""),
    ("adaptiveend", ""),
    ("prio", ""),
    ("set-prio", ""),
    ("set-prio-low", ""),
    ("tag", ""),
    ("tagged", ""),
    ("tcpflags1", ""),
    ("tcpflags2", ""),
    ("tcpflags_any", "0"),
    ("categories", ""),
    ("sched", ""),
    ("tos", ""),
    ("shaper1", ""),
    ("shaper2", ""),
];

/// The same knobs under their legacy names.
const LEGACY_DEFAULTS: &[(&str, &str)] = &[
    ("gateway", ""),
    ("reply-to", ""),
    ("disablereplyto", ""),
    ("icmptype", ""),
    ("icmp6-type", ""),
    ("allowopts", ""),
    ("nosync", ""),
    ("nopfsync", ""),
    ("tag", ""),
    ("tagged", ""),
    ("max", ""),
    ("max-src-nodes", ""),
    ("max-src-conn", ""),
    ("max-src-states", ""),
    ("statetimeout", ""),
    ("tcpflags1", ""),
    ("tcpflags2", ""),
    ("tcpflags_any", ""),
    ("sched", ""),
    ("category", ""),
    ("os", ""),
];

impl Mapper<Document> for FilterMapper {
    fn name(&self) -> &'static str {
        "filter"
    }

    fn sections(&self) -> &'static [&'static str] {
        &[
            "filter/rule",
            "OPNsense/Firewall/Filter/rules/rule",
            "OPNsense/Firewall/Filter/general",
            "OPNsense/Firewall/Filter/npt",
            "OPNsense/Firewall/Filter/onetoone",
            // Containers, so an empty one counts as read.
            "filter",
            "OPNsense/Firewall/Filter/rules",
            "OPNsense/Firewall/Filter/snatrules",
        ]
    }

    fn map<'doc>(&self, r: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        let staged = match r.name.as_str() {
            "general" => {
                ctx.consume_subtree(r);
                return;
            }
            // Containers: the framework marked them read; their items map one by one.
            "filter" | "rules" | "snatrules" => return,
            // NPTv6 and 1:1 NAT are not modelled yet: fine while empty, reported otherwise.
            "npt" | "onetoone" => {
                if r.is_empty() {
                    ctx.consume_subtree(r);
                } else {
                    ctx.release(r);
                }
                return;
            }
            _ if r.is_empty() => {
                // An empty `<rule/>` (left by a cancelled edit) matches nothing in OPNsense.
                ctx.consume_subtree(r);
                ctx.warn(r, Severity::Info, "empty rule skipped");
                return;
            }
            _ if r.child("source_net").is_some() || r.child("action").is_some() => {
                mvc_rule(r, ctx, out)
            }
            _ => {
                let index = self
                    .staged
                    .borrow()
                    .iter()
                    .filter(|s| s.origin == 1)
                    .count();
                legacy_rule(r, ctx, out, index as u64)
            }
        };
        match staged {
            Some(s) => self.staged.borrow_mut().push(s),
            // A rule that cannot be imported is reported whole, not half-mapped.
            None => ctx.release(r),
        }
    }

    fn finish(&self, _doc: &XmlDocument, _ctx: &mut MapContext<'_>, out: &mut Document) {
        let mut staged = std::mem::take(&mut *self.staged.borrow_mut());
        staged.sort_by_key(|s| (s.band, s.origin, s.key));
        let mut seq = 0u32;
        for mut s in staged {
            seq = seq.saturating_add(SEQUENCE_STEP);
            s.rule.sequence = seq;
            out.firewall.rules.insert(s.id, s.rule);
        }
    }
}

/// pf priority band of a rule (see the module docs).
fn band(rule: &FilterRule) -> u32 {
    if rule.interfaces.len() != 1 || rule.interface_not {
        200_000
    } else {
        400_000
    }
}

fn interfaces(
    ctx: &mut MapContext<'_>,
    at: &Element,
    text: &str,
    out: &Document,
) -> Option<Vec<InterfaceId>> {
    let mut ids = Vec::new();
    for name in list(text, &[',']) {
        match interface_id(out, &name) {
            Some(id) => ids.push(id),
            None => {
                ctx.warn(
                    at,
                    Severity::Invalid,
                    format!("rule not imported: interface {name:?} is not assigned"),
                );
                return None;
            }
        }
    }
    Some(ids)
}

fn protocol(ctx: &mut MapContext<'_>, at: &Element, text: &str) -> Option<Protocol> {
    let t = text.trim();
    if t.is_empty() || t.eq_ignore_ascii_case("any") {
        return Some(Protocol::Any);
    }
    translate(ctx, at, t, |s| {
        s.parse::<Protocol>()
            .map_err(|e| format!("rule not imported: protocol {s:?}: {e}"))
    })
}

fn state_type(text: &str) -> Option<StateType> {
    Some(match text.trim() {
        "" | "keep" | "keep state" => StateType::Keep,
        "sloppy" | "sloppy state" => StateType::Sloppy,
        "modulate" | "modulate state" => StateType::Modulate,
        "synproxy" | "synproxy state" => StateType::Synproxy,
        "none" => StateType::None,
        _ => return None,
    })
}

fn direction(text: &str) -> Option<Direction> {
    Some(match text.trim() {
        "" | "in" => Direction::In,
        "out" => Direction::Out,
        "any" => Direction::Any,
        _ => return None,
    })
}

fn action(text: &str) -> Option<RuleAction> {
    Some(match text.trim() {
        "" | "pass" => RuleAction::Pass,
        "block" => RuleAction::Block,
        "reject" => RuleAction::Reject,
        _ => return None,
    })
}

/// Read an enum-like leaf; an unknown value is left unconsumed (and so reported).
fn choice<'doc, T>(
    ctx: &mut MapContext<'doc>,
    r: &'doc Element,
    name: &str,
    f: impl Fn(&str) -> Option<T>,
    default: T,
) -> Option<T> {
    let Some(c) = r.child(name) else {
        return Some(default);
    };
    let v = f(&c.text())?;
    ctx.consume_subtree(c);
    Some(v)
}

fn mvc_rule<'doc>(r: &'doc Element, ctx: &mut MapContext<'doc>, out: &Document) -> Option<Staged> {
    let id = item_uuid(ctx, r);
    let iface_text = r.child("interface").map(Element::text).unwrap_or_default();
    let ifaces = interfaces(ctx, r, &iface_text, out)?;
    let family = translate(
        ctx,
        r,
        &r.child("ipprotocol").map(Element::text).unwrap_or_default(),
        family,
    )?;
    let proto = protocol(
        ctx,
        r,
        &r.child("protocol").map(Element::text).unwrap_or_default(),
    )?;
    let source = mvc_endpoint(ctx, r, "source", out)?;
    let destination = mvc_endpoint(ctx, r, "destination", out)?;
    let rule_action = choice(ctx, r, "action", action, RuleAction::Pass)?;
    let dir = choice(ctx, r, "direction", direction, Direction::In)?;
    let state = choice(ctx, r, "statetype", state_type, StateType::Keep)?;
    for f in ["interface", "ipprotocol", "protocol"] {
        if let Some(c) = r.child(f) {
            ctx.consume_subtree(c);
        }
    }
    let key = ctx.parse::<u64>(r, "sequence").unwrap_or(0);
    let descr = ctx.text(r, "description");
    let rule = FilterRule {
        enabled: ctx.flag(r, "enabled"),
        sequence: 0,
        action: rule_action,
        quick: ctx.flag(r, "quick"),
        interfaces: ifaces,
        interface_not: ctx.flag(r, "interfacenot"),
        direction: dir,
        ip_protocol: family,
        protocol: proto,
        source,
        destination,
        log: ctx.flag(r, "log"),
        state_type: state,
        description: description(ctx, r, descr),
        gateway: None,
    };
    ctx.defaults(r, MVC_DEFAULTS);
    Some(Staged {
        band: band(&rule),
        origin: 0,
        key,
        id,
        rule,
    })
}

fn mvc_endpoint<'doc>(
    ctx: &mut MapContext<'doc>,
    r: &'doc Element,
    side: &str,
    out: &Document,
) -> Option<Endpoint> {
    let net_el = r.child(&format!("{side}_net"));
    let net_text = net_el.map(Element::text).unwrap_or_default();
    let at = net_el.unwrap_or(r);
    if list(&net_text, &[',']).len() > 1 {
        ctx.warn(
            at,
            Severity::Invalid,
            format!("rule not imported: multiple {side} addresses are not supported yet"),
        );
        return None;
    }
    let net = translate(ctx, at, &net_text, |t| {
        operand(out, t).map_err(|e| format!("rule not imported: {e}"))
    })?;
    let port_el = r.child(&format!("{side}_port"));
    let port_text = port_el.map(Element::text).unwrap_or_default();
    let port = translate(ctx, port_el.unwrap_or(r), &port_text, |t| {
        port_operand(out, t).map_err(|e| format!("rule not imported: {e}"))
    })?;
    if let Some(e) = net_el {
        ctx.consume_subtree(e);
    }
    if let Some(e) = port_el {
        ctx.consume_subtree(e);
    }
    let not = ctx.flag(r, &format!("{side}_not"));
    Some(Endpoint { net, not, port })
}

fn legacy_rule<'doc>(
    r: &'doc Element,
    ctx: &mut MapContext<'doc>,
    out: &Document,
    index: u64,
) -> Option<Staged> {
    let id = item_uuid(ctx, r);
    let floating = r.child("floating").is_some_and(|f| f.text().trim() != "no");
    let iface_text = r.child("interface").map(Element::text).unwrap_or_default();
    let ifaces = interfaces(ctx, r, &iface_text, out)?;
    let family = translate(
        ctx,
        r,
        &r.child("ipprotocol").map(Element::text).unwrap_or_default(),
        family,
    )?;
    let proto = protocol(
        ctx,
        r,
        &r.child("protocol").map(Element::text).unwrap_or_default(),
    )?;
    let source = legacy_endpoint(ctx, r.child("source"), out)?;
    let destination = legacy_endpoint(ctx, r.child("destination"), out)?;
    let rule_action = choice(ctx, r, "type", action, RuleAction::Pass)?;
    let dir = choice(ctx, r, "direction", direction, Direction::In)?;
    let state = choice(ctx, r, "statetype", state_type, StateType::Keep)?;
    for f in ["interface", "ipprotocol", "protocol", "floating"] {
        if let Some(c) = r.child(f) {
            ctx.consume_subtree(c);
        }
    }
    // Legacy interface rules are always quick; floating ones only when asked.
    let quick = match r.child("quick") {
        Some(_) => ctx.flag(r, "quick"),
        None => !floating,
    };
    let descr = ctx.text(r, "descr");
    let mut rule = FilterRule {
        enabled: !ctx.flag(r, "disabled"),
        sequence: 0,
        action: rule_action,
        quick,
        interfaces: ifaces,
        interface_not: false,
        direction: dir,
        ip_protocol: family,
        protocol: proto,
        source,
        destination,
        log: ctx.flag(r, "log"),
        state_type: state,
        description: description(ctx, r, descr),
        gateway: None,
    };
    if !floating && rule.interfaces.len() != 1 {
        ctx.warn(
            r,
            Severity::Invalid,
            "rule not imported: a non-floating rule needs exactly one interface",
        );
        return None;
    }
    if floating && rule.interfaces.len() == 1 {
        // A floating rule on one interface still sits in the floating band.
        rule.interface_not = false;
    }
    ctx.defaults(r, LEGACY_DEFAULTS);
    Some(Staged {
        band: if floating { 200_000 } else { 400_000 },
        origin: 1,
        key: index,
        id,
        rule,
    })
}

/// `<source>`/`<destination>`: `<any/>`, `<network>` (interface, `lanip`, `(self)`)
/// or `<address>` (alias or literal), plus `<port>` and `<not/>`.
fn legacy_endpoint<'doc>(
    ctx: &mut MapContext<'doc>,
    e: Option<&'doc Element>,
    out: &Document,
) -> Option<Endpoint> {
    let Some(e) = e else {
        return Some(Endpoint::any());
    };
    ctx.consume(e);
    let net = if let Some(a) = e.child("any") {
        ctx.consume_subtree(a);
        sensr_schema::fields::NetOrAlias::Any
    } else if let Some(n) = e.child("network").or_else(|| e.child("address")) {
        let v = translate(ctx, n, &n.text(), |t| {
            operand(out, t).map_err(|e| format!("rule not imported: {e}"))
        })?;
        ctx.consume_subtree(n);
        v
    } else {
        sensr_schema::fields::NetOrAlias::Any
    };
    let port = match e.child("port") {
        Some(p) => {
            let v = translate(ctx, p, &p.text(), |t| {
                port_operand(out, t).map_err(|e| format!("rule not imported: {e}"))
            })?;
            ctx.consume_subtree(p);
            v
        }
        None => None,
    };
    let not = ctx.flag(e, "not");
    Some(Endpoint { net, not, port })
}
