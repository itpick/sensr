//! NAT: outbound mode and rules (legacy `nat/outbound/rule` and MVC
//! `OPNsense/Firewall/Filter/snatrules`) and port forwards (`nat/rule`, the
//! legacy-mapped `Firewall/DNat` model).

use std::cell::RefCell;

use sensr_schema::array::Relation;
use sensr_schema::fields::{NetOrAlias, PortRange};
use sensr_schema::models::firewall::Endpoint;
use sensr_schema::models::nat::{
    ForwardFilter, OutboundNatMode, PortForward, ReflectionMode, SourceNatRule,
};
use sensr_schema::{Document, Uuid};

use super::common::{
    description, family, interface_id, item_uuid, list, operand, port_operand, translate,
};
use super::filter::SEQUENCE_STEP;
use crate::mapper::{MapContext, Mapper};
use crate::report::Severity;
use crate::tree::{Document as XmlDocument, Element};

#[derive(Default)]
pub struct NatMapper {
    /// Outbound rules: (origin 0 = MVC / 1 = legacy, order key, id, rule).
    staged: RefCell<Vec<(u8, u64, Uuid, SourceNatRule)>>,
}

impl Mapper<Document> for NatMapper {
    fn name(&self) -> &'static str {
        "nat"
    }

    fn sections(&self) -> &'static [&'static str] {
        &[
            "nat/outbound",
            "nat/rule",
            "OPNsense/Firewall/Filter/snatrules/rule",
        ]
    }

    fn map<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        match s.name.as_str() {
            "outbound" => self.outbound(s, ctx, out),
            "rule" if s.child("source_net").is_some() || s.child("nonat").is_some() => {
                let key = ctx.parse::<u64>(s, "sequence").unwrap_or(0);
                match snat_rule(s, ctx, out, true) {
                    Some((id, rule)) => self.staged.borrow_mut().push((0, key, id, rule)),
                    None => ctx.release(s),
                }
            }
            _ => match port_forward(s, ctx, out) {
                Some((id, pf)) => {
                    out.nat.port_forwards.insert(id, pf);
                }
                None => ctx.release(s),
            },
        }
    }

    fn finish(&self, _doc: &XmlDocument, _ctx: &mut MapContext<'_>, out: &mut Document) {
        let mut staged = std::mem::take(&mut *self.staged.borrow_mut());
        staged.sort_by_key(|(origin, key, _, _)| (*origin, *key));
        let mut seq = 0u32;
        for (_, _, id, mut rule) in staged {
            seq = seq.saturating_add(SEQUENCE_STEP);
            rule.sequence = seq;
            out.nat.outbound.rules.insert(id, rule);
        }
    }
}

impl NatMapper {
    fn outbound<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        if let Some(m) = s.child("mode") {
            let mode = match m.text().trim() {
                "" | "automatic" => Some(OutboundNatMode::Automatic),
                "hybrid" => Some(OutboundNatMode::Hybrid),
                "advanced" => Some(OutboundNatMode::Manual),
                "disabled" => Some(OutboundNatMode::Disabled),
                _ => None,
            };
            if let Some(mode) = mode {
                ctx.consume(m);
                out.nat.outbound.mode = mode;
            }
        }
        for (index, r) in s.children_named("rule").enumerate() {
            ctx.consume(r);
            match snat_rule(r, ctx, out, false) {
                Some((id, rule)) => self.staged.borrow_mut().push((1, index as u64, id, rule)),
                None => ctx.release(r),
            }
        }
    }
}

/// Endpoint of an MVC rule (`<side>_net`, `<side>_not`, `<side>_port`).
fn mvc_endpoint<'doc>(
    ctx: &mut MapContext<'doc>,
    r: &'doc Element,
    side: &str,
    out: &Document,
) -> Option<Endpoint> {
    let net_el = r.child(&format!("{side}_net"));
    let at = net_el.unwrap_or(r);
    let net = translate(
        ctx,
        at,
        &net_el.map(Element::text).unwrap_or_default(),
        |t| operand(out, t),
    )?;
    let port_el = r.child(&format!("{side}_port"));
    let port = translate(
        ctx,
        port_el.unwrap_or(r),
        &port_el.map(Element::text).unwrap_or_default(),
        |t| port_operand(out, t),
    )?;
    for e in [net_el, port_el].into_iter().flatten() {
        ctx.consume_subtree(e);
    }
    let not = ctx.flag(r, &format!("{side}_not"));
    Some(Endpoint { net, not, port })
}

/// Endpoint in the legacy nested form (`<source><network/><port/><not/></source>`).
fn nested_endpoint<'doc>(
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
        NetOrAlias::Any
    } else if let Some(n) = e.child("network").or_else(|| e.child("address")) {
        let v = translate(ctx, n, &n.text(), |t| operand(out, t))?;
        ctx.consume_subtree(n);
        v
    } else {
        NetOrAlias::Any
    };
    let port = match e.child("port") {
        Some(p) => {
            let v = translate(ctx, p, &p.text(), |t| port_operand(out, t))?;
            ctx.consume_subtree(p);
            v
        }
        None => None,
    };
    let not = ctx.flag(e, "not");
    Some(Endpoint { net, not, port })
}

fn snat_rule<'doc>(
    r: &'doc Element,
    ctx: &mut MapContext<'doc>,
    out: &Document,
    mvc: bool,
) -> Option<(Uuid, SourceNatRule)> {
    let id = item_uuid(ctx, r);
    let if_el = r.child("interface")?;
    let Some(interface) = interface_id(out, if_el.text().trim()) else {
        ctx.warn(
            if_el,
            Severity::Invalid,
            format!(
                "NAT rule not imported: interface {:?} is not assigned",
                if_el.text()
            ),
        );
        return None;
    };
    ctx.consume(if_el);
    let ip_protocol = translate(
        ctx,
        r,
        &r.child("ipprotocol").map(Element::text).unwrap_or_default(),
        family,
    )?;
    let protocol_text = r.child("protocol").map(Element::text).unwrap_or_default();
    let protocol = if protocol_text.trim().is_empty() || protocol_text.trim() == "any" {
        sensr_schema::fields::Protocol::Any
    } else {
        translate(ctx, r, &protocol_text, |t| {
            t.parse().map_err(|e| format!("{t:?}: {e}"))
        })?
    };
    for f in ["ipprotocol", "protocol"] {
        if let Some(c) = r.child(f) {
            ctx.consume(c);
        }
    }
    let (source, destination) = if mvc {
        (
            mvc_endpoint(ctx, r, "source", out)?,
            mvc_endpoint(ctx, r, "destination", out)?,
        )
    } else {
        let mut src = nested_endpoint(ctx, r.child("source"), out)?;
        let mut dst = nested_endpoint(ctx, r.child("destination"), out)?;
        // Legacy outbound rules keep the ports beside the endpoints.
        if let Some(p) = r.child("sourceport") {
            src.port = translate(ctx, p, &p.text(), |t| port_operand(out, t))?;
            ctx.consume(p);
        }
        if let Some(p) = r.child("dstport") {
            dst.port = translate(ctx, p, &p.text(), |t| port_operand(out, t))?;
            ctx.consume(p);
        }
        (src, dst)
    };
    let target = match r.child("target") {
        Some(t) => {
            let text = t.text();
            let v = if text.trim().is_empty() {
                None
            } else {
                Some(translate(ctx, t, &text, |s| operand(out, s))?)
            };
            ctx.consume(t);
            v
        }
        None => None,
    };
    let target_port = match r.child(if mvc { "target_port" } else { "natport" }) {
        Some(p) => {
            let text = p.text();
            let v = if text.trim().is_empty() {
                None
            } else {
                Some(translate(ctx, p, &text, |s| {
                    s.parse::<PortRange>().map_err(|e| format!("{s:?}: {e}"))
                })?)
            };
            ctx.consume(p);
            v
        }
        None => None,
    };
    let enabled = if mvc {
        ctx.flag(r, "enabled")
    } else {
        !ctx.flag(r, "disabled")
    };
    let descr = ctx.text(r, if mvc { "description" } else { "descr" });
    let rule = SourceNatRule {
        enabled,
        no_nat: ctx.flag(r, "nonat"),
        sequence: 0,
        interface,
        ip_protocol,
        protocol,
        source,
        destination,
        target,
        target_port,
        static_port: ctx.flag(r, "staticnatport"),
        log: ctx.flag(r, "log"),
        description: description(ctx, r, descr),
    };
    ctx.defaults(
        r,
        &[
            ("nosync", "0"),
            ("endpoint-independent", "0"),
            ("poolopts", ""),
            ("poolopts_sourcehashkey", ""),
            ("tagged", ""),
            ("tag", ""),
            ("categories", ""),
            ("category", ""),
            ("targetip", ""),
            ("targetip_subnet", ""),
            ("sequence", ""),
        ],
    );
    Some((id, rule))
}

fn port_forward<'doc>(
    r: &'doc Element,
    ctx: &mut MapContext<'doc>,
    out: &Document,
) -> Option<(Uuid, PortForward)> {
    let id = item_uuid(ctx, r);
    let if_el = r.child("interface")?;
    let mut interfaces = Vec::new();
    for name in list(&if_el.text(), &[',']) {
        let Some(i) = interface_id(out, &name) else {
            ctx.warn(
                if_el,
                Severity::Invalid,
                format!("port forward not imported: interface {name:?} is not assigned"),
            );
            return None;
        };
        interfaces.push(i);
    }
    ctx.consume(if_el);
    let ip_protocol = translate(
        ctx,
        r,
        &r.child("ipprotocol").map(Element::text).unwrap_or_default(),
        family,
    )?;
    let protocol_text = r.child("protocol").map(Element::text).unwrap_or_default();
    let protocol = if protocol_text.trim().is_empty() || protocol_text.trim() == "any" {
        sensr_schema::fields::Protocol::Any
    } else {
        translate(ctx, r, &protocol_text, |t| {
            t.parse().map_err(|e| format!("{t:?}: {e}"))
        })?
    };
    for f in ["ipprotocol", "protocol"] {
        if let Some(c) = r.child(f) {
            ctx.consume(c);
        }
    }
    let source = nested_endpoint(ctx, r.child("source"), out)?;
    let destination = nested_endpoint(ctx, r.child("destination"), out)?;
    let target_el = r.child("target")?;
    let target = translate(ctx, target_el, &target_el.text(), |t| operand(out, t))?;
    ctx.consume(target_el);
    let target_port = match r.child("local-port") {
        Some(p) => {
            let v = translate(ctx, p, &p.text(), |t| port_operand(out, t))?;
            ctx.consume(p);
            v
        }
        None => None,
    };
    let reflection = match r.child("natreflection") {
        Some(n) => {
            let v = match n.text().trim() {
                "" => None,
                "purenat" => Some(ReflectionMode::Purenat),
                "enable" => Some(ReflectionMode::Enable),
                "disable" => Some(ReflectionMode::Disable),
                _ => return None,
            };
            ctx.consume(n);
            v
        }
        None => None,
    };
    let linked = r
        .child("associated-rule-id")
        .map(Element::text)
        .filter(|t| !t.trim().is_empty());
    let filter = match (
        r.child("pass").map(Element::text).as_deref().map(str::trim),
        linked,
    ) {
        (_, Some(rule)) => match rule.trim().parse::<Uuid>() {
            Ok(u) => ForwardFilter::Rule(Relation::new(u)),
            Err(_) => {
                ctx.warn(
                    r,
                    Severity::Degraded,
                    format!("linked rule {rule:?} is not a UUID; traffic is passed implicitly"),
                );
                ForwardFilter::Pass
            }
        },
        (Some("pass"), None) => ForwardFilter::Pass,
        (Some("rule"), None) => {
            ctx.warn(
                r,
                Severity::Info,
                "OPNsense registers a filter rule for this forward at load time; sensr passes the forwarded traffic implicitly",
            );
            ForwardFilter::Pass
        }
        _ => ForwardFilter::None,
    };
    for f in ["pass", "associated-rule-id"] {
        if let Some(c) = r.child(f) {
            ctx.consume(c);
        }
    }
    let sequence = ctx.parse::<u32>(r, "sequence").unwrap_or(1);
    let descr = ctx.text(r, "descr");
    let pf = PortForward {
        enabled: !ctx.flag(r, "disabled"),
        sequence,
        no_rdr: ctx.flag(r, "nordr"),
        interfaces,
        ip_protocol,
        protocol,
        source,
        destination,
        target,
        target_port,
        log: ctx.flag(r, "log"),
        description: description(ctx, r, descr),
        reflection,
        filter,
    };
    ctx.defaults(
        r,
        &[
            ("poolopts", ""),
            ("category", ""),
            ("tag", ""),
            ("tagged", ""),
            ("nosync", "0"),
        ],
    );
    Some((id, pf))
}
