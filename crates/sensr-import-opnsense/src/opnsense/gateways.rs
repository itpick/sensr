//! Gateways (`OPNsense/Gateways`, legacy `gateways/gateway_item`), gateway groups
//! (`gateways/gateway_group`), and the references to them: an interface's
//! `gateway`/`gatewayv6` and a filter rule's policy-routing `gateway`.

use std::net::IpAddr;

use sensr_schema::fields::{GatewayName, IpFamily};
use sensr_schema::models::gateways::{
    Gateway, GatewayGroup, GroupMember, GroupTrigger, MonitorThresholds,
};
use sensr_schema::models::interfaces::{InterfaceRole, Ipv4Config, Ipv6Config};
use sensr_schema::{Document, Uuid};

use super::common::{description, family, interface_id, item_uuid, list, parse_or_warn, translate};
use crate::mapper::{MapContext, Mapper};
use crate::report::Severity;
use crate::tree::{Document as XmlDocument, Element};

pub struct GatewayMapper;

/// Monitoring knobs that are empty (dpinger defaults) unless tuned.
const MONITOR_DEFAULTS: &[(&str, &str)] = &[
    ("monitor_noroute", "0"),
    ("monitor_killstates", "0"),
    ("monitor_killstates_priority", "0"),
    ("nosync", "0"),
];

impl Mapper<Document> for GatewayMapper {
    fn name(&self) -> &'static str {
        "gateways"
    }

    fn sections(&self) -> &'static [&'static str] {
        &[
            "OPNsense/Gateways",
            "OPNsense/Gateways/gateway_item",
            "gateways",
            "gateways/gateway_item",
            "gateways/gateway_group",
        ]
    }

    fn map<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        let mapped = match s.name.as_str() {
            "gateway_item" => gateway(s, ctx, out).map(|(id, g)| {
                out.gateways.gateways.insert(id, g);
            }),
            "gateway_group" => group(s, ctx).map(|(id, g)| {
                out.gateways.groups.insert(id, g);
            }),
            // Containers: their items map one by one.
            _ => Some(()),
        };
        if mapped.is_none() {
            ctx.release(s);
        }
    }

    fn finish<'doc>(&self, doc: &'doc XmlDocument, ctx: &mut MapContext<'doc>, out: &mut Document) {
        if let Some(ifaces) = doc.root.child("interfaces") {
            for i in ifaces.elements() {
                interface_gateway(i, ctx, out);
            }
        }
        let mvc = doc.root.path(&["OPNsense", "Firewall", "Filter", "rules"]);
        let legacy = doc.root.child("filter");
        for r in mvc
            .into_iter()
            .chain(legacy)
            .flat_map(|c| c.children_named("rule"))
        {
            rule_gateway(r, ctx, out);
        }
    }
}

fn gateway<'doc>(
    g: &'doc Element,
    ctx: &mut MapContext<'doc>,
    out: &Document,
) -> Option<(Uuid, Gateway)> {
    let id = item_uuid(ctx, g);
    let name_el = ctx.child(g, "name")?;
    let name: GatewayName = parse_or_warn(ctx, name_el, &name_el.text(), "gateway name")?;
    let if_el = ctx.child(g, "interface")?;
    let Some(interface) = interface_id(out, if_el.text().trim()) else {
        ctx.warn(
            if_el,
            Severity::Invalid,
            format!(
                "gateway {name}: interface {:?} is not assigned",
                if_el.text()
            ),
        );
        return None;
    };
    let fam = translate(
        ctx,
        g,
        &g.child("ipprotocol").map(Element::text).unwrap_or_default(),
        family,
    )?;
    let fam = if fam == IpFamily::Inet46 {
        IpFamily::Inet
    } else {
        fam
    };
    if let Some(c) = g.child("ipprotocol") {
        ctx.consume(c);
    }
    let address = match ctx.text(g, "gateway").as_deref().map(str::trim) {
        None | Some("" | "dynamic") => None,
        Some(a) => Some(parse_or_warn::<IpAddr>(ctx, g, a, "gateway address")?),
    };
    let monitor_address = match ctx.non_empty(g, "monitor") {
        Some(m) => parse_or_warn(ctx, g, &m, "monitor address"),
        None => None,
    };
    // monitor_disable defaults to 1 in the model: an absent element means off.
    let monitor = g.child("monitor_disable").is_some() && !ctx.flag(g, "monitor_disable");
    let descr = ctx.text(g, "descr");
    let gw = Gateway {
        enabled: !ctx.flag(g, "disabled"),
        name,
        description: description(ctx, g, descr),
        interface,
        family: fam,
        address,
        default_route: ctx.flag(g, "defaultgw"),
        far: ctx.flag(g, "fargw"),
        monitor,
        monitor_address,
        priority: ctx.parse(g, "priority").unwrap_or(255),
        weight: ctx.parse(g, "weight").unwrap_or(1),
        force_down: ctx.flag(g, "force_down"),
        thresholds: MonitorThresholds {
            latency_low: num(ctx, g, "latencylow"),
            latency_high: num(ctx, g, "latencyhigh"),
            loss_low: num(ctx, g, "losslow"),
            loss_high: num(ctx, g, "losshigh"),
            interval: num(ctx, g, "interval"),
            loss_interval: num(ctx, g, "loss_interval"),
            time_period: num(ctx, g, "time_period"),
            data_length: num(ctx, g, "data_length"),
        },
    };
    ctx.defaults(g, MONITOR_DEFAULTS);
    Some((id, gw))
}

/// A whole-number setting; empty means the default. Fractions (seconds
/// like `0.5`) round up.
fn num<'doc>(ctx: &mut MapContext<'doc>, g: &'doc Element, name: &str) -> Option<u32> {
    let t = ctx.non_empty(g, name)?;
    match t.trim().parse::<f64>() {
        Ok(v) if v.is_finite() && v >= 0.0 && v < 4.0e9 => Some(v.ceil() as u32),
        _ => {
            ctx.warn(
                g,
                Severity::Invalid,
                format!("{name} {t:?} not imported; default used"),
            );
            None
        }
    }
}

fn group<'doc>(g: &'doc Element, ctx: &mut MapContext<'doc>) -> Option<(Uuid, GatewayGroup)> {
    let id = item_uuid(ctx, g);
    let name_el = ctx.child(g, "name")?;
    let name: GatewayName = parse_or_warn(ctx, name_el, &name_el.text(), "group name")?;
    let mut members = Vec::new();
    // `item` is tier 1, `item2`..`item5` the lower tiers; older configs wrote
    // `GW|tier` entries into repeated `item` elements instead.
    for (tag, tier) in [
        ("item", 1u8),
        ("item2", 2),
        ("item3", 3),
        ("item4", 4),
        ("item5", 5),
    ] {
        for e in ctx.children(g, tag) {
            for entry in list(&e.text(), &[',']) {
                let (gw, t) = match entry.split_once('|') {
                    Some((gw, t)) => (gw.to_owned(), t.trim().parse().unwrap_or(tier)),
                    None => (entry, tier),
                };
                if let Some(gateway) = parse_or_warn::<GatewayName>(ctx, e, &gw, "gateway name") {
                    members.push(GroupMember { gateway, tier: t });
                }
            }
        }
    }
    let trigger = match ctx.text(g, "trigger").as_deref().map(str::trim) {
        None | Some("" | "down") => GroupTrigger::Down,
        Some("downloss") => GroupTrigger::DownLoss,
        Some("downlatency") => GroupTrigger::DownLatency,
        Some("downlosslatency") => GroupTrigger::DownLossLatency,
        Some(other) => {
            ctx.warn(
                g,
                Severity::Invalid,
                format!("trigger {other:?} not imported"),
            );
            return None;
        }
    };
    let descr = ctx.text(g, "descr");
    ctx.defaults(g, &[("poolopts", "")]);
    Some((
        id,
        GatewayGroup {
            name,
            description: description(ctx, g, descr),
            members,
            trigger,
        },
    ))
}

/// A static interface's `gateway` names its upstream: the address goes into the
/// interface's addressing and the interface becomes a WAN.
fn interface_gateway<'doc>(i: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
    let Some(id) = interface_id(out, &i.name) else {
        return;
    };
    for (tag, v6) in [("gateway", false), ("gatewayv6", true)] {
        let Some(e) = i.child(tag) else { continue };
        let text = e.text();
        let name = text.trim();
        if name.is_empty() {
            continue;
        }
        let Ok(gw_name) = name.parse::<GatewayName>() else {
            continue;
        };
        let Some(addr) = out.gateways.gateway(&gw_name).and_then(|g| g.address) else {
            ctx.warn(
                e,
                Severity::Invalid,
                format!("gateway {name} is not a gateway with a fixed address"),
            );
            continue;
        };
        let Some(iface) = out.interfaces.0.get_mut(&id) else {
            continue;
        };
        let set = match (&mut iface.ipv4, &mut iface.ipv6, addr, v6) {
            (Ipv4Config::Static { gateway, .. }, _, IpAddr::V4(a), false) => {
                *gateway = Some(a);
                true
            }
            (_, Ipv6Config::Static { gateway, .. }, IpAddr::V6(a), true) => {
                *gateway = Some(a);
                true
            }
            _ => false,
        };
        if set {
            ctx.consume_subtree(e);
            if iface.role == InterfaceRole::Lan && id.as_str() != "lan" {
                iface.role = InterfaceRole::Wan;
            }
        }
    }
}

fn rule_gateway<'doc>(r: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
    let Some(e) = r.child("gateway") else { return };
    let text = e.text();
    let name = text.trim();
    if name.is_empty() {
        return;
    }
    let id = item_uuid(ctx, r);
    let Some(rule) = out.firewall.rules.get_mut(&id) else {
        return;
    };
    match name.parse::<GatewayName>() {
        Ok(gw) if out.gateways.has(&gw) => {
            rule.gateway = Some(gw);
            ctx.consume_subtree(e);
        }
        _ => ctx.warn(
            e,
            Severity::Invalid,
            format!("rule gateway {name:?} is not a gateway or group"),
        ),
    }
}
