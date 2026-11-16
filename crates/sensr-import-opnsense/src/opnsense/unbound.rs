//! `OPNsense/unboundplus`: the Unbound DNS resolver.

use std::net::IpAddr;

use sensr_schema::fields::{DomainName, HostOverrideName, InterfaceId};
use sensr_schema::models::dns::{DnsRecord, Forwarder, HostOverride, LocalZoneType};
use sensr_schema::{Document, Uuid};

use super::common::{description, interface_id, item_uuid, list, parse_or_warn};
use crate::mapper::{MapContext, Mapper};
use crate::report::Severity;
use crate::tree::Element;

pub struct UnboundMapper;

impl Mapper<Document> for UnboundMapper {
    fn name(&self) -> &'static str {
        "unbound"
    }

    fn sections(&self) -> &'static [&'static str] {
        // `unbound` is the pre-MVC section factory configs still carry.
        &["unbound", "OPNsense/unboundplus"]
    }

    fn map<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        if s.name == "unbound" {
            // Only the switch survives the migration to the MVC model; the MVC section,
            // mapped after this one, overrides it when present.
            out.dns.enabled = ctx.flag(s, "enable");
            return;
        }
        if let Some(g) = ctx.child(s, "general") {
            general(g, ctx, out);
        }
        if let Some(f) = ctx.child(s, "forwarding") {
            out.dns.forwarding.use_system_servers = ctx.flag(f, "enabled");
        }
        if let Some(dots) = ctx.child(s, "dots") {
            for d in ctx.children(dots, "dot") {
                match forwarder(d, ctx) {
                    Some((id, f)) => {
                        out.dns.forwarding.servers.insert(id, f);
                    }
                    None => ctx.release(d),
                }
            }
        }
        if let Some(hosts) = ctx.child(s, "hosts") {
            for h in ctx.children(hosts, "host") {
                match host(h, ctx) {
                    Some((id, o)) => {
                        out.dns.host_overrides.insert(id, o);
                    }
                    None => ctx.release(h),
                }
            }
        }
        // An empty alias list is fine; host aliases themselves are not modelled yet.
        if let Some(a) = s.child("aliases")
            && !a.has_element_children()
        {
            ctx.consume_subtree(a);
        }
    }
}

fn interfaces(
    ctx: &mut MapContext<'_>,
    at: &Element,
    text: &str,
    out: &Document,
) -> Vec<InterfaceId> {
    let mut ids = Vec::new();
    for name in list(text, &[',']) {
        match interface_id(out, &name) {
            Some(id) => ids.push(id),
            None => ctx.warn(
                at,
                Severity::Invalid,
                format!("interface {name:?} is not assigned"),
            ),
        }
    }
    ids
}

fn general<'doc>(g: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
    let dns = &mut out.dns;
    dns.enabled = ctx.flag(g, "enabled");
    if let Some(p) = ctx.parse(g, "port") {
        dns.port = p;
    }
    dns.dnssec = ctx.flag(g, "dnssec");
    dns.dns64 = ctx.flag(g, "dns64");
    dns.register_dhcp_leases = ctx.flag(g, "regdhcp");
    dns.register_dhcp_static = ctx.flag(g, "regdhcpstatic");
    if let Some(d) = ctx.non_empty(g, "regdhcpdomain") {
        dns.dhcp_domain = parse_or_warn::<DomainName>(ctx, g, &d, "domain");
    }
    if let Some(z) = g.child("local_zone_type") {
        let t = z.text();
        if t.trim().is_empty() {
            ctx.consume(z);
        } else if let Some(v) = zone_type(t.trim()) {
            ctx.consume(z);
            out.dns.local_zone_type = v;
        }
    }
    if let Some(i) = g.child("active_interface") {
        ctx.consume(i);
        out.dns.listen_interfaces = interfaces(ctx, i, &i.text(), out);
    }
    if let Some(i) = g.child("outgoing_interface") {
        ctx.consume(i);
        out.dns.outgoing_interfaces = interfaces(ctx, i, &i.text(), out);
    }
    ctx.defaults(
        g,
        &[
            ("stats", "0"),
            ("dns64prefix", ""),
            ("noarecords", "0"),
            ("noreglladdr6", "0"),
            ("noregrecords", "0"),
            ("txtsupport", "0"),
            ("cacheflush", "0"),
            ("safesearch", "0"),
            ("enable_wpad", "0"),
        ],
    );
}

/// Unbound's `local-zone` type names.
fn zone_type(t: &str) -> Option<LocalZoneType> {
    Some(match t {
        "transparent" => LocalZoneType::Transparent,
        "typetransparent" => LocalZoneType::Typetransparent,
        "static" => LocalZoneType::Static,
        "refuse" => LocalZoneType::Refuse,
        "deny" => LocalZoneType::Deny,
        "redirect" => LocalZoneType::Redirect,
        "inform" => LocalZoneType::Inform,
        "inform_deny" => LocalZoneType::InformDeny,
        "nodefault" => LocalZoneType::Nodefault,
        "always_transparent" => LocalZoneType::AlwaysTransparent,
        "always_refuse" => LocalZoneType::AlwaysRefuse,
        "always_nxdomain" => LocalZoneType::AlwaysNxdomain,
        _ => return None,
    })
}

fn forwarder<'doc>(d: &'doc Element, ctx: &mut MapContext<'doc>) -> Option<(Uuid, Forwarder)> {
    let id = item_uuid(ctx, d);
    let kind = d.child("type").map(Element::text).unwrap_or_default();
    let tls = match kind.trim() {
        "forward" => false,
        "dot" => true,
        _ => return None,
    };
    ctx.consume(d.child("type")?);
    let server_el = ctx.child(d, "server")?;
    let address: IpAddr = parse_or_warn(ctx, server_el, &server_el.text(), "server")?;
    let domain = match ctx.non_empty(d, "domain") {
        Some(t) => Some(parse_or_warn::<DomainName>(ctx, d, &t, "domain")?),
        None => None,
    };
    let port = ctx.parse(d, "port");
    let tls_name = match ctx.non_empty(d, "verify") {
        Some(v) if tls => parse_or_warn::<DomainName>(ctx, d, &v, "TLS name"),
        Some(_) => {
            ctx.warn(
                d,
                Severity::Info,
                "certificate name ignored for a plain forwarder",
            );
            None
        }
        None => None,
    };
    if tls && tls_name.is_none() {
        ctx.warn(
            d,
            Severity::Degraded,
            "DNS over TLS without a certificate name to verify: sensr requires one, so this upstream is imported as plain DNS",
        );
    }
    let enabled = ctx.flag(d, "enabled");
    let descr = ctx.text(d, "description");
    ctx.defaults(d, &[("forward_tcp_upstream", "0"), ("forward_first", "0")]);
    Some((
        id,
        Forwarder {
            enabled,
            domain,
            address,
            port,
            tls_name,
            description: description(ctx, d, descr),
        },
    ))
}

fn host<'doc>(h: &'doc Element, ctx: &mut MapContext<'doc>) -> Option<(Uuid, HostOverride)> {
    let id = item_uuid(ctx, h);
    let rr = h.child("rr").map(Element::text).unwrap_or_default();
    let record = match rr.trim() {
        "A" | "AAAA" => {
            let s = h.child("server")?;
            let ip: IpAddr = parse_or_warn(ctx, s, &s.text(), "address")?;
            ctx.consume(s);
            match (rr.trim(), ip) {
                ("A", IpAddr::V4(address)) => DnsRecord::A { address },
                ("AAAA", IpAddr::V6(address)) => DnsRecord::Aaaa { address },
                _ => {
                    ctx.warn(
                        s,
                        Severity::Invalid,
                        format!("{ip} does not match record type {rr}"),
                    );
                    return None;
                }
            }
        }
        "MX" => {
            let priority = ctx.parse::<u16>(h, "mxprio")?;
            let host_el = ctx.child(h, "mx")?;
            let host: DomainName = parse_or_warn(ctx, host_el, &host_el.text(), "mail host")?;
            DnsRecord::Mx { priority, host }
        }
        "TXT" => DnsRecord::Txt {
            data: ctx.text(h, "txtdata")?,
        },
        _ => return None,
    };
    ctx.consume(h.child("rr")?);
    let hostname_text = ctx.text(h, "hostname").unwrap_or_default();
    let hostname: HostOverrideName = parse_or_warn(ctx, h, &hostname_text, "host name")?;
    let domain_el = ctx.child(h, "domain")?;
    let domain: DomainName = parse_or_warn(ctx, domain_el, &domain_el.text(), "domain")?;
    let ttl = ctx.parse(h, "ttl");
    let enabled = ctx.flag(h, "enabled");
    let descr = ctx.text(h, "description");
    // A/AAAA overrides publish the matching PTR by default.
    ctx.defaults(
        h,
        &[
            ("addptr", "1"),
            ("mxprio", ""),
            ("mx", ""),
            ("server", ""),
            ("txtdata", ""),
        ],
    );
    Some((
        id,
        HostOverride {
            enabled,
            hostname,
            domain,
            record,
            ttl,
            description: description(ctx, h, descr),
        },
    ))
}
