//! `OPNsense/unboundplus`: the Unbound DNS resolver.

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use ipnet::IpNet;
use sensr_schema::fields::{Description, DomainName, HostOverrideName, HttpUrl, InterfaceId};
use sensr_schema::models::dns::{
    AccessAction, AccessList, CacheSize, DnsRecord, Forwarder, HostOverride, LocalZoneType, Tuning,
};
use sensr_schema::models::dnsbl::{AllowEntry, BlockAnswer, Blocklist, KnownList};
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
        if let Some(a) = ctx.child(s, "advanced") {
            advanced(a, ctx, out);
        }
        if let Some(a) = ctx.child(s, "acls") {
            acls(a, ctx, out);
        }
        if let Some(d) = ctx.child(s, "dnsbl") {
            for b in ctx.children(d, "blocklist") {
                match blocklist(b, ctx) {
                    Some((id, bl)) => {
                        out.dns.blocklists.insert(id, bl);
                    }
                    None => ctx.release(b),
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
    dns.statistics = ctx.bool01(g, "stats");
    dns.dns64_prefix = ctx.parse(g, "dns64prefix");
    if g.child("noregrecords").is_some() {
        dns.register_firewall_records = !ctx.bool01(g, "noregrecords");
    }
    dns.txt_descriptions = ctx.bool01(g, "txtsupport");
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
            ("noarecords", "0"),
            ("noreglladdr6", "0"),
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
    // Configs from before `addptr` existed published the PTR.
    let ptr = h.child("addptr").is_none() || ctx.bool01(h, "addptr");
    ctx.defaults(
        h,
        &[("mxprio", ""), ("mx", ""), ("server", ""), ("txtdata", "")],
    );
    Some((
        id,
        HostOverride {
            enabled,
            hostname,
            domain,
            record,
            ttl,
            ptr,
            description: description(ctx, h, descr),
        },
    ))
}

/// A comma-separated leaf parsed item by item; bad items are reported and
/// skipped.
fn csv<'doc, T: FromStr>(
    ctx: &mut MapContext<'doc>,
    parent: &'doc Element,
    name: &str,
    what: &str,
) -> Vec<T>
where
    T::Err: std::fmt::Display,
{
    let Some(el) = parent.child(name) else {
        return Vec::new();
    };
    let text = ctx.text(parent, name).unwrap_or_default();
    list(&text, &[','])
        .iter()
        .filter_map(|t| parse_or_warn(ctx, el, t, what))
        .collect()
}

fn advanced<'doc>(a: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
    let mut t = Tuning {
        hide_identity: ctx.bool01(a, "hideidentity"),
        hide_version: ctx.bool01(a, "hideversion"),
        prefetch: ctx.bool01(a, "prefetch"),
        prefetch_key: ctx.bool01(a, "prefetchkey"),
        harden_dnssec_stripped: ctx.bool01(a, "dnssecstripped"),
        serve_expired: ctx.bool01(a, "serveexpired"),
        serve_expired_reply_ttl: ctx.parse(a, "serveexpiredreplyttl"),
        serve_expired_ttl: ctx.parse(a, "serveexpiredttl"),
        serve_expired_ttl_reset: ctx.bool01(a, "serveexpiredttlreset"),
        serve_expired_client_timeout: ctx.parse(a, "serveexpiredclienttimeout"),
        qname_minimisation_strict: ctx.bool01(a, "qnameminstrict"),
        extended_statistics: ctx.bool01(a, "extendedstatistics"),
        log_queries: ctx.bool01(a, "logqueries"),
        log_replies: ctx.bool01(a, "logreplies"),
        log_tag_query_reply: ctx.bool01(a, "logtagqueryreply"),
        log_servfail: ctx.bool01(a, "logservfail"),
        log_local_actions: ctx.bool01(a, "loglocalactions"),
        private_domains: csv(ctx, a, "privatedomain", "private domain"),
        insecure_domains: csv(ctx, a, "insecuredomain", "insecure domain"),
        msg_cache_size: ctx.parse::<CacheSize>(a, "msgcachesize"),
        rrset_cache_size: ctx.parse::<CacheSize>(a, "rrsetcachesize"),
        outgoing_num_tcp: ctx.parse(a, "outgoingnumtcp"),
        incoming_num_tcp: ctx.parse(a, "incomingnumtcp"),
        num_queries_per_thread: ctx.parse(a, "numqueriesperthread"),
        outgoing_range: ctx.parse(a, "outgoingrange"),
        jostle_timeout: ctx.parse(a, "jostletimeout"),
        discard_timeout: ctx.parse(a, "discardtimeout"),
        cache_max_ttl: ctx.parse(a, "cachemaxttl"),
        cache_max_negative_ttl: ctx.parse(a, "cachemaxnegativettl"),
        cache_min_ttl: ctx.parse(a, "cacheminttl"),
        infra_host_ttl: ctx.parse(a, "infrahostttl"),
        infra_keep_probing: ctx.bool01(a, "infrakeepprobing"),
        infra_cache_numhosts: ctx.parse(a, "infracachenumhosts"),
        unwanted_reply_threshold: ctx.parse(a, "unwantedreplythreshold"),
        ..Tuning::default()
    };
    // Both default to on: absent or empty keeps the default.
    for (leaf, field) in [
        ("belownxdomain", &mut t.harden_below_nxdomain),
        ("aggressivensec", &mut t.aggressive_nsec),
    ] {
        if let Some(v) = ctx.text(a, leaf).filter(|v| !v.trim().is_empty()) {
            *field = v.trim() == "1";
        }
    }
    if let Some(v) = ctx.parse::<u8>(a, "logverbosity") {
        t.log_verbosity = v;
    }
    t.val_log_level = ctx.parse::<u8>(a, "valloglevel").filter(|v| *v != 0);
    if a.child("privateaddress").is_some() {
        // Required in OPNsense: an empty list is rebinding protection off.
        t.private_addresses = csv::<IpNet>(ctx, a, "privateaddress", "private address");
    }
    out.dns.tuning = t;
}

fn access_action(t: &str) -> Option<AccessAction> {
    Some(match t.trim() {
        "allow" => AccessAction::Allow,
        "deny" => AccessAction::Deny,
        "refuse" => AccessAction::Refuse,
        "allow_snoop" => AccessAction::AllowSnoop,
        "deny_non_local" => AccessAction::DenyNonLocal,
        "refuse_non_local" => AccessAction::RefuseNonLocal,
        _ => return None,
    })
}

fn acls<'doc>(a: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
    if let Some(d) = a.child("default_action") {
        match access_action(&d.text()) {
            Some(v) => {
                ctx.consume(d);
                out.dns.access.default_action = v;
            }
            None if d.text().trim().is_empty() => ctx.consume(d),
            None => {}
        }
    }
    for l in ctx.children(a, "acl") {
        let id = item_uuid(ctx, l);
        let action = match l.child("action") {
            Some(e) => match access_action(&e.text()) {
                Some(v) => {
                    ctx.consume(e);
                    v
                }
                None => {
                    ctx.release(l);
                    continue;
                }
            },
            None => AccessAction::Allow,
        };
        let enabled = l.child("enabled").is_none() || ctx.bool01(l, "enabled");
        let networks = csv::<IpNet>(ctx, l, "networks", "network");
        let name_text = ctx.text(l, "name").unwrap_or_default();
        let descr = ctx.text(l, "description");
        let Some(name) = parse_or_warn::<Description>(ctx, l, &name_text, "name") else {
            ctx.release(l);
            continue;
        };
        if networks.is_empty() {
            ctx.warn(
                l,
                Severity::Invalid,
                "access list without networks not imported",
            );
            continue;
        }
        out.dns.access.lists.insert(
            id,
            AccessList {
                enabled,
                name,
                action,
                networks,
                description: description(ctx, l, descr),
            },
        );
    }
}

/// An OPNsense allowlist item. They are regular expressions, but nearly
/// always written as plain names, which mean exactly that name.
fn allow_entry(t: &str) -> AllowEntry {
    let t = t.trim();
    if let Ok(d) = t.trim_end_matches('.').parse::<DomainName>() {
        return AllowEntry::Domain(d);
    }
    AllowEntry::Pattern(t.to_owned())
}

fn blocklist<'doc>(b: &'doc Element, ctx: &mut MapContext<'doc>) -> Option<(Uuid, Blocklist)> {
    let id = item_uuid(ctx, b);
    let descr_text = ctx.text(b, "description");
    let description = description(ctx, b, descr_text).or_else(|| {
        ctx.warn(
            b,
            Severity::Info,
            "blocklist without a description; named \"Blocklist\"",
        );
        "Blocklist".parse().ok()
    })?;
    let mut bl = Blocklist::new(description);
    bl.enabled = b.child("enabled").is_none() || ctx.bool01(b, "enabled");
    if let Some(el) = b.child("type") {
        let text = ctx.text(b, "type").unwrap_or_default();
        for code in list(&text, &[',']) {
            match KnownList::from_opnsense_code(&code) {
                Some(l) => bl.lists.push(l),
                None => ctx.warn(
                    el,
                    Severity::Degraded,
                    format!("blocklist {code:?} is not known to sensr; add its URL instead"),
                ),
            }
        }
    }
    bl.urls = csv::<HttpUrl>(ctx, b, "lists", "list URL");
    if let Some(el) = b.child("allowlists") {
        let text = ctx.text(b, "allowlists").unwrap_or_default();
        for t in list(&text, &[',']) {
            match allow_entry(&t) {
                AllowEntry::Pattern(p) => match format!("/{p}/").parse::<AllowEntry>() {
                    Ok(e) => bl.allow.push(e),
                    Err(e) => ctx.warn(
                        el,
                        Severity::Invalid,
                        format!("allowlist pattern {p:?} not imported: {e}"),
                    ),
                },
                e => bl.allow.push(e),
            }
        }
    }
    bl.block = csv(ctx, b, "blocklists", "blocked domain");
    bl.block_subtrees = csv(ctx, b, "wildcards", "wildcard domain");
    bl.source_nets = csv(ctx, b, "source_nets", "source network");
    let nxdomain = ctx.bool01(b, "nxdomain");
    let address = ctx.parse::<Ipv4Addr>(b, "address");
    bl.answer = if nxdomain {
        BlockAnswer::Nxdomain
    } else {
        BlockAnswer::Address {
            address: address.unwrap_or(Ipv4Addr::UNSPECIFIED),
        }
    };
    if let Some(ttl) = ctx.parse::<u32>(b, "cache_ttl") {
        bl.refresh_seconds = ttl;
    }
    Some((id, bl))
}
