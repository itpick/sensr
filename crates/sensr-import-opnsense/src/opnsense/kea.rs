//! `OPNsense/Kea/dhcp4`: the Kea DHCPv4 server.

use std::net::Ipv4Addr;

use sensr_schema::array::Relation;
use sensr_schema::fields::{DomainName, MacAddr};
use sensr_schema::ipnet::Ipv4Net;
use sensr_schema::models::dhcp::{ClientMatch, Dhcp4Options, Pool4, Reservation4, Subnet4};
use sensr_schema::{Document, Uuid};

use super::common::{description, interface_id, item_uuid, list, parse_or_warn};
use crate::mapper::{MapContext, Mapper};
use crate::report::Severity;
use crate::tree::Element;

pub struct KeaMapper;

impl Mapper<Document> for KeaMapper {
    fn name(&self) -> &'static str {
        "kea-dhcp4"
    }

    fn sections(&self) -> &'static [&'static str] {
        &["OPNsense/Kea/dhcp4"]
    }

    fn map<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        if let Some(g) = ctx.child(s, "general") {
            let enabled = ctx.flag(g, "enabled");
            if enabled && out.dhcpv4.enabled {
                ctx.warn(
                    g,
                    Severity::Degraded,
                    "both ISC DHCP and Kea are enabled; the Kea configuration wins",
                );
            }
            if enabled {
                out.dhcpv4.enabled = true;
            }
            if let Some(i) = g.child("interfaces") {
                ctx.consume(i);
                out.dhcpv4.interfaces.clear();
                for name in list(&i.text(), &[',']) {
                    match interface_id(out, &name) {
                        Some(id) => out.dhcpv4.interfaces.push(id),
                        None => ctx.warn(
                            i,
                            Severity::Invalid,
                            format!("interface {name:?} is not assigned"),
                        ),
                    }
                }
            }
            if let Some(v) = ctx.parse::<u32>(g, "valid_lifetime") {
                out.dhcpv4.valid_lifetime = v;
            }
            out.dhcpv4.firewall_rules = ctx.flag(g, "fwrules");
            ctx.defaults(
                g,
                &[
                    ("manual_config", "0"),
                    ("dhcp_socket_type", "raw"),
                    ("compatibility", ""),
                    ("service_sockets_max_retries", ""),
                    ("service_sockets_retry_wait_time", ""),
                    ("decline_probation_period", ""),
                ],
            );
        }
        if let Some(subnets) = ctx.child(s, "subnets") {
            for sn in ctx.children(subnets, "subnet4") {
                if let Some((id, subnet)) = map_subnet(sn, ctx, out) {
                    out.dhcpv4.subnets.insert(id, subnet);
                } else {
                    ctx.release(sn);
                }
            }
        }
        // Custom option definitions and HA peers: empty unless used (then reported).
        ctx.defaults(s, &[("options", ""), ("ha_peers", "")]);
        if let Some(res) = ctx.child(s, "reservations") {
            for r in ctx.children(res, "reservation") {
                if let Some((id, reservation)) = map_reservation(r, ctx) {
                    out.dhcpv4.reservations.insert(id, reservation);
                } else {
                    ctx.release(r);
                }
            }
        }
    }
}

fn addrs(ctx: &mut MapContext<'_>, at: &Element, text: &str) -> Vec<Ipv4Addr> {
    list(text, &[','])
        .iter()
        .filter_map(|a| parse_or_warn(ctx, at, a, "IPv4 address"))
        .collect()
}

fn map_subnet<'doc>(
    sn: &'doc Element,
    ctx: &mut MapContext<'doc>,
    out: &Document,
) -> Option<(Uuid, Subnet4)> {
    let id = item_uuid(ctx, sn);
    let net_el = ctx.child(sn, "subnet")?;
    let net: Ipv4Net = parse_or_warn(ctx, net_el, &net_el.text(), "subnet")?;
    let mut subnet = Subnet4::new(net);
    if let Some(i) = ctx.non_empty(sn, "interface") {
        subnet.interface = interface_id(out, &i);
        if subnet.interface.is_none() {
            ctx.warn(
                sn,
                Severity::Invalid,
                format!("subnet interface {i:?} is not assigned"),
            );
        }
    }
    if let Some(p) = sn.child("pools") {
        ctx.consume(p);
        for pool in list(&p.text(), &['\n', ',']) {
            subnet
                .pools
                .extend(parse_or_warn::<Pool4>(ctx, p, &pool, "pool"));
        }
    }
    subnet.valid_lifetime = ctx.parse(sn, "valid_lifetime");
    subnet.next_server = ctx.parse(sn, "next_server");
    subnet.auto_options = ctx.flag(sn, "option_data_autocollect");
    subnet.match_client_id = match sn.child("match-client-id") {
        Some(_) => ctx.flag(sn, "match-client-id"),
        None => true,
    };
    if let Some(o) = ctx.child(sn, "option_data") {
        subnet.options = options(o, ctx);
    }
    let descr = ctx.text(sn, "description");
    subnet.description = description(ctx, sn, descr);
    // Kea assigns subnet ids itself in sensr's renderer; DDNS and ping-check are off
    // unless set.
    if let Some(i) = sn.child("subnet_id") {
        ctx.consume(i);
    }
    ctx.defaults(
        sn,
        &[
            ("ping_check", "0"),
            ("match_code", ""),
            ("match_encoding", ""),
            ("match_data", ""),
            ("allocator", ""),
            ("option", ""),
            ("ddns_forward_zone", ""),
            ("ddns_reverse_zone", ""),
            ("ddns_qualifying_suffix", ""),
            ("ddns_dns_server", ""),
            ("ddns_dns_port", ""),
            ("ddns_domain_key_name", ""),
            ("ddns_domain_key_secret", ""),
            ("ddns_domain_key_algorithm", ""),
            ("ddns_override_no_update", "0"),
            ("ddns_override_client_update", "0"),
            ("ddns_update_on_renew", "0"),
            ("ddns_conflict_resolution_mode", ""),
        ],
    );
    Some((id, subnet))
}

fn options<'doc>(o: &'doc Element, ctx: &mut MapContext<'doc>) -> Dhcp4Options {
    let mut opts = Dhcp4Options::default();
    if let Some(t) = ctx.text(o, "routers") {
        opts.routers = addrs(ctx, o, &t);
    }
    if let Some(t) = ctx.text(o, "domain_name_servers") {
        opts.dns_servers = addrs(ctx, o, &t);
    }
    if let Some(t) = ctx.text(o, "ntp_servers") {
        opts.ntp_servers = addrs(ctx, o, &t);
    }
    if let Some(t) = ctx.non_empty(o, "domain_name") {
        opts.domain_name = parse_or_warn::<DomainName>(ctx, o, &t, "domain name");
    }
    if let Some(t) = ctx.text(o, "domain_search") {
        opts.domain_search = list(&t, &[','])
            .iter()
            .filter_map(|d| parse_or_warn(ctx, o, d, "search domain"))
            .collect();
    }
    opts.tftp_server_name = ctx.non_empty(o, "tftp_server_name");
    opts.boot_file_name = ctx.non_empty(o, "boot_file_name");
    opts.v6_only_preferred = ctx.parse(o, "v6_only_preferred");
    ctx.defaults(
        o,
        &[
            ("static_routes", ""),
            ("classless_static_route", ""),
            ("time_servers", ""),
            ("v4_dnr", ""),
        ],
    );
    opts
}

fn map_reservation<'doc>(
    r: &'doc Element,
    ctx: &mut MapContext<'doc>,
) -> Option<(Uuid, Reservation4)> {
    let id = item_uuid(ctx, r);
    let subnet_el = ctx.child(r, "subnet")?;
    let subnet: Uuid = parse_or_warn(ctx, subnet_el, &subnet_el.text(), "subnet reference")?;
    let client = if let Some(mac) = ctx.non_empty(r, "hw_address") {
        ClientMatch::HwAddress(parse_or_warn::<MacAddr>(ctx, r, &mac, "MAC address")?)
    } else if let Some(cid) = ctx.non_empty(r, "client_id") {
        ClientMatch::ClientId(parse_or_warn(ctx, r, &cid, "client id")?)
    } else {
        ctx.warn(
            r,
            Severity::Invalid,
            "reservation without MAC address or client id not imported",
        );
        return None;
    };
    let ip_address = ctx.parse(r, "ip_address");
    let hostname = match ctx.non_empty(r, "hostname") {
        Some(h) => parse_or_warn(ctx, r, &h, "host name"),
        None => None,
    };
    let descr = ctx.text(r, "description");
    ctx.defaults(r, &[("client_id", ""), ("next_server", ""), ("option", "")]);
    if let Some(o) = r.child("option_data") {
        // Per-reservation options are not modelled; an empty block is fine.
        if o.elements().all(|e| e.text().trim().is_empty()) {
            ctx.consume_subtree(o);
        } else {
            ctx.consume(o);
            ctx.defaults(
                o,
                &[
                    ("domain_name_servers", ""),
                    ("domain_search", ""),
                    ("routers", ""),
                    ("static_routes", ""),
                    ("classless_static_route", ""),
                    ("domain_name", ""),
                    ("ntp_servers", ""),
                    ("time_servers", ""),
                    ("tftp_server_name", ""),
                    ("boot_file_name", ""),
                    ("v4_dnr", ""),
                ],
            );
        }
    }
    Some((
        id,
        Reservation4 {
            subnet: Relation::new(subnet),
            client,
            ip_address,
            hostname,
            description: description(ctx, r, descr),
        },
    ))
}
