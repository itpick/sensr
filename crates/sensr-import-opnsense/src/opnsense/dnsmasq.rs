//! `dnsmasq`: the DHCP server of newer OPNsense factory configs (Dnsmasq model).
//! Its DHCPv4 ranges and static hosts map into the DHCPv4 model; its own DNS
//! service is not imported (sensr's resolver is Unbound), and DHCPv6/RA ranges stay
//! reported until sensr models them.

use std::net::IpAddr;

use sensr_schema::array::Relation;
use sensr_schema::fields::MacAddr;
use sensr_schema::models::dhcp::{ClientMatch, Pool4, Reservation4, Subnet4};
use sensr_schema::models::interfaces::Ipv4Config;
use sensr_schema::{Document, Uuid};

use super::common::{description, interface_id, item_uuid, parse_or_warn, stable_uuid};
use super::dhcp_servers::{Ledger, Server, SharedLedger};
use crate::mapper::{MapContext, Mapper};
use crate::report::Severity;
use crate::tree::Element;

/// The global settings of the Dnsmasq model (`Dnsmasq.xml`). With dnsmasq disabled
/// they are leftover form state; enabled, sensr does not model them yet, so they
/// stay reported.
const GLOBAL_SETTINGS: &[&str] = &[
    "regdhcp",
    "regdhcpstatic",
    "dhcpfirst",
    "strict_order",
    "domain_needed",
    "no_private_reverse",
    "no_resolv",
    "log_queries",
    "no_hosts",
    "expand_hosts",
    "strictbind",
    "dnssec",
    "regdhcpdomain",
    "dns_port",
    "dns_forward_max",
    "cache_size",
    "local_ttl",
    "add_mac",
    "add_subnet",
    "strip_subnet",
    "no_ident",
];

pub struct DnsmasqMapper {
    ledger: SharedLedger,
}

impl DnsmasqMapper {
    pub fn new(ledger: SharedLedger) -> Self {
        Self { ledger }
    }
}

fn subnet_id(id: &sensr_schema::fields::InterfaceId) -> Uuid {
    stable_uuid(&format!("dnsmasq-subnet:{id}"))
}

impl Mapper<Document> for DnsmasqMapper {
    fn name(&self) -> &'static str {
        "dnsmasq-dhcp"
    }

    fn sections(&self) -> &'static [&'static str] {
        &["dnsmasq"]
    }

    fn map<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        let enabled = ctx.flag(s, "enable");
        if let Some(p) = s.child("port") {
            ctx.consume(p);
            if enabled && p.text().trim() != "0" {
                ctx.warn(
                    p,
                    Severity::Info,
                    "dnsmasq's DNS service is not imported; Unbound answers DNS in sensr",
                );
            }
        }
        // Interfaces dnsmasq listens on; DHCP service follows the ranges below.
        if let Some(i) = s.child("interface") {
            ctx.consume(i);
        }
        let mut served = Vec::new();
        for r in s.children_named("dhcp_ranges") {
            let start = r.child("start_addr").map(Element::text).unwrap_or_default();
            if r.child("constructor").is_some()
                || start.parse::<std::net::Ipv6Addr>().is_ok()
                || start.starts_with("::")
            {
                continue; // DHCPv6 / RA: reported.
            }
            ctx.consume(r);
            if let Some(id) = range(r, ctx, out, &mut self.ledger.borrow_mut()) {
                served.push(id);
            } else {
                ctx.release(r);
            }
        }
        for h in s.children_named("hosts") {
            ctx.consume(h);
            if !host(h, ctx, out, &mut self.ledger.borrow_mut()) {
                ctx.release(h);
            }
        }
        if enabled && !served.is_empty() {
            self.ledger.borrow_mut().activate(Server::Dnsmasq);
            out.dhcpv4.enabled = true;
            for id in served {
                if !out.dhcpv4.interfaces.contains(&id) {
                    out.dhcpv4.interfaces.push(id);
                }
            }
        }
        if !enabled {
            for name in GLOBAL_SETTINGS {
                for c in s.children_named(name) {
                    ctx.consume_subtree(c);
                }
            }
        }
        if let Some(d) = s.child("dhcp") {
            ctx.consume(d);
            if !enabled {
                ctx.consume_subtree(d);
            }
            ctx.defaults(
                d,
                &[
                    ("no_interface", ""),
                    ("fqdn", "1"),
                    ("domain", ""),
                    ("local", "1"),
                    ("lease_max", ""),
                    ("authoritative", "0"),
                    ("default_fw_rules", "1"),
                    ("reply_delay", ""),
                    ("host_ping", "1"),
                    ("nosync", "0"),
                    ("log_dhcp", "0"),
                    ("log_quiet", "0"),
                ],
            );
        }
    }
}

fn range<'doc>(
    r: &'doc Element,
    ctx: &mut MapContext<'doc>,
    out: &mut Document,
    ledger: &mut Ledger,
) -> Option<sensr_schema::fields::InterfaceId> {
    let if_el = ctx.child(r, "interface")?;
    let id = interface_id(out, if_el.text().trim())?;
    let Some(net) = out.interfaces.get(&id).and_then(|i| match &i.ipv4 {
        Ipv4Config::Static { address, .. } => Some(address.trunc()),
        _ => None,
    }) else {
        ctx.warn(
            r,
            Severity::Invalid,
            format!("DHCP range on {id} needs a static IPv4 address; not imported"),
        );
        return None;
    };
    let start = ctx.parse(r, "start_addr")?;
    let end = ctx.parse(r, "end_addr")?;
    let pool = match Pool4::new(start, end) {
        Ok(p) => p,
        Err(e) => {
            ctx.warn(r, Severity::Invalid, format!("range not imported: {e}"));
            return None;
        }
    };
    let lease = ctx.parse::<u32>(r, "lease_time");
    let descr = ctx.text(r, "description");
    let descr = description(ctx, r, descr);
    ctx.defaults(
        r,
        &[
            ("set_tag", ""),
            ("subnet_mask", ""),
            ("mode", ""),
            ("domain_type", ""),
            ("domain", ""),
            ("nosync", "0"),
        ],
    );
    // One subnet per interface; further ranges add pools to it.
    let subnet_id = subnet_id(&id);
    match out.dhcpv4.subnets.get_mut(&subnet_id) {
        Some(s) => s.pools.push(pool),
        None => {
            let mut s = Subnet4::new(net);
            s.interface = Some(id.clone());
            s.pools.push(pool);
            s.valid_lifetime = lease;
            s.description = descr;
            out.dhcpv4.subnets.insert(subnet_id, s);
            ledger.subnet(Server::Dnsmasq, subnet_id, ctx.xpath(r));
        }
    }
    Some(id)
}

fn host<'doc>(
    h: &'doc Element,
    ctx: &mut MapContext<'doc>,
    out: &mut Document,
    ledger: &mut Ledger,
) -> bool {
    let id = item_uuid(ctx, h);
    let Some(mac) = ctx.non_empty(h, "hwaddr") else {
        return false;
    };
    let Some(mac) = parse_or_warn::<MacAddr>(ctx, h, &mac, "MAC address") else {
        return false;
    };
    let ip: Option<IpAddr> = ctx.parse(h, "ip");
    let Some(IpAddr::V4(ip)) = ip else {
        return false;
    };
    // dnsmasq's own range subnet first: another server may define the same network.
    let own = out.dhcpv4.subnets.iter().find(|(sid, s)| {
        s.subnet.contains(&ip) && s.interface.as_ref().is_some_and(|i| **sid == subnet_id(i))
    });
    let Some((subnet, _)) = own.or_else(|| out.dhcpv4.subnet_for(ip)) else {
        ctx.warn(
            h,
            Severity::Invalid,
            format!("{ip} is in no DHCP range's subnet; reservation not imported"),
        );
        return false;
    };
    let subnet: Uuid = *subnet;
    let hostname = match ctx.non_empty(h, "host") {
        Some(n) => parse_or_warn(ctx, h, &n, "host name"),
        None => None,
    };
    let descr = ctx.text(h, "descr");
    let descr = description(ctx, h, descr);
    ctx.defaults(
        h,
        &[
            ("domain", ""),
            ("local", "0"),
            ("cnames", ""),
            ("client_id", ""),
            ("lease_time", ""),
            ("ignore", "0"),
            ("set_tag", ""),
            ("comments", ""),
            ("aliases", ""),
        ],
    );
    ledger.reservation(Server::Dnsmasq, id, ctx.xpath(h));
    out.dhcpv4.reservations.insert(
        id,
        Reservation4 {
            subnet: Relation::new(subnet),
            client: ClientMatch::HwAddress(mac),
            ip_address: Some(ip),
            hostname,
            description: descr,
        },
    );
    true
}
