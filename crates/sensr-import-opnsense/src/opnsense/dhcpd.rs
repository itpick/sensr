//! `dhcpd`: the legacy ISC DHCPv4 server (`services_dhcp.php`), one block per
//! interface. Mapped into the same DHCPv4 model as Kea; the subnet is the served
//! interface's network.

use std::net::Ipv4Addr;

use sensr_schema::Document;
use sensr_schema::array::Relation;
use sensr_schema::fields::{DomainName, MacAddr};
use sensr_schema::models::dhcp::{ClientMatch, Pool4, Reservation4, Subnet4};
use sensr_schema::models::interfaces::Ipv4Config;

use super::common::{description, interface_id, item_uuid, list, parse_or_warn};
use super::dhcp_servers::{Server, SharedLedger};
use crate::mapper::{MapContext, Mapper};
use crate::report::Severity;
use crate::tree::Element;

/// dhcpd's own `default-lease-time` when an interface sets none (`dhcpd.inc`).
const DEFAULT_LEASE: u32 = 7200;

pub struct DhcpdMapper {
    ledger: SharedLedger,
}

impl DhcpdMapper {
    pub fn new(ledger: SharedLedger) -> Self {
        Self { ledger }
    }
}

impl Mapper<Document> for DhcpdMapper {
    fn name(&self) -> &'static str {
        "isc-dhcpd"
    }

    fn sections(&self) -> &'static [&'static str] {
        &["dhcpd"]
    }

    fn map<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        for block in s.elements() {
            ctx.consume(block);
            let Some(id) = interface_id(out, &block.name) else {
                ctx.release(block);
                continue;
            };
            let enabled = ctx.flag(block, "enable");
            let Some(net) = out.interfaces.get(&id).and_then(|i| match &i.ipv4 {
                Ipv4Config::Static { address, .. } => Some(address.trunc()),
                _ => None,
            }) else {
                if enabled {
                    ctx.warn(
                        block,
                        Severity::Invalid,
                        format!("DHCP on {id} needs a static IPv4 address; not imported"),
                    );
                    ctx.release(block);
                } else {
                    // A disabled block for an interface without a static address is
                    // leftover form state.
                    ctx.consume_subtree(block);
                }
                continue;
            };
            if enabled {
                self.ledger.borrow_mut().activate(Server::Isc);
                out.dhcpv4.enabled = true;
                if !out.dhcpv4.interfaces.contains(&id) {
                    out.dhcpv4.interfaces.push(id.clone());
                }
            }
            let mut subnet = Subnet4::new(net);
            subnet.interface = Some(id.clone());
            if let Some(r) = ctx.child(block, "range") {
                let from = ctx.parse::<Ipv4Addr>(r, "from");
                let to = ctx.parse::<Ipv4Addr>(r, "to");
                if let (Some(a), Some(b)) = (from, to) {
                    match Pool4::new(a, b) {
                        Ok(p) => subnet.pools.push(p),
                        Err(e) => {
                            ctx.warn(r, Severity::Invalid, format!("range not imported: {e}"))
                        }
                    }
                }
            }
            if let Some(g) = ctx.non_empty(block, "gateway") {
                subnet
                    .options
                    .routers
                    .extend(parse_or_warn::<Ipv4Addr>(ctx, block, &g, "gateway"));
            }
            for d in ctx.children(block, "dnsserver") {
                let t = d.text();
                if !t.trim().is_empty() {
                    subnet.options.dns_servers.extend(parse_or_warn::<Ipv4Addr>(
                        ctx,
                        d,
                        &t,
                        "DNS server",
                    ));
                }
            }
            for n in ctx.children(block, "ntpserver") {
                let t = n.text();
                if !t.trim().is_empty() {
                    subnet.options.ntp_servers.extend(parse_or_warn::<Ipv4Addr>(
                        ctx,
                        n,
                        &t,
                        "NTP server",
                    ));
                }
            }
            if let Some(d) = ctx.non_empty(block, "domain") {
                subnet.options.domain_name = parse_or_warn::<DomainName>(ctx, block, &d, "domain");
            }
            if let Some(d) = ctx.non_empty(block, "domainsearchlist") {
                subnet.options.domain_search = list(&d, &[';', ' ', ','])
                    .iter()
                    .filter_map(|x| parse_or_warn(ctx, block, x, "search domain"))
                    .collect();
            }
            subnet.valid_lifetime = Some(
                ctx.parse(block, "defaultleasetime")
                    .unwrap_or(DEFAULT_LEASE),
            );
            let descr = ctx.text(block, "descr");
            subnet.description = description(ctx, block, descr);
            // Without explicit options ISC hands out the interface address.
            subnet.auto_options = true;
            let subnet_id = item_uuid(ctx, block);
            let reservations: Vec<_> = ctx
                .children(block, "staticmap")
                .into_iter()
                .filter_map(|m| static_map(m, ctx, subnet_id))
                .collect();
            out.dhcpv4.subnets.insert(subnet_id, subnet);
            let mut ledger = self.ledger.borrow_mut();
            ledger.subnet(Server::Isc, subnet_id, ctx.xpath(block));
            for (rid, xpath, r) in reservations {
                ledger.reservation(Server::Isc, rid, xpath);
                out.dhcpv4.reservations.insert(rid, r);
            }
            drop(ledger);
            ctx.defaults(
                block,
                &[
                    ("maxleasetime", ""),
                    ("winsserver", ""),
                    ("ddnsdomain", ""),
                    ("ddnsupdate", ""),
                    ("mac_allow", ""),
                    ("mac_deny", ""),
                    ("tftp", ""),
                    ("bootfilename", ""),
                    ("ldap", ""),
                    ("netboot", ""),
                    ("nextserver", ""),
                    ("filename", ""),
                    ("rootpath", ""),
                    ("failover_peerip", ""),
                    ("failover_split", ""),
                    ("denyunknown", ""),
                    ("ignoreuids", ""),
                    ("staticarp", ""),
                    // The key algorithm select always posts a value.
                    ("ddnsdomainalgorithm", "hmac-md5"),
                    ("ddnsdomainprimary", ""),
                    ("ddnsdomainkeyname", ""),
                    ("ddnsdomainkey", ""),
                    ("filename32", ""),
                    ("filename64", ""),
                    ("filename32arm", ""),
                    ("filename64arm", ""),
                    ("filenameipxe", ""),
                    ("netmask", ""),
                    ("interface_mtu", ""),
                    ("wpad", ""),
                    ("omapi", ""),
                    ("omapiport", ""),
                    ("omapialgorithm", ""),
                    ("omapikey", ""),
                    ("minsecs", ""),
                ],
            );
            // Additional options: the form saves an empty row as `<item/>`.
            ctx.blank(block, &["numberoptions"]);
        }
    }
}

fn static_map<'doc>(
    m: &'doc Element,
    ctx: &mut MapContext<'doc>,
    subnet: sensr_schema::Uuid,
) -> Option<(sensr_schema::Uuid, String, Reservation4)> {
    let id = item_uuid(ctx, m);
    let client = if let Some(mac) = ctx.non_empty(m, "mac") {
        ClientMatch::HwAddress(parse_or_warn::<MacAddr>(ctx, m, &mac, "MAC address")?)
    } else if let Some(cid) = ctx.non_empty(m, "cid") {
        ClientMatch::ClientId(parse_or_warn(ctx, m, &cid, "client id")?)
    } else {
        ctx.warn(
            m,
            Severity::Invalid,
            "static mapping without MAC address or client id not imported",
        );
        ctx.release(m);
        return None;
    };
    let ip_address = ctx.parse(m, "ipaddr");
    let hostname = match ctx.non_empty(m, "hostname") {
        Some(h) => parse_or_warn(ctx, m, &h, "host name"),
        None => None,
    };
    let descr = ctx.text(m, "descr");
    // Per-host options (`services_dhcp_edit.php`) are not modelled on a
    // reservation: empty ones (the form always writes the server lists) are unset,
    // set ones stay reported.
    ctx.defaults(
        m,
        &[
            ("cid", ""),
            ("filename", ""),
            ("rootpath", ""),
            ("defaultleasetime", ""),
            ("maxleasetime", ""),
            ("arp_table_static_entry", ""),
            ("gateway", ""),
            ("domain", ""),
            ("domainsearchlist", ""),
            ("ddnsdomain", ""),
            ("tftp", ""),
            ("bootfilename", ""),
            ("winsserver", ""),
            ("dnsserver", ""),
            ("ntpserver", ""),
        ],
    );
    Some((
        id,
        ctx.xpath(m),
        Reservation4 {
            subnet: Relation::new(subnet),
            client,
            ip_address,
            hostname,
            description: description(ctx, m, descr),
        },
    ))
}
