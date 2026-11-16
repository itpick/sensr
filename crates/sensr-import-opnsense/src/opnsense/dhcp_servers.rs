//! Which of OPNsense's three DHCPv4 servers (ISC `dhcpd`, dnsmasq, Kea) actually
//! serves, and reconciling what each of them contributed to sensr's single DHCPv4
//! service.
//!
//! OPNsense keeps the configuration of every server it ever had enabled: switching
//! from Kea back to ISC (or the other way round) leaves the other server's subnets
//! and reservations in `config.xml`, inert. Each server starts on its own
//! (`kea_configure_do()` only when `KeaDhcpv4::isEnabled()`, dhcpd per enabled
//! interface block, dnsmasq when enabled), so importing them all would serve
//! networks OPNsense does not serve and duplicate subnets the active server
//! already covers. The three mappers record what they inserted in a shared
//! [`Ledger`]; once all of them ran, [`reconcile`] keeps the active servers'
//! items and reports the rest as not imported.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::rc::Rc;

use sensr_schema::{Document, Uuid};

use crate::mapper::MapContext;
use crate::report::Severity;

/// One of the DHCPv4 servers, in ascending precedence for subnets that more than
/// one of them define.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Server {
    Dnsmasq,
    Isc,
    Kea,
}

impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Server::Dnsmasq => "dnsmasq",
            Server::Isc => "ISC DHCP",
            Server::Kea => "Kea DHCPv4",
        })
    }
}

#[derive(Debug)]
struct Item {
    server: Server,
    id: Uuid,
    xpath: String,
}

/// What each DHCPv4 mapper put into the document.
#[derive(Debug, Default)]
pub struct Ledger {
    active: Vec<Server>,
    subnets: Vec<Item>,
    reservations: Vec<Item>,
}

/// The ledger the DHCPv4 mappers share for one import.
pub type SharedLedger = Rc<RefCell<Ledger>>;

impl Ledger {
    /// `server` will serve DHCPv4 on the box.
    pub fn activate(&mut self, server: Server) {
        if !self.active.contains(&server) {
            self.active.push(server);
        }
    }

    /// The servers recorded so far that serve.
    pub fn active(&self) -> &[Server] {
        &self.active
    }

    /// `server` inserted subnet `id`, read from the element at `xpath`.
    pub fn subnet(&mut self, server: Server, id: Uuid, xpath: String) {
        self.subnets.push(Item { server, id, xpath });
    }

    /// `server` inserted reservation `id`, read from the element at `xpath`.
    pub fn reservation(&mut self, server: Server, id: Uuid, xpath: String) {
        self.reservations.push(Item { server, id, xpath });
    }
}

fn names(servers: &[Server]) -> String {
    let v: Vec<String> = servers.iter().map(ToString::to_string).collect();
    v.join(" and ")
}

/// Drop what inactive servers contributed while another server serves, then
/// resolve subnets defined by more than one server in favour of the one that
/// takes precedence ([`Server`] order), and finally reservations whose subnet
/// was dropped. Every dropped item gets a warning at its source element.
pub fn reconcile(ledger: Ledger, ctx: &mut MapContext<'_>, out: &mut Document) {
    let Ledger {
        active,
        subnets,
        reservations,
    } = ledger;
    let d = &mut out.dhcpv4;
    let mut dropped: HashSet<Uuid> = HashSet::new();

    if !active.is_empty() {
        let serving = names(&active);
        for item in subnets.iter().filter(|i| !active.contains(&i.server)) {
            if let Some(s) = d.subnets.remove(&item.id) {
                dropped.insert(item.id);
                ctx.warn_xpath(
                    item.xpath.clone(),
                    Severity::Info,
                    format!(
                        "{} is disabled and {serving} serves DHCPv4; its subnet {} is not imported",
                        item.server, s.subnet
                    ),
                );
            }
        }
        for item in reservations.iter().filter(|i| !active.contains(&i.server)) {
            if d.reservations.remove(&item.id).is_some() {
                ctx.warn_xpath(
                    item.xpath.clone(),
                    Severity::Info,
                    format!(
                        "{} is disabled and {serving} serves DHCPv4; this reservation is not imported",
                        item.server
                    ),
                );
            }
        }
    }

    // The same network from two servers: keep the one with precedence.
    let mut owner: HashMap<Uuid, Server> = HashMap::new();
    for item in &subnets {
        owner.entry(item.id).or_insert(item.server);
    }
    let mut best: HashMap<sensr_schema::ipnet::Ipv4Net, Server> = HashMap::new();
    for (id, s) in d.subnets.iter() {
        if let Some(&server) = owner.get(id) {
            let e = best.entry(s.subnet).or_insert(server);
            *e = (*e).max(server);
        }
    }
    for item in &subnets {
        let Some(s) = d.subnets.get(&item.id) else {
            continue;
        };
        let winner = best[&s.subnet];
        if winner == item.server {
            continue;
        }
        let net = s.subnet;
        d.subnets.remove(&item.id);
        dropped.insert(item.id);
        let both_serve = active.contains(&winner) && active.contains(&item.server);
        let (severity, message) = if both_serve {
            (
                Severity::Degraded,
                format!(
                    "both {winner} and {} serve {net}; OPNsense runs both daemons, sensr imports the {winner} subnet",
                    item.server
                ),
            )
        } else {
            (
                Severity::Info,
                format!("{winner} also defines {net}; its subnet is imported instead of this one"),
            )
        };
        ctx.warn_xpath(item.xpath.clone(), severity, message);
    }

    // Reservations whose subnet was dropped above.
    for item in &reservations {
        let Some(r) = d.reservations.get(&item.id) else {
            continue;
        };
        if dropped.contains(&r.subnet.id()) {
            d.reservations.remove(&item.id);
            ctx.warn_xpath(
                item.xpath.clone(),
                Severity::Info,
                "the subnet of this reservation is not imported, so neither is the reservation",
            );
        }
    }
}
