//! Device isolation: filter rules that lock selected clients out of the local
//! networks while leaving the router's own services and the internet
//! reachable.
//!
//! For every policy two quick rules are registered ahead of the user's rules:
//! a pass for the client's traffic to the firewall itself (DNS, DHCP, NTP,
//! the web GUI, anything the user later adds as a service there) and a block
//! to each internal network. Because they are quick and run first, a broad
//! "allow LAN to any" rule further down cannot undo the isolation. Traffic
//! leaving through a gateway (the internet) is untouched.

use crate::conf;
use crate::conf::Conf;
use crate::normalize::Context;
use crate::ruleset::Ruleset;

/// One policy, already stripped to what the rules need.
pub struct Policy<'a> {
    /// Interface the clients are attached to.
    pub interface: &'a str,
    /// Source operand as rules write it (`alias:guests`, a network, `net:lan`).
    pub source: &'a str,
    /// Invert the source.
    pub source_not: bool,
    /// Free text for rule labels.
    pub description: &'a str,
}

/// Registers the rules for every policy. Rules go immediately after the
/// system rules (priority 6) and before any rule the user wrote.
pub fn register(rs: &mut Ruleset, policies: &[Policy<'_>], ctx: &Context<'_>) {
    let internal: Vec<&String> = ctx
        .interfaces
        .iter()
        .filter(|(_, i)| i.is_internal())
        .map(|(name, _)| name)
        .collect();
    for p in policies {
        let descr = if p.description.is_empty() {
            format!("isolation on {}", p.interface)
        } else {
            p.description.to_owned()
        };
        let add = |rs: &mut Ruleset, to: &str, action: &'static str, what: &str, prio: u32| {
            let mut c: Conf = conf! {
                "interface" => p.interface,
                "direction" => "in",
                "quick" => true,
                "type" => action,
                "#ref" => "ui/firewall/isolation",
                "descr" => format!("{descr}: {what}"),
            };
            c.set("from", p.source);
            if p.source_not {
                c.set("from_not", true);
            }
            c.set("to", to);
            rs.register_filter(prio, &c, None, ctx);
        };
        // The router's own services stay reachable: DNS, DHCP, NTP, the GUI.
        add(rs, "(self)", "pass", "allow the router's own services", 6);
        for iface in &internal {
            add(rs, iface.as_str(), "block", &format!("block {iface}"), 6);
        }
    }
}
