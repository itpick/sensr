//! Policy routing (pf `route-to` / `reply-to`) as packet marks.
//!
//! pf routes a packet at filter time; Linux decides the route before the
//! filter, from the packet mark and `ip rule fwmark … lookup <table>`. So a
//! `route_pre` chain (prerouting, mangle priority) re-evaluates the inbound
//! rules that decide a connection's gateway and marks it; the mark is kept in
//! the conntrack mark and restored on every later packet. Multi-WAN replies
//! (`reply-to`) work the same way in the other direction: a connection that
//! arrived on a WAN is marked with that WAN's gateway, and its reply packets
//! are routed back out of it.
//!
//! Mark layout (32 bits, shared by skb and conntrack marks):
//!
//! | bits | use |
//! |---|---|
//! | `0x0000_0001` | `rdr pass` (filter skipped for the redirected connection) |
//! | `0x0000_ff00` | route-to target, original direction |
//! | `0x00ff_0000` | reply-to target, reply direction (`>> 8` gives the route mark) |
//!
//! The routing layer installs, for every target, `ip rule fwmark
//! <mark>/0xff00 lookup <table>` and a table whose default route is the
//! gateway (or the active member of a gateway group).

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::Serialize;

/// `rdr pass` connections.
pub const RDR_PASS_MARK: u32 = 0x0000_0001;
/// Route-to target bits.
pub const ROUTE_MASK: u32 = 0x0000_ff00;
/// Reply-to target bits.
pub const REPLY_MASK: u32 = 0x00ff_0000;
/// First routing table used for policy targets.
pub const TABLE_BASE: u32 = 10_000;

/// Where a policy target sends traffic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TargetKind {
    /// one gateway
    Gateway {
        /// logical interface
        interface: String,
        /// next hop (`None`: learned from DHCP / RA)
        address: Option<IpAddr>,
    },
    /// a gateway group: members by tier (lowest tier first)
    Group {
        /// `(tier, gateway name)`
        members: Vec<(u8, String)>,
    },
}

/// One route-to / reply-to target.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Target {
    /// mark in [`ROUTE_MASK`]
    pub mark: u32,
    /// routing table holding its default route
    pub table: u32,
    /// what it routes to
    pub kind: TargetKind,
}

/// Every policy target and the reply-to gateway of each WAN.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PolicyRouting {
    /// target name (gateway or group) → target
    pub targets: BTreeMap<String, Target>,
    /// logical interface → gateway its inbound connections reply through
    pub reply: BTreeMap<String, String>,
}

impl PolicyRouting {
    /// Assigns marks and tables in name order (stable across applies).
    pub fn new(
        targets: BTreeMap<String, TargetKind>,
        reply: BTreeMap<String, String>,
    ) -> PolicyRouting {
        let targets = targets
            .into_iter()
            .take(255)
            .enumerate()
            .map(|(i, (name, kind))| {
                let n = i as u32 + 1;
                (
                    name,
                    Target {
                        mark: n << 8,
                        table: TABLE_BASE + n,
                        kind,
                    },
                )
            })
            .collect();
        PolicyRouting { targets, reply }
    }

    /// Route mark of a target.
    pub fn mark(&self, name: &str) -> Option<u32> {
        self.targets.get(name).map(|t| t.mark)
    }

    /// Nothing to mark.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_are_stable_and_in_range() {
        let t: BTreeMap<String, TargetKind> = ["WAN2", "WAN1"]
            .into_iter()
            .map(|n| {
                (
                    n.to_owned(),
                    TargetKind::Gateway {
                        interface: "wan".into(),
                        address: None,
                    },
                )
            })
            .collect();
        let p = PolicyRouting::new(t, BTreeMap::new());
        assert_eq!(p.mark("WAN1"), Some(0x100));
        assert_eq!(p.mark("WAN2"), Some(0x200));
        assert_eq!(p.targets["WAN2"].table, TABLE_BASE + 2);
        assert!(p.targets.values().all(|t| t.mark & !ROUTE_MASK == 0));
    }
}
