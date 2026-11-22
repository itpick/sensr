//! Host modes: per-MAC containment on every internal interface.
//!
//! - **Isolated** (`host_isolated`): the router's own services and the
//!   internet stay reachable; every local network is blocked.
//! - **Quarantine** (`host_quarantine`): only the router's DHCP, DNS and NTP;
//!   everything else (the GUI, SSH, other local hosts, the internet) is
//!   blocked, ahead of the anti-lockout rule.
//! - **Reverse**: no local host reaches a locked host's addresses
//!   (`host_locked_v4/v6`, filled at run time from the neighbour table and
//!   leases).
//!
//! The rules match `ether saddr @host_<kind>`, so they live only in the `in`
//! chains, which the input and forward hooks reach (both have a link-layer
//! header). In forward, `(self)` never matches and a pass is a `return`, so
//! the quarantine block and the isolated blocks hold there without relying
//! on an early accept.

use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use sensr_schema::fields::MacAddr;
use sensr_schema::models::firewall::HostModeKind;

use crate::conf;
use crate::ir::{Addr, IpFamily};
use crate::normalize::Context;
use crate::render::nft::SetContents;
use crate::ruleset::Ruleset;

/// Source-MAC set of Isolated hosts.
pub const ISOLATED_SET: &str = "host_isolated";
/// Source-MAC set of quarantined hosts.
pub const QUARANTINE_SET: &str = "host_quarantine";
/// Both source-MAC sets.
pub const MAC_SETS: [&str; 2] = [ISOLATED_SET, QUARANTINE_SET];
/// Base name of the locked hosts' address sets (`host_locked_v4`, `_v6`).
pub const LOCKED_SET: &str = "host_locked";

const REF: &str = "ui/core/dashboard";
/// Quarantine runs ahead of the system rules at priority 5 (anti-lockout).
const QUARANTINE_PRIO: u32 = 4;
const REVERSE_PRIO: u32 = 5;
/// After the system rules, with device isolation.
const ISOLATED_PRIO: u32 = 6;

/// One enabled host mode, stripped to what the rules need.
pub struct HostModeEntry<'a> {
    /// the host's MAC address
    pub mac: &'a MacAddr,
    /// how it is contained
    pub kind: HostModeKind,
    /// free text; kept out of rule descriptions so labels stay stable
    pub description: &'a str,
}

/// Contents of the four host-mode sets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostModeSets {
    /// MACs of Isolated hosts (from the configuration)
    pub isolated: Vec<MacAddr>,
    /// MACs of quarantined hosts (from the configuration)
    pub quarantine: Vec<MacAddr>,
    /// current IPv4 addresses of every locked host (run time)
    pub locked_v4: Vec<Ipv4Addr>,
    /// current IPv6 addresses of every locked host (run time)
    pub locked_v6: Vec<Ipv6Addr>,
}

impl HostModeSets {
    /// The MAC sets of `entries`; the address sets start empty.
    pub fn of(entries: &[HostModeEntry<'_>]) -> Self {
        let macs = |kind| {
            let mut v: Vec<MacAddr> = entries
                .iter()
                .filter(|e| e.kind == kind)
                .map(|e| *e.mac)
                .collect();
            v.sort();
            v.dedup();
            v
        };
        HostModeSets {
            isolated: macs(HostModeKind::Isolated),
            quarantine: macs(HostModeKind::Quarantine),
            ..HostModeSets::default()
        }
    }

    /// True when no host is in any mode.
    pub fn is_empty(&self) -> bool {
        self.isolated.is_empty() && self.quarantine.is_empty()
    }

    /// Contents of a MAC set by name (empty for an unknown name).
    pub fn macs(&self, set: &str) -> &[MacAddr] {
        match set {
            ISOLATED_SET => &self.isolated,
            QUARANTINE_SET => &self.quarantine,
            _ => &[],
        }
    }

    /// Contents of one family of an address set by base name.
    pub fn ips(&self, set: &str, fam: IpFamily) -> Vec<IpNet> {
        if set != LOCKED_SET {
            return Vec::new();
        }
        match fam {
            IpFamily::V4 => self
                .locked_v4
                .iter()
                .map(|&a| IpNet::from(std::net::IpAddr::from(a)))
                .collect(),
            IpFamily::V6 => self
                .locked_v6
                .iter()
                .map(|&a| IpNet::from(std::net::IpAddr::from(a)))
                .collect(),
        }
    }
}

/// The four host-mode sets with their contents, for
/// [`render_set_updates`](crate::render::nft::render_set_updates).
pub fn host_mode_set_updates(sets: &HostModeSets) -> Vec<(String, SetContents)> {
    let mut v: Vec<(String, SetContents)> = MAC_SETS
        .iter()
        .map(|&n| (n.to_owned(), SetContents::Macs(sets.macs(n).to_vec())))
        .collect();
    for fam in IpFamily::BOTH {
        v.push((
            crate::compile::ip_set(LOCKED_SET, fam),
            SetContents::Nets(sets.ips(LOCKED_SET, fam)),
        ));
    }
    v
}

/// Registers the rules for `entries` on every internal interface (neither
/// virtual nor a gateway). Rules match the kind's MAC set, so each kind's
/// rules are registered once however many hosts it holds; the reverse
/// block is registered once per interface whenever any host is locked.
pub fn register(rs: &mut Ruleset, entries: &[HostModeEntry<'_>], ctx: &Context<'_>) {
    if entries.is_empty() {
        return;
    }
    let internal: Vec<&str> = ctx
        .interfaces
        .iter()
        .filter(|(_, i)| i.is_internal())
        .map(|(name, _)| name.as_str())
        .collect();
    // Fixed descriptions: the label is a hash of the rule, so it must not
    // change when hosts are added, removed or renamed.
    let any = |kind| entries.iter().any(|e| e.kind == kind);
    let quarantine = any(HostModeKind::Quarantine).then_some("host mode quarantine");
    let isolated = any(HostModeKind::Isolated).then_some("host mode isolated");
    for iface in &internal {
        let rule = |action: &str, descr: String| {
            conf! {
                "interface" => *iface,
                "direction" => "in",
                "quick" => true,
                "type" => action,
                "#ref" => REF,
                "descr" => descr,
            }
        };
        if let Some(l) = quarantine {
            let src = QUARANTINE_SET;
            for (proto, to, port, what) in [
                ("udp", "(self)", 67i64, "DHCP"),
                // DISCOVER/REQUEST go to the broadcast address, which
                // `(self)` (fib daddr type local) does not match
                ("udp", "255.255.255.255", 67, "DHCP broadcast"),
                ("tcp/udp", "(self)", 53, "DNS"),
                ("udp", "(self)", 123, "NTP"),
            ] {
                let mut c = rule("pass", format!("{l}: allow {what} to the router"));
                c.set("protocol", proto);
                c.set("to", to);
                c.set("to_port", port);
                register_from(rs, QUARANTINE_PRIO, &c, ctx, src);
            }
            let c = rule("block", format!("{l}: block everything else"));
            register_from(rs, QUARANTINE_PRIO, &c, ctx, src);
        }

        // reverse: nothing arriving on an internal interface (local,
        // routed or tunnelled sources alike) reaches a locked host
        let mut c = rule(
            "pass",
            "host modes: allow the router to locked hosts".into(),
        );
        // Defensive: the router's own traffic leaves through output, never
        // an `in` chain; this keeps a router-sourced packet seen here (a
        // hairpin, a future chain layout) from being caught by the block.
        c.set("from", "(self)");
        register_to_locked(rs, &c, ctx);
        let c = rule("block", "host modes: block traffic to locked hosts".into());
        register_to_locked(rs, &c, ctx);

        if let Some(l) = isolated {
            let src = ISOLATED_SET;
            let mut c = rule("pass", format!("{l}: allow the router's own services"));
            c.set("to", "(self)");
            register_from(rs, ISOLATED_PRIO, &c, ctx, src);
            for net in &internal {
                let mut c = rule("block", format!("{l}: block {net}"));
                c.set("to", *net);
                register_from(rs, ISOLATED_PRIO, &c, ctx, src);
            }
        }
    }
}

/// Registers `c` with its source replaced by the MAC set `set` (rule arrays
/// have no MAC operand). The set is written into the array as a table token
/// first so the label hash tells the rule apart from the same rule on
/// another set.
fn register_from(rs: &mut Ruleset, prio: u32, c: &conf::Conf, ctx: &Context<'_>, set: &str) {
    let mut c = c.clone();
    c.set("from", format!("<{set}>"));
    let start = rs.rules.len();
    rs.register_filter(prio, &c, None, ctx);
    for r in &mut rs.rules[start..] {
        r.src.addr = Addr::MacSet(set.into());
    }
}

/// Registers `c` with its destination replaced by the locked hosts' sets
/// (as a table token in the array, for a distinct label hash).
fn register_to_locked(rs: &mut Ruleset, c: &conf::Conf, ctx: &Context<'_>) {
    let mut c = c.clone();
    c.set("to", format!("<{LOCKED_SET}>"));
    let start = rs.rules.len();
    rs.register_filter(REVERSE_PRIO, &c, None, ctx);
    for r in &mut rs.rules[start..] {
        r.dst.addr = Addr::IpSet(LOCKED_SET.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_of_entries_are_sorted_and_unique() {
        let a: MacAddr = "02:00:00:00:00:02".parse().unwrap();
        let b: MacAddr = "02:00:00:00:00:01".parse().unwrap();
        let e = |mac, kind| HostModeEntry {
            mac,
            kind,
            description: "",
        };
        let sets = HostModeSets::of(&[
            e(&a, HostModeKind::Isolated),
            e(&b, HostModeKind::Isolated),
            e(&a, HostModeKind::Isolated),
            e(&b, HostModeKind::Quarantine),
        ]);
        assert_eq!(sets.isolated, vec![b, a]);
        assert_eq!(sets.quarantine, vec![b]);
        assert!(sets.locked_v4.is_empty() && sets.locked_v6.is_empty());
        assert!(!sets.is_empty() && HostModeSets::default().is_empty());
        assert_eq!(sets.macs("other"), &[] as &[MacAddr]);
    }
}
