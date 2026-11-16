//! Gateways and gateway groups (OPNsense `Routing/Gateways.xml`,
//! `Routing/GatewayGroups.xml`): next hops for the default route, for
//! policy-routed filter rules and for multi-WAN failover.

use std::collections::HashSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::array::ArrayField;
use crate::fields::{Description, GatewayName, InterfaceId, IpFamily};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldPath, Validations, ValidatorKind};

/// All gateways and groups.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gateways {
    /// Individual next hops.
    #[serde(default)]
    pub gateways: ArrayField<Gateway>,
    /// Failover / load-balancing groups of gateways.
    #[serde(default)]
    pub groups: ArrayField<GatewayGroup>,
}

impl Gateways {
    /// True if `name` is a gateway or a group.
    pub fn has(&self, name: &GatewayName) -> bool {
        self.gateway(name).is_some() || self.groups.values().any(|g| &g.name == name)
    }

    /// The gateway called `name`.
    pub fn gateway(&self, name: &GatewayName) -> Option<&Gateway> {
        self.gateways.values().find(|g| &g.name == name)
    }
}

/// One next hop on an interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gateway {
    /// Disabled gateways are never used.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Name rules and groups refer to.
    pub name: GatewayName,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
    /// Interface the next hop is reached through.
    pub interface: InterfaceId,
    /// `inet` or `inet6`.
    #[serde(default)]
    pub family: IpFamily,
    /// Next-hop address; `None` for a dynamic gateway learned from DHCP, PPP
    /// or router advertisements on `interface`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<IpAddr>,
    /// Candidate for the default route (OPNsense `defaultgw`).
    #[serde(default)]
    pub default_route: bool,
    /// The next hop is outside the interface's subnet (`fargw`).
    #[serde(default)]
    pub far: bool,
    /// Probe the gateway to detect failure (inverse of `monitor_disable`).
    #[serde(default)]
    pub monitor: bool,
    /// Address to probe; `None` probes `address`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitor_address: Option<IpAddr>,
    /// Lower wins when several default-route candidates are up, 0 to 255.
    #[serde(default = "default_priority")]
    pub priority: u8,
    /// Share of traffic in a load-balancing group, 1 to 10.
    #[serde(default = "one")]
    pub weight: u8,
}

fn default_priority() -> u8 {
    255
}

fn one() -> u8 {
    1
}

/// When a group member counts as down (OPNsense `trigger`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupTrigger {
    /// The monitor reports it down.
    #[default]
    Down,
    /// Down or packet loss above the threshold.
    DownLoss,
    /// Down or latency above the threshold.
    DownLatency,
    /// Down, packet loss or latency.
    DownLossLatency,
}

/// One member of a gateway group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupMember {
    /// The gateway.
    pub gateway: GatewayName,
    /// Tier 1 to 5: the lowest tier with an up member carries the traffic;
    /// members of the same tier share it by weight.
    pub tier: u8,
}

/// A failover / load-balancing group, usable wherever a gateway is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayGroup {
    /// Name rules refer to.
    pub name: GatewayName,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
    /// Members with their tiers.
    #[serde(default)]
    pub members: Vec<GroupMember>,
    /// Failure condition.
    #[serde(default)]
    pub trigger: GroupTrigger,
}

impl Validate for Gateways {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        let gws = at.join("gateways");
        let groups = at.join("groups");
        check::unique(
            self.gateways
                .iter()
                .map(|(id, g)| (gws.join(id), Some(g.name.clone())))
                .chain(
                    self.groups
                        .iter()
                        .map(|(id, g)| (groups.join(id), Some(g.name.clone()))),
                ),
            "name",
            "Gateway with this name already exists.",
            out,
        );
        let mut addresses = HashSet::new();
        for (id, g) in &self.gateways {
            let p = gws.join(id);
            check::interface(ctx, &g.interface, &p.join("interface"), out);
            if g.family == IpFamily::Inet46 {
                out.add(
                    &p.join("family"),
                    ValidatorKind::Callback,
                    "A gateway is either IPv4 or IPv6.",
                );
            }
            for (field, addr) in [
                ("address", g.address),
                ("monitor_address", g.monitor_address),
            ] {
                if let Some(a) = addr
                    && !g.family.admits(a)
                {
                    out.add(
                        &p.join(field),
                        ValidatorKind::Callback,
                        "The address family of the address does not match the gateway's IP version.",
                    );
                }
            }
            if let Some(a) = g.address
                && !addresses.insert(a)
            {
                out.add(
                    &p.join("address"),
                    ValidatorKind::Constraint,
                    "This gateway IP address already exists.",
                );
            }
            check::range(g.weight, 1..=10, &p.join("weight"), out);
        }
        for (id, grp) in &self.groups {
            let p = groups.join(id);
            for m in &grp.members {
                if self.gateway(&m.gateway).is_none() {
                    out.add(
                        &p.join("members"),
                        ValidatorKind::Callback,
                        format!("Gateway {} does not exist.", m.gateway),
                    );
                }
                check::range(m.tier, 1..=5, &p.join("members"), out);
            }
        }
    }
}
