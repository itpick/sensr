//! Gateways and gateway groups (OPNsense `Routing/Gateways.xml`,
//! `Routing/GatewayGroups.xml`): next hops for the default route, for
//! policy-routed filter rules and for multi-WAN failover.

use std::collections::HashSet;
use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::array::ArrayField;
use crate::fields::{Description, GatewayName, InterfaceId, IpFamily};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldPath, Validations, ValidatorKind};

/// All gateways and groups.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Gateways {
    /// Individual next hops.
    #[serde(default)]
    pub gateways: ArrayField<Gateway>,
    /// Failover / load-balancing groups of gateways.
    #[serde(default)]
    pub groups: ArrayField<GatewayGroup>,
    /// Move the default route to the next candidate when the default
    /// gateway goes down (OPNsense `system/gw_switch_default`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub switch_default: bool,
}

/// Probe timing and alarm thresholds (OPNsense dpinger settings); `None`
/// keeps OPNsense's default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MonitorThresholds {
    /// Latency (ms) above which the gateway is "delay" (default 200).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_low: Option<u32>,
    /// Latency (ms) above which the gateway is down (default 500).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_high: Option<u32>,
    /// Loss (%) above which the gateway is "loss" (default 10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_low: Option<u32>,
    /// Loss (%) above which the gateway is down (default 20).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_high: Option<u32>,
    /// Seconds between probes (default 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u32>,
    /// Seconds after which an unanswered probe is lost (default 4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loss_interval: Option<u32>,
    /// Seconds of history averaged (default 60).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_period: Option<u32>,
    /// Probe payload bytes (default 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_length: Option<u32>,
}

impl MonitorThresholds {
    /// True when every value is the default.
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
    /// Treat the gateway as down regardless of probes (`force_down`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub force_down: bool,
    /// Probe timing and thresholds.
    #[serde(default, skip_serializing_if = "MonitorThresholds::is_default")]
    pub thresholds: MonitorThresholds,
}

fn default_priority() -> u8 {
    255
}

fn one() -> u8 {
    1
}

/// When a group member counts as down (OPNsense `trigger`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GroupMember {
    /// The gateway.
    pub gateway: GatewayName,
    /// Tier 1 to 5: the lowest tier with an up member carries the traffic;
    /// members of the same tier share it by weight.
    pub tier: u8,
}

/// A failover / load-balancing group, usable wherever a gateway is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
            let t = &g.thresholds;
            let pair = |lo: Option<u32>, hi: Option<u32>, dlo: u32, dhi: u32| {
                lo.unwrap_or(dlo) < hi.unwrap_or(dhi)
            };
            if !pair(t.latency_low, t.latency_high, 200, 500) {
                out.add(
                    &p.join("thresholds"),
                    ValidatorKind::Callback,
                    "The low latency threshold must be below the high one.",
                );
            }
            if !pair(t.loss_low, t.loss_high, 10, 20) || t.loss_high.is_some_and(|h| h > 100) {
                out.add(
                    &p.join("thresholds"),
                    ValidatorKind::Callback,
                    "Loss thresholds must be percentages with the low one below the high one.",
                );
            }
            if t.interval == Some(0) || t.time_period == Some(0) || t.loss_interval == Some(0) {
                out.add(
                    &p.join("thresholds"),
                    ValidatorKind::Callback,
                    "Probe intervals and the time period must be at least one second.",
                );
            }
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
