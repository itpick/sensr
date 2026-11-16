//! Virtual devices that interfaces can be assigned to: bridges, link
//! aggregates and loopbacks (OPNsense `Interfaces/{Bridge,Lagg,Loopback}.xml`;
//! VLANs are per interface, see [`super::interfaces::Vlan`]), and virtual IP
//! addresses (`Interfaces/Vip.xml`).

use std::collections::HashMap;

use ipnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::check;
use crate::array::ArrayField;
use crate::fields::{Description, DeviceName, InterfaceId, Secret};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldPath, Validations, ValidatorKind};

/// Bridges, LAGGs and loopbacks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Devices {
    /// Layer-2 bridges.
    #[serde(default, skip_serializing_if = "ArrayField::is_empty")]
    pub bridges: ArrayField<Bridge>,
    /// Link aggregates (Linux bonds).
    #[serde(default, skip_serializing_if = "ArrayField::is_empty")]
    pub laggs: ArrayField<Lagg>,
    /// Extra loopback (dummy) devices.
    #[serde(default, skip_serializing_if = "ArrayField::is_empty")]
    pub loopbacks: ArrayField<Loopback>,
}

impl Devices {
    /// True when no devices are configured.
    pub fn is_empty(&self) -> bool {
        self.bridges.is_empty() && self.laggs.is_empty() && self.loopbacks.is_empty()
    }

    /// True if `name` is created by one of these definitions.
    pub fn defines(&self, name: &DeviceName) -> bool {
        self.bridges.values().any(|b| &b.device == name)
            || self.laggs.values().any(|l| &l.device == name)
            || self.loopbacks.values().any(|l| &l.device() == name)
    }
}

/// Spanning tree flavour.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum StpProtocol {
    /// Rapid spanning tree (802.1w).
    #[default]
    Rstp,
    /// Classic spanning tree (802.1D).
    Stp,
}

/// Spanning tree settings of a bridge.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Stp {
    /// Protocol.
    #[serde(default)]
    pub protocol: StpProtocol,
    /// Members that take part in spanning tree; empty means all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<DeviceName>,
    /// Max age in seconds (6-40).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age: Option<u8>,
    /// Forward delay in seconds (4-30).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_delay: Option<u8>,
    /// Transmit hold count (1-10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hold_count: Option<u8>,
    /// Members that are edge ports (no bridges behind them).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edge: Vec<DeviceName>,
}

/// A layer-2 bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Bridge {
    /// Device name (`br0`).
    pub device: DeviceName,
    /// Member devices.
    pub members: Vec<DeviceName>,
    /// Spanning tree; `None` disables it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stp: Option<Stp>,
    /// Keep an IPv6 link-local address on the bridge.
    #[serde(default)]
    pub link_local: bool,
    /// Learned address table size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_addresses: Option<u32>,
    /// Learned address timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ageing_time: Option<u32>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

/// How a LAGG spreads and fails over traffic.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LaggProtocol {
    /// 802.3ad LACP (Linux `802.3ad`).
    #[default]
    Lacp,
    /// Active/backup on the primary member (`active-backup`).
    Failover,
    /// Static hash distribution (`balance-xor`; OPNsense `loadbalance`/`fec`).
    Loadbalance,
    /// Round robin (`balance-rr`).
    Roundrobin,
    /// No distribution: traffic only on the first member.
    None,
}

/// Header layers hashed to pick a LAGG member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LaggHash {
    /// Source/destination MAC and VLAN.
    L2,
    /// Source/destination address.
    L3,
    /// Source/destination port.
    L4,
}

/// A link aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Lagg {
    /// Device name (`bond0`; imported `lagg0` keeps its name).
    pub device: DeviceName,
    /// Member devices.
    pub members: Vec<DeviceName>,
    /// Distribution protocol.
    #[serde(default)]
    pub protocol: LaggProtocol,
    /// Preferred member for failover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_member: Option<DeviceName>,
    /// LACP fast (1 s) timeout.
    #[serde(default)]
    pub lacp_fast_timeout: bool,
    /// Hash layers for load balancing; empty for the kernel default.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hash: Vec<LaggHash>,
    /// MTU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

/// An extra loopback device `lo<id>` (a Linux dummy device).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Loopback {
    /// Device number; the device is `lo<id>`.
    pub id: u16,
    /// Free text (required upstream).
    pub description: Description,
}

impl Loopback {
    /// The device name.
    pub fn device(&self) -> DeviceName {
        format!("lo{}", self.id)
            .parse()
            .unwrap_or_else(|_| unreachable!("lo<u16> is a valid device name"))
    }
}

/// How a virtual IP is provided.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum VipMode {
    /// An additional address on the interface.
    #[default]
    IpAlias,
    /// Answer ARP for the address without configuring it (whole subnets).
    ProxyArp,
    /// A shared address failing over between firewalls (OPNsense CARP,
    /// VRRP on sensr).
    Carp {
        /// Virtual host id, 1-255, unique per interface.
        vhid: u8,
        /// Advertisement interval base in seconds (1-254).
        #[serde(default = "one")]
        advbase: u8,
        /// Advertisement skew (0-254); higher loses elections.
        #[serde(default)]
        advskew: u8,
        /// Shared secret.
        password: Secret<String>,
    },
}

fn one() -> u8 {
    1
}

/// A virtual IP address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VirtualIp {
    /// Interface carrying the address.
    pub interface: InterfaceId,
    /// The address with its prefix length.
    #[schemars(with = "String")]
    pub address: IpNet,
    /// Mode and its settings.
    #[serde(default)]
    pub mode: VipMode,
    /// Do not bind services to the address (`nobind`).
    #[serde(default)]
    pub no_bind: bool,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

impl Validate for Devices {
    fn validate(&self, _ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        let mut defined: HashMap<DeviceName, FieldPath> = HashMap::new();
        let mut define = |name: DeviceName, p: FieldPath, out: &mut Validations| {
            if let Some(first) = defined.insert(name.clone(), p.clone()) {
                out.add(
                    &p,
                    ValidatorKind::Constraint,
                    format!("Device {name} is already defined at {first}."),
                );
            }
        };
        let mut member_of: HashMap<&DeviceName, String> = HashMap::new();
        let bridges = at.join("bridges");
        for (id, b) in &self.bridges {
            let p = bridges.join(id);
            define(b.device.clone(), p.join("device"), out);
            if b.members.is_empty() {
                out.add(
                    &p.join("members"),
                    ValidatorKind::PresenceOf,
                    "Select at least one member.",
                );
            }
            for m in &b.members {
                if m == &b.device {
                    out.add(
                        &p.join("members"),
                        ValidatorKind::Callback,
                        "A bridge cannot be its own member.",
                    );
                } else if let Some(other) = member_of.insert(m, b.device.to_string()) {
                    out.add(
                        &p.join("members"),
                        ValidatorKind::Constraint,
                        format!("Member {m} is already used by {other}."),
                    );
                }
            }
            if let Some(stp) = &b.stp {
                let sp = p.join("stp");
                for (field, v, r) in [
                    ("max_age", stp.max_age, 6..=40),
                    ("forward_delay", stp.forward_delay, 4..=30),
                    ("hold_count", stp.hold_count, 1..=10),
                ] {
                    if let Some(v) = v {
                        check::range(v, r, &sp.join(field), out);
                    }
                }
                if stp
                    .members
                    .iter()
                    .chain(&stp.edge)
                    .any(|m| !b.members.contains(m))
                {
                    out.add(&sp, ValidatorKind::Callback, "Contains non bridge members.");
                }
            }
        }
        let laggs = at.join("laggs");
        for (id, l) in &self.laggs {
            let p = laggs.join(id);
            define(l.device.clone(), p.join("device"), out);
            if l.members.is_empty() {
                out.add(
                    &p.join("members"),
                    ValidatorKind::PresenceOf,
                    "Select at least one member.",
                );
            }
            let used: Vec<String> = l
                .members
                .iter()
                .filter(|m| member_of.insert(m, l.device.to_string()).is_some())
                .map(ToString::to_string)
                .collect();
            if !used.is_empty() {
                out.add(
                    &p.join("members"),
                    ValidatorKind::Constraint,
                    format!(
                        "Members {} are already used in other laggs.",
                        used.join(",")
                    ),
                );
            }
            if let Some(pm) = &l.primary_member
                && !l.members.contains(pm)
            {
                out.add(
                    &p.join("primary_member"),
                    ValidatorKind::Callback,
                    format!("Primary member {pm} not in member list."),
                );
            }
            if let Some(mtu) = l.mtu {
                check::range(mtu, 576..=9216, &p.join("mtu"), out);
            }
        }
        let loops = at.join("loopbacks");
        for (id, l) in &self.loopbacks {
            define(l.device(), loops.join(id).join("id"), out);
        }
    }
}

/// All virtual IPs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VirtualIps {
    /// The addresses.
    #[serde(default)]
    pub vips: ArrayField<VirtualIp>,
}

impl VirtualIps {
    /// True when none are configured.
    pub fn is_empty(&self) -> bool {
        self.vips.is_empty()
    }
}

impl Validate for VirtualIps {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        let at = at.join("vips");
        let mut addresses: HashMap<std::net::IpAddr, ()> = HashMap::new();
        let mut vhids: HashMap<(&InterfaceId, u8), ()> = HashMap::new();
        for (id, v) in &self.vips {
            let p = at.join(id);
            check::interface(ctx, &v.interface, &p.join("interface"), out);
            let ap = p.join("address");
            let host_bits = v.address.prefix_len() < v.address.max_prefix_len().saturating_sub(1);
            if host_bits
                && v.address.addr() == v.address.network()
                && !matches!(v.mode, VipMode::ProxyArp)
            {
                out.add(
                    &ap,
                    ValidatorKind::Callback,
                    "You cannot use the network address.",
                );
            }
            if let IpNet::V4(n) = v.address
                && host_bits
                && n.addr() == n.broadcast()
            {
                out.add(
                    &ap,
                    ValidatorKind::Callback,
                    "You cannot use the broadcast address.",
                );
            }
            if matches!(v.mode, VipMode::ProxyArp) && v.address.addr() != v.address.network() {
                out.add(
                    &ap,
                    ValidatorKind::Callback,
                    "Only strict subnets are allowed for Proxy ARP types.",
                );
            }
            if addresses.insert(v.address.addr(), ()).is_some() {
                out.add(&ap, ValidatorKind::Constraint, "Address already assigned.");
            }
            if let VipMode::Carp {
                vhid,
                advbase,
                advskew,
                password,
            } = &v.mode
            {
                let mp = p.join("mode");
                check::range(*vhid, 1..=255, &mp.join("vhid"), out);
                check::range(*advbase, 1..=254, &mp.join("advbase"), out);
                check::range(*advskew, 0..=254, &mp.join("advskew"), out);
                if password.expose().is_empty() {
                    out.add(
                        &mp.join("password"),
                        ValidatorKind::PresenceOf,
                        "You must specify a CARP password that is shared between the two VHID members.",
                    );
                }
                if vhids.insert((&v.interface, *vhid), ()).is_some() {
                    out.add(
                        &mp.join("vhid"),
                        ValidatorKind::Constraint,
                        format!("VHID {vhid} is already used on {}.", v.interface),
                    );
                }
            }
        }
    }
}
