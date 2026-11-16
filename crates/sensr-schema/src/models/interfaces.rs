//! Interface assignments and addressing (OPNsense `interfaces` section).
//!
//! Interfaces are keyed by a logical [`InterfaceId`] (`wan`, `lan`, `opt1`)
//! that rules and services reference; each binds to a kernel device, which
//! can be pinned by MAC so a NIC keeps its role when enumeration order changes.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use indexmap::IndexMap;
use ipnet::{Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::fields::{Description, DeviceName, Hostname, InterfaceId, MacAddr};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldPath, Validations, ValidatorKind};

/// All assigned interfaces, in assignment order.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Interfaces(pub IndexMap<InterfaceId, Interface>);

impl Interfaces {
    /// The interface with `id`.
    pub fn get(&self, id: &InterfaceId) -> Option<&Interface> {
        self.0.get(id)
    }

    /// Iterates `(id, interface)` in assignment order.
    pub fn iter(&self) -> impl Iterator<Item = (&InterfaceId, &Interface)> {
        self.0.iter()
    }

    /// Enabled interfaces with the given role.
    pub fn with_role(
        &self,
        role: InterfaceRole,
    ) -> impl Iterator<Item = (&InterfaceId, &Interface)> {
        self.0
            .iter()
            .filter(move |(_, i)| i.enabled && i.role == role)
    }

    /// Adds or replaces an interface.
    pub fn insert(&mut self, id: InterfaceId, iface: Interface) -> Option<Interface> {
        self.0.insert(id, iface)
    }
}

/// What an interface is for. OPNsense infers this from the `wan`/`lan` ids
/// and from whether a gateway is attached; sensr records it, because
/// automatic outbound NAT, anti-lockout and default rules depend on it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceRole {
    /// Upstream: NAT source, default route, bogon/private blocking applies.
    Wan,
    /// Internal network: served by DHCP/DNS, NATed out.
    Lan,
    /// Anything else (DMZ, transit, VPN).
    #[default]
    Other,
}

/// Queueing discipline on egress. The default is fq_codel because
/// bufferbloat dominated the latency results in the evaluation
/// (docs/research/07); OPNsense ships none.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Qdisc {
    /// Fair queueing with CoDel AQM.
    #[default]
    FqCodel,
    /// CAKE, optionally shaped to a bandwidth (needed below the link rate,
    /// e.g. DSL or cable uplinks).
    Cake {
        /// Shaping rate in kbit/s; `None` for unshaped.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        bandwidth_kbit: Option<u32>,
    },
    /// Kernel default (no change).
    Kernel,
}

/// One assigned interface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    /// Administratively up.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// What the interface is for.
    #[serde(default)]
    pub role: InterfaceRole,
    /// Display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
    /// Kernel device name.
    pub device: DeviceName,
    /// Permanent MAC of the NIC that must carry this device name; when set,
    /// sensr generates a `systemd.link` rename so the assignment survives
    /// re-enumeration (PLAN §2.2, `sensr-net`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_mac: Option<MacAddr>,
    /// MAC to use instead of the hardware one (OPNsense `spoofmac`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spoof_mac: Option<MacAddr>,
    /// MTU; `None` keeps the device default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// IPv4 configuration.
    #[serde(default)]
    pub ipv4: Ipv4Config,
    /// IPv6 configuration.
    #[serde(default)]
    pub ipv6: Ipv6Config,
    /// Drop inbound traffic from RFC 1918 / ULA sources (OPNsense `blockpriv`).
    #[serde(default)]
    pub block_private: bool,
    /// Drop inbound traffic from bogon sources (OPNsense `blockbogons`).
    #[serde(default)]
    pub block_bogons: bool,
    /// Egress queueing.
    #[serde(default)]
    pub qdisc: Qdisc,
    /// When set, `device` is a VLAN sub-interface sensr creates on a parent
    /// device (OPNsense `vlans`, Interfaces › Devices › VLAN).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan: Option<Vlan>,
}

/// 802.1Q / 802.1ad tagging of a VLAN device.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum VlanProtocol {
    /// Customer tag (`802.1q`).
    #[default]
    #[serde(rename = "802.1q")]
    Dot1Q,
    /// Service tag, for QinQ (`802.1ad`).
    #[serde(rename = "802.1ad")]
    Dot1Ad,
}

/// A VLAN sub-interface: frames on `parent` tagged `tag`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Vlan {
    /// The device carrying the tagged frames.
    pub parent: DeviceName,
    /// VLAN id, 1 to 4094.
    pub tag: u16,
    /// 802.1p priority code point of egress frames, 0 to 7.
    #[serde(default)]
    pub pcp: u8,
    /// Tag protocol.
    #[serde(default)]
    pub protocol: VlanProtocol,
}

impl Interface {
    /// An enabled interface on `device` with no addressing.
    pub fn new(device: DeviceName, role: InterfaceRole) -> Self {
        Self {
            enabled: true,
            role,
            description: None,
            device,
            match_mac: None,
            spoof_mac: None,
            mtu: None,
            ipv4: Ipv4Config::None,
            ipv6: Ipv6Config::None,
            block_private: false,
            block_bogons: false,
            qdisc: Qdisc::default(),
            vlan: None,
        }
    }
}

/// IPv4 addressing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Ipv4Config {
    /// No IPv4.
    #[default]
    None,
    /// DHCP client.
    Dhcp {
        /// Host name sent in the request (option 12).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hostname: Option<Hostname>,
        /// Ignore leases from these servers (OPNsense `dhcprejectfrom`).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        reject_from: Vec<Ipv4Addr>,
        /// Install the default route learned from DHCP.
        #[serde(default = "yes")]
        use_gateway: bool,
    },
    /// Static address with prefix length (host bits are the address).
    Static {
        /// Address and prefix, e.g. `192.168.1.1/24`.
        #[schemars(with = "String")]
        address: Ipv4Net,
        /// Upstream gateway, for WAN-type interfaces.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gateway: Option<Ipv4Addr>,
    },
}

impl Ipv4Config {
    /// DHCP with defaults.
    pub fn dhcp() -> Self {
        Self::Dhcp {
            hostname: None,
            reject_from: Vec::new(),
            use_gateway: true,
        }
    }

    /// The static network, if any (`192.168.1.0/24` for `192.168.1.1/24`).
    pub fn static_net(&self) -> Option<Ipv4Net> {
        match self {
            Self::Static { address, .. } => Some(address.trunc()),
            _ => None,
        }
    }
}

/// IPv6 addressing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Ipv6Config {
    /// No IPv6 beyond link-local.
    #[default]
    None,
    /// DHCPv6 client, optionally requesting a delegated prefix.
    Dhcp6 {
        /// Requested delegation size (`/48`, `/56`, `/60`, `/64`); `None` for
        /// no prefix delegation (OPNsense `dhcp6-ia-pd-len`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix_delegation_len: Option<u8>,
        /// Send the size as a hint (`dhcp6-ia-pd-send-hint`).
        #[serde(default)]
        send_prefix_hint: bool,
        /// Request only a prefix, no address (`dhcp6prefixonly`).
        #[serde(default)]
        prefix_only: bool,
    },
    /// Stateless autoconfiguration from router advertisements.
    Slaac,
    /// Static address with prefix length.
    Static {
        /// Address and prefix.
        #[schemars(with = "String")]
        address: Ipv6Net,
        /// Upstream gateway.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gateway: Option<Ipv6Addr>,
    },
    /// Take a /64 out of the prefix another interface had delegated
    /// (OPNsense `track6` / `idassoc6`).
    Track {
        /// The interface whose delegated prefix is used.
        interface: InterfaceId,
        /// Which /64 of the delegation (`track6-prefix-id`).
        #[serde(default)]
        prefix_id: u16,
    },
}

impl Default for Interface {
    fn default() -> Self {
        Self::new("eth0".parse().expect("valid literal"), InterfaceRole::Other)
    }
}

impl Validate for Interfaces {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        let mut devices: HashMap<&DeviceName, &InterfaceId> = HashMap::new();
        let mut macs: HashMap<MacAddr, &InterfaceId> = HashMap::new();
        let mut vlans: HashMap<(&DeviceName, u16), &InterfaceId> = HashMap::new();
        for (id, iface) in &self.0 {
            let p = at.join(id);
            if let Some(other) = devices.insert(&iface.device, id) {
                out.add(
                    &p.join("device"),
                    ValidatorKind::Constraint,
                    format!("Device {} is already assigned to {other}.", iface.device),
                );
            }
            if let Some(mac) = iface.match_mac
                && let Some(other) = macs.insert(mac, id)
            {
                out.add(
                    &p.join("match_mac"),
                    ValidatorKind::Constraint,
                    format!("MAC {mac} is already pinned to {other}."),
                );
            }
            for (field, mac) in [
                ("match_mac", iface.match_mac),
                ("spoof_mac", iface.spoof_mac),
            ] {
                if mac.is_some_and(|m| m.is_multicast()) {
                    out.add(
                        &p.join(field),
                        ValidatorKind::Callback,
                        "A multicast MAC address cannot be assigned to an interface.",
                    );
                }
            }
            if let Some(vlan) = &iface.vlan {
                let vp = p.join("vlan");
                check::range(vlan.tag, 1..=4094, &vp.join("tag"), out);
                check::range(vlan.pcp, 0..=7, &vp.join("pcp"), out);
                if vlan.parent == iface.device {
                    out.add(
                        &vp.join("parent"),
                        ValidatorKind::Callback,
                        "A VLAN cannot be its own parent device.",
                    );
                }
                if let Some(other) = vlans.insert((&vlan.parent, vlan.tag), id) {
                    out.add(
                        &vp.join("tag"),
                        ValidatorKind::Constraint,
                        format!("Tag for this device must be unique (already used by {other})."),
                    );
                }
            }
            if let Some(mtu) = iface.mtu {
                check::range(mtu, 576..=9216, &p.join("mtu"), out);
            }
            validate_v4(&iface.ipv4, &p.join("ipv4"), out);
            self.validate_v6(ctx, id, &iface.ipv6, &p.join("ipv6"), out);
        }
    }
}

fn validate_v4(cfg: &Ipv4Config, at: &FieldPath, out: &mut Validations) {
    if let Ipv4Config::Static { address, gateway } = cfg {
        let addr = address.addr();
        let p = at.join("address");
        if address.prefix_len() < 31 {
            if addr == address.network() {
                out.add(
                    &p,
                    ValidatorKind::Callback,
                    "This IPv4 address is the network address and cannot be used.",
                );
            } else if addr == address.broadcast() {
                out.add(
                    &p,
                    ValidatorKind::Callback,
                    "This IPv4 address is the broadcast address and cannot be used.",
                );
            }
        }
        if addr.is_unspecified() || addr.is_multicast() || addr.is_broadcast() {
            out.add(
                &p,
                ValidatorKind::Callback,
                "A valid IPv4 address must be specified.",
            );
        }
        if let Some(gw) = gateway
            && (*gw == addr || gw.is_unspecified() || gw.is_multicast())
        {
            out.add(
                &at.join("gateway"),
                ValidatorKind::Callback,
                "A valid IPv4 gateway must be specified.",
            );
        }
    }
}

impl Interfaces {
    fn validate_v6(
        &self,
        ctx: &dyn RefContext,
        me: &InterfaceId,
        cfg: &Ipv6Config,
        at: &FieldPath,
        out: &mut Validations,
    ) {
        match cfg {
            Ipv6Config::Dhcp6 {
                prefix_delegation_len: Some(len),
                ..
            } if !(32..=64).contains(len) => {
                out.add(
                    &at.join("prefix_delegation_len"),
                    ValidatorKind::MinMax,
                    "The delegated prefix length must be between 32 and 64.",
                );
            }
            Ipv6Config::Static { address, .. }
                if address.addr().is_unspecified() || address.addr().is_multicast() =>
            {
                out.add(
                    &at.join("address"),
                    ValidatorKind::Callback,
                    "A valid IPv6 address must be specified.",
                );
            }
            Ipv6Config::Track {
                interface,
                prefix_id,
            } => {
                let p = at.join("interface");
                if interface == me {
                    out.add(
                        &p,
                        ValidatorKind::Callback,
                        "An interface cannot track itself.",
                    );
                    return;
                }
                check::interface(ctx, interface, &p, out);
                match self.get(interface).map(|i| &i.ipv6) {
                    Some(Ipv6Config::Dhcp6 {
                        prefix_delegation_len: Some(len),
                        ..
                    }) => {
                        // A /len delegation holds 2^(64-len) /64s.
                        let slots = 1u64 << (64 - u64::from((*len).clamp(32, 64)));
                        if u64::from(*prefix_id) >= slots {
                            out.add(
                                &at.join("prefix_id"),
                                ValidatorKind::MinMax,
                                format!("The prefix ID must be smaller than {slots} for a /{len} delegation."),
                            );
                        }
                    }
                    Some(_) => out.add(
                        &p,
                        ValidatorKind::Callback,
                        "The tracked interface does not request a delegated prefix.",
                    ),
                    None => {}
                }
            }
            _ => {}
        }
    }
}
