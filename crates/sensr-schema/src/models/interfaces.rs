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
use crate::fields::{Description, DeviceName, HexBytes, Hostname, InterfaceId, MacAddr};
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
        /// What the client identifier (option 61) is built from.
        #[serde(default, skip_serializing_if = "is_default")]
        client_id: DhcpClientId,
        /// Vendor class identifier, option 60.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vendor_class: Option<String>,
        /// User classes, option 77.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        user_class: Vec<String>,
        /// Further options sent in every request (OPNsense
        /// `adv_dhcp_send_options`).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        send_options: Vec<DhcpSendOption>,
        /// Option codes to ask for in addition to the client's defaults
        /// (option 55, OPNsense `adv_dhcp_request_options`).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        request_options: Vec<u8>,
        /// 802.1p priority of the client's frames on a VLAN interface, 0 to 7
        /// (OPNsense `dhcpvlanprio`; some ISPs drop requests without it).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vlan_priority: Option<u8>,
        /// Apply the MTU the server offers (option 26). Off by default, as in
        /// OPNsense: ISPs get it wrong often enough (`dhcphonourmtu`).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        use_mtu: bool,
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
            client_id: DhcpClientId::default(),
            vendor_class: None,
            user_class: Vec::new(),
            send_options: Vec::new(),
            request_options: Vec::new(),
            vlan_priority: None,
            use_mtu: false,
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
        /// Ask for the two-message exchange (`dhcp6_rapid_commit`).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        rapid_commit: bool,
        /// Which /64 of the delegation this interface addresses itself from
        /// (OPNsense `dhcp6-prefix-id`); `None` takes no address from it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prefix_id: Option<u16>,
        /// The DHCP unique identifier to present, type included (OPNsense
        /// `Interfaces/settings/dhcp6_duid`). `None` derives a DUID-LL from
        /// the interface's MAC, the spoofed one when set, so the delegation
        /// survives reinstalls.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duid: Option<HexBytes>,
        /// Release the lease when the client stops (inverse of OPNsense
        /// `dhcp6_norelease`). Turning it off keeps the ISP's delegation
        /// across restarts with ISPs that hand out a new prefix otherwise.
        #[serde(default = "yes", skip_serializing_if = "is_true")]
        send_release: bool,
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

impl Ipv6Config {
    /// A DHCPv6 client asking for a `/len` delegation (`None`: no
    /// delegation), everything else at its default.
    pub fn dhcp6(prefix_delegation_len: Option<u8>) -> Self {
        Self::Dhcp6 {
            prefix_delegation_len,
            send_prefix_hint: false,
            prefix_only: false,
            rapid_commit: false,
            prefix_id: None,
            duid: None,
            send_release: true,
        }
    }
}

/// What a DHCPv4 client identifier (option 61) is built from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DhcpClientId {
    /// Hardware type 1 and the interface's MAC, the spoofed one when
    /// `spoof_mac` is set: what dhclient (and so OPNsense) sends, and what a
    /// residential gateway in passthrough mode recognises its client by.
    #[default]
    Mac,
    /// RFC 4361: IAID plus the DHCP unique identifier.
    Duid,
}

/// The value of a DHCPv4 option the client sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DhcpOptionValue {
    /// Text.
    String(String),
    /// Raw bytes (`01:02:f3`).
    Hex(HexBytes),
    /// An IPv4 address.
    Ipv4(Ipv4Addr),
    /// An 8-bit number.
    Uint8(u8),
    /// A 16-bit number.
    Uint16(u16),
    /// A 32-bit number.
    Uint32(u32),
}

/// A DHCPv4 option the client adds to its requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DhcpSendOption {
    /// Option code, 1 to 254.
    pub code: u8,
    /// Its value.
    pub value: DhcpOptionValue,
}

/// Options the client builds itself, with the field that sets them.
const CLIENT_OWNED_OPTIONS: &[(u8, &str)] = &[
    (12, "Set the host name with hostname."),
    (50, "The client manages the requested address itself."),
    (51, "The client manages the lease time itself."),
    (53, "The client manages the message type itself."),
    (54, "The client manages the server identifier itself."),
    (55, "Set the parameter request list with request_options."),
    (57, "The client manages the maximum message size itself."),
    (60, "Set the vendor class with vendor_class."),
    (61, "Set the client identifier with client_id."),
    (77, "Set the user class with user_class."),
];

fn is_default<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

fn is_true(b: &bool) -> bool {
    *b
}

/// Text a networkd setting can carry on one line.
fn plain_text(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(char::is_control)
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
        // Each /64 of a delegation can go to one interface only.
        let mut subnets: HashMap<(&InterfaceId, u16), &InterfaceId> = HashMap::new();
        for (id, iface) in &self.0 {
            if let Ipv6Config::Dhcp6 {
                prefix_id: Some(n), ..
            } = &iface.ipv6
            {
                subnets.insert((id, *n), id);
            }
        }
        for (id, iface) in &self.0 {
            if let Ipv6Config::Track {
                interface,
                prefix_id,
            } = &iface.ipv6
                && iface.enabled
                && let Some(other) = subnets.insert((interface, *prefix_id), id)
                && other != id
            {
                out.add(
                    &at.join(id).join("ipv6").join("prefix_id"),
                    ValidatorKind::Constraint,
                    format!("Prefix ID 0x{prefix_id:x} of {interface} is already used by {other}."),
                );
            }
        }
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

fn validate_dhcp4(cfg: &Ipv4Config, at: &FieldPath, out: &mut Validations) {
    let Ipv4Config::Dhcp {
        vendor_class,
        user_class,
        send_options,
        request_options,
        vlan_priority,
        ..
    } = cfg
    else {
        return;
    };
    if vendor_class.as_deref().is_some_and(|v| !plain_text(v)) {
        out.add(
            &at.join("vendor_class"),
            ValidatorKind::Callback,
            "The vendor class must be non-empty text without control characters.",
        );
    }
    if user_class
        .iter()
        .any(|u| !plain_text(u) || u.contains(char::is_whitespace))
    {
        out.add(
            &at.join("user_class"),
            ValidatorKind::Callback,
            "A user class must be non-empty text without spaces or control characters.",
        );
    }
    let sp = at.join("send_options");
    for o in send_options {
        if o.code == 0 || o.code == 255 {
            out.add(
                &sp,
                ValidatorKind::MinMax,
                "An option code must be between 1 and 254.",
            );
        } else if let Some((_, why)) = CLIENT_OWNED_OPTIONS.iter().find(|(c, _)| *c == o.code) {
            out.add(
                &sp,
                ValidatorKind::Callback,
                format!("Option {} cannot be sent this way. {why}", o.code),
            );
        }
        if let DhcpOptionValue::String(t) = &o.value
            && !plain_text(t)
        {
            out.add(
                &sp,
                ValidatorKind::Callback,
                format!(
                    "Option {}: text must be non-empty, without control characters.",
                    o.code
                ),
            );
        }
    }
    if request_options.iter().any(|c| *c == 0 || *c == 255) {
        out.add(
            &at.join("request_options"),
            ValidatorKind::MinMax,
            "An option code must be between 1 and 254.",
        );
    }
    if let Some(p) = vlan_priority {
        check::range(*p, 0..=7, &at.join("vlan_priority"), out);
    }
}

fn validate_v4(cfg: &Ipv4Config, at: &FieldPath, out: &mut Validations) {
    validate_dhcp4(cfg, at, out);
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
        if let Ipv6Config::Dhcp6 {
            prefix_delegation_len,
            prefix_id,
            duid,
            ..
        } = cfg
        {
            // A DUID is a 2-byte type plus 1 to 128 bytes (RFC 8415 §11.1).
            if duid
                .as_ref()
                .is_some_and(|d| !(3..=130).contains(&d.as_bytes().len()))
            {
                out.add(
                    &at.join("duid"),
                    ValidatorKind::Callback,
                    "A valid DUID must be specified.",
                );
            }
            if let Some(id) = prefix_id {
                match prefix_delegation_len {
                    None => out.add(
                        &at.join("prefix_id"),
                        ValidatorKind::Callback,
                        "A prefix ID needs a prefix delegation size.",
                    ),
                    Some(len) if (32..=64).contains(len) => {
                        let slots = 1u64 << (64 - u64::from(*len));
                        if u64::from(*id) >= slots {
                            out.add(
                                &at.join("prefix_id"),
                                ValidatorKind::MinMax,
                                format!("The prefix ID must be smaller than {slots} for a /{len} delegation."),
                            );
                        }
                    }
                    Some(_) => {}
                }
            }
        }
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
