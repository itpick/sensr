//! The typed root of a configuration revision.

use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::devices::{Devices, VirtualIps};
use super::dhcp::{Dhcpv4, Pool4, Subnet4};
use super::dhcpv6::{Dhcpv6, RouterAdvertisements};
use super::dns::DnsResolver;
use super::firewall::{AliasType, Endpoint, FilterRule, Firewall};
use super::gateways::Gateways;
use super::ids::Ids;
use super::insight::Insight;
use super::interfaces::{Interface, InterfaceRole, Interfaces, Ipv4Config, Ipv6Config};
use super::nat::Nat;
use super::ntp::Ntp;
use super::routes::Routes;
use super::system::System;
use super::trust::Trust;
use super::wireguard::WireGuard;
use crate::array::Uuid;
use crate::fields::{
    AliasName, GatewayName, GroupName, InterfaceId, IpFamily, NetOrAlias, string_serde,
};
use crate::refs::{ItemKind, RefContext, Validate};

use crate::validation::{FieldError, FieldPath, Validations};

/// A document schema version (`major.minor.patch`). Migrations move a
/// document from one version to the next.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SchemaVersion {
    /// Incompatible changes.
    pub major: u16,
    /// Additive changes.
    pub minor: u16,
    /// Fixes.
    pub patch: u16,
}

impl SchemaVersion {
    /// Builds a version.
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl FromStr for SchemaVersion {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || FieldError::syntax("A version must be written as major.minor.patch.");
        let mut it = s.split('.').map(|p| {
            if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) {
                p.parse::<u16>().map_err(|_| err())
            } else {
                Err(err())
            }
        });
        let v = Self::new(
            it.next().ok_or_else(err)??,
            it.next().ok_or_else(err)??,
            it.next().ok_or_else(err)??,
        );
        if it.next().is_some() {
            return Err(err());
        }
        Ok(v)
    }
}

impl fmt::Display for SchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}
string_serde!(SchemaVersion);

/// The schema version this build writes.
pub const SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(0, 1, 0);

/// Top-level sections, the unit of change tracking: the apply engine
/// re-renders only the subsystems whose section changed.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    /// `system`.
    System,
    /// `interfaces`.
    Interfaces,
    /// `firewall`.
    Firewall,
    /// `nat`.
    Nat,
    /// `dhcpv4`.
    Dhcpv4,
    /// `dns`.
    Dns,
    /// `wireguard`.
    Wireguard,
    /// `gateways`.
    Gateways,
    /// `trust`.
    Trust,
    /// `routes`.
    Routes,
    /// `devices`.
    Devices,
    /// `virtual_ips`.
    VirtualIps,
    /// `dhcpv6`.
    Dhcpv6,
    /// `router_advertisements`.
    RouterAdvertisements,
    /// `ntp`.
    Ntp,
    /// `ids`.
    Ids,
    /// `insight`.
    Insight,
}

impl Section {
    /// Every section, in document order.
    pub const ALL: [Section; 17] = [
        Self::System,
        Self::Interfaces,
        Self::Firewall,
        Self::Nat,
        Self::Dhcpv4,
        Self::Dns,
        Self::Wireguard,
        Self::Gateways,
        Self::Trust,
        Self::Routes,
        Self::Devices,
        Self::VirtualIps,
        Self::Dhcpv6,
        Self::RouterAdvertisements,
        Self::Ntp,
        Self::Ids,
        Self::Insight,
    ];

    /// The section's key in the JSON document.
    pub fn key(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Interfaces => "interfaces",
            Self::Firewall => "firewall",
            Self::Nat => "nat",
            Self::Dhcpv4 => "dhcpv4",
            Self::Dns => "dns",
            Self::Wireguard => "wireguard",
            Self::Gateways => "gateways",
            Self::Trust => "trust",
            Self::Routes => "routes",
            Self::Devices => "devices",
            Self::VirtualIps => "virtual_ips",
            Self::Dhcpv6 => "dhcpv6",
            Self::RouterAdvertisements => "router_advertisements",
            Self::Ntp => "ntp",
            Self::Ids => "ids",
            Self::Insight => "insight",
        }
    }
}

/// One complete configuration: everything the agent needs to render and
/// apply the box.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Document {
    /// Schema version of this document.
    pub schema_version: SchemaVersion,
    /// Identity, accounts, time.
    #[serde(default)]
    pub system: System,
    /// Interface assignments and addressing.
    #[serde(default)]
    pub interfaces: Interfaces,
    /// Aliases, filter rules, settings.
    #[serde(default)]
    pub firewall: Firewall,
    /// Outbound NAT and port forwards.
    #[serde(default)]
    pub nat: Nat,
    /// DHCPv4 server.
    #[serde(default)]
    pub dhcpv4: Dhcpv4,
    /// DNS resolver.
    #[serde(default)]
    pub dns: DnsResolver,
    /// WireGuard.
    #[serde(default)]
    pub wireguard: WireGuard,
    /// Gateways and gateway groups.
    #[serde(default)]
    pub gateways: Gateways,
    /// Certificate authorities and certificates.
    #[serde(default)]
    pub trust: Trust,
    /// Static routes. Omitted when empty, so documents without routes
    /// serialise as before the section existed.
    #[serde(default, skip_serializing_if = "Routes::is_empty")]
    pub routes: Routes,
    /// Bridges, LAGGs and loopbacks (omitted while empty).
    #[serde(default, skip_serializing_if = "Devices::is_empty")]
    pub devices: Devices,
    /// Virtual IP addresses (omitted while empty).
    #[serde(default, skip_serializing_if = "VirtualIps::is_empty")]
    pub virtual_ips: VirtualIps,
    /// DHCPv6 server (omitted while unconfigured).
    #[serde(default, skip_serializing_if = "Dhcpv6::is_empty")]
    pub dhcpv6: Dhcpv6,
    /// Router advertisements (omitted while empty).
    #[serde(default, skip_serializing_if = "RouterAdvertisements::is_empty")]
    pub router_advertisements: RouterAdvertisements,
    /// NTP service (omitted while at defaults).
    #[serde(default, skip_serializing_if = "Ntp::is_empty")]
    pub ntp: Ntp,
    /// Intrusion detection (omitted while at defaults).
    #[serde(default, skip_serializing_if = "Ids::is_empty")]
    pub ids: Ids,
    /// Traffic accounting (omitted while at defaults).
    #[serde(default, skip_serializing_if = "Insight::is_empty")]
    pub insight: Insight,
}

impl Default for Document {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            system: System::default(),
            interfaces: Interfaces::default(),
            firewall: Firewall::default(),
            nat: Nat::default(),
            dhcpv4: Dhcpv4::default(),
            dns: DnsResolver::default(),
            wireguard: WireGuard::default(),
            gateways: Gateways::default(),
            trust: Trust::default(),
            routes: Routes::default(),
            devices: Devices::default(),
            virtual_ips: VirtualIps::default(),
            dhcpv6: Dhcpv6::default(),
            router_advertisements: RouterAdvertisements::default(),
            ntp: Ntp::default(),
            ids: Ids::default(),
            insight: Insight::default(),
        }
    }
}

impl Document {
    /// The factory configuration: WAN on `eth0` by DHCP/DHCPv6-PD, LAN on
    /// `eth1` at 192.168.1.1/24 tracking WAN's prefix, LAN-to-any rules for
    /// both families, automatic outbound NAT, DHCP on LAN with a .100-.199
    /// pool, and the resolver on (the shape of OPNsense's
    /// `config.xml.sample`).
    pub fn factory() -> Self {
        let id = |s: &str| -> InterfaceId { s.parse().expect("valid literal") };
        let mut doc = Self::default();

        let mut wan = Interface::new("eth0".parse().expect("valid literal"), InterfaceRole::Wan);
        wan.ipv4 = Ipv4Config::dhcp();
        wan.ipv6 = Ipv6Config::Dhcp6 {
            prefix_delegation_len: Some(64),
            send_prefix_hint: false,
            prefix_only: false,
        };
        wan.block_private = true;
        wan.block_bogons = true;
        doc.interfaces.insert(id("wan"), wan);

        let mut lan = Interface::new("eth1".parse().expect("valid literal"), InterfaceRole::Lan);
        lan.ipv4 = Ipv4Config::Static {
            address: "192.168.1.1/24".parse().expect("valid literal"),
            gateway: None,
        };
        lan.ipv6 = Ipv6Config::Track {
            interface: id("wan"),
            prefix_id: 0,
        };
        doc.interfaces.insert(id("lan"), lan);

        // Fixed UUIDs keep the factory document (and its hash) identical on
        // every box.
        for (uuid, sequence, family, text) in [
            (
                0x5e45_0001,
                1,
                IpFamily::Inet,
                "Default allow LAN to any rule",
            ),
            (
                0x5e45_0002,
                11,
                IpFamily::Inet6,
                "Default allow LAN IPv6 to any rule",
            ),
        ] {
            doc.firewall.rules.insert(
                Uuid::from_u128(uuid),
                FilterRule {
                    sequence,
                    interfaces: vec![id("lan")],
                    ip_protocol: family,
                    source: Endpoint::net(NetOrAlias::InterfaceNet(id("lan"))),
                    description: Some(text.parse().expect("valid literal")),
                    ..FilterRule::default()
                },
            );
        }

        doc.dhcpv4.enabled = true;
        doc.dhcpv4.interfaces = vec![id("lan")];
        let mut subnet = Subnet4::new("192.168.1.0/24".parse().expect("valid literal"));
        subnet.interface = Some(id("lan"));
        subnet.pools.push(
            Pool4::new([192, 168, 1, 100].into(), [192, 168, 1, 199].into()).expect("ordered"),
        );
        doc.dhcpv4
            .subnets
            .insert(Uuid::from_u128(0x5e45_0003), subnet);

        doc.dns.enabled = true;
        doc
    }

    /// Validates the whole document: every field, cross-field rule and
    /// reference. An empty result means the document may be committed.
    pub fn validate(&self) -> Validations {
        let mut out = Validations::new();
        let root = FieldPath::root();
        self.system.validate(self, &root.join("system"), &mut out);
        self.interfaces
            .validate(self, &root.join("interfaces"), &mut out);
        self.firewall
            .validate(self, &root.join("firewall"), &mut out);
        self.nat.validate(self, &root.join("nat"), &mut out);
        self.dhcpv4.validate(self, &root.join("dhcpv4"), &mut out);
        self.dns.validate(self, &root.join("dns"), &mut out);
        self.wireguard
            .validate(self, &root.join("wireguard"), &mut out);
        self.gateways
            .validate(self, &root.join("gateways"), &mut out);
        self.trust.validate(self, &root.join("trust"), &mut out);
        self.routes.validate(self, &root.join("routes"), &mut out);
        self.devices.validate(self, &root.join("devices"), &mut out);
        self.virtual_ips
            .validate(self, &root.join("virtual_ips"), &mut out);
        self.dhcpv6.validate(self, &root.join("dhcpv6"), &mut out);
        self.router_advertisements
            .validate(self, &root.join("router_advertisements"), &mut out);
        self.ntp
            .validate_with(&self.system.time_servers, self, &root.join("ntp"), &mut out);
        self.ids.validate(self, &root.join("ids"), &mut out);
        self.insight.validate(self, &root.join("insight"), &mut out);
        out
    }

    /// The JSON Schema of a document (draft 2020-12), for UI forms, the
    /// compat layer and `xtask lint-schema`.
    pub fn json_schema() -> serde_json::Value {
        serde_json::to_value(schemars::schema_for!(Document)).unwrap_or_default()
    }

    /// The sections whose content differs between `self` and `other`.
    pub fn changed_sections(&self, other: &Document) -> Vec<Section> {
        Section::ALL
            .into_iter()
            .filter(|s| match s {
                Section::System => self.system != other.system,
                Section::Interfaces => self.interfaces != other.interfaces,
                Section::Firewall => self.firewall != other.firewall,
                Section::Nat => self.nat != other.nat,
                Section::Dhcpv4 => self.dhcpv4 != other.dhcpv4,
                Section::Dns => self.dns != other.dns,
                Section::Wireguard => self.wireguard != other.wireguard,
                Section::Gateways => self.gateways != other.gateways,
                Section::Trust => self.trust != other.trust,
                Section::Routes => self.routes != other.routes,
                Section::Devices => self.devices != other.devices,
                Section::VirtualIps => self.virtual_ips != other.virtual_ips,
                Section::Dhcpv6 => self.dhcpv6 != other.dhcpv6,
                Section::RouterAdvertisements => {
                    self.router_advertisements != other.router_advertisements
                }
                Section::Ntp => self.ntp != other.ntp,
                Section::Ids => self.ids != other.ids,
                Section::Insight => self.insight != other.insight,
            })
            .collect()
    }
}

impl RefContext for Document {
    fn has_interface(&self, id: &InterfaceId) -> bool {
        self.interfaces.get(id).is_some()
    }

    fn alias_type(&self, name: &AliasName) -> Option<AliasType> {
        self.firewall.alias(name).map(|a| a.content.alias_type())
    }

    fn has_item(&self, kind: ItemKind, id: &Uuid) -> bool {
        match kind {
            ItemKind::Dhcp4Subnet => self.dhcpv4.subnets.contains(id),
            ItemKind::WgPeer => self.wireguard.peers.contains(id),
            ItemKind::WgServer => self.wireguard.servers.contains(id),
            ItemKind::FilterRule => self.firewall.rules.contains(id),
        }
    }

    fn has_gateway(&self, name: &GatewayName) -> bool {
        self.gateways.has(name)
    }

    fn gateway_family(&self, name: &GatewayName) -> Option<IpFamily> {
        let g = self.gateways.gateway(name)?;
        Some(match g.address {
            Some(std::net::IpAddr::V4(_)) => IpFamily::Inet,
            Some(std::net::IpAddr::V6(_)) => IpFamily::Inet6,
            None => g.family,
        })
    }

    fn has_group(&self, name: &GroupName) -> bool {
        self.system.groups.values().any(|g| &g.name == name)
    }
}
