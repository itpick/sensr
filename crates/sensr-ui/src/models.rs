//! View models for the routing-slice pages, their form/grid metadata, and the registries that
//! let a serializable id ([`FormId`], [`GridId`]) stand in for a model type across the
//! server/browser boundary.
//!
//! Field names, labels and order follow the OPNsense forms admins know; types are stricter.
//! These are UI-side shapes over sensr-api's JSON; they move to `sensr-schema` metadata once it
//! exports form descriptions.

use crate::api::FieldError;
use crate::form::{ChoiceSet, FieldKind as K, FieldSpec as F, FormModel, Inputs, apply_inputs};
use crate::grid::{Column, GridModel};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Generates a fresh object key. Server side only; the browser never mints keys.
pub fn new_uuid() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let a = t ^ n.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    format!(
        "{:08x}-{:04x}-4{:03x}-a{:03x}-{:012x}",
        (a >> 32) as u32,
        (a >> 16) as u16,
        a & 0xfff,
        n & 0xfff,
        a.rotate_left(17) & 0xffff_ffff_ffff
    )
}

// ---------------------------------------------------------------- System › Settings › General

/// System › Settings › General.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SystemGeneral {
    /// Host name without domain.
    pub hostname: String,
    /// Domain.
    pub domain: String,
    /// IANA time zone.
    pub timezone: String,
    /// Upstream DNS servers.
    pub dns_servers: Vec<String>,
    /// Let DHCP/PPP on WAN override the DNS servers.
    pub dns_allow_override: bool,
    /// Allow IPv6 traffic at all.
    pub ipv6_allow: bool,
}

const TIMEZONES: &[(&str, &str)] = &[
    ("Etc/UTC", "Etc/UTC"),
    ("America/Chicago", "America/Chicago"),
    ("America/Los_Angeles", "America/Los_Angeles"),
    ("America/New_York", "America/New_York"),
    ("Europe/Amsterdam", "Europe/Amsterdam"),
    ("Europe/Berlin", "Europe/Berlin"),
    ("Europe/London", "Europe/London"),
    ("Asia/Tokyo", "Asia/Tokyo"),
    ("Australia/Sydney", "Australia/Sydney"),
];

impl FormModel for SystemGeneral {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("hostname", "Hostname", K::Hostname)
                .required()
                .help("Name of the firewall host, without domain part."),
            F::new("domain", "Domain", K::Hostname)
                .required()
                .help("Do not use 'local' as a domain name; it breaks local name resolution."),
            F::new("timezone", "Timezone", K::Select(TIMEZONES)),
            F::new("dns_servers", "DNS servers", K::IpLines)
                .help("One address per line. Used by the system and offered to DHCP clients."),
            F::new("dns_allow_override", "DNS server options", K::Checkbox)
                .help("Allow DNS server list to be overridden by DHCP/PPP on WAN."),
            F::new("ipv6_allow", "Allow IPv6", K::Checkbox)
                .help("Allow IPv6 traffic. When off, all IPv6 is blocked."),
        ];
        FIELDS
    }
}

// ---------------------------------------------------------------- Interfaces

/// IPv4 configuration type.
pub const IPV4_TYPES: &[(&str, &str)] = &[
    ("none", "None"),
    ("static", "Static IPv4"),
    ("dhcp", "DHCP"),
];

/// IPv6 configuration type.
pub const IPV6_TYPES: &[(&str, &str)] = &[
    ("none", "None"),
    ("static", "Static IPv6"),
    ("dhcp6", "DHCPv6"),
    ("slaac", "SLAAC"),
    ("track6", "Track Interface"),
];

/// An interface assignment with its addressing (Interfaces › [WAN] etc.).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Interface {
    /// Assignment id: `wan`, `lan`, `opt1`… Immutable after creation.
    pub id: String,
    /// Kernel device.
    pub device: String,
    /// Description shown in menus (`WAN`).
    pub description: String,
    /// Interface enabled.
    pub enabled: bool,
    /// Block RFC 1918 sources.
    pub block_private: bool,
    /// Block bogon sources.
    pub block_bogons: bool,
    /// IPv4 configuration type.
    pub ipv4_type: String,
    /// Static IPv4 address/prefix.
    pub ipv4_address: String,
    /// Static IPv4 upstream gateway.
    pub ipv4_gateway: String,
    /// IPv6 configuration type.
    pub ipv6_type: String,
    /// Static IPv6 address/prefix.
    pub ipv6_address: String,
    /// MTU; empty for the device default.
    pub mtu: Option<u16>,
}

/// Kernel devices offered in the assignment dialog (mock inventory until the agent reports).
pub const DEVICES: &[(&str, &str)] = &[
    ("eth0", "eth0 (52:54:00:12:34:01)"),
    ("eth1", "eth1 (52:54:00:12:34:02)"),
    ("eth2", "eth2 (52:54:00:12:34:03)"),
    ("wg0", "wg0 (WireGuard)"),
];

impl FormModel for Interface {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enable", K::Checkbox),
            F::new("description", "Description", K::Text).required(),
            F::new("device", "Device", K::Select(DEVICES)).required(),
            F::new("block_private", "Block private networks", K::Checkbox)
                .help("Block traffic from RFC 1918 and unique local addresses on this interface."),
            F::new("block_bogons", "Block bogon networks", K::Checkbox),
            F::new(
                "ipv4_type",
                "IPv4 Configuration Type",
                K::Select(IPV4_TYPES),
            ),
            F::new("ipv4_address", "IPv4 address", K::Cidr),
            F::new("ipv4_gateway", "IPv4 upstream gateway", K::Ipv4),
            F::new(
                "ipv6_type",
                "IPv6 Configuration Type",
                K::Select(IPV6_TYPES),
            ),
            F::new("ipv6_address", "IPv6 address", K::Cidr),
            F::new(
                "mtu",
                "MTU",
                K::Number {
                    min: 576,
                    max: 9216,
                },
            )
            .help("Leave empty to use the device default."),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        if self.ipv4_type == "static" && self.ipv4_address.is_empty() {
            e.push(FieldError::new(
                "ipv4_address",
                "A static IPv4 configuration needs an address.",
            ));
        }
        if self.ipv4_type == "static"
            && !self.ipv4_address.is_empty()
            && !self.ipv4_address.contains('.')
        {
            e.push(FieldError::new(
                "ipv4_address",
                "This is not an IPv4 address.",
            ));
        }
        if self.ipv6_type == "static" && self.ipv6_address.is_empty() {
            e.push(FieldError::new(
                "ipv6_address",
                "A static IPv6 configuration needs an address.",
            ));
        }
        e
    }
}

impl GridModel for Interface {
    const KEY: &'static str = "id";
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::text("id", "Interface"),
            Column::text("description", "Description"),
            Column::text("device", "Device"),
            Column::text("ipv4_address", "IPv4"),
            Column::bool("enabled", "Enabled"),
        ];
        C
    }
}

// ---------------------------------------------------------------- Firewall › Aliases

/// Alias types.
pub const ALIAS_TYPES: &[(&str, &str)] = &[
    ("host", "Host(s)"),
    ("network", "Network(s)"),
    ("port", "Port(s)"),
    ("url", "URL (IPs)"),
    ("url_table", "URL Table (IPs)"),
    ("geo_ip", "GeoIP"),
    ("asn", "BGP ASN"),
    ("network_group", "Network group"),
    ("mac", "MAC address"),
    ("external", "External (advanced)"),
];

/// A firewall alias.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Alias {
    /// Object key.
    pub uuid: String,
    /// Enabled.
    pub enabled: bool,
    /// Name referenced by rules.
    pub name: String,
    /// Alias type.
    #[serde(rename = "type")]
    pub kind: String,
    /// Entries, one per line.
    pub content: Vec<String>,
    /// Description.
    pub description: String,
}

impl FormModel for Alias {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enabled", K::Checkbox),
            F::new("name", "Name", K::Text)
                .required()
                .help("Letters, digits and underscores; must not start with a digit."),
            F::new("type", "Type", K::Select(ALIAS_TYPES)).required(),
            F::new("content", "Content", K::Lines).help("One entry per line."),
            F::new("description", "Description", K::Text),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        let ok_name = self.name.len() <= 31
            && self
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !self.name.starts_with(|c: char| c.is_ascii_digit());
        if !ok_name {
            e.push(FieldError::new(
                "name",
                "The name must be at most 31 characters: letters, digits and '_', not starting with a digit.",
            ));
        }
        let bad = |entry: &str| -> bool {
            match self.kind.as_str() {
                _ if entry.starts_with("alias:") => false,
                "host" => {
                    let e = entry.trim_start_matches('!');
                    e.parse::<std::net::IpAddr>().is_err() && !e.contains(['.', '-', ':'])
                }
                "network" => {
                    let e = entry.trim_start_matches('!');
                    !e.contains('/') && e.parse::<std::net::IpAddr>().is_err()
                }
                "port" => !entry.split(['-', ':']).all(|p| {
                    p.parse::<u16>().is_ok_and(|n| n > 0)
                        || p.chars().all(|c| c.is_ascii_alphanumeric())
                }),
                "url" | "url_table" => {
                    !(entry.starts_with("http://") || entry.starts_with("https://"))
                }
                _ => false,
            }
        };
        if let Some(entry) = self.content.iter().find(|c| bad(c)) {
            e.push(FieldError::new(
                "content",
                format!("Entry \u{201c}{entry}\u{201d} is not valid for this alias type."),
            ));
        }
        e
    }
}

impl GridModel for Alias {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::bool("enabled", "Enabled"),
            Column::text("name", "Name"),
            Column::text("type", "Type"),
            Column::list("content", "Content"),
            Column::text("description", "Description"),
        ];
        C
    }
}

// ---------------------------------------------------------------- Firewall › Rules

const ACTIONS: &[(&str, &str)] = &[("pass", "Pass"), ("block", "Block"), ("reject", "Reject")];
const DIRECTIONS: &[(&str, &str)] = &[("in", "in"), ("out", "out"), ("any", "any")];
const IPPROTO: &[(&str, &str)] = &[("inet", "IPv4"), ("inet6", "IPv6"), ("inet46", "IPv4+IPv6")];
/// Protocols as the schema spells them.
pub const PROTOCOLS: &[(&str, &str)] = &[
    ("any", "any"),
    ("tcp", "TCP"),
    ("udp", "UDP"),
    ("tcp/udp", "TCP/UDP"),
    ("icmp", "ICMP"),
    ("ipv6-icmp", "IPV6-ICMP"),
    ("esp", "ESP"),
    ("gre", "GRE"),
];

/// Interfaces a rule can be placed on, when the document is not at hand (tests).
pub const RULE_INTERFACES: &[(&str, &str)] = &[
    ("floating", "Floating"),
    ("wan", "WAN"),
    ("lan", "LAN"),
    ("opt1", "WireGuard"),
];

/// Interfaces NAT rules can egress/ingress on.
pub const NAT_INTERFACES: &[(&str, &str)] =
    &[("wan", "WAN"), ("lan", "LAN"), ("opt1", "WireGuard")];

/// A filter rule. List order is evaluation order.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterRule {
    /// Object key.
    pub uuid: String,
    /// Evaluation order (lowest first); changed by reordering, not edited.
    pub sequence: Option<u32>,
    /// Enabled.
    pub enabled: bool,
    /// Pass, block or reject.
    pub action: String,
    /// Stop at first match.
    pub quick: bool,
    /// Interface (or `floating`).
    pub interface: String,
    /// in/out.
    pub direction: String,
    /// Address family.
    pub ipprotocol: String,
    /// L4 protocol.
    pub protocol: String,
    /// Source (address, network, alias or `any`).
    pub source: String,
    /// Source port.
    pub source_port: String,
    /// Destination.
    pub destination: String,
    /// Destination port.
    pub destination_port: String,
    /// Log matches.
    pub log: bool,
    /// Description.
    pub description: String,
}

impl FormModel for FilterRule {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enabled", K::Checkbox),
            F::new("action", "Action", K::Select(ACTIONS)).required(),
            F::new("quick", "Quick", K::Checkbox)
                .help("Apply the action immediately on match, without evaluating later rules."),
            F::new("interface", "Interface", K::Choice(ChoiceSet::RuleInterfaces)).required(),
            F::new("direction", "Direction", K::Select(DIRECTIONS)),
            F::new("ipprotocol", "Version", K::Select(IPPROTO)),
            F::new("protocol", "Protocol", K::Select(PROTOCOLS)),
            F::new("source", "Source", K::Text).help(
                "'any', an address or network, 'net:lan' / 'addr:lan', 'alias:name' or 'self'; prefix '!' to invert.",
            ),
            F::new("source_port", "Source port", K::Text),
            F::new("destination", "Destination", K::Text),
            F::new("destination_port", "Destination port", K::Text),
            F::new("log", "Log", K::Checkbox).help("Log packets that are handled by this rule."),
            F::new("description", "Description", K::Text),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        let ports_ok = |p: &str| {
            p.is_empty()
                || p == "any"
                || p.starts_with("alias:")
                || p.split(['-', ':'])
                    .all(|n| n.parse::<u16>().is_ok_and(|n| n > 0))
                || p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        };
        let l4 = matches!(self.protocol.as_str(), "tcp" | "udp" | "tcp/udp");
        for (path, v) in [
            ("source_port", &self.source_port),
            ("destination_port", &self.destination_port),
        ] {
            if !v.is_empty() && v != "any" && !l4 {
                e.push(FieldError::new(
                    path,
                    "Ports need protocol TCP, UDP or TCP/UDP.",
                ));
            } else if !ports_ok(v) {
                e.push(FieldError::new(
                    path,
                    "Enter a port, a range (80-90) or alias:name.",
                ));
            }
        }
        e
    }
}

impl GridModel for FilterRule {
    const ORDERED: bool = true;
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::bool("enabled", "Enabled"),
            Column::text("action", "Action"),
            Column::text("protocol", "Protocol"),
            Column::endpoint("source", "Source"),
            Column::port("source_port", "Port"),
            Column::endpoint("destination", "Destination"),
            Column::port("destination_port", "Port"),
            Column::text("description", "Description"),
        ];
        C
    }
}

// ---------------------------------------------------------------- Firewall › NAT

/// Source (outbound) NAT mode.
pub const SNAT_MODES: &[(&str, &str)] = &[
    ("automatic", "Automatic outbound NAT rule generation"),
    ("hybrid", "Hybrid outbound NAT rule generation"),
    ("manual", "Manual outbound NAT rule generation"),
    ("disabled", "Disable outbound NAT rule generation"),
];

/// Source NAT mode settings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SourceNatMode {
    /// One of [`SNAT_MODES`].
    pub mode: String,
}

impl FormModel for SourceNatMode {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[F::new("mode", "Mode", K::Select(SNAT_MODES))
            .help("Automatic rules translate every local network to the WAN address.")];
        FIELDS
    }
}

/// A manual source NAT (outbound) rule.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SourceNatRule {
    /// Object key.
    pub uuid: String,
    /// Evaluation order (lowest first); changed by reordering, not edited.
    pub sequence: Option<u32>,
    /// Enabled.
    pub enabled: bool,
    /// Do not NAT matching traffic.
    pub nonat: bool,
    /// Egress interface.
    pub interface: String,
    /// Protocol.
    pub protocol: String,
    /// Source network.
    pub source: String,
    /// Destination.
    pub destination: String,
    /// Translation target; empty for the interface address.
    pub target: String,
    /// Description.
    pub description: String,
}

impl FormModel for SourceNatRule {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enabled", K::Checkbox),
            F::new("nonat", "Do not NAT", K::Checkbox),
            F::new("interface", "Interface", K::Choice(ChoiceSet::Interfaces)).required(),
            F::new("protocol", "Protocol", K::Select(PROTOCOLS)),
            F::new("source", "Source", K::Text).required(),
            F::new("destination", "Destination", K::Text),
            F::new("target", "Translation / target", K::Text)
                .help("Leave empty for the interface address, or enter an address or alias:name."),
            F::new("description", "Description", K::Text),
        ];
        FIELDS
    }
}

impl GridModel for SourceNatRule {
    const ORDERED: bool = true;
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::bool("enabled", "Enabled"),
            Column::text("interface", "Interface"),
            Column::endpoint("source", "Source"),
            Column::endpoint("destination", "Destination"),
            Column::endpoint("target", "NAT"),
            Column::text("description", "Description"),
        ];
        C
    }
}

/// A destination NAT rule (port forward).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PortForward {
    /// Object key.
    pub uuid: String,
    /// Evaluation order (lowest first); changed by reordering, not edited.
    pub sequence: Option<u32>,
    /// Enabled.
    pub enabled: bool,
    /// Ingress interface.
    pub interface: String,
    /// Protocol.
    pub protocol: String,
    /// Original destination (usually the WAN address).
    pub destination: String,
    /// Original destination port.
    pub destination_port: String,
    /// Redirect target IP.
    pub target: String,
    /// Redirect target port.
    pub target_port: String,
    /// Description.
    pub description: String,
}

impl FormModel for PortForward {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enabled", K::Checkbox),
            F::new("interface", "Interface", K::Choice(ChoiceSet::Interfaces)).required(),
            F::new("protocol", "Protocol", K::Select(PROTOCOLS)),
            F::new("destination", "Destination", K::Text)
                .help("Usually 'addr:wan', the WAN address."),
            F::new("destination_port", "Destination port", K::Text).required(),
            F::new("target", "Redirect target IP", K::Text)
                .required()
                .help("An address or alias:name."),
            F::new("target_port", "Redirect target port", K::Text),
            F::new("description", "Description", K::Text),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        if !matches!(self.protocol.as_str(), "tcp" | "udp" | "tcp/udp") {
            e.push(FieldError::new(
                "protocol",
                "Port forwards need protocol TCP, UDP or TCP/UDP.",
            ));
        }
        e
    }
}

impl GridModel for PortForward {
    const ORDERED: bool = true;
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::bool("enabled", "Enabled"),
            Column::text("interface", "Interface"),
            Column::text("protocol", "Protocol"),
            Column::port("destination_port", "Dest. port"),
            Column::text("target", "Target"),
            Column::text("target_port", "Target port"),
            Column::text("description", "Description"),
        ];
        C
    }
}

// ---------------------------------------------------------------- Services › DHCPv4

/// Per-interface DHCPv4 server settings (the interface's subnet in the schema).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DhcpSettings {
    /// Serve DHCP on this interface.
    pub enabled: bool,
    /// The subnet served (from the interface address; shown, not edited).
    pub subnet: String,
    /// DNS servers handed out; empty for the interface address.
    pub dns_servers: Vec<String>,
    /// Gateway handed out; empty for the interface address.
    pub gateway: String,
    /// Domain name handed out.
    pub domain: String,
    /// Lease time, seconds; empty for the server default.
    pub lease: Option<u32>,
}

fn ipv4_num(s: &str) -> Option<u32> {
    s.parse::<std::net::Ipv4Addr>().ok().map(u32::from)
}

impl FormModel for DhcpSettings {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enable", K::Checkbox)
                .help("Enable the DHCP server on this interface."),
            F::new("dns_servers", "DNS servers", K::IpLines)
                .help("Leave empty to hand out this interface's address."),
            F::new("gateway", "Gateway", K::Ipv4)
                .help("Leave empty to hand out this interface's address."),
            F::new("domain", "Domain name", K::Hostname),
            F::new(
                "lease",
                "Lease time (seconds)",
                K::Number {
                    min: 60,
                    max: 31_536_000,
                },
            )
            .help("Leave empty for the server default."),
        ];
        FIELDS
    }
}

/// A DHCPv4 address pool.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DhcpRange {
    /// Row key (pool index).
    pub uuid: String,
    /// First address.
    pub from: String,
    /// Last address.
    pub to: String,
}

impl FormModel for DhcpRange {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("from", "From", K::Ipv4).required(),
            F::new("to", "To", K::Ipv4).required(),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        match (ipv4_num(&self.from), ipv4_num(&self.to)) {
            (Some(a), Some(b)) if a > b => vec![FieldError::new(
                "to",
                "The range end must not be before its start.",
            )],
            _ => vec![],
        }
    }
}

impl GridModel for DhcpRange {
    const TOGGLE: Option<&'static str> = None;
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[Column::text("from", "From"), Column::text("to", "To")];
        C
    }
}

/// A DHCPv4 static mapping.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StaticMap {
    /// Object key.
    pub uuid: String,
    /// Client MAC address.
    pub mac: String,
    /// Reserved IPv4 address.
    pub ipaddr: String,
    /// Hostname.
    pub hostname: String,
    /// Description.
    pub description: String,
}

impl FormModel for StaticMap {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("mac", "MAC address", K::Mac).required(),
            F::new("ipaddr", "IP address", K::Ipv4)
                .required()
                .help("Should be outside the dynamic range."),
            F::new("hostname", "Hostname", K::Hostname),
            F::new("description", "Description", K::Text),
        ];
        FIELDS
    }
}

impl GridModel for StaticMap {
    const TOGGLE: Option<&'static str> = None;
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::text("mac", "MAC address"),
            Column::text("ipaddr", "IP address"),
            Column::text("hostname", "Hostname"),
            Column::text("description", "Description"),
        ];
        C
    }
}

// ---------------------------------------------------------------- Services › Unbound DNS

/// Unbound DNS › General.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UnboundGeneral {
    /// Enable the resolver.
    pub enabled: bool,
    /// Listen port.
    pub port: Option<u16>,
    /// Listen interfaces; empty for all.
    pub interfaces: Vec<String>,
    /// DNSSEC validation.
    pub dnssec: bool,
    /// Register DHCP leases.
    pub register_dhcp_leases: bool,
    /// Register DHCP static mappings.
    pub register_dhcp_static: bool,
    /// Local zone type.
    pub local_zone_type: String,
}

const ZONE_TYPES: &[(&str, &str)] = &[
    ("transparent", "transparent"),
    ("typetransparent", "typetransparent"),
    ("static", "static"),
    ("refuse", "refuse"),
    ("deny", "deny"),
    ("redirect", "redirect"),
    ("inform", "inform"),
    ("inform_deny", "inform_deny"),
    ("nodefault", "nodefault"),
    ("always_transparent", "always_transparent"),
    ("always_refuse", "always_refuse"),
    ("always_nxdomain", "always_nxdomain"),
];

impl FormModel for UnboundGeneral {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enable Unbound", K::Checkbox),
            F::new("port", "Listen Port", K::Number { min: 1, max: 65535 }),
            F::new("interfaces", "Network Interfaces", K::Lines)
                .help("Interface names, one per line. Empty listens on all."),
            F::new("dnssec", "Enable DNSSEC Support", K::Checkbox),
            F::new("register_dhcp_leases", "Register DHCP Leases", K::Checkbox),
            F::new(
                "register_dhcp_static",
                "Register DHCP Static Mappings",
                K::Checkbox,
            ),
            F::new("local_zone_type", "Local Zone Type", K::Select(ZONE_TYPES)),
        ];
        FIELDS
    }
}

const RR_TYPES: &[(&str, &str)] = &[
    ("A", "A (IPv4 address)"),
    ("AAAA", "AAAA (IPv6 address)"),
    ("MX", "MX (Mail server)"),
    ("TXT", "TXT (Text record)"),
];

/// Unbound host override.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HostOverride {
    /// Object key.
    pub uuid: String,
    /// Enabled.
    pub enabled: bool,
    /// Host label; `*` for a wildcard.
    pub hostname: String,
    /// Domain.
    pub domain: String,
    /// Record type.
    pub rr: String,
    /// Address for A/AAAA.
    pub server: String,
    /// Mail host for MX.
    pub mx: String,
    /// MX priority.
    pub mxprio: Option<u16>,
    /// Description.
    pub description: String,
}

impl FormModel for HostOverride {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enabled", K::Checkbox),
            F::new("hostname", "Host", K::Text)
                .required()
                .help("Use '*' to create a wildcard entry."),
            F::new("domain", "Domain", K::Hostname).required(),
            F::new("rr", "Type", K::Select(RR_TYPES)).required(),
            F::new("server", "IP address", K::Text).help("For TXT records: the text."),
            F::new("mx", "MX Host", K::Text),
            F::new("mxprio", "MX Priority", K::Number { min: 0, max: 65535 }),
            F::new("description", "Description", K::Text),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        if self.hostname != "*"
            && !self
                .hostname
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            e.push(FieldError::new(
                "hostname",
                "The host name contains invalid characters.",
            ));
        }
        match self.rr.as_str() {
            "A" if self.server.parse::<std::net::Ipv4Addr>().is_err() => {
                e.push(FieldError::new(
                    "server",
                    "An A record needs an IPv4 address.",
                ));
            }
            "AAAA" if self.server.parse::<std::net::Ipv6Addr>().is_err() => {
                e.push(FieldError::new(
                    "server",
                    "An AAAA record needs an IPv6 address.",
                ));
            }
            "MX" if self.mx.is_empty() => {
                e.push(FieldError::new("mx", "An MX record needs a mail host."));
            }
            _ => {}
        }
        e
    }
}

impl GridModel for HostOverride {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::bool("enabled", "Enabled"),
            Column::text("hostname", "Host"),
            Column::text("domain", "Domain"),
            Column::text("rr", "Type"),
            Column::text("server", "Value"),
            Column::text("description", "Description"),
        ];
        C
    }
}

// ---------------------------------------------------------------- VPN › WireGuard

fn is_wg_key(s: &str) -> bool {
    s.len() == 44
        && s.ends_with('=')
        && s[..43]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
}

/// A WireGuard instance (local endpoint).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WgInstance {
    /// Object key.
    pub uuid: String,
    /// Enabled.
    pub enabled: bool,
    /// Name.
    pub name: String,
    /// Instance number (wgN); assigned when empty.
    pub instance: Option<u32>,
    /// Public key.
    pub pubkey: String,
    /// Private key (write-only).
    pub privkey: String,
    /// UDP listen port.
    pub port: Option<u16>,
    /// MTU.
    pub mtu: Option<u16>,
    /// Tunnel addresses.
    pub tunneladdress: Vec<String>,
    /// DNS servers.
    pub dns: Vec<String>,
    /// Do not install routes for peers' allowed IPs.
    pub disableroutes: bool,
    /// Peer names.
    pub peers: Vec<String>,
}

impl FormModel for WgInstance {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enabled", K::Checkbox),
            F::new("name", "Name", K::Text).required(),
            F::new("pubkey", "Public key", K::Text).required(),
            F::new("instance", "Instance", K::Number { min: 0, max: 9999 })
                .help("Device number (wg0, wg1, …). Leave empty to pick the next free one."),
            F::new("privkey", "Private key", K::Secret).help(
                "Write-only: required for a new instance, leave empty to keep the stored key.",
            ),
            F::new("port", "Listen port", K::Number { min: 1, max: 65535 }),
            F::new(
                "mtu",
                "MTU",
                K::Number {
                    min: 1280,
                    max: 9000,
                },
            ),
            F::new("tunneladdress", "Tunnel address", K::CidrLines),
            F::new("dns", "DNS servers", K::IpLines),
            F::new("disableroutes", "Disable routes", K::Checkbox),
            F::new("peers", "Peers", K::Lines).help("Peer names, one per line."),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        if !is_wg_key(&self.pubkey) {
            e.push(FieldError::new(
                "pubkey",
                "Not a valid WireGuard key (44 characters base64).",
            ));
        }
        if self.uuid.is_empty() && self.privkey.is_empty() {
            e.push(FieldError::new(
                "privkey",
                "A new instance needs a private key.",
            ));
        }
        if !self.privkey.is_empty() && !is_wg_key(&self.privkey) {
            e.push(FieldError::new(
                "privkey",
                "Not a valid WireGuard key (44 characters base64).",
            ));
        }
        e
    }
}

impl GridModel for WgInstance {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::bool("enabled", "Enabled"),
            Column::text("name", "Name"),
            Column::text("port", "Port"),
            Column::list("tunneladdress", "Tunnel address"),
            Column::text("pubkey", "Public key"),
        ];
        C
    }
}

/// A WireGuard peer.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct WgPeer {
    /// Object key.
    pub uuid: String,
    /// Enabled.
    pub enabled: bool,
    /// Name.
    pub name: String,
    /// Peer public key.
    pub pubkey: String,
    /// Pre-shared key (write-only).
    pub psk: String,
    /// Allowed IPs.
    pub tunneladdress: Vec<String>,
    /// Endpoint address.
    pub serveraddress: String,
    /// Endpoint port.
    pub serverport: Option<u16>,
    /// Instance names this peer belongs to (computed; edit on the instance).
    pub servers: Vec<String>,
    /// Keepalive interval, seconds.
    pub keepalive: Option<u16>,
}

impl FormModel for WgPeer {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enabled", K::Checkbox),
            F::new("name", "Name", K::Text).required(),
            F::new("pubkey", "Public key", K::Text).required(),
            F::new("psk", "Pre-shared key", K::Secret)
                .help("Write-only: leave empty to keep the stored key."),
            F::new("tunneladdress", "Allowed IPs", K::CidrLines).required(),
            F::new("serveraddress", "Endpoint address", K::Text),
            F::new(
                "serverport",
                "Endpoint port",
                K::Number { min: 1, max: 65535 },
            ),
            F::new(
                "keepalive",
                "Keepalive interval",
                K::Number { min: 1, max: 86400 },
            ),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        if !is_wg_key(&self.pubkey) {
            e.push(FieldError::new(
                "pubkey",
                "Not a valid WireGuard key (44 characters base64).",
            ));
        }
        if self.serverport.is_some() && self.serveraddress.is_empty() {
            e.push(FieldError::new(
                "serveraddress",
                "An endpoint port needs an endpoint address.",
            ));
        }
        e
    }
}

impl GridModel for WgPeer {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::bool("enabled", "Enabled"),
            Column::text("name", "Name"),
            Column::text("serveraddress", "Endpoint"),
            Column::list("tunneladdress", "Allowed IPs"),
            Column::list("servers", "Instances"),
        ];
        C
    }
}

// ---------------------------------------------------------------- registries

/// Serializable stand-in for a settings form's model type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FormId {
    /// [`SystemGeneral`].
    SystemGeneral,
    /// [`Interface`] (scope: interface id).
    Interface,
    /// [`SourceNatMode`].
    SourceNatMode,
    /// [`DhcpSettings`] (scope: interface id).
    DhcpSettings,
    /// [`UnboundGeneral`].
    UnboundGeneral,
}

/// Serializable stand-in for a grid's row type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GridId {
    /// Interfaces › Assignments.
    Assignments,
    /// Firewall › Aliases.
    Aliases,
    /// Firewall › Rules (scope: interface).
    FilterRules,
    /// Firewall › NAT › Source NAT.
    SourceNat,
    /// Firewall › NAT › Destination NAT.
    PortForwards,
    /// Services › DHCPv4 ranges (scope: interface).
    DhcpRanges,
    /// Services › DHCPv4 static mappings (scope: interface).
    StaticMaps,
    /// Services › Unbound DNS › Overrides.
    HostOverrides,
    /// VPN › WireGuard › Instances.
    WgInstances,
    /// VPN › WireGuard › Peers.
    WgPeers,
}

fn sanitize(scope: &Option<String>, default: &str) -> String {
    scope
        .as_deref()
        .filter(|s| !s.is_empty() && s.len() <= 32)
        .filter(|s| s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(default)
        .to_owned()
}

impl FormId {
    /// Field descriptions.
    pub fn fields(self) -> &'static [F] {
        match self {
            Self::SystemGeneral => SystemGeneral::fields(),
            Self::Interface => Interface::fields(),
            Self::SourceNatMode => SourceNatMode::fields(),
            Self::DhcpSettings => DhcpSettings::fields(),
            Self::UnboundGeneral => UnboundGeneral::fields(),
        }
    }

    /// Parses and validates inputs over `base`, returning the model as JSON.
    pub fn apply(self, base: &Value, inputs: &Inputs) -> Result<Value, Vec<FieldError>> {
        fn go<T: FormModel>(base: &Value, inputs: &Inputs) -> Result<Value, Vec<FieldError>> {
            let m: T = apply_inputs(base, inputs)?;
            serde_json::to_value(m).map_err(|e| vec![FieldError::new("", e.to_string())])
        }
        match self {
            Self::SystemGeneral => go::<SystemGeneral>(base, inputs),
            Self::Interface => go::<Interface>(base, inputs),
            Self::SourceNatMode => go::<SourceNatMode>(base, inputs),
            Self::DhcpSettings => go::<DhcpSettings>(base, inputs),
            Self::UnboundGeneral => go::<UnboundGeneral>(base, inputs),
        }
    }

    /// The scope a form edits (an interface id), sanitised; defaults to LAN.
    pub fn scope(self, scope: &Option<String>) -> String {
        match self {
            Self::Interface | Self::DhcpSettings => sanitize(scope, "lan"),
            _ => String::new(),
        }
    }
}

impl GridId {
    /// Column descriptions.
    pub fn columns(self) -> &'static [Column] {
        self.meta().columns
    }

    /// Key field, toggle field, reorderability and the default row.
    pub fn meta(self) -> GridMeta {
        match self {
            Self::Assignments => GridMeta::of::<Interface>(),
            Self::Aliases => GridMeta::of::<Alias>(),
            Self::FilterRules => GridMeta::of::<FilterRule>(),
            Self::SourceNat => GridMeta::of::<SourceNatRule>(),
            Self::PortForwards => GridMeta::of::<PortForward>(),
            Self::DhcpRanges => GridMeta::of::<DhcpRange>(),
            Self::StaticMaps => GridMeta::of::<StaticMap>(),
            Self::HostOverrides => GridMeta::of::<HostOverride>(),
            Self::WgInstances => GridMeta::of::<WgInstance>(),
            Self::WgPeers => GridMeta::of::<WgPeer>(),
        }
    }

    /// Parses and validates a row edited in the dialog.
    pub fn apply(self, base: &Value, inputs: &Inputs) -> Result<Value, Vec<FieldError>> {
        fn go<T: FormModel>(base: &Value, inputs: &Inputs) -> Result<Value, Vec<FieldError>> {
            let m: T = apply_inputs(base, inputs)?;
            serde_json::to_value(m).map_err(|e| vec![FieldError::new("", e.to_string())])
        }
        match self {
            Self::Assignments => go::<Interface>(base, inputs),
            Self::Aliases => go::<Alias>(base, inputs),
            Self::FilterRules => go::<FilterRule>(base, inputs),
            Self::SourceNat => go::<SourceNatRule>(base, inputs),
            Self::PortForwards => go::<PortForward>(base, inputs),
            Self::DhcpRanges => go::<DhcpRange>(base, inputs),
            Self::StaticMaps => go::<StaticMap>(base, inputs),
            Self::HostOverrides => go::<HostOverride>(base, inputs),
            Self::WgInstances => go::<WgInstance>(base, inputs),
            Self::WgPeers => go::<WgPeer>(base, inputs),
        }
    }

    /// Redacts secrets from a row before it goes to the browser.
    pub fn redact(self, row: &Value) -> Value {
        match self {
            Self::WgInstances => crate::form::redact::<WgInstance>(row),
            Self::WgPeers => crate::form::redact::<WgPeer>(row),
            _ => row.clone(),
        }
    }

    /// The scope a grid shows (an interface id), sanitised; defaults to LAN.
    pub fn scope(self, scope: &Option<String>) -> String {
        match self {
            Self::FilterRules | Self::DhcpRanges | Self::StaticMaps => sanitize(scope, "lan"),
            _ => String::new(),
        }
    }

    /// Default JSON for a new row.
    pub fn new_row(self) -> Value {
        let mut v = self.meta().default_row;
        if let Some(obj) = v.as_object_mut() {
            if obj.contains_key("enabled") {
                obj.insert("enabled".into(), Value::Bool(true));
            }
            let defaults: &[(&str, &str)] = match self {
                Self::FilterRules => &[
                    ("action", "pass"),
                    ("direction", "in"),
                    ("ipprotocol", "inet"),
                    ("protocol", "any"),
                    ("source", "any"),
                    ("destination", "any"),
                ],
                Self::Aliases => &[("type", "host")],
                Self::HostOverrides => &[("rr", "A")],
                Self::PortForwards => &[
                    ("interface", "wan"),
                    ("protocol", "tcp"),
                    ("destination", "addr:wan"),
                ],
                Self::SourceNat => &[("interface", "wan"), ("protocol", "any"), ("source", "any")],
                Self::Assignments => &[("ipv4_type", "none"), ("ipv6_type", "none")],
                _ => &[],
            };
            for (k, val) in defaults {
                obj.insert((*k).into(), Value::String((*val).into()));
            }
        }
        v
    }
}

/// Static facts about a grid's row type.
#[derive(Debug, Clone)]
pub struct GridMeta {
    /// Columns.
    pub columns: &'static [Column],
    /// Dialog fields.
    pub fields: &'static [F],
    /// Key field.
    pub key: &'static str,
    /// Enable/disable field, if any.
    pub toggle: Option<&'static str>,
    /// Rows can be reordered.
    pub ordered: bool,
    /// `T::default()` as JSON.
    pub default_row: Value,
}

impl GridMeta {
    fn of<T: GridModel>() -> Self {
        Self {
            columns: T::columns(),
            fields: T::fields(),
            key: T::KEY,
            toggle: T::TOGGLE,
            ordered: T::ORDERED,
            default_row: serde_json::to_value(T::default()).unwrap_or(Value::Null),
        }
    }
}

/// Links a form model type to its serializable id.
pub trait FormKind: FormModel {
    /// The id.
    const ID: FormId;
}

/// Links a grid row type to its serializable id.
pub trait GridKind: GridModel {
    /// The id.
    const ID: GridId;
    /// Singular noun for dialog titles ("Add alias").
    const NOUN: &'static str;
}

macro_rules! kinds {
    (forms: $($f:ident),*; grids: $($g:ident => $gid:ident, $noun:literal),*) => {
        $(impl FormKind for $f { const ID: FormId = FormId::$f; })*
        $(impl GridKind for $g { const ID: GridId = GridId::$gid; const NOUN: &'static str = $noun; })*
    };
}

kinds! {
    forms: SystemGeneral, Interface, SourceNatMode, DhcpSettings, UnboundGeneral;
    grids: Interface => Assignments, "interface",
        Alias => Aliases, "alias",
        FilterRule => FilterRules, "rule",
        SourceNatRule => SourceNat, "source NAT rule",
        PortForward => PortForwards, "port forward",
        DhcpRange => DhcpRanges, "range",
        StaticMap => StaticMaps, "static mapping",
        HostOverride => HostOverrides, "host override",
        WgInstance => WgInstances, "instance",
        WgPeer => WgPeers, "peer"
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn alias_rejects_bad_names_and_entries() {
        let inputs: Inputs = [("name", "1bad"), ("type", "port"), ("content", "80\nhttp!")]
            .iter()
            .map(|(a, b)| ((*a).into(), (*b).into()))
            .collect();
        let errs = GridId::Aliases.apply(&json!({}), &inputs).unwrap_err();
        let paths: Vec<_> = errs.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["name", "content"]);
    }

    #[test]
    fn wireguard_keeps_private_key_when_left_empty() {
        let key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
        let stored = json!({"name": "wg0", "pubkey": key, "privkey": key});
        let inputs: Inputs = [("name", "wg0"), ("pubkey", key), ("privkey", "")]
            .iter()
            .map(|(a, b)| ((*a).into(), (*b).into()))
            .collect();
        let v = GridId::WgInstances.apply(&stored, &inputs).unwrap();
        assert_eq!(v["privkey"], key);
        assert_eq!(GridId::WgInstances.redact(&v)["privkey"], "");
    }

    #[test]
    fn every_grid_has_meta_and_new_rows_deserialize() {
        for g in [
            GridId::Assignments,
            GridId::Aliases,
            GridId::FilterRules,
            GridId::SourceNat,
            GridId::PortForwards,
            GridId::DhcpRanges,
            GridId::StaticMaps,
            GridId::HostOverrides,
            GridId::WgInstances,
            GridId::WgPeers,
        ] {
            let meta = g.meta();
            assert!(!meta.columns.is_empty());
            for c in meta.columns {
                assert!(
                    meta.default_row.get(c.path).is_some(),
                    "{g:?} column {} is not a model field",
                    c.path
                );
            }
            for f in meta.fields {
                assert!(
                    crate::form::get_path(&meta.default_row, f.path).is_some(),
                    "{g:?} field {} is not a model field",
                    f.path
                );
            }
            assert!(g.new_row().is_object());
        }
    }

    #[test]
    fn scope_is_sanitised() {
        assert_eq!(GridId::DhcpRanges.scope(&Some("lan.evil".into())), "lan");
        assert_eq!(GridId::FilterRules.scope(&Some("opt1".into())), "opt1");
    }
}
