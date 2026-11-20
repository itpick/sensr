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

/// The mock backend's network cards (the real ones come from the agent).
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
            F::new("device", "Device", K::Choice(ChoiceSet::Devices))
                .required()
                .help("Cards are bound by their MAC address: moving a card to another slot or USB port keeps its network."),
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
    /// URL table refresh period, whole days.
    pub refresh_days: Option<u16>,
    /// URL table refresh period, additional hours.
    pub refresh_hours: Option<u8>,
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
            F::new("content", "Content", K::Lines).help(
                "One entry per line. BGP ASN: AS numbers (AS64500 or 64500); URL table: one URL.",
            ),
            F::new("refresh_days", "Refresh frequency (days)", K::Number { min: 0, max: 999 })
                .help("URL table only: how often the list is fetched again. Leave both empty for the default."),
            F::new("refresh_hours", "Refresh frequency (hours)", K::Number { min: 0, max: 23 })
                .help("URL table only: hours on top of the days."),
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
                "asn" => {
                    let d = entry.trim();
                    let d = d
                        .strip_prefix("AS")
                        .or_else(|| d.strip_prefix("as"))
                        .unwrap_or(d);
                    d.parse::<u32>().is_err()
                }
                _ => false,
            }
        };
        if self.kind == "url_table" && self.content.len() > 1 {
            e.push(FieldError::new(
                "content",
                "A URL table loads a single URL; use a URL alias for several.",
            ));
        }
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
            Column::status("loaded", "Loaded"),
            Column::status("updated", "Last updated"),
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
    /// Synthesize AAAA records (DNS64).
    pub dns64: bool,
    /// DNS64 prefix; empty for `64:ff9b::/96`.
    pub dns64_prefix: String,
    /// Register DHCP leases.
    pub register_dhcp_leases: bool,
    /// Domain for registered leases; empty for the system domain.
    pub dhcp_domain: String,
    /// Register DHCP static mappings.
    pub register_dhcp_static: bool,
    /// Do not publish the firewall's own A/AAAA records (inverse of the schema's
    /// `register_firewall_records`, as OPNsense words it).
    pub no_register_records: bool,
    /// Publish descriptions as TXT records.
    pub txt_descriptions: bool,
    /// Local zone type.
    pub local_zone_type: String,
    /// Keep query statistics.
    pub statistics: bool,
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

fn is_v6_cidr(s: &str) -> bool {
    s.split_once('/').is_some_and(|(a, l)| {
        a.parse::<std::net::Ipv6Addr>().is_ok() && l.parse::<u8>().is_ok_and(|l| l <= 128)
    })
}

impl FormModel for UnboundGeneral {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enable Unbound", K::Checkbox),
            F::new("port", "Listen Port", K::Number { min: 1, max: 65535 })
                .help("The TCP/UDP port used for responding to DNS queries."),
            F::new("interfaces", "Network Interfaces", K::Lines)
                .help("Interface names, one per line. Empty listens on all."),
            F::new("dnssec", "Enable DNSSEC Support", K::Checkbox),
            F::new("dns64", "Enable DNS64 Support", K::Checkbox).help(
                "Synthesize AAAA records from A records if no actual AAAA records are present.",
            ),
            F::new("dns64_prefix", "DNS64 Prefix", K::Cidr)
                .help("Leave empty for the well-known prefix 64:ff9b::/96."),
            F::new("register_dhcp_leases", "Register DHCP Leases", K::Checkbox).help(
                "Machines that send their hostname when requesting a DHCP lease are registered, so that their name can be resolved.",
            ),
            F::new("dhcp_domain", "DHCP Domain Override", K::Hostname).help(
                "The domain name to use for DHCP lease registration. If empty, the system domain is used.",
            ),
            F::new(
                "register_dhcp_static",
                "Register DHCP Static Mappings",
                K::Checkbox,
            ),
            F::new(
                "no_register_records",
                "Do not register system A/AAAA records",
                K::Checkbox,
            )
            .help(
                "No A/AAAA records for the listen interfaces are generated for the firewall's own name. Add them as host overrides if desired.",
            ),
            F::new("txt_descriptions", "TXT Comment Support", K::Checkbox).help(
                "Descriptions of host overrides and DHCP static mappings create a corresponding TXT record.",
            ),
            F::new("local_zone_type", "Local Zone Type", K::Select(ZONE_TYPES))
                .help("The local zone type used for the system domain. The default is 'transparent'."),
            F::new("statistics", "Enable Statistics", K::Checkbox)
                .help("Keep Unbound query statistics (shown under Statistics and on the Blocklist page)."),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        if !self.dns64_prefix.is_empty() && !is_v6_cidr(&self.dns64_prefix) {
            return vec![FieldError::new(
                "dns64_prefix",
                "Enter an IPv6 prefix, e.g. 64:ff9b::/96.",
            )];
        }
        vec![]
    }
}

// Unbound › Advanced, one form per OPNsense section. View field names are the schema's
// `dns.tuning` field names, so one adapter serves all four.

const U32: K = K::Number {
    min: 0,
    max: u32::MAX as i64,
};

/// Unbound log verbosity levels.
pub const LOG_VERBOSITY: &[(&str, &str)] = &[
    ("0", "Level 0"),
    ("1", "Level 1 (Default)"),
    ("2", "Level 2"),
    ("3", "Level 3"),
    ("4", "Level 4"),
    ("5", "Level 5"),
];

/// DNSSEC validation log levels; empty for Unbound's default.
pub const VAL_LOG_LEVEL: &[(&str, &str)] = &[
    ("", "Default"),
    ("0", "Level 0"),
    ("1", "Level 1"),
    ("2", "Level 2"),
];

/// Unbound › Advanced › General Settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UnboundAdvanced {
    /// Refuse `id.server` queries.
    pub hide_identity: bool,
    /// Refuse `version.server` queries.
    pub hide_version: bool,
    /// Fetch DNSKEYs early.
    pub prefetch_key: bool,
    /// Harden DNSSEC-stripped zones.
    pub harden_dnssec_stripped: bool,
    /// RFC 8020.
    pub harden_below_nxdomain: bool,
    /// RFC 8198.
    pub aggressive_nsec: bool,
    /// Strict QNAME minimisation.
    pub qname_minimisation_strict: bool,
    /// Outgoing TCP buffers.
    pub outgoing_num_tcp: Option<u32>,
    /// Incoming TCP buffers.
    pub incoming_num_tcp: Option<u32>,
    /// Queries per thread.
    pub num_queries_per_thread: Option<u32>,
    /// Outgoing ports per thread.
    pub outgoing_range: Option<u32>,
    /// Jostle timeout, ms.
    pub jostle_timeout: Option<u32>,
    /// Discard timeout, ms.
    pub discard_timeout: Option<u32>,
    /// Domains allowed to answer with private addresses.
    pub private_domains: Vec<String>,
    /// Rebinding protection ranges.
    pub private_addresses: Vec<String>,
    /// Domains not DNSSEC-validated.
    pub insecure_domains: Vec<String>,
}

impl Default for UnboundAdvanced {
    fn default() -> Self {
        Self {
            hide_identity: false,
            hide_version: false,
            prefetch_key: false,
            harden_dnssec_stripped: false,
            harden_below_nxdomain: true,
            aggressive_nsec: true,
            qname_minimisation_strict: false,
            outgoing_num_tcp: None,
            incoming_num_tcp: None,
            num_queries_per_thread: None,
            outgoing_range: None,
            jostle_timeout: None,
            discard_timeout: None,
            private_domains: vec![],
            private_addresses: vec![],
            insecure_domains: vec![],
        }
    }
}

impl FormModel for UnboundAdvanced {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("hide_identity", "Hide Identity", K::Checkbox)
                .help("If enabled, id.server and hostname.bind queries are refused."),
            F::new("hide_version", "Hide Version", K::Checkbox)
                .help("If enabled, version.server and version.bind queries are refused."),
            F::new("prefetch_key", "Prefetch DNS Key Support", K::Checkbox).help(
                "DNSKEYs are fetched earlier in the validation process when a delegation signer is encountered. Lowers latency at a little more CPU.",
            ),
            F::new("harden_dnssec_stripped", "Harden DNSSEC Data", K::Checkbox).help(
                "DNSSEC data is required for trust-anchored zones; if it is absent, the zone becomes bogus. If disabled, such a zone is made insecure.",
            ),
            F::new("harden_below_nxdomain", "Harden Below NXDOMAIN", K::Checkbox).help(
                "Stops queries for names under a known NXDOMAIN. May cause issues with very old software or non-DNSSEC reverse lookups.",
            ),
            F::new("aggressive_nsec", "Aggressive NSEC", K::Checkbox).help(
                "Use the DNSSEC-validated cache aggressively (RFC 8198) to reduce queries towards authorities.",
            ),
            F::new(
                "qname_minimisation_strict",
                "Strict QNAME Minimisation",
                K::Checkbox,
            )
            .help(
                "Never fall back to sending the full QNAME to broken name servers. Many domains will not resolve; only use if you know what you are doing.",
            ),
            F::new("outgoing_num_tcp", "Outgoing TCP Buffers", U32).help(
                "Outgoing TCP buffers per thread. 0 means no TCP queries to authoritative servers. Leave empty for the default.",
            ),
            F::new("incoming_num_tcp", "Incoming TCP Buffers", U32).help(
                "Incoming TCP buffers per thread. 0 means no TCP queries from clients are accepted.",
            ),
            F::new("num_queries_per_thread", "Number of queries per thread", U32).help(
                "Queries every thread services simultaneously; more are dropped unless older ones can be jostled out.",
            ),
            F::new("outgoing_range", "Outgoing Range", U32).help(
                "Ports opened per thread. Usually double the number of queries per thread.",
            ),
            F::new("jostle_timeout", "Jostle Timeout", U32)
                .help("Milliseconds after which a long-running query may be replaced when busy."),
            F::new("discard_timeout", "Discard Timeout", U32).help(
                "Milliseconds after which recursion requests are dropped. Keep it above the Client Expired Response Timeout.",
            ),
            F::new("private_domains", "Private Domains", K::HostnameLines).help(
                "One domain per line. These domains and their subdomains may contain private addresses.",
            ),
            F::new("private_addresses", "Rebind protection networks", K::CidrLines).help(
                "Addresses on your private network that may not be returned for public internet names (DNS rebinding protection). Empty turns the protection off.",
            ),
            F::new("insecure_domains", "Insecure Domains", K::HostnameLines)
                .help("One domain per line. The DNSSEC chain of trust is ignored towards these domains."),
        ];
        FIELDS
    }
}

/// Unbound › Advanced › Serve Expired Settings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UnboundServeExpired {
    /// Serve expired records.
    pub serve_expired: bool,
    /// TTL of expired answers.
    pub serve_expired_reply_ttl: Option<u32>,
    /// Serving window past expiry, seconds.
    pub serve_expired_ttl: Option<u32>,
    /// Reset the window on refresh.
    pub serve_expired_ttl_reset: bool,
    /// Wait before serving expired, ms.
    pub serve_expired_client_timeout: Option<u32>,
}

impl FormModel for UnboundServeExpired {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("serve_expired", "Serve Expired Responses", K::Checkbox).help(
                "Serve expired responses from the cache with a TTL of 0 without waiting for the actual resolution to finish.",
            ),
            F::new("serve_expired_reply_ttl", "Expired Record Reply TTL value", U32).help(
                "TTL to use when replying with expired data. With a client timeout, 30 is recommended (RFC 8767).",
            ),
            F::new("serve_expired_ttl", "TTL for Expired Responses", U32).help(
                "Seconds after expiration during which expired records may be served. 0 disables the limit; RFC 8767 suggests 86400 to 259200.",
            ),
            F::new("serve_expired_ttl_reset", "Reset Expired Record TTL", K::Checkbox).help(
                "Reset the TTL of expired records after a failed refresh, so they keep being served while queried.",
            ),
            F::new(
                "serve_expired_client_timeout",
                "Client Expired Response Timeout",
                U32,
            )
            .help(
                "Milliseconds to try resolving before replying with expired data. RFC 8767 recommends 1800; 0 disables this.",
            ),
        ];
        FIELDS
    }
}

/// Unbound › Advanced › Logging Settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UnboundLogging {
    /// Extended statistics.
    pub extended_statistics: bool,
    /// Log queries.
    pub log_queries: bool,
    /// Log replies.
    pub log_replies: bool,
    /// Tag queries and replies.
    pub log_tag_query_reply: bool,
    /// Log local zone actions.
    pub log_local_actions: bool,
    /// Log SERVFAIL reasons.
    pub log_servfail: bool,
    /// Verbosity, `"0"`..`"5"`.
    pub log_verbosity: String,
    /// Validation log level; empty for the default.
    pub val_log_level: String,
}

impl Default for UnboundLogging {
    fn default() -> Self {
        Self {
            extended_statistics: false,
            log_queries: false,
            log_replies: false,
            log_tag_query_reply: false,
            log_local_actions: false,
            log_servfail: false,
            log_verbosity: "1".into(),
            val_log_level: String::new(),
        }
    }
}

impl FormModel for UnboundLogging {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("extended_statistics", "Extended Statistics", K::Checkbox)
                .help("If enabled, extended statistics are printed."),
            F::new("log_queries", "Log Queries", K::Checkbox).help(
                "Print one line per query to the log. This makes the server (significantly) slower.",
            ),
            F::new("log_replies", "Log Replies", K::Checkbox).help(
                "Print one line per reply to the log. This makes the server (significantly) slower.",
            ),
            F::new("log_tag_query_reply", "Tag Queries and Replies", K::Checkbox)
                .help("Prefix logged queries and replies with 'query: ' and 'reply: '."),
            F::new("log_local_actions", "Log local actions", K::Checkbox)
                .help("Log lines about local zone actions, for all local zone types."),
            F::new("log_servfail", "Log SERVFAIL", K::Checkbox)
                .help("Log why queries return SERVFAIL to clients, at the error level."),
            F::new("log_verbosity", "Log Level Verbosity", K::Select(LOG_VERBOSITY)).help(
                "Level 0 logs errors only, 1 operational information, 2 detailed operational information, 3 per query, 4 algorithm level, 5 client identification for cache misses.",
            ),
            F::new("val_log_level", "Log validation level", K::Select(VAL_LOG_LEVEL)).help(
                "Print validation failures to the log regardless of verbosity: 1 one line per failed query, 2 also the reason and bad server.",
            ),
        ];
        FIELDS
    }
}

/// Unbound › Advanced › Cache Settings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UnboundCache {
    /// Prefetch popular entries.
    pub prefetch: bool,
    /// Unwanted reply threshold.
    pub unwanted_reply_threshold: Option<u32>,
    /// Message cache size (`4m`).
    pub msg_cache_size: String,
    /// RRset cache size.
    pub rrset_cache_size: String,
    /// Max TTL.
    pub cache_max_ttl: Option<u32>,
    /// Max negative TTL.
    pub cache_max_negative_ttl: Option<u32>,
    /// Min TTL.
    pub cache_min_ttl: Option<u32>,
    /// Host cache TTL.
    pub infra_host_ttl: Option<u32>,
    /// Keep probing down hosts.
    pub infra_keep_probing: bool,
    /// Hosts kept in the infrastructure cache.
    pub infra_cache_numhosts: Option<u32>,
}

/// `4m`, `512k`, `1g` or plain bytes.
fn is_cache_size(s: &str) -> bool {
    let num = s.strip_suffix(['k', 'K', 'm', 'M', 'g', 'G']).unwrap_or(s);
    num.parse::<u64>().is_ok_and(|n| n > 0)
}

impl FormModel for UnboundCache {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("prefetch", "Prefetch Support", K::Checkbox).help(
                "Prefetch message cache elements before they expire. Around 10% more DNS traffic, but popular names do not expire from the cache.",
            ),
            F::new("unwanted_reply_threshold", "Unwanted Reply Threshold", U32).help(
                "After this many unwanted replies the caches are cleared as a defence against poisoning. Leave empty to disable.",
            ),
            F::new("msg_cache_size", "Message Cache Size", K::Text).help(
                "Size of the message cache: plain bytes, or a number followed by k, m or g.",
            ),
            F::new("rrset_cache_size", "RRset Cache Size", K::Text).help(
                "Size of the RRset cache: plain bytes, or a number followed by k, m or g.",
            ),
            F::new("cache_max_ttl", "Maximum TTL for RRsets and messages", U32)
                .help("Seconds; caps very large TTLs so data is queried more often."),
            F::new(
                "cache_max_negative_ttl",
                "Maximum Negative TTL for RRsets and messages",
                U32,
            )
            .help("Seconds; caps how long negative answers are cached."),
            F::new("cache_min_ttl", "Minimum TTL for RRsets and messages", U32).help(
                "Seconds; data is cached at least this long, longer than the domain owner may intend. 0 keeps their TTLs.",
            ),
            F::new("infra_host_ttl", "TTL for Host Cache entries", U32)
                .help("Seconds to keep round-trip, lameness and EDNS data about upstream servers."),
            F::new("infra_keep_probing", "Keep probing down hosts", K::Checkbox)
                .help("Keep probing servers that are down, about every 120 seconds with backoff."),
            F::new("infra_cache_numhosts", "Number of Hosts to cache", U32)
                .help("Number of upstream servers whose information is cached."),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        [
            ("msg_cache_size", &self.msg_cache_size),
            ("rrset_cache_size", &self.rrset_cache_size),
        ]
        .into_iter()
        .filter(|(_, v)| !v.is_empty() && !is_cache_size(v))
        .map(|(p, _)| FieldError::new(p, "Enter a size such as 4m, 512k or 1g."))
        .collect()
    }
}

// Unbound › Access Lists.

/// Actions for clients no list matches.
pub const ACL_DEFAULT_ACTIONS: &[(&str, &str)] =
    &[("allow", "Allow"), ("deny", "Deny"), ("refuse", "Refuse")];

/// Actions of an access list.
pub const ACL_ACTIONS: &[(&str, &str)] = &[
    ("allow", "Allow"),
    ("deny", "Deny"),
    ("refuse", "Refuse"),
    ("allow_snoop", "Allow Snoop"),
    ("deny_non_local", "Deny Non-local"),
    ("refuse_non_local", "Refuse Non-local"),
];

/// Unbound › Access Lists: the default action.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UnboundAclDefault {
    /// One of [`ACL_DEFAULT_ACTIONS`].
    pub default_action: String,
}

impl FormModel for UnboundAclDefault {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[F::new(
            "default_action",
            "Default Action",
            K::Select(ACL_DEFAULT_ACTIONS),
        )
        .help(
            "By default Unbound allows queries from all networks. The most specific network wins, so the access lists below override this for their networks.",
        )];
        FIELDS
    }
}

/// One Unbound access list.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessList {
    /// Object key.
    pub uuid: String,
    /// Enabled.
    pub enabled: bool,
    /// Name.
    pub name: String,
    /// One of [`ACL_ACTIONS`].
    pub action: String,
    /// Networks in CIDR notation.
    pub networks: Vec<String>,
    /// Description.
    pub description: String,
}

impl FormModel for AccessList {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enabled", K::Checkbox).help("Enable or disable this ACL."),
            F::new("name", "Access List Name", K::Text)
                .required()
                .help("Provide an access list name."),
            F::new("action", "Action", K::Select(ACL_ACTIONS)).required().help(
                "Deny drops queries; Refuse answers REFUSED; Allow answers; Allow Snoop also answers non-recursive queries (cache snooping, admin hosts only); Deny/Refuse Non-local only answer local data.",
            ),
            F::new("networks", "Networks", K::CidrLines)
                .required()
                .help("Networks in CIDR notation, one per line, for example 192.168.1.0/24."),
            F::new("description", "Description", K::Text)
                .help("You may enter a description here for your reference."),
        ];
        FIELDS
    }
}

impl GridModel for AccessList {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::bool("enabled", "Enabled"),
            Column::text("name", "Name"),
            Column::text("action", "Action"),
            Column::list("networks", "Networks"),
            Column::text("description", "Description"),
        ];
        C
    }
}

// Unbound › Query Forwarding.

/// Unbound › Query Forwarding: the system-nameserver switch.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UnboundForwarding {
    /// Forward everything to the system DNS servers.
    pub use_system_servers: bool,
}

impl FormModel for UnboundForwarding {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[F::new("use_system_servers", "Use System Nameservers", K::Checkbox)
            .help(
                "Forward queries to the system nameservers (System › Settings › General). This overrides the entries below, except those for a specific domain.",
            )];
        FIELDS
    }
}

/// A forwarding server without TLS, optionally for one domain (a "domain override").
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Forwarder {
    /// Object key.
    pub uuid: String,
    /// Enabled.
    pub enabled: bool,
    /// Only for names under this domain; empty for everything.
    pub domain: String,
    /// Server address.
    pub server: String,
    /// Server port; empty for 53.
    pub port: Option<u16>,
    /// Description.
    pub description: String,
}

impl FormModel for Forwarder {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enabled", K::Checkbox).help("Enable or disable this server."),
            F::new("domain", "Domain", K::Hostname).help(
                "Queries for this domain are forwarded to this server. Leave blank to forward all queries.",
            ),
            F::new("server", "Server IP", K::Ip)
                .required()
                .help("IP address of the DNS server to forward requests to."),
            F::new("port", "Server Port", K::Number { min: 1, max: 65535 })
                .help("Leave empty for 53."),
            F::new("description", "Description", K::Text)
                .help("You may enter a description here for your reference (not parsed)."),
        ];
        FIELDS
    }
}

impl GridModel for Forwarder {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::bool("enabled", "Enabled"),
            Column::text("domain", "Domain"),
            Column::text("server", "Server IP"),
            Column::text("port", "Port"),
            Column::text("description", "Description"),
        ];
        C
    }
}

// Unbound › Blocklist.

/// The curated lists, grouped as OPNsense groups them. Values are sensr-schema's `KnownList`
/// names and labels its `label()`; a test keeps the two in step.
pub const KNOWN_LISTS: &[crate::form::OptGroup] = &[
    (
        "General Blocklists",
        &[
            ("adguard", "AdGuard List"),
            ("easylist", "EasyList"),
            ("easyprivacy", "EasyPrivacy"),
            ("steven-black", "Steven Black List"),
            ("yoyo", "YoYo List"),
        ],
    ),
    (
        "HaGeZi Multi - Clean the Internet",
        &[
            ("hagezi-light", "HaGeZi LIGHT - Relaxed Blocking"),
            ("hagezi-normal", "HaGeZi NORMAL - Relaxed/Balanced Blocking"),
            ("hagezi-pro", "HaGeZi PRO - Balanced Blocking"),
            (
                "hagezi-pro-plus",
                "HaGeZi PRO++ - Balanced/Aggressive Blocking",
            ),
            ("hagezi-ultimate", "HaGeZi ULTIMATE - Aggressive Blocking"),
        ],
    ),
    (
        "OISD Blocklists",
        &[
            ("oisd-small", "OISD Ads Blocklist"),
            ("oisd-big", "OISD Big Blocklist (incl. Ads)"),
            ("oisd-nsfw", "OISD NSFW Blocklist"),
        ],
    ),
    (
        "HaGeZi Targeted Lists",
        &[
            ("hagezi-tif", "HaGeZi Threat Intelligence Feeds"),
            ("hagezi-fake", "HaGeZi Fake - scams / fakes"),
            ("hagezi-popup-ads", "HaGeZi Pop-Up Ads"),
            ("hagezi-bypass", "HaGeZi DoH/VPN/TOR/Proxy Bypass"),
            ("hagezi-no-safesearch", "HaGeZi Safesearch not supported"),
            ("hagezi-dyndns", "HaGeZi Dynamic DNS blocking"),
            ("hagezi-hoster", "HaGeZi Badware Hoster blocking"),
            ("hagezi-anti-piracy", "HaGeZi Anti Piracy"),
            ("hagezi-gambling", "HaGeZi Gambling"),
            ("hagezi-social", "HaGeZi Social Networks"),
        ],
    ),
    (
        "Minimal Hardware Requirements",
        &[
            ("hagezi-pro-mini", "HaGeZi Multi PRO - Mini"),
            ("hagezi-pro-plus-mini", "HaGeZi Multi PRO++ - Mini"),
            ("hagezi-ultimate-mini", "HaGeZi Multi ULTIMATE - Mini"),
            (
                "hagezi-tif-medium",
                "HaGeZi Threat Intelligence Feeds - Medium",
            ),
            ("hagezi-tif-mini", "HaGeZi Threat Intelligence Feeds - Mini"),
            ("hagezi-gambling-medium", "HaGeZi Gambling - Medium"),
            ("hagezi-gambling-mini", "HaGeZi Gambling - Mini"),
        ],
    ),
];

/// The label of a curated list value, or the value itself if unknown.
pub fn known_list_label(value: &str) -> &str {
    KNOWN_LISTS
        .iter()
        .flat_map(|(_, opts)| opts.iter())
        .find(|(v, _)| *v == value)
        .map_or(value, |(_, l)| l)
}

/// How blocked names are answered.
pub const BLOCK_ANSWERS: &[(&str, &str)] = &[
    ("address", "Destination address"),
    ("nxdomain", "Return NXDOMAIN"),
];

/// A DNS blocklist policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Blocklist {
    /// Object key.
    pub uuid: String,
    /// Enabled.
    pub enabled: bool,
    /// What the policy is for.
    pub description: String,
    /// Curated lists ([`KNOWN_LISTS`] values).
    pub lists: Vec<String>,
    /// Curated list labels (computed for the grid; not edited).
    pub list_names: Vec<String>,
    /// Further list URLs.
    pub urls: Vec<String>,
    /// Allowed names: `name`, `*.name` or `/regex/`.
    pub allow: Vec<String>,
    /// Names blocked exactly.
    pub block: Vec<String>,
    /// Names blocked with their subdomains.
    pub block_subtrees: Vec<String>,
    /// Clients the policy applies to; empty for all.
    pub source_nets: Vec<String>,
    /// `address` or `nxdomain`.
    pub answer: String,
    /// Answer address; empty for 0.0.0.0.
    pub address: String,
    /// Seconds a downloaded list is reused.
    pub refresh_seconds: Option<u32>,
}

impl Default for Blocklist {
    fn default() -> Self {
        Self {
            uuid: String::new(),
            enabled: false,
            description: String::new(),
            lists: vec![],
            list_names: vec![],
            urls: vec![],
            allow: vec![],
            block: vec![],
            block_subtrees: vec![],
            source_nets: vec![],
            answer: "address".into(),
            address: String::new(),
            refresh_seconds: Some(72_000),
        }
    }
}

fn allow_entry_ok(e: &str) -> bool {
    if let Some(p) = e.strip_prefix('/') {
        // The pattern itself is checked by sensr-schema (it has the regex engine).
        return p.len() > 1 && p.ends_with('/');
    }
    crate::form::is_listed_name(e.strip_prefix("*.").unwrap_or(e))
}

impl FormModel for Blocklist {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enable", K::Checkbox).help("Enable the usage of this blocklist policy."),
            F::new("description", "Description", K::Text).required().help(
                "To keep track of which policies apply to which source networks, a description is required.",
            ),
            F::new("lists", "Type of DNSBL", K::MultiSelect(KNOWN_LISTS))
                .help("Select which curated lists to use."),
            F::new("urls", "URLs of Blocklists", K::Lines).help(
                "One URL per line. Hosts files, domain lists, *.domain wildcard lists and AdBlock-style ||domain^ lines are understood.",
            ),
            F::new("allow", "Allowlist Domains", K::Lines).help(
                "Names never blocked by this policy, one per line: name, *.name for a name and its subdomains, or /regex/. Applies only to this policy's lists.",
            ),
            F::new("block", "Blocklist Domains", K::ListedNameLines)
                .help("Names to block, one per line. Only exact matches."),
            F::new("block_subtrees", "Wildcard Domains", K::ListedNameLines).help(
                "Names to block with all their subdomains, one per line. Blocking first-level domains is not supported.",
            ),
            F::new("source_nets", "Source Net(s)", K::CidrLines).help(
                "Client networks this policy applies to, for example 192.168.1.0/24. Leave empty to apply to everything. Use one address family and equally sized networks to avoid priority issues.",
            ),
            F::new("answer", "Answer", K::Select(BLOCK_ANSWERS))
                .help("Answer blocked names with an address, or with the response code NXDOMAIN."),
            F::new("address", "Destination Address", K::Ipv4).help(
                "Address returned for blocked names; leave empty for 0.0.0.0. Not used with NXDOMAIN.",
            ),
            F::new(
                "refresh_seconds",
                "Refresh interval (seconds)",
                K::Number {
                    min: 60,
                    max: 31_536_000,
                },
            )
            .required()
            .help(
                "Downloaded lists are cached and reused this long before they are fetched again. Remote lists rarely change more than once a day; the default is 72000 (20 hours).",
            ),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        if self.enabled
            && self.lists.is_empty()
            && self.urls.is_empty()
            && self.block.is_empty()
            && self.block_subtrees.is_empty()
        {
            e.push(FieldError::new(
                "lists",
                "Select a list, add a URL or name a domain to block.",
            ));
        }
        if let Some(u) = self
            .urls
            .iter()
            .find(|u| !(u.starts_with("http://") || u.starts_with("https://")))
        {
            e.push(FieldError::new(
                "urls",
                format!("\u{201c}{u}\u{201d} is not an http(s) URL."),
            ));
        }
        if let Some(a) = self.allow.iter().find(|a| !allow_entry_ok(a)) {
            e.push(FieldError::new(
                "allow",
                format!("\u{201c}{a}\u{201d} is not a name, *.name or /regex/."),
            ));
        }
        e
    }
}

impl GridModel for Blocklist {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::bool("enabled", "Enabled"),
            Column::text("description", "Description"),
            Column::list("list_names", "Type of DNSBL"),
            Column::list("urls", "URLs"),
            Column::list("source_nets", "Source Net(s)"),
        ];
        C
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
    /// TTL in seconds; empty for the resolver default.
    pub ttl: Option<u32>,
    /// Also answer reverse lookups (A/AAAA).
    pub ptr: bool,
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
            F::new(
                "ttl",
                "TTL (seconds)",
                K::Number {
                    min: 0,
                    max: 2_147_483_647,
                },
            )
            .help("TTL of the record, e.g. 3600. Leave empty for the resolver default."),
            F::new("ptr", "Add PTR record", K::Checkbox).help(
                "Add a PTR record for this host. There can only be a single active PTR record per target address.",
            ),
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

// ---------------------------------------------------------------- System › Gateways

/// IPv4 or IPv6 next hop.
pub const GATEWAY_FAMILIES: &[(&str, &str)] = &[("inet", "IPv4"), ("inet6", "IPv6")];

/// System › Gateways › Configuration: one next hop.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Gateway {
    /// Object key.
    pub uuid: String,
    /// Enabled.
    pub enabled: bool,
    /// The name rules and groups refer to.
    pub name: String,
    /// Free text.
    pub description: String,
    /// Interface the next hop is reached through.
    pub interface: String,
    /// `inet` or `inet6`.
    pub family: String,
    /// Next-hop address; empty for a gateway learned from DHCP, PPP or router
    /// advertisements on the interface.
    pub address: String,
    /// Candidate for the default route.
    pub default_route: bool,
    /// The next hop is outside the interface's subnet.
    pub far: bool,
    /// Probe the gateway to detect failure.
    pub monitor: bool,
    /// Address to probe; empty probes the gateway address.
    pub monitor_address: String,
    /// Ranking among default-route candidates, 0 to 255: lower wins.
    pub priority: u32,
    /// Share of the traffic in a load-balancing group, 1 to 10.
    pub weight: u32,
    /// Treat the gateway as down whatever the probes say.
    pub force_down: bool,
}

impl Default for Gateway {
    fn default() -> Self {
        Self {
            uuid: String::new(),
            enabled: false,
            name: String::new(),
            description: String::new(),
            interface: String::new(),
            family: "inet".into(),
            address: String::new(),
            default_route: false,
            far: false,
            monitor: true,
            monitor_address: String::new(),
            priority: 255,
            weight: 1,
            force_down: false,
        }
    }
}

impl FormModel for Gateway {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enable", K::Checkbox),
            F::new("name", "Name", K::Text)
                .required()
                .help("Name of the gateway, used by routes, groups and rules (GW_WAN)."),
            F::new("description", "Description", K::Text),
            F::new("interface", "Interface", K::Choice(ChoiceSet::Interfaces))
                .required()
                .help("Interface the gateway is reached through."),
            F::new("family", "Address Family", K::Select(GATEWAY_FAMILIES)),
            F::new("address", "Gateway", K::Ip).help(
                "Next-hop address. Leave empty for a gateway learned from DHCP, PPP or router advertisements on the interface.",
            ),
            F::new("default_route", "Default gateway", K::Checkbox)
                .help("Use this gateway for the default route. With several candidates the priority decides."),
            F::new("far", "Far gateway", K::Checkbox)
                .help("The next hop is outside the interface's subnet."),
            F::new("monitor", "Enable gateway monitoring", K::Checkbox)
                .help("Probe the gateway and take it out of service when it stops answering."),
            F::new("monitor_address", "Monitor IP", K::Ip)
                .help("Address to probe instead of the gateway address."),
            F::new(
                "priority",
                "Priority",
                K::Number {
                    min: 0,
                    max: 255,
                },
            )
            .help("Lower wins when several default gateways are available."),
            F::new(
                "weight",
                "Weight",
                K::Number { min: 1, max: 10 },
            )
            .help("Share of the traffic when the gateway joins a load-balancing group."),
            F::new("force_down", "Force down", K::Checkbox)
                .help("Keep the gateway out of service regardless of the probes."),
        ];
        FIELDS
    }
}

impl GridModel for Gateway {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::bool("enabled", "Enabled"),
            Column::text("name", "Name"),
            Column::text("interface", "Interface"),
            Column::text("address", "Gateway"),
            Column::text("family", "Family"),
            Column::bool("default_route", "Default"),
            Column::bool("monitor", "Monitor"),
            Column::text("description", "Description"),
        ];
        C
    }
}

/// LAGG distribution protocol.
pub const LAGG_PROTOCOLS: &[(&str, &str)] = &[
    ("lacp", "LACP"),
    ("failover", "Failover"),
    ("loadbalance", "Load balancing"),
    ("roundrobin", "Round robin"),
    ("none", "None"),
];

/// Interfaces › Devices › Bridge: a layer-2 bridge between devices.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Bridge {
    /// Object key.
    pub uuid: String,
    /// Device name.
    pub device: String,
    /// Member devices.
    pub members: Vec<String>,
    /// Keep an IPv6 link-local address on the bridge.
    pub link_local: bool,
    /// Learned address table size.
    pub max_addresses: Option<u32>,
    /// Learned address timeout in seconds.
    pub ageing_time: Option<u32>,
    /// Free text.
    pub description: String,
}

impl FormModel for Bridge {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("device", "Device", K::Text)
                .required()
                .help("Name of the bridge, for example br0."),
            F::new("members", "Member devices", K::Lines)
                .required()
                .help("One device per line, for example ue1. Cards are named by the assignment they carry."),
            F::new("link_local", "Link-local address", K::Checkbox)
                .help("Keep an IPv6 link-local address on the bridge."),
            F::new(
                "max_addresses",
                "Address table size",
                K::Number {
                    min: 1,
                    max: 1_000_000,
                },
            )
            .help("Leave empty for the kernel default."),
            F::new(
                "ageing_time",
                "Ageing time (seconds)",
                K::Number {
                    min: 1,
                    max: 1_000_000,
                },
            )
            .help("How long a learned address is kept. Empty for the kernel default."),
            F::new("description", "Description", K::Text),
        ];
        FIELDS
    }
}

impl GridModel for Bridge {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::text("device", "Device"),
            Column::list("members", "Members"),
            Column::text("description", "Description"),
        ];
        C
    }

    const TOGGLE: Option<&'static str> = None;
}

/// Interfaces › Devices › LAGG: a link aggregate.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Lagg {
    /// Object key.
    pub uuid: String,
    /// Device name.
    pub device: String,
    /// Member devices.
    pub members: Vec<String>,
    /// Distribution protocol.
    pub protocol: String,
    /// Preferred member for failover.
    pub primary_member: String,
    /// LACP fast (1 s) timeout.
    pub lacp_fast_timeout: bool,
    /// MTU.
    pub mtu: Option<u16>,
    /// Free text.
    pub description: String,
}

impl FormModel for Lagg {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("device", "Device", K::Text)
                .required()
                .help("Name of the aggregate, for example bond0."),
            F::new("members", "Member devices", K::Lines)
                .required()
                .help("One device per line. Members must not carry an assignment of their own."),
            F::new("protocol", "Protocol", K::Select(LAGG_PROTOCOLS)),
            F::new("primary_member", "Primary member", K::Text)
                .help("Member the failover protocol prefers; empty picks the first."),
            F::new("lacp_fast_timeout", "LACP fast timeout", K::Checkbox),
            F::new(
                "mtu",
                "MTU",
                K::Number {
                    min: 1280,
                    max: 9000,
                },
            ),
            F::new("description", "Description", K::Text),
        ];
        FIELDS
    }
}

impl GridModel for Lagg {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::text("device", "Device"),
            Column::list("members", "Members"),
            Column::text("protocol", "Protocol"),
            Column::text("description", "Description"),
        ];
        C
    }

    const TOGGLE: Option<&'static str> = None;
}

/// Interfaces › Devices › Loopback: an extra `lo<id>` device.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoopbackDevice {
    /// Object key.
    pub uuid: String,
    /// Device number.
    pub id: u32,
    /// Free text.
    pub description: String,
}

impl FormModel for LoopbackDevice {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("id", "Device number", K::Number { min: 1, max: 9999 })
                .required()
                .help("The device is named lo<number>."),
            F::new("description", "Description", K::Text).required(),
        ];
        FIELDS
    }
}

impl GridModel for LoopbackDevice {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::text("id", "Device"),
            Column::text("description", "Description"),
        ];
        C
    }

    const TOGGLE: Option<&'static str> = None;
}

/// How a virtual IP is provided.
pub const VIP_MODES: &[(&str, &str)] = &[
    ("ip_alias", "IP alias"),
    ("proxy_arp", "Proxy ARP"),
    ("carp", "Shared address (CARP/VRRP)"),
];

/// Interfaces › Virtual IPs › Settings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VirtualIp {
    /// Object key.
    pub uuid: String,
    /// Interface carrying the address.
    pub interface: String,
    /// The address with its prefix length.
    pub address: String,
    /// How the address is provided.
    pub mode: String,
    /// Virtual host id for a shared address, 1 to 255.
    pub vhid: u32,
    /// Advertisement interval base in seconds.
    pub advbase: u32,
    /// Advertisement skew; higher loses elections.
    pub advskew: u32,
    /// Shared secret (write-only).
    pub password: String,
    /// Do not bind services to the address.
    pub no_bind: bool,
    /// Free text.
    pub description: String,
}

impl FormModel for VirtualIp {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("interface", "Interface", K::Choice(ChoiceSet::Interfaces))
                .required()
                .help("Interface the address belongs to."),
            F::new("address", "Address", K::Cidr)
                .required()
                .help("The address with its prefix length, for example 192.168.1.2/24."),
            F::new("mode", "Type", K::Select(VIP_MODES)),
            F::new(
                "vhid",
                "Virtual host ID",
                K::Number {
                    min: 1,
                    max: 255,
                },
            )
            .help("Unique per interface. Only for a shared address."),
            F::new(
                "advbase",
                "Advertisement base (seconds)",
                K::Number {
                    min: 1,
                    max: 254,
                },
            ),
            F::new(
                "advskew",
                "Advertisement skew",
                K::Number {
                    min: 0,
                    max: 254,
                },
            )
            .help("Higher skew loses the election."),
            F::new("password", "Password", K::Secret).help(
                "Shared secret of the failover pair. Write-only: leave empty to keep the stored one.",
            ),
            F::new("no_bind", "Do not bind services", K::Checkbox)
                .help("Services listen on the wildcard address instead of this one."),
            F::new("description", "Description", K::Text),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        if self.mode == "carp" && !self.uuid.is_empty() && self.password.is_empty() {
            // A new address needs the secret; an existing one keeps it.
        }
        if self.mode == "carp" && self.uuid.is_empty() && self.password.is_empty() {
            e.push(FieldError::new(
                "password",
                "A shared address needs the secret it shares with its peer.",
            ));
        }
        e
    }
}

impl GridModel for VirtualIp {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::text("interface", "Interface"),
            Column::text("address", "Address"),
            Column::text("mode", "Type"),
            Column::text("description", "Description"),
        ];
        C
    }

    const TOGGLE: Option<&'static str> = None;
}

/// Firewall › Groups: interface groups rules can name.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct InterfaceGroup {
    /// Object key.
    pub uuid: String,
    /// The name rules use.
    pub name: String,
    /// Member interfaces.
    pub members: Vec<String>,
    /// Include every WireGuard instance.
    pub wireguard: bool,
    /// Evaluation order between groups.
    pub sequence: u32,
    /// Hide the group from the interface menu.
    pub hidden: bool,
    /// Free text.
    pub description: String,
}

impl FormModel for InterfaceGroup {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("name", "Name", K::Text).required().help(
                "Name rules use for this group; it must differ from every interface identifier.",
            ),
            F::new("members", "Member interfaces", K::Lines)
                .help("One interface per line, for example lan or opt1."),
            F::new("wireguard", "Include every WireGuard instance", K::Checkbox),
            F::new(
                "sequence",
                "Sequence",
                K::Number {
                    min: 0,
                    max: 1_000_000,
                },
            )
            .help("Groups with a lower sequence are evaluated first."),
            F::new("hidden", "Hide from the interface menu", K::Checkbox),
            F::new("description", "Description", K::Text),
        ];
        FIELDS
    }
}

impl GridModel for InterfaceGroup {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::text("name", "Name"),
            Column::list("members", "Members"),
            Column::bool("hidden", "Hidden"),
            Column::text("description", "Description"),
        ];
        C
    }

    const TOGGLE: Option<&'static str> = None;
}

/// System › Access › Users: a local account.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct User {
    /// Object key.
    pub uuid: String,
    /// Login name.
    pub name: String,
    /// Numeric user id.
    pub uid: u32,
    /// Full name or note.
    pub description: String,
    /// Account locked.
    pub disabled: bool,
    /// New password (write-only); empty keeps the stored hash.
    pub password: String,
    /// Keys allowed to log in over SSH.
    pub authorized_keys: Vec<String>,
    /// Groups the user belongs to.
    pub groups: Vec<String>,
    /// Login shell.
    pub shell: String,
}

impl FormModel for User {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("name", "Username", K::Text)
                .required()
                .help("Login name."),
            F::new(
                "uid",
                "User ID",
                K::Number {
                    min: 0,
                    max: 65_000,
                },
            )
            .help("Numeric id, unique on the system. 0 is root; leave it empty on a new account and the next free id is assigned."),
            F::new("description", "Full name", K::Text),
            F::new("disabled", "Disabled", K::Checkbox)
                .help("A disabled account cannot log in, over the web GUI or SSH."),
            F::new("password", "Password", K::Secret).help(
                "Write-only: leave empty to keep the stored password. Changing it does not log the user out.",
            ),
            F::new("authorized_keys", "Authorized SSH keys", K::Lines)
                .help("One public key per line, as in authorized_keys."),
            F::new("groups", "Groups", K::Lines).help("One group name per line."),
            F::new("shell", "Login shell", K::Text)
                .help("Absolute path; leave empty for the system default."),
        ];
        FIELDS
    }
}

impl GridModel for User {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::text("name", "Username"),
            Column::text("uid", "User ID"),
            Column::text("description", "Full name"),
            Column::list("groups", "Groups"),
            Column::bool("disabled", "Disabled"),
        ];
        C
    }

    // The flag is inverted, so the bulk enable/disable buttons do not fit;
    // the column has a plain Disabled marker instead.
    const TOGGLE: Option<&'static str> = None;
}

/// System › Access › Groups: a local group and its privileges.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserGroup {
    /// Object key.
    pub uuid: String,
    /// Group name.
    pub name: String,
    /// Numeric group id.
    pub gid: u32,
    /// Free text.
    pub description: String,
    /// Privileges granted to members.
    pub privileges: Vec<String>,
}

impl FormModel for UserGroup {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("name", "Group name", K::Text).required(),
            F::new(
                "gid",
                "Group ID",
                K::Number {
                    min: 0,
                    max: 65_000,
                },
            )
            .help("Numeric id, unique on the system. Leave it empty on a new group and the next free id is assigned."),
            F::new("description", "Description", K::Text),
            F::new("privileges", "Privileges", K::Lines).help(
                "One privilege per line, for example page-all (the whole web GUI) or page-firewall-rules.",
            ),
        ];
        FIELDS
    }
}

impl GridModel for UserGroup {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::text("name", "Group name"),
            Column::text("gid", "Group ID"),
            Column::list("privileges", "Privileges"),
            Column::text("description", "Description"),
        ];
        C
    }

    const TOGGLE: Option<&'static str> = None;
}

// ---------------------------------------------------------------- System › Access › OpenID Connect

/// The master switch for OpenID Connect login.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct OidcSettings {
    /// Offer the configured providers on the login page.
    pub enabled: bool,
}

impl FormModel for OidcSettings {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[F::new("enabled", "Enable OpenID Connect login", K::Checkbox)
            .help("Adds a sign-in button for each enabled provider on the login page. Local passwords keep working.")];
        FIELDS
    }
}

/// Provider presets.
pub const OIDC_KINDS: &[(&str, &str)] = &[
    ("generic", "Generic OpenID Connect"),
    ("zitadel", "Zitadel"),
    ("google", "Google"),
    ("apple", "Apple"),
];

/// System › Access › OpenID Connect: one relying-party entry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct OidcProvider {
    /// Object key.
    pub uuid: String,
    /// Offered on the login page.
    pub enabled: bool,
    /// Provider preset.
    pub kind: String,
    /// Button text.
    pub name: String,
    /// Issuer identifier (discovery is fetched from it).
    pub issuer: String,
    /// Client id.
    pub client_id: String,
    /// Client secret (write-only; empty keeps the stored one).
    pub client_secret: String,
    /// Apple: team identifier.
    pub team_id: String,
    /// Apple: key identifier.
    pub key_id: String,
    /// Apple: `.p8` signing key (write-only; empty keeps the stored one).
    pub private_key: String,
    /// Extra scopes.
    pub scopes: Vec<String>,
    /// Claim that carries the login name.
    pub username_claim: String,
    /// Claim that lists provider groups.
    pub groups_claim: String,
    /// Provider groups allowed to sign in.
    pub allowed_groups: Vec<String>,
    /// Local group whose privileges the identity gets.
    pub local_group: String,
}

impl FormModel for OidcProvider {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enabled", K::Checkbox),
            F::new("name", "Button label", K::Text)
                .required()
                .help("Text on the login page, for example Zitadel."),
            F::new("kind", "Provider", K::Select(OIDC_KINDS))
                .help("Supplies defaults for scopes and claims; the protocol is the same."),
            F::new("issuer", "Issuer", K::Text)
                .required()
                .help("The provider's issuer identifier, for example https://id.example.com or https://accounts.google.com. Must use https (http only for localhost)."),
            F::new("client_id", "Client ID", K::Text).required(),
            F::new("client_secret", "Client secret", K::Secret).help(
                "Write-only: leave empty to keep the stored secret. Optional for public clients that use PKCE.",
            ),
            F::new("username_claim", "Username claim", K::Text)
                .help("Claim shown as the login name, for example email or preferred_username."),
            F::new("groups_claim", "Groups claim", K::Text).help(
                "Claim carrying the provider groups, for example groups. Leave empty when the provider has none.",
            ),
            F::new("allowed_groups", "Allowed provider groups", K::Lines)
                .help("One group name per line. Empty allows every authenticated identity."),
            F::new("local_group", "Local group", K::Text)
                .required()
                .help("Group in System › Access › Groups whose privileges the signed-in identity gets."),
            F::new("scopes", "Extra scopes", K::Lines)
                .help("openid, email and profile are requested automatically."),
            F::new("team_id", "Apple team ID", K::Text),
            F::new("key_id", "Apple key ID", K::Text),
            F::new("private_key", "Apple private key", K::Secret).help(
                "The .p8 key; with the team and key id it generates the short-lived client secret. Leave empty when a client secret is pasted instead.",
            ),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        if self.name.trim().is_empty() {
            e.push(FieldError::new(
                "name",
                "Enter a label for the login button.",
            ));
        }
        if !self.issuer.starts_with("https://") && !self.issuer.starts_with("http://") {
            e.push(FieldError::new("issuer", "Enter an http or https URL."));
        }
        if self.client_id.trim().is_empty() {
            e.push(FieldError::new("client_id", "Enter the client id."));
        }
        if self.local_group.trim().is_empty() {
            e.push(FieldError::new(
                "local_group",
                "Enter the local group whose privileges this provider grants.",
            ));
        }
        if self.username_claim.trim().is_empty() {
            e.push(FieldError::new(
                "username_claim",
                "Enter the claim that carries the login name.",
            ));
        }
        e
    }
}

impl GridModel for OidcProvider {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::text("name", "Button label"),
            Column::text("kind", "Provider"),
            Column::text("issuer", "Issuer"),
            Column::text("local_group", "Local group"),
            Column::bool("enabled", "Enabled"),
        ];
        C
    }

    const TOGGLE: Option<&'static str> = Some("enabled");
}

// ---------------------------------------------------------------- System › Access › SAML

/// The master switch for SAML login.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SamlSettings {
    /// Offer the configured providers on the login page.
    pub enabled: bool,
}

impl FormModel for SamlSettings {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[F::new("enabled", "Enable SAML login", K::Checkbox)
            .help("Adds a sign-in button for each enabled provider on the login page. Local passwords keep working.")];
        FIELDS
    }
}

/// System › Access › SAML: one service-provider entry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SamlProvider {
    /// Object key.
    pub uuid: String,
    /// Offered on the login page.
    pub enabled: bool,
    /// Button text.
    pub name: String,
    /// The identity provider's metadata XML.
    pub metadata: String,
    /// Attribute that carries the login name; empty uses the NameID.
    pub username_claim: String,
    /// Attribute that lists provider groups.
    pub groups_claim: String,
    /// Provider groups allowed to sign in.
    pub allowed_groups: Vec<String>,
    /// Local group whose privileges the identity gets.
    pub local_group: String,
}

impl FormModel for SamlProvider {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enabled", K::Checkbox),
            F::new("name", "Button label", K::Text)
                .required()
                .help("Text on the login page."),
            F::new("metadata", "Identity provider metadata", K::Lines)
                .required()
                .help("Paste the IdP's SAML metadata XML (the EntityDescriptor)."),
            F::new("username_claim", "Username attribute", K::Text).help(
                "SAML attribute that carries the login name; empty uses the assertion's NameID.",
            ),
            F::new("groups_claim", "Groups attribute", K::Text)
                .help("SAML attribute carrying provider groups, for example memberOf."),
            F::new("allowed_groups", "Allowed provider groups", K::Lines)
                .help("One group name per line. Empty allows every authenticated identity."),
            F::new("local_group", "Local group", K::Text)
                .required()
                .help("Group in System › Access › Groups whose privileges the signed-in identity gets."),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        if self.name.trim().is_empty() {
            e.push(FieldError::new(
                "name",
                "Enter a label for the login button.",
            ));
        }
        if self.metadata.trim().is_empty() {
            e.push(FieldError::new(
                "metadata",
                "Paste the identity provider metadata.",
            ));
        } else if !self.metadata.contains("EntityDescriptor") {
            e.push(FieldError::new(
                "metadata",
                "This is not SAML metadata: the EntityDescriptor element is missing.",
            ));
        }
        if self.local_group.trim().is_empty() {
            e.push(FieldError::new(
                "local_group",
                "Enter the local group whose privileges this provider grants.",
            ));
        }
        e
    }
}

impl GridModel for SamlProvider {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::text("name", "Button label"),
            Column::text("username_claim", "Username attribute"),
            Column::text("groups_claim", "Groups attribute"),
            Column::text("local_group", "Local group"),
            Column::text("sp_metadata", "Service provider metadata"),
            Column::bool("enabled", "Enabled"),
        ];
        C
    }

    const TOGGLE: Option<&'static str> = Some("enabled");
}

/// Failure condition of a gateway group.
pub const GROUP_TRIGGERS: &[(&str, &str)] = &[
    ("down", "Member down"),
    ("down_loss", "Packet loss"),
    ("down_latency", "High latency"),
    ("down_loss_latency", "Packet loss or high latency"),
];

/// System › Gateways › Group: failover or load balancing across gateways.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayGroup {
    /// Object key.
    pub uuid: String,
    /// The name rules refer to.
    pub name: String,
    /// Free text.
    pub description: String,
    /// Members, one `GATEWAY:tier` per line.
    pub members: Vec<String>,
    /// Failure condition.
    pub trigger: String,
}

impl FormModel for GatewayGroup {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("name", "Group name", K::Text)
                .required()
                .help("Name rules and routes use for this group."),
            F::new("description", "Description", K::Text),
            F::new("members", "Gateways", K::Lines).help(
                "One member per line as GATEWAY:tier, for example GW_WAN:1. The lowest tier with a member that is up carries the traffic; members of one tier share it by weight.",
            ),
            F::new("trigger", "Trigger Level", K::Select(GROUP_TRIGGERS))
                .help("What counts as the member being down."),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        for m in &self.members {
            let ok = m.rsplit_once(':').is_some_and(|(g, t)| {
                !g.is_empty() && t.parse::<u8>().is_ok_and(|t| (1..=5).contains(&t))
            });
            if !ok {
                e.push(FieldError::new(
                    "members",
                    format!("{m}: expected GATEWAY:tier with a tier from 1 to 5."),
                ));
            }
        }
        e
    }
}

impl GridModel for GatewayGroup {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::text("name", "Group name"),
            Column::list("members", "Gateways"),
            Column::text("trigger", "Trigger"),
            Column::text("description", "Description"),
        ];
        C
    }

    const TOGGLE: Option<&'static str> = None;
}

/// System › Routes › Configuration: a static route.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StaticRoute {
    /// Object key.
    pub uuid: String,
    /// Installed when true.
    pub enabled: bool,
    /// Destination network.
    pub network: String,
    /// Next hop: a gateway or group name.
    pub gateway: String,
    /// Free text.
    pub description: String,
}

impl FormModel for StaticRoute {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enable", K::Checkbox),
            F::new("network", "Destination network", K::Cidr)
                .required()
                .help("Network the route is for, for example 10.0.0.0/8."),
            F::new("gateway", "Gateway", K::Text).required().help(
                "Name of the gateway or gateway group the traffic goes to. Both families must match the destination.",
            ),
            F::new("description", "Description", K::Text),
        ];
        FIELDS
    }
}

impl GridModel for StaticRoute {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::bool("enabled", "Enabled"),
            Column::text("network", "Network"),
            Column::text("gateway", "Gateway"),
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

// ---------------------------------------------------------------- Services › Intrusion Detection

/// IDS capture modes.
pub const IDS_MODES: &[(&str, &str)] = &[
    ("detect", "Detect (IDS): alerts only"),
    ("prevent", "Prevent (IPS): inline, drop rules block"),
];

/// Which rules files load.
pub const IDS_PROFILES: &[(&str, &str)] = &[
    ("home", "Home: curated ET Open subset"),
    ("all", "All rules the sources ship"),
    ("custom", "Custom: the configured rules files"),
];

/// Services › Intrusion Detection › Settings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct IdsSettings {
    /// Run Suricata.
    pub enabled: bool,
    /// `detect` or `prevent`.
    pub mode: String,
    /// Interfaces to inspect.
    pub interfaces: Vec<String>,
    /// Extra home networks.
    pub home_net: Vec<String>,
    /// Add every interface's addresses to HOME_NET.
    pub home_net_auto: bool,
    /// Rules profile.
    pub profile: String,
    /// Include the default suppressions.
    pub default_suppressions: bool,
    /// Download rules daily.
    pub updates_enabled: bool,
    /// Download hour.
    pub update_hour: Option<u32>,
    /// Download minute.
    pub update_minute: Option<u32>,
    /// Days of alerts kept.
    pub retention_days: Option<u32>,
}

impl FormModel for IdsSettings {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enabled", K::Checkbox).help("Enable intrusion detection system."),
            F::new("mode", "Capture mode", K::Select(IDS_MODES)).help(
                "Detect captures a copy of the traffic and only alerts. Prevent queues forwarded traffic to Suricata, so drop rules block; it fails open, letting traffic through while the engine is stopped or overloaded.",
            ),
            F::new("interfaces", "Interfaces", K::Lines)
                .help("Interfaces to inspect (wan, lan, opt1), one per line."),
            F::new("home_net", "Home networks", K::CidrLines)
                .help("Networks to interpret as local, one per line."),
            F::new("home_net_auto", "Add interface addresses", K::Checkbox).help(
                "Also count every interface's addresses and subnets as home networks, following lease changes. This adds the WAN's current address, which is needed after NAT: outbound flows leave the WAN public-to-public, so without it most rules written for the home network never match.",
            ),
            F::new("profile", "Rules", K::Select(IDS_PROFILES)).help(
                "The home profile loads exploits, malware, command-and-control, scans and phishing rules: about a third of ET Open, light enough for a small router at gigabit speed.",
            ),
            F::new("default_suppressions", "Default suppressions", K::Checkbox).help(
                "Silence chatty informational signatures (STUN from video calls, stream-engine noise). They still run, and still drop in prevent mode.",
            ),
            F::new("updates_enabled", "Download rules daily", K::Checkbox),
            F::new("update_hour", "Download hour", K::Number { min: 0, max: 23 })
                .help("Local time; leave empty for 04."),
            F::new("update_minute", "Download minute", K::Number { min: 0, max: 59 }),
            F::new(
                "retention_days",
                "Keep alerts (days)",
                K::Number { min: 1, max: 3650 },
            )
            .help("Leave empty for 30 days."),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        if self.enabled && self.interfaces.is_empty() {
            e.push(FieldError::new(
                "interfaces",
                "Select at least one interface to inspect.",
            ));
        }
        e
    }
}

/// Which address of an alert a suppression is limited to.
pub const TRACK_BY: &[(&str, &str)] = &[
    ("", "Every address"),
    ("src", "Source address"),
    ("dst", "Destination address"),
    ("either", "Either address"),
];

/// A suppressed signature (`ids.suppressions`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct IdsSuppression {
    /// Object key.
    pub uuid: String,
    /// Enabled.
    pub enabled: bool,
    /// Signature id.
    pub sid: Option<u32>,
    /// Generator id.
    pub gid: Option<u32>,
    /// `src`, `dst`, `either`, or empty for every address.
    pub track_by: String,
    /// The addresses it is limited to.
    pub track_net: String,
    /// Why.
    pub description: String,
    /// Where it applies, for the grid (computed).
    pub applies: String,
}

impl FormModel for IdsSuppression {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enabled", K::Checkbox),
            F::new(
                "sid",
                "Signature id",
                K::Number {
                    min: 1,
                    max: 4_294_967_295,
                },
            )
            .required(),
            F::new(
                "gid",
                "Generator id",
                K::Number {
                    min: 1,
                    max: 4_294_967_295,
                },
            )
            .help("1 for normal rules; leave empty for 1."),
            F::new("track_by", "Limit to", K::Select(TRACK_BY)),
            F::new("track_net", "Addresses", K::Cidr)
                .help("A network or a single address with /32 (/128 for IPv6)."),
            F::new("description", "Description", K::Text),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        if !self.track_by.is_empty() && self.track_net.is_empty() {
            e.push(FieldError::new(
                "track_net",
                "Enter the addresses to limit the suppression to.",
            ));
        }
        if self.track_by.is_empty() && !self.track_net.is_empty() {
            e.push(FieldError::new(
                "track_by",
                "Choose which address of the alert these are.",
            ));
        }
        e
    }
}

impl GridModel for IdsSuppression {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::bool("enabled", "Enabled"),
            Column::text("sid", "Sid"),
            Column::text("applies", "Applies to"),
            Column::text("description", "Description"),
        ];
        C
    }
}

/// User-defined rule actions.
pub const USER_RULE_ACTIONS: &[(&str, &str)] =
    &[("alert", "Alert"), ("drop", "Drop"), ("pass", "Pass")];

/// A user-defined rule (`ids.user_rules`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct IdsUserRule {
    /// Object key.
    pub uuid: String,
    /// Enabled.
    pub enabled: bool,
    /// Description, also the alert message.
    pub description: String,
    /// Source network; empty for any.
    pub source: String,
    /// Destination network; empty for any.
    pub destination: String,
    /// TLS certificate SHA-1 fingerprint.
    pub fingerprint: String,
    /// Alert, drop or pass.
    pub action: String,
    /// With pass: stop inspecting the flow.
    pub bypass: bool,
}

impl FormModel for IdsUserRule {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enabled", K::Checkbox),
            F::new("description", "Description", K::Text)
                .required()
                .help("Also the message of the alerts it raises."),
            F::new("source", "Source", K::Cidr).help("A network or address/32; empty for any."),
            F::new("destination", "Destination", K::Cidr)
                .help("A network or address/32; empty for any."),
            F::new("fingerprint", "SSL fingerprint", K::Text)
                .help("SHA-1 fingerprint of a TLS certificate, as aa:bb:… (59 characters)."),
            F::new("action", "Action", K::Select(USER_RULE_ACTIONS)),
            F::new("bypass", "Bypass", K::Checkbox)
                .help("With pass: stop inspecting the matching flow altogether."),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut e = Vec::new();
        if self.source.is_empty() && self.destination.is_empty() && self.fingerprint.is_empty() {
            e.push(FieldError::new(
                "source",
                "Set a source, a destination or a fingerprint.",
            ));
        }
        let fp = &self.fingerprint;
        if !fp.is_empty()
            && !(fp.len() == 59
                && fp
                    .split(':')
                    .all(|b| b.len() == 2 && b.chars().all(|c| c.is_ascii_hexdigit())))
        {
            e.push(FieldError::new(
                "fingerprint",
                "A SSL fingerprint should be a 59 character long hex value.",
            ));
        }
        if self.bypass && self.action != "pass" {
            e.push(FieldError::new(
                "bypass",
                "Bypass only applies to pass rules.",
            ));
        }
        e
    }
}

impl GridModel for IdsUserRule {
    fn columns() -> &'static [Column] {
        const C: &[Column] = &[
            Column::bool("enabled", "Enabled"),
            Column::text("description", "Description"),
            Column::text("source", "Source"),
            Column::text("destination", "Destination"),
            Column::text("action", "Action"),
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
    /// [`UnboundAdvanced`].
    UnboundAdvanced,
    /// [`UnboundServeExpired`].
    UnboundServeExpired,
    /// [`UnboundLogging`].
    UnboundLogging,
    /// [`UnboundCache`].
    UnboundCache,
    /// [`UnboundAclDefault`].
    UnboundAclDefault,
    /// [`UnboundForwarding`].
    UnboundForwarding,
    /// [`IdsSettings`].
    IdsSettings,
    /// [`OidcSettings`].
    OidcSettings,
    /// [`SamlSettings`].
    SamlSettings,
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
    /// Services › Unbound DNS › Access Lists.
    AccessLists,
    /// Services › Unbound DNS › Query Forwarding (servers without TLS).
    Forwarders,
    /// Services › Unbound DNS › Blocklist.
    Blocklists,
    /// VPN › WireGuard › Instances.
    WgInstances,
    /// VPN › WireGuard › Peers.
    WgPeers,
    /// Services › Intrusion Detection › Rules (suppressions).
    IdsSuppressions,
    /// Services › Intrusion Detection › User defined.
    IdsUserRules,
    /// System › Gateways › Configuration.
    Gateways,
    /// System › Gateways › Group.
    GatewayGroups,
    /// System › Routes › Configuration.
    StaticRoutes,
    /// Interfaces › Devices › Bridge.
    Bridges,
    /// Interfaces › Devices › LAGG.
    Laggs,
    /// Interfaces › Devices › Loopback.
    Loopbacks,
    /// Interfaces › Virtual IPs › Settings.
    VirtualIps,
    /// Firewall › Groups.
    FirewallGroups,
    /// System › Access › Users.
    Users,
    /// System › Access › Groups.
    UserGroups,
    /// System › Access › OpenID Connect.
    OidcProviders,
    /// System › Access › SAML.
    SamlProviders,
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
            Self::UnboundAdvanced => UnboundAdvanced::fields(),
            Self::UnboundServeExpired => UnboundServeExpired::fields(),
            Self::UnboundLogging => UnboundLogging::fields(),
            Self::UnboundCache => UnboundCache::fields(),
            Self::UnboundAclDefault => UnboundAclDefault::fields(),
            Self::UnboundForwarding => UnboundForwarding::fields(),
            Self::IdsSettings => IdsSettings::fields(),
            Self::OidcSettings => OidcSettings::fields(),
            Self::SamlSettings => SamlSettings::fields(),
        }
    }

    /// The model's default value as JSON.
    pub fn default_value(self) -> Value {
        fn go<T: FormModel>() -> Value {
            serde_json::to_value(T::default()).unwrap_or(Value::Null)
        }
        match self {
            Self::SystemGeneral => go::<SystemGeneral>(),
            Self::Interface => go::<Interface>(),
            Self::SourceNatMode => go::<SourceNatMode>(),
            Self::DhcpSettings => go::<DhcpSettings>(),
            Self::UnboundGeneral => go::<UnboundGeneral>(),
            Self::UnboundAdvanced => go::<UnboundAdvanced>(),
            Self::UnboundServeExpired => go::<UnboundServeExpired>(),
            Self::UnboundLogging => go::<UnboundLogging>(),
            Self::UnboundCache => go::<UnboundCache>(),
            Self::UnboundAclDefault => go::<UnboundAclDefault>(),
            Self::UnboundForwarding => go::<UnboundForwarding>(),
            Self::IdsSettings => go::<IdsSettings>(),
            Self::OidcSettings => go::<OidcSettings>(),
            Self::SamlSettings => go::<SamlSettings>(),
        }
    }

    /// Forms over `dns.tuning`, whose view fields are the schema's field names.
    pub fn is_tuning(self) -> bool {
        matches!(
            self,
            Self::UnboundAdvanced
                | Self::UnboundServeExpired
                | Self::UnboundLogging
                | Self::UnboundCache
        )
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
            Self::UnboundAdvanced => go::<UnboundAdvanced>(base, inputs),
            Self::UnboundServeExpired => go::<UnboundServeExpired>(base, inputs),
            Self::UnboundLogging => go::<UnboundLogging>(base, inputs),
            Self::UnboundCache => go::<UnboundCache>(base, inputs),
            Self::UnboundAclDefault => go::<UnboundAclDefault>(base, inputs),
            Self::UnboundForwarding => go::<UnboundForwarding>(base, inputs),
            Self::IdsSettings => go::<IdsSettings>(base, inputs),
            Self::OidcSettings => go::<OidcSettings>(base, inputs),
            Self::SamlSettings => go::<SamlSettings>(base, inputs),
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
            Self::AccessLists => GridMeta::of::<AccessList>(),
            Self::Forwarders => GridMeta::of::<Forwarder>(),
            Self::Blocklists => GridMeta::of::<Blocklist>(),
            Self::WgInstances => GridMeta::of::<WgInstance>(),
            Self::WgPeers => GridMeta::of::<WgPeer>(),
            Self::IdsSuppressions => GridMeta::of::<IdsSuppression>(),
            Self::IdsUserRules => GridMeta::of::<IdsUserRule>(),
            Self::Gateways => GridMeta::of::<Gateway>(),
            Self::GatewayGroups => GridMeta::of::<GatewayGroup>(),
            Self::StaticRoutes => GridMeta::of::<StaticRoute>(),
            Self::Bridges => GridMeta::of::<Bridge>(),
            Self::Laggs => GridMeta::of::<Lagg>(),
            Self::Loopbacks => GridMeta::of::<LoopbackDevice>(),
            Self::VirtualIps => GridMeta::of::<VirtualIp>(),
            Self::FirewallGroups => GridMeta::of::<InterfaceGroup>(),
            Self::Users => GridMeta::of::<User>(),
            Self::UserGroups => GridMeta::of::<UserGroup>(),
            Self::OidcProviders => GridMeta::of::<OidcProvider>(),
            Self::SamlProviders => GridMeta::of::<SamlProvider>(),
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
            Self::AccessLists => go::<AccessList>(base, inputs),
            Self::Forwarders => go::<Forwarder>(base, inputs),
            Self::Blocklists => go::<Blocklist>(base, inputs),
            Self::WgInstances => go::<WgInstance>(base, inputs),
            Self::WgPeers => go::<WgPeer>(base, inputs),
            Self::IdsSuppressions => go::<IdsSuppression>(base, inputs),
            Self::IdsUserRules => go::<IdsUserRule>(base, inputs),
            Self::Gateways => go::<Gateway>(base, inputs),
            Self::GatewayGroups => go::<GatewayGroup>(base, inputs),
            Self::StaticRoutes => go::<StaticRoute>(base, inputs),
            Self::Bridges => go::<Bridge>(base, inputs),
            Self::Laggs => go::<Lagg>(base, inputs),
            Self::Loopbacks => go::<LoopbackDevice>(base, inputs),
            Self::VirtualIps => go::<VirtualIp>(base, inputs),
            Self::FirewallGroups => go::<InterfaceGroup>(base, inputs),
            Self::Users => go::<User>(base, inputs),
            Self::UserGroups => go::<UserGroup>(base, inputs),
            Self::OidcProviders => go::<OidcProvider>(base, inputs),
            Self::SamlProviders => go::<SamlProvider>(base, inputs),
        }
    }

    /// Redacts secrets from a row before it goes to the browser.
    pub fn redact(self, row: &Value) -> Value {
        match self {
            Self::WgInstances => crate::form::redact::<WgInstance>(row),
            Self::WgPeers => crate::form::redact::<WgPeer>(row),
            Self::OidcProviders => crate::form::redact::<OidcProvider>(row),
            Self::SamlProviders => crate::form::redact::<SamlProvider>(row),
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
                Self::AccessLists => &[("action", "allow")],
                Self::PortForwards => &[
                    ("interface", "wan"),
                    ("protocol", "tcp"),
                    ("destination", "addr:wan"),
                ],
                Self::SourceNat => &[("interface", "wan"), ("protocol", "any"), ("source", "any")],
                Self::Assignments => &[("ipv4_type", "none"), ("ipv6_type", "none")],
                Self::IdsUserRules => &[("action", "alert")],
                Self::OidcProviders => &[("kind", "generic"), ("username_claim", "email")],
                Self::SamlProviders => &[],
                _ => &[],
            };
            for (k, val) in defaults {
                obj.insert((*k).into(), Value::String((*val).into()));
            }
            if self == Self::HostOverrides {
                obj.insert("ptr".into(), Value::Bool(true));
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
    forms: SystemGeneral, Interface, SourceNatMode, DhcpSettings, UnboundGeneral, UnboundAdvanced,
        UnboundServeExpired, UnboundLogging, UnboundCache, UnboundAclDefault, UnboundForwarding,
        IdsSettings, OidcSettings, SamlSettings;
    grids: Interface => Assignments, "interface",
        Alias => Aliases, "alias",
        FilterRule => FilterRules, "rule",
        SourceNatRule => SourceNat, "source NAT rule",
        PortForward => PortForwards, "port forward",
        DhcpRange => DhcpRanges, "range",
        StaticMap => StaticMaps, "static mapping",
        HostOverride => HostOverrides, "host override",
        AccessList => AccessLists, "access list",
        Forwarder => Forwarders, "forwarding server",
        Blocklist => Blocklists, "blocklist policy",
        WgInstance => WgInstances, "instance",
        WgPeer => WgPeers, "peer",
        IdsSuppression => IdsSuppressions, "suppression",
        IdsUserRule => IdsUserRules, "rule",
        Gateway => Gateways, "gateway",
        GatewayGroup => GatewayGroups, "group",
        StaticRoute => StaticRoutes, "route",
        Bridge => Bridges, "bridge",
        Lagg => Laggs, "aggregate",
        LoopbackDevice => Loopbacks, "loopback",
        VirtualIp => VirtualIps, "virtual IP",
        InterfaceGroup => FirewallGroups, "group",
        User => Users, "user",
        UserGroup => UserGroups, "group",
        OidcProvider => OidcProviders, "provider",
        SamlProvider => SamlProviders, "provider"
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
            GridId::AccessLists,
            GridId::Forwarders,
            GridId::Blocklists,
            GridId::WgInstances,
            GridId::WgPeers,
            GridId::IdsSuppressions,
            GridId::IdsUserRules,
            GridId::Gateways,
            GridId::GatewayGroups,
            GridId::StaticRoutes,
            GridId::Bridges,
            GridId::Laggs,
            GridId::Loopbacks,
            GridId::VirtualIps,
            GridId::FirewallGroups,
            GridId::Users,
            GridId::UserGroups,
        ] {
            let meta = g.meta();
            assert!(!meta.columns.is_empty());
            // Run-time columns are filled by the server, not stored.
            for c in meta
                .columns
                .iter()
                .filter(|c| c.kind != crate::grid::ColumnKind::Status)
            {
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
    fn blocklist_needs_a_source_and_valid_entries() {
        let inputs: Inputs = [
            ("enabled", "true"),
            ("description", "Kids"),
            (
                "allow",
                "ok.example\n*._tcp.example\n/^ads[0-9]+\\./\nbad name",
            ),
            ("refresh_seconds", "72000"),
        ]
        .iter()
        .map(|(a, b)| ((*a).into(), (*b).into()))
        .collect();
        let errs = GridId::Blocklists
            .apply(&GridId::Blocklists.new_row(), &inputs)
            .unwrap_err();
        let paths: Vec<_> = errs.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["lists", "allow"], "{errs:?}");
        assert!(errs[1].message.contains("bad name"));
        let mut ftp = inputs.clone();
        ftp.insert("urls".into(), "ftp://x".into());
        let errs = GridId::Blocklists
            .apply(&GridId::Blocklists.new_row(), &ftp)
            .unwrap_err();
        let paths: Vec<_> = errs.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["urls", "allow"], "a URL counts as a source");
        let mut ok = inputs.clone();
        ok.insert(
            "allow".into(),
            "ok.example\n*._tcp.example\n/^ads[0-9]+\\./".into(),
        );
        ok.insert("urls".into(), "".into());
        ok.insert("lists".into(), "hagezi-pro\noisd-small".into());
        let v = GridId::Blocklists
            .apply(&GridId::Blocklists.new_row(), &ok)
            .unwrap();
        assert_eq!(v["lists"], json!(["hagezi-pro", "oisd-small"]));
        assert_eq!(known_list_label("oisd-small"), "OISD Ads Blocklist");
    }

    #[test]
    fn known_lists_are_listed_once() {
        let mut all: Vec<&str> = KNOWN_LISTS
            .iter()
            .flat_map(|(_, o)| o.iter().map(|(v, _)| *v))
            .collect();
        let n = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), n);
    }

    #[test]
    fn scope_is_sanitised() {
        assert_eq!(GridId::DhcpRanges.scope(&Some("lan.evil".into())), "lan");
        assert_eq!(GridId::FilterRules.scope(&Some("opt1".into())), "opt1");
    }
}
