//! The typed rule IR both renderers consume.
//!
//! A [`FilterRule`] here is one *expanded* rule: one interface, one address
//! family, one source and one destination term — the shape upstream's
//! `Rule::reader()` yields after its cartesian expansion. The nft compiler
//! folds runs of such rules back into sets and verdict maps
//! ([`crate::compile`]), so expansion costs nothing at packet time.

use std::fmt;
use std::net::IpAddr;

use indexmap::IndexMap;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::icmp::IcmpType;
use crate::proto::ProtoMatch;

/// IPv4 or IPv6.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpFamily {
    /// IPv4 (`inet`)
    V4,
    /// IPv6 (`inet6`)
    V6,
}

impl IpFamily {
    /// Both families, v4 first (upstream's `inet46` expansion order).
    pub const BOTH: [IpFamily; 2] = [IpFamily::V4, IpFamily::V6];

    /// Family of an address.
    pub fn of(addr: &IpAddr) -> IpFamily {
        match addr {
            IpAddr::V4(_) => IpFamily::V4,
            IpAddr::V6(_) => IpFamily::V6,
        }
    }

    /// pf keyword.
    pub fn pf(self) -> &'static str {
        match self {
            IpFamily::V4 => "inet",
            IpFamily::V6 => "inet6",
        }
    }
}

/// What happens to a matching packet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// pass (and keep state)
    #[default]
    Pass,
    /// silently drop
    Block,
    /// drop and tell the sender (TCP RST / ICMP unreachable)
    Reject,
}

/// pf direction relative to the interface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// entering the interface (the default)
    #[default]
    In,
    /// leaving the interface
    Out,
    /// both directions
    Any,
}

impl Direction {
    /// Applies to packets entering an interface.
    pub fn matches_in(self) -> bool {
        matches!(self, Direction::In | Direction::Any)
    }

    /// Applies to packets leaving an interface.
    pub fn matches_out(self) -> bool {
        matches!(self, Direction::Out | Direction::Any)
    }
}

/// One address term of a rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Addr {
    /// any address
    #[default]
    Any,
    /// any address of this firewall (`(self)`)
    SelfAddr,
    /// a literal host
    Host(IpAddr),
    /// a literal network
    Net(IpNet),
    /// a user alias (non-port)
    Alias(String),
    /// an automation table (`<sshlockout>`, `<bogons>`, …)
    Table(String),
    /// the networks of a logical interface (`lan`); in IPv6 filter rules
    /// upstream also matches link-local (`fe80::/10`) here
    IfaceNet {
        /// logical interface name
        iface: String,
        /// also match `fe80::/10`
        link_local: bool,
    },
    /// the addresses of a logical interface (`lanip`)
    IfaceAddr(String),
    /// a literal device reference written by automated rules (`(em0)`)
    Device(String),
    /// a named set of source MAC addresses (`ether saddr @name`; the name
    /// without `@`), written by host-mode rules; source-only and nft-only
    MacSet(String),
    /// an address that failed to parse; the rule is disabled
    Invalid(String),
}

/// A port or range (inclusive), or a port alias.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortMatch {
    /// one port
    Single(u16),
    /// inclusive range, `lo < hi`
    Range(u16, u16),
    /// a port alias
    Alias(String),
}

impl fmt::Display for PortMatch {
    /// pf spelling.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortMatch::Single(p) => write!(f, "{p}"),
            PortMatch::Range(a, b) => write!(f, "{a}:{b}"),
            PortMatch::Alias(a) => write!(f, "${a}"),
        }
    }
}

/// Source or destination of a rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    /// address term
    pub addr: Addr,
    /// `!` — match everything except `addr`
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub negate: bool,
    /// port, only with TCP/UDP
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<PortMatch>,
}

/// pf state tracking mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateKind {
    /// `keep state` (pf's implicit default)
    #[default]
    Keep,
    /// `keep state (sloppy)`
    Sloppy,
    /// `modulate state`
    Modulate,
    /// `synproxy state`
    Synproxy,
    /// `no state`
    None,
}

/// Explicit state options of a pass rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct State {
    /// tracking mode
    pub kind: StateKind,
    /// limits and timeouts, pf spelling (`max 100`, `tcp.established 60`)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub options: Vec<String>,
}

/// TCP flag test `flags <set>/<mask>`, as single-letter pf flags.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpFlags {
    /// `flags any`
    Any,
    /// flags in `set` must be on, out of those in `mask`
    Test {
        /// letters out of `FSRPAUEW`
        set: String,
        /// letters out of `FSRPAUEW`
        mask: String,
    },
}

/// Where a rule came from, by upstream's priority bands (`ruleOrigin()`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    /// system rules before user rules (< 200000)
    Internal,
    /// floating rules
    Floating,
    /// interface-group rules
    Group,
    /// per-interface user rules
    Interface,
    /// rules registered by automation (port forwards' filter rules, …)
    Automation,
    /// system rules after user rules
    Internal2,
}

impl Origin {
    /// Band of a priority; `has_seq` marks user rules with a sequence number.
    pub fn from_priority(prio: u32, has_seq: bool) -> Origin {
        match prio {
            0..200_000 => Origin::Internal,
            200_000..300_000 => Origin::Floating,
            300_000..400_000 => Origin::Group,
            400_000..500_000 if has_seq => Origin::Interface,
            400_000..500_000 => Origin::Automation,
            _ => Origin::Internal2,
        }
    }
}

/// One expanded filter rule.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterRule {
    /// upstream priority band (lower first, stable within a priority)
    pub priority: u32,
    /// stable identifier: OPNsense md5 label or the MVC rule UUID
    pub label: String,
    /// free-text description
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub descr: String,
    /// UI back-reference (`#ref`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// `false` renders the rule commented out (pf) or not at all (nft)
    pub enabled: bool,
    /// why normalisation disabled or changed the rule (pf `#debug:` line)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub debug: Vec<String>,
    /// verdict
    pub action: Action,
    /// direction
    pub direction: Direction,
    /// first match wins (`quick`); otherwise last match wins
    pub quick: bool,
    /// log matches
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub log: bool,
    /// logical interface; `None` = every interface (floating)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// invert `interface` (`on ! lan`)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub interface_not: bool,
    /// address family restriction
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<IpFamily>,
    /// layer-4 protocol
    pub proto: ProtoMatch,
    /// source
    pub src: Endpoint,
    /// destination
    pub dst: Endpoint,
    /// ICMP types (IPv4)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icmp_types: Vec<IcmpType>,
    /// ICMPv6 types
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icmp6_types: Vec<IcmpType>,
    /// TCP flags test
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_flags: Option<TcpFlags>,
    /// explicit state handling (pass rules only)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<State>,
    /// pf `allow-opts`
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_opts: bool,
    /// policy route via this gateway (`route-to`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// packet tag to set
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// packet tag to match
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tagged: Option<String>,
    /// `set prio` value(s), pf spelling
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_prio: Option<String>,
}

impl FilterRule {
    /// The rule's origin band.
    pub fn origin(&self) -> Origin {
        Origin::from_priority(self.priority, false)
    }
}

/// How a logical interface gets its IPv4 address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum V4Mode {
    /// unconfigured
    #[default]
    None,
    /// static address
    Static,
    /// DHCP client
    Dhcp,
}

/// How a logical interface gets its IPv6 address.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum V6Mode {
    /// unconfigured
    #[default]
    None,
    /// static address
    Static,
    /// DHCPv6 client
    Dhcp6,
    /// SLAAC
    Slaac,
    /// track another interface's delegated prefix
    Track6,
    /// 6rd tunnel to a border relay
    SixRd {
        /// border relay address
        gateway: IpAddr,
    },
    /// 6to4
    SixToFour,
}

/// An address configured on an interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IfAddr {
    /// interface address
    pub addr: IpAddr,
    /// prefix length of the connected network
    pub prefix_len: u8,
}

impl IfAddr {
    /// The connected network.
    pub fn network(&self) -> Option<IpNet> {
        IpNet::new(self.addr, self.prefix_len)
            .ok()
            .map(|n| n.trunc())
    }
}

/// A logical interface (`wan`, `lan`, `opt1`) as the rule engine sees it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    /// Linux device (`eth0`, `wg0`); upstream's `if`
    pub device: String,
    /// human description (`LAN`)
    pub descr: String,
    /// static or currently known addresses
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<IfAddr>,
    /// has an IPv4 upstream gateway (a "WAN" in NAT terms)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub gateway_v4: bool,
    /// has an IPv6 upstream gateway
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub gateway_v6: bool,
    /// virtual (VPN, loopback, …): no bogon/private blocks
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub r#virtual: bool,
    /// block bogon sources
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub block_bogons: bool,
    /// block RFC 1918 / ULA sources
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub block_private: bool,
    /// IPv4 addressing
    #[serde(default)]
    pub v4: V4Mode,
    /// IPv6 addressing
    #[serde(default)]
    pub v6: V6Mode,
    /// a DHCPv4 server serves this interface
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dhcp4_server: bool,
    /// a DHCPv6 server or relay serves this interface
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dhcp6_server: bool,
}

impl Interface {
    /// Addresses of one family.
    pub fn addrs_of(&self, fam: IpFamily) -> impl Iterator<Item = &IfAddr> {
        self.addrs
            .iter()
            .filter(move |a| IpFamily::of(&a.addr) == fam)
    }

    /// Any address of the family is configured.
    pub fn has_family(&self, fam: IpFamily) -> bool {
        self.addrs_of(fam).next().is_some()
    }
}

/// Logical interface name → interface, in configuration order (upstream
/// iterates interfaces in `config.xml` order, which the pf oracle keeps).
pub type InterfaceMap = IndexMap<String, Interface>;

/// Kind of an alias as far as rule normalisation cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AliasClass {
    /// holds addresses or networks
    Address,
    /// holds ports
    Port,
}
