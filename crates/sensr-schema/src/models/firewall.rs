//! Firewall aliases, filter rules and settings (OPNsense `Firewall/Alias.xml`,
//! `Firewall/Filter.xml`, legacy `filter/rule`).

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::array::ArrayField;
use crate::fields::{
    AddressRange, AliasName, CountryCode, Description, DomainName, GatewayName, HttpUrl,
    InterfaceId, IpFamily, MacAddr, NetOrAlias, PortSpec, Protocol, string_serde,
};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldError, FieldPath, Validations, ValidatorKind, messages};

/// Aliases, rules and global filter settings.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Firewall {
    /// Named address/port sets referenced by rules.
    #[serde(default)]
    pub aliases: ArrayField<Alias>,
    /// Filter rules; evaluated by `sequence`, then by position.
    #[serde(default)]
    pub rules: ArrayField<FilterRule>,
    /// Global behaviour.
    #[serde(default)]
    pub settings: FirewallSettings,
}

impl Firewall {
    /// The alias called `name`.
    pub fn alias(&self, name: &AliasName) -> Option<&Alias> {
        self.aliases.values().find(|a| &a.name == name)
    }

    /// Rules in evaluation order: by `sequence`, ties by position.
    pub fn rules_in_order(&self) -> Vec<(&crate::Uuid, &FilterRule)> {
        let mut v: Vec<_> = self.rules.iter().collect();
        v.sort_by_key(|(_, r)| r.sequence);
        v
    }
}

/// Global filter settings (OPNsense `Firewall/Filter.xml` `settings`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallSettings {
    /// Keep the anti-lockout rule that admits management access on LAN
    /// (inverse of OPNsense `no_antilockout`).
    #[serde(default = "yes")]
    pub anti_lockout: bool,
    /// Log packets dropped by the default deny (`logging.default_block`).
    #[serde(default = "yes")]
    pub log_default_block: bool,
    /// Log packets passed by default rules (`logging.default_pass`).
    #[serde(default = "yes")]
    pub log_default_pass: bool,
    /// Connection-tracking table size; `None` for the kernel default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_states: Option<u32>,
    /// Offload established flows to the nftables flowtable fast path.
    #[serde(default)]
    pub flow_offload: bool,
}

impl Default for FirewallSettings {
    fn default() -> Self {
        Self {
            anti_lockout: true,
            log_default_block: true,
            log_default_pass: true,
            maximum_states: None,
            flow_offload: false,
        }
    }
}

/// A named set of addresses, ports or other selectors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alias {
    /// Disabled aliases resolve to nothing.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Name rules use to refer to it.
    pub name: AliasName,
    /// What the alias holds.
    pub content: AliasContent,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
    /// Keep per-alias counters.
    #[serde(default)]
    pub counters: bool,
}

/// The type of an alias, without its content (what [`RefContext`] reports).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasType {
    /// Hosts, ranges and host names.
    Host,
    /// Networks.
    Network,
    /// Ports and port ranges.
    Port,
    /// Addresses listed at URLs, fetched once.
    Url,
    /// Addresses listed at a URL, refreshed periodically.
    UrlTable,
    /// Country address blocks.
    GeoIp,
    /// A union of other address aliases.
    NetworkGroup,
    /// MAC addresses.
    Mac,
    /// Contents managed outside the configuration (API / scripts).
    External,
}

impl AliasType {
    /// True if the alias can stand where an address or network is expected.
    pub fn holds_addresses(self) -> bool {
        !matches!(self, Self::Port | Self::Mac)
    }
}

/// Refresh period of a URL table (OPNsense `updatefreq`, in days with
/// fractions; here split into days and hours).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refresh {
    /// Whole days.
    #[serde(default)]
    pub days: u16,
    /// Additional hours.
    #[serde(default)]
    pub hours: u8,
}

/// Which address families a URL or GeoIP alias loads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Families {
    /// Load IPv4 entries.
    #[serde(default = "yes")]
    pub ipv4: bool,
    /// Load IPv6 entries.
    #[serde(default = "yes")]
    pub ipv6: bool,
}

impl Default for Families {
    fn default() -> Self {
        Self {
            ipv4: true,
            ipv6: true,
        }
    }
}

/// Alias content by type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AliasContent {
    /// Hosts: addresses, ranges, host names (resolved periodically) and
    /// nested aliases.
    Host {
        /// Entries.
        #[serde(default)]
        entries: Vec<AliasEntry>,
    },
    /// Networks: CIDR blocks, nested aliases, `!` exclusions.
    Network {
        /// Entries.
        #[serde(default)]
        entries: Vec<AliasEntry>,
    },
    /// Ports, ranges and nested port aliases.
    Port {
        /// Entries.
        #[serde(default)]
        entries: Vec<PortSpec>,
    },
    /// Address lists fetched from URLs when the rules load.
    Url {
        /// Sources.
        urls: Vec<HttpUrl>,
    },
    /// An address list fetched from a URL and refreshed (URL Table).
    /// Fetching and parsing are the alias resolver's (`sensr-rules`) job.
    UrlTable {
        /// Source.
        url: HttpUrl,
        /// Refresh period.
        #[serde(default)]
        refresh: Refresh,
        /// Families to load.
        #[serde(default)]
        families: Families,
    },
    /// Country address blocks.
    GeoIp {
        /// Countries.
        countries: Vec<CountryCode>,
        /// Families to load.
        #[serde(default)]
        families: Families,
    },
    /// A union of other address aliases.
    NetworkGroup {
        /// Member aliases.
        members: Vec<AliasName>,
    },
    /// MAC addresses (matched on the local segment only).
    Mac {
        /// Addresses.
        addresses: Vec<MacAddr>,
    },
    /// Contents are pushed at run time; the configuration holds none.
    External,
}

impl AliasContent {
    /// The content's type tag.
    pub fn alias_type(&self) -> AliasType {
        match self {
            Self::Host { .. } => AliasType::Host,
            Self::Network { .. } => AliasType::Network,
            Self::Port { .. } => AliasType::Port,
            Self::Url { .. } => AliasType::Url,
            Self::UrlTable { .. } => AliasType::UrlTable,
            Self::GeoIp { .. } => AliasType::GeoIp,
            Self::NetworkGroup { .. } => AliasType::NetworkGroup,
            Self::Mac { .. } => AliasType::Mac,
            Self::External => AliasType::External,
        }
    }

    /// Names of aliases this one includes.
    pub fn nested_aliases(&self) -> Vec<&AliasName> {
        match self {
            Self::Host { entries } | Self::Network { entries } => entries
                .iter()
                .filter_map(|e| match &e.value {
                    AliasValue::Alias(a) => Some(a),
                    _ => None,
                })
                .collect(),
            Self::Port { entries } => entries
                .iter()
                .filter_map(|p| match p {
                    PortSpec::Alias(a) => Some(a),
                    PortSpec::Range(_) => None,
                })
                .collect(),
            Self::NetworkGroup { members } => members.iter().collect(),
            _ => Vec::new(),
        }
    }
}

/// One entry of a host or network alias. Text form: optional `!`
/// (exclude), then an address, `a-b` range, CIDR, host name or
/// `alias:<name>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AliasEntry {
    /// Remove these addresses from the set instead of adding them.
    pub exclude: bool,
    /// The selector.
    pub value: AliasValue,
}

/// The selector of an [`AliasEntry`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AliasValue {
    /// A single address.
    Addr(IpAddr),
    /// A network.
    Net(IpNet),
    /// An inclusive range.
    Range(AddressRange),
    /// A DNS name, resolved by the alias resolver.
    Name(DomainName),
    /// Another alias.
    Alias(AliasName),
}

impl FromStr for AliasEntry {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (exclude, rest) = match s.strip_prefix('!') {
            Some(r) => (true, r),
            None => (false, s),
        };
        let value = if let Some(a) = rest.strip_prefix("alias:") {
            AliasValue::Alias(a.parse()?)
        } else if let Ok(ip) = rest.parse::<IpAddr>() {
            AliasValue::Addr(ip)
        } else if let Ok(net) = rest.parse::<IpNet>() {
            AliasValue::Net(net)
        } else if let Ok(r) = rest.parse::<AddressRange>() {
            AliasValue::Range(r)
        } else if !rest
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'.' || b == b'/')
        {
            AliasValue::Name(rest.parse().map_err(|_| invalid_entry(s))?)
        } else {
            return Err(invalid_entry(s));
        };
        Ok(Self { exclude, value })
    }
}

fn invalid_entry(s: &str) -> FieldError {
    FieldError::syntax(format!(
        "Entry \"{s}\" is not a valid hostname, IP address or range."
    ))
}

impl fmt::Display for AliasEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.exclude {
            f.write_str("!")?;
        }
        match &self.value {
            AliasValue::Addr(a) => a.fmt(f),
            AliasValue::Net(n) => n.fmt(f),
            AliasValue::Range(r) => r.fmt(f),
            AliasValue::Name(n) => n.fmt(f),
            AliasValue::Alias(a) => write!(f, "alias:{a}"),
        }
    }
}
string_serde!(AliasEntry);

/// What a matching rule does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Allow.
    #[default]
    Pass,
    /// Drop silently.
    Block,
    /// Drop and answer with TCP RST / ICMP unreachable.
    Reject,
}

/// Which way traffic crosses the interface.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Arriving on the interface.
    #[default]
    In,
    /// Leaving through the interface.
    Out,
    /// Either way.
    Any,
}

/// Connection tracking for a pass rule (OPNsense `statetype`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateType {
    /// Track connections.
    #[default]
    Keep,
    /// Track, without TCP window checks (asymmetric routing).
    Sloppy,
    /// Track and randomise TCP initial sequence numbers.
    Modulate,
    /// Track and proxy the TCP handshake.
    Synproxy,
    /// Stateless.
    None,
}

/// Source or destination of a rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// Address operand.
    #[serde(default)]
    pub net: NetOrAlias,
    /// Match everything except `net`.
    #[serde(default)]
    pub not: bool,
    /// Port operand (TCP/UDP only); `None` for any port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<PortSpec>,
}

impl Endpoint {
    /// Anything, any port.
    pub fn any() -> Self {
        Self::default()
    }

    /// `net`, any port.
    pub fn net(net: NetOrAlias) -> Self {
        Self {
            net,
            not: false,
            port: None,
        }
    }
}

/// A filter rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterRule {
    /// Disabled rules are kept but not loaded.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Evaluation order key (lower first); ties keep list order.
    #[serde(default = "one")]
    pub sequence: u32,
    /// What a match does.
    #[serde(default)]
    pub action: RuleAction,
    /// Stop at the first match (pf `quick`). Non-quick rules are
    /// last-match-wins, as in pf.
    #[serde(default = "yes")]
    pub quick: bool,
    /// Interfaces the rule applies to; empty means every interface
    /// (OPNsense "floating").
    #[serde(default)]
    pub interfaces: Vec<InterfaceId>,
    /// Apply to every interface except `interfaces`.
    #[serde(default)]
    pub interface_not: bool,
    /// Direction.
    #[serde(default)]
    pub direction: Direction,
    /// Address families.
    #[serde(default)]
    pub ip_protocol: IpFamily,
    /// Protocol.
    #[serde(default)]
    pub protocol: Protocol,
    /// Source.
    #[serde(default)]
    pub source: Endpoint,
    /// Destination.
    #[serde(default)]
    pub destination: Endpoint,
    /// Log matches.
    #[serde(default)]
    pub log: bool,
    /// Connection tracking.
    #[serde(default)]
    pub state_type: StateType,
    /// Free text; also shown in the live log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
    /// Policy routing: send matching traffic via this gateway or gateway group
    /// instead of the routing table (pass rules only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewayName>,
}

fn one() -> u32 {
    1
}

impl Default for FilterRule {
    fn default() -> Self {
        Self {
            enabled: true,
            sequence: 1,
            action: RuleAction::Pass,
            quick: true,
            interfaces: Vec::new(),
            interface_not: false,
            direction: Direction::In,
            ip_protocol: IpFamily::Inet,
            protocol: Protocol::Any,
            source: Endpoint::any(),
            destination: Endpoint::any(),
            log: false,
            state_type: StateType::Keep,
            description: None,
            gateway: None,
        }
    }
}

/// Checks the parts every rule-shaped object shares: endpoints resolve, ports
/// only with port-carrying protocols, literal addresses match the family.
pub(crate) fn validate_match(
    ctx: &dyn RefContext,
    family: IpFamily,
    protocol: Protocol,
    endpoints: [(&str, &Endpoint); 2],
    at: &FieldPath,
    out: &mut Validations,
) {
    for (name, ep) in endpoints {
        let p = at.join(name);
        check::net_or_alias(ctx, &ep.net, &p.join("net"), out);
        if let Some(lit) = ep.net.literal_family()
            && family != IpFamily::Inet46
            && lit != family
        {
            out.add(
                &p.join("net"),
                ValidatorKind::Callback,
                "The address family of the address does not match the rule's IP version.",
            );
        }
        if let Some(port) = &ep.port {
            if protocol.has_ports() {
                check::port_spec(ctx, port, &p.join("port"), out);
            } else {
                out.add(
                    &p.join("port"),
                    ValidatorKind::Callback,
                    "Ports can only be specified for TCP, UDP or SCTP.",
                );
            }
        }
    }
}

impl Validate for Firewall {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        let aliases = at.join("aliases");
        check::unique(
            self.aliases
                .iter()
                .map(|(id, a)| (aliases.join(id), Some(a.name.clone()))),
            "name",
            "An alias with this name already exists.",
            out,
        );
        for (id, alias) in &self.aliases {
            validate_alias(ctx, alias, &aliases.join(id).join("content"), out);
        }
        detect_alias_cycles(self, &aliases, out);

        let rules = at.join("rules");
        for (id, rule) in &self.rules {
            let p = rules.join(id);
            check::interfaces(ctx, &rule.interfaces, &p.join("interfaces"), out);
            validate_match(
                ctx,
                rule.ip_protocol,
                rule.protocol,
                [("source", &rule.source), ("destination", &rule.destination)],
                &p,
                out,
            );
            if let Some(gw) = &rule.gateway {
                if !ctx.has_gateway(gw) {
                    out.add(
                        &p.join("gateway"),
                        ValidatorKind::Callback,
                        format!("Gateway {gw} does not exist."),
                    );
                } else if rule.action != RuleAction::Pass {
                    out.add(
                        &p.join("gateway"),
                        ValidatorKind::Callback,
                        "A gateway can only be set on a pass rule.",
                    );
                }
            }
            if rule.interface_not && rule.interfaces.is_empty() {
                out.add(
                    &p.join("interface_not"),
                    ValidatorKind::Callback,
                    "Inverting the interface selection requires at least one interface.",
                );
            }
        }
    }
}

fn validate_alias(ctx: &dyn RefContext, alias: &Alias, at: &FieldPath, out: &mut Validations) {
    let expect = |ctx: &dyn RefContext,
                  name: &AliasName,
                  ok: fn(AliasType) -> bool,
                  out: &mut Validations| match ctx.alias_type(name) {
        None => out.add(
            at,
            ValidatorKind::Callback,
            format!("{}: {name}", messages::UNKNOWN_ALIAS.trim_end_matches('.')),
        ),
        Some(t) if !ok(t) => out.add(
            at,
            ValidatorKind::Callback,
            format!("Alias {name} cannot be nested here."),
        ),
        Some(_) => {}
    };
    match &alias.content {
        AliasContent::Host { entries } | AliasContent::Network { entries } => {
            let host = matches!(alias.content, AliasContent::Host { .. });
            for e in entries {
                match &e.value {
                    AliasValue::Alias(a) => expect(ctx, a, AliasType::holds_addresses, out),
                    AliasValue::Net(n) if host && n.prefix_len() != n.max_prefix_len() => out.add(
                        at,
                        ValidatorKind::Callback,
                        format!("Entry \"{e}\" is a network; use a network alias for networks."),
                    ),
                    _ => {}
                }
            }
        }
        AliasContent::Port { entries } => {
            for p in entries {
                if let PortSpec::Alias(a) = p {
                    expect(ctx, a, |t| t == AliasType::Port, out);
                }
            }
        }
        AliasContent::NetworkGroup { members } => {
            for m in members {
                expect(
                    ctx,
                    m,
                    |t| {
                        matches!(
                            t,
                            AliasType::Host | AliasType::Network | AliasType::NetworkGroup
                        )
                    },
                    out,
                );
            }
        }
        AliasContent::GeoIp { families, .. } | AliasContent::UrlTable { families, .. }
            if !families.ipv4 && !families.ipv6 =>
        {
            out.add(
                at,
                ValidatorKind::Callback,
                "Select at least one address family.",
            );
        }
        _ => {}
    }
}

/// Nested aliases must form a DAG; a cycle would make resolution loop.
/// Every alias on a cycle is reported.
fn detect_alias_cycles(fw: &Firewall, at: &FieldPath, out: &mut Validations) {
    let by_name: HashMap<&AliasName, &Alias> = fw.aliases.values().map(|a| (&a.name, a)).collect();
    for (id, alias) in &fw.aliases {
        if alias
            .content
            .nested_aliases()
            .into_iter()
            .any(|m| reaches(m, &alias.name, &by_name))
        {
            out.add(
                &at.join(id).join("content"),
                ValidatorKind::Constraint,
                "Alias contents may not refer back to the alias itself.",
            );
        }
    }
}

/// True if `from` (transitively) includes `target`.
fn reaches(from: &AliasName, target: &AliasName, by_name: &HashMap<&AliasName, &Alias>) -> bool {
    let mut stack = vec![from];
    let mut seen = std::collections::HashSet::new();
    while let Some(n) = stack.pop() {
        if n == target {
            return true;
        }
        if !seen.insert(n) {
            continue;
        }
        if let Some(a) = by_name.get(n) {
            stack.extend(a.content.nested_aliases());
        }
    }
    false
}
