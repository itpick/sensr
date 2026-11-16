//! DHCPv6 server and router advertisements (OPNsense `Kea/KeaDhcpv6.xml`,
//! `Radvd/Radvd.xml`).

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

use ipnet::Ipv6Net;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::array::{ArrayField, Relation, Uuid};
use crate::fields::{
    Description, DomainName, HexBytes, Hostname, InterfaceId, MacAddr, string_serde,
};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldError, FieldPath, Validations, ValidatorKind};

/// The DHCPv6 service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Dhcpv6 {
    /// Run the server.
    #[serde(default)]
    pub enabled: bool,
    /// Interfaces to serve.
    #[serde(default)]
    pub interfaces: Vec<InterfaceId>,
    /// Default lease time in seconds.
    #[serde(default = "lease")]
    pub valid_lifetime: u32,
    /// Subnets.
    #[serde(default)]
    pub subnets: ArrayField<Subnet6>,
    /// Static reservations.
    #[serde(default, skip_serializing_if = "ArrayField::is_empty")]
    pub reservations: ArrayField<Reservation6>,
    /// Prefix delegation pools.
    #[serde(default, skip_serializing_if = "ArrayField::is_empty")]
    pub pd_pools: ArrayField<PdPool>,
}

fn lease() -> u32 {
    4000
}

impl Default for Dhcpv6 {
    fn default() -> Self {
        Self {
            enabled: false,
            interfaces: Vec::new(),
            valid_lifetime: lease(),
            subnets: ArrayField::new(),
            reservations: ArrayField::new(),
            pd_pools: ArrayField::new(),
        }
    }
}

impl Dhcpv6 {
    /// True when nothing is configured (the section is then omitted).
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Where a DHCPv6 subnet's prefix comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Addressing6 {
    /// A fixed prefix with explicit pools.
    Static {
        /// The subnet.
        #[schemars(with = "String")]
        subnet: Ipv6Net,
        /// Dynamic address pools.
        #[serde(default)]
        pools: Vec<Pool6>,
    },
    /// The subnet follows the prefix delegated to the interface (`track`);
    /// pools are generated from it (OPNsense `dynamic_prefix`).
    DynamicPrefix,
}

/// A served IPv6 subnet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Subnet6 {
    /// Interface the subnet is served on.
    pub interface: InterfaceId,
    /// Prefix and pools.
    pub addressing: Addressing6,
    /// Fill unset DNS servers from the interface address.
    #[serde(default)]
    pub auto_options: bool,
    /// Options handed out.
    #[serde(default)]
    pub options: Dhcp6Options,
    /// Lease time override in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_lifetime: Option<u32>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

/// Commonly used DHCPv6 options.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Dhcp6Options {
    /// Option 23.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_servers: Vec<Ipv6Addr>,
    /// Option 24.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_search: Vec<DomainName>,
}

/// A dynamic IPv6 pool, `start-end` or a prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pool6 {
    start: Ipv6Addr,
    end: Ipv6Addr,
}

impl Pool6 {
    /// A pool from `start` to `end` inclusive.
    pub fn new(start: Ipv6Addr, end: Ipv6Addr) -> Result<Self, FieldError> {
        if start <= end {
            Ok(Self { start, end })
        } else {
            Err(FieldError::callback(
                "The start of the pool must not be after its end.",
            ))
        }
    }

    /// First address.
    pub fn start(&self) -> Ipv6Addr {
        self.start
    }

    /// Last address.
    pub fn end(&self) -> Ipv6Addr {
        self.end
    }
}

impl FromStr for Pool6 {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || FieldError::syntax("A pool must be written as start-end or as a prefix.");
        match s.trim().split_once('-') {
            Some((a, b)) => Self::new(
                a.trim().parse().map_err(|_| err())?,
                b.trim().parse().map_err(|_| err())?,
            ),
            None => {
                let n: Ipv6Net = s.trim().parse().map_err(|_| err())?;
                Self::new(n.network(), n.broadcast())
            }
        }
    }
}

impl fmt::Display for Pool6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}
string_serde!(Pool6);

/// How a DHCPv6 reservation recognises its client.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Client6Match {
    /// DHCP unique identifier.
    Duid(HexBytes),
    /// Hardware address.
    HwAddress(MacAddr),
}

/// A static DHCPv6 reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Reservation6 {
    /// The subnet the reservation belongs to (a static one).
    pub subnet: Relation<Subnet6>,
    /// Which client.
    pub client: Client6Match,
    /// Fixed address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<Ipv6Addr>,
    /// Fixed delegated prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub prefix: Option<Ipv6Net>,
    /// Host name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<Hostname>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

/// A prefix delegation pool: `prefix` carved into `/delegated_len` pieces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PdPool {
    /// The subnet the pool belongs to.
    pub subnet: Relation<Subnet6>,
    /// The pool's prefix.
    #[schemars(with = "String")]
    pub prefix: Ipv6Net,
    /// Size of each delegation.
    pub delegated_len: u8,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

impl Validate for Dhcpv6 {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        check::interfaces(ctx, &self.interfaces, &at.join("interfaces"), out);
        let subnets = at.join("subnets");
        let mut dynamic_on: HashMap<&InterfaceId, Uuid> = HashMap::new();
        let mut statics: HashSet<Ipv6Net> = HashSet::new();
        for (id, s) in &self.subnets {
            let p = subnets.join(id);
            check::interface(ctx, &s.interface, &p.join("interface"), out);
            if !self.interfaces.contains(&s.interface) {
                out.add(
                    &p.join("interface"),
                    ValidatorKind::Callback,
                    "Interface is not selected in the general settings.",
                );
            }
            match &s.addressing {
                Addressing6::Static { subnet, pools } => {
                    let sp = p.join("addressing");
                    if *subnet != subnet.trunc() {
                        out.add(
                            &sp.join("subnet"),
                            ValidatorKind::Callback,
                            "The subnet must be a network address.",
                        );
                    }
                    if !statics.insert(subnet.trunc()) {
                        out.add(
                            &sp.join("subnet"),
                            ValidatorKind::Constraint,
                            "Subnet must be unique.",
                        );
                    }
                    for pool in pools {
                        if !subnet.contains(&pool.start) || !subnet.contains(&pool.end) {
                            out.add(
                                &sp.join("pools"),
                                ValidatorKind::Callback,
                                format!("Pool \"{pool}\" not in specified subnet."),
                            );
                        }
                    }
                }
                Addressing6::DynamicPrefix => {
                    if dynamic_on.insert(&s.interface, *id).is_some() {
                        out.add(
                            &p.join("interface"),
                            ValidatorKind::Constraint,
                            "Only one dynamic prefix subnet may be configured per interface.",
                        );
                    }
                }
            }
            if s.auto_options && !s.options.dns_servers.is_empty() {
                out.add(
                    &p.join("options").join("dns_servers"),
                    ValidatorKind::Callback,
                    "DNS servers must be empty when option data autocollect is enabled.",
                );
            }
        }
        let res = at.join("reservations");
        let mut clients: HashSet<(Uuid, &Client6Match)> = HashSet::new();
        for (id, r) in &self.reservations {
            let p = res.join(id);
            let Some(subnet) = r.subnet.resolve(&self.subnets) else {
                out.add(
                    &p.join("subnet"),
                    ValidatorKind::Callback,
                    "Related subnet not found.",
                );
                continue;
            };
            let Addressing6::Static { subnet: net, .. } = &subnet.addressing else {
                out.add(
                    &p.join("subnet"),
                    ValidatorKind::Callback,
                    "Reservations cannot be assigned to dynamic prefix subnets.",
                );
                continue;
            };
            if r.ip_address.is_none() && r.prefix.is_none() {
                out.add(
                    &p.join("ip_address"),
                    ValidatorKind::PresenceOf,
                    "Either an IP address or a Prefix should be specified.",
                );
            }
            if r.ip_address.is_some_and(|a| !net.contains(&a)) {
                out.add(
                    &p.join("ip_address"),
                    ValidatorKind::Callback,
                    "Address not in specified subnet.",
                );
            }
            if r.prefix.is_some_and(|pfx| !net.contains(&pfx)) {
                out.add(
                    &p.join("prefix"),
                    ValidatorKind::Callback,
                    "Prefix not in specified subnet.",
                );
            }
            if !clients.insert((r.subnet.id(), &r.client)) {
                out.add(
                    &p.join("client"),
                    ValidatorKind::Constraint,
                    "Duplicate entry exists.",
                );
            }
        }
        let pd = at.join("pd_pools");
        for (id, pool) in &self.pd_pools {
            let p = pd.join(id);
            if !self.subnets.contains(&pool.subnet.id()) {
                out.add(
                    &p.join("subnet"),
                    ValidatorKind::Callback,
                    "Related subnet not found.",
                );
            }
            if pool.delegated_len < pool.prefix.prefix_len() || pool.delegated_len > 128 {
                out.add(
                    &p.join("delegated_len"),
                    ValidatorKind::MinMax,
                    format!(
                        "Please specify a value between {} and 128.",
                        pool.prefix.prefix_len()
                    ),
                );
            }
        }
    }
}

/// What router advertisements tell hosts to do (OPNsense radvd modes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RaMode {
    /// Default router only, no prefix information.
    RouterOnly,
    /// SLAAC only.
    Unmanaged,
    /// Addresses from DHCPv6 (M flag).
    Managed,
    /// SLAAC and DHCPv6 addresses.
    Assisted,
    /// SLAAC plus DHCPv6 for other configuration (O flag).
    #[default]
    Stateless,
}

/// Default router preference (RFC 4191).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RouterPreference {
    /// Low.
    Low,
    /// Medium.
    #[default]
    Medium,
    /// High.
    High,
}

/// Router advertisement settings of one interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RaInterface {
    /// Advertise on this interface.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The interface.
    pub interface: InterfaceId,
    /// Take the advertised prefix from this interface instead
    /// (OPNsense `Base6Interface`, "constructor").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_from: Option<InterfaceId>,
    /// What hosts should do.
    #[serde(default)]
    pub mode: RaMode,
    /// Advertise the resolver (RDNSS/DNSSL) when no explicit servers are set.
    #[serde(default = "yes")]
    pub dns: bool,
    /// Explicit RDNSS servers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rdnss: Vec<Ipv6Addr>,
    /// Explicit DNS search list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dnssl: Vec<DomainName>,
    /// More-specific routes to advertise (RFC 4191).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(with = "Vec<String>")]
    pub routes: Vec<Ipv6Net>,
    /// Minimum interval in seconds (3 up to 0.75 × max).
    #[serde(default = "min_interval")]
    pub min_interval: u32,
    /// Maximum interval in seconds (4-1800).
    #[serde(default = "max_interval")]
    pub max_interval: u32,
    /// Router lifetime in seconds (max_interval-9000); `None` for 3 × max.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_lifetime: Option<u32>,
    /// Default router preference.
    #[serde(default)]
    pub preference: RouterPreference,
    /// Advertised link MTU (1280-65535).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// Advertised hop limit.
    #[serde(default = "hop_limit")]
    pub hop_limit: u8,
    /// NAT64 prefix to advertise (RFC 8781; /32, /40, /48, /56, /64 or /96).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub nat64_prefix: Option<Ipv6Net>,
}

fn min_interval() -> u32 {
    200
}

fn max_interval() -> u32 {
    600
}

fn hop_limit() -> u8 {
    64
}

impl RaInterface {
    /// Defaults for `interface`.
    pub fn new(interface: InterfaceId) -> Self {
        Self {
            enabled: true,
            interface,
            prefix_from: None,
            mode: RaMode::default(),
            dns: true,
            rdnss: Vec::new(),
            dnssl: Vec::new(),
            routes: Vec::new(),
            min_interval: min_interval(),
            max_interval: max_interval(),
            default_lifetime: None,
            preference: RouterPreference::default(),
            mtu: None,
            hop_limit: hop_limit(),
            nat64_prefix: None,
        }
    }
}

/// Router advertisements.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RouterAdvertisements {
    /// Per-interface settings.
    #[serde(default)]
    pub interfaces: ArrayField<RaInterface>,
}

impl RouterAdvertisements {
    /// True when none are configured.
    pub fn is_empty(&self) -> bool {
        self.interfaces.is_empty()
    }
}

impl Validate for RouterAdvertisements {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        let at = at.join("interfaces");
        let mut seen: HashSet<&InterfaceId> = HashSet::new();
        for (id, ra) in &self.interfaces {
            let p = at.join(id);
            check::interface(ctx, &ra.interface, &p.join("interface"), out);
            if !seen.insert(&ra.interface) {
                out.add(
                    &p.join("interface"),
                    ValidatorKind::Constraint,
                    "Router advertisements are already configured for this interface.",
                );
            }
            if let Some(from) = &ra.prefix_from {
                if from == &ra.interface {
                    out.add(
                        &p.join("prefix_from"),
                        ValidatorKind::Callback,
                        "Constructor cannot be the same as interface.",
                    );
                }
                check::interface(ctx, from, &p.join("prefix_from"), out);
            }
            if let Some(pfx) = ra.nat64_prefix
                && ![32, 40, 48, 56, 64, 96].contains(&pfx.prefix_len())
            {
                out.add(
                    &p.join("nat64_prefix"),
                    ValidatorKind::Callback,
                    "Prefix size must be one of 32, 40, 48, 56, 64 or 96.",
                );
            }
            if let Some(mtu) = ra.mtu {
                check::range(mtu, 1280..=65535, &p.join("mtu"), out);
            }
            if !(4..=1800).contains(&ra.max_interval) {
                out.add(
                    &p.join("max_interval"),
                    ValidatorKind::MinMax,
                    "Maximum interval must be between 4 and 1800 seconds.",
                );
                continue;
            }
            let min_allowed = ra.max_interval * 3 / 4;
            if ra.min_interval < 3 {
                out.add(
                    &p.join("min_interval"),
                    ValidatorKind::MinMax,
                    "Please specify a value between 3 and 1350.",
                );
            } else if ra.min_interval > min_allowed {
                out.add(
                    &p.join("min_interval"),
                    ValidatorKind::MinMax,
                    format!("Value cannot be greater than {min_allowed}."),
                );
            }
            if let Some(lt) = ra.default_lifetime
                && (lt < ra.max_interval || lt > 9000)
            {
                out.add(
                    &p.join("default_lifetime"),
                    ValidatorKind::MinMax,
                    format!(
                        "Value must be between {} and 9000 seconds.",
                        ra.max_interval
                    ),
                );
            }
        }
    }
}
