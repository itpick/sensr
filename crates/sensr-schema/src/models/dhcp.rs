//! DHCPv4 server: subnets, pools, options and static reservations
//! (OPNsense `Kea/KeaDhcpv4.xml`; legacy ISC `dhcpd` and dnsmasq ranges are
//! translated into this by the importer).

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::array::{ArrayField, Relation, Uuid};
use crate::fields::{
    Description, DomainName, HexBytes, Hostname, InterfaceId, MacAddr, string_serde,
};
use crate::refs::{ItemKind, RefContext, Validate};
use crate::validation::{FieldError, FieldPath, Validations, ValidatorKind};

/// The DHCPv4 service.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dhcpv4 {
    /// Run the server.
    #[serde(default)]
    pub enabled: bool,
    /// Interfaces to serve.
    #[serde(default)]
    pub interfaces: Vec<InterfaceId>,
    /// Default lease time in seconds.
    #[serde(default = "lease")]
    pub valid_lifetime: u32,
    /// Add the filter rules DHCP needs automatically (OPNsense `fwrules`).
    #[serde(default = "yes")]
    pub firewall_rules: bool,
    /// Subnets with pools and options.
    #[serde(default)]
    pub subnets: ArrayField<Subnet4>,
    /// Static reservations.
    #[serde(default)]
    pub reservations: ArrayField<Reservation4>,
}

fn lease() -> u32 {
    4000
}

impl Default for Dhcpv4 {
    fn default() -> Self {
        Self {
            enabled: false,
            interfaces: Vec::new(),
            valid_lifetime: lease(),
            firewall_rules: true,
            subnets: ArrayField::new(),
            reservations: ArrayField::new(),
        }
    }
}

impl Dhcpv4 {
    /// The subnet that contains `addr`.
    pub fn subnet_for(&self, addr: Ipv4Addr) -> Option<(&Uuid, &Subnet4)> {
        self.subnets.iter().find(|(_, s)| s.subnet.contains(&addr))
    }
}

/// A served subnet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subnet4 {
    /// The subnet, e.g. `192.168.1.0/24`.
    pub subnet: Ipv4Net,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
    /// Interface the subnet is served on; `None` lets the server pick by
    /// address (Kea's default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<InterfaceId>,
    /// Dynamic address pools.
    #[serde(default)]
    pub pools: Vec<Pool4>,
    /// Lease time override in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_lifetime: Option<u32>,
    /// Fill unset `routers`/`dns_servers` from the interface address
    /// (OPNsense `option_data_autocollect`).
    #[serde(default = "yes")]
    pub auto_options: bool,
    /// Options handed out.
    #[serde(default)]
    pub options: Dhcp4Options,
    /// Boot server (`next-server`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_server: Option<Ipv4Addr>,
    /// Identify clients by client-id when they send one.
    #[serde(default = "yes")]
    pub match_client_id: bool,
}

impl Subnet4 {
    /// A subnet with no pools and default options.
    pub fn new(subnet: Ipv4Net) -> Self {
        Self {
            subnet,
            description: None,
            interface: None,
            pools: Vec::new(),
            valid_lifetime: None,
            auto_options: true,
            options: Dhcp4Options::default(),
            next_server: None,
            match_client_id: true,
        }
    }
}

/// Commonly used DHCPv4 options.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dhcp4Options {
    /// Option 3.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routers: Vec<Ipv4Addr>,
    /// Option 6.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_servers: Vec<Ipv4Addr>,
    /// Option 15.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<DomainName>,
    /// Option 119.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_search: Vec<DomainName>,
    /// Option 42.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ntp_servers: Vec<Ipv4Addr>,
    /// Option 66.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tftp_server_name: Option<String>,
    /// Option 67.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_file_name: Option<String>,
    /// Option 108 (IPv6-only preferred), seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6_only_preferred: Option<u32>,
}

/// A dynamic pool: `start-end` or a CIDR block inside the subnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Pool4 {
    start: Ipv4Addr,
    end: Ipv4Addr,
}

impl Pool4 {
    /// A pool from `start` to `end` inclusive.
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Result<Self, FieldError> {
        if start <= end {
            Ok(Self { start, end })
        } else {
            Err(FieldError::callback(
                "The start of the pool must not be after its end.",
            ))
        }
    }

    /// First address.
    pub fn start(&self) -> Ipv4Addr {
        self.start
    }

    /// Last address.
    pub fn end(&self) -> Ipv4Addr {
        self.end
    }

    /// True if `a` is in the pool.
    pub fn contains(&self, a: Ipv4Addr) -> bool {
        self.start <= a && a <= self.end
    }

    fn overlaps(&self, o: &Pool4) -> bool {
        self.start <= o.end && o.start <= self.end
    }
}

impl FromStr for Pool4 {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || {
            FieldError::syntax(
                "A pool must be written as start-end or as a network in CIDR notation.",
            )
        };
        let s = s.trim();
        if let Some((a, b)) = s.split_once('-') {
            Self::new(
                a.trim().parse().map_err(|_| err())?,
                b.trim().parse().map_err(|_| err())?,
            )
        } else {
            let net: Ipv4Net = s.parse().map_err(|_| err())?;
            Self::new(net.network(), net.broadcast())
        }
    }
}

impl fmt::Display for Pool4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}
string_serde!(Pool4);

/// How a reservation recognises its client: exactly one of MAC or client-id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientMatch {
    /// Hardware address.
    HwAddress(MacAddr),
    /// DHCP client identifier (option 61).
    ClientId(HexBytes),
}

/// A static reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation4 {
    /// The subnet the reservation belongs to.
    pub subnet: Relation<Subnet4>,
    /// Which client.
    pub client: ClientMatch,
    /// Fixed address; `None` reserves only the host name / options.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<Ipv4Addr>,
    /// Host name handed to the client and registered in DNS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<Hostname>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

impl Validate for Dhcpv4 {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        check::interfaces(ctx, &self.interfaces, &at.join("interfaces"), out);
        let subnets = at.join("subnets");
        check::unique(
            self.subnets
                .iter()
                .map(|(id, s)| (subnets.join(id), Some(s.subnet.trunc()))),
            "subnet",
            "Subnet must be unique.",
            out,
        );
        for (id, s) in &self.subnets {
            let p = subnets.join(id);
            if s.subnet != s.subnet.trunc() {
                out.add(
                    &p.join("subnet"),
                    ValidatorKind::Callback,
                    "The subnet must be a network address.",
                );
            }
            if let Some(i) = &s.interface {
                check::interface(ctx, i, &p.join("interface"), out);
                if !self.interfaces.contains(i) {
                    out.add(
                        &p.join("interface"),
                        ValidatorKind::Callback,
                        "Interface is not selected in the general settings.",
                    );
                }
            }
            for (n, pool) in s.pools.iter().enumerate() {
                if !s.subnet.contains(&pool.start) || !s.subnet.contains(&pool.end) {
                    out.add(
                        &p.join("pools"),
                        ValidatorKind::Callback,
                        format!("Pool {pool} is not within subnet {}.", s.subnet),
                    );
                }
                if s.pools[..n].iter().any(|q| q.overlaps(pool)) {
                    out.add(
                        &p.join("pools"),
                        ValidatorKind::Callback,
                        format!("Pool {pool} overlaps another pool."),
                    );
                }
            }
            if s.options.routers.iter().any(|a| !s.subnet.contains(a)) {
                out.add(
                    &p.join("options").join("routers"),
                    ValidatorKind::Callback,
                    "Router must be within the subnet.",
                );
            }
            for (field, text) in [
                ("tftp_server_name", &s.options.tftp_server_name),
                ("boot_file_name", &s.options.boot_file_name),
            ] {
                if text.as_deref().is_some_and(|t| t.contains(['\n', '"'])) {
                    out.add(
                        &p.join("options").join(field),
                        ValidatorKind::Regex,
                        "Newlines and quotes are not allowed.",
                    );
                }
            }
        }

        let res = at.join("reservations");
        let mut ips: HashMap<(Uuid, Ipv4Addr), ()> = HashMap::new();
        let mut clients: HashMap<(Uuid, &ClientMatch), ()> = HashMap::new();
        for (id, r) in &self.reservations {
            let p = res.join(id);
            let Some(subnet) = r.subnet.resolve(&self.subnets) else {
                if !ctx.has_item(ItemKind::Dhcp4Subnet, &r.subnet.id()) {
                    out.add(
                        &p.join("subnet"),
                        ValidatorKind::Callback,
                        "Related subnet not found.",
                    );
                }
                continue;
            };
            if clients.insert((r.subnet.id(), &r.client), ()).is_some() {
                out.add(
                    &p.join("client"),
                    ValidatorKind::Constraint,
                    "Duplicate entry exists.",
                );
            }
            if let Some(ip) = r.ip_address {
                if !subnet.subnet.contains(&ip)
                    || ip == subnet.subnet.network()
                    || ip == subnet.subnet.broadcast()
                {
                    out.add(
                        &p.join("ip_address"),
                        ValidatorKind::Callback,
                        "Address not in specified subnet.",
                    );
                }
                if ips.insert((r.subnet.id(), ip), ()).is_some() {
                    out.add(
                        &p.join("ip_address"),
                        ValidatorKind::Constraint,
                        "Duplicate entry exists.",
                    );
                }
            }
        }
    }
}
