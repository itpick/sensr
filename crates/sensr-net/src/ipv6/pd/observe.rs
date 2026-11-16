//! Reading the delegated prefix out of the kernel, so the agent can poll
//! what systemd-networkd obtained without talking DBus.
//!
//! Assumption (systemd-networkd 256+, `networkd-dhcp-prefix-delegation.c`;
//! to be confirmed on the router):
//! for every delegated prefix shorter than /64 networkd installs an
//! `unreachable` route for the whole prefix with `protocol dhcp` (RFC 7084
//! WPD-5: do not forward unassigned parts of the delegation back upstream)
//! and gives it the prefix's valid lifetime, which the kernel reports as
//! `expires`. A /64 delegation gets no such route; for that case the prefix
//! is taken from the addresses networkd assigned to the downstream links,
//! whose kernel lifetimes are the delegation's preferred/valid lifetimes.
//! See `crates/sensr-net/docs/pd.md`.
//!
//! Input is the raw JSON of `ip -j -6 route show table all` and
//! `ip -j -6 addr show`.

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;
use serde::Deserialize;

use super::{INFINITE_LIFETIME, Observation};

/// Errors reading `ip -j` output.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// Not the JSON shape `ip -j` prints.
    #[error("ip -j output: {0}")]
    Json(#[from] serde_json::Error),
    /// Several delegated prefixes and none of the downstream links tells
    /// which one belongs to this uplink.
    #[error("several delegated prefixes and no downstream address to pick one: {0:?}")]
    Ambiguous(Vec<Ipv6Net>),
}

/// A delegated-prefix route found in the routing tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdRoute {
    /// The delegated prefix.
    pub prefix: Ipv6Net,
    /// Remaining valid lifetime ([`INFINITE_LIFETIME`] without `expires`).
    pub valid_lifetime: u32,
    /// Routing table, when `ip` printed one.
    pub table: Option<String>,
}

/// A global IPv6 address and its kernel lifetimes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrLifetime {
    /// Kernel interface name.
    pub ifname: String,
    /// The address.
    pub address: Ipv6Addr,
    /// The on-link prefix (address/prefixlen, host bits cleared).
    pub prefix: Ipv6Net,
    /// Remaining preferred lifetime ([`INFINITE_LIFETIME`] = forever).
    pub preferred_lifetime: u32,
    /// Remaining valid lifetime ([`INFINITE_LIFETIME`] = forever).
    pub valid_lifetime: u32,
    /// Set for addresses with a finite lifetime (DHCP/PD/SLAAC), unset for
    /// static ones.
    pub dynamic: bool,
}

/// A downstream address whose valid lifetime disagrees with the delegated
/// prefix route by more than [`MISMATCH_TOLERANCE_SECS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifetimeMismatch {
    /// The address that disagrees.
    pub addr: AddrLifetime,
    /// The route's valid lifetime.
    pub route_valid_lifetime: u32,
}

/// Route and address lifetimes are read at slightly different moments and
/// networkd refreshes them in separate netlink calls.
pub const MISMATCH_TOLERANCE_SECS: u32 = 60;

/// What the kernel says the uplink holds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KernelObservation {
    /// The observation to feed to [`super::PdState::observe`].
    pub observation: Option<Observation>,
    /// Cross-check findings; worth logging, not fatal.
    pub mismatches: Vec<LifetimeMismatch>,
}

#[derive(Deserialize)]
struct RawRoute {
    #[serde(rename = "type")]
    kind: Option<String>,
    dst: Option<String>,
    protocol: Option<String>,
    table: Option<String>,
    expires: Option<Expires>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Expires {
    Secs(i64),
    Text(String),
}

impl Expires {
    fn secs(&self) -> Option<u32> {
        let n = match self {
            Self::Secs(n) => *n,
            Self::Text(s) => s.trim().trim_end_matches("sec").trim().parse().ok()?,
        };
        Some(u32::try_from(n.max(0)).unwrap_or(u32::MAX - 1))
    }
}

#[derive(Deserialize)]
struct RawLink {
    ifname: Option<String>,
    #[serde(default)]
    addr_info: Vec<RawAddr>,
}

#[derive(Deserialize)]
struct RawAddr {
    family: Option<String>,
    local: Option<String>,
    prefixlen: Option<u8>,
    scope: Option<String>,
    #[serde(default)]
    dynamic: bool,
    valid_life_time: Option<u64>,
    preferred_life_time: Option<u64>,
}

fn lifetime(v: Option<u64>) -> u32 {
    v.map_or(INFINITE_LIFETIME, |n| {
        u32::try_from(n).unwrap_or(INFINITE_LIFETIME)
    })
}

/// The delegated-prefix routes in `ip -j -6 route show table all` output:
/// `unreachable`, `protocol dhcp`, destination shorter than /64.
pub fn parse_pd_routes(json: &[u8]) -> Result<Vec<PdRoute>, ParseError> {
    let raw: Vec<RawRoute> = serde_json::from_slice(json)?;
    Ok(raw
        .into_iter()
        .filter(|r| r.kind.as_deref() == Some("unreachable"))
        .filter(|r| r.protocol.as_deref() == Some("dhcp"))
        .filter_map(|r| {
            let prefix: Ipv6Net = r.dst.as_deref()?.parse().ok()?;
            if prefix.prefix_len() >= 64 || prefix.addr().is_unicast_link_local() {
                return None;
            }
            Some(PdRoute {
                prefix: prefix.trunc(),
                valid_lifetime: r
                    .expires
                    .as_ref()
                    .and_then(Expires::secs)
                    .unwrap_or(INFINITE_LIFETIME),
                table: r.table,
            })
        })
        .collect())
}

/// Global IPv6 addresses with their lifetimes from `ip -j -6 addr show`.
pub fn parse_addr_lifetimes(json: &[u8]) -> Result<Vec<AddrLifetime>, ParseError> {
    let raw: Vec<RawLink> = serde_json::from_slice(json)?;
    let mut out = Vec::new();
    for link in raw {
        let Some(ifname) = link.ifname else { continue };
        for a in link.addr_info {
            if a.family.as_deref() != Some("inet6") || a.scope.as_deref() != Some("global") {
                continue;
            }
            let (Some(local), Some(len)) = (a.local.as_deref(), a.prefixlen) else {
                continue;
            };
            let Ok(address) = local.parse::<Ipv6Addr>() else {
                continue;
            };
            let Ok(prefix) = Ipv6Net::new(address, len) else {
                continue;
            };
            out.push(AddrLifetime {
                ifname: ifname.clone(),
                address,
                prefix: prefix.trunc(),
                preferred_lifetime: lifetime(a.preferred_life_time),
                valid_lifetime: lifetime(a.valid_life_time),
                dynamic: a.dynamic,
            });
        }
    }
    Ok(out)
}

/// Combine both outputs into one observation for the uplink whose
/// downstream links are `downstream` (kernel interface names of the LANs
/// tracking it).
///
/// - One PD route: that is the prefix. Several: the one containing a
///   downstream address; none contains one: [`ParseError::Ambiguous`].
/// - No PD route (a /64 delegation): the single /64 of the dynamic global
///   addresses on the downstream links, with their lifetimes.
/// - Valid lifetime comes from the route; preferred from the downstream
///   addresses inside the prefix (capped at valid), or equals valid when
///   no downstream address exists yet.
pub fn observation_from_kernel(
    routes_json: &[u8],
    addrs_json: &[u8],
    downstream: &[&str],
) -> Result<KernelObservation, ParseError> {
    let routes = parse_pd_routes(routes_json)?;
    let lan: Vec<AddrLifetime> = parse_addr_lifetimes(addrs_json)?
        .into_iter()
        .filter(|a| a.dynamic && downstream.contains(&a.ifname.as_str()))
        .collect();

    let route = match routes.as_slice() {
        [] => None,
        [only] => Some(only.clone()),
        many => Some(
            many.iter()
                .find(|r| lan.iter().any(|a| r.prefix.contains(&a.address)))
                .cloned()
                .ok_or_else(|| ParseError::Ambiguous(many.iter().map(|r| r.prefix).collect()))?,
        ),
    };

    let Some(route) = route else {
        return Ok(KernelObservation {
            observation: from_addresses_only(&lan),
            mismatches: Vec::new(),
        });
    };

    let inside: Vec<&AddrLifetime> = lan
        .iter()
        .filter(|a| route.prefix.contains(&a.address))
        .collect();
    let preferred = inside
        .iter()
        .map(|a| a.preferred_lifetime)
        .max()
        .unwrap_or(route.valid_lifetime)
        .min(route.valid_lifetime);
    let mismatches = inside
        .iter()
        .filter(|a| {
            a.valid_lifetime.abs_diff(route.valid_lifetime) > MISMATCH_TOLERANCE_SECS
                && !(a.valid_lifetime == INFINITE_LIFETIME
                    && route.valid_lifetime == INFINITE_LIFETIME)
        })
        .map(|a| LifetimeMismatch {
            addr: (*a).clone(),
            route_valid_lifetime: route.valid_lifetime,
        })
        .collect();
    Ok(KernelObservation {
        observation: Some(Observation {
            prefix: route.prefix,
            preferred_lifetime: preferred,
            valid_lifetime: route.valid_lifetime,
            iaid: None,
        }),
        mismatches,
    })
}

fn from_addresses_only(lan: &[AddrLifetime]) -> Option<Observation> {
    let mut nets: Vec<Ipv6Net> = lan
        .iter()
        .filter(|a| a.prefix.prefix_len() == 64)
        .map(|a| a.prefix)
        .collect();
    nets.sort();
    nets.dedup();
    let [prefix] = nets.as_slice() else {
        return None;
    };
    let mine = lan.iter().filter(|a| a.prefix == *prefix);
    let valid = mine.clone().map(|a| a.valid_lifetime).max()?;
    let preferred = mine.map(|a| a.preferred_lifetime).max()?.min(valid);
    Some(Observation {
        prefix: *prefix,
        preferred_lifetime: preferred,
        valid_lifetime: valid,
        iaid: None,
    })
}
