//! Aliases: kinds, hermetic resolvers and nested resolution
//! (`scripts/filter/lib/alias`, `update_tables.py`).
//!
//! Resolution turns every alias into the contents of its nft sets
//! ([`ResolvedAlias`]). Nested aliases are unions of their members; negated
//! entries follow pf table semantics (longest prefix wins, see [`ipset`]).
//! Everything outside the configuration — HTTP, DNS, GeoIP and ASN data,
//! the neighbour table, interface addresses — comes through [`Sources`], so
//! tests are hermetic and the agent decides how and when to fetch.

pub mod asn;
pub mod dns;
pub mod dynipv6;
pub mod geoip;
pub mod ipset;
pub mod mac;
pub mod parse;
pub mod sources;

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use ipnet::IpNet;

use crate::ir::{AliasClass, IpFamily};
use crate::normalize::AliasInfo;
use crate::render::nft::ResolvedAlias;
use ipset::{AddrSet, TableEntry};
pub use sources::{Auth, FetchError, Sources};

/// Which families an alias loads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Families {
    /// IPv4
    pub v4: bool,
    /// IPv6
    pub v6: bool,
}

impl Default for Families {
    fn default() -> Self {
        Families { v4: true, v6: true }
    }
}

impl Families {
    fn admits(self, n: &IpNet) -> bool {
        match n {
            IpNet::V4(_) => self.v4,
            IpNet::V6(_) => self.v6,
        }
    }
}

/// One entry of a host or network alias.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostEntry {
    /// an address or network, possibly excluded
    Net(TableEntry),
    /// an inclusive address range
    Range {
        /// first address
        lo: IpAddr,
        /// last address
        hi: IpAddr,
        /// exclude instead of include
        exclude: bool,
    },
    /// a DNS name
    Name(String),
    /// another alias (excluded: its contents are removed)
    Alias {
        /// alias name
        name: String,
        /// exclude instead of include
        exclude: bool,
    },
    /// an untyped token (legacy config, URL list line), parsed by
    /// [`parse::parse_entry`]; an alias name if one exists
    Raw(String),
}

/// One entry of a port alias.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortEntry {
    /// inclusive range (`lo == hi` for one port)
    Range(u16, u16),
    /// another port alias
    Alias(String),
}

/// What an alias holds and how it is resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AliasKind {
    /// hosts, ranges, names, nested aliases
    Host(Vec<HostEntry>),
    /// networks, nested aliases
    Network(Vec<HostEntry>),
    /// union of address aliases
    NetworkGroup(Vec<String>),
    /// ports, nested port aliases
    Port(Vec<PortEntry>),
    /// lists fetched from URLs at load time
    Url {
        /// sources
        urls: Vec<String>,
        /// authentication
        auth: Auth,
        /// families kept
        families: Families,
    },
    /// a list fetched from a URL and refreshed every `refresh_secs`
    UrlTable {
        /// source
        url: String,
        /// authentication
        auth: Auth,
        /// refresh period
        refresh_secs: u64,
        /// families kept
        families: Families,
    },
    /// country blocks
    GeoIp {
        /// ISO 3166 alpha-2 codes (or `EU`)
        countries: Vec<String>,
        /// families kept
        families: Families,
    },
    /// networks announced by autonomous systems
    Asn {
        /// AS numbers
        asns: Vec<u32>,
        /// families kept
        families: Families,
    },
    /// addresses currently seen for MAC addresses or prefixes
    Mac(Vec<String>),
    /// interface prefix + fixed IPv6 host suffixes
    DynIpv6Host {
        /// logical interface
        interface: String,
        /// suffixes like `::1005`
        suffixes: Vec<String>,
    },
    /// contents managed at run time (API, scripts)
    External,
}

impl AliasKind {
    /// Address or port alias.
    pub fn class(&self) -> AliasClass {
        match self {
            AliasKind::Port(_) => AliasClass::Port,
            _ => AliasClass::Address,
        }
    }

    /// Whether sensr generates the contents (`Alias.is_managed`): external
    /// aliases are only filled from outside, port aliases are not tables.
    pub fn is_managed(&self) -> bool {
        !matches!(self, AliasKind::External | AliasKind::Port(_))
    }
}

/// An alias definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AliasDef {
    /// name rules refer to
    pub name: String,
    /// disabled aliases resolve to nothing
    pub enabled: bool,
    /// contents
    pub kind: AliasKind,
}

/// Why (part of) an alias could not be resolved. The agent keeps the
/// previous contents of a failed alias, as upstream does.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AliasError {
    /// nested aliases form a cycle
    #[error("alias {0} is part of a nesting cycle")]
    Cycle(String),
    /// a source could not be fetched
    #[error(transparent)]
    Fetch(#[from] FetchError),
    /// a host name did not resolve
    #[error("alias {alias}: {error}")]
    Dns {
        /// alias
        alias: String,
        /// lookup error
        error: dns::DnsError,
    },
}

/// Resolution result for all aliases.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resolution {
    /// set contents per alias
    pub aliases: BTreeMap<String, ResolvedAlias>,
    /// problems; DNS errors are informational, the others mean `failed`
    pub errors: Vec<AliasError>,
    /// aliases whose contents are incomplete (keep the previous ones)
    pub failed: BTreeSet<String>,
}

/// Alias names and classes for rule normalisation.
pub fn index(defs: &[AliasDef]) -> BTreeMap<String, AliasInfo> {
    defs.iter()
        .map(|d| {
            let empty = match &d.kind {
                AliasKind::Port(v) => v.is_empty(),
                AliasKind::Host(v) | AliasKind::Network(v) => v.is_empty(),
                _ => false,
            };
            (
                d.name.clone(),
                AliasInfo {
                    class: d.kind.class(),
                    empty,
                },
            )
        })
        .collect()
}

#[derive(Clone, Debug, Default)]
struct Content {
    entries: Vec<TableEntry>,
    ports: Vec<(u16, u16)>,
    failed: bool,
}

struct Resolver<'a> {
    by_name: BTreeMap<&'a str, &'a AliasDef>,
    src: &'a dyn Sources,
    done: BTreeMap<String, Content>,
    errors: Vec<AliasError>,
}

impl<'a> Resolver<'a> {
    fn deps(&self, d: &AliasDef) -> Vec<String> {
        let known = |n: &str| self.by_name.contains_key(n);
        match &d.kind {
            AliasKind::Host(v) | AliasKind::Network(v) => v
                .iter()
                .filter_map(|e| match e {
                    HostEntry::Alias { name, .. } => Some(name.clone()),
                    HostEntry::Raw(t) if known(t.trim_start_matches('!')) => {
                        Some(t.trim_start_matches('!').to_owned())
                    }
                    _ => None,
                })
                .collect(),
            AliasKind::NetworkGroup(m) => m.clone(),
            AliasKind::Port(v) => v
                .iter()
                .filter_map(|p| match p {
                    PortEntry::Alias(a) => Some(a.clone()),
                    PortEntry::Range(..) => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Names on nesting cycles.
    fn cycles(&self) -> BTreeSet<String> {
        let mut on_cycle = BTreeSet::new();
        for &start in self.by_name.keys() {
            // depth-first from each alias: does it reach itself?
            let mut stack = vec![start.to_owned()];
            let mut seen = BTreeSet::new();
            while let Some(n) = stack.pop() {
                let Some(d) = self.by_name.get(n.as_str()) else {
                    continue;
                };
                for dep in self.deps(d) {
                    if dep == start {
                        on_cycle.insert(start.to_owned());
                    } else if seen.insert(dep.clone()) {
                        stack.push(dep);
                    }
                }
            }
        }
        on_cycle
    }

    fn resolve(&mut self, name: &str) -> Content {
        if let Some(c) = self.done.get(name) {
            return c.clone();
        }
        let Some(&d) = self.by_name.get(name) else {
            return Content::default();
        };
        let c = if d.enabled {
            self.own(d)
        } else {
            Content::default()
        };
        self.done.insert(name.to_owned(), c.clone());
        c
    }

    fn nested(&mut self, name: &str, exclude: bool, out: &mut Content) {
        let c = self.resolve(name);
        out.failed |= c.failed;
        out.ports.extend(c.ports);
        out.entries.extend(c.entries.into_iter().map(|mut e| {
            e.negate ^= exclude;
            e
        }));
    }

    fn host_entries(&mut self, alias: &str, v: &[HostEntry], out: &mut Content) {
        let mut names = Vec::new();
        for e in v {
            match e {
                HostEntry::Net(t) => out.entries.push(*t),
                HostEntry::Range { lo, hi, exclude } => {
                    out.entries
                        .extend(
                            ipset::summarize(*lo, *hi)
                                .into_iter()
                                .map(|net| TableEntry {
                                    net,
                                    negate: *exclude,
                                }),
                        );
                }
                HostEntry::Name(n) => names.push(n.clone()),
                HostEntry::Alias { name, exclude } => self.nested(name, *exclude, out),
                HostEntry::Raw(t) => {
                    let bare = t.trim_start_matches('!');
                    if self.by_name.contains_key(bare) {
                        self.nested(bare, t.starts_with('!'), out);
                        continue;
                    }
                    match parse::parse_entry(t) {
                        parse::Parsed::Entries(es) => out.entries.extend(es),
                        parse::Parsed::Hostname(h) => names.push(h),
                        parse::Parsed::Dropped => {}
                    }
                }
            }
        }
        self.dns(alias, &names, Families::default(), out);
    }

    fn dns(&mut self, alias: &str, names: &[String], fam: Families, out: &mut Content) {
        if names.is_empty() {
            return;
        }
        let (addrs, errors) = dns::collect(names, self.src.resolver());
        out.entries.extend(
            addrs
                .into_iter()
                .map(IpNet::from)
                .filter(|n| fam.admits(n))
                .map(|net| TableEntry { net, negate: false }),
        );
        self.errors
            .extend(errors.into_iter().map(|error| AliasError::Dns {
                alias: alias.to_owned(),
                error,
            }));
    }

    fn list(&mut self, alias: &str, body: &str, fam: Families, out: &mut Content) {
        let mut names = Vec::new();
        for line in body.lines() {
            let Some(tok) = parse::list_line(line) else {
                continue;
            };
            match parse::parse_entry(tok) {
                parse::Parsed::Entries(es) => out
                    .entries
                    .extend(es.into_iter().filter(|e| fam.admits(&e.net))),
                parse::Parsed::Hostname(h) => names.push(h),
                parse::Parsed::Dropped => {}
            }
        }
        self.dns(alias, &names, fam, out);
    }

    fn own(&mut self, d: &AliasDef) -> Content {
        let mut out = Content::default();
        let nets = |v: Vec<IpNet>, fam: Families| {
            v.into_iter()
                .filter(move |n| fam.admits(n))
                .map(|net| TableEntry { net, negate: false })
        };
        match &d.kind {
            AliasKind::Host(v) | AliasKind::Network(v) => self.host_entries(&d.name, v, &mut out),
            AliasKind::NetworkGroup(m) => {
                for n in m {
                    self.nested(n, false, &mut out);
                }
            }
            AliasKind::Port(v) => {
                for p in v {
                    match p {
                        PortEntry::Range(a, b) => out.ports.push((*a, *b)),
                        PortEntry::Alias(a) => self.nested(a, false, &mut out),
                    }
                }
            }
            AliasKind::Url {
                urls,
                auth,
                families,
            } => {
                for u in urls {
                    match self.src.fetch(u, auth) {
                        Ok(body) => self.list(&d.name, &body, *families, &mut out),
                        Err(e) => {
                            out.failed = true;
                            self.errors.push(e.into());
                        }
                    }
                }
            }
            AliasKind::UrlTable {
                url,
                auth,
                families,
                ..
            } => match self.src.fetch(url, auth) {
                Ok(body) => self.list(&d.name, &body, *families, &mut out),
                Err(e) => {
                    out.failed = true;
                    self.errors.push(e.into());
                }
            },
            AliasKind::GeoIp {
                countries,
                families,
            } => {
                for cc in countries {
                    for f in IpFamily::BOTH {
                        out.entries.extend(nets(self.src.geoip(cc, f), *families));
                    }
                }
            }
            AliasKind::Asn { asns, families } => {
                for a in asns {
                    out.entries.extend(nets(self.src.asn(*a), *families));
                }
            }
            AliasKind::Mac(macs) => {
                let table = self.src.neighbours();
                for m in macs {
                    out.entries
                        .extend(mac::lookup(&table, m).into_iter().map(|ip| TableEntry {
                            net: IpNet::from(ip),
                            negate: false,
                        }));
                }
            }
            AliasKind::DynIpv6Host {
                interface,
                suffixes,
            } => {
                let addrs = self.src.interface_addrs(interface);
                for s in suffixes {
                    for a in dynipv6::prefix_plus_suffix(&addrs, s) {
                        if let parse::Parsed::Entries(es) = parse::parse_entry(&a) {
                            out.entries.extend(es);
                        }
                    }
                }
            }
            AliasKind::External => {
                out.entries
                    .extend(nets(self.src.external(&d.name), Families::default()));
            }
        }
        out
    }
}

/// Resolves every alias. Cycles resolve to empty with an error; failed
/// fetches are listed in [`Resolution::failed`].
pub fn resolve_all(defs: &[AliasDef], src: &dyn Sources) -> Resolution {
    let mut r = Resolver {
        by_name: defs.iter().map(|d| (d.name.as_str(), d)).collect(),
        src,
        done: BTreeMap::new(),
        errors: Vec::new(),
    };
    let cyclic = r.cycles();
    for n in &cyclic {
        r.done.insert(
            n.clone(),
            Content {
                failed: true,
                ..Content::default()
            },
        );
        r.errors.push(AliasError::Cycle(n.clone()));
    }
    let mut res = Resolution::default();
    for d in defs {
        let c = r.resolve(&d.name);
        if c.failed {
            res.failed.insert(d.name.clone());
        }
        let mut ports = c.ports;
        ports.sort_unstable();
        ports.dedup();
        res.aliases.insert(
            d.name.clone(),
            ResolvedAlias {
                nets: AddrSet::from_entries(c.entries).to_nets(),
                ports,
            },
        );
    }
    res.errors = r.errors;
    res
}

mod schema;

#[cfg(test)]
mod tests;
