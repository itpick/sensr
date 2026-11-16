//! Recursive DNS resolver settings and host overrides (OPNsense
//! `Unbound/Unbound.xml`; legacy `unbound` host/domain overrides are
//! translated by the importer).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::{IpNet, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::dnsbl::{self, Blocklist};
use super::{check, yes};
use crate::array::ArrayField;
use crate::fields::{Description, DomainName, HostOverrideName, InterfaceId, Port};
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldError, FieldPath, Validations, ValidatorKind};

/// Unbound `local-zone` type for the system domain: how names without local
/// data are answered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LocalZoneType {
    /// Answer local data, resolve everything else normally.
    #[default]
    Transparent,
    /// Like transparent, and also resolve other types of names that have
    /// local data.
    Typetransparent,
    /// Answer local data only; NXDOMAIN otherwise.
    Static,
    /// Answer local data; REFUSED otherwise.
    Refuse,
    /// Answer local data; drop otherwise.
    Deny,
    /// Answer every name under the zone with the zone apex data.
    Redirect,
    /// Like transparent, logging the client.
    Inform,
    /// Like deny, logging the client.
    InformDeny,
    /// No default local zone.
    Nodefault,
    /// Resolve normally, ignoring local data.
    AlwaysTransparent,
    /// Always REFUSED.
    AlwaysRefuse,
    /// Always NXDOMAIN.
    AlwaysNxdomain,
}

/// The recursive resolver.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DnsResolver {
    /// Run the resolver.
    #[serde(default)]
    pub enabled: bool,
    /// Listen port.
    #[serde(default = "dns_port")]
    pub port: Port,
    /// Interfaces to answer on; empty means all.
    #[serde(default)]
    pub listen_interfaces: Vec<InterfaceId>,
    /// Interfaces to send queries from; empty means all.
    #[serde(default)]
    pub outgoing_interfaces: Vec<InterfaceId>,
    /// Validate DNSSEC.
    #[serde(default)]
    pub dnssec: bool,
    /// Synthesize AAAA records for IPv4-only names.
    #[serde(default)]
    pub dns64: bool,
    /// Register DHCP leases by host name.
    #[serde(default)]
    pub register_dhcp_leases: bool,
    /// Register DHCP static reservations.
    #[serde(default)]
    pub register_dhcp_static: bool,
    /// Domain for registered leases; `None` uses `system.domain`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp_domain: Option<DomainName>,
    /// Local zone behaviour.
    #[serde(default)]
    pub local_zone_type: LocalZoneType,
    /// Forward queries instead of recursing.
    #[serde(default)]
    pub forwarding: Forwarding,
    /// Static records.
    #[serde(default)]
    pub host_overrides: ArrayField<HostOverride>,
    /// Keep query statistics (OPNsense `stats`; `unbound-control stats`).
    #[serde(default)]
    pub statistics: bool,
    /// Prefix for DNS64 synthesis; `None` for the well-known `64:ff9b::/96`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub dns64_prefix: Option<Ipv6Net>,
    /// Publish the firewall's own name for its interface addresses
    /// (OPNsense `noregrecords` unset).
    #[serde(default = "yes")]
    pub register_firewall_records: bool,
    /// Publish descriptions of host overrides and reservations as TXT
    /// records (OPNsense `txtsupport`).
    #[serde(default)]
    pub txt_descriptions: bool,
    /// Who may query.
    #[serde(default, skip_serializing_if = "AccessControl::is_default")]
    pub access: AccessControl,
    /// Resolver tuning (OPNsense Unbound › Advanced).
    #[serde(default, skip_serializing_if = "Tuning::is_default")]
    pub tuning: Tuning,
    /// Blocklist policies (OPNsense Unbound › Blocklist).
    #[serde(default, skip_serializing_if = "ArrayField::is_empty")]
    pub blocklists: ArrayField<Blocklist>,
}

fn dns_port() -> Port {
    Port::new(53).expect("non-zero")
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self {
            enabled: false,
            port: dns_port(),
            listen_interfaces: Vec::new(),
            outgoing_interfaces: Vec::new(),
            dnssec: false,
            dns64: false,
            register_dhcp_leases: false,
            register_dhcp_static: false,
            dhcp_domain: None,
            local_zone_type: LocalZoneType::Transparent,
            forwarding: Forwarding::default(),
            host_overrides: ArrayField::new(),
            statistics: false,
            dns64_prefix: None,
            register_firewall_records: true,
            txt_descriptions: false,
            access: AccessControl::default(),
            tuning: Tuning::default(),
            blocklists: ArrayField::new(),
        }
    }
}

/// Query forwarding (Unbound forward zones / OPNsense "Query Forwarding" and
/// "DNS over TLS").
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Forwarding {
    /// Forward everything to `system.dns_servers` (OPNsense forwarding mode).
    #[serde(default)]
    pub use_system_servers: bool,
    /// Explicit upstreams, optionally per domain.
    #[serde(default)]
    pub servers: ArrayField<Forwarder>,
}

/// One upstream server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Forwarder {
    /// Use this upstream.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Only for names under this domain; `None` for everything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<DomainName>,
    /// Server address.
    pub address: IpAddr,
    /// Server port; `None` for 53 (or 853 with TLS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<Port>,
    /// Name to verify in the server's certificate; enables DNS over TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_name: Option<DomainName>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

/// The data of a host override.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "rr", rename_all = "UPPERCASE", deny_unknown_fields)]
pub enum DnsRecord {
    /// IPv4 address.
    A {
        /// Address.
        address: Ipv4Addr,
    },
    /// IPv6 address.
    Aaaa {
        /// Address.
        address: Ipv6Addr,
    },
    /// Mail exchanger.
    Mx {
        /// Preference (lower first).
        priority: u16,
        /// Mail server host.
        host: DomainName,
    },
    /// Text.
    Txt {
        /// Record text.
        data: String,
    },
}

/// A static DNS record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostOverride {
    /// Serve the record.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Host part (empty for the domain itself, `*` for a wildcard).
    #[serde(default = "apex")]
    pub hostname: HostOverrideName,
    /// Domain.
    pub domain: DomainName,
    /// Record data.
    pub record: DnsRecord,
    /// TTL in seconds; `None` for the resolver default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    /// Also answer reverse lookups for an A/AAAA record (OPNsense `addptr`).
    #[serde(default = "yes")]
    pub ptr: bool,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

fn apex() -> HostOverrideName {
    HostOverrideName::Apex
}

impl HostOverride {
    /// The full name (`host.domain`, or `domain` for the apex).
    pub fn fqdn(&self) -> String {
        match &self.hostname {
            HostOverrideName::Apex => self.domain.to_string(),
            h => format!("{h}.{}", self.domain),
        }
    }
}

/// What the resolver does with a client's query.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AccessAction {
    /// Answer, recursing as needed.
    #[default]
    Allow,
    /// Drop the query.
    Deny,
    /// Answer REFUSED.
    Refuse,
    /// Answer, also queries without the RD bit (cache snooping).
    AllowSnoop,
    /// Drop, except queries for local data.
    DenyNonLocal,
    /// REFUSED, except queries for local data.
    RefuseNonLocal,
}

/// Access control (OPNsense Unbound › Access Lists).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessControl {
    /// Action for clients no list matches. OPNsense offers allow, deny and
    /// refuse here; the firewall keeps WAN clients out either way.
    #[serde(default)]
    pub default_action: AccessAction,
    /// Lists, matched by the most specific network.
    #[serde(default, skip_serializing_if = "ArrayField::is_empty")]
    pub lists: ArrayField<AccessList>,
}

impl AccessControl {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// One access list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccessList {
    /// Use this list.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Name.
    pub name: Description,
    /// Action.
    #[serde(default)]
    pub action: AccessAction,
    /// Networks (at least one).
    #[schemars(with = "Vec<String>")]
    pub networks: Vec<IpNet>,
    /// Free text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

/// A cache size: bytes, or a number with a `k`, `m` or `g` suffix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CacheSize(u64);

impl CacheSize {
    /// Bytes.
    pub fn bytes(self) -> u64 {
        self.0
    }
}

impl FromStr for CacheSize {
    type Err = FieldError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let (num, mult) = match s.char_indices().last() {
            Some((i, c)) if c.eq_ignore_ascii_case(&'k') => (&s[..i], 1u64 << 10),
            Some((i, c)) if c.eq_ignore_ascii_case(&'m') => (&s[..i], 1 << 20),
            Some((i, c)) if c.eq_ignore_ascii_case(&'g') => (&s[..i], 1 << 30),
            _ => (s, 1),
        };
        num.parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(mult))
            .filter(|n| *n > 0)
            .map(Self)
            .ok_or_else(|| FieldError::syntax("Enter a size such as 4m, 512k or 1g."))
    }
}

impl fmt::Display for CacheSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.0;
        for (shift, unit) in [(30, 'g'), (20, 'm'), (10, 'k')] {
            if n.is_multiple_of(1 << shift) {
                return write!(f, "{}{unit}", n >> shift);
            }
        }
        write!(f, "{n}")
    }
}
crate::fields::string_serde!(CacheSize);

/// Private address ranges answers from public names may not contain (DNS
/// rebinding protection; OPNsense's default `privateaddress`).
pub const DEFAULT_PRIVATE_ADDRESSES: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "233.252.0.0/24",
    "::1/128",
    "2001:db8::/32",
    "fc00::/8",
    "fd00::/8",
    "fe80::/10",
];

fn default_private_addresses() -> Vec<IpNet> {
    DEFAULT_PRIVATE_ADDRESSES
        .iter()
        .filter_map(|n| n.parse().ok())
        .collect()
}

fn is_default_private(v: &[IpNet]) -> bool {
    v == default_private_addresses().as_slice()
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_true(b: &bool) -> bool {
    *b
}

fn one() -> u8 {
    1
}

fn is_one(v: &u8) -> bool {
    *v == 1
}

/// Resolver tuning (OPNsense Unbound › Advanced). `None` leaves Unbound's
/// own default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Tuning {
    /// Refuse `id.server` and `hostname.bind` queries.
    #[serde(default, skip_serializing_if = "is_false")]
    pub hide_identity: bool,
    /// Refuse `version.server` and `version.bind` queries.
    #[serde(default, skip_serializing_if = "is_false")]
    pub hide_version: bool,
    /// Refresh popular cache entries before they expire.
    #[serde(default, skip_serializing_if = "is_false")]
    pub prefetch: bool,
    /// Fetch DNSKEYs early while validating.
    #[serde(default, skip_serializing_if = "is_false")]
    pub prefetch_key: bool,
    /// Treat zones that should be signed but are not as bogus.
    #[serde(default, skip_serializing_if = "is_false")]
    pub harden_dnssec_stripped: bool,
    /// Answer NXDOMAIN below an NXDOMAIN (RFC 8020).
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub harden_below_nxdomain: bool,
    /// Synthesize negative answers from cached NSEC records (RFC 8198).
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub aggressive_nsec: bool,
    /// Serve expired records while refreshing them.
    #[serde(default, skip_serializing_if = "is_false")]
    pub serve_expired: bool,
    /// TTL of expired answers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serve_expired_reply_ttl: Option<u32>,
    /// How long past expiry records may be served (seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serve_expired_ttl: Option<u32>,
    /// Reset the expired-serving window when a record is refreshed.
    #[serde(default, skip_serializing_if = "is_false")]
    pub serve_expired_ttl_reset: bool,
    /// Milliseconds to wait for a fresh answer before serving an expired one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serve_expired_client_timeout: Option<u32>,
    /// Strict QNAME minimisation.
    #[serde(default, skip_serializing_if = "is_false")]
    pub qname_minimisation_strict: bool,
    /// Extended statistics (per type, rcode, ...).
    #[serde(default, skip_serializing_if = "is_false")]
    pub extended_statistics: bool,
    /// Log every query.
    #[serde(default, skip_serializing_if = "is_false")]
    pub log_queries: bool,
    /// Log every reply.
    #[serde(default, skip_serializing_if = "is_false")]
    pub log_replies: bool,
    /// Tag logged queries and replies.
    #[serde(default, skip_serializing_if = "is_false")]
    pub log_tag_query_reply: bool,
    /// Log SERVFAIL reasons.
    #[serde(default, skip_serializing_if = "is_false")]
    pub log_servfail: bool,
    /// Log answers from local zones.
    #[serde(default, skip_serializing_if = "is_false")]
    pub log_local_actions: bool,
    /// Log verbosity (0-5).
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub log_verbosity: u8,
    /// DNSSEC validation log level (0-2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub val_log_level: Option<u8>,
    /// Domains allowed to answer with private addresses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub private_domains: Vec<DomainName>,
    /// Ranges public answers may not contain (rebinding protection); empty
    /// turns the protection off.
    #[serde(
        default = "default_private_addresses",
        skip_serializing_if = "is_default_private"
    )]
    #[schemars(with = "Vec<String>")]
    pub private_addresses: Vec<IpNet>,
    /// Domains not DNSSEC-validated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub insecure_domains: Vec<DomainName>,
    /// Message cache size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub msg_cache_size: Option<CacheSize>,
    /// RRset cache size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rrset_cache_size: Option<CacheSize>,
    /// Outgoing TCP buffers per thread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outgoing_num_tcp: Option<u32>,
    /// Incoming TCP buffers per thread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incoming_num_tcp: Option<u32>,
    /// Queries served at once per thread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub num_queries_per_thread: Option<u32>,
    /// Ports opened for outgoing queries per thread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outgoing_range: Option<u32>,
    /// Milliseconds before a long query may be replaced under load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jostle_timeout: Option<u32>,
    /// Milliseconds before an unanswered reply is discarded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discard_timeout: Option<u32>,
    /// Upper bound on cached TTLs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_max_ttl: Option<u32>,
    /// Upper bound on cached negative TTLs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_max_negative_ttl: Option<u32>,
    /// Lower bound on cached TTLs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_min_ttl: Option<u32>,
    /// Seconds upstream server data is kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub infra_host_ttl: Option<u32>,
    /// Keep probing servers that are down.
    #[serde(default, skip_serializing_if = "is_false")]
    pub infra_keep_probing: bool,
    /// Upstream servers kept in the infrastructure cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub infra_cache_numhosts: Option<u32>,
    /// Unwanted replies before the cache is flushed as a defence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unwanted_reply_threshold: Option<u32>,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            hide_identity: false,
            hide_version: false,
            prefetch: false,
            prefetch_key: false,
            harden_dnssec_stripped: false,
            harden_below_nxdomain: true,
            aggressive_nsec: true,
            serve_expired: false,
            serve_expired_reply_ttl: None,
            serve_expired_ttl: None,
            serve_expired_ttl_reset: false,
            serve_expired_client_timeout: None,
            qname_minimisation_strict: false,
            extended_statistics: false,
            log_queries: false,
            log_replies: false,
            log_tag_query_reply: false,
            log_servfail: false,
            log_local_actions: false,
            log_verbosity: 1,
            val_log_level: None,
            private_domains: Vec::new(),
            private_addresses: default_private_addresses(),
            insecure_domains: Vec::new(),
            msg_cache_size: None,
            rrset_cache_size: None,
            outgoing_num_tcp: None,
            incoming_num_tcp: None,
            num_queries_per_thread: None,
            outgoing_range: None,
            jostle_timeout: None,
            discard_timeout: None,
            cache_max_ttl: None,
            cache_max_negative_ttl: None,
            cache_min_ttl: None,
            infra_host_ttl: None,
            infra_keep_probing: false,
            infra_cache_numhosts: None,
            unwanted_reply_threshold: None,
        }
    }
}

impl Tuning {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

impl Validate for DnsResolver {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        check::interfaces(
            ctx,
            &self.listen_interfaces,
            &at.join("listen_interfaces"),
            out,
        );
        check::interfaces(
            ctx,
            &self.outgoing_interfaces,
            &at.join("outgoing_interfaces"),
            out,
        );
        let acl = at.join("access").join("lists");
        for (id, l) in &self.access.lists {
            if l.networks.is_empty() {
                out.add(
                    &acl.join(id).join("networks"),
                    ValidatorKind::PresenceOf,
                    "A value is required.",
                );
            }
        }
        let t = at.join("tuning");
        check::range(
            self.tuning.log_verbosity,
            0..=5,
            &t.join("log_verbosity"),
            out,
        );
        if let Some(v) = self.tuning.val_log_level {
            check::range(v, 0..=2, &t.join("val_log_level"), out);
        }
        dnsbl::validate(&self.blocklists, ctx, &at.join("blocklists"), out);
        let hosts = at.join("host_overrides");
        for (id, h) in &self.host_overrides {
            let p = hosts.join(id);
            if let Some(ttl) = h.ttl {
                check::range(ttl, 0..=2_147_483_647, &p.join("ttl"), out);
            }
            if let DnsRecord::Txt { data } = &h.record
                && (data.is_empty() || data.contains(['\n', '\r']))
            {
                out.add(
                    &p.join("record").join("data"),
                    ValidatorKind::Regex,
                    "The TXT data must be a single non-empty line.",
                );
            }
        }
        check::unique(
            self.host_overrides
                .iter()
                .filter(|(_, h)| {
                    h.enabled && matches!(h.record, DnsRecord::A { .. } | DnsRecord::Aaaa { .. })
                })
                .map(|(id, h)| {
                    (
                        hosts.join(id),
                        Some((h.fqdn().to_ascii_lowercase(), h.record.clone())),
                    )
                }),
            "record",
            "Duplicate entry exists.",
            out,
        );
    }
}
