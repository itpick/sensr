//! Unbound: `unbound.conf` rendered by the `unbound` template module from a
//! typed model.
//!
//! Behaviour follows OPNsense (`unbound.inc` + `Unbound/core/*.conf`): bind to
//! the selected interface addresses or to everything with
//! `interface-automatic`; ACLs with a default action plus per-network
//! entries; a `local-zone` for the system domain with localhost and the
//! firewall's own records plus PTRs; host overrides as `local-data`
//! (wildcards as a `redirect` zone); domain overrides as `forward-zone` +
//! `domain-insecure` + `private-domain`; forwarding (optionally over TLS) for
//! `.`; DNS-rebinding protection via `private-address`. Lease registration is
//! off unless asked for. Remote control is a unix socket, so lease
//! registration can use `unbound-control local_data` without restarts.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use ipnet::{IpNet, Ipv6Net};
use sensr_schema::fields::{Description, DomainName, HostOverrideName, Hostname};
use sensr_schema::models::dns::{AccessAction, DnsRecord, HostOverride, LocalZoneType, Tuning};
use serde::{Deserialize, Serialize};

use super::dns_runtime::{self, DnsRuntime};
use crate::cmd::{Cmd, CmdError, Runner};
use crate::templates::{Module, Rendered, TemplateError, Templates};

/// Access-control action (Unbound `access-control` keywords).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclAction {
    /// Allow recursion.
    Allow,
    /// Drop silently.
    Deny,
    /// Answer REFUSED.
    Refuse,
    /// Allow, including queries with the RD bit clear (snooping).
    AllowSnoop,
    /// Drop, except queries for local data.
    DenyNonLocal,
    /// REFUSED, except queries for local data.
    RefuseNonLocal,
}

impl From<AccessAction> for AclAction {
    fn from(a: AccessAction) -> Self {
        match a {
            AccessAction::Allow => Self::Allow,
            AccessAction::Deny => Self::Deny,
            AccessAction::Refuse => Self::Refuse,
            AccessAction::AllowSnoop => Self::AllowSnoop,
            AccessAction::DenyNonLocal => Self::DenyNonLocal,
            AccessAction::RefuseNonLocal => Self::RefuseNonLocal,
        }
    }
}

/// One access-control entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acl {
    /// Network.
    pub network: IpNet,
    /// Action.
    pub action: AclAction,
    /// The access list's name (rendered as a comment).
    pub name: Option<String>,
}

/// An upstream server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Upstream {
    /// Address.
    pub address: IpAddr,
    /// Port (default 53, or 853 for TLS).
    pub port: Option<u16>,
    /// TLS authentication name; `Some` makes this a DNS-over-TLS upstream.
    pub tls_name: Option<DomainName>,
}

/// A domain forwarded to specific servers (an OPNsense domain override).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainForward {
    /// Domain.
    pub domain: DomainName,
    /// Servers.
    pub servers: Vec<Upstream>,
}

/// A static name registered from a DHCP reservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticHost {
    /// Host part.
    pub hostname: Hostname,
    /// Domain (the subnet's domain name, else the system domain).
    pub domain: DomainName,
    /// Reserved address.
    pub address: IpAddr,
    /// Description (TXT record when `txt_descriptions`).
    pub description: Option<Description>,
}

impl StaticHost {
    /// `hostname.domain`.
    pub fn fqdn(&self) -> String {
        format!("{}.{}", self.hostname, self.domain)
    }
}

/// The resolver input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnboundModel {
    /// Listen port.
    pub port: u16,
    /// Bind addresses; empty = all, with `interface-automatic`.
    pub listen: Vec<IpAddr>,
    /// Source addresses for upstream queries; empty = any.
    pub outgoing: Vec<IpAddr>,
    /// Enable IPv6 transport.
    pub ipv6: bool,
    /// Action for clients not matched by `acls`.
    pub default_action: AclAction,
    /// Per-network access control.
    pub acls: Vec<Acl>,
    /// DNSSEC validation.
    pub dnssec: bool,
    /// DNS64 synthesis, with its prefix (`None`: `64:ff9b::/96`).
    pub dns64: Option<Option<Ipv6Net>>,
    /// Forward `.` to these instead of recursing.
    pub forwarders: Vec<Upstream>,
    /// Per-domain forwarding.
    pub domain_forwards: Vec<DomainForward>,
    /// Static records (enabled ones).
    pub host_overrides: Vec<HostOverride>,
    /// Registered DHCP reservations.
    pub static_hosts: Vec<StaticHost>,
    /// Publish descriptions as TXT records.
    pub txt_descriptions: bool,
    /// Type of the system domain's local zone.
    pub local_zone_type: LocalZoneType,
    /// The firewall's own host name.
    pub hostname: Hostname,
    /// The system domain.
    pub domain: DomainName,
    /// The firewall's own addresses (A/AAAA for `hostname.domain` and
    /// `hostname`); the first of each family also gets the PTR, as OPNsense
    /// gives it to the primary interface only.
    pub self_addresses: Vec<IpAddr>,
    /// Drop answers with private addresses from public names
    /// (`tuning.private_addresses`; empty turns it off).
    pub rebind_protection: bool,
    /// Resolver tuning.
    pub tuning: Tuning,
    /// Include the registered DHCP leases.
    pub register_dhcp_leases: bool,
    /// Include the compiled blocklist.
    pub blocklist: bool,
    /// What `sensr-dns` needs.
    pub runtime: DnsRuntime,
    /// Working directory (trust anchor).
    pub directory: PathBuf,
    /// CA bundle for DNS-over-TLS.
    pub tls_cert_bundle: PathBuf,
    /// Remote-control unix socket.
    pub control_socket: PathBuf,
}

/// Model errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UnboundError {
    /// TXT data Unbound's config syntax cannot carry.
    #[error("TXT record for {name} contains quotes or control characters")]
    BadTxt {
        /// The record's name.
        name: String,
    },
    /// Template failure.
    #[error("{0}")]
    Template(String),
}

/// Template view: precomputed strings, so the template stays declarative.
#[derive(Serialize)]
struct View<'a> {
    port: u16,
    listen: &'a [IpAddr],
    outgoing: &'a [IpAddr],
    ipv6: bool,
    default_action: AclAction,
    acls: &'a [Acl],
    dnssec: bool,
    dns64_prefix: Option<String>,
    domain: &'a DomainName,
    local_zone_type: String,
    rebind_protection: bool,
    register_dhcp_leases: bool,
    blocklist: bool,
    leases_include: String,
    blocklist_include: String,
    directory: &'a Path,
    tls_cert_bundle: &'a Path,
    control_socket: &'a Path,
    any_tls: bool,
    tls_bundle: bool,
    forward_addrs: Vec<String>,
    domain_forwards: Vec<(String, Vec<String>, bool)>,
    local_zones: Vec<String>,
    local_data: Vec<String>,
    private_addresses: Vec<String>,
    private_domains: Vec<String>,
    insecure_domains: Vec<String>,
    tuning: Vec<(&'static str, String)>,
    logfile: &'static str,
    module_config: String,
    runtime_json: String,
}

#[derive(Serialize)]
struct Ctx<'a> {
    unbound: View<'a>,
}

fn rr(addr: &IpAddr) -> &'static str {
    if addr.is_ipv4() { "A" } else { "AAAA" }
}

fn upstream(u: &Upstream, tls: bool) -> String {
    let mut s = u.address.to_string();
    if let Some(p) = u.port.or(tls.then_some(853)) {
        s.push_str(&format!("@{p}"));
    }
    if let Some(n) = &u.tls_name {
        s.push_str(&format!("#{n}"));
    }
    s
}

fn yes_no(b: bool) -> String {
    if b { "yes" } else { "no" }.to_owned()
}

/// A description as TXT data: Unbound's syntax cannot carry quotes, so they
/// are dropped (OPNsense escapes them with addslashes, which Unbound reads
/// literally).
fn txt_text(d: &str) -> String {
    d.chars()
        .filter(|c| *c != '"' && *c != '\'' && *c != '\\' && !c.is_control())
        .collect()
}

/// `server:` options from the tuning section, in OPNsense's order.
fn tuning_lines(t: &Tuning) -> Vec<(&'static str, String)> {
    let mut v = vec![
        ("hide-identity", yes_no(t.hide_identity)),
        ("hide-version", yes_no(t.hide_version)),
        ("prefetch", yes_no(t.prefetch)),
        ("prefetch-key", yes_no(t.prefetch_key)),
        ("harden-dnssec-stripped", yes_no(t.harden_dnssec_stripped)),
        ("harden-below-nxdomain", yes_no(t.harden_below_nxdomain)),
        ("aggressive-nsec", yes_no(t.aggressive_nsec)),
        ("serve-expired", yes_no(t.serve_expired)),
    ];
    let num = |v: &mut Vec<(&'static str, String)>, k: &'static str, n: Option<u32>| {
        if let Some(n) = n {
            v.push((k, n.to_string()));
        }
    };
    num(&mut v, "serve-expired-reply-ttl", t.serve_expired_reply_ttl);
    num(&mut v, "serve-expired-ttl", t.serve_expired_ttl);
    v.push(("serve-expired-ttl-reset", yes_no(t.serve_expired_ttl_reset)));
    num(
        &mut v,
        "serve-expired-client-timeout",
        t.serve_expired_client_timeout,
    );
    v.extend([
        (
            "qname-minimisation-strict",
            yes_no(t.qname_minimisation_strict),
        ),
        ("extended-statistics", yes_no(t.extended_statistics)),
        ("log-queries", yes_no(t.log_queries)),
        ("log-replies", yes_no(t.log_replies)),
        ("log-tag-queryreply", yes_no(t.log_tag_query_reply)),
        ("log-servfail", yes_no(t.log_servfail)),
        ("log-local-actions", yes_no(t.log_local_actions)),
        ("verbosity", t.log_verbosity.to_string()),
    ]);
    if let Some(s) = t.msg_cache_size {
        v.push(("msg-cache-size", s.bytes().to_string()));
    }
    if let Some(s) = t.rrset_cache_size {
        v.push(("rrset-cache-size", s.bytes().to_string()));
    }
    num(&mut v, "outgoing-num-tcp", t.outgoing_num_tcp);
    num(&mut v, "incoming-num-tcp", t.incoming_num_tcp);
    num(&mut v, "num-queries-per-thread", t.num_queries_per_thread);
    num(&mut v, "outgoing-range", t.outgoing_range);
    num(&mut v, "jostle-timeout", t.jostle_timeout);
    num(&mut v, "discard-timeout", t.discard_timeout);
    num(&mut v, "cache-max-ttl", t.cache_max_ttl);
    num(&mut v, "cache-max-negative-ttl", t.cache_max_negative_ttl);
    num(&mut v, "cache-min-ttl", t.cache_min_ttl);
    num(&mut v, "infra-host-ttl", t.infra_host_ttl);
    v.push(("infra-keep-probing", yes_no(t.infra_keep_probing)));
    num(&mut v, "infra-cache-numhosts", t.infra_cache_numhosts);
    num(
        &mut v,
        "unwanted-reply-threshold",
        t.unwanted_reply_threshold,
    );
    if let Some(l) = t.val_log_level {
        v.push(("val-log-level", l.to_string()));
    }
    v
}

fn is_reverse_zone(d: &DomainName) -> bool {
    let d = d.as_str().to_ascii_lowercase();
    d.ends_with(".in-addr.arpa") || d.ends_with(".ip6.arpa")
}

/// Local data and PTRs, deduplicating PTRs per address as OPNsense does
/// (the first name for an address keeps it).
#[derive(Default)]
struct Records {
    data: Vec<String>,
    ptrs: Vec<String>,
    ptr_addrs: BTreeSet<IpAddr>,
}

impl Records {
    fn ptr(&mut self, addr: IpAddr, name: &str) {
        if self.ptr_addrs.insert(addr) {
            self.ptrs.push(format!("\"{addr} {name}\""));
        }
    }
}

impl UnboundModel {
    fn view(&self) -> Result<View<'_>, UnboundError> {
        let any_tls = self.forwarders.iter().any(|f| f.tls_name.is_some());
        let forward_addrs = self
            .forwarders
            .iter()
            // In TLS mode only TLS upstreams are used: mixing would leak
            // queries in plain text.
            .filter(|f| !any_tls || f.tls_name.is_some())
            .map(|f| upstream(f, any_tls))
            .collect();
        let domain_forwards = self
            .domain_forwards
            .iter()
            .map(|d| {
                let tls = d.servers.iter().any(|s| s.tls_name.is_some());
                (
                    d.domain.to_string(),
                    d.servers
                        .iter()
                        .filter(|s| !tls || s.tls_name.is_some())
                        .map(|s| upstream(s, tls))
                        .collect(),
                    tls,
                )
            })
            .collect();

        let fqdn = format!("{}.{}", self.hostname, self.domain);
        let mut r = Records {
            data: vec![
                "\"localhost A 127.0.0.1\"".to_owned(),
                "\"localhost AAAA ::1\"".to_owned(),
                format!("\"localhost.{} A 127.0.0.1\"", self.domain),
                format!("\"localhost.{} AAAA ::1\"", self.domain),
            ],
            ..Records::default()
        };
        r.ptr(IpAddr::from([127, 0, 0, 1]), "localhost");
        r.ptr(IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]), "localhost");
        let mut primary = BTreeSet::new();
        for a in &self.self_addresses {
            r.data.push(format!("\"{fqdn} {} {a}\"", rr(a)));
            r.data.push(format!("\"{} {} {a}\"", self.hostname, rr(a)));
            if primary.insert(a.is_ipv4()) {
                r.ptr(*a, &fqdn);
            }
        }
        let mut zones = Vec::new();
        for h in &self.host_overrides {
            // A wildcard answers every name under the domain: Unbound
            // expresses that as a redirect zone with apex data.
            let wildcard = matches!(h.hostname, HostOverrideName::Wildcard);
            let name = if wildcard {
                zones.push(format!("\"{}.\" redirect", h.domain));
                h.domain.to_string()
            } else {
                h.fqdn()
            };
            let ttl = h.ttl.map(|t| format!("{t} ")).unwrap_or_default();
            match &h.record {
                DnsRecord::A { address } => {
                    r.data.push(format!("\"{name}. {ttl}IN A {address}\""));
                    if !wildcard && h.ptr {
                        r.ptr(IpAddr::V4(*address), &name);
                    }
                }
                DnsRecord::Aaaa { address } => {
                    r.data.push(format!("\"{name}. {ttl}IN AAAA {address}\""));
                    if !wildcard && h.ptr {
                        r.ptr(IpAddr::V6(*address), &name);
                    }
                }
                DnsRecord::Mx { priority, host } => {
                    r.data
                        .push(format!("\"{name}. {ttl}IN MX {priority} {host}.\""));
                }
                DnsRecord::Txt { data: txt } => {
                    if txt.chars().any(|c| c == '\'' || c == '"' || c.is_control()) {
                        return Err(UnboundError::BadTxt { name });
                    }
                    r.data.push(format!("'{name}. {ttl}IN TXT \"{txt}\"'"));
                }
            }
            if self.txt_descriptions
                && !wildcard
                && let Some(d) = &h.description
            {
                r.data
                    .push(format!("'{name}. TXT \"{}\"'", txt_text(d.as_str())));
            }
        }
        let overridden: BTreeSet<String> = self
            .host_overrides
            .iter()
            .map(|h| h.fqdn().to_ascii_lowercase())
            .collect();
        for s in &self.static_hosts {
            let name = s.fqdn();
            // A host override for the same name wins over the reservation.
            if overridden.contains(&name.to_ascii_lowercase()) {
                continue;
            }
            r.data
                .push(format!("\"{name}. IN {} {}\"", rr(&s.address), s.address));
            r.ptr(s.address, &name);
            if self.txt_descriptions
                && let Some(d) = &s.description
            {
                r.data
                    .push(format!("'{name}. TXT \"{}\"'", txt_text(d.as_str())));
            }
        }
        for d in &self.domain_forwards {
            if is_reverse_zone(&d.domain) {
                zones.push(format!("\"{}.\" typetransparent", d.domain));
            }
        }
        let local_data = r
            .data
            .into_iter()
            .map(|d| format!("local-data: {d}"))
            .chain(r.ptrs.into_iter().map(|p| format!("local-data-ptr: {p}")))
            .collect();
        let local_zone_type = serde_json::to_value(self.local_zone_type)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| "transparent".to_owned());
        let mut private_domains: Vec<String> = Vec::new();
        let push_unique = |v: &mut Vec<String>, s: String| {
            if !v.contains(&s) {
                v.push(s);
            }
        };
        push_unique(&mut private_domains, self.domain.to_string());
        for d in &self.tuning.private_domains {
            push_unique(&mut private_domains, d.to_string());
        }
        for d in &self.domain_forwards {
            if !is_reverse_zone(&d.domain) {
                push_unique(&mut private_domains, d.domain.to_string());
            }
        }
        let mut insecure_domains: Vec<String> = Vec::new();
        for d in self
            .domain_forwards
            .iter()
            .map(|d| d.domain.to_string())
            .chain(self.tuning.insecure_domains.iter().map(|d| d.to_string()))
        {
            push_unique(&mut insecure_domains, d);
        }
        let mut modules = Vec::new();
        if self.dns64.is_some() {
            modules.push("dns64");
        }
        if self.dnssec {
            modules.push("validator");
        }
        modules.push("iterator");
        let runtime_json = serde_json::to_string_pretty(&self.runtime)
            .map_err(|e| UnboundError::Template(e.to_string()))?;
        Ok(View {
            port: self.port,
            listen: &self.listen,
            outgoing: &self.outgoing,
            ipv6: self.ipv6,
            default_action: self.default_action,
            acls: &self.acls,
            dnssec: self.dnssec,
            dns64_prefix: self.dns64.flatten().map(|p| p.to_string()),
            domain: &self.domain,
            local_zone_type,
            rebind_protection: self.rebind_protection && !self.tuning.private_addresses.is_empty(),
            register_dhcp_leases: self.register_dhcp_leases,
            blocklist: self.blocklist,
            // Globs, so a file sensr-dns has not written yet is no error.
            leases_include: dns_runtime::LEASES_INCLUDE.replace(".conf", "*.conf"),
            blocklist_include: dns_runtime::BLOCKLIST_INCLUDE.replace(".conf", "*.conf"),
            directory: &self.directory,
            tls_cert_bundle: &self.tls_cert_bundle,
            control_socket: &self.control_socket,
            any_tls,
            tls_bundle: any_tls
                || self
                    .domain_forwards
                    .iter()
                    .any(|d| d.servers.iter().any(|s| s.tls_name.is_some())),
            forward_addrs,
            domain_forwards,
            local_zones: zones,
            local_data,
            private_addresses: self
                .tuning
                .private_addresses
                .iter()
                .map(|n| n.to_string())
                .collect(),
            private_domains,
            insecure_domains,
            tuning: tuning_lines(&self.tuning),
            logfile: if self.tuning.log_queries {
                dns_runtime::QUERY_LOG
            } else {
                ""
            },
            module_config: modules.join(" "),
            runtime_json,
        })
    }

    /// The template context for this model.
    pub fn context(&self) -> Result<impl Serialize + '_, UnboundError> {
        Ok(Ctx {
            unbound: self.view()?,
        })
    }

    /// Render `unbound.conf`, the `unbound-control` configuration and
    /// `sensr-dns.json`.
    pub fn render(&self, templates: &Templates) -> Result<Vec<Rendered>, RenderError> {
        Ok(templates.render("unbound", &self.context()?)?)
    }
}

/// Render errors.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    /// Invalid model.
    #[error(transparent)]
    Model(#[from] UnboundError),
    /// Template failure.
    #[error(transparent)]
    Template(#[from] TemplateError),
}

/// The `unbound` template module.
pub const MODULE: Module = Module {
    name: "unbound",
    dir: "run/sensr/unbound",
    templates: &[
        (
            "unbound.conf",
            include_str!("../../templates/unbound/unbound.conf"),
        ),
        (
            "control.conf",
            include_str!("../../templates/unbound/control.conf"),
        ),
        (
            "sensr-dns.json",
            include_str!("../../templates/unbound/sensr-dns.json"),
        ),
    ],
    targets: include_str!("../../templates/unbound/TARGETS"),
};

/// Run `unbound-checkconf <file>`: `Ok(None)` when Unbound is not installed,
/// `Ok(Some(""))` when accepted, else its message.
pub fn check(runner: &dyn Runner, file: &Path) -> Result<Option<String>, CmdError> {
    if !runner.has_program("unbound-checkconf") {
        return Ok(None);
    }
    let out = runner.run(&Cmd::new("unbound-checkconf").arg(file), None)?;
    Ok(Some(if out.success() {
        String::new()
    } else {
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            out.stderr_text()
        )
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::appliers::convert::tests::slice_models;
    use crate::cmd::SystemRunner;

    pub(crate) fn model() -> UnboundModel {
        slice_models().unbound.expect("fixture has DNS on")
    }

    fn render_file(m: &UnboundModel, name: &str) -> String {
        let mut t = Templates::empty();
        t.register(MODULE).unwrap();
        let out = m.render(&t).unwrap();
        assert_eq!(out.len(), 3, "unbound.conf, control.conf, sensr-dns.json");
        out.iter()
            .find(|r| r.dest.ends_with(name))
            .unwrap()
            .contents
            .clone()
    }

    fn render(m: &UnboundModel) -> String {
        render_file(m, "unbound.conf")
    }

    fn dot(mut m: UnboundModel) -> UnboundModel {
        m.listen = vec!["192.168.1.1".parse().unwrap(), "::1".parse().unwrap()];
        m.dnssec = false;
        m.register_dhcp_leases = true;
        m.rebind_protection = false;
        m.forwarders = vec![
            Upstream {
                address: "9.9.9.9".parse().unwrap(),
                port: None,
                tls_name: Some("dns.quad9.net".parse().unwrap()),
            },
            Upstream {
                address: "1.1.1.1".parse().unwrap(),
                port: Some(53),
                tls_name: None,
            },
        ];
        m
    }

    #[test]
    fn unbound_recursive_golden() {
        insta::assert_snapshot!(render(&model()));
    }

    #[test]
    fn unbound_dot_forwarding_golden() {
        let out = render(&dot(model()));
        assert!(
            !out.contains("1.1.1.1"),
            "plain upstream must not be used in TLS mode"
        );
        insta::assert_snapshot!(out);
    }

    #[test]
    fn runtime_and_control_goldens() {
        let m = model();
        let json = render_file(&m, "sensr-dns.json");
        let back: DnsRuntime = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m.runtime);
        insta::assert_snapshot!("sensr_dns_json", json);
        insta::assert_snapshot!("control_conf", render_file(&m, "control.conf"));
    }

    #[test]
    fn registrations_ptrs_and_txt() {
        let out = render(&model());
        // Reservations by name in the system domain (no subnet domain).
        assert!(out.contains("local-data: \"printer.home.arpa. IN A 192.168.1.11\""));
        assert!(out.contains("local-data-ptr: \"192.168.1.11 printer.home.arpa\""));
        // One PTR per address: the NAS override has it, the reservation
        // and the second override for the same address do not.
        assert_eq!(out.matches("local-data-ptr: \"192.168.1.10 ").count(), 1);
        assert!(out.contains("local-data-ptr: \"192.168.1.10 nas.home.arpa\""));
        // ptr: false
        assert!(out.contains("cluster.internal.example.org. IN A 192.168.1.20"));
        assert!(!out.contains("192.168.1.20 cluster"));
        // TXT descriptions, quotes dropped.
        assert!(out.contains("local-data: 'nas.home.arpa. TXT \"NAS main box\"'"));
        // Reverse domain override: typetransparent, not private.
        assert!(out.contains("local-zone: \"1.168.192.in-addr.arpa.\" typetransparent"));
        assert!(!out.contains("private-domain: \"1.168.192.in-addr.arpa\""));
        assert!(out.contains("domain-insecure: \"1.168.192.in-addr.arpa\""));
        // Access lists and includes.
        assert!(out.contains("access-control: 192.168.30.0/24 refuse_non_local"));
        assert!(out.contains("include: \"/var/lib/sensr-dns/leases*.conf\""));
        assert!(out.contains("include: \"/var/lib/sensr-dns/blocklist*.conf\""));
        assert!(out.contains("msg-cache-size: 8388608"));
    }

    #[test]
    fn firewall_records_and_dns64() {
        let mut m = model();
        m.self_addresses = vec![
            "192.168.1.1".parse().unwrap(),
            "192.168.2.1".parse().unwrap(),
            "fd00:1::1".parse().unwrap(),
        ];
        m.dns64 = Some(Some("64:ff9b:1::/96".parse().unwrap()));
        let out = render(&m);
        assert!(
            out.contains("local-data: \"sensr 192.168.2.1\"")
                || out.contains("local-data: \"sensr A 192.168.2.1\"")
        );
        // PTR only for the first address of each family (OPNsense: the
        // primary interface).
        assert!(out.contains("local-data-ptr: \"192.168.1.1 sensr.home.arpa\""));
        assert!(!out.contains("local-data-ptr: \"192.168.2.1"));
        assert!(out.contains("local-data-ptr: \"fd00:1::1 sensr.home.arpa\""));
        assert!(out.contains("module-config: \"dns64 validator iterator\""));
        assert!(out.contains("dns64-prefix: 64:ff9b:1::/96"));
    }

    #[test]
    fn txt_with_quotes_is_rejected() {
        let mut m = model();
        let mut h = m.host_overrides[0].clone();
        h.record = DnsRecord::Txt {
            data: "x\" \nserver:".into(),
        };
        m.host_overrides.push(h);
        assert!(matches!(m.context(), Err(UnboundError::BadTxt { .. })));
    }

    /// `unbound-checkconf` on both goldens when Unbound is installed (nixtop:
    /// `nix shell nixpkgs#unbound -c cargo test -p sensr-apply unbound`).
    #[test]
    fn real_unbound_checkconf_accepts_goldens() {
        if !SystemRunner.has_program("unbound-checkconf") {
            eprintln!("note: unbound-checkconf not installed; skipping");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        // The NixOS unbound unit creates this with unbound-anchor; the root
        // KSK-2017 DS record is enough for the checker.
        std::fs::write(
            dir.path().join("root.key"),
            ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n",
        )
        .unwrap();
        // What sensr-dns writes: leases, and a blocklist with a view.
        std::fs::write(
            dir.path().join("leases.conf"),
            "local-data: \"laptop.home.arpa. IN A 192.168.1.150\"\nlocal-data-ptr: \"192.168.1.150 laptop.home.arpa\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("blocklist.conf"),
            "server:\n  local-zone: \"ads.example.net.\" always_null\n  access-control: 192.168.20.0/24 allow\n  access-control-view: 192.168.20.0/24 \"sensr-bl-1\"\nview:\n  name: \"sensr-bl-1\"\n  view-first: yes\n  local-zone: \"tif.example.net.\" always_nxdomain\n",
        )
        .unwrap();
        for (label, mut m) in [("recursive", model()), ("dot", dot(model()))] {
            m.directory = dir.path().to_owned();
            m.control_socket = dir.path().join("ctl");
            // Unprivileged: no user switch, no fixed listen addresses.
            m.listen.clear();
            m.outgoing.clear();
            let conf = render(&m).replace("/var/lib/sensr-dns", &dir.path().display().to_string());
            let f = dir.path().join("unbound.conf");
            std::fs::write(&f, conf).unwrap();
            let msg = check(&SystemRunner, &f).unwrap().unwrap();
            assert!(msg.is_empty(), "unbound-checkconf ({label}): {msg}");
        }
    }
}
