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

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use ipnet::IpNet;
use sensr_schema::fields::{DomainName, HostOverrideName, Hostname};
use sensr_schema::models::dns::{DnsRecord, HostOverride, LocalZoneType};
use serde::{Deserialize, Serialize};

use crate::cmd::{Cmd, CmdError, Runner};
use crate::templates::{Module, Rendered, TemplateError, Templates};

/// Access-control action.
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
}

/// One access-control entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Acl {
    /// Network.
    pub network: IpNet,
    /// Action.
    pub action: AclAction,
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

/// A domain forwarded to specific servers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainForward {
    /// Domain.
    pub domain: DomainName,
    /// Servers.
    pub servers: Vec<Upstream>,
}

/// The resolver input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnboundModel {
    /// Listen port.
    pub port: u16,
    /// Bind addresses; empty = all, with `interface-automatic`.
    pub listen: Vec<IpAddr>,
    /// Enable IPv6 transport.
    pub ipv6: bool,
    /// Action for clients not matched by `acls`.
    pub default_action: AclAction,
    /// Per-network access control.
    pub acls: Vec<Acl>,
    /// DNSSEC validation.
    pub dnssec: bool,
    /// Forward `.` to these instead of recursing.
    pub forwarders: Vec<Upstream>,
    /// Per-domain forwarding.
    pub domain_forwards: Vec<DomainForward>,
    /// Static records (enabled ones).
    pub host_overrides: Vec<HostOverride>,
    /// Type of the system domain's local zone.
    pub local_zone_type: LocalZoneType,
    /// The firewall's own host name.
    pub hostname: Hostname,
    /// The system domain.
    pub domain: DomainName,
    /// The firewall's own addresses (A/AAAA + PTR for `hostname.domain`).
    pub self_addresses: Vec<IpAddr>,
    /// Drop answers with private addresses from public names.
    pub rebind_protection: bool,
    /// Include registered DHCP leases (off by default, as upstream).
    pub register_dhcp_leases: bool,
    /// Working directory (trust anchor, lease include).
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

/// Private ranges for rebinding protection (RFC 1918, 6598, 3927, 4193, 4291).
pub const PRIVATE_ADDRESSES: &[&str] = &[
    "10.0.0.0/8",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fd00::/8",
    "fe80::/10",
];

/// Template view: precomputed strings, so the template stays declarative.
#[derive(Serialize)]
struct View<'a> {
    port: u16,
    listen: &'a [IpAddr],
    ipv6: bool,
    default_action: AclAction,
    acls: &'a [Acl],
    dnssec: bool,
    domain: &'a DomainName,
    local_zone_type: String,
    rebind_protection: bool,
    register_dhcp_leases: bool,
    directory: &'a Path,
    tls_cert_bundle: &'a Path,
    control_socket: &'a Path,
    any_tls: bool,
    forward_addrs: Vec<String>,
    domain_forwards: Vec<(String, Vec<String>)>,
    local_zones: Vec<String>,
    local_data: Vec<String>,
    private_addresses: &'static [&'static str],
    module_config: &'static str,
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
                (
                    d.domain.to_string(),
                    d.servers
                        .iter()
                        .map(|s| upstream(s, s.tls_name.is_some()))
                        .collect(),
                )
            })
            .collect();

        let fqdn = format!("{}.{}", self.hostname, self.domain);
        let mut data = vec![
            "\"localhost A 127.0.0.1\"".to_owned(),
            "\"localhost AAAA ::1\"".to_owned(),
            format!("\"localhost.{} A 127.0.0.1\"", self.domain),
            format!("\"localhost.{} AAAA ::1\"", self.domain),
        ];
        let mut ptrs = vec![
            "\"127.0.0.1 localhost\"".to_owned(),
            "\"::1 localhost\"".to_owned(),
        ];
        for a in &self.self_addresses {
            data.push(format!("\"{fqdn} {} {a}\"", rr(a)));
            ptrs.push(format!("\"{a} {fqdn}\""));
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
                    data.push(format!("\"{name}. {ttl}IN A {address}\""));
                    if !wildcard {
                        ptrs.push(format!("\"{address} {name}\""));
                    }
                }
                DnsRecord::Aaaa { address } => {
                    data.push(format!("\"{name}. {ttl}IN AAAA {address}\""));
                    if !wildcard {
                        ptrs.push(format!("\"{address} {name}\""));
                    }
                }
                DnsRecord::Mx { priority, host } => {
                    data.push(format!("\"{name}. {ttl}IN MX {priority} {host}.\""));
                }
                DnsRecord::Txt { data: txt } => {
                    if txt.chars().any(|c| c == '\'' || c == '"' || c.is_control()) {
                        return Err(UnboundError::BadTxt { name });
                    }
                    data.push(format!("'{name}. {ttl}IN TXT \"{txt}\"'"));
                }
            }
        }
        let local_data = data
            .into_iter()
            .map(|d| format!("local-data: {d}"))
            .chain(ptrs.into_iter().map(|p| format!("local-data-ptr: {p}")))
            .collect();
        let local_zone_type = serde_json::to_value(self.local_zone_type)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| "transparent".to_owned());
        Ok(View {
            port: self.port,
            listen: &self.listen,
            ipv6: self.ipv6,
            default_action: self.default_action,
            acls: &self.acls,
            dnssec: self.dnssec,
            domain: &self.domain,
            local_zone_type,
            rebind_protection: self.rebind_protection,
            register_dhcp_leases: self.register_dhcp_leases,
            directory: &self.directory,
            tls_cert_bundle: &self.tls_cert_bundle,
            control_socket: &self.control_socket,
            any_tls,
            forward_addrs,
            domain_forwards,
            local_zones: zones,
            local_data,
            private_addresses: PRIVATE_ADDRESSES,
            module_config: if self.dnssec {
                "validator iterator"
            } else {
                "iterator"
            },
        })
    }

    /// The template context for this model.
    pub fn context(&self) -> Result<impl Serialize + '_, UnboundError> {
        Ok(Ctx {
            unbound: self.view()?,
        })
    }

    /// Render `unbound.conf`.
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
            "dhcp-leases.conf",
            include_str!("../../templates/unbound/dhcp-leases.conf"),
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

    fn render(m: &UnboundModel) -> String {
        let mut t = Templates::empty();
        t.register(MODULE).unwrap();
        let out = m.render(&t).unwrap();
        assert_eq!(out.len(), 2, "unbound.conf + the lease include");
        out.iter()
            .find(|r| r.dest.ends_with("unbound.conf"))
            .unwrap()
            .contents
            .clone()
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
        std::fs::write(dir.path().join("dhcp-leases.conf"), "").unwrap();
        let include = dir.path().join("dhcp-leases.conf");
        for (label, mut m) in [("recursive", model()), ("dot", dot(model()))] {
            m.directory = dir.path().to_owned();
            m.control_socket = dir.path().join("ctl");
            // Unprivileged: no user switch, no fixed listen addresses.
            m.listen.clear();
            let conf = render(&m).replace(
                "/run/sensr/unbound/dhcp-leases.conf",
                &include.display().to_string(),
            );
            let f = dir.path().join("unbound.conf");
            std::fs::write(&f, conf).unwrap();
            let msg = check(&SystemRunner, &f).unwrap().unwrap();
            assert!(msg.is_empty(), "unbound-checkconf ({label}): {msg}");
        }
    }
}
