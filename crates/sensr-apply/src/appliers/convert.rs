//! `sensr_schema::Document` → the appliers' inputs.
//!
//! The schema holds configuration in OPNsense's terms (logical interface ids,
//! UUID-keyed lists, secrets inline); the appliers need it resolved: kernel
//! devices, Kea's numeric subnet ids, interface addresses for automatic DHCP
//! options and resolver bindings, and secrets as files the daemons read.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use sensr_schema::Document;
use sensr_schema::array::Uuid;
use sensr_schema::fields::{DeviceName, DomainName, Host, HostOverrideName, InterfaceId};
use sensr_schema::models::interfaces::{Interface, InterfaceRole, Ipv4Config, Ipv6Config, Qdisc};

use super::SliceModels;
use super::dns_runtime::{self, BlocklistRuntime, DnsRuntime, LeaseRuntime, PolicyRuntime};
use super::kea::{self, Dhcp4Model, KeaSubnet};
use super::ntp::{self as ntp_applier, NtpModel, Source, SourceMode};
use super::qdisc::{Diffserv, QdiscModel, Shaper};
use super::sysctl::SysctlModel;
use super::unbound::{Acl, DomainForward, StaticHost, UnboundModel, Upstream};
use super::wireguard::{Endpoint, WgInterface, WgPeer, WireguardModel};

/// Conversion failures (references the schema's validation already checks,
/// reported rather than panicking if an unvalidated document gets here).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConvertError {
    /// An interface id with no assignment.
    #[error("{at}: unknown interface {id}")]
    UnknownInterface {
        /// Where it was referenced.
        at: &'static str,
        /// The id.
        id: InterfaceId,
    },
    /// A WireGuard instance whose device name is not a valid link name.
    #[error("WireGuard instance {0} has no valid device name")]
    BadInstance(u32),
}

/// Where secrets are materialised as files (mode 0640, readable by the
/// daemon that needs them). The agent writes them from [`secret_files`].
#[derive(Debug, Clone)]
pub struct SecretsDir(pub PathBuf);

impl Default for SecretsDir {
    fn default() -> Self {
        SecretsDir("/var/lib/sensr/secrets".into())
    }
}

impl SecretsDir {
    fn wg_private(&self, instance: u32) -> PathBuf {
        self.0.join(format!("wireguard/wg{instance}.key"))
    }
    fn wg_psk(&self, peer: &Uuid) -> PathBuf {
        self.0.join(format!("wireguard/{peer}.psk"))
    }
}

/// The secret files the slice needs: (path, contents). The contents are the
/// only place key material leaves the store.
pub fn secret_files(doc: &Document, dir: &SecretsDir) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    if !doc.wireguard.enabled {
        return out;
    }
    for s in doc.wireguard.servers.values().filter(|s| s.enabled) {
        out.push((
            dir.wg_private(s.instance),
            format!("{}\n", s.private_key.expose()),
        ));
    }
    for (id, p) in doc.wireguard.peers.iter().filter(|(_, p)| p.enabled) {
        if let Some(psk) = &p.preshared_key {
            out.push((dir.wg_psk(id), format!("{}\n", psk.expose())));
        }
    }
    out
}

fn iface<'a>(
    doc: &'a Document,
    id: &InterfaceId,
    at: &'static str,
) -> Result<&'a Interface, ConvertError> {
    doc.interfaces
        .get(id)
        .ok_or_else(|| ConvertError::UnknownInterface { at, id: id.clone() })
}

fn device(doc: &Document, id: &InterfaceId, at: &'static str) -> Result<DeviceName, ConvertError> {
    Ok(iface(doc, id, at)?.device.clone())
}

/// A stable Kea subnet id from the subnet's UUID (all 128 bits folded, top
/// bit clear, never 0), so leases survive reordering and edits.
pub fn kea_subnet_id(uuid: &Uuid) -> u32 {
    let v = uuid.as_u128();
    let folded = (v as u32) ^ ((v >> 32) as u32) ^ ((v >> 64) as u32) ^ ((v >> 96) as u32);
    match folded & 0x7fff_ffff {
        0 => 1,
        n => n,
    }
}

fn static_v4(i: &Interface) -> Option<ipnet::Ipv4Net> {
    match &i.ipv4 {
        Ipv4Config::Static { address, .. } => Some(*address),
        _ => None,
    }
}

fn static_v6(i: &Interface) -> Option<ipnet::Ipv6Net> {
    match &i.ipv6 {
        Ipv6Config::Static { address, .. } => Some(*address),
        _ => None,
    }
}

/// DHCPv4 (`None` when disabled).
pub fn kea(doc: &Document) -> Result<Option<Dhcp4Model>, ConvertError> {
    let d = &doc.dhcpv4;
    if !d.enabled {
        return Ok(None);
    }
    let interfaces = d
        .interfaces
        .iter()
        .map(|i| device(doc, i, "dhcpv4.interfaces"))
        .collect::<Result<Vec<_>, _>>()?;
    let mut subnets = Vec::new();
    for (uuid, s) in &d.subnets {
        let mut subnet = s.clone();
        // OPNsense `option_data_autocollect`: the serving interface's own
        // address is router and DNS server unless set explicitly.
        let own = s
            .interface
            .as_ref()
            .and_then(|i| doc.interfaces.get(i))
            .into_iter()
            .chain(doc.interfaces.iter().map(|(_, i)| i))
            .filter_map(static_v4)
            .find(|a| s.subnet.contains(&a.addr()))
            .map(|a| a.addr());
        if s.auto_options
            && let Some(a) = own
        {
            if subnet.options.routers.is_empty() {
                subnet.options.routers.push(a);
            }
            if subnet.options.dns_servers.is_empty() && doc.dns.enabled {
                subnet.options.dns_servers.push(a);
            }
        }
        subnets.push(KeaSubnet {
            id: kea_subnet_id(uuid),
            device: s
                .interface
                .as_ref()
                .map(|i| device(doc, i, "dhcpv4.subnets.interface"))
                .transpose()?,
            reservations: d
                .reservations
                .values()
                .filter(|r| r.subnet.id() == *uuid)
                .cloned()
                .collect(),
            subnet,
        });
    }
    Ok(Some(Dhcp4Model {
        interfaces,
        valid_lifetime: d.valid_lifetime,
        system_domain: doc.system.domain.clone(),
        subnets,
        lease_file: kea::LEASE_FILE.into(),
        control_socket: kea::CONTROL_SOCKET.into(),
    }))
}

/// The resolver (`None` when disabled).
pub fn unbound(doc: &Document) -> Result<Option<UnboundModel>, ConvertError> {
    let d = &doc.dns;
    if !d.enabled {
        return Ok(None);
    }
    // Bind to the selected interfaces' static addresses. If one of them is
    // dynamically addressed its address is unknown here, so bind everything
    // and let interface-automatic answer from the right source.
    let mut listen = Vec::new();
    let mut dynamic = false;
    for id in &d.listen_interfaces {
        let i = iface(doc, id, "dns.listen_interfaces")?;
        let before = listen.len();
        listen.extend(static_v4(i).map(|a| IpAddr::V4(a.addr())));
        listen.extend(static_v6(i).map(|a| IpAddr::V6(a.addr())));
        // Router advertisements name the router's link-local address as
        // the resolver there; only the wildcard bind answers on it.
        dynamic |= listen.len() == before || super::interfaces::advertises_link_local_dns(doc, id);
    }
    if dynamic {
        listen.clear();
    } else if !listen.is_empty() {
        listen.insert(0, IpAddr::from([127, 0, 0, 1]));
        listen.insert(1, "::1".parse().unwrap_or(IpAddr::from([0u8; 16])));
    }
    let up = |a: IpAddr, port: Option<u16>, tls_name| Upstream {
        address: a,
        port,
        tls_name,
    };
    let mut forwarders = Vec::new();
    if d.forwarding.use_system_servers {
        forwarders.extend(doc.system.dns_servers.iter().map(|a| up(*a, None, None)));
    }
    let mut domain_forwards: Vec<DomainForward> = Vec::new();
    for f in d.forwarding.servers.values().filter(|f| f.enabled) {
        let u = up(f.address, f.port.map(|p| p.get()), f.tls_name.clone());
        match &f.domain {
            None => forwarders.push(u),
            Some(dom) => match domain_forwards.iter_mut().find(|x| &x.domain == dom) {
                Some(x) => x.servers.push(u),
                None => domain_forwards.push(DomainForward {
                    domain: dom.clone(),
                    servers: vec![u],
                }),
            },
        }
    }
    let self_addresses: Vec<IpAddr> = if d.register_firewall_records {
        doc.interfaces
            .iter()
            .filter(|(_, i)| i.enabled && i.role != InterfaceRole::Wan)
            .flat_map(|(_, i)| {
                static_v4(i)
                    .map(|a| IpAddr::V4(a.addr()))
                    .into_iter()
                    .chain(static_v6(i).map(|a| IpAddr::V6(a.addr())))
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut outgoing = Vec::new();
    for id in &d.outgoing_interfaces {
        let i = iface(doc, id, "dns.outgoing_interfaces")?;
        outgoing.extend(static_v4(i).map(|a| IpAddr::V4(a.addr())));
        outgoing.extend(static_v6(i).map(|a| IpAddr::V6(a.addr())));
    }
    let acls: Vec<Acl> = d
        .access
        .lists
        .values()
        .filter(|l| l.enabled)
        .flat_map(|l| {
            l.networks.iter().map(|n| Acl {
                network: *n,
                action: l.action.into(),
                name: Some(l.name.to_string()),
            })
        })
        .collect();
    let host_overrides: Vec<_> = d
        .host_overrides
        .values()
        .filter(|h| h.enabled)
        .cloned()
        .collect();

    // Reservations by name (OPNsense `regdhcpstatic`), in the subnet's
    // domain or the system domain, only while the DHCP server runs (Kea's
    // static-mapping hook returns nothing when it is disabled).
    let subnet_domain = |uuid: &Uuid| {
        doc.dhcpv4
            .subnets
            .get(uuid)
            .and_then(|s| s.options.domain_name.clone())
    };
    let static_hosts: Vec<StaticHost> = if d.register_dhcp_static && doc.dhcpv4.enabled {
        doc.dhcpv4
            .reservations
            .values()
            .filter_map(|r| {
                Some(StaticHost {
                    hostname: r.hostname.clone()?,
                    domain: subnet_domain(&r.subnet.id())
                        .unwrap_or_else(|| doc.system.domain.clone()),
                    address: IpAddr::V4(r.ip_address?),
                    description: r.description.clone(),
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    let leases = (d.register_dhcp_leases && doc.dhcpv4.enabled).then(|| LeaseRuntime {
        lease_file: kea::LEASE_FILE.into(),
        default_domain: d
            .dhcp_domain
            .clone()
            .unwrap_or_else(|| doc.system.domain.clone()),
        subnets: doc
            .dhcpv4
            .subnets
            .iter()
            .filter_map(|(id, s)| Some((kea_subnet_id(id), s.options.domain_name.clone()?)))
            .collect(),
        static_names: host_overrides
            .iter()
            .filter(|h| !matches!(h.hostname, HostOverrideName::Wildcard))
            .map(|h| h.fqdn().to_ascii_lowercase())
            .chain(static_hosts.iter().map(|h| h.fqdn().to_ascii_lowercase()))
            .chain([format!("{}.{}", doc.system.hostname, doc.system.domain).to_ascii_lowercase()])
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        static_addresses: static_hosts
            .iter()
            .map(|h| h.address)
            .chain(self_addresses.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    });

    let policies: Vec<PolicyRuntime> = d
        .blocklists
        .iter()
        .filter(|(_, b)| b.enabled)
        .map(|(id, b)| PolicyRuntime {
            id: *id,
            policy: b.clone(),
        })
        .collect();
    let blocklist = (!policies.is_empty()).then(|| {
        let mut protected = vec![doc.system.domain.clone()];
        let mut add = |n: DomainName| {
            if !protected.contains(&n) {
                protected.push(n);
            }
        };
        for h in &host_overrides {
            if let Ok(n) = h.fqdn().parse() {
                add(n);
            }
        }
        for f in &domain_forwards {
            add(f.domain.clone());
        }
        for s in &static_hosts {
            add(s.domain.clone());
        }
        if let Some(l) = &leases {
            add(l.default_domain.clone());
            for (_, dom) in &l.subnets {
                add(dom.clone());
            }
        }
        BlocklistRuntime {
            policies,
            protected,
            default_action: d.access.default_action.into(),
            acls: acls.iter().map(|a| (a.network, a.action)).collect(),
        }
    });

    Ok(Some(UnboundModel {
        port: d.port.get(),
        listen,
        outgoing,
        ipv6: true,
        // OPNsense's default; the firewall keeps WAN clients out.
        default_action: d.access.default_action.into(),
        acls,
        dnssec: d.dnssec,
        dns64: d.dns64.then_some(d.dns64_prefix),
        forwarders,
        domain_forwards,
        host_overrides,
        static_hosts,
        txt_descriptions: d.txt_descriptions,
        local_zone_type: d.local_zone_type,
        hostname: doc.system.hostname.clone(),
        domain: doc.system.domain.clone(),
        self_addresses,
        rebind_protection: true,
        tuning: d.tuning.clone(),
        register_dhcp_leases: leases.is_some(),
        blocklist: blocklist.is_some(),
        runtime: DnsRuntime {
            control_conf: dns_runtime::CONTROL_CONF.into(),
            state_dir: dns_runtime::STATE_DIR.into(),
            statistics: d.statistics,
            log_queries: d.tuning.log_queries,
            blocklist,
            leases,
        },
        directory: "/var/lib/unbound".into(),
        tls_cert_bundle: "/etc/ssl/certs/ca-certificates.crt".into(),
        control_socket: "/run/unbound/unbound.ctl".into(),
    }))
}

/// Tunnels (enabled servers with their enabled peers).
pub fn wireguard(doc: &Document, secrets: &SecretsDir) -> Result<WireguardModel, ConvertError> {
    let w = &doc.wireguard;
    if !w.enabled {
        return Ok(WireguardModel::default());
    }
    let mut interfaces = Vec::new();
    for s in w.servers.values().filter(|s| s.enabled) {
        let name: DeviceName = format!("wg{}", s.instance)
            .parse()
            .map_err(|_| ConvertError::BadInstance(s.instance))?;
        let peers = s
            .peers
            .iter()
            .filter_map(|rel| {
                let p = rel.resolve(&w.peers)?;
                p.enabled.then(|| WgPeer {
                    name: p.name.clone(),
                    public_key: p.public_key,
                    preshared_key_file: p.preshared_key.as_ref().map(|_| secrets.wg_psk(&rel.id())),
                    endpoint: p.endpoint.as_ref().map(|h: &Host| Endpoint {
                        host: h.clone(),
                        port: p.endpoint_port.map_or(51820, |p| p.get()),
                    }),
                    allowed_ips: p.allowed_ips.clone(),
                    keepalive: p.keepalive,
                })
            })
            .collect();
        interfaces.push(WgInterface {
            name,
            private_key_file: secrets.wg_private(s.instance),
            listen_port: s.listen_port.map(|p| p.get()),
            addresses: s.tunnel_addresses.clone(),
            mtu: s.mtu,
            route_allowed_ips: !s.disable_routes,
            peers,
        });
    }
    Ok(WireguardModel { interfaces })
}

/// The time service (`None` without time servers: OPNsense then runs no
/// ntpd either).
pub fn ntp(doc: &Document) -> Result<Option<NtpModel>, ConvertError> {
    let servers = &doc.system.time_servers;
    if servers.is_empty() {
        return Ok(None);
    }
    let n = &doc.ntp;
    let sources = servers
        .iter()
        .filter_map(|host| {
            let o = n.options(host);
            if o.is_some_and(|o| o.no_select) {
                return None;
            }
            // ntpd.inc: a name under pool.ntp.org is always a pool.
            let pool = o.is_some_and(|o| o.pool)
                || matches!(host, Host::Name(d) if d.as_str().ends_with(".pool.ntp.org"));
            let nts = o.is_some_and(|o| o.nts);
            let mode = match (nts, pool) {
                (false, false) => SourceMode::Server,
                (false, true) => SourceMode::Pool,
                (true, false) => SourceMode::Nts,
                (true, true) => SourceMode::NtsPool,
            };
            Some(Source {
                host: host.clone(),
                mode,
            })
        })
        .collect();
    let listen = if n.serve {
        ntp_listen(doc, &n.listen_interfaces)?
    } else {
        Vec::new()
    };
    Ok(Some(NtpModel {
        sources,
        listen,
        local_stratum: n.orphan_stratum,
        observation_path: ntp_applier::OBSERVATION_SOCKET.into(),
    }))
}

/// Bind the selected interfaces' static addresses plus loopback, as OPNsense
/// does; no selection, or a selected interface without a static address,
/// means the wildcard, which the firewall then guards.
fn ntp_listen(doc: &Document, ids: &[InterfaceId]) -> Result<Vec<SocketAddr>, ConvertError> {
    let mut addrs = vec![
        IpAddr::from([127, 0, 0, 1]),
        IpAddr::from(Ipv6Addr::LOCALHOST),
    ];
    for id in ids {
        let i = iface(doc, id, "ntp.listen_interfaces")?;
        let before = addrs.len();
        addrs.extend(static_v4(i).map(|a| IpAddr::V4(a.addr())));
        addrs.extend(static_v6(i).map(|a| IpAddr::V6(a.addr())));
        if addrs.len() == before {
            return Ok(vec![ntp_applier::wildcard()]);
        }
    }
    if ids.is_empty() {
        return Ok(vec![ntp_applier::wildcard()]);
    }
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in addrs {
        let s = SocketAddr::new(a, ntp_applier::NTP_PORT);
        if !out.contains(&s) {
            out.push(s);
        }
    }
    Ok(out)
}

/// Queueing: CAKE shapers from interface settings (fq_codel elsewhere).
pub fn qdisc(doc: &Document) -> QdiscModel {
    QdiscModel {
        default: Default::default(),
        shapers: doc
            .interfaces
            .iter()
            .filter(|(_, i)| i.enabled)
            .filter_map(|(_, i)| match i.qdisc {
                Qdisc::Cake { bandwidth_kbit } => Some(Shaper {
                    iface: i.device.clone(),
                    bandwidth_kbit: bandwidth_kbit.map(u64::from),
                    nat: i.role == InterfaceRole::Wan,
                    diffserv: Diffserv::Besteffort,
                    overhead: None,
                }),
                Qdisc::FqCodel | Qdisc::Kernel => None,
            })
            .collect(),
    }
}

impl SliceModels {
    /// Every slice applier's input from one document.
    pub fn from_document(doc: &Document, secrets: &SecretsDir) -> Result<Self, ConvertError> {
        Ok(SliceModels {
            sysctl: SysctlModel::default(),
            qdisc: qdisc(doc),
            kea: kea(doc)?,
            unbound: unbound(doc)?,
            wireguard: wireguard(doc, secrets)?,
            ntp: ntp(doc)?,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The shared fixture: the schema's factory document plus what the
    /// slice needs exercised (reservation, host overrides, a forwarded
    /// domain, a WireGuard server with two peers, CAKE on WAN).
    pub(crate) fn document() -> Document {
        serde_json::from_str(include_str!("../../tests/fixtures/slice.json"))
            .expect("fixture parses")
    }

    pub(crate) fn slice_models() -> SliceModels {
        SliceModels::from_document(&document(), &SecretsDir::default()).expect("converts")
    }

    #[test]
    fn fixture_validates() {
        let v = document().validate();
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn factory_document_converts() {
        let m = SliceModels::from_document(&Document::factory(), &SecretsDir::default()).unwrap();
        let k = m.kea.unwrap();
        assert_eq!(k.interfaces[0].as_str(), "eth1");
        // Automatic options: LAN address as router and resolver.
        assert_eq!(
            k.subnets[0].subnet.options.routers,
            ["192.168.1.1".parse::<std::net::Ipv4Addr>().unwrap()]
        );
        assert_eq!(k.subnets[0].subnet.options.dns_servers.len(), 1);
        assert_eq!(k.subnets[0].id, 0x5e45_0003);
        assert!(m.unbound.is_some());
        assert!(m.wireguard.interfaces.is_empty());
    }

    #[test]
    fn secrets_go_to_files_not_configs() {
        let files = secret_files(&document(), &SecretsDir::default());
        let paths: Vec<_> = files.iter().map(|(p, _)| p.display().to_string()).collect();
        assert_eq!(paths.len(), 2, "{paths:?}");
        assert!(paths[0].ends_with("wireguard/wg0.key"));
        assert!(paths[1].ends_with(".psk"));
        let wg = slice_models().wireguard;
        assert_eq!(wg.interfaces[0].private_key_file, PathBuf::from(&paths[0]));
    }

    #[test]
    fn kea_subnet_ids_are_stable_and_nonzero() {
        assert_eq!(kea_subnet_id(&Uuid::from_u128(0)), 1);
        let u = Uuid::from_u128(0x0123_4567_89ab_cdef_0011_2233_4455_6677);
        assert_eq!(kea_subnet_id(&u), kea_subnet_id(&u));
        assert!(kea_subnet_id(&u) < 0x8000_0000);
    }
}
