//! Interface addressing through systemd-networkd (OPNsense counterpart:
//! `interfaces.inc` `interface_configure`): one `.network` per assigned
//! interface (static addresses, DHCPv4/DHCPv6 clients, prefix delegation to
//! tracking interfaces), one `.netdev` per VLAN.
//!
//! This is the slice's stand-in for `sensr-net`'s netlink reconciler (PLAN
//! §2.2): networkd already owns links on the NixOS image, so rendering its
//! files gives WAN DHCP and LAN static addressing today, and the same model
//! can later drive netlink directly.

use std::collections::BTreeMap;

use serde::Serialize;

use std::net::IpAddr;

use sensr_rules::routing::{PolicyRouting, ROUTE_MASK, TargetKind};
use sensr_schema::Document;
use sensr_schema::fields::InterfaceId;
use sensr_schema::models::dhcpv6::{RaMode, RouterPreference};
use sensr_schema::models::interfaces::{
    DhcpClientId, DhcpOptionValue, DhcpSendOption, InterfaceRole, Ipv4Config, Ipv6Config,
    VlanProtocol,
};

use crate::cmd::Cmd;
use crate::templates::{Module, Rendered, TemplateError, Templates};

/// The `interfaces` template module.
pub const MODULE: Module = Module {
    name: "interfaces",
    dir: "run/systemd/network",
    templates: &[
        (
            "interfaces.network",
            include_str!("../../templates/interfaces/interfaces.network"),
        ),
        (
            "interfaces.netdev",
            include_str!("../../templates/interfaces/interfaces.netdev"),
        ),
    ],
    targets: include_str!("../../templates/interfaces/TARGETS"),
};

/// DHCPv4 client settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dhcp4 {
    /// install the offered default route (`yes`/`no`)
    pub use_gateway: &'static str,
    /// hostname to send
    pub hostname: Option<String>,
    /// servers whose offers are ignored
    pub deny: Vec<String>,
    /// networkd `ClientIdentifier=` (`mac`/`duid`)
    pub client_id: &'static str,
    /// option 60
    pub vendor_class: Option<String>,
    /// option 77, space-separated
    pub user_class: Option<String>,
    /// networkd `SendOption=` values (`code:type:value`)
    pub send_options: Vec<String>,
    /// option codes for `RequestOptions=`, space-separated
    pub request_options: Option<String>,
    /// skb priority of the client's raw socket (VLAN priority via the
    /// VLAN's egress map)
    pub socket_priority: Option<u32>,
    /// apply the offered MTU (`yes`/`no`)
    pub use_mtu: &'static str,
}

/// DHCPv6 client settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dhcp6 {
    /// prefix length to hint (`None`: no hint)
    pub pd_hint: Option<u8>,
    /// ask for a delegated prefix (`yes`/`no`)
    pub use_pd: &'static str,
    /// only take a prefix, no address
    pub prefix_only: bool,
    /// `RapidCommit=` (`yes`/`no`)
    pub rapid_commit: &'static str,
    /// `DUIDType=`
    pub duid_type: String,
    /// `DUIDRawData=` (bytes after the type)
    pub duid_raw: Option<String>,
    /// `SendRelease=` (`yes`/`no`)
    pub send_release: &'static str,
}

/// Prefix delegation to a downstream interface (or the uplink itself).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Track {
    /// device that received the delegation, `:self` for the uplink
    pub uplink: String,
    /// subnet id within the delegated prefix (hex, as networkd wants it)
    pub subnet_id: String,
    /// put the prefix into router advertisements
    pub announce: &'static str,
}

/// Router advertisements sent on a link (`[IPv6SendRA]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SendRa {
    /// M flag (`yes`/`no`)
    pub managed: &'static str,
    /// O flag (`yes`/`no`)
    pub other: &'static str,
    /// `RouterLifetimeSec=`; `None` keeps networkd's 1800 s (3 × the 600 s
    /// maximum interval, as radvd)
    pub router_lifetime: Option<u32>,
    /// `RouterPreference=`; `None` keeps medium
    pub preference: Option<&'static str>,
    /// `HopLimit=`; `None` keeps 64
    pub hop_limit: Option<u8>,
    /// `EmitDNS=` (`yes`/`no`)
    pub emit_dns: &'static str,
    /// RDNSS servers; `_link_local` is the router's own link-local address
    pub dns: Vec<String>,
    /// `EmitDomains=` (`yes`/`no`)
    pub emit_domains: &'static str,
    /// DNSSL domains
    pub domains: Vec<String>,
    /// static prefixes (`[IPv6Prefix]`)
    pub prefixes: Vec<RaPrefix>,
    /// more-specific routes (`[IPv6RoutePrefix]`)
    pub routes: Vec<String>,
    /// NAT64 prefix (`[IPv6PREF64Prefix]`)
    pub pref64: Option<String>,
}

/// A static prefix in router advertisements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RaPrefix {
    /// prefix
    pub prefix: String,
    /// L flag (`yes`/`no`)
    pub on_link: &'static str,
    /// A flag (`yes`/`no`)
    pub autonomous: &'static str,
}

/// A default route in a policy table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyRoute {
    /// next hop, or `_dhcp4` / `_ipv6ra` for a learned one
    pub gateway: String,
    /// routing table
    pub table: u32,
}

/// `ip rule fwmark <mark>/<mask> lookup <table>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyRule {
    /// `0x400/0xff00`
    pub mark: String,
    /// routing table
    pub table: u32,
    /// rule priority
    pub priority: u32,
}

/// One `.network` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Link {
    /// device name
    pub name: String,
    /// MTU override
    pub mtu: Option<u16>,
    /// spoofed MAC
    pub mac: Option<String>,
    /// `routable` for WANs, `no` otherwise (boot does not wait for LANs)
    pub required_for_online: &'static str,
    /// networkd `DHCP=`
    pub dhcp: &'static str,
    /// networkd `IPv6AcceptRA=`
    pub accept_ra: &'static str,
    /// networkd `LinkLocalAddressing=`
    pub link_local: &'static str,
    /// static addresses with prefix length
    pub addresses: Vec<String>,
    /// static gateways
    pub gateways: Vec<String>,
    /// VLAN devices on top of this one
    pub vlans: Vec<String>,
    /// DHCPv4 client
    pub dhcp4: Option<Dhcp4>,
    /// DHCPv6 client
    pub dhcp6: Option<Dhcp6>,
    /// tracked prefix
    pub track: Option<Track>,
    /// router advertisements sent on this link
    pub send_ra: Option<SendRa>,
    /// default routes of policy tables that leave through this link
    pub policy_routes: Vec<PolicyRoute>,
    /// policy rules installed with this link
    pub policy_rules: Vec<PolicyRule>,
}

/// One VLAN `.netdev` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Vlan {
    /// VLAN device name
    pub name: String,
    /// tag
    pub id: u16,
    /// `802.1ad` for service tags, `None` for the default 802.1Q
    pub protocol: Option<&'static str>,
    /// `EgressQOSMaps=` pairs (`skb priority-PCP`)
    pub egress_qos: Vec<String>,
}

/// Every link sensr configures.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct InterfacesModel {
    /// `.network` files
    pub links: Vec<Link>,
    /// `.netdev` files
    pub vlans: Vec<Vlan>,
}

impl InterfacesModel {
    /// The model of a document's enabled interfaces.
    pub fn from_document(doc: &Document) -> InterfacesModel {
        let mut links: Vec<Link> = Vec::new();
        let mut vlans = Vec::new();
        let mut children: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (_, i) in doc.interfaces.iter().filter(|(_, i)| i.enabled) {
            if let Some(v) = &i.vlan {
                children
                    .entry(v.parent.as_str().to_owned())
                    .or_default()
                    .push(i.device.as_str().to_owned());
                let mut egress_qos = Vec::new();
                if let Ipv4Config::Dhcp {
                    vlan_priority: Some(pcp),
                    ..
                } = &i.ipv4
                {
                    egress_qos.push(format!("{DHCP4_SKB_PRIORITY}-{pcp}"));
                }
                vlans.push(Vlan {
                    name: i.device.as_str().to_owned(),
                    id: v.tag,
                    protocol: match v.protocol {
                        VlanProtocol::Dot1Q => None,
                        _ => Some("802.1ad"),
                    },
                    egress_qos,
                });
            }
        }
        // WireGuard devices get their own files from the wireguard applier
        let wg: Vec<String> = if doc.wireguard.enabled {
            doc.wireguard
                .servers
                .values()
                .filter(|s| s.enabled)
                .map(|s| format!("wg{}", s.instance))
                .collect()
        } else {
            Vec::new()
        };
        for (id, i) in doc
            .interfaces
            .iter()
            .filter(|(_, i)| i.enabled && !wg.iter().any(|w| w == i.device.as_str()))
        {
            let mut addresses = Vec::new();
            let mut gateways = Vec::new();
            let mut dhcp4 = None;
            let mut dhcp6 = None;
            let mut track = None;
            match &i.ipv4 {
                Ipv4Config::None => {}
                cfg @ Ipv4Config::Dhcp { .. } => dhcp4 = Some(Dhcp4::new(cfg, i.vlan.is_some())),
                Ipv4Config::Static { address, gateway } => {
                    addresses.push(address.to_string());
                    gateways.extend(gateway.iter().map(ToString::to_string));
                }
            }
            let mut slaac = false;
            let mut static_v6 = None;
            match &i.ipv6 {
                Ipv6Config::None => {}
                cfg @ Ipv6Config::Dhcp6 { prefix_id, .. } => {
                    dhcp6 = Dhcp6::new(cfg);
                    // the uplink's own /64 out of its delegation
                    track = prefix_id.map(|id| Track {
                        uplink: ":self".into(),
                        subnet_id: format!("0x{id:x}"),
                        announce: "no",
                    });
                }
                Ipv6Config::Slaac => slaac = true,
                Ipv6Config::Static { address, gateway } => {
                    static_v6 = Some(address.trunc());
                    addresses.push(address.to_string());
                    gateways.extend(gateway.iter().map(ToString::to_string));
                }
                Ipv6Config::Track {
                    interface,
                    prefix_id,
                } => {
                    if let Some(up) = doc.interfaces.get(interface) {
                        track = Some(Track {
                            uplink: up.device.as_str().to_owned(),
                            subnet_id: format!("0x{prefix_id:x}"),
                            announce: "yes",
                        });
                    }
                }
            }
            let send_ra = send_ra(doc, id, &i.ipv6, static_v6, track.as_mut());
            let dhcp = match (dhcp4.is_some(), dhcp6.is_some()) {
                (true, true) => "yes",
                (true, false) => "ipv4",
                (false, true) => "ipv6",
                (false, false) => "no",
            };
            links.push(Link {
                name: i.device.as_str().to_owned(),
                mtu: i.mtu,
                mac: i.spoof_mac.map(|m| m.to_string()),
                required_for_online: if i.role == InterfaceRole::Wan {
                    "routable"
                } else {
                    "no"
                },
                dhcp,
                accept_ra: if dhcp6.is_some() || slaac {
                    "yes"
                } else {
                    "no"
                },
                link_local: "ipv6",
                addresses,
                gateways,
                vlans: children.remove(i.device.as_str()).unwrap_or_default(),
                dhcp4,
                dhcp6,
                track,
                send_ra,
                policy_routes: Vec::new(),
                policy_rules: Vec::new(),
            });
        }
        // VLAN parents that are not assigned interfaces still carry the tags
        for (parent, vl) in children {
            links.push(Link {
                name: parent,
                mtu: None,
                mac: None,
                required_for_online: "no",
                dhcp: "no",
                accept_ra: "no",
                link_local: "no",
                addresses: Vec::new(),
                gateways: Vec::new(),
                vlans: vl,
                dhcp4: None,
                dhcp6: None,
                track: None,
                send_ra: None,
                policy_routes: Vec::new(),
                policy_rules: Vec::new(),
            });
        }
        InterfacesModel { links, vlans }
    }

    /// Adds the routing tables and rules policy-routed rules need
    /// (`sensr_rules::routing`): per gateway a table with its default route
    /// and an `fwmark` rule; per gateway group the same through its tier-1
    /// member (failover between tiers needs gateway monitoring).
    pub fn with_routing(mut self, doc: &Document, routing: &PolicyRouting) -> InterfacesModel {
        let next_hop = |iface: &str, addr: Option<IpAddr>, v6: bool| -> Option<(String, String)> {
            let i = doc
                .interfaces
                .iter()
                .find(|(id, _)| id.as_str() == iface)?
                .1;
            let hop = match addr {
                Some(a) => a.to_string(),
                None if !v6 && matches!(i.ipv4, Ipv4Config::Dhcp { .. }) => "_dhcp4".into(),
                None if v6 => "_ipv6ra".into(),
                None => return None,
            };
            Some((i.device.as_str().to_owned(), hop))
        };
        let gateway = |name: &str| -> Option<(String, String)> {
            let g = doc
                .gateways
                .gateways
                .values()
                .find(|g| g.name.as_str() == name && g.enabled)?;
            next_hop(
                g.interface.as_str(),
                g.address,
                g.family == sensr_schema::fields::IpFamily::Inet6,
            )
        };
        for (idx, (name, t)) in routing.targets.iter().enumerate() {
            let via = match &t.kind {
                TargetKind::Gateway { .. } => gateway(name),
                TargetKind::Group { members } => members.iter().find_map(|(_, m)| gateway(m)),
            };
            let Some((dev, hop)) = via else { continue };
            let Some(link) = self.links.iter_mut().find(|l| l.name == dev) else {
                continue;
            };
            link.policy_routes.push(PolicyRoute {
                gateway: hop,
                table: t.table,
            });
            link.policy_rules.push(PolicyRule {
                mark: format!("0x{:x}/0x{:x}", t.mark, ROUTE_MASK),
                table: t.table,
                priority: 1000 + idx as u32,
            });
        }
        self
    }

    /// Render the networkd files.
    pub fn render(&self, templates: &Templates) -> Result<Vec<Rendered>, TemplateError> {
        templates.render("interfaces", &Ctx { networkd: self })
    }

    /// Commands after the files are in place: delete VLANs that went away or
    /// changed tag, reload networkd, reconfigure links whose file changed.
    pub fn commands(&self, applied: &InterfacesModel) -> Vec<Cmd> {
        let old: BTreeMap<&str, &Link> =
            applied.links.iter().map(|l| (l.name.as_str(), l)).collect();
        let old_vlans: BTreeMap<&str, &Vlan> =
            applied.vlans.iter().map(|v| (v.name.as_str(), v)).collect();
        let new_vlans: BTreeMap<&str, &Vlan> =
            self.vlans.iter().map(|v| (v.name.as_str(), v)).collect();
        let mut cmds: Vec<Cmd> = old_vlans
            .iter()
            .filter(|(n, v)| new_vlans.get(*n) != Some(*v))
            .map(|(n, _)| Cmd::new("ip").args(["link", "delete", n]))
            .collect();
        let changed: Vec<&str> = self
            .links
            .iter()
            .filter(|l| old.get(l.name.as_str()) != Some(l))
            .map(|l| l.name.as_str())
            .collect();
        let removed = old.keys().any(|n| !self.links.iter().any(|l| l.name == *n));
        if !changed.is_empty() || removed || !cmds.is_empty() || new_vlans != old_vlans {
            cmds.push(Cmd::new("networkctl").arg("reload"));
        }
        cmds.extend(
            changed
                .iter()
                .filter(|n| old.contains_key(*n))
                .map(|n| Cmd::new("networkctl").args(["reconfigure", n])),
        );
        cmds
    }
}

/// The skb priority sensr gives the DHCPv4 client's socket when a VLAN
/// priority is set: outside 0-7, which locally generated IPv4 traffic gets
/// from its TOS bits, so only the DHCP frames pick up the mapped PCP.
pub const DHCP4_SKB_PRIORITY: u32 = 8;

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

/// A networkd string value: `SendOption=` C-unescapes it.
fn escape(s: &str) -> String {
    s.replace('\\', "\\\\")
}

fn send_option(o: &DhcpSendOption) -> String {
    let (ty, value) = match &o.value {
        DhcpOptionValue::String(t) => ("string", escape(t)),
        DhcpOptionValue::Hex(h) => (
            "string",
            h.as_bytes().iter().map(|b| format!("\\x{b:02x}")).collect(),
        ),
        DhcpOptionValue::Ipv4(a) => ("ipv4address", a.to_string()),
        DhcpOptionValue::Uint8(n) => ("uint8", n.to_string()),
        DhcpOptionValue::Uint16(n) => ("uint16", n.to_string()),
        DhcpOptionValue::Uint32(n) => ("uint32", n.to_string()),
    };
    format!("{}:{ty}:{value}", o.code)
}

impl Dhcp4 {
    fn new(cfg: &Ipv4Config, on_vlan: bool) -> Dhcp4 {
        let Ipv4Config::Dhcp {
            hostname,
            reject_from,
            use_gateway,
            client_id,
            vendor_class,
            user_class,
            send_options,
            request_options,
            vlan_priority,
            use_mtu,
        } = cfg
        else {
            unreachable!("called for DHCP configurations only")
        };
        let join = |v: Vec<String>| (!v.is_empty()).then(|| v.join(" "));
        Dhcp4 {
            use_gateway: yes_no(*use_gateway),
            hostname: hostname.as_ref().map(ToString::to_string),
            deny: reject_from.iter().map(ToString::to_string).collect(),
            client_id: match client_id {
                DhcpClientId::Mac => "mac",
                DhcpClientId::Duid => "duid",
            },
            vendor_class: vendor_class.clone(),
            user_class: join(user_class.clone()),
            send_options: send_options.iter().map(send_option).collect(),
            request_options: join(request_options.iter().map(ToString::to_string).collect()),
            socket_priority: vlan_priority
                .filter(|_| on_vlan)
                .map(|_| DHCP4_SKB_PRIORITY),
            use_mtu: yes_no(*use_mtu),
        }
    }
}

impl Dhcp6 {
    fn new(cfg: &Ipv6Config) -> Option<Dhcp6> {
        let Ipv6Config::Dhcp6 {
            prefix_delegation_len,
            send_prefix_hint,
            prefix_only,
            rapid_commit,
            duid,
            send_release,
            ..
        } = cfg
        else {
            return None;
        };
        // A DUID-LL follows the (spoofed) MAC, so the ISP sees the same
        // client after a reinstall; networkd's default derives it from
        // /etc/machine-id instead.
        let (duid_type, duid_raw) = match duid.as_ref().map(|d| d.as_bytes()) {
            Some([hi, lo, rest @ ..]) if !rest.is_empty() => {
                let ty = match u16::from_be_bytes([*hi, *lo]) {
                    1 => "link-layer-time".to_owned(),
                    2 => "vendor".to_owned(),
                    3 => "link-layer".to_owned(),
                    4 => "uuid".to_owned(),
                    n => n.to_string(),
                };
                let raw = rest
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":");
                (ty, Some(raw))
            }
            _ => ("link-layer".to_owned(), None),
        };
        Some(Dhcp6 {
            pd_hint: prefix_delegation_len.filter(|_| *send_prefix_hint),
            use_pd: yes_no(prefix_delegation_len.is_some()),
            prefix_only: *prefix_only,
            rapid_commit: yes_no(*rapid_commit),
            duid_type,
            duid_raw,
            send_release: yes_no(*send_release),
        })
    }
}

/// Whether the router advertisements on `id` name the router's own
/// link-local address as the resolver, so Unbound must answer there.
pub fn advertises_link_local_dns(doc: &Document, id: &InterfaceId) -> bool {
    let Some(i) = doc.interfaces.get(id).filter(|i| i.enabled) else {
        return false;
    };
    let static_net = match &i.ipv6 {
        Ipv6Config::Static { address, .. } => Some(address.trunc()),
        _ => None,
    };
    send_ra(doc, id, &i.ipv6, static_net, None)
        .is_some_and(|ra| ra.dns.iter().any(|d| d == "_link_local"))
}

/// Router advertisements for one link: the interface's
/// `router_advertisements` entry when it has one, else OPNsense's automatic
/// ones for a tracking interface (`radvd.inc`: RDNSS is the router itself
/// when it resolves, DNSSL the system domain).
fn send_ra(
    doc: &Document,
    id: &InterfaceId,
    ipv6: &Ipv6Config,
    static_net: Option<ipnet::Ipv6Net>,
    track: Option<&mut Track>,
) -> Option<SendRa> {
    let tracking = matches!(ipv6, Ipv6Config::Track { .. });
    let entry = doc
        .router_advertisements
        .interfaces
        .values()
        .find(|r| &r.interface == id);
    if !tracking && static_net.is_none() {
        return None;
    }
    if entry.is_none() && !tracking {
        return None;
    }
    if entry.is_some_and(|e| !e.enabled) {
        if let Some(t) = track {
            t.announce = "no";
        }
        return None;
    }
    // The resolver answers on every address when it serves this link, so
    // the link-local one is always reachable, whatever the delegation is.
    let local_dns = doc.dns.enabled
        && (doc.dns.listen_interfaces.is_empty() || doc.dns.listen_interfaces.contains(id));
    let default_dns = || -> Vec<String> {
        if local_dns {
            vec!["_link_local".into()]
        } else {
            // radvd carries at most three RDNSS addresses
            doc.system
                .dns_servers
                .iter()
                .filter(|a| a.is_ipv6())
                .take(3)
                .map(ToString::to_string)
                .collect()
        }
    };
    let domain = vec![doc.system.domain.to_string()];
    let Some(e) = entry else {
        // Automatic: M and O only when a DHCPv6 server answers on the link
        // (OPNsense sets both because it always starts one for tracking
        // interfaces; sensr does not serve DHCPv6 by itself).
        let dhcp6 = doc.dhcpv6.enabled && doc.dhcpv6.interfaces.contains(id);
        let dns = default_dns();
        return Some(SendRa {
            managed: yes_no(dhcp6),
            other: yes_no(dhcp6),
            router_lifetime: None,
            preference: None,
            hop_limit: None,
            emit_dns: yes_no(!dns.is_empty()),
            dns,
            emit_domains: "yes",
            domains: domain,
            prefixes: Vec::new(),
            routes: Vec::new(),
            pref64: None,
        });
    };
    let (managed, other, on_link, autonomous) = match e.mode {
        RaMode::RouterOnly => (false, false, false, false),
        RaMode::Unmanaged => (false, false, true, true),
        RaMode::Managed => (true, true, true, false),
        RaMode::Assisted => (true, true, true, true),
        RaMode::Stateless => (false, true, true, true),
    };
    if let Some(t) = track {
        // networkd cannot clear the A flag of a delegated prefix, so
        // `managed` still lets hosts autoconfigure (docs/models.md).
        t.announce = yes_no(on_link);
    }
    let (dns, domains) = if e.dns {
        (
            if e.rdnss.is_empty() {
                default_dns()
            } else {
                e.rdnss.iter().map(ToString::to_string).collect()
            },
            if e.dnssl.is_empty() {
                domain
            } else {
                e.dnssl.iter().map(ToString::to_string).collect()
            },
        )
    } else {
        (Vec::new(), Vec::new())
    };
    Some(SendRa {
        managed: yes_no(managed),
        other: yes_no(other),
        router_lifetime: Some(e.default_lifetime.unwrap_or(3 * e.max_interval)),
        preference: match e.preference {
            RouterPreference::Medium => None,
            RouterPreference::Low => Some("low"),
            RouterPreference::High => Some("high"),
        },
        hop_limit: (e.hop_limit != 64).then_some(e.hop_limit),
        emit_dns: yes_no(!dns.is_empty()),
        dns,
        emit_domains: yes_no(!domains.is_empty()),
        domains,
        prefixes: static_net
            .map(|n| RaPrefix {
                prefix: n.to_string(),
                on_link: yes_no(on_link),
                autonomous: yes_no(autonomous),
            })
            .into_iter()
            .collect(),
        routes: e.routes.iter().map(ToString::to_string).collect(),
        pref64: e.nat64_prefix.map(|p| p.to_string()),
    })
}

#[derive(Serialize)]
struct Ctx<'a> {
    networkd: &'a InterfacesModel,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The template context of the home-router corpus document.
    pub(crate) fn context() -> serde_json::Value {
        serde_json::to_value(Ctx {
            networkd: &InterfacesModel::from_document(&home_router()),
        })
        .unwrap()
    }

    fn home_router() -> Document {
        serde_json::from_str(include_str!(
            "../../../sensr-import-opnsense/tests/golden/home-router.sensr.json"
        ))
        .unwrap()
    }

    #[test]
    fn home_router_networkd_files() {
        let m = InterfacesModel::from_document(&home_router());
        let t = Templates::builtin().unwrap();
        let files = m.render(&t).unwrap();
        for f in &files {
            let name = f.dest.file_name().unwrap().to_string_lossy().into_owned();
            insta::assert_snapshot!(format!("interfaces__{name}"), f.contents);
        }
        assert!(
            !files
                .iter()
                .any(|f| f.dest.to_string_lossy().contains("wg0"))
        );
        assert!(
            files
                .iter()
                .any(|f| f.dest.to_string_lossy().ends_with("vlan01.netdev"))
        );
    }

    #[test]
    fn multiwan_policy_tables() {
        let doc: Document = serde_json::from_str(include_str!(
            "../../../sensr-import-opnsense/tests/golden/multiwan.sensr.json"
        ))
        .unwrap();
        let compiled = sensr_rules::document::compile(&doc, &Default::default());
        let m = InterfacesModel::from_document(&doc).with_routing(&doc, &compiled.routing);
        let t = Templates::builtin().unwrap();
        for f in m.render(&t).unwrap() {
            let name = f.dest.file_name().unwrap().to_string_lossy().into_owned();
            if name.contains("igc0") || name.contains("igc2") {
                insta::assert_snapshot!(format!("multiwan__{name}"), f.contents);
            }
        }
        let wan2 = m.links.iter().find(|l| l.name == "igc2").unwrap();
        assert!(
            wan2.policy_routes
                .iter()
                .any(|r| r.gateway == "198.51.100.1")
        );
        let wan1 = m.links.iter().find(|l| l.name == "igc0").unwrap();
        assert!(wan1.policy_routes.iter().any(|r| r.gateway == "_dhcp4"));
    }

    fn fibre() -> Document {
        serde_json::from_str(include_str!(
            "../../../sensr-import-opnsense/tests/golden/fibre-passthrough.sensr.json"
        ))
        .unwrap()
    }

    fn file(m: &InterfacesModel, dev: &str) -> String {
        let t = Templates::builtin().unwrap();
        m.render(&t)
            .unwrap()
            .into_iter()
            .find(|f| {
                f.dest
                    .to_string_lossy()
                    .ends_with(&format!("-{dev}.network"))
            })
            .unwrap()
            .contents
    }

    /// The owner's shape: spoofed WAN MAC, DHCPv4 with options, DHCPv6-PD
    /// /60 with a fixed DUID, three LANs tracking it.
    #[test]
    fn fibre_passthrough_networkd_files() {
        let m = InterfacesModel::from_document(&fibre());
        let t = Templates::builtin().unwrap();
        for f in m.render(&t).unwrap() {
            let name = f.dest.file_name().unwrap().to_string_lossy().into_owned();
            insta::assert_snapshot!(format!("fibre__{name}"), f.contents);
        }
        let wan = file(&m, "igc0");
        for line in [
            "MACAddress=02:00:5e:10:20:30",
            "ClientIdentifier=mac",
            "VendorClassIdentifier=sensr-test",
            "SendOption=125:string:\\x00\\x00\\x0d\\xe9\\x04\\x01\\x02\\x03\\x04",
            "RequestOptions=1 3 6 121",
            "DenyList=192.168.1.254",
            "UseDelegatedPrefix=yes",
            "PrefixDelegationHint=::/60",
            "RapidCommit=yes",
            "SendRelease=no",
            "DUIDType=link-layer",
            "DUIDRawData=00:01:02:00:5e:10:20:30",
        ] {
            assert!(wan.lines().any(|l| l == line), "{line} missing:\n{wan}");
        }
        assert!(!wan.contains("IPv6SendRA"));
        for (dev, id) in [("igc1", "0x0"), ("igc2", "0x1"), ("igc3", "0xa")] {
            let lan = file(&m, dev);
            for line in [
                "DHCPPrefixDelegation=yes",
                "IPv6SendRA=yes",
                "UplinkInterface=igc0",
                &format!("SubnetId={id}"),
                "Announce=yes",
                "EmitDNS=yes",
                "DNS=_link_local",
                "EmitDomains=yes",
                "Domains=home.example",
                "Managed=no",
                "OtherInformation=no",
            ] {
                assert!(
                    lan.lines().any(|l| l == line),
                    "{dev}: {line} missing:\n{lan}"
                );
            }
        }
    }

    #[test]
    fn hint_only_when_asked_and_no_delegation_without_a_size() {
        let mut doc = fibre();
        let wan = doc
            .interfaces
            .0
            .get_mut(&"wan".parse::<InterfaceId>().unwrap())
            .unwrap();
        if let Ipv6Config::Dhcp6 {
            send_prefix_hint, ..
        } = &mut wan.ipv6
        {
            *send_prefix_hint = false;
        }
        let f = file(&InterfacesModel::from_document(&doc), "igc0");
        assert!(!f.contains("PrefixDelegationHint"), "{f}");
        assert!(f.contains("UseDelegatedPrefix=yes"));
        doc.interfaces
            .0
            .get_mut(&"wan".parse::<InterfaceId>().unwrap())
            .unwrap()
            .ipv6 = Ipv6Config::dhcp6(None);
        let f = file(&InterfacesModel::from_document(&doc), "igc0");
        assert!(f.contains("UseDelegatedPrefix=no"), "{f}");
        // no DUID configured: DUID-LL from the (spoofed) MAC, stable across reinstalls
        assert!(f.contains("DUIDType=link-layer") && !f.contains("DUIDRawData"));
    }

    #[test]
    fn wan_prefix_id_addresses_the_uplink_from_its_delegation() {
        let mut doc = fibre();
        if let Ipv6Config::Dhcp6 { prefix_id, .. } = &mut doc
            .interfaces
            .0
            .get_mut(&"wan".parse::<InterfaceId>().unwrap())
            .unwrap()
            .ipv6
        {
            *prefix_id = Some(0xf);
        }
        let f = file(&InterfacesModel::from_document(&doc), "igc0");
        for line in [
            "DHCPPrefixDelegation=yes",
            "UplinkInterface=:self",
            "SubnetId=0xf",
            "Announce=no",
        ] {
            assert!(f.lines().any(|l| l == line), "{line}:\n{f}");
        }
        assert!(!f.contains("IPv6SendRA"));
    }

    #[test]
    fn router_advertisement_entries_shape_the_ra() {
        use sensr_schema::models::dhcpv6::{RaInterface, RaMode, RouterPreference};
        let mut doc = fibre();
        let mut ra = RaInterface::new("opt1".parse().unwrap());
        ra.mode = RaMode::Assisted;
        ra.rdnss = vec!["2001:db8::53".parse().unwrap()];
        ra.dnssl = vec!["kids.home.example".parse().unwrap()];
        ra.preference = RouterPreference::High;
        ra.max_interval = 300;
        ra.min_interval = 100;
        ra.routes = vec!["2001:db8:100::/48".parse().unwrap()];
        ra.nat64_prefix = Some("64:ff9b::/96".parse().unwrap());
        doc.router_advertisements
            .interfaces
            .insert(sensr_schema::array::Uuid::from_u128(1), ra);
        let mut off = RaInterface::new("opt2".parse().unwrap());
        off.enabled = false;
        doc.router_advertisements
            .interfaces
            .insert(sensr_schema::array::Uuid::from_u128(2), off);
        let m = InterfacesModel::from_document(&doc);
        let kids = file(&m, "igc2");
        for line in [
            "Managed=yes",
            "OtherInformation=yes",
            "RouterLifetimeSec=900",
            "RouterPreference=high",
            "DNS=2001:db8::53",
            "Domains=kids.home.example",
            "Route=2001:db8:100::/48",
            "Prefix=64:ff9b::/96",
        ] {
            assert!(kids.lines().any(|l| l == line), "{line}:\n{kids}");
        }
        let lab = file(&m, "igc3");
        assert!(
            lab.contains("IPv6SendRA=no") && lab.contains("Announce=no"),
            "{lab}"
        );
        // without Unbound the system's IPv6 resolvers are advertised
        doc.dns.enabled = false;
        let lan = file(&InterfacesModel::from_document(&doc), "igc1");
        assert!(lan.lines().any(|l| l == "DNS=2001:db8:53::53"), "{lan}");
    }

    #[test]
    fn dhcp_vlan_priority_maps_the_client_socket_to_the_pcp() {
        let mut doc = home_router();
        let opt1 = doc
            .interfaces
            .0
            .get_mut(&"opt1".parse::<InterfaceId>().unwrap())
            .unwrap();
        assert!(opt1.vlan.is_some());
        opt1.ipv4 = Ipv4Config::dhcp();
        if let Ipv4Config::Dhcp { vlan_priority, .. } = &mut opt1.ipv4 {
            *vlan_priority = Some(5);
        }
        let m = InterfacesModel::from_document(&doc);
        let v = m.vlans.iter().find(|v| v.name == "vlan01").unwrap();
        assert_eq!(v.egress_qos, ["8-5"]);
        assert!(file(&m, "vlan01").contains("SocketPriority=8"));
    }

    #[test]
    fn link_local_rdnss_makes_unbound_bind_everything() {
        let mut doc = fibre();
        doc.dns.listen_interfaces = vec!["lan".parse().unwrap()];
        assert!(advertises_link_local_dns(&doc, &"lan".parse().unwrap()));
        let u = crate::appliers::convert::unbound(&doc).unwrap().unwrap();
        assert!(u.listen.is_empty(), "{:?}", u.listen);
    }

    #[test]
    fn unchanged_model_is_a_noop_and_changes_reconfigure() {
        let m = InterfacesModel::from_document(&home_router());
        assert!(m.commands(&m).is_empty());
        let first: Vec<String> = m
            .commands(&InterfacesModel::default())
            .iter()
            .map(|c| c.display())
            .collect();
        assert_eq!(first, ["networkctl 'reload'"]);
        let mut changed = m.clone();
        changed.links[1].addresses = vec!["192.168.2.1/24".into()];
        let lines: Vec<String> = changed.commands(&m).iter().map(|c| c.display()).collect();
        assert_eq!(
            lines,
            ["networkctl 'reload'", "networkctl 'reconfigure' 'igc1'"]
        );
    }
}
