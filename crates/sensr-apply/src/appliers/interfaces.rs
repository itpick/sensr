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
use sensr_schema::models::interfaces::{InterfaceRole, Ipv4Config, Ipv6Config, VlanProtocol};

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
}

/// DHCPv6 client settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dhcp6 {
    /// prefix length to ask for (`None`: no delegation hint)
    pub pd_len: Option<u8>,
    /// only take a prefix, no address
    pub prefix_only: bool,
}

/// Prefix delegation to a downstream interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Track {
    /// device that received the delegation
    pub uplink: String,
    /// subnet id within the delegated prefix (hex, as networkd wants it)
    pub subnet_id: String,
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
                vlans.push(Vlan {
                    name: i.device.as_str().to_owned(),
                    id: v.tag,
                    protocol: match v.protocol {
                        VlanProtocol::Dot1Q => None,
                        _ => Some("802.1ad"),
                    },
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
        for (_, i) in doc
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
                Ipv4Config::Dhcp {
                    hostname,
                    reject_from,
                    use_gateway,
                } => {
                    dhcp4 = Some(Dhcp4 {
                        use_gateway: if *use_gateway { "yes" } else { "no" },
                        hostname: hostname.as_ref().map(ToString::to_string),
                        deny: reject_from.iter().map(ToString::to_string).collect(),
                    })
                }
                Ipv4Config::Static { address, gateway } => {
                    addresses.push(address.to_string());
                    gateways.extend(gateway.iter().map(ToString::to_string));
                }
            }
            let mut slaac = false;
            match &i.ipv6 {
                Ipv6Config::None => {}
                Ipv6Config::Dhcp6 {
                    prefix_delegation_len,
                    prefix_only,
                    ..
                } => {
                    dhcp6 = Some(Dhcp6 {
                        pd_len: *prefix_delegation_len,
                        prefix_only: *prefix_only,
                    })
                }
                Ipv6Config::Slaac => slaac = true,
                Ipv6Config::Static { address, gateway } => {
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
                        });
                    }
                }
            }
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
