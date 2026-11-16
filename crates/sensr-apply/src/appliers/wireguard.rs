//! WireGuard as systemd-networkd `.netdev` + `.network` files, rendered by the
//! `wireguard` template module into `/run/systemd/network/` (networkd's
//! runtime directory, so nothing lands in the immutable `/etc`).
//!
//! Upstream renders `wg-quick`-style `wgN.conf` files and drives `wg`; sensr
//! uses networkd because it already owns the other links, routes and
//! addresses, and it reads keys from files (`PrivateKeyFile=`,
//! `PresharedKeyFile=`) so no secret is ever part of a rendered file, a plan,
//! a diff or a log. A `wg-quick` renderer could reuse the same model.
//!
//! networkd does not re-create a netdev whose `.netdev` changed, so changed or
//! removed tunnels are deleted first; a `.network`-only change is a
//! reconfigure.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::PathBuf;

use ipnet::IpNet;
use sensr_schema::fields::{DeviceName, Host, WgKey, WgName};
use serde::Serialize;

use crate::cmd::Cmd;
use crate::templates::{Module, Rendered, TemplateError, Templates};

/// Peer endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Host.
    pub host: Host,
    /// UDP port.
    pub port: u16,
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(a)) => write!(f, "[{a}]:{}", self.port),
            Host::Ip(a) => write!(f, "{a}:{}", self.port),
            Host::Name(n) => write!(f, "{n}:{}", self.port),
        }
    }
}

/// A peer, resolved for one tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgPeer {
    /// Friendly name (written as a comment).
    pub name: WgName,
    /// Peer public key.
    pub public_key: WgKey,
    /// File holding the preshared key.
    pub preshared_key_file: Option<PathBuf>,
    /// Where to reach it (`None` for roaming clients).
    pub endpoint: Option<Endpoint>,
    /// Addresses routed to/accepted from this peer.
    pub allowed_ips: Vec<IpNet>,
    /// Keepalive interval in seconds.
    pub keepalive: Option<u16>,
}

/// A tunnel interface (an OPNsense WireGuard "instance").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WgInterface {
    /// Link name (`wg0`).
    pub name: DeviceName,
    /// File holding the private key (mode 0640 root:systemd-network).
    pub private_key_file: PathBuf,
    /// UDP listen port (`None`: random, client-only).
    pub listen_port: Option<u16>,
    /// Tunnel addresses.
    pub addresses: Vec<IpNet>,
    /// MTU.
    pub mtu: Option<u16>,
    /// Install routes for peers' allowed IPs (OPNsense "disable routes" off).
    pub route_allowed_ips: bool,
    /// Peers.
    pub peers: Vec<WgPeer>,
}

/// All tunnels.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WireguardModel {
    /// Tunnel interfaces.
    pub interfaces: Vec<WgInterface>,
}

/// Model errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WgError {
    /// Two tunnels with one name.
    #[error("interface {0} defined twice")]
    DuplicateInterface(DeviceName),
    /// The same public key twice on one interface.
    #[error("{iface}: peer key {key} listed twice")]
    DuplicatePeer {
        /// Interface.
        iface: DeviceName,
        /// Key.
        key: String,
    },
    /// A relative key file path.
    #[error("{0}: key files must be absolute paths")]
    RelativeKeyFile(DeviceName),
}

#[derive(Serialize)]
struct PeerView<'a> {
    name: &'a WgName,
    public_key: String,
    preshared_key_file: Option<&'a PathBuf>,
    endpoint: Option<String>,
    allowed_ips: String,
    keepalive: Option<u16>,
}

#[derive(Serialize)]
struct IfaceView<'a> {
    name: &'a DeviceName,
    private_key_file: &'a PathBuf,
    listen_port: Option<u16>,
    addresses: &'a [IpNet],
    mtu: Option<u16>,
    route_table: &'static str,
    peers: Vec<PeerView<'a>>,
}

#[derive(Serialize)]
struct Ctx<'a> {
    wireguard: BTreeMap<&'static str, Vec<IfaceView<'a>>>,
}

impl WireguardModel {
    /// Check cross-object constraints.
    pub fn validate(&self) -> Result<(), WgError> {
        let mut names = BTreeSet::new();
        for i in &self.interfaces {
            if !names.insert(&i.name) {
                return Err(WgError::DuplicateInterface(i.name.clone()));
            }
            if !i.private_key_file.is_absolute() {
                return Err(WgError::RelativeKeyFile(i.name.clone()));
            }
            let mut keys = BTreeSet::new();
            for p in &i.peers {
                if p.preshared_key_file
                    .as_ref()
                    .is_some_and(|f| !f.is_absolute())
                {
                    return Err(WgError::RelativeKeyFile(i.name.clone()));
                }
                if !keys.insert(p.public_key.to_string()) {
                    return Err(WgError::DuplicatePeer {
                        iface: i.name.clone(),
                        key: p.public_key.to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    /// The template context.
    pub fn context(&self) -> Result<impl Serialize + '_, WgError> {
        self.validate()?;
        let views = self
            .interfaces
            .iter()
            .map(|i| IfaceView {
                name: &i.name,
                private_key_file: &i.private_key_file,
                listen_port: i.listen_port,
                addresses: &i.addresses,
                mtu: i.mtu,
                route_table: if i.route_allowed_ips { "main" } else { "off" },
                peers: i
                    .peers
                    .iter()
                    .map(|p| PeerView {
                        name: &p.name,
                        public_key: p.public_key.to_string(),
                        preshared_key_file: p.preshared_key_file.as_ref(),
                        endpoint: p.endpoint.as_ref().map(ToString::to_string),
                        allowed_ips: p
                            .allowed_ips
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(","),
                        keepalive: p.keepalive,
                    })
                    .collect(),
            })
            .collect();
        Ok(Ctx {
            wireguard: [("interfaces", views)].into(),
        })
    }

    /// Render the networkd files.
    pub fn render(&self, templates: &Templates) -> Result<Vec<Rendered>, RenderError> {
        let ctx = self.context()?;
        Ok(templates.render("wireguard", &ctx)?)
    }

    /// Link-level commands to go from `applied` to `self`, run after the new
    /// files are in place: delete tunnels that were removed or whose netdev
    /// definition changed, reload networkd, reconfigure tunnels whose
    /// addresses changed.
    pub fn commands(&self, applied: &WireguardModel) -> Vec<Cmd> {
        let old: BTreeMap<&DeviceName, &WgInterface> =
            applied.interfaces.iter().map(|i| (&i.name, i)).collect();
        let new: BTreeMap<&DeviceName, &WgInterface> =
            self.interfaces.iter().map(|i| (&i.name, i)).collect();
        let netdev_changed = |a: &WgInterface, b: &WgInterface| {
            a.private_key_file != b.private_key_file
                || a.listen_port != b.listen_port
                || a.mtu != b.mtu
                || a.route_allowed_ips != b.route_allowed_ips
                || a.peers != b.peers
        };
        let mut delete = Vec::new();
        let mut reconfigure = Vec::new();
        for (name, o) in &old {
            match new.get(name) {
                None => delete.push(*name),
                Some(n) if netdev_changed(o, n) => delete.push(*name),
                Some(n) if o.addresses != n.addresses => reconfigure.push(*name),
                Some(_) => {}
            }
        }
        let added = new.keys().any(|k| !old.contains_key(k));
        let mut cmds: Vec<Cmd> = delete
            .iter()
            .map(|n| Cmd::new("ip").args(["link", "delete", n.as_str()]))
            .collect();
        if added || !delete.is_empty() || !reconfigure.is_empty() {
            cmds.push(Cmd::new("networkctl").arg("reload"));
        }
        cmds.extend(
            reconfigure
                .iter()
                .map(|n| Cmd::new("networkctl").args(["reconfigure", n.as_str()])),
        );
        cmds
    }
}

/// Render errors.
#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    /// Invalid model.
    #[error(transparent)]
    Model(#[from] WgError),
    /// Template failure.
    #[error(transparent)]
    Template(#[from] TemplateError),
}

/// The `wireguard` template module.
pub const MODULE: Module = Module {
    name: "wireguard",
    dir: "run/systemd/network",
    templates: &[
        (
            "wireguard.netdev",
            include_str!("../../templates/wireguard/wireguard.netdev"),
        ),
        (
            "wireguard.network",
            include_str!("../../templates/wireguard/wireguard.network"),
        ),
    ],
    targets: include_str!("../../templates/wireguard/TARGETS"),
};

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::appliers::convert::tests::slice_models;
    use crate::templates::Staging;

    pub(crate) fn model() -> WireguardModel {
        slice_models().wireguard
    }

    fn templates() -> Templates {
        let mut t = Templates::empty();
        t.register(MODULE).unwrap();
        t
    }

    #[test]
    fn wireguard_networkd_golden() {
        let out = model().render(&templates()).unwrap();
        let s = Staging::new("/");
        let paths: Vec<_> = out.iter().map(|r| s.live_path(r)).collect();
        assert_eq!(
            paths,
            [
                PathBuf::from("/run/systemd/network/50-sensr-wg0.netdev"),
                PathBuf::from("/run/systemd/network/50-sensr-wg0.network")
            ]
        );
        for r in &out {
            assert!(!r.contents.contains("PrivateKey="), "no inline secrets");
            insta::assert_snapshot!(
                format!(
                    "wireguard__{}",
                    r.dest.file_name().unwrap().to_string_lossy()
                ),
                r.contents
            );
        }
    }

    #[test]
    fn commands_delete_changed_netdevs_reconfigure_address_changes() {
        let m = model();
        assert!(m.commands(&m).is_empty(), "idempotent");
        let names = |c: Vec<Cmd>| c.iter().map(Cmd::display).collect::<Vec<_>>();
        assert_eq!(
            names(m.commands(&WireguardModel::default())),
            ["networkctl 'reload'"]
        );
        let mut addr = m.clone();
        addr.interfaces[0].addresses.pop();
        assert_eq!(
            names(addr.commands(&m)),
            ["networkctl 'reload'", "networkctl 'reconfigure' 'wg0'"]
        );
        let mut peer = m.clone();
        peer.interfaces[0].peers.pop();
        assert_eq!(
            names(peer.commands(&m)),
            ["ip 'link' 'delete' 'wg0'", "networkctl 'reload'"]
        );
        assert_eq!(
            names(WireguardModel::default().commands(&m)),
            ["ip 'link' 'delete' 'wg0'", "networkctl 'reload'"]
        );
    }

    #[test]
    fn invalid_models_are_rejected() {
        let mut m = model();
        let dup = m.interfaces[0].peers[0].clone();
        m.interfaces[0].peers.push(dup);
        assert!(matches!(m.validate(), Err(WgError::DuplicatePeer { .. })));
        let mut m = model();
        m.interfaces[0].private_key_file = "wg0.key".into();
        assert!(matches!(m.validate(), Err(WgError::RelativeKeyFile(_))));
        let mut m = model();
        let i = m.interfaces[0].clone();
        m.interfaces.push(i);
        assert!(matches!(m.validate(), Err(WgError::DuplicateInterface(_))));
    }
}
