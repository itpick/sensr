//! WireGuard instances and peers (OPNsense `Wireguard/{General,Server,Client}.xml`).

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::array::{ArrayField, Relation};
use crate::fields::{Host, Port, Secret, WgKey, WgName};
use crate::refs::{ItemKind, RefContext, Validate};
use crate::validation::{FieldPath, Validations, ValidatorKind, messages};

/// WireGuard as a whole.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuard {
    /// Master switch (OPNsense `general.enabled`).
    #[serde(default)]
    pub enabled: bool,
    /// Local instances (`wgN` devices).
    #[serde(default)]
    pub servers: ArrayField<WgServer>,
    /// Remote peers, attached to instances by reference.
    #[serde(default)]
    pub peers: ArrayField<WgPeer>,
}

/// A local WireGuard instance (one `wg<instance>` device).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WgServer {
    /// Bring the instance up.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Name.
    pub name: WgName,
    /// Device number: the device is `wg<instance>`.
    pub instance: u32,
    /// Public key (derived from the private key when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<WgKey>,
    /// Private key.
    pub private_key: Secret<WgKey>,
    /// UDP listen port; `None` picks one at random.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<Port>,
    /// MTU; `None` for the kernel default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// DNS servers pushed to generated client configs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<IpAddr>,
    /// Addresses of the tunnel interface.
    #[serde(default)]
    pub tunnel_addresses: Vec<IpNet>,
    /// Don't install routes for peers' allowed IPs.
    #[serde(default)]
    pub disable_routes: bool,
    /// Gateway address for policy routing (requires `disable_routes`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<IpAddr>,
    /// Peers of this instance.
    #[serde(default)]
    pub peers: Vec<Relation<WgPeer>>,
}

/// A remote peer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WgPeer {
    /// Use the peer.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Name.
    pub name: WgName,
    /// The peer's public key.
    pub public_key: WgKey,
    /// Pre-shared key for post-quantum hardening.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<Secret<WgKey>>,
    /// Allowed IPs: traffic to these is routed to the peer, traffic from the
    /// peer must come from these (OPNsense `tunneladdress`).
    pub allowed_ips: Vec<IpNet>,
    /// Endpoint host; `None` waits for the peer to connect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<Host>,
    /// Endpoint port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_port: Option<Port>,
    /// Persistent keepalive interval in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<u16>,
}

impl Validate for WireGuard {
    fn validate(&self, ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        let servers = at.join("servers");
        check::unique(
            self.servers
                .iter()
                .map(|(id, s)| (servers.join(id), Some(s.instance))),
            "instance",
            "Instance number must be unique.",
            out,
        );
        check::unique(
            self.servers
                .iter()
                .map(|(id, s)| (servers.join(id), Some(s.name.clone()))),
            "name",
            "Name must be unique.",
            out,
        );
        for (id, s) in &self.servers {
            let p = servers.join(id);
            if let Some(mtu) = s.mtu {
                check::range(mtu, 1..=9300, &p.join("mtu"), out);
            }
            if s.gateway.is_some() && !s.disable_routes {
                out.add(
                    &p.join("disable_routes"),
                    ValidatorKind::Constraint,
                    "You have to enable Disable Routes option.",
                );
            }
            for peer in &s.peers {
                if !self.peers.contains(&peer.id()) && !ctx.has_item(ItemKind::WgPeer, &peer.id()) {
                    out.add(
                        &p.join("peers"),
                        ValidatorKind::Callback,
                        messages::RELATION_NOT_FOUND,
                    );
                }
            }
        }
        let peers = at.join("peers");
        check::unique(
            self.peers.iter().map(|(id, c)| {
                (
                    peers.join(id),
                    Some((c.public_key, c.endpoint.clone(), c.endpoint_port)),
                )
            }),
            "public_key",
            "Public keys should be unique.",
            out,
        );
        for (id, c) in &self.peers {
            let p = peers.join(id);
            if c.allowed_ips.is_empty() {
                out.add(
                    &p.join("allowed_ips"),
                    ValidatorKind::PresenceOf,
                    "Allowed IPs are required.",
                );
            }
            if c.endpoint_port.is_some() && c.endpoint.is_none() {
                out.add(
                    &p.join("endpoint"),
                    ValidatorKind::Constraint,
                    "An endpoint port requires an endpoint address.",
                );
            }
            if c.keepalive == Some(0) {
                out.add(
                    &p.join("keepalive"),
                    ValidatorKind::MinMax,
                    "Please specify a value between 1 and 65535.",
                );
            }
        }
    }
}
