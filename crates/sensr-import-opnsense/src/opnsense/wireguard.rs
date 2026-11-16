//! `OPNsense/wireguard`: instances (`server`) and peers (`client`).

use std::net::IpAddr;

use sensr_schema::array::Relation;
use sensr_schema::fields::{Host, Secret, WgKey, WgName};
use sensr_schema::ipnet::IpNet;
use sensr_schema::models::wireguard::{WgPeer, WgServer};
use sensr_schema::{Document, Uuid};

use super::common::{item_uuid, list, parse_or_warn};
use crate::mapper::{MapContext, Mapper};
use crate::report::Severity;
use crate::tree::Element;

pub struct WireGuardMapper;

impl Mapper<Document> for WireGuardMapper {
    fn name(&self) -> &'static str {
        "wireguard"
    }

    fn sections(&self) -> &'static [&'static str] {
        &["OPNsense/wireguard"]
    }

    fn map<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        if let Some(g) = ctx.child(s, "general") {
            out.wireguard.enabled = ctx.flag(g, "enabled");
        }
        if let Some(c) = ctx.child(s, "client")
            && let Some(clients) = ctx.child(c, "clients")
        {
            for p in ctx.children(clients, "client") {
                match peer(p, ctx) {
                    Some((id, peer)) => {
                        out.wireguard.peers.insert(id, peer);
                    }
                    None => ctx.release(p),
                }
            }
        }
        if let Some(sv) = ctx.child(s, "server")
            && let Some(servers) = ctx.child(sv, "servers")
        {
            for i in ctx.children(servers, "server") {
                match server(i, ctx) {
                    Some((id, server)) => {
                        out.wireguard.servers.insert(id, server);
                    }
                    None => ctx.release(i),
                }
            }
        }
    }

    fn expected_unmapped(&self) -> &'static [(&'static str, &'static str)] {
        &[
            (
                "OPNsense/wireguard/server/servers/server/endpoint",
                "client-export defaults are not modelled yet",
            ),
            (
                "OPNsense/wireguard/server/servers/server/allowed_ips",
                "client-export defaults are not modelled yet",
            ),
        ]
    }
}

fn nets(ctx: &mut MapContext<'_>, at: &Element, text: &str) -> Vec<IpNet> {
    list(text, &[','])
        .iter()
        .filter_map(|n| {
            n.parse::<IpNet>()
                .ok()
                .or_else(|| n.parse::<IpAddr>().ok().map(IpNet::from))
                .or_else(|| {
                    ctx.warn(at, Severity::Invalid, format!("network {n:?} not imported"));
                    None
                })
        })
        .collect()
}

fn server<'doc>(i: &'doc Element, ctx: &mut MapContext<'doc>) -> Option<(Uuid, WgServer)> {
    let id = item_uuid(ctx, i);
    let name_el = ctx.child(i, "name")?;
    let name: WgName = parse_or_warn(ctx, name_el, &name_el.text(), "instance name")?;
    let instance = ctx.parse::<u32>(i, "instance")?;
    let priv_el = ctx.child(i, "privkey")?;
    let private_key: WgKey = parse_or_warn(ctx, priv_el, &priv_el.text(), "private key")?;
    let public_key = match ctx.non_empty(i, "pubkey") {
        Some(k) => parse_or_warn(ctx, i, &k, "public key"),
        None => None,
    };
    let tunnel_addresses = match i.child("tunneladdress") {
        Some(t) => {
            ctx.consume(t);
            nets(ctx, t, &t.text())
        }
        None => Vec::new(),
    };
    let mut peers = Vec::new();
    if let Some(p) = i.child("peers") {
        ctx.consume(p);
        for u in list(&p.text(), &[',']) {
            peers.extend(parse_or_warn::<Uuid>(ctx, p, &u, "peer reference").map(Relation::new));
        }
    }
    let mut dns = Vec::new();
    if let Some(d) = i.child("peer_dns") {
        ctx.consume(d);
        for a in list(&d.text(), &[',']) {
            dns.extend(parse_or_warn::<IpAddr>(ctx, d, &a, "DNS server"));
        }
    }
    let gateway = ctx.parse(i, "gateway");
    let server = WgServer {
        enabled: ctx.flag(i, "enabled"),
        name,
        instance,
        public_key,
        private_key: Secret::new(private_key),
        listen_port: ctx.parse(i, "port"),
        mtu: ctx.parse(i, "mtu"),
        dns,
        tunnel_addresses,
        disable_routes: ctx.flag(i, "disableroutes"),
        gateway,
        peers,
    };
    // `dns` here is the firewall's own resolver override for the tunnel, not
    // modelled; `debug` only raises log verbosity.
    ctx.defaults(i, &[("dns", ""), ("carp_depend_on", ""), ("debug", "0")]);
    Some((id, server))
}

fn peer<'doc>(p: &'doc Element, ctx: &mut MapContext<'doc>) -> Option<(Uuid, WgPeer)> {
    let id = item_uuid(ctx, p);
    let name_el = ctx.child(p, "name")?;
    let name: WgName = parse_or_warn(ctx, name_el, &name_el.text(), "peer name")?;
    let key_el = ctx.child(p, "pubkey")?;
    let public_key: WgKey = parse_or_warn(ctx, key_el, &key_el.text(), "public key")?;
    let preshared_key = match ctx.non_empty(p, "psk") {
        Some(k) => Some(Secret::new(parse_or_warn::<WgKey>(
            ctx,
            p,
            &k,
            "pre-shared key",
        )?)),
        None => None,
    };
    let allowed_ips = match p.child("tunneladdress") {
        Some(t) => {
            ctx.consume(t);
            nets(ctx, t, &t.text())
        }
        None => Vec::new(),
    };
    let endpoint = match ctx.non_empty(p, "serveraddress") {
        Some(h) => parse_or_warn::<Host>(ctx, p, &h, "endpoint"),
        None => None,
    };
    let peer = WgPeer {
        enabled: ctx.flag(p, "enabled"),
        name,
        public_key,
        preshared_key,
        allowed_ips,
        endpoint,
        endpoint_port: ctx.parse(p, "serverport"),
        keepalive: ctx.parse(p, "keepalive"),
    };
    ctx.defaults(p, &[("privkey", ""), ("servers", "")]);
    Some((id, peer))
}
