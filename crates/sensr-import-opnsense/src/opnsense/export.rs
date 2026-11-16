//! Export of the mapped subset back to an OPNsense `config.xml` tree.
//!
//! The export writes what the importer reads, in the current (MVC) form wherever
//! OPNsense has one, so `import(export(doc)) == doc` for every document the importer
//! produces (the round-trip test), and an operator can carry a sensr configuration
//! back to OPNsense. Nodes the importer reported as unmapped are not reproduced.

use base64::Engine as _;
use sensr_schema::Document;
use sensr_schema::fields::{IpFamily, NetOrAlias, PortSpec, Protocol};
use sensr_schema::models::dhcp::{ClientMatch, Dhcp4Options};
use sensr_schema::models::dns::{DnsRecord, LocalZoneType};
use sensr_schema::models::firewall::{
    AliasContent, AliasValue, Direction, Endpoint, RuleAction, StateType,
};
use sensr_schema::models::interfaces::{Ipv4Config, Ipv6Config, VlanProtocol};
use sensr_schema::models::nat::{ForwardFilter, OutboundNatMode, ReflectionMode};

use super::common::stable_uuid;
use crate::tree::{Document as XmlDocument, Element};

fn leaf(name: &str, text: impl ToString) -> Element {
    Element::with_text(name, text.to_string())
}

fn flag01(b: bool) -> &'static str {
    if b { "1" } else { "0" }
}

fn join<T: ToString>(items: &[T], sep: &str) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(sep)
}

trait Push {
    fn put(&mut self, e: Element) -> &mut Self;
    fn put_opt<T: ToString>(&mut self, name: &str, v: Option<T>) -> &mut Self;
}

impl Push for Element {
    fn put(&mut self, e: Element) -> &mut Self {
        self.push_element(e);
        self
    }
    fn put_opt<T: ToString>(&mut self, name: &str, v: Option<T>) -> &mut Self {
        if let Some(v) = v {
            self.push_element(leaf(name, v));
        }
        self
    }
}

/// Build the `config.xml` tree for `doc`.
pub fn export_document(doc: &Document) -> XmlDocument {
    let mut root = Element::new("opnsense");
    root.push_element(system(doc));
    root.push_element(interfaces(doc));
    root.push_element(vlans(doc));
    root.push_element(nat(doc));
    root.push_element(gateway_groups(doc));
    trust(doc, &mut root);
    let mut opn = Element::new("OPNsense");
    let mut fw = Element::new("Firewall");
    fw.push_element(aliases(doc));
    fw.push_element(filter(doc));
    opn.push_element(fw);
    let mut kea = Element::new("Kea");
    kea.push_element(kea4(doc));
    opn.push_element(kea);
    opn.push_element(unbound(doc));
    opn.push_element(wireguard(doc));
    opn.push_element(gateways(doc));
    root.push_element(opn);
    XmlDocument { root }
}

fn system(doc: &Document) -> Element {
    let s = &doc.system;
    let mut e = Element::new("system");
    e.put(leaf("hostname", &s.hostname))
        .put(leaf("domain", &s.domain));
    for d in &s.dns_servers {
        e.put(leaf("dnsserver", d));
    }
    e.put(leaf("dnsallowoverride", flag01(s.dns_allow_override)));
    e.put(leaf("timezone", &s.timezone));
    if !s.time_servers.is_empty() {
        e.put(leaf("timeservers", join(&s.time_servers, " ")));
    }
    if s.ipv6_allow {
        e.put(leaf("ipv6allow", "1"));
    }
    for (id, g) in s.groups.iter() {
        let members: Vec<String> = s
            .users
            .values()
            .filter(|u| u.groups.contains(&g.name))
            .map(|u| u.uid.to_string())
            .collect();
        let mut ge = Element::new("group").attr("uuid", id.to_string());
        ge.put(leaf("gid", g.gid))
            .put(leaf("name", &g.name))
            .put_opt("description", g.description.as_ref())
            .put(leaf("priv", g.privileges.join(",")))
            .put(leaf("member", members.join(",")));
        e.put(ge);
    }
    for (id, u) in s.users.iter() {
        let mut ue = Element::new("user").attr("uuid", id.to_string());
        ue.put(leaf("uid", u.uid))
            .put(leaf("name", &u.name))
            .put(leaf("disabled", flag01(u.disabled)));
        if !u.authorized_keys.is_empty() {
            let text = join(&u.authorized_keys, "\n");
            ue.put(leaf(
                "authorizedkeys",
                base64::engine::general_purpose::STANDARD.encode(text),
            ));
        }
        ue.put_opt("shell", u.shell.as_ref()).put_opt(
            "password",
            u.password_hash.as_ref().map(|p| p.expose().clone()),
        );
        if !u.api_keys.is_empty() {
            let lines: Vec<String> = u
                .api_keys
                .iter()
                .map(|k| format!("{}|{}", k.key, k.secret_hash.expose()))
                .collect();
            ue.put(leaf("apikeys", lines.join("\n")));
        }
        ue.put_opt("descr", u.description.as_ref());
        e.put(ue);
    }
    let ssh = &s.ssh;
    let mut se = Element::new("ssh");
    if let Some(g) = &ssh.group {
        se.put(leaf("group", g));
    }
    if !ssh.interfaces.is_empty() {
        se.put(leaf("interfaces", join(&ssh.interfaces, ",")));
    }
    if ssh.port.get() != 22 {
        se.put(leaf("port", ssh.port));
    }
    if ssh.permit_root_login {
        se.put(leaf("permitrootlogin", "1"));
    }
    if ssh.password_auth {
        se.put(leaf("passwordauth", "1"));
    }
    if ssh.enabled {
        se.put(leaf("enabled", "enabled"));
    }
    e.put(se);
    let r = &doc.nat.reflection;
    if r.source_nat {
        e.put(leaf("enablenatreflectionhelper", "yes"));
    }
    if !r.port_forwards {
        e.put(leaf("disablenatreflection", "yes"));
    }
    e
}

fn interfaces(doc: &Document) -> Element {
    let mut e = Element::new("interfaces");
    for (id, i) in doc.interfaces.iter() {
        let mut ie = Element::new(id.as_str());
        ie.put(leaf("if", &i.device))
            .put_opt("descr", i.description.as_ref());
        if i.enabled {
            ie.put(leaf("enable", "1"));
        }
        ie.put_opt("spoofmac", i.spoof_mac).put_opt("mtu", i.mtu);
        if i.block_private {
            ie.put(leaf("blockpriv", "1"));
        }
        if i.block_bogons {
            ie.put(leaf("blockbogons", "1"));
        }
        match &i.ipv4 {
            Ipv4Config::None => {}
            Ipv4Config::Dhcp {
                hostname,
                reject_from,
                ..
            } => {
                ie.put(leaf("ipaddr", "dhcp"))
                    .put_opt("dhcphostname", hostname.as_ref());
                if !reject_from.is_empty() {
                    ie.put(leaf("dhcprejectfrom", join(reject_from, ",")));
                }
            }
            Ipv4Config::Static { address, gateway } => {
                ie.put(leaf("ipaddr", address.addr()))
                    .put(leaf("subnet", address.prefix_len()))
                    .put_opt(
                        "gateway",
                        gateway.and_then(|a| gateway_name(doc, id, a.into())),
                    );
            }
        }
        match &i.ipv6 {
            Ipv6Config::None => {}
            Ipv6Config::Dhcp6 {
                prefix_delegation_len,
                send_prefix_hint,
                prefix_only,
            } => {
                ie.put(leaf("ipaddrv6", "dhcp6"));
                ie.put(leaf(
                    "dhcp6-ia-pd-len",
                    prefix_delegation_len
                        .map_or_else(|| "none".to_owned(), |l| (64 - l.min(64)).to_string()),
                ));
                if *send_prefix_hint {
                    ie.put(leaf("dhcp6-ia-pd-send-hint", "1"));
                }
                if *prefix_only {
                    ie.put(leaf("dhcp6prefixonly", "1"));
                }
            }
            Ipv6Config::Slaac => {
                ie.put(leaf("ipaddrv6", "slaac"));
            }
            Ipv6Config::Static { address, gateway } => {
                ie.put(leaf("ipaddrv6", address.addr()))
                    .put(leaf("subnetv6", address.prefix_len()))
                    .put_opt(
                        "gatewayv6",
                        gateway.and_then(|a| gateway_name(doc, id, a.into())),
                    );
            }
            Ipv6Config::Track {
                interface,
                prefix_id,
            } => {
                ie.put(leaf("ipaddrv6", "idassoc6"))
                    .put(leaf("track6-interface", interface))
                    .put(leaf("track6-prefix-id", prefix_id));
            }
        }
        e.put(ie);
    }
    e
}

fn vlans(doc: &Document) -> Element {
    let mut e = Element::new("vlans");
    for (_, i) in doc.interfaces.iter() {
        if let Some(v) = &i.vlan {
            let mut ve = Element::new("vlan").attr(
                "uuid",
                stable_uuid(&format!("vlan:{}", i.device)).to_string(),
            );
            ve.put(leaf("if", &v.parent))
                .put(leaf("tag", v.tag))
                .put(leaf("pcp", v.pcp));
            ve.put(leaf(
                "proto",
                match v.protocol {
                    VlanProtocol::Dot1Q => "802.1q",
                    VlanProtocol::Dot1Ad => "802.1ad",
                },
            ));
            ve.put(leaf("vlanif", &i.device));
            e.put(ve);
        }
    }
    e
}

/// The OPNsense spelling of an address operand.
fn operand(n: &NetOrAlias) -> String {
    match n {
        NetOrAlias::Any => "any".into(),
        NetOrAlias::This => "(self)".into(),
        NetOrAlias::InterfaceNet(i) => i.to_string(),
        NetOrAlias::InterfaceAddr(i) => format!("{i}ip"),
        NetOrAlias::Alias(a) => a.to_string(),
        other => other.to_string(),
    }
}

fn port(p: &PortSpec) -> String {
    match p {
        PortSpec::Alias(a) => a.to_string(),
        PortSpec::Range(r) => r.to_string(),
    }
}

fn family(f: IpFamily) -> &'static str {
    match f {
        IpFamily::Inet => "inet",
        IpFamily::Inet6 => "inet6",
        IpFamily::Inet46 => "inet46",
    }
}

fn protocol(p: Protocol) -> String {
    p.to_string()
}

fn mvc_endpoint(e: &mut Element, side: &str, ep: &Endpoint) {
    e.put(leaf(&format!("{side}_net"), operand(&ep.net)))
        .put(leaf(&format!("{side}_not"), flag01(ep.not)))
        .put(leaf(
            &format!("{side}_port"),
            ep.port.as_ref().map(port).unwrap_or_default(),
        ));
}

fn nested_endpoint(name: &str, ep: &Endpoint) -> Element {
    let mut e = Element::new(name);
    if ep.net.is_any() {
        e.put(leaf("any", "1"));
    } else {
        e.put(leaf("network", operand(&ep.net)));
    }
    e.put_opt("port", ep.port.as_ref().map(port));
    if ep.not {
        e.put(leaf("not", "1"));
    }
    e
}

fn aliases(doc: &Document) -> Element {
    let mut list = Element::new("aliases");
    for (id, a) in doc.firewall.aliases.iter() {
        let (kind, content, proto, updatefreq) = match &a.content {
            AliasContent::Host { entries } | AliasContent::Network { entries } => {
                let items: Vec<String> = entries
                    .iter()
                    .map(|en| match &en.value {
                        AliasValue::Alias(n) => format!("{}{n}", if en.exclude { "!" } else { "" }),
                        _ => en.to_string(),
                    })
                    .collect();
                let kind = if matches!(a.content, AliasContent::Host { .. }) {
                    "host"
                } else {
                    "network"
                };
                (kind, items.join("\n"), String::new(), String::new())
            }
            AliasContent::Port { entries } => (
                "port",
                entries.iter().map(port).collect::<Vec<_>>().join("\n"),
                String::new(),
                String::new(),
            ),
            AliasContent::Url { urls } => ("url", join(urls, "\n"), String::new(), String::new()),
            AliasContent::UrlTable {
                url,
                refresh,
                families,
            } => {
                let days = f64::from(refresh.days) + f64::from(refresh.hours) / 24.0;
                let freq = if refresh.days == 0 && refresh.hours == 0 {
                    String::new()
                } else {
                    trim_float(days)
                };
                ("urltable", url.to_string(), families_text(*families), freq)
            }
            AliasContent::GeoIp {
                countries,
                families,
            } => (
                "geoip",
                join(countries, "\n"),
                families_text(*families),
                String::new(),
            ),
            AliasContent::NetworkGroup { members } => (
                "networkgroup",
                join(members, "\n"),
                String::new(),
                String::new(),
            ),
            AliasContent::Mac { addresses } => {
                ("mac", join(addresses, "\n"), String::new(), String::new())
            }
            AliasContent::External => ("external", String::new(), String::new(), String::new()),
        };
        let mut ae = Element::new("alias").attr("uuid", id.to_string());
        ae.put(leaf("enabled", flag01(a.enabled)))
            .put(leaf("name", &a.name))
            .put(leaf("type", kind))
            .put(leaf("proto", proto))
            .put(leaf("counters", flag01(a.counters)))
            .put(leaf("updatefreq", updatefreq))
            .put(leaf("content", content))
            .put_opt("description", a.description.as_ref());
        list.put(ae);
    }
    let mut e = Element::new("Alias");
    e.put(list);
    e
}

fn trim_float(v: f64) -> String {
    let s = format!("{v:.6}");
    s.trim_end_matches('0').trim_end_matches('.').to_owned()
}

fn families_text(f: sensr_schema::models::firewall::Families) -> String {
    match (f.ipv4, f.ipv6) {
        (true, true) => "IPv4,IPv6".into(),
        (true, false) => "IPv4".into(),
        (false, true) => "IPv6".into(),
        (false, false) => String::new(),
    }
}

fn filter(doc: &Document) -> Element {
    let mut rules = Element::new("rules");
    for (id, r) in doc.firewall.rules_in_order() {
        let mut re = Element::new("rule").attr("uuid", id.to_string());
        re.put(leaf("enabled", flag01(r.enabled)))
            .put(leaf(
                "statetype",
                match r.state_type {
                    StateType::Keep => "keep",
                    StateType::Sloppy => "sloppy",
                    StateType::Modulate => "modulate",
                    StateType::Synproxy => "synproxy",
                    StateType::None => "none",
                },
            ))
            .put(leaf("sequence", r.sequence))
            .put(leaf(
                "action",
                match r.action {
                    RuleAction::Pass => "pass",
                    RuleAction::Block => "block",
                    RuleAction::Reject => "reject",
                },
            ))
            .put(leaf("quick", flag01(r.quick)))
            .put(leaf("interfacenot", flag01(r.interface_not)))
            .put(leaf("interface", join(&r.interfaces, ",")))
            .put(leaf(
                "direction",
                match r.direction {
                    Direction::In => "in",
                    Direction::Out => "out",
                    Direction::Any => "any",
                },
            ))
            .put(leaf("ipprotocol", family(r.ip_protocol)))
            .put(leaf("protocol", protocol(r.protocol)));
        mvc_endpoint(&mut re, "source", &r.source);
        mvc_endpoint(&mut re, "destination", &r.destination);
        re.put(leaf("log", flag01(r.log)))
            .put_opt("gateway", r.gateway.as_ref())
            .put_opt("description", r.description.as_ref());
        rules.put(re);
    }
    let mut snat = Element::new("snatrules");
    for (id, r) in doc.nat.outbound.rules.iter() {
        let mut re = Element::new("rule").attr("uuid", id.to_string());
        re.put(leaf("enabled", flag01(r.enabled)))
            .put(leaf("nonat", flag01(r.no_nat)))
            .put(leaf("sequence", r.sequence))
            .put(leaf("interface", &r.interface))
            .put(leaf("ipprotocol", family(r.ip_protocol)))
            .put(leaf("protocol", protocol(r.protocol)));
        mvc_endpoint(&mut re, "source", &r.source);
        mvc_endpoint(&mut re, "destination", &r.destination);
        re.put(leaf(
            "target",
            r.target.as_ref().map(operand).unwrap_or_default(),
        ))
        .put(leaf(
            "target_port",
            r.target_port.map(|p| p.to_string()).unwrap_or_default(),
        ))
        .put(leaf("staticnatport", flag01(r.static_port)))
        .put(leaf("log", flag01(r.log)))
        .put_opt("description", r.description.as_ref());
        snat.put(re);
    }
    let mut e = Element::new("Filter");
    e.put(rules).put(snat);
    e
}

fn nat(doc: &Document) -> Element {
    let mut e = Element::new("nat");
    let mut ob = Element::new("outbound");
    ob.put(leaf(
        "mode",
        match doc.nat.outbound.mode {
            OutboundNatMode::Automatic => "automatic",
            OutboundNatMode::Hybrid => "hybrid",
            OutboundNatMode::Manual => "advanced",
            OutboundNatMode::Disabled => "disabled",
        },
    ));
    e.put(ob);
    for (id, f) in doc.nat.port_forwards.iter() {
        let mut re = Element::new("rule").attr("uuid", id.to_string());
        re.put(leaf("sequence", f.sequence))
            .put(leaf("disabled", flag01(!f.enabled)))
            .put(leaf("nordr", flag01(f.no_rdr)))
            .put(leaf("interface", join(&f.interfaces, ",")))
            .put(leaf("ipprotocol", family(f.ip_protocol)))
            .put(leaf("protocol", protocol(f.protocol)))
            .put(nested_endpoint("source", &f.source))
            .put(nested_endpoint("destination", &f.destination))
            .put(leaf("target", operand(&f.target)))
            .put_opt("local-port", f.target_port.as_ref().map(port))
            .put(leaf("log", flag01(f.log)))
            .put_opt("descr", f.description.as_ref())
            .put(leaf(
                "natreflection",
                match f.reflection {
                    None => "",
                    Some(ReflectionMode::Purenat) => "purenat",
                    Some(ReflectionMode::Enable) => "enable",
                    Some(ReflectionMode::Disable) => "disable",
                },
            ));
        match &f.filter {
            ForwardFilter::Pass => {
                re.put(leaf("pass", "pass"));
            }
            ForwardFilter::Rule(r) => {
                re.put(leaf("associated-rule-id", r.id()));
            }
            ForwardFilter::None => {
                re.put(leaf("pass", ""));
            }
        }
        e.put(re);
    }
    e
}

fn options(o: &Dhcp4Options) -> Element {
    let mut e = Element::new("option_data");
    e.put(leaf("domain_name_servers", join(&o.dns_servers, ",")))
        .put(leaf("domain_search", join(&o.domain_search, ",")))
        .put(leaf("routers", join(&o.routers, ",")))
        .put_opt("domain_name", o.domain_name.as_ref())
        .put(leaf("ntp_servers", join(&o.ntp_servers, ",")))
        .put_opt("tftp_server_name", o.tftp_server_name.as_ref())
        .put_opt("boot_file_name", o.boot_file_name.as_ref())
        .put_opt("v6_only_preferred", o.v6_only_preferred);
    e
}

fn kea4(doc: &Document) -> Element {
    let d = &doc.dhcpv4;
    let mut g = Element::new("general");
    g.put(leaf("enabled", flag01(d.enabled)))
        .put(leaf("interfaces", join(&d.interfaces, ",")))
        .put(leaf("valid_lifetime", d.valid_lifetime))
        .put(leaf("fwrules", flag01(d.firewall_rules)));
    let mut subnets = Element::new("subnets");
    for (id, s) in d.subnets.iter() {
        let mut se = Element::new("subnet4").attr("uuid", id.to_string());
        se.put_opt("interface", s.interface.as_ref())
            .put(leaf("subnet", s.subnet))
            .put_opt("valid_lifetime", s.valid_lifetime)
            .put_opt("next_server", s.next_server)
            .put(leaf("option_data_autocollect", flag01(s.auto_options)))
            .put(options(&s.options))
            .put(leaf("match-client-id", flag01(s.match_client_id)))
            .put(leaf("pools", join(&s.pools, "\n")))
            .put_opt("description", s.description.as_ref());
        subnets.put(se);
    }
    let mut res = Element::new("reservations");
    for (id, r) in d.reservations.iter() {
        let mut re = Element::new("reservation").attr("uuid", id.to_string());
        re.put(leaf("subnet", r.subnet.id()))
            .put_opt("ip_address", r.ip_address);
        match &r.client {
            ClientMatch::HwAddress(m) => re.put(leaf("hw_address", m)),
            ClientMatch::ClientId(c) => re.put(leaf("client_id", c)),
        };
        re.put_opt("hostname", r.hostname.as_ref())
            .put_opt("description", r.description.as_ref());
        res.put(re);
    }
    let mut e = Element::new("dhcp4");
    e.put(g).put(subnets).put(res);
    e
}

fn zone_type(z: LocalZoneType) -> &'static str {
    match z {
        LocalZoneType::Transparent => "transparent",
        LocalZoneType::Typetransparent => "typetransparent",
        LocalZoneType::Static => "static",
        LocalZoneType::Refuse => "refuse",
        LocalZoneType::Deny => "deny",
        LocalZoneType::Redirect => "redirect",
        LocalZoneType::Inform => "inform",
        LocalZoneType::InformDeny => "inform_deny",
        LocalZoneType::Nodefault => "nodefault",
        LocalZoneType::AlwaysTransparent => "always_transparent",
        LocalZoneType::AlwaysRefuse => "always_refuse",
        LocalZoneType::AlwaysNxdomain => "always_nxdomain",
    }
}

fn unbound(doc: &Document) -> Element {
    let d = &doc.dns;
    let mut g = Element::new("general");
    g.put(leaf("enabled", flag01(d.enabled)))
        .put(leaf("port", d.port))
        .put(leaf("active_interface", join(&d.listen_interfaces, ",")))
        .put(leaf("dnssec", flag01(d.dnssec)))
        .put(leaf("dns64", flag01(d.dns64)))
        .put(leaf("regdhcp", flag01(d.register_dhcp_leases)))
        .put_opt("regdhcpdomain", d.dhcp_domain.as_ref())
        .put(leaf("regdhcpstatic", flag01(d.register_dhcp_static)))
        .put(leaf("local_zone_type", zone_type(d.local_zone_type)))
        .put(leaf(
            "outgoing_interface",
            join(&d.outgoing_interfaces, ","),
        ));
    let mut fwd = Element::new("forwarding");
    fwd.put(leaf("enabled", flag01(d.forwarding.use_system_servers)));
    let mut dots = Element::new("dots");
    for (id, f) in d.forwarding.servers.iter() {
        let mut de = Element::new("dot").attr("uuid", id.to_string());
        de.put(leaf("enabled", flag01(f.enabled)))
            .put(leaf(
                "type",
                if f.tls_name.is_some() {
                    "dot"
                } else {
                    "forward"
                },
            ))
            .put_opt("domain", f.domain.as_ref())
            .put(leaf("server", f.address))
            .put_opt("port", f.port)
            .put_opt("verify", f.tls_name.as_ref())
            .put_opt("description", f.description.as_ref());
        dots.put(de);
    }
    let mut hosts = Element::new("hosts");
    for (id, h) in d.host_overrides.iter() {
        let mut he = Element::new("host").attr("uuid", id.to_string());
        he.put(leaf("enabled", flag01(h.enabled)))
            .put(leaf("hostname", &h.hostname))
            .put(leaf("domain", &h.domain));
        match &h.record {
            DnsRecord::A { address } => he.put(leaf("rr", "A")).put(leaf("server", address)),
            DnsRecord::Aaaa { address } => he.put(leaf("rr", "AAAA")).put(leaf("server", address)),
            DnsRecord::Mx { priority, host } => he
                .put(leaf("rr", "MX"))
                .put(leaf("mxprio", priority))
                .put(leaf("mx", host)),
            DnsRecord::Txt { data } => he.put(leaf("rr", "TXT")).put(leaf("txtdata", data)),
        };
        he.put_opt("ttl", h.ttl)
            .put_opt("description", h.description.as_ref());
        hosts.put(he);
    }
    let mut e = Element::new("unboundplus");
    e.put(g).put(fwd).put(dots).put(hosts);
    e
}

fn wireguard(doc: &Document) -> Element {
    let w = &doc.wireguard;
    let mut general = Element::new("general");
    general.put(leaf("enabled", flag01(w.enabled)));
    let mut clients = Element::new("clients");
    for (id, p) in w.peers.iter() {
        let mut pe = Element::new("client").attr("uuid", id.to_string());
        pe.put(leaf("enabled", flag01(p.enabled)))
            .put(leaf("name", &p.name))
            .put(leaf("pubkey", p.public_key))
            .put_opt("psk", p.preshared_key.as_ref().map(|k| *k.expose()))
            .put(leaf("tunneladdress", join(&p.allowed_ips, ",")))
            .put_opt("serveraddress", p.endpoint.as_ref())
            .put_opt("serverport", p.endpoint_port)
            .put_opt("keepalive", p.keepalive);
        clients.put(pe);
    }
    let mut servers = Element::new("servers");
    for (id, s) in w.servers.iter() {
        let mut se = Element::new("server").attr("uuid", id.to_string());
        se.put(leaf("enabled", flag01(s.enabled)))
            .put(leaf("name", &s.name))
            .put(leaf("instance", s.instance))
            .put_opt("pubkey", s.public_key)
            .put(leaf("privkey", s.private_key.expose()))
            .put_opt("port", s.listen_port)
            .put_opt("mtu", s.mtu)
            .put(leaf("tunneladdress", join(&s.tunnel_addresses, ",")))
            .put(leaf("disableroutes", flag01(s.disable_routes)))
            .put_opt("gateway", s.gateway)
            .put(leaf(
                "peers",
                s.peers
                    .iter()
                    .map(|p| p.id().to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ))
            .put(leaf("peer_dns", join(&s.dns, ",")));
        servers.put(se);
    }
    let mut client = Element::new("client");
    client.put(clients);
    let mut server = Element::new("server");
    server.put(servers);
    let mut e = Element::new("wireguard");
    e.put(general).put(client).put(server);
    e
}

/// The gateway on `iface` with `addr`, which an interface's `gateway` names.
fn gateway_name(
    doc: &Document,
    iface: &sensr_schema::fields::InterfaceId,
    addr: std::net::IpAddr,
) -> Option<String> {
    doc.gateways
        .gateways
        .values()
        .find(|g| &g.interface == iface && g.address == Some(addr))
        .map(|g| g.name.to_string())
}

fn gateways(doc: &Document) -> Element {
    let mut e = Element::new("Gateways");
    for (id, g) in doc.gateways.gateways.iter() {
        let mut ge = Element::new("gateway_item").attr("uuid", id.to_string());
        ge.put(leaf("disabled", flag01(!g.enabled)))
            .put(leaf("name", &g.name))
            .put_opt("descr", g.description.as_ref())
            .put(leaf("interface", &g.interface))
            .put(leaf("ipprotocol", family(g.family)))
            .put(leaf(
                "gateway",
                g.address.map(|a| a.to_string()).unwrap_or_default(),
            ))
            .put(leaf("defaultgw", flag01(g.default_route)))
            .put(leaf("fargw", flag01(g.far)))
            .put(leaf("monitor_disable", flag01(!g.monitor)))
            .put_opt("monitor", g.monitor_address)
            .put(leaf("priority", g.priority))
            .put(leaf("weight", g.weight));
        e.put(ge);
    }
    e
}

fn gateway_groups(doc: &Document) -> Element {
    use sensr_schema::models::gateways::GroupTrigger;
    let mut e = Element::new("gateways");
    for (id, g) in doc.gateways.groups.iter() {
        let mut ge = Element::new("gateway_group").attr("uuid", id.to_string());
        ge.put(leaf("name", &g.name));
        for (tag, tier) in [
            ("item2", 2u8),
            ("item3", 3),
            ("item4", 4),
            ("item5", 5),
            ("item", 1),
        ] {
            let names: Vec<String> = g
                .members
                .iter()
                .filter(|m| m.tier == tier)
                .map(|m| m.gateway.to_string())
                .collect();
            ge.put(leaf(tag, names.join(",")));
        }
        ge.put(leaf(
            "trigger",
            match g.trigger {
                GroupTrigger::Down => "down",
                GroupTrigger::DownLoss => "downloss",
                GroupTrigger::DownLatency => "downlatency",
                GroupTrigger::DownLossLatency => "downlosslatency",
            },
        ))
        .put_opt("descr", g.description.as_ref());
        e.put(ge);
    }
    e
}

fn b64(p: &sensr_schema::fields::Pem) -> String {
    base64::engine::general_purpose::STANDARD.encode(p.as_str())
}

fn trust(doc: &Document, root: &mut Element) {
    let refid = |id: &sensr_schema::Uuid| doc.trust.authorities.get(id).map(|c| c.refid.clone());
    for (id, c) in doc.trust.authorities.iter() {
        let mut e = Element::new("ca").attr("uuid", id.to_string());
        e.put(leaf("refid", &c.refid))
            .put(leaf("descr", &c.description))
            .put(leaf("crt", b64(&c.certificate)))
            .put_opt("prv", c.private_key.as_ref().map(|k| b64(k.expose())))
            .put(leaf("serial", c.serial))
            .put_opt("caref", c.issuer.as_ref().and_then(|i| refid(&i.id())));
        root.put(e);
    }
    for (id, c) in doc.trust.certificates.iter() {
        let mut e = Element::new("cert").attr("uuid", id.to_string());
        e.put(leaf("refid", &c.refid))
            .put(leaf("descr", &c.description))
            .put_opt("caref", c.issuer.as_ref().and_then(|i| refid(&i.id())))
            .put_opt("crt", c.certificate.as_ref().map(b64))
            .put_opt("csr", c.request.as_ref().map(b64))
            .put_opt("prv", c.private_key.as_ref().map(|k| b64(k.expose())));
        root.put(e);
    }
}
