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
use sensr_schema::models::dns::{AccessAction, DnsRecord, LocalZoneType};
use sensr_schema::models::dnsbl::{AllowEntry, BlockAnswer};
use sensr_schema::models::firewall::{
    AliasContent, AliasValue, Direction, Endpoint, RuleAction, StateType,
};
use sensr_schema::models::interfaces::{DhcpOptionValue, Ipv4Config, Ipv6Config, VlanProtocol};
use sensr_schema::models::nat::{
    ForwardFilter, OneToOneKind, OneToOneReflection, OutboundNatMode, ReflectionMode,
};
use sensr_schema::models::ntp::NtpServerOptions;

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
    if let Some(g) = ifgroups(doc) {
        root.push_element(g);
    }
    root.push_element(nat(doc));
    root.push_element(gateway_groups(doc));
    if let Some(n) = ntpd(doc) {
        root.push_element(n);
    }
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
    opn.push_element(interface_settings(doc));
    root.push_element(opn);
    XmlDocument { root }
}

/// `ntpd`, when time is served or anything differs from the defaults.
fn ntpd(doc: &Document) -> Option<Element> {
    let n = &doc.ntp;
    if n.is_empty() && doc.system.time_servers.is_empty() {
        return None;
    }
    let mut e = Element::new("ntpd");
    type Flag = fn(&NtpServerOptions) -> bool;
    let flags: [(&str, Flag); 4] = [
        ("prefer", |o| o.prefer),
        ("noselect", |o| o.no_select),
        ("iburst", |o| o.iburst),
        ("ispool", |o| o.pool),
    ];
    for (name, f) in flags {
        let hosts: Vec<String> = n
            .servers
            .iter()
            .filter(|o| f(o))
            .map(|o| o.host.to_string())
            .collect();
        if !hosts.is_empty() {
            e.put(leaf(name, hosts.join(" ")));
        }
    }
    if !n.listen_interfaces.is_empty() {
        e.put(leaf("interface", join(&n.listen_interfaces, ",")));
    }
    e.put_opt("orphan", n.orphan_stratum);
    if !n.serve {
        e.put(leaf("noserve", "1"));
    }
    if n.allow_query {
        e.put(leaf("query", "1"));
    }
    Some(e)
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
    if doc.gateways.switch_default {
        e.put(leaf("gw_switch_default", "1"));
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
        // OPNsense has no separate switch: a seed means two-factor login.
        ue.put_opt(
            "otp_seed",
            u.otp_seed.as_ref().map(|seed| seed.expose().clone()),
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
    let w = &s.webgui;
    let mut we = Element::new("webgui");
    we.put(leaf("protocol", if w.https() { "https" } else { "http" }));
    if let Some(cert) = w
        .certificate
        .as_ref()
        .and_then(|c| doc.trust.certificates.get(&c.id()))
    {
        we.put(leaf("ssl-certref", &cert.refid));
    }
    if let Some(p) = w.port {
        we.put(leaf("port", p));
    }
    if !w.interfaces.is_empty() {
        we.put(leaf("interfaces", join(&w.interfaces, ",")));
    }
    if !w.http_redirect {
        we.put(leaf("disablehttpredirect", "1"));
    }
    e.put(we);
    let r = &doc.nat.reflection;
    if r.source_nat {
        e.put(leaf("enablenatreflectionhelper", "yes"));
    }
    if !r.port_forwards {
        e.put(leaf("disablenatreflection", "yes"));
    }
    if r.one_to_one {
        e.put(leaf("enablebinatreflection", "yes"));
    }
    e
}

/// A DHCP option value as dhclient.conf writes it (quoted text, hex bytes,
/// an address or a number).
fn dhcp_value(v: &DhcpOptionValue) -> String {
    match v {
        DhcpOptionValue::String(t) => format!("\"{t}\""),
        DhcpOptionValue::Hex(h) => h.to_string(),
        DhcpOptionValue::Ipv4(a) => a.to_string(),
        DhcpOptionValue::Uint8(n) => n.to_string(),
        DhcpOptionValue::Uint16(n) => n.to_string(),
        DhcpOptionValue::Uint32(n) => n.to_string(),
    }
}

/// `OPNsense/Interfaces/settings`: IPv6 on/off (`disableipv6`, which
/// replaced `system/ipv6allow`), and the DHCPv6 DUID and release setting,
/// global there, so the first DHCPv6 interface's carry over.
fn interface_settings(doc: &Document) -> Element {
    let (duid, send_release) = doc
        .interfaces
        .iter()
        .find_map(|(_, i)| match &i.ipv6 {
            Ipv6Config::Dhcp6 {
                duid, send_release, ..
            } => Some((duid.clone(), *send_release)),
            _ => None,
        })
        .unwrap_or((None, true));
    let mut settings = Element::new("settings");
    settings.put(leaf("disableipv6", flag01(!doc.system.ipv6_allow)));
    settings.put(leaf("dhcp6_norelease", flag01(!send_release)));
    settings.put_opt("dhcp6_duid", duid);
    let mut e = Element::new("Interfaces");
    e.put(settings);
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
                vendor_class,
                user_class,
                send_options,
                request_options,
                vlan_priority,
                use_mtu,
                ..
            } => {
                ie.put(leaf("ipaddr", "dhcp"))
                    .put_opt("dhcphostname", hostname.as_ref());
                if !reject_from.is_empty() {
                    ie.put(leaf("dhcprejectfrom", join(reject_from, ",")));
                }
                if *use_mtu {
                    ie.put(leaf("dhcphonourmtu", "1"));
                }
                ie.put_opt("dhcpvlanprio", *vlan_priority);
                // Options live in the "advanced" form, the one the GUI keeps.
                let mut sends: Vec<String> = Vec::new();
                if let Some(v) = vendor_class {
                    sends.push(format!("vendor-class-identifier \"{v}\""));
                }
                for u in user_class {
                    sends.push(format!("user-class \"{u}\""));
                }
                for o in send_options {
                    sends.push(format!("option-{} {}", o.code, dhcp_value(&o.value)));
                }
                if !sends.is_empty() || !request_options.is_empty() {
                    ie.put(leaf("adv_dhcp_config_advanced", "1"));
                    if !sends.is_empty() {
                        ie.put(leaf("adv_dhcp_send_options", sends.join(", ")));
                    }
                    if !request_options.is_empty() {
                        let names: Vec<String> = request_options
                            .iter()
                            .map(|c| format!("option-{c}"))
                            .collect();
                        ie.put(leaf("adv_dhcp_request_options", names.join(", ")));
                    }
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
                rapid_commit,
                prefix_id,
                ..
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
                if *rapid_commit {
                    ie.put(leaf("dhcp6_rapid_commit", "1"));
                }
                ie.put_opt("dhcp6-prefix-id", *prefix_id);
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
    // plugins' automatic groups live among the interfaces
    for g in doc
        .firewall
        .groups
        .values()
        .filter(|g| g.wireguard || is_plugin_group(g))
    {
        let mut ge = Element::new(g.name.as_str());
        ge.put(leaf("internal_dynamic", "1"))
            .put_opt("descr", g.description.as_ref())
            .put(leaf("if", g.name.as_str()))
            .put(leaf("virtual", "1"))
            .put(leaf("enable", "1"))
            .put(leaf("type", "group"));
        e.put(ge);
    }
    e
}

/// A memberless group named after a plugin (`openvpn`): created by that plugin.
fn is_plugin_group(g: &sensr_schema::models::firewall::InterfaceGroup) -> bool {
    g.members.is_empty() && matches!(g.name.as_str(), "openvpn" | "ipsec" | "enc0")
}

fn ifgroups(doc: &Document) -> Option<Element> {
    let mut e = Element::new("ifgroups");
    for (id, g) in doc
        .firewall
        .groups
        .iter()
        .filter(|(_, g)| !g.wireguard && !is_plugin_group(g))
    {
        let mut ge = Element::new("ifgroupentry").attr("uuid", id.to_string());
        ge.put(leaf("ifname", &g.name))
            .put(leaf("members", join(&g.members, ",")))
            .put(leaf("nogroup", flag01(g.hidden)))
            .put(leaf("sequence", g.sequence))
            .put_opt("descr", g.description.as_ref());
        e.put(ge);
    }
    (!e.is_empty()).then_some(e)
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
            AliasContent::Asn { asns, families } => (
                "asn",
                join(asns, "\n"),
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
    if let Some(url) = &doc.firewall.feeds.geoip_url {
        let mut g = Element::new("geoip");
        g.put(leaf("url", url));
        e.put(g);
    }
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
    let mut one = Element::new("onetoone");
    for (id, r) in doc.nat.one_to_one.iter() {
        let mut re = Element::new("rule").attr("uuid", id.to_string());
        let external = if r.external.prefix_len() == r.external.max_prefix_len() {
            r.external.addr().to_string()
        } else {
            r.external.to_string()
        };
        re.put(leaf("enabled", flag01(r.enabled)))
            .put(leaf("log", flag01(r.log)))
            .put(leaf("sequence", r.sequence))
            .put(leaf("interface", &r.interface))
            .put(leaf(
                "type",
                match r.kind {
                    OneToOneKind::Binat => "binat",
                    OneToOneKind::Nat => "nat",
                },
            ))
            .put(leaf("source_net", operand(&r.source.net)))
            .put(leaf("source_not", flag01(r.source.not)))
            .put(leaf("destination_net", operand(&r.destination.net)))
            .put(leaf("destination_not", flag01(r.destination.not)))
            .put(leaf("external", external))
            .put(leaf(
                "natreflection",
                match r.reflection {
                    None => "",
                    Some(OneToOneReflection::Enable) => "enable",
                    Some(OneToOneReflection::Disable) => "disable",
                },
            ))
            .put_opt("description", r.description.as_ref());
        one.put(re);
    }
    let mut e = Element::new("Filter");
    e.put(rules).put(snat).put(one);
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
        .put_opt("dns64prefix", d.dns64_prefix)
        .put(leaf("stats", flag01(d.statistics)))
        .put(leaf("noregrecords", flag01(!d.register_firewall_records)))
        .put(leaf("txtsupport", flag01(d.txt_descriptions)))
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
            .put(leaf("addptr", flag01(h.ptr)))
            .put_opt("description", h.description.as_ref());
        hosts.put(he);
    }
    let mut e = Element::new("unboundplus");
    e.put(g)
        .put(unbound_advanced(doc))
        .put(unbound_acls(doc))
        .put(unbound_dnsbl(doc))
        .put(fwd)
        .put(dots)
        .put(hosts);
    e
}

fn unbound_advanced(doc: &Document) -> Element {
    let t = &doc.dns.tuning;
    let mut a = Element::new("advanced");
    a.put(leaf("hideidentity", flag01(t.hide_identity)))
        .put(leaf("hideversion", flag01(t.hide_version)))
        .put(leaf("prefetch", flag01(t.prefetch)))
        .put(leaf("prefetchkey", flag01(t.prefetch_key)))
        .put(leaf("dnssecstripped", flag01(t.harden_dnssec_stripped)))
        .put(leaf("belownxdomain", flag01(t.harden_below_nxdomain)))
        .put(leaf("aggressivensec", flag01(t.aggressive_nsec)))
        .put(leaf("serveexpired", flag01(t.serve_expired)))
        .put_opt("serveexpiredreplyttl", t.serve_expired_reply_ttl)
        .put_opt("serveexpiredttl", t.serve_expired_ttl)
        .put(leaf(
            "serveexpiredttlreset",
            flag01(t.serve_expired_ttl_reset),
        ))
        .put_opt("serveexpiredclienttimeout", t.serve_expired_client_timeout)
        .put(leaf("qnameminstrict", flag01(t.qname_minimisation_strict)))
        .put(leaf("extendedstatistics", flag01(t.extended_statistics)))
        .put(leaf("logqueries", flag01(t.log_queries)))
        .put(leaf("logreplies", flag01(t.log_replies)))
        .put(leaf("logtagqueryreply", flag01(t.log_tag_query_reply)))
        .put(leaf("logservfail", flag01(t.log_servfail)))
        .put(leaf("loglocalactions", flag01(t.log_local_actions)))
        .put(leaf("logverbosity", t.log_verbosity))
        .put(leaf("valloglevel", t.val_log_level.unwrap_or(0)))
        .put(leaf("privatedomain", join(&t.private_domains, ",")))
        .put(leaf("privateaddress", join(&t.private_addresses, ",")))
        .put(leaf("insecuredomain", join(&t.insecure_domains, ",")))
        .put_opt("msgcachesize", t.msg_cache_size)
        .put_opt("rrsetcachesize", t.rrset_cache_size)
        .put_opt("outgoingnumtcp", t.outgoing_num_tcp)
        .put_opt("incomingnumtcp", t.incoming_num_tcp)
        .put_opt("numqueriesperthread", t.num_queries_per_thread)
        .put_opt("outgoingrange", t.outgoing_range)
        .put_opt("jostletimeout", t.jostle_timeout)
        .put_opt("discardtimeout", t.discard_timeout)
        .put_opt("cachemaxttl", t.cache_max_ttl)
        .put_opt("cachemaxnegativettl", t.cache_max_negative_ttl)
        .put_opt("cacheminttl", t.cache_min_ttl)
        .put_opt("infrahostttl", t.infra_host_ttl)
        .put(leaf("infrakeepprobing", flag01(t.infra_keep_probing)))
        .put_opt("infracachenumhosts", t.infra_cache_numhosts)
        .put_opt("unwantedreplythreshold", t.unwanted_reply_threshold);
    a
}

fn access_action(a: AccessAction) -> &'static str {
    match a {
        AccessAction::Allow => "allow",
        AccessAction::Deny => "deny",
        AccessAction::Refuse => "refuse",
        AccessAction::AllowSnoop => "allow_snoop",
        AccessAction::DenyNonLocal => "deny_non_local",
        AccessAction::RefuseNonLocal => "refuse_non_local",
    }
}

fn unbound_acls(doc: &Document) -> Element {
    let a = &doc.dns.access;
    let mut e = Element::new("acls");
    e.put(leaf("default_action", access_action(a.default_action)));
    for (id, l) in a.lists.iter() {
        let mut le = Element::new("acl").attr("uuid", id.to_string());
        le.put(leaf("enabled", flag01(l.enabled)))
            .put(leaf("name", &l.name))
            .put(leaf("action", access_action(l.action)))
            .put(leaf("networks", join(&l.networks, ",")))
            .put_opt("description", l.description.as_ref());
        e.put(le);
    }
    e
}

fn unbound_dnsbl(doc: &Document) -> Element {
    let mut e = Element::new("dnsbl");
    for (id, b) in doc.dns.blocklists.iter() {
        let mut be = Element::new("blocklist").attr("uuid", id.to_string());
        let codes: Vec<&str> = b.lists.iter().map(|l| l.opnsense_code()).collect();
        // OPNsense allowlists are regular expressions; a plain name there
        // means exactly that name.
        let allow: Vec<String> = b
            .allow
            .iter()
            .map(|a| match a {
                AllowEntry::Domain(d) => d.to_string(),
                AllowEntry::Subtree(d) => format!("(.*\\.)?{}$", d.as_str().replace('.', "\\.")),
                AllowEntry::Pattern(p) => p.clone(),
            })
            .collect();
        let (address, nxdomain) = match b.answer {
            BlockAnswer::Address { address } if address.is_unspecified() => (None, false),
            BlockAnswer::Address { address } => (Some(address), false),
            BlockAnswer::Nxdomain => (None, true),
        };
        be.put(leaf("enabled", flag01(b.enabled)))
            .put(leaf("type", codes.join(",")))
            .put(leaf("lists", join(&b.urls, ",")))
            .put(leaf("allowlists", allow.join(",")))
            .put(leaf("blocklists", join(&b.block, ",")))
            .put(leaf("wildcards", join(&b.block_subtrees, ",")))
            .put(leaf("source_nets", join(&b.source_nets, ",")))
            .put_opt("address", address)
            .put(leaf("nxdomain", flag01(nxdomain)))
            .put(leaf("cache_ttl", b.refresh_seconds))
            .put(leaf("description", &b.description));
        e.put(be);
    }
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
        if g.force_down {
            ge.put(leaf("force_down", "1"));
        }
        let t = &g.thresholds;
        for (k, v) in [
            ("latencylow", t.latency_low),
            ("latencyhigh", t.latency_high),
            ("losslow", t.loss_low),
            ("losshigh", t.loss_high),
            ("interval", t.interval),
            ("loss_interval", t.loss_interval),
            ("time_period", t.time_period),
            ("data_length", t.data_length),
        ] {
            ge.put_opt(k, v);
        }
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
