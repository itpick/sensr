//! `interfaces`: logical assignments, devices and addressing (`interfaces.php`,
//! `interfaces.inc`).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;

use sensr_schema::Document;
use sensr_schema::fields::{DeviceName, HexBytes, Hostname, InterfaceId, MacAddr};
use sensr_schema::ipnet::{Ipv4Net, Ipv6Net};
use sensr_schema::models::firewall::InterfaceGroup;
use sensr_schema::models::interfaces::{
    DhcpClientId, DhcpOptionValue, DhcpSendOption, Interface, InterfaceRole, Ipv4Config,
    Ipv6Config, Vlan, VlanProtocol,
};

use super::ImportOptions;
use super::common::{description, list, parse_or_warn};
use crate::mapper::{MapContext, Mapper};
use crate::report::Severity;
use crate::tree::Element;

pub struct InterfacesMapper {
    pub options: Arc<ImportOptions>,
    /// VLAN devices from `vlans`, by device name, waiting for their assignment.
    pub vlans: RefCell<BTreeMap<String, Vlan>>,
    /// The global DHCPv6 client settings, copied into every DHCPv6 interface.
    pub dhcp6: RefCell<Dhcp6Globals>,
}

/// `OPNsense/Interfaces/settings` (and the legacy `system/ipv6duid`): the
/// DHCPv6 client's DUID and release behaviour, global in OPNsense.
#[derive(Debug, Default)]
pub struct Dhcp6Globals {
    duid: Option<HexBytes>,
    no_release: bool,
}

impl InterfacesMapper {
    pub fn new(options: Arc<ImportOptions>) -> Self {
        Self {
            options,
            vlans: RefCell::default(),
            dhcp6: RefCell::default(),
        }
    }

    /// The Linux name for an OPNsense device name, with a note when it is kept.
    fn device<'doc>(
        &self,
        ctx: &mut MapContext<'doc>,
        at: &'doc Element,
        name: &str,
    ) -> Option<DeviceName> {
        if let Some(d) = self.options.devices.get(name.trim()) {
            return Some(d.clone());
        }
        let d: DeviceName = parse_or_warn(ctx, at, name, "device")?;
        // VLAN and WireGuard devices are created by sensr; only hardware needs assigning.
        let virtual_device = self.vlans.borrow().contains_key(d.as_str())
            || d.as_str()
                .strip_prefix("wg")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if !virtual_device {
            ctx.warn(
                at,
                Severity::Info,
                format!("device {d} keeps its OPNsense name; assign the Linux device during installation"),
            );
        }
        Some(d)
    }

    fn vlans<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>) {
        for v in ctx.children(s, "vlan") {
            let Some(parent_el) = ctx.child(v, "if") else {
                continue;
            };
            let Some(parent) = self.device(ctx, parent_el, &parent_el.text()) else {
                continue;
            };
            let Some(tag) = ctx.parse::<u16>(v, "tag") else {
                continue;
            };
            let pcp = ctx.parse::<u8>(v, "pcp").unwrap_or(0);
            let protocol = match ctx.text(v, "proto").as_deref().map(str::trim) {
                None | Some("" | "802.1q") => VlanProtocol::Dot1Q,
                Some("802.1ad") => VlanProtocol::Dot1Ad,
                Some(other) => {
                    ctx.warn(
                        v,
                        Severity::Invalid,
                        format!("VLAN protocol {other:?} not imported"),
                    );
                    continue;
                }
            };
            let Some(name) = ctx.non_empty(v, "vlanif") else {
                continue;
            };
            // The description belongs to the assignment in sensr; the device's own one
            // is dropped only when the interface has one.
            if let Some(d) = v.child("descr") {
                ctx.consume(d);
            }
            self.vlans.borrow_mut().insert(
                name,
                Vlan {
                    parent,
                    tag,
                    pcp,
                    protocol,
                },
            );
        }
    }
}

impl InterfacesMapper {
    /// `OPNsense/Interfaces/settings`: the DHCPv6 DUID and "do not release".
    fn settings<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        // `is_ipv6_allowed()`: this setting replaced `system/ipv6allow`
        // (migration SET1_0_0, negated); when the section exists it wins.
        out.system.ipv6_allow = !set(ctx, s, "disableipv6");
        ctx.defaults(s, &[("disableipv6", "0")]);
        let mut g = self.dhcp6.borrow_mut();
        if let Some(d) = ctx.non_empty(s, "dhcp6_duid") {
            g.duid = parse_duid(ctx, s, &d);
        }
        g.no_release = ctx.bool01(s, "dhcp6_norelease");
        if let Some(t) = ctx.text(s, "dhcp6_ratimeout")
            && !matches!(t.trim(), "" | "10")
        {
            ctx.warn(
                s,
                Severity::Info,
                format!("DHCPv6 RA timeout {t}: sensr's client solicits right away, without waiting for a router advertisement"),
            );
        }
        if ctx.bool01(s, "dhcp6_debug") {
            ctx.warn(
                s,
                Severity::Info,
                "DHCPv6 debug logging: networkd's client logs at its own level (SYSTEMD_LOG_LEVEL)",
            );
        }
    }

    /// Legacy `system/ipv6duid`, used when the MVC setting is empty.
    fn legacy_duid<'doc>(&self, e: &'doc Element, ctx: &mut MapContext<'doc>) {
        ctx.consume_subtree(e);
        let t = e.text();
        if t.trim().is_empty() {
            return;
        }
        let mut g = self.dhcp6.borrow_mut();
        if g.duid.is_none() {
            g.duid = parse_duid(ctx, e, &t);
        }
    }
}

/// An OPNsense DUID (`00:01:00:01:...`, the type first; `DUIDField` also
/// accepts single-digit groups).
fn parse_duid(ctx: &mut MapContext<'_>, at: &Element, text: &str) -> Option<HexBytes> {
    let padded = text
        .trim()
        .split(':')
        .map(|p| format!("{p:0>2}"))
        .collect::<Vec<_>>()
        .join(":");
    parse_or_warn::<HexBytes>(ctx, at, &padded, "DUID")
}

/// The dhclient protocol timings OPNsense's "advanced" mode writes;
/// networkd's client has its own fixed backoff (1 s doubling to 64 s).
const DHCP4_TIMINGS: &[(&str, &str)] = &[
    ("adv_dhcp_pt_timeout", "timeout"),
    ("adv_dhcp_pt_retry", "retry"),
    ("adv_dhcp_pt_select_timeout", "select-timeout"),
    ("adv_dhcp_pt_reboot", "reboot"),
    ("adv_dhcp_pt_backoff_cutoff", "backoff-cutoff"),
    ("adv_dhcp_pt_initial_interval", "initial-interval"),
];

/// DHCPv4 client fields of an interface that is not a DHCP client: inert in
/// OPNsense too (the form keeps them when the type changes).
const DHCP4_FIELDS: &[&str] = &[
    "alias-address",
    "alias-subnet",
    "adv_dhcp_pt_timeout",
    "adv_dhcp_pt_retry",
    "adv_dhcp_pt_select_timeout",
    "adv_dhcp_pt_reboot",
    "adv_dhcp_pt_backoff_cutoff",
    "adv_dhcp_pt_initial_interval",
    "adv_dhcp_pt_values",
    "adv_dhcp_send_options",
    "adv_dhcp_request_options",
    "adv_dhcp_required_options",
    "adv_dhcp_option_modifiers",
    "adv_dhcp_config_advanced",
    "adv_dhcp_config_file_override",
    "adv_dhcp_config_file_override_path",
    "dhcp_send_options",
    "dhcp_request_options",
    "dhcprejectfrom",
    "dhcphonourmtu",
    "dhcpvlanprio",
];

/// The DHCPv6 client's advanced statements; empty means defaults.
const DHCP6_DEFAULTS: &[(&str, &str)] = &[
    ("adv_dhcp6_authentication_statement_algorithm", ""),
    ("adv_dhcp6_authentication_statement_authname", ""),
    ("adv_dhcp6_authentication_statement_protocol", ""),
    ("adv_dhcp6_authentication_statement_rdm", ""),
    ("adv_dhcp6_config_advanced", ""),
    ("adv_dhcp6_config_file_override", ""),
    ("adv_dhcp6_config_file_override_path", ""),
    ("adv_dhcp6_id_assoc_statement_address", ""),
    ("adv_dhcp6_id_assoc_statement_address_enable", ""),
    ("adv_dhcp6_id_assoc_statement_address_id", ""),
    ("adv_dhcp6_id_assoc_statement_address_pltime", ""),
    ("adv_dhcp6_id_assoc_statement_address_vltime", ""),
    ("adv_dhcp6_id_assoc_statement_prefix", ""),
    ("adv_dhcp6_id_assoc_statement_prefix_enable", ""),
    ("adv_dhcp6_id_assoc_statement_prefix_id", ""),
    ("adv_dhcp6_id_assoc_statement_prefix_pltime", ""),
    ("adv_dhcp6_id_assoc_statement_prefix_vltime", ""),
    ("adv_dhcp6_interface_statement_information_only_enable", ""),
    ("adv_dhcp6_interface_statement_request_options", ""),
    ("adv_dhcp6_interface_statement_script", ""),
    ("adv_dhcp6_interface_statement_send_options", ""),
    ("adv_dhcp6_key_info_statement_expire", ""),
    ("adv_dhcp6_key_info_statement_keyid", ""),
    ("adv_dhcp6_key_info_statement_keyname", ""),
    ("adv_dhcp6_key_info_statement_realm", ""),
    ("adv_dhcp6_key_info_statement_secret", ""),
    ("adv_dhcp6_prefix_interface_statement_sla_len", ""),
    ("adv_dhcp6_prefix_selected_interface", ""),
];

impl Mapper<Document> for InterfacesMapper {
    fn name(&self) -> &'static str {
        "interfaces"
    }

    fn sections(&self) -> &'static [&'static str] {
        // VLAN devices first, so assignments can pick them up; groups last,
        // their members are interfaces.
        &[
            "vlans",
            "OPNsense/Interfaces/settings",
            "system/ipv6duid",
            "interfaces",
            "ifgroups",
        ]
    }

    fn map<'doc>(&self, s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
        if s.name == "vlans" {
            self.vlans(s, ctx);
            return;
        }
        if s.name == "ifgroups" {
            ifgroups(s, ctx, out);
            return;
        }
        if s.name == "settings" {
            self.settings(s, ctx, out);
            return;
        }
        if s.name == "ipv6duid" {
            self.legacy_duid(s, ctx);
            return;
        }
        // Two passes: addressing that tracks another interface needs the other
        // interface's id to exist, whatever the document order.
        let mut pending = Vec::new();
        for i in s.elements() {
            ctx.consume(i);
            if i.child("internal_dynamic")
                .is_some_and(|c| c.text().trim() == "1")
            {
                ctx.consume_subtree(i);
                if i.child("type").is_some_and(|t| t.text().trim() == "group")
                    && let Ok(name) = i.name.parse::<InterfaceId>()
                {
                    // Plugins' automatic groups (`wireguard`, `openvpn`): rules
                    // may name them. The WireGuard one holds every instance.
                    dynamic_group(name, i, ctx, out);
                    continue;
                }
                // lo0 is created by OPNsense itself; sensr has its own loopback.
                ctx.warn(
                    i,
                    Severity::Info,
                    format!("dynamic interface {} is not imported", i.name),
                );
                continue;
            }
            let Some(id) = parse_or_warn::<InterfaceId>(ctx, i, &i.name, "interface id") else {
                continue;
            };
            pending.push((id, i));
        }
        for (id, i) in &pending {
            if let Some(iface) = self.map_interface(id, i, ctx) {
                out.interfaces.insert(id.clone(), iface);
            }
        }
        let mut vlans = std::mem::take(&mut *self.vlans.borrow_mut());
        for iface in out.interfaces.0.values_mut() {
            iface.vlan = vlans.remove(iface.device.as_str());
        }
        for (name, _) in vlans {
            ctx.warn(
                s,
                Severity::Degraded,
                format!("VLAN device {name} is not assigned to an interface; not imported"),
            );
        }
        for (id, i) in &pending {
            let ipv6 = map_ipv6(i, ctx, out, &self.dhcp6.borrow());
            // Leftover form fields of modes not in use are inert in OPNsense too.
            if !matches!(ipv6, Ipv6Config::Track { .. }) {
                for f in ["track6-interface", "track6-prefix-id"] {
                    if let Some(c) = i.child(f) {
                        ctx.consume_subtree(c);
                    }
                }
            }
            ctx.defaults(
                i,
                &[
                    ("subnet", ""),
                    ("subnetv6", ""),
                    ("gateway", ""),
                    ("gatewayv6", ""),
                    ("ipaddrv6", ""),
                    ("dhcphostname", ""),
                ],
            );
            if let Some(iface) = out.interfaces.0.get_mut(id) {
                iface.ipv6 = ipv6;
                // dhclient's `vlan-pcp` tags frames on a vlan(4) device, or
                // priority-tags them (VID 0) on a plain NIC, which sensr
                // does not create.
                if iface.vlan.is_none()
                    && let Ipv4Config::Dhcp { vlan_priority, .. } = &mut iface.ipv4
                    && let Some(p) = vlan_priority.take()
                {
                    let at = i.child("dhcpvlanprio").unwrap_or(i);
                    ctx.warn(
                        at,
                        Severity::Degraded,
                        format!("DHCP VLAN priority {p} on {}, which is not a VLAN: sensr sends untagged requests (priority-tagged VID 0 frames are not supported)", iface.device),
                    );
                }
            }
        }
    }

    fn expected_unmapped(&self) -> &'static [(&'static str, &'static str)] {
        &[
            ("interfaces/*/lock", "web GUI deletion lock"),
            (
                "OPNsense/Interfaces/settings/disablechecksumoffloading",
                "FreeBSD NIC offload tuning; Linux keeps the driver's offloads",
            ),
            (
                "OPNsense/Interfaces/settings/disablesegmentationoffloading",
                "FreeBSD NIC offload tuning; Linux keeps the driver's offloads",
            ),
            (
                "OPNsense/Interfaces/settings/disablelargereceiveoffloading",
                "FreeBSD NIC offload tuning; Linux keeps the driver's offloads",
            ),
            (
                "OPNsense/Interfaces/settings/disablevlanhwfilter",
                "FreeBSD VLAN hardware filter tuning; Linux keeps the driver's setting",
            ),
        ]
    }
}

/// An automatic group of a plugin (`interfaces/<name>` with `type` group).
fn dynamic_group(name: InterfaceId, i: &Element, ctx: &mut MapContext<'_>, out: &mut Document) {
    let wireguard = name.as_str() == "wireguard";
    if !wireguard {
        ctx.warn(
            i,
            Severity::Info,
            format!(
                "interface group {name} is imported without members; sensr has no {name} devices"
            ),
        );
    }
    if out.firewall.group(&name).is_some() {
        return;
    }
    let id = super::common::stable_uuid(&ctx.xpath(i));
    out.firewall.groups.insert(
        id,
        InterfaceGroup {
            description: i.child("descr").and_then(|d| d.text().trim().parse().ok()),
            name,
            members: Vec::new(),
            wireguard,
            sequence: 0,
            hidden: false,
        },
    );
}

/// Firewall › Groups (`ifgroups/ifgroupentry`, `Firewall/Group.xml`).
fn ifgroups<'doc>(s: &'doc Element, ctx: &mut MapContext<'doc>, out: &mut Document) {
    ctx.consume(s);
    for e in s.elements() {
        ctx.consume(e);
        let Some(name) = ctx
            .non_empty(e, "ifname")
            .and_then(|n| parse_or_warn::<InterfaceId>(ctx, e, &n, "group name"))
        else {
            ctx.release(e);
            continue;
        };
        let mut members = Vec::new();
        if let Some(m) = e.child("members") {
            ctx.consume(m);
            // `,` since the MVC model; older configs separate with spaces
            for n in list(&m.text(), &[',', ' ']) {
                match n.parse::<InterfaceId>() {
                    Ok(id) if out.interfaces.get(&id).is_some() => members.push(id),
                    _ => ctx.warn(
                        m,
                        Severity::Degraded,
                        format!(
                            "group {name}: member {n:?} is not an imported interface; left out"
                        ),
                    ),
                }
            }
        }
        let sequence = ctx.parse::<u32>(e, "sequence").unwrap_or(0);
        let hidden = ctx.flag(e, "nogroup");
        let descr = ctx.text(e, "descr");
        let description = description(ctx, e, descr);
        if out.firewall.group(&name).is_some() {
            ctx.warn(
                e,
                Severity::Degraded,
                format!("group {name} is defined twice; the first one is kept"),
            );
            continue;
        }
        let id = super::common::item_uuid(ctx, e);
        out.firewall.groups.insert(
            id,
            InterfaceGroup {
                name,
                members,
                wireguard: false,
                sequence,
                hidden,
                description,
            },
        );
    }
}

impl InterfacesMapper {
    fn map_interface<'doc>(
        &self,
        id: &InterfaceId,
        i: &'doc Element,
        ctx: &mut MapContext<'doc>,
    ) -> Option<Interface> {
        let dev_el = ctx.child(i, "if")?;
        let device = self.device(ctx, dev_el, &dev_el.text())?;
        let mut spoof_mac = None;
        if let Some(c) = i.child("spoofmac") {
            ctx.consume(c);
            let t = c.text();
            if !t.trim().is_empty() {
                spoof_mac = parse_or_warn::<MacAddr>(ctx, c, &t, "MAC address");
            }
        }
        let ipv4 = map_ipv4(i, ctx, spoof_mac);
        let role = match id.as_str() {
            "wan" => InterfaceRole::Wan,
            "lan" => InterfaceRole::Lan,
            _ => match &ipv4 {
                Ipv4Config::Dhcp { .. }
                | Ipv4Config::Static {
                    gateway: Some(_), ..
                } => InterfaceRole::Wan,
                Ipv4Config::Static { gateway: None, .. } => InterfaceRole::Lan,
                Ipv4Config::None => InterfaceRole::Other,
            },
        };
        let descr = ctx.text(i, "descr");
        let mut iface = Interface::new(device, role);
        iface.enabled = ctx.flag(i, "enable");
        iface.description = description(ctx, i, descr);
        iface.spoof_mac = spoof_mac;
        iface.mtu = ctx.parse(i, "mtu");
        iface.block_private = ctx.flag(i, "blockpriv");
        iface.block_bogons = ctx.flag(i, "blockbogons");
        iface.ipv4 = ipv4;
        ctx.defaults(i, &[("media", ""), ("mediaopt", ""), ("mss", "")]);
        Some(iface)
    }
}

fn map_ipv4<'doc>(
    i: &'doc Element,
    ctx: &mut MapContext<'doc>,
    spoof_mac: Option<MacAddr>,
) -> Ipv4Config {
    let mode = i.child("ipaddr").map(|e| e.text());
    if mode.as_deref().map(str::trim) != Some("dhcp") {
        for f in DHCP4_FIELDS {
            if let Some(c) = i.child(f) {
                ctx.consume_subtree(c);
            }
        }
    }
    let Some(addr_el) = i.child("ipaddr") else {
        return Ipv4Config::None;
    };
    let addr = addr_el.text();
    match addr.trim() {
        "" => {
            ctx.consume(addr_el);
            Ipv4Config::None
        }
        "dhcp" => {
            ctx.consume(addr_el);
            map_dhcp4(i, ctx, spoof_mac)
        }
        literal => {
            let Ok(ip) = literal.parse::<std::net::Ipv4Addr>() else {
                // pppoe, pptp, l2tp and friends: left unconsumed, so reported.
                return Ipv4Config::None;
            };
            ctx.consume(addr_el);
            let prefix = ctx.parse::<u8>(i, "subnet").unwrap_or(32);
            match Ipv4Net::new(ip, prefix) {
                Ok(address) => Ipv4Config::Static {
                    address,
                    gateway: None,
                },
                Err(e) => {
                    ctx.warn(
                        addr_el,
                        Severity::Invalid,
                        format!("{literal}/{prefix}: {e}"),
                    );
                    Ipv4Config::None
                }
            }
        }
    }
}

/// A field the DHCP code tests with PHP `!empty()`: set, non-empty, not `0`.
fn set<'doc>(ctx: &mut MapContext<'doc>, i: &'doc Element, name: &str) -> bool {
    let Some(c) = i.child(name) else {
        return false;
    };
    if matches!(c.text().trim(), "" | "0") {
        // unset; the defaults lists consume it
        return false;
    }
    ctx.consume_subtree(c);
    true
}

/// The DHCPv4 client (`interface_dhcp_configure`): the basic form, or the
/// "advanced" one whose dhclient.conf statements replace the basic ones.
fn map_dhcp4<'doc>(
    i: &'doc Element,
    ctx: &mut MapContext<'doc>,
    spoof_mac: Option<MacAddr>,
) -> Ipv4Config {
    let hostname: Option<Hostname> = match ctx.non_empty(i, "dhcphostname") {
        Some(h) => parse_or_warn(ctx, i, &h, "DHCP host name"),
        None => None,
    };
    let mut reject_from = Vec::new();
    if let Some(r) = i.child("dhcprejectfrom") {
        ctx.consume(r);
        for a in list(&r.text(), &[',', ' ']) {
            reject_from.extend(parse_or_warn::<std::net::Ipv4Addr>(ctx, r, &a, "address"));
        }
    }
    let use_mtu = set(ctx, i, "dhcphonourmtu");
    let vlan_priority = ctx.parse::<u8>(i, "dhcpvlanprio").filter(|p| {
        if *p > 7 {
            ctx.warn(
                i,
                Severity::Invalid,
                format!("DHCP VLAN priority {p} not imported"),
            );
        }
        *p <= 7
    });
    let advanced = set(ctx, i, "adv_dhcp_config_advanced");
    let file_override = set(ctx, i, "adv_dhcp_config_file_override");
    let path = ctx.text(i, "adv_dhcp_config_file_override_path");
    if file_override {
        ctx.warn(
            i,
            Severity::Degraded,
            format!("DHCP client configuration file override {:?}: the file is not part of config.xml; sensr uses the interface's other DHCP settings", path.unwrap_or_default()),
        );
    }
    // unset flags (`!empty()` is false for these)
    let unset = [
        "adv_dhcp_config_advanced",
        "adv_dhcp_config_file_override",
        "dhcphonourmtu",
    ];
    for f in unset {
        ctx.defaults(i, &[(f, "0")]);
    }
    // UI preset buttons, not settings
    if let Some(c) = i.child("adv_dhcp_pt_values") {
        ctx.consume_subtree(c);
    }
    let alias = ctx.non_empty(i, "alias-address");
    let alias_subnet = ctx.text(i, "alias-subnet");
    if let Some(a) = alias {
        ctx.warn(
            i,
            Severity::Degraded,
            format!(
                "DHCP alias address {a}/{}: not imported; add it as a virtual IP",
                alias_subnet.as_deref().unwrap_or("32")
            ),
        );
    }

    let mut c = Dhcp4Client {
        hostname,
        spoof_mac,
        client_id: DhcpClientId::Mac,
        vendor_class: None,
        user_class: Vec::new(),
        send_options: Vec::new(),
        request_options: Vec::new(),
    };
    // Basic mode's own option lists, one statement per line.
    for (field, send) in [("dhcp_send_options", true), ("dhcp_request_options", false)] {
        if let Some(e) = ctx.child(i, field) {
            ctx.consume_subtree(e);
            for line in e.text().lines().filter(|l| !l.trim().is_empty()) {
                let stmts = split_statements(line);
                match (send, stmts.into_iter().next()) {
                    (true, Some(st)) => c.send(ctx, e, &st),
                    (false, Some(st)) => c.request(ctx, e, &Token::join(&st)),
                    _ => {}
                }
            }
        }
    }
    let adv = [
        "adv_dhcp_send_options",
        "adv_dhcp_request_options",
        "adv_dhcp_required_options",
        "adv_dhcp_option_modifiers",
    ];
    if advanced {
        if let Some(e) = ctx.child(i, "adv_dhcp_send_options") {
            ctx.consume_subtree(e);
            for st in split_statements(&e.text()) {
                c.send(ctx, e, &st);
            }
        }
        if let Some(e) = ctx.child(i, "adv_dhcp_request_options") {
            ctx.consume_subtree(e);
            c.request(ctx, e, &e.text());
        }
        if let Some(t) = ctx.non_empty(i, "adv_dhcp_required_options") {
            ctx.warn(
                i,
                Severity::Degraded,
                format!("DHCP required options {t:?}: networkd's client cannot refuse leases that lack options; leases are accepted without them"),
            );
        }
        if let Some(t) = ctx.non_empty(i, "adv_dhcp_option_modifiers") {
            ctx.warn(
                i,
                Severity::Degraded,
                format!("DHCP option modifiers {t:?} (default/supersede/prepend/append) are not supported by networkd's client; not imported"),
            );
        }
        for (field, keyword) in DHCP4_TIMINGS {
            if let Some(t) = ctx.non_empty(i, field) {
                ctx.warn(
                    i,
                    Severity::Degraded,
                    format!("DHCP protocol timing {keyword} {}: networkd's client has fixed timings (retries from 1 s doubling to 64 s); not imported", t.trim()),
                );
            }
        }
    } else {
        // Without "advanced", OPNsense writes none of these.
        for f in adv.iter().chain(DHCP4_TIMINGS.iter().map(|(f, _)| f)) {
            if let Some(e) = i.child(f) {
                ctx.consume_subtree(e);
            }
        }
        if let Some(h) = &c.hostname {
            ctx.warn(
                i,
                Severity::Degraded,
                format!("DHCP host name {h}: OPNsense also sends it as the client identifier (option 61); sensr sends type 1 plus the interface MAC there, as OPNsense does without a host name"),
            );
        }
    }
    Ipv4Config::Dhcp {
        hostname: c.hostname,
        reject_from,
        use_gateway: true,
        client_id: c.client_id,
        vendor_class: c.vendor_class,
        user_class: c.user_class,
        send_options: c.send_options,
        request_options: c.request_options,
        vlan_priority,
        use_mtu,
    }
}

/// The DHCPv4 client options being collected from dhclient statements.
struct Dhcp4Client {
    hostname: Option<Hostname>,
    spoof_mac: Option<MacAddr>,
    client_id: DhcpClientId,
    vendor_class: Option<String>,
    user_class: Vec<String>,
    send_options: Vec<DhcpSendOption>,
    request_options: Vec<u8>,
}

/// One `send`/`request` argument: its text and whether it was quoted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Token {
    text: String,
    quoted: bool,
}

impl Token {
    fn join(tokens: &[Token]) -> String {
        tokens
            .iter()
            .map(|t| t.text.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// OPNsense's option list syntax (`interfaces_dhcp_split`): statements
/// separated by commas outside quotes (`\,` is a literal comma), each a
/// list of whitespace-separated words or quoted strings. Quotes,
/// backslashes and semicolons inside arguments are dropped, as OPNsense
/// does before writing dhclient.conf.
fn split_statements(text: &str) -> Vec<Vec<Token>> {
    let mut stmts = Vec::new();
    let mut cur: Vec<Token> = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut chars = text.chars().peekable();
    let clean = |s: &str| s.replace(['\\', '"', ';'], "");
    let flush = |word: &mut String, in_word: &mut bool, cur: &mut Vec<Token>| {
        if *in_word {
            cur.push(Token {
                text: clean(word),
                quoted: false,
            });
            word.clear();
            *in_word = false;
        }
    };
    while let Some(ch) = chars.next() {
        match ch {
            '"' if !in_word => {
                let mut q = String::new();
                let mut closed = false;
                for c2 in chars.by_ref() {
                    if c2 == '"' {
                        closed = true;
                        break;
                    }
                    q.push(c2);
                }
                if closed {
                    cur.push(Token {
                        text: clean(&q),
                        quoted: true,
                    });
                } else {
                    // OPNsense drops a statement with an unbalanced quote
                    cur.clear();
                }
            }
            '\\' if chars.peek() == Some(&',') => {
                chars.next();
                word.push(',');
                in_word = true;
            }
            ',' => {
                flush(&mut word, &mut in_word, &mut cur);
                if !cur.is_empty() {
                    stmts.push(std::mem::take(&mut cur));
                }
            }
            c if c.is_whitespace() => flush(&mut word, &mut in_word, &mut cur),
            c => {
                word.push(c);
                in_word = true;
            }
        }
    }
    flush(&mut word, &mut in_word, &mut cur);
    if !cur.is_empty() {
        stmts.push(cur);
    }
    stmts
}

/// dhclient's colon-separated hex (`1:2:f3`, one or two digits a byte).
fn hex_bytes(text: &str) -> Option<HexBytes> {
    if !text.contains(':') {
        return None;
    }
    let parts: Vec<&str> = text.split(':').collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || p.len() > 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    parts
        .iter()
        .map(|p| format!("{p:0>2}"))
        .collect::<Vec<_>>()
        .join(":")
        .parse()
        .ok()
}

/// dhclient option names sensr understands, with their codes.
const DHCP4_OPTION_NAMES: &[(&str, u8)] = &[
    ("subnet-mask", 1),
    ("time-offset", 2),
    ("routers", 3),
    ("time-servers", 4),
    ("domain-name-servers", 6),
    ("log-servers", 7),
    ("host-name", 12),
    ("domain-name", 15),
    ("root-path", 17),
    ("interface-mtu", 26),
    ("broadcast-address", 28),
    ("static-routes", 33),
    ("nis-domain", 40),
    ("nis-servers", 41),
    ("ntp-servers", 42),
    ("vendor-encapsulated-options", 43),
    ("netbios-name-servers", 44),
    ("netbios-scope", 47),
    ("dhcp-requested-address", 50),
    ("dhcp-lease-time", 51),
    ("dhcp-message-type", 53),
    ("dhcp-server-identifier", 54),
    ("dhcp-parameter-request-list", 55),
    ("dhcp-max-message-size", 57),
    ("dhcp-renewal-time", 58),
    ("dhcp-rebinding-time", 59),
    ("vendor-class-identifier", 60),
    ("dhcp-client-identifier", 61),
    ("tftp-server-name", 66),
    ("bootfile-name", 67),
    ("user-class", 77),
    ("fqdn", 81),
    ("domain-search", 119),
    ("classless-routes", 121),
    ("classless-static-routes", 121),
    ("ms-classless-static-routes", 249),
];

/// Integer widths of the numeric options a `send` may carry unquoted.
const DHCP4_INT_WIDTHS: &[(u8, u8)] = &[(2, 32), (26, 16), (51, 32), (57, 16), (58, 32), (59, 32)];

/// `routers` → 3, `option-121` → 121.
fn option_code(name: &str) -> Option<u8> {
    let n = name.trim().to_ascii_lowercase();
    if let Some(num) = n.strip_prefix("option-") {
        return num.parse().ok();
    }
    DHCP4_OPTION_NAMES
        .iter()
        .find(|(k, _)| *k == n)
        .map(|(_, c)| *c)
}

/// dhclient.conf value substitutions (`DHCP_Config_File_Substitutions`):
/// `{hostname}` and the `{mac_addr_*}` forms, from what the import knows.
/// `Err` names the placeholder that cannot be resolved.
fn substitute(
    text: &str,
    hostname: Option<&Hostname>,
    mac: Option<MacAddr>,
) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let Some(len) = rest[start..].find('}') else {
            out.push_str(&rest[start..]);
            return Ok(out);
        };
        let key = &rest[start + 1..start + len];
        rest = &rest[start + len + 1..];
        if key == "hostname" {
            out.push_str(
                &hostname
                    .map(ToString::to_string)
                    .ok_or_else(|| "{hostname}".to_owned())?,
            );
            continue;
        }
        let (hex, tail) = if let Some(t) = key.strip_prefix("mac_addr_ascii") {
            (false, t)
        } else if let Some(t) = key.strip_prefix("mac_addr_hex") {
            (true, t)
        } else {
            return Err(format!("{{{key}}}"));
        };
        let mut chars = tail.chars();
        let case = chars.next();
        let delim: String = chars.collect();
        if !matches!(case, Some('U' | 'L')) || !matches!(delim.as_str(), "" | " " | ":" | "-" | ".")
        {
            return Err(format!("{{{key}}}"));
        }
        let Some(mac) = mac else {
            return Err(format!("{{{key}}}"));
        };
        let ascii = mac.to_string();
        let ascii = if case == Some('U') {
            ascii.to_ascii_uppercase()
        } else {
            ascii.to_ascii_lowercase()
        };
        let parts: Vec<String> = if hex {
            // each character of the textual MAC as its hex code
            ascii
                .replace(':', "")
                .bytes()
                .map(|b| format!("{b:02x}"))
                .collect()
        } else {
            ascii.split(':').map(str::to_owned).collect()
        };
        out.push_str(&parts.join(&delim));
    }
    out.push_str(rest);
    Ok(out)
}

impl Dhcp4Client {
    /// One `send <option> <value>` statement.
    fn send(&mut self, ctx: &mut MapContext<'_>, at: &Element, st: &[Token]) {
        let stmt = Token::join(st);
        let Some((name, args)) = st.split_first() else {
            return;
        };
        let Some(code) = option_code(&name.text) else {
            ctx.warn(
                at,
                Severity::Degraded,
                format!("DHCP send option {stmt:?}: unknown option name (use option-<code>); not imported"),
            );
            return;
        };
        let [arg] = args else {
            ctx.warn(
                at,
                Severity::Degraded,
                format!("DHCP send option {stmt:?}: only single-value options are supported; not imported"),
            );
            return;
        };
        let text = match substitute(&arg.text, self.hostname.as_ref(), self.spoof_mac) {
            Ok(t) => t,
            Err(placeholder) => {
                ctx.warn(
                    at,
                    Severity::Degraded,
                    format!("DHCP send option {stmt:?}: {placeholder} has no value known at import (set spoof_mac or the host name); not imported"),
                );
                return;
            }
        };
        let value = if arg.quoted {
            DhcpOptionValue::String(text)
        } else if let Some(h) = hex_bytes(&text) {
            DhcpOptionValue::Hex(h)
        } else if let Ok(a) = text.parse::<std::net::Ipv4Addr>() {
            DhcpOptionValue::Ipv4(a)
        } else if let Ok(n) = text.parse::<u32>() {
            match DHCP4_INT_WIDTHS
                .iter()
                .find(|(c, _)| *c == code)
                .map(|(_, w)| *w)
            {
                Some(16) if n <= u32::from(u16::MAX) => DhcpOptionValue::Uint16(n as u16),
                Some(32) => DhcpOptionValue::Uint32(n),
                _ => {
                    ctx.warn(
                        at,
                        Severity::Degraded,
                        format!("DHCP send option {stmt:?}: the width of option {code}'s number is unknown (send it as hex bytes); not imported"),
                    );
                    return;
                }
            }
        } else {
            DhcpOptionValue::String(text)
        };
        let as_text = |v: &DhcpOptionValue| match v {
            DhcpOptionValue::String(t) => Some(t.clone()),
            DhcpOptionValue::Hex(h) => String::from_utf8(h.as_bytes().to_vec()).ok(),
            _ => None,
        };
        match code {
            61 => {
                let mac_id = match (&value, self.spoof_mac) {
                    (DhcpOptionValue::Hex(h), Some(mac)) => {
                        h.as_bytes().first() == Some(&1) && h.as_bytes()[1..] == mac.octets()
                    }
                    _ => false,
                };
                if mac_id {
                    self.client_id = DhcpClientId::Mac;
                } else {
                    ctx.warn(
                        at,
                        Severity::Degraded,
                        format!("DHCP client identifier {stmt:?}: networkd sends type 1 plus the interface's MAC (or a DUID), not an arbitrary identifier; sensr sends the MAC-based one (set spoof_mac to the MAC it should carry)"),
                    );
                }
            }
            12 => match as_text(&value).map(|t| t.parse::<Hostname>()) {
                Some(Ok(h)) if self.hostname.is_none() || self.hostname.as_ref() == Some(&h) => {
                    self.hostname = Some(h);
                }
                _ => ctx.warn(
                    at,
                    Severity::Degraded,
                    format!("DHCP send option {stmt:?}: conflicts with the interface's host name or is not a valid host name; not imported"),
                ),
            },
            60 => match as_text(&value) {
                Some(t) => self.vendor_class = Some(t),
                None => ctx.warn(
                    at,
                    Severity::Degraded,
                    format!("DHCP vendor class {stmt:?}: networkd sends text only; not imported"),
                ),
            },
            77 => match as_text(&value) {
                Some(t) if !t.contains(char::is_whitespace) && !t.is_empty() => {
                    self.user_class.push(t)
                }
                _ => ctx.warn(
                    at,
                    Severity::Degraded,
                    format!("DHCP user class {stmt:?}: networkd sends single words only; not imported"),
                ),
            },
            50 | 51 | 53 | 54 | 55 | 57 | 0 | 255 => ctx.warn(
                at,
                Severity::Degraded,
                format!("DHCP send option {stmt:?}: networkd's client sets option {code} itself; not imported"),
            ),
            _ => self.send_options.push(DhcpSendOption { code, value }),
        }
    }

    /// A `request` list: option names, comma- or space-separated.
    fn request(&mut self, ctx: &mut MapContext<'_>, at: &Element, text: &str) {
        let mut added = false;
        for name in list(text, &[',', ' ']) {
            match option_code(&name).filter(|c| *c != 0 && *c != 255) {
                Some(c) => {
                    if !self.request_options.contains(&c) {
                        self.request_options.push(c);
                    }
                    added = true;
                }
                None => ctx.warn(
                    at,
                    Severity::Degraded,
                    format!("DHCP request option {name:?}: unknown option name; not imported"),
                ),
            }
        }
        if added {
            ctx.warn(
                at,
                Severity::Info,
                "DHCP request options: dhclient asks for exactly these, networkd adds them to its own list (subnet mask, router, DNS, domain, routes, ...)",
            );
        }
    }
}

fn map_ipv6<'doc>(
    i: &'doc Element,
    ctx: &mut MapContext<'doc>,
    out: &Document,
    globals: &Dhcp6Globals,
) -> Ipv6Config {
    let Some(mode_el) = i.child("ipaddrv6") else {
        return Ipv6Config::None;
    };
    let mode = mode_el.text();
    match mode.trim() {
        "" | "none" => {
            ctx.consume(mode_el);
            Ipv6Config::None
        }
        "dhcp6" => {
            ctx.consume(mode_el);
            let prefix_delegation_len = match ctx.non_empty(i, "dhcp6-ia-pd-len").as_deref() {
                None | Some("none") => None,
                // OPNsense stores the number of bits below /64: 8 means a /56.
                Some(bits) => match bits.trim().parse::<u8>() {
                    Ok(b) if b <= 32 => Some(64 - b),
                    _ => {
                        ctx.warn(
                            i,
                            Severity::Invalid,
                            format!("prefix delegation size {bits:?} not imported"),
                        );
                        None
                    }
                },
            };
            let send_prefix_hint = ctx.flag(i, "dhcp6-ia-pd-send-hint");
            let prefix_only = ctx.flag(i, "dhcp6prefixonly");
            let rapid_commit = set(ctx, i, "dhcp6_rapid_commit");
            // stored as a decimal number, entered as hex in the form
            let prefix_id = ctx
                .parse::<u16>(i, "dhcp6-prefix-id")
                .filter(|_| prefix_delegation_len.is_some());
            if let Some(v) = ctx.non_empty(i, "dhcp6vlanprio") {
                ctx.warn(
                    i,
                    Severity::Degraded,
                    format!("DHCPv6 VLAN priority {}: networkd's DHCPv6 client cannot set a socket priority; requests go out with priority 0", v.trim()),
                );
            }
            if set(ctx, i, "adv_dhcp6_config_advanced")
                || set(ctx, i, "adv_dhcp6_config_file_override")
            {
                ctx.warn(
                    i,
                    Severity::Degraded,
                    "DHCPv6 advanced configuration or file override: dhcp6c statements cannot be expressed for networkd; sensr uses the basic settings (delegation size, hint, prefix only)",
                );
                for (f, _) in DHCP6_DEFAULTS {
                    if let Some(c) = i.child(f) {
                        ctx.consume_subtree(c);
                    }
                }
            }
            if let Some(c) = i.child("dhcp6_norequest_dns")
                && c.text().trim() == "1"
            {
                ctx.consume(c);
                ctx.warn(
                    c,
                    Severity::Degraded,
                    "\"do not request DNS\" is not modelled; DHCPv6-supplied DNS servers follow system.dns_allow_override",
                );
            }
            ctx.defaults(
                i,
                &[
                    ("dhcp6_norequest_dns", "0"),
                    ("dhcp6_rapid_commit", "0"),
                    ("dhcp6vlanprio", ""),
                    ("dhcp6-prefix-id", ""),
                ],
            );
            ctx.defaults(i, DHCP6_DEFAULTS);
            Ipv6Config::Dhcp6 {
                prefix_delegation_len,
                send_prefix_hint,
                prefix_only,
                rapid_commit,
                prefix_id,
                duid: globals.duid.clone(),
                send_release: !globals.no_release,
            }
        }
        "slaac" => {
            ctx.consume(mode_el);
            Ipv6Config::Slaac
        }
        "track6" | "idassoc6" => {
            ctx.consume(mode_el);
            let Some(tracked_el) = ctx.child(i, "track6-interface") else {
                ctx.warn(
                    mode_el,
                    Severity::Invalid,
                    "prefix tracking without a tracked interface",
                );
                return Ipv6Config::None;
            };
            let tracked = tracked_el.text();
            let Some(interface) = super::common::interface_id(out, tracked.trim()) else {
                ctx.warn(
                    tracked_el,
                    Severity::Invalid,
                    format!("tracked interface {tracked:?} is not assigned"),
                );
                return Ipv6Config::None;
            };
            let prefix_id = ctx.parse::<u16>(i, "track6-prefix-id").unwrap_or(0);
            ctx.defaults(i, &[("track6_ifid", ""), ("dhcpd6track6allowoverride", "")]);
            Ipv6Config::Track {
                interface,
                prefix_id,
            }
        }
        literal => {
            let Ok(ip) = literal.parse::<std::net::Ipv6Addr>() else {
                return Ipv6Config::None;
            };
            ctx.consume(mode_el);
            let prefix = ctx.parse::<u8>(i, "subnetv6").unwrap_or(128);
            match Ipv6Net::new(ip, prefix) {
                Ok(address) => Ipv6Config::Static {
                    address,
                    gateway: None,
                },
                Err(e) => {
                    ctx.warn(
                        mode_el,
                        Severity::Invalid,
                        format!("{literal}/{prefix}: {e}"),
                    );
                    Ipv6Config::None
                }
            }
        }
    }
}
