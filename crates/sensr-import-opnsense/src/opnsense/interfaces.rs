//! `interfaces`: logical assignments, devices and addressing (`interfaces.php`,
//! `interfaces.inc`).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::Arc;

use sensr_schema::Document;
use sensr_schema::fields::{DeviceName, InterfaceId, MacAddr};
use sensr_schema::ipnet::{Ipv4Net, Ipv6Net};
use sensr_schema::models::firewall::InterfaceGroup;
use sensr_schema::models::interfaces::{
    Interface, InterfaceRole, Ipv4Config, Ipv6Config, Vlan, VlanProtocol,
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
}

impl InterfacesMapper {
    pub fn new(options: Arc<ImportOptions>) -> Self {
        Self {
            options,
            vlans: RefCell::default(),
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

/// DHCPv4 client tuning OPNsense always writes; empty (or these values) means the
/// client's defaults, which is what sensr's client uses.
const DHCP4_DEFAULTS: &[(&str, &str)] = &[
    ("alias-address", ""),
    ("alias-subnet", "32"),
    ("adv_dhcp_pt_timeout", ""),
    ("adv_dhcp_pt_retry", ""),
    ("adv_dhcp_pt_select_timeout", ""),
    ("adv_dhcp_pt_reboot", ""),
    ("adv_dhcp_pt_backoff_cutoff", ""),
    ("adv_dhcp_pt_initial_interval", ""),
    ("adv_dhcp_pt_values", "SavedCfg"),
    ("adv_dhcp_send_options", ""),
    ("adv_dhcp_request_options", ""),
    ("adv_dhcp_required_options", ""),
    ("adv_dhcp_option_modifiers", ""),
    ("adv_dhcp_config_advanced", ""),
    ("adv_dhcp_config_file_override", ""),
    ("adv_dhcp_config_file_override_path", ""),
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
        &["vlans", "interfaces", "ifgroups"]
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
            let ipv6 = map_ipv6(i, ctx, out);
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
            }
        }
    }

    fn expected_unmapped(&self) -> &'static [(&'static str, &'static str)] {
        &[("interfaces/*/lock", "web GUI deletion lock")]
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
        let ipv4 = map_ipv4(i, ctx);
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
        if let Some(c) = i.child("spoofmac") {
            ctx.consume(c);
            let t = c.text();
            if !t.trim().is_empty() {
                iface.spoof_mac = parse_or_warn::<MacAddr>(ctx, c, &t, "MAC address");
            }
        }
        iface.mtu = ctx.parse(i, "mtu");
        iface.block_private = ctx.flag(i, "blockpriv");
        iface.block_bogons = ctx.flag(i, "blockbogons");
        iface.ipv4 = ipv4;
        ctx.defaults(i, &[("media", ""), ("mediaopt", ""), ("mss", "")]);
        Some(iface)
    }
}

fn map_ipv4<'doc>(i: &'doc Element, ctx: &mut MapContext<'doc>) -> Ipv4Config {
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
            let hostname = match ctx.non_empty(i, "dhcphostname") {
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
            ctx.defaults(i, DHCP4_DEFAULTS);
            Ipv4Config::Dhcp {
                hostname,
                reject_from,
                use_gateway: true,
            }
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

fn map_ipv6<'doc>(i: &'doc Element, ctx: &mut MapContext<'doc>, out: &Document) -> Ipv6Config {
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
                    ("dhcp6vlanprio", ""),
                    ("dhcp6-prefix-id", ""),
                ],
            );
            ctx.defaults(i, DHCP6_DEFAULTS);
            Ipv6Config::Dhcp6 {
                prefix_delegation_len,
                send_prefix_hint,
                prefix_only,
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
