//! System filter rules as data (`filter.lib.inc` `filter_core_rules_system`,
//! `kea_firewall`).
//!
//! Each rule is the exact array upstream registers — same keys, same PHP
//! value types — so labels (`calcRuleHash`) match OPNsense's, and the pf
//! oracle shows what OPNsense would load. Only the conditions around them
//! are code.

use crate::conf;
use crate::conf::{Conf, Value};
use crate::ir::{V4Mode, V6Mode};
use crate::normalize::Context;
use crate::ruleset::Ruleset;

/// Web GUI listener, for anti-lockout and lockout-table rules.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebGui {
    /// HTTPS (default) or plain HTTP
    pub https: bool,
    /// explicit port (`None`: 443/80)
    pub port: Option<u16>,
    /// also listen on 80 and redirect to HTTPS
    pub http_redirect: bool,
}

impl Default for WebGui {
    fn default() -> Self {
        WebGui {
            https: true,
            port: None,
            http_redirect: true,
        }
    }
}

/// Settings that shape the system rules (firewall settings, system
/// settings and the services that register rules).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemSettings {
    /// IPv6 allowed (`system/ipv6allow`)
    pub ipv6_allowed: bool,
    /// log default pass rules
    pub log_default_pass: bool,
    /// log default block rules
    pub log_default_block: bool,
    /// log bogon blocks
    pub log_bogons: bool,
    /// log private-network blocks
    pub log_private: bool,
    /// RFC 4890 ICMPv6 rules (inverse of `no_ipv6_rfc4890_req`)
    pub rfc4890: bool,
    /// block port 0 (inverse of `no_port0_block`)
    pub block_port0: bool,
    /// `<sshlockout>` table rules (inverse of `no_sshlockout`)
    pub sshlockout: bool,
    /// `<virusprot>` table rule (inverse of `no_virusprot`)
    pub virusprot: bool,
    /// anti-lockout rule (inverse of `no_antilockout`)
    pub anti_lockout: bool,
    /// CARP / VRRP in use
    pub carp: bool,
    /// web GUI listener
    pub webgui: WebGui,
    /// SSH port when SSH is enabled
    pub ssh: Option<u16>,
    /// logical interfaces Kea DHCPv4 serves with automatic rules
    pub kea4_interfaces: Vec<String>,
}

impl Default for SystemSettings {
    fn default() -> Self {
        SystemSettings {
            ipv6_allowed: true,
            log_default_pass: false,
            log_default_block: false,
            log_bogons: false,
            log_private: false,
            rfc4890: true,
            block_port0: true,
            sshlockout: true,
            virusprot: true,
            anti_lockout: true,
            carp: false,
            webgui: WebGui::default(),
            ssh: None,
            kea4_interfaces: Vec::new(),
        }
    }
}

const REF_FILTER: &str = "ui/firewall/settings#settings-filter";

/// `filter_core_get_antilockout`: the primary interface (first of `lan`,
/// `optN`, `wan` in natural order) and its sorted management ports.
pub fn anti_lockout(s: &SystemSettings, ctx: &Context<'_>) -> Option<(String, Vec<String>)> {
    if !s.anti_lockout {
        return None;
    }
    let mut names: Vec<&String> = ctx
        .interfaces
        .iter()
        .filter(|(_, i)| !i.r#virtual)
        .map(|(n, _)| n)
        .collect();
    names.sort_by(|a, b| natural_cmp(a, b));
    let iface = names.into_iter().find(|n| {
        *n == "lan"
            || *n == "wan"
            || n.strip_prefix("opt")
                .is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
    })?;
    let mut ports = vec![match s.webgui.port {
        Some(p) => p.to_string(),
        None if s.webgui.https => "443".into(),
        None => "80".into(),
    }];
    if s.webgui.https && s.webgui.http_redirect {
        ports.push("80".into());
    }
    if let Some(p) = s.ssh {
        ports.push(p.to_string());
    }
    // PHP sort(): numeric strings compare as numbers
    ports.sort_by_key(|p| p.parse::<u32>().unwrap_or(u32::MAX));
    Some((iface.clone(), ports))
}

/// PHP `natsort` order for interface names.
fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let split = |s: &str| {
        let i = s.find(|c: char| c.is_ascii_digit()).unwrap_or(s.len());
        (s[..i].to_owned(), s[i..].parse::<u64>().unwrap_or(0))
    };
    split(a).cmp(&split(b))
}

/// Registers every system rule into `rs`, in upstream's order.
pub fn register(rs: &mut Ruleset, s: &SystemSettings, ctx: &Context<'_>) {
    let pass = conf! { "type" => "pass", "log" => s.log_default_pass, "disablereplyto" => 1i64 };
    let block = conf! { "type" => "block", "log" => s.log_default_block, "disablereplyto" => 1i64 };
    let v6_off = !s.ipv6_allowed;
    let mut reg = |prio: u32, c: Conf, d: Option<&Conf>| rs.register_filter(prio, &c, d, ctx);

    reg(
        1,
        conf! { "ipprotocol" => "inet6", "descr" => "Block all IPv6", "disabled" => !v6_off,
        "#ref" => "ui/interfaces/settings" },
        Some(&block),
    );
    reg(
        1,
        conf! { "ipprotocol" => "inet46", "descr" => "Default deny / state violation rule", "quick" => false },
        Some(&block),
    );

    if s.rfc4890 {
        let icmp6 = |types: &str| -> Conf {
            conf! { "ipprotocol" => "inet6", "protocol" => "ipv6-icmp", "icmp6-type" => types,
            "statetype" => "keep", "descr" => "IPv6 RFC4890 requirements (ICMP)" }
        };
        let mut c = icmp6("1,2,3,4,135,136");
        c.set("disabled", v6_off);
        c.set("#ref", REF_FILTER);
        reg(1, c, Some(&pass));
        for (types, from, to, dir) in [
            (
                "128,129,133,134,135,136",
                "(self)",
                "fe80::/10,ff02::/16",
                "out",
            ),
            (
                "128,133,134,135,136",
                "fe80::/10",
                "fe80::/10,ff02::/16",
                "in",
            ),
            ("128,133,134,135,136", "ff02::/16", "fe80::/10", "in"),
            ("128,133,134,135,136", "::", "ff02::/16", "in"),
        ] {
            let mut c = icmp6(types);
            c.set("from", from);
            c.set("to", to);
            c.set("direction", dir);
            c.set("disabled", v6_off);
            c.set("#ref", REF_FILTER);
            reg(1, c, Some(&pass));
        }
    }

    if s.block_port0 {
        for target in ["from_port", "to_port"] {
            let mut c = conf! { "ipprotocol" => "inet46", "protocol" => "tcp/udp" };
            c.set(target, "0");
            c.set("descr", "block all targeting port 0");
            c.set("#ref", REF_FILTER);
            reg(1, c, Some(&block));
        }
    }

    if s.carp {
        let tos: &[&str] = if v6_off {
            &["224.0.0.18"]
        } else {
            &["ff02::12", "224.0.0.18"]
        };
        for to in tos {
            reg(
                1,
                conf! { "protocol" => "carp", "direction" => "any", "to" => *to, "descr" => "CARP defaults" },
                Some(&pass),
            );
        }
    }

    if s.sshlockout {
        let ssh_port: Value = match s.ssh {
            Some(p) => p.to_string().into(),
            None => 22i64.into(),
        };
        reg(
            1,
            conf! { "protocol" => "tcp", "from" => "<sshlockout>", "to" => "(self)", "descr" => "sshlockout",
            "direction" => "in", "to_port" => ssh_port, "#ref" => REF_FILTER },
            Some(&block),
        );
        let web = match s.webgui.port {
            Some(p) => p.to_string(),
            None if !s.webgui.https => "80".into(),
            None => "443".into(),
        };
        reg(
            1,
            conf! { "protocol" => "tcp", "from" => "<sshlockout>", "to" => "(self)", "descr" => "sshlockout",
            "direction" => "in", "to_port" => web, "#ref" => REF_FILTER },
            Some(&block),
        );
    }

    if s.virusprot {
        reg(
            1,
            conf! { "from" => "<virusprot>", "descr" => "virusprot overload table", "#ref" => REF_FILTER },
            Some(&block),
        );
    }

    let bogon = conf! { "type" => "block", "log" => s.log_bogons, "disablereplyto" => 1i64 };
    let private = conf! { "type" => "block", "log" => s.log_private, "disablereplyto" => 1i64 };
    for (name, i) in ctx.interfaces.iter().filter(|(_, i)| !i.r#virtual) {
        let r = |anchor: &str| format!("interfaces.php?if={name}#{anchor}");
        reg(
            5,
            conf! { "from" => "<bogons>", "direction" => "in", "interface" => name.as_str(), "ipprotocol" => "inet",
            "descr" => format!("Block bogon IPv4 networks from {}", i.descr),
            "#ref" => r("blockbogons"), "disabled" => !i.block_bogons },
            Some(&bogon),
        );
        reg(
            5,
            conf! { "from" => "<bogonsv6>", "direction" => "in", "interface" => name.as_str(), "ipprotocol" => "inet6",
            "disabled" => v6_off || !i.block_bogons, "#ref" => r("blockbogons"),
            "descr" => format!("Block bogon IPv6 networks from {}", i.descr) },
            Some(&bogon),
        );
        reg(
            5,
            conf! { "direction" => "in", "interface" => name.as_str(), "ipprotocol" => "inet",
            "#ref" => r("blockpriv"), "descr" => format!("Block private networks from {}", i.descr),
            "from" => "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16",
            "disabled" => !i.block_private },
            Some(&private),
        );
        reg(
            5,
            conf! { "direction" => "in", "interface" => name.as_str(), "ipprotocol" => "inet6",
            "#ref" => r("blockpriv"), "descr" => format!("Block private networks from {}", i.descr),
            "from" => "fd00::/8,fe80::/10", "disabled" => v6_off || !i.block_private },
            Some(&private),
        );
    }

    for (name, i) in ctx.interfaces.iter() {
        let n = name.as_str();
        if !v6_off && matches!(i.v6, V6Mode::Dhcp6 | V6Mode::Slaac) {
            reg(
                1,
                conf! { "descr" => format!("allow dhcpv6 client in {}", i.descr), "#ref" => "ui/interfaces/settings",
                "interface" => n, "protocol" => "udp", "to" => "fe80::/10", "to_port" => 546i64 },
                Some(&pass),
            );
            reg(
                1,
                conf! { "descr" => format!("allow dhcpv6 client out {}", i.descr), "#ref" => "ui/interfaces/settings",
                "direction" => "out", "interface" => n, "protocol" => "udp", "from" => "fe80::/10",
                "from_port" => 546i64, "to" => "fe80::/10,ff02::/16", "to_port" => 547i64 },
                Some(&pass),
            );
        }
        if i.v4 == V4Mode::Dhcp {
            let r = format!("interfaces.php?if={n}#type");
            let d = format!("allow DHCP client on {}", i.descr);
            reg(
                1,
                conf! { "protocol" => "udp", "direction" => "in", "from_port" => 67i64, "to_port" => 68i64,
                "#ref" => r.as_str(), "interface" => n, "descr" => d.as_str() },
                Some(&pass),
            );
            reg(
                1,
                conf! { "protocol" => "udp", "direction" => "out", "from_port" => 68i64, "to_port" => 67i64,
                "#ref" => r.as_str(), "interface" => n, "descr" => d.as_str() },
                Some(&pass),
            );
        }
        if v6_off {
            continue;
        }
        let r6 = format!("interfaces.php?if={n}#type6");
        match &i.v6 {
            V6Mode::SixRd { gateway } => {
                let gw = gateway.to_string();
                reg(
                    1,
                    conf! { "protocol" => "41", "direction" => "in", "from" => gw.as_str(), "#ref" => r6.as_str(),
                    "quick" => false, "interface" => n,
                    "descr" => format!("Allow 6in4 traffic in for 6rd on {}", i.descr) },
                    Some(&pass),
                );
                reg(
                    1,
                    conf! { "protocol" => "41", "direction" => "out", "to" => gw.as_str(), "#ref" => r6.as_str(),
                    "quick" => false, "interface" => n,
                    "descr" => format!("Allow 6in4 traffic out for 6rd on {}", i.descr) },
                    Some(&pass),
                );
            }
            V6Mode::SixToFour => {
                reg(
                    1,
                    conf! { "protocol" => "41", "direction" => "in", "to" => "(self)", "interface" => n,
                    "#ref" => r6.as_str(), "quick" => false,
                    "descr" => format!("Allow 6in4 traffic in for 6to4 on {}", i.descr) },
                    Some(&pass),
                );
                reg(
                    1,
                    conf! { "protocol" => "41", "direction" => "out", "from" => "(self)", "interface" => n,
                    "#ref" => r6.as_str(), "quick" => false,
                    "descr" => format!("Allow 6in4 traffic out for 6to4 on {}", i.descr) },
                    Some(&pass),
                );
            }
            _ => {}
        }
    }

    reg(
        5,
        conf! { "direction" => "out", "statetype" => "keep", "allowopts" => true, "quick" => false,
        "descr" => "let out anything from firewall host itself" },
        Some(&pass),
    );

    if let Some((iface, ports)) = anti_lockout(s, ctx) {
        for port in ports {
            reg(
                5,
                conf! { "direction" => "in", "interface" => iface.as_str(), "statetype" => "keep",
                "protocol" => "tcp", "to" => "(self)", "to_port" => port, "descr" => "anti-lockout rule",
                "#ref" => REF_FILTER },
                Some(&pass),
            );
        }
    }

    // kea_firewall(): automatic DHCPv4 server rules
    for iface in &s.kea4_interfaces {
        for to in ["255.255.255.255", "(self)"] {
            reg(
                1,
                conf! { "protocol" => "udp", "direction" => "in", "from_port" => 68i64, "to" => to,
                "#ref" => "ui/kea/dhcp/v4", "to_port" => 67i64, "interface" => iface.as_str(),
                "descr" => "allow access to DHCP server", "log" => s.log_default_pass },
                None,
            );
        }
    }
}
