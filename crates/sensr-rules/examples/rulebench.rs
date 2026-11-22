//! Render benchmark: the 07-performance-evaluation home-router policy (system
//! rules, aliases incl. a blocklist, specific LAN rules, N per-host rules,
//! "LAN to any", automatic NAT) normalised and rendered to nft JSON.
//!
//! ```text
//! cargo run --release -p sensr-rules --example rulebench -- <rules> <blocklist> <reps> [out.json]
//! ```
//!
//! Prints one JSON line per repetition: normalisation and render time, JSON
//! size, compiled counts and peak RSS (Linux). `nft -j -f out.json` timing is
//! measured outside (scripts/rulebench.sh), since only `sensr-apply` may run
//! processes.

use std::collections::BTreeMap;
use std::time::Instant;

use sensr_rules::conf;
use sensr_rules::conf::Conf;
use sensr_rules::ir::{AliasClass, IfAddr, Interface, InterfaceMap, V4Mode};
use sensr_rules::nat::{self, NatRules, OutboundMode};
use sensr_rules::normalize::{AliasInfo, Context};
use sensr_rules::render::nft::{self, Options, ResolvedAlias};
use sensr_rules::ruleset::Ruleset;
use sensr_rules::system_rules::{self, SystemSettings};

fn interfaces() -> InterfaceMap {
    let mut ifs = InterfaceMap::new();
    ifs.insert(
        "wan".into(),
        Interface {
            device: "wan0".into(),
            descr: "WAN".into(),
            gateway_v4: true,
            v4: V4Mode::Dhcp,
            ..Default::default()
        },
    );
    ifs.insert(
        "lan".into(),
        Interface {
            device: "lan0".into(),
            descr: "LAN".into(),
            addrs: vec![IfAddr {
                addr: "192.168.1.1".parse().unwrap(),
                prefix_len: 24,
            }],
            v4: V4Mode::Static,
            ..Default::default()
        },
    );
    ifs
}

/// Deterministic pseudo-random public /32 and /24 entries (no RNG crate).
fn blocklist(n: usize) -> Vec<ipnet::IpNet> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let a = (x % 223 + 1) as u8;
        if matches!(a, 10 | 100 | 127 | 169 | 172 | 192 | 198 | 203) {
            continue;
        }
        let (b, c, d) = ((x >> 8) as u8, (x >> 16) as u8, ((x >> 24) as u8).max(1));
        out.push(if x % 10 < 3 {
            format!("{a}.{b}.{c}.0/24").parse().unwrap()
        } else {
            format!("{a}.{b}.{c}.{d}/32").parse().unwrap()
        });
    }
    out
}

fn alias_defs(block: usize) -> (BTreeMap<String, AliasInfo>, BTreeMap<String, ResolvedAlias>) {
    let mut info = BTreeMap::new();
    let mut res = BTreeMap::new();
    let mut addr = |name: &str, nets: Vec<ipnet::IpNet>| {
        info.insert(
            name.to_owned(),
            AliasInfo {
                class: AliasClass::Address,
                empty: nets.is_empty(),
            },
        );
        res.insert(
            name.to_owned(),
            ResolvedAlias {
                nets,
                ports: vec![],
            },
        );
    };
    let hosts = |r: std::ops::Range<u8>| -> Vec<ipnet::IpNet> {
        r.map(|i| format!("192.168.1.{i}/32").parse().unwrap())
            .collect()
    };
    addr("iot_devices", hosts(20..28));
    addr("kids_devices", hosts(40..44));
    addr("admin_hosts", hosts(10..12));
    addr(
        "work_vpn_nets",
        vec![
            "203.0.113.0/24".parse().unwrap(),
            "198.51.100.0/24".parse().unwrap(),
        ],
    );
    addr("blocklist_v4", blocklist(block));
    for (name, ports) in [
        (
            "web_ports",
            vec![(80, 80), (443, 443), (8080, 8080), (8443, 8443)],
        ),
        (
            "mail_ports",
            vec![(25, 25), (465, 465), (587, 587), (993, 993), (995, 995)],
        ),
    ] {
        info.insert(
            name.to_owned(),
            AliasInfo {
                class: AliasClass::Port,
                empty: false,
            },
        );
        res.insert(
            name.to_owned(),
            ResolvedAlias {
                nets: vec![],
                ports,
            },
        );
    }
    (info, res)
}

fn lan_rule(ty: &str, proto: &str, from: &str, to: &str, port: &str, descr: &str) -> Conf {
    let mut c = conf! { "type" => ty, "interface" => "lan", "ipprotocol" => "inet", "from" => from, "to" => to, "descr" => descr };
    if proto != "any" {
        c.set("protocol", proto);
    }
    if !port.is_empty() {
        c.set("to_port", port);
    }
    c
}

fn user_rules(extra: usize) -> Vec<Conf> {
    let mut v = vec![
        lan_rule("pass", "udp", "lan", "(self)", "53", "DNS to router"),
        lan_rule("pass", "tcp", "lan", "(self)", "53", "DNS/TCP to router"),
        lan_rule("pass", "udp", "lan", "(self)", "123", "NTP to router"),
        lan_rule("pass", "tcp", "admin_hosts", "(self)", "22", "admin SSH"),
        lan_rule("pass", "tcp", "admin_hosts", "(self)", "443", "admin GUI"),
        lan_rule("pass", "icmp", "lan", "(self)", "", "ping router"),
        lan_rule("block", "any", "lan", "blocklist_v4", "", "blocklist"),
        lan_rule(
            "block",
            "tcp",
            "iot_devices",
            "any",
            "mail_ports",
            "IoT no mail",
        ),
        lan_rule(
            "block",
            "any",
            "iot_devices",
            "work_vpn_nets",
            "",
            "IoT not to work",
        ),
        lan_rule("pass", "tcp", "iot_devices", "any", "web_ports", "IoT web"),
        lan_rule("pass", "udp", "iot_devices", "any", "123", "IoT NTP"),
        lan_rule("block", "any", "iot_devices", "any", "", "IoT default deny"),
        lan_rule(
            "block",
            "tcp",
            "kids_devices",
            "any",
            "6881-6889",
            "kids no bittorrent",
        ),
        lan_rule(
            "pass",
            "tcp",
            "kids_devices",
            "any",
            "web_ports",
            "kids web",
        ),
    ];
    for j in 0..extra {
        v.push(lan_rule(
            if j % 3 == 0 { "block" } else { "pass" },
            if j % 2 == 0 { "udp" } else { "tcp" },
            &format!("192.168.1.{}", 150 + j % 100),
            &format!("100.{}.{}.0/24", 64 + (j / 250) % 60, j % 250),
            &(20_000 + j % 40_000).to_string(),
            &format!("synthetic rule {j}"),
        ));
    }
    v.push(lan_rule("pass", "any", "lan", "any", "", "LAN to any"));
    v
}

fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let extra: usize = args.get(1).and_then(|a| a.parse().ok()).unwrap_or(36);
    let block: usize = args.get(2).and_then(|a| a.parse().ok()).unwrap_or(200);
    let reps: usize = args.get(3).and_then(|a| a.parse().ok()).unwrap_or(5);
    let out_path = args.get(4).cloned();
    // optional: an alias refresh document replacing the blocklist set
    let update_path = args.get(5).cloned();

    let ifs = interfaces();
    let (info, resolved) = alias_defs(block);
    let ctx = Context {
        interfaces: &ifs,
        aliases: &info,
    };
    let confs = user_rules(extra);
    for rep in 0..reps {
        let t0 = Instant::now();
        let mut rs = Ruleset::default();
        system_rules::register(&mut rs, &SystemSettings::default(), &ctx);
        for c in &confs {
            rs.register_filter(400_000, c, None, &ctx);
        }
        let mut nat_rules = NatRules::default();
        nat::automatic_outbound(OutboundMode::Automatic, false, &ctx, &mut nat_rules.snat);
        let t1 = Instant::now();
        let policy = nft::Policy {
            rules: &rs.rules,
            interfaces: &ifs,
            aliases: &resolved,
            nat: Some(&nat_rules),
            routing: None,
            host_modes: None,
        };
        let mut buf = Vec::with_capacity(256 * 1024);
        let report = nft::render(&policy, &Options::default(), &mut buf).expect("render");
        let t2 = Instant::now();
        if rep == 0
            && let Some(p) = &out_path
        {
            std::fs::write(p, &buf).expect("write output");
        }
        if rep == 0
            && let Some(p) = &update_path
        {
            let t = Instant::now();
            let mut upd = Vec::new();
            nft::render_set_updates(
                "sensr",
                &nft::alias_set_updates("blocklist_v4", &resolved["blocklist_v4"]),
                &mut upd,
            )
            .expect("render update");
            eprintln!(
                "{}",
                serde_json::json!({"set_update_entries": block, "render_ms": t.elapsed().as_secs_f64() * 1e3, "json_bytes": upd.len()})
            );
            std::fs::write(p, &upd).expect("write update");
        }
        println!(
            "{}",
            serde_json::json!({
                "user_rules": confs.len(),
                "blocklist": block,
                "ir_rules": rs.rules.len(),
                "normalize_ms": (t1 - t0).as_secs_f64() * 1e3,
                "render_ms": (t2 - t1).as_secs_f64() * 1e3,
                "json_bytes": buf.len(),
                "nft_rules": report.stats.nft_rules,
                "vmaps": report.stats.vmaps,
                "vmap_entries": report.stats.vmap_entries,
                "peak_rss_kib": peak_rss_kib(),
            })
        );
    }
}
