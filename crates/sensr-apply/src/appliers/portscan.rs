//! Port scanner: the `sensr-scan` daemon's configuration.

use std::net::IpAddr;

use ipnet::IpNet;
use sensr_scan::config::{Config, Exclude, Pace};
use sensr_schema::Document;
use sensr_schema::models::interfaces::{InterfaceRole, Ipv4Config, Ipv6Config};
use sensr_schema::models::portscan::{ScanPace, ScanTarget};

/// Live directory of the daemon's files.
pub const DIR: &str = "run/sensr/portscan";
/// The daemon's configuration (`sensr_scan::config::CONFIG_PATH`).
pub const CONFIG: &str = "portscan.json";
/// The daemon.
pub const UNIT: &str = "sensr-scan.service";

fn pace(p: ScanPace) -> Pace {
    match p {
        ScanPace::Gentle => Pace::Gentle,
        ScanPace::Normal => Pace::Normal,
        ScanPace::Fast => Pace::Fast,
    }
}

/// The daemon's configuration (`None`: scanning is switched off).
///
/// `local` is the subnet of every enabled non-WAN interface and the tunnel
/// network of every enabled WireGuard instance; `router` is the box's own
/// address on each of them. Dynamic addressing (DHCP, SLAAC, tracked
/// prefixes) contributes nothing: those are the WAN side or not known until
/// run time, and the daemon treats private ranges as local anyway.
pub fn config(doc: &Document) -> Option<Config> {
    let p = &doc.portscan;
    if !p.enabled {
        return None;
    }
    let mut local: Vec<IpNet> = Vec::new();
    let mut router: Vec<IpAddr> = Vec::new();
    let mut add = |net: IpNet| {
        let n = net.trunc();
        if !local.contains(&n) {
            local.push(n);
        }
        if !router.contains(&net.addr()) {
            router.push(net.addr());
        }
    };
    for (_, i) in doc.interfaces.iter().filter(|(_, i)| i.enabled) {
        if i.role == InterfaceRole::Wan {
            continue;
        }
        if let Ipv4Config::Static { address, .. } = &i.ipv4 {
            add(IpNet::V4(*address));
        }
        if let Ipv6Config::Static { address, .. } = &i.ipv6 {
            add(IpNet::V6(*address));
        }
    }
    if doc.wireguard.enabled {
        for s in doc.wireguard.servers.values().filter(|s| s.enabled) {
            for a in &s.tunnel_addresses {
                add(*a);
            }
        }
    }
    let exclude = p
        .exclude
        .values()
        .filter(|e| e.enabled)
        .filter_map(|e| e.parsed())
        .map(|t| match t {
            ScanTarget::Mac(m) => Exclude::Mac(m.to_string().to_ascii_lowercase()),
            ScanTarget::Addr(a) => Exclude::Addr(a),
        })
        .collect();
    Some(Config {
        enabled: true,
        auto_scan_new: p.auto_scan_new,
        pace: pace(p.pace),
        history: p.history,
        max_range: p.max_range,
        exclude,
        local,
        router,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensr_schema::fields::InterfaceId;
    use sensr_schema::models::portscan::ScanExclude;

    fn doc() -> Document {
        serde_json::from_str(include_str!(
            "../../../sensr-import-opnsense/tests/golden/home-router.sensr.json"
        ))
        .unwrap()
    }

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn local_has_lan_subnets_and_not_wan() {
        let c = config(&doc()).unwrap();
        assert!(c.local.contains(&net("192.168.1.0/24")), "{:?}", c.local);
        assert!(c.local.contains(&net("192.168.20.0/24")));
        assert!(c.local.contains(&net("192.168.30.0/24")));
        assert_eq!(c.local.len(), 5, "{:?}", c.local); // 3 LANs + 2 tunnel networks
        assert!(c.router.contains(&"192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn wan_static_address_is_not_local() {
        let mut d = doc();
        let wan = d
            .interfaces
            .0
            .get_mut(&"wan".parse::<InterfaceId>().unwrap())
            .unwrap();
        wan.ipv4 = Ipv4Config::Static {
            address: "203.0.113.5/24".parse().unwrap(),
            gateway: None,
        };
        let c = config(&d).unwrap();
        assert!(!c.local.contains(&net("203.0.113.0/24")));
        assert!(!c.router.contains(&"203.0.113.5".parse().unwrap()));
    }

    #[test]
    fn disabled_interface_is_skipped() {
        let mut d = doc();
        d.interfaces
            .0
            .get_mut(&"opt2".parse::<InterfaceId>().unwrap())
            .unwrap()
            .enabled = false;
        let c = config(&d).unwrap();
        assert!(!c.local.contains(&net("192.168.30.0/24")));
        assert!(!c.router.contains(&"192.168.30.1".parse().unwrap()));
    }

    #[test]
    fn wireguard_tunnel_networks_are_local() {
        let mut d = doc();
        let c = config(&d).unwrap();
        assert!(c.local.contains(&net("10.10.10.0/24")), "{:?}", c.local);
        assert!(c.local.contains(&net("2001:db8:10::/64")));
        d.wireguard.enabled = false;
        let c = config(&d).unwrap();
        assert!(!c.local.contains(&net("10.10.10.0/24")));
        d.wireguard.enabled = true;
        for (_, s) in d.wireguard.servers.iter_mut() {
            s.enabled = false;
        }
        let c = config(&d).unwrap();
        assert!(!c.local.contains(&net("10.10.10.0/24")));
    }

    #[test]
    fn exclude_maps_mac_lowercased_and_addr() {
        let mut d = doc();
        let ex = |t: &str, enabled| ScanExclude {
            enabled,
            target: t.into(),
            description: None,
        };
        d.portscan.exclude.push(ex("AA:BB:CC:DD:EE:FF", true));
        d.portscan.exclude.push(ex("192.168.1.9", true));
        d.portscan.exclude.push(ex("11-22-33-44-55-66", false));
        let c = config(&d).unwrap();
        assert_eq!(
            c.exclude,
            [
                Exclude::Mac("aa:bb:cc:dd:ee:ff".into()),
                Exclude::Addr("192.168.1.9".parse().unwrap())
            ]
        );
    }

    #[test]
    fn settings_carry_over() {
        let mut d = doc();
        d.portscan.pace = ScanPace::Fast;
        d.portscan.auto_scan_new = false;
        d.portscan.history = 7;
        d.portscan.max_range = 256;
        let c = config(&d).unwrap();
        assert!(c.enabled && !c.auto_scan_new);
        assert_eq!((c.pace, c.history, c.max_range), (Pace::Fast, 7, 256));
    }

    #[test]
    fn none_when_disabled() {
        let mut d = doc();
        assert!(config(&d).is_some());
        d.portscan.enabled = false;
        assert!(config(&d).is_none());
    }
}
