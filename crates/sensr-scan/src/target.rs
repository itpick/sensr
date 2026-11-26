//! Scan targets: parsing, enumeration and the safety checks that keep a scan
//! on the local network unless a person says otherwise.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use crate::config::Config;
use crate::proto::Refusal;

/// Longest IPv6 network accepted (`/120`: 256 addresses).
const MIN_V6_PREFIX: u8 = 120;

/// What to scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// One address.
    One(IpAddr),
    /// A network (network and broadcast addresses are not scanned for IPv4).
    Net(IpNet),
    /// An inclusive range of addresses of one family.
    Span(IpAddr, IpAddr),
}

/// Reads `192.168.1.5`, `192.168.1.0/24`, `192.168.1.10-20`,
/// `10.0.0.1-10.0.1.5` or an IPv6 address (nets no larger than `/120`).
///
/// # Errors
/// A message for the person when the text is not a target.
pub fn parse(s: &str) -> Result<Target, String> {
    let s = s.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(Target::One(ip));
    }
    if s.contains('/') {
        let net: IpNet = s.parse().map_err(|_| format!("'{s}' is not a network"))?;
        if let IpNet::V6(n) = net
            && n.prefix_len() < MIN_V6_PREFIX
        {
            return Err(format!(
                "IPv6 networks larger than /{MIN_V6_PREFIX} are not scanned"
            ));
        }
        return Ok(Target::Net(net.trunc()));
    }
    if let Some((a, b)) = s.split_once('-') {
        let (a, b) = (a.trim(), b.trim());
        let start: IpAddr = a.parse().map_err(|_| format!("'{a}' is not an address"))?;
        let end: IpAddr = match (b.parse::<IpAddr>(), start) {
            (Ok(end), _) => end,
            (Err(_), IpAddr::V4(v4)) => {
                let last: u8 = b
                    .parse()
                    .map_err(|_| format!("'{b}' is not an address or last octet"))?;
                let [x, y, z, _] = v4.octets();
                IpAddr::V4(Ipv4Addr::new(x, y, z, last))
            }
            (Err(_), IpAddr::V6(_)) => return Err(format!("'{b}' is not an address")),
        };
        return match (start, end) {
            (IpAddr::V4(x), IpAddr::V4(y)) if x <= y => Ok(Target::Span(start, end)),
            (IpAddr::V6(x), IpAddr::V6(y)) if x <= y => Ok(Target::Span(start, end)),
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => {
                Err("a range cannot mix IPv4 and IPv6".into())
            }
            _ => Err("the range ends before it starts".into()),
        };
    }
    Err(format!("'{s}' is not an address, network or range"))
}

fn v4_span(a: Ipv4Addr, b: Ipv4Addr) -> impl Iterator<Item = IpAddr> {
    (u32::from(a)..=u32::from(b)).map(|n| IpAddr::V4(Ipv4Addr::from(n)))
}

fn v6_span(a: Ipv6Addr, b: Ipv6Addr) -> impl Iterator<Item = IpAddr> {
    (u128::from(a)..=u128::from(b)).map(|n| IpAddr::V6(Ipv6Addr::from(n)))
}

/// The addresses to scan, in order, without the router's own.
///
/// An IPv4 network of `/30` or larger skips its network and broadcast
/// addresses.
pub fn addresses<'a>(t: &Target, router: &'a [IpAddr]) -> impl Iterator<Item = IpAddr> + use<'a> {
    let all: Box<dyn Iterator<Item = IpAddr>> = match *t {
        Target::One(ip) => Box::new(std::iter::once(ip)),
        Target::Net(IpNet::V4(n)) => {
            let (first, last) = (n.network(), n.broadcast());
            if n.prefix_len() >= 31 {
                Box::new(v4_span(first, last))
            } else {
                let (lo, hi) = (u32::from(first) + 1, u32::from(last) - 1);
                Box::new(v4_span(Ipv4Addr::from(lo), Ipv4Addr::from(hi)))
            }
        }
        Target::Net(IpNet::V6(n)) => Box::new(v6_span(n.network(), n.broadcast())),
        Target::Span(IpAddr::V4(a), IpAddr::V4(b)) => Box::new(v4_span(a, b)),
        Target::Span(IpAddr::V6(a), IpAddr::V6(b)) => Box::new(v6_span(a, b)),
        Target::Span(..) => Box::new(std::iter::empty()),
    };
    all.filter(|ip| !router.contains(ip))
}

/// How many addresses the target covers, before router exclusion. For a
/// network that is its full size (network and broadcast included): the size
/// the range limit is judged by.
#[must_use]
pub fn count(t: &Target) -> u64 {
    fn clamp(n: u128) -> u64 {
        u64::try_from(n).unwrap_or(u64::MAX)
    }
    match *t {
        Target::One(_) => 1,
        Target::Net(IpNet::V4(n)) => 1u64 << (32 - u32::from(n.prefix_len())),
        Target::Net(IpNet::V6(n)) => clamp(1u128 << (128 - u32::from(n.prefix_len()))),
        Target::Span(IpAddr::V4(a), IpAddr::V4(b)) => {
            u64::from(u32::from(b).saturating_sub(u32::from(a))) + 1
        }
        Target::Span(IpAddr::V6(a), IpAddr::V6(b)) => clamp(
            u128::from(b)
                .saturating_sub(u128::from(a))
                .saturating_add(1),
        ),
        Target::Span(..) => 0,
    }
}

/// Built-in local blocks: private and link-local IPv4, unique-local and
/// link-local IPv6 (the spec's RFC 1918 / ULA / link-local). Shared space
/// (CGNAT, 100.64.0.0/10) is the ISP's, not ours: it is local only when it
/// is one of the configured `local` nets.
const LOCAL_BLOCKS: [&str; 6] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10",
];

/// The local block (built-in or one of `local`) containing both addresses.
fn shared_block(a: IpAddr, b: IpAddr, local: &[IpNet]) -> bool {
    let builtin = LOCAL_BLOCKS
        .iter()
        .filter_map(|n| n.parse::<IpNet>().ok())
        .any(|n| n.contains(&a) && n.contains(&b));
    builtin || local.iter().any(|n| n.contains(&a) && n.contains(&b))
}

/// Whether `ip` is on a local network: private or link-local space, unique-local IPv6, or one of the configured `local` nets.
#[must_use]
pub fn is_local(ip: IpAddr, local: &[IpNet]) -> bool {
    shared_block(ip, ip, local)
}

/// Whether the target may be scanned: local unless `public_ok`, and no larger
/// than the configured maximum.
///
/// # Errors
/// The [`Refusal`] to send back.
pub fn check(t: &Target, cfg: &Config, public_ok: bool) -> Result<(), Refusal> {
    // Both ends must lie in the same local block, so a span cannot reach
    // public space between two local endpoints. For a Net this is sound too:
    // an aligned CIDR and a block are nested or disjoint, so a block holding
    // the network and broadcast addresses holds every address between them.
    let ends = match *t {
        Target::One(ip) => (ip, ip),
        Target::Net(n) => (n.network(), n.broadcast()),
        Target::Span(a, b) => (a, b),
    };
    if !public_ok && !shared_block(ends.0, ends.1, &cfg.local) {
        return Err(Refusal::Public);
    }
    let addresses = count(t);
    if addresses > u64::from(cfg.max_range) {
        return Err(Refusal::TooLarge {
            addresses,
            max: cfg.max_range,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Pace;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cfg() -> Config {
        Config {
            enabled: true,
            auto_scan_new: false,
            pace: Pace::Normal,
            history: 10,
            max_range: 4096,
            exclude: vec![],
            local: vec![],
            router: vec![],
        }
    }

    #[test]
    fn parses_each_form() {
        assert_eq!(parse("192.168.1.5"), Ok(Target::One(ip("192.168.1.5"))));
        assert_eq!(
            parse("192.168.1.0/24"),
            Ok(Target::Net("192.168.1.0/24".parse().unwrap()))
        );
        assert_eq!(
            parse("192.168.1.10-20"),
            Ok(Target::Span(ip("192.168.1.10"), ip("192.168.1.20")))
        );
        assert_eq!(
            parse("10.0.0.1-10.0.1.5"),
            Ok(Target::Span(ip("10.0.0.1"), ip("10.0.1.5")))
        );
        assert_eq!(parse("fd00::1"), Ok(Target::One(ip("fd00::1"))));
        assert!(matches!(parse("fd00::/120"), Ok(Target::Net(_))));
    }

    #[test]
    fn rejects_bad_targets() {
        assert!(parse("::/0").is_err());
        assert!(parse("fd00::/64").is_err());
        assert!(parse("hostname").is_err());
        assert!(parse("192.168.1.20-10").is_err());
        assert!(parse("192.168.1.1-fd00::1").is_err());
        assert!(parse("192.168.1.1-300").is_err());
        assert!(parse("").is_err());
    }

    #[test]
    fn net_skips_network_and_broadcast() {
        let t = parse("192.168.1.0/30").unwrap();
        let got: Vec<_> = addresses(&t, &[]).collect();
        assert_eq!(got, vec![ip("192.168.1.1"), ip("192.168.1.2")]);
    }

    #[test]
    fn tiny_nets_keep_every_address() {
        let t = parse("192.168.1.4/31").unwrap();
        assert_eq!(addresses(&t, &[]).count(), 2);
        let t = parse("192.168.1.4/32").unwrap();
        assert_eq!(addresses(&t, &[]).count(), 1);
    }

    #[test]
    fn router_is_excluded() {
        let t = parse("192.168.68.0/29").unwrap();
        let router = [ip("192.168.68.1")];
        let got: Vec<_> = addresses(&t, &router).collect();
        assert_eq!(got.len(), 5);
        assert!(!got.contains(&router[0]));
    }

    #[test]
    fn span_is_inclusive() {
        let t = parse("192.168.1.10-12").unwrap();
        let got: Vec<_> = addresses(&t, &[]).collect();
        assert_eq!(
            got,
            vec![ip("192.168.1.10"), ip("192.168.1.11"), ip("192.168.1.12")]
        );
        assert_eq!(count(&t), 3);
    }

    #[test]
    fn v6_net_enumerates() {
        let t = parse("fd00::/120").unwrap();
        assert_eq!(addresses(&t, &[]).count(), 256);
        assert_eq!(count(&t), 256);
    }

    #[test]
    fn counts() {
        assert_eq!(count(&parse("10.0.0.0/20").unwrap()), 4096);
        assert_eq!(count(&parse("10.0.0.5").unwrap()), 1);
        assert_eq!(count(&parse("0.0.0.0/0").unwrap()), 1 << 32);
    }

    #[test]
    fn too_large_is_refused() {
        let t = parse("192.168.0.0/19").unwrap();
        assert_eq!(
            check(&t, &cfg(), false),
            Err(Refusal::TooLarge {
                addresses: 8192,
                max: 4096
            })
        );
    }

    #[test]
    fn public_needs_permission() {
        let t = parse("8.8.8.8").unwrap();
        assert_eq!(check(&t, &cfg(), false), Err(Refusal::Public));
        assert_eq!(check(&t, &cfg(), true), Ok(()));
    }

    #[test]
    fn local_is_fine() {
        for s in [
            "192.168.1.5",
            "10.1.2.3",
            "172.16.0.9",
            "fd00::1",
            "169.254.1.1",
        ] {
            assert_eq!(check(&parse(s).unwrap(), &cfg(), false), Ok(()), "{s}");
        }
        assert!(!is_local(ip("100.128.0.1"), &[]));
    }

    #[test]
    fn cgnat_is_public_unless_configured() {
        assert_eq!(
            check(&parse("100.64.1.1").unwrap(), &cfg(), false),
            Err(Refusal::Public)
        );
        let mut c = cfg();
        c.local = vec!["100.64.0.0/10".parse().unwrap()];
        assert_eq!(check(&parse("100.64.1.1").unwrap(), &c, false), Ok(()));
        assert!(!is_local(ip("2001:db8::1"), &[]));
    }

    #[test]
    fn configured_local_nets_count() {
        let local = ["203.0.113.0/24".parse().unwrap()];
        assert!(is_local(ip("203.0.113.7"), &local));
        let mut c = cfg();
        c.local = local.to_vec();
        assert_eq!(check(&parse("203.0.113.0/28").unwrap(), &c, false), Ok(()));
    }

    #[test]
    fn straddling_targets_are_refused() {
        // Local endpoints with public space between (172.16/12 .. 192.168/16).
        for s in [
            "10.0.0.1-100.64.0.5",
            "192.168.255.250-192.169.0.5",
            "172.16.0.1-192.168.0.1",
        ] {
            let t = parse(s).unwrap();
            assert_eq!(check(&t, &cfg(), false), Err(Refusal::Public), "{s}");
            let mut big = cfg();
            big.max_range = u32::MAX;
            assert_eq!(check(&t, &big, true), Ok(()), "{s}");
        }
        // A net covering local and public space.
        assert_eq!(
            check(&parse("192.168.0.0/15").unwrap(), &cfg(), false),
            Err(Refusal::Public)
        );
    }

    #[test]
    fn span_inside_one_block_is_fine() {
        let t = parse("192.168.1.10-192.168.2.20").unwrap();
        assert_eq!(check(&t, &cfg(), false), Ok(()));
    }

    #[test]
    fn loopback_is_not_local() {
        assert!(!is_local(ip("127.0.0.1"), &[]));
        assert!(!is_local(ip("::1"), &[]));
    }
}
