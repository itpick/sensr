//! Reading what networkd obtained out of `ip -j` output (synthetic
//! fixtures, see tests/fixtures/README.md).
//!
//! Covers: IF-007 (DHCPv6 prefix delegation on the WAN), ISS-C-002 (the PD
//! state machine's input).

use ipnet::Ipv6Net;
use pretty_assertions::assert_eq;
use sensr_net::ipv6::pd::observe::{
    ParseError, observation_from_kernel, parse_addr_lifetimes, parse_pd_routes,
};
use sensr_net::ipv6::pd::{INFINITE_LIFETIME, Observation, PdEvent, PdState};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn net(s: &str) -> Ipv6Net {
    s.parse().unwrap()
}

#[test]
fn only_unreachable_dhcp_routes_count() {
    let r = parse_pd_routes(&fixture("routes-pd56.json")).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].prefix, net("2001:db8:1234:ab00::/56"));
    assert_eq!(r[0].valid_lifetime, 3539);
}

#[test]
fn expires_as_text_and_missing_expires() {
    let r = parse_pd_routes(&fixture("routes-expires-text.json")).unwrap();
    assert_eq!(r[0].valid_lifetime, 3539);
    assert_eq!(r[1].prefix, net("2001:db8:78::/48"));
    assert_eq!(r[1].valid_lifetime, INFINITE_LIFETIME);
}

#[test]
fn address_lifetimes_global_only() {
    let a = parse_addr_lifetimes(&fixture("addrs-pd56.json")).unwrap();
    let names: Vec<_> = a
        .iter()
        .map(|a| (a.ifname.as_str(), a.address.to_string(), a.dynamic))
        .collect();
    assert_eq!(
        names,
        vec![
            ("wan0", "2001:db8:ffff:1::42".to_string(), true),
            ("lan0", "2001:db8:1234:ab00::1".to_string(), true),
            ("lan0", "fd00:db8::1".to_string(), false),
            ("lan1", "2001:db8:1234:ab10::1".to_string(), true),
        ]
    );
    assert_eq!(a[2].valid_lifetime, INFINITE_LIFETIME);
    assert_eq!(a[1].preferred_lifetime, 1740);
}

#[test]
fn kernel_observation_for_a_56() {
    let k = observation_from_kernel(
        &fixture("routes-pd56.json"),
        &fixture("addrs-pd56.json"),
        &["lan0", "lan1"],
    )
    .unwrap();
    assert_eq!(
        k.observation,
        Some(Observation {
            prefix: net("2001:db8:1234:ab00::/56"),
            preferred_lifetime: 1740,
            valid_lifetime: 3539,
            iaid: None,
        })
    );
    assert!(k.mismatches.is_empty());

    // Feeds the state machine directly.
    let mut s = PdState::new();
    let e = s.observe(1_800_000_000, k.observation);
    assert!(matches!(e.as_slice(), [PdEvent::Acquired(_)]));
}

#[test]
fn before_lans_are_configured_preferred_equals_valid() {
    let k = observation_from_kernel(&fixture("routes-pd56.json"), b"[]", &["lan0"]).unwrap();
    let o = k.observation.unwrap();
    assert_eq!((o.preferred_lifetime, o.valid_lifetime), (3539, 3539));
}

#[test]
fn slash_64_delegation_falls_back_to_lan_addresses() {
    let k = observation_from_kernel(
        &fixture("routes-pd64.json"),
        &fixture("addrs-pd64.json"),
        &["lan0"],
    )
    .unwrap();
    assert_eq!(
        k.observation,
        Some(Observation {
            prefix: net("2001:db8:5:6::/64"),
            preferred_lifetime: 3590,
            valid_lifetime: 7190,
            iaid: None,
        })
    );
    // Without the LAN in the list there is nothing to go on.
    let k = observation_from_kernel(
        &fixture("routes-pd64.json"),
        &fixture("addrs-pd64.json"),
        &["lan7"],
    )
    .unwrap();
    assert_eq!(k.observation, None);
}

#[test]
fn two_uplinks_are_told_apart_by_their_lans() {
    let routes = fixture("routes-two-uplinks.json");
    let addrs = fixture("addrs-two-uplinks.json");
    let a = observation_from_kernel(&routes, &addrs, &["lan0"]).unwrap();
    assert_eq!(a.observation.unwrap().prefix, net("2001:db8:a::/56"));
    let b = observation_from_kernel(&routes, &addrs, &["lan9"]).unwrap();
    let b = b.observation.unwrap();
    assert_eq!(b.prefix, net("2001:db8:b::/60"));
    assert_eq!((b.preferred_lifetime, b.valid_lifetime), (600, 1200));
    assert!(matches!(
        observation_from_kernel(&routes, &addrs, &["lan5"]),
        Err(ParseError::Ambiguous(v)) if v.len() == 2
    ));
}

#[test]
fn lifetime_mismatch_is_reported() {
    let addrs = br#"[{"ifname":"lan0","addr_info":[{"family":"inet6","local":"2001:db8:1234:ab00::1","prefixlen":64,"scope":"global","dynamic":true,"valid_life_time":600,"preferred_life_time":300}]}]"#;
    let k = observation_from_kernel(&fixture("routes-pd56.json"), addrs, &["lan0"]).unwrap();
    assert_eq!(k.mismatches.len(), 1);
    assert_eq!(k.mismatches[0].route_valid_lifetime, 3539);
    assert_eq!(k.observation.unwrap().preferred_lifetime, 300);
}

#[test]
fn empty_and_malformed_input() {
    let k = observation_from_kernel(b"[]", b"[]", &["lan0"]).unwrap();
    assert_eq!(k.observation, None);
    assert!(matches!(
        parse_pd_routes(b"not json"),
        Err(ParseError::Json(_))
    ));
    assert!(matches!(
        parse_addr_lifetimes(b"{}"),
        Err(ParseError::Json(_))
    ));
}
