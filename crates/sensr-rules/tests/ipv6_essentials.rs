//! What SLAAC, DHCPv6 prefix delegation and router advertisements need from
//! the ruleset, for a DHCPv6-PD WAN with LANs tracking it (the importer's
//! `fibre-passthrough` corpus document): the RFC 4890 ICMPv6 passes, the
//! DHCPv6 client on the WAN, and ND/RA between the router and its LANs.
//! Neighbour discovery and MLD are untracked in Linux conntrack, so they must
//! reach these rules past the `ct state invalid drop` fast path.

use sensr_rules::document::{self, Runtime};

fn ruleset() -> Vec<(String, String)> {
    let path = format!(
        "{}/../sensr-import-opnsense/tests/golden/fibre-passthrough.sensr.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let doc: sensr_schema::Document =
        serde_json::from_str(&std::fs::read_to_string(path).expect("golden")).expect("document");
    let c = document::compile(&doc, &Runtime::default());
    let mut buf = Vec::new();
    c.render_nft(&mut buf).expect("render");
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("nft json");
    json["nftables"]
        .as_array()
        .expect("objects")
        .iter()
        .filter_map(|o| o.get("add")?.get("rule"))
        .map(|r| {
            (
                r["chain"].as_str().unwrap().to_owned(),
                r["expr"].to_string(),
            )
        })
        .collect()
}

/// A passing rule in `chain` whose expression mentions every needle.
fn passes(rules: &[(String, String)], chain: &str, needles: &[&str]) -> bool {
    rules.iter().any(|(c, e)| {
        c == chain
            && !e.contains("\"drop\"")
            && !e.contains("\"reject\"")
            && needles.iter().all(|n| e.contains(&n.replace(' ', "")))
    })
}

#[test]
fn wan_accepts_router_advertisements_and_dhcpv6_replies() {
    let r = ruleset();
    // RA from the upstream router's link-local address
    assert!(passes(&r, "in_wan", &["\"fe80::\"", "nd-router-advert"]));
    // neighbour solicitation / advertisement
    assert!(passes(
        &r,
        "in_wan",
        &["nd-neighbor-solicit", "nd-neighbor-advert"]
    ));
    // DHCPv6 replies to the client port on our link-local address, from any source
    assert!(passes(
        &r,
        "in_wan",
        &["\"dport\"}}, \"right\": 546", "\"fe80::\""]
    ));
    // and the solicits out, link-local to the servers' multicast group
    assert!(passes(
        &r,
        "out_wan",
        &["\"sport\"}}, \"right\": 546", "\"ff02::\"", "547"]
    ));
    // router solicitations out
    assert!(passes(&r, "out_wan", &["nd-router-solicit", "\"ff02::\""]));
}

#[test]
fn tracking_lans_get_router_solicitations_in_and_advertisements_out() {
    let r = ruleset();
    for lan in ["lan", "opt1", "opt2"] {
        let inn = format!("in_{lan}");
        let out = format!("out_{lan}");
        // hosts' RS and DAD (unspecified source) reach the router
        assert!(
            passes(&r, &inn, &["\"fe80::\"", "nd-router-solicit"]),
            "{lan}"
        );
        assert!(
            passes(&r, &inn, &["\"::\"", "\"ff02::\"", "nd-neighbor-solicit"]),
            "{lan}"
        );
        // the router's RA to all-nodes
        assert!(
            passes(&r, &out, &["\"ff02::\"", "nd-router-advert"]),
            "{lan}"
        );
    }
}

#[test]
fn untracked_neighbour_discovery_is_not_dropped_by_the_fast_path() {
    let r = ruleset();
    let fast: Vec<&String> = r
        .iter()
        .filter(|(c, e)| c == "input" && e.contains("\"ct\""))
        .map(|(_, e)| e)
        .collect();
    assert!(!fast.is_empty());
    for e in fast {
        assert!(!e.contains("untracked"), "{e}");
    }
}
