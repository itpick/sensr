//! The importer's synthetic home-router corpus document compiled to the
//! ruleset the agent loads (the M-slice input). Golden pf + nft; CI loads the
//! nft golden with `nft -c -j -f`.

mod common;

use sensr_rules::document::{self, Runtime};
use sensr_rules::ir::IfAddr;

fn load(name: &str) -> sensr_schema::Document {
    let path = format!(
        "{}/../sensr-import-opnsense/tests/golden/{name}.sensr.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(&path).expect("importer golden"))
        .expect("document")
}

fn check(name: &str, rt: &Runtime<'_>) -> document::Compiled {
    let doc = load(name);
    let c = document::compile(&doc, rt);
    let mut buf = Vec::new();
    let report = c.render_nft(&mut buf).expect("render");
    common::golden_json(&format!("doc-{name}"), &buf);
    common::golden_text(&format!("doc-{name}.pf"), &c.render_pf());
    let warnings: Vec<String> = report
        .warnings
        .iter()
        .map(|w| format!("{}: {}", w.label, w.message))
        .collect();
    common::golden_text(
        &format!("doc-{name}.warnings"),
        &(warnings.join("\n") + "\n"),
    );
    c
}

#[test]
fn home_router_document_compiles() {
    let mut rt = Runtime::default();
    // what DHCP gave the WAN at render time (sets follow later changes)
    rt.addrs.insert(
        "wan".into(),
        vec![IfAddr {
            addr: "203.0.113.2".parse().unwrap(),
            prefix_len: 24,
        }],
    );
    let c = check("home-router", &rt);
    // offline: URL and GeoIP aliases keep their previous contents
    assert!(
        c.aliases.failed.contains("DROP_FEED"),
        "{:?}",
        c.aliases.failed
    );
    assert_eq!(c.aliases.aliases["NAS_HOST"].nets.len(), 1);
    // the assigned WireGuard interface carries the instance's tunnel networks
    assert!(c.interfaces["opt3"].has_family(sensr_rules::ir::IpFamily::V4));
}

#[test]
fn multiwan_document_compiles() {
    check("multiwan", &Runtime::default());
}
