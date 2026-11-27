//! The core pack's default rules (bpf/guard/rules.json, shipped by
//! nix/packages/sensr-guard-bpf.nix) are valid `Rule`s with the spec's
//! defaults.

use std::collections::HashSet;
use std::path::PathBuf;

use sensr_guard::rule::{Action, Hook, Rule, Target};

fn core_rules() -> Vec<Rule> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../bpf/guard/rules.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).expect("rules.json parses as [Rule]")
}

fn find<'a>(rules: &'a [Rule], id: &str) -> &'a Rule {
    rules
        .iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("no rule {id}"))
}

#[test]
fn ids_are_unique_and_namespaced() {
    let rules = core_rules();
    let ids: HashSet<_> = rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids.len(), rules.len(), "duplicate ids");
    assert!(rules.iter().all(|r| r.id.starts_with("core-")));
    assert!(rules.iter().all(|r| !r.description.is_empty()));
}

#[test]
fn everything_alerts_except_the_disabled_bpf_block() {
    let rules = core_rules();
    for r in &rules {
        if r.id == "core-bpf-block-others" {
            assert_eq!(r.action, Action::Block);
            assert!(!r.enabled, "the suggested block ships disabled");
        } else {
            assert_eq!(r.action, Action::Alert, "{}", r.id);
            assert!(r.enabled, "{}", r.id);
        }
    }
}

#[test]
fn covers_the_spec_defaults() {
    let rules = core_rules();
    let prefix = |id: &str| match &find(&rules, id).target {
        Target::PathPrefix(p) => p.clone(),
        t => panic!("{id}: {t:?}"),
    };
    for (id, p) in [
        ("core-write-nix-store", "/nix/store"),
        ("core-write-boot-firmware", "/boot/firmware"),
        ("core-write-etc-sensr", "/etc/sensr"),
    ] {
        assert_eq!(find(&rules, id).hook, Hook::FileWrite);
        assert_eq!(prefix(id), p);
    }
    for (id, hook) in [
        ("core-listen-any", Hook::Listen),
        ("core-module-load", Hook::Module),
        ("core-bpf-load", Hook::Bpf),
        ("core-bpf-block-others", Hook::Bpf),
    ] {
        let r = find(&rules, id);
        assert_eq!((r.hook, &r.target), (hook, &Target::Any), "{id}");
    }
    let su = find(&rules, "core-setuid-root");
    assert_eq!((su.hook, &su.target), (Hook::Setuid, &Target::Uid(0)));
    // "starts from outside /nix/store": no rule can say "not under", so the
    // pack watches the writable places a program could be dropped into.
    let exec: Vec<_> = rules.iter().filter(|r| r.hook == Hook::Exec).collect();
    assert!(exec.len() >= 5);
    for r in exec {
        let p = prefix(&r.id);
        assert!(!p.starts_with("/nix/store") && !p.starts_with("/run/current-system"));
    }
    assert!(
        rules
            .iter()
            .any(|r| r.hook == Hook::Exec && prefix(&r.id) == "/tmp")
    );
}

#[test]
fn every_rule_has_no_process_filter() {
    // Defaults watch every process; owners narrow them with overrides.
    for r in core_rules() {
        assert_eq!(r.process, Default::default(), "{}", r.id);
    }
}
