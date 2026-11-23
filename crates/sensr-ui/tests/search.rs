//! Global search over the mock backend: the server-side entry point, its cache and its
//! permission handling.

use sensr_ui::api::Backend;
use sensr_ui::mock::MockBackend;
use sensr_ui::search::{SearchResults, run};

fn search(b: &MockBackend, q: &str) -> SearchResults {
    futures::executor::block_on(run(b as &dyn Backend, q)).expect("search")
}

fn has(r: &SearchResults, group: &str) -> bool {
    r.groups.iter().any(|g| g.name == group)
}

#[test]
fn global_search_finds_mock_alias() {
    let r = search(&MockBackend::new(), "rfc1918");
    let g = r
        .groups
        .iter()
        .find(|g| g.name == "Aliases")
        .expect("aliases");
    assert_eq!(g.hits[0].title, "rfc1918");
    assert!(g.hits[0].url.starts_with("/ui/firewall/alias?edit="));
}

#[test]
fn global_search_read_only_user_still_searches() {
    let m = MockBackend::new().with_privileges(&["page-all", "user-config-readonly"]);
    assert!(has(&search(&m, "rfc1918"), "Aliases"));
}

#[test]
fn cache_is_per_privilege_set() {
    let full = MockBackend::new();
    assert!(has(&search(&full, "rfc1918"), "Aliases"));
    assert!(has(&search(&full, "rules"), "Pages"));
    let limited = MockBackend::new().with_privileges(&["page-sensr-status"]);
    let r = search(&limited, "rfc1918");
    assert!(!has(&r, "Aliases"), "{r:?}");
    assert!(!has(&r, "Rules"), "{r:?}");
    let r = search(&limited, "rules");
    assert!(!has(&r, "Pages") && !has(&r, "Rules"), "{r:?}");
    // and back: the full user still sees them
    assert!(has(&search(&full, "rfc1918"), "Aliases"));
}

#[test]
fn global_search_sees_staged_objects() {
    let m = MockBackend::new();
    assert!(!has(&search(&m, "zzstaged"), "Aliases"));
    futures::executor::block_on(m.set(
        "firewall.aliases.6d1f3a0e-0b54-4c43-9a51-2f1f0d4c8aff",
        serde_json::json!({"enabled": true, "name": "zzstaged",
            "content": {"type": "host", "entries": ["10.9.9.9"]}}),
    ))
    .expect("stage");
    assert!(has(&search(&m, "zzstaged"), "Aliases"));
}

#[test]
fn hosts_need_the_hosts_privilege() {
    assert!(has(&search(&MockBackend::new(), "bench-pi"), "Hosts"));
    let m = MockBackend::new().with_privileges(&["page-firewall-alias-edit"]);
    assert!(!has(&search(&m, "bench-pi"), "Hosts"));
    let m = MockBackend::new().with_privileges(&["page-all", "user-config-readonly"]);
    assert!(has(&search(&m, "bench-pi"), "Hosts"));
}
