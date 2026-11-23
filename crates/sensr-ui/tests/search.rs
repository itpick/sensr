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

/// The mock with chosen calls failing, as for a caller the agent refuses them to.
struct Flaky {
    inner: MockBackend,
    deny_get: bool,
    fail_hosts: bool,
}

mod flaky {
    use super::Flaky;
    use futures::future::BoxFuture;
    use sensr_ui::api::*;
    use sensr_ui::runtime::RuntimeSection;
    use serde_json::Value;

    impl Backend for Flaky {
        fn get<'a>(&'a self, p: &'a str) -> BoxFuture<'a, ApiResult<Value>> {
            if self.deny_get {
                return Box::pin(async { Err(ApiError::Backend("config.get denied".into())) });
            }
            self.inner.get(p)
        }
        fn set<'a>(&'a self, p: &'a str, v: Value) -> BoxFuture<'a, ApiResult<()>> {
            self.inner.set(p, v)
        }
        fn pending(&self) -> BoxFuture<'_, ApiResult<Pending>> {
            self.inner.pending()
        }
        fn commit<'a>(
            &'a self,
            u: &'a str,
            m: &'a str,
            c: Option<u32>,
        ) -> BoxFuture<'a, ApiResult<Revision>> {
            self.inner.commit(u, m, c)
        }
        fn confirm(&self) -> BoxFuture<'_, ApiResult<()>> {
            self.inner.confirm()
        }
        fn discard(&self) -> BoxFuture<'_, ApiResult<()>> {
            self.inner.discard()
        }
        fn rollback<'a>(&'a self, u: &'a str, to: u64) -> BoxFuture<'a, ApiResult<Revision>> {
            self.inner.rollback(u, to)
        }
        fn history(&self) -> BoxFuture<'_, ApiResult<Vec<Revision>>> {
            self.inner.history()
        }
        fn diff(&self, f: u64, t: Option<u64>) -> BoxFuture<'_, ApiResult<Vec<DiffLine>>> {
            self.inner.diff(f, t)
        }
        fn status(&self) -> BoxFuture<'_, ApiResult<SystemStatus>> {
            self.inner.status()
        }
        fn nics(&self) -> BoxFuture<'_, ApiResult<Vec<NetworkCard>>> {
            self.inner.nics()
        }
        fn may_access(&self, url: &str) -> bool {
            self.inner.may_access(url)
        }
        fn runtime(&self, s: RuntimeSection) -> BoxFuture<'_, ApiResult<Value>> {
            if self.fail_hosts && matches!(s, RuntimeSection::Hosts) {
                return Box::pin(async { Err(ApiError::Backend("agent down".into())) });
            }
            self.inner.runtime(s)
        }
        fn forget_host(&self, k: String) -> BoxFuture<'_, ApiResult<()>> {
            self.inner.forget_host(k)
        }
        fn set_host_mode(
            &self,
            m: String,
            mode: Option<String>,
            r: Option<std::net::IpAddr>,
        ) -> BoxFuture<'_, ApiResult<String>> {
            self.inner.set_host_mode(m, mode, r)
        }
        fn set_host_label(
            &self,
            m: String,
            k: Option<String>,
            mk: Option<String>,
        ) -> BoxFuture<'_, ApiResult<String>> {
            self.inner.set_host_label(m, k, mk)
        }
        fn host_activity(
            &self,
            m: String,
            r: String,
            p: u32,
        ) -> BoxFuture<'_, ApiResult<HostActivityView>> {
            self.inner.host_activity(m, r, p)
        }
        fn set_service_override(
            &self,
            s: String,
            sv: Option<String>,
            c: Option<String>,
        ) -> BoxFuture<'_, ApiResult<String>> {
            self.inner.set_service_override(s, sv, c)
        }
    }
}

fn run_on(b: &Flaky, q: &str) -> SearchResults {
    futures::executor::block_on(run(b as &dyn Backend, q)).expect("search must not fail")
}

#[test]
fn failing_hosts_call_still_returns_pages_and_rows() {
    let b = Flaky {
        inner: MockBackend::new(),
        deny_get: false,
        fail_hosts: true,
    };
    assert!(has(&run_on(&b, "rfc1918"), "Aliases"));
    assert!(has(&run_on(&b, "alias"), "Pages"));
    assert!(!has(&run_on(&b, "bench-pi"), "Hosts"));
}

#[test]
fn refused_config_degrades_to_pages_and_settings() {
    let b = Flaky {
        inner: MockBackend::new(),
        deny_get: true,
        fail_hosts: false,
    };
    let r = run_on(&b, "rfc1918");
    assert!(!has(&r, "Aliases"), "{r:?}");
    assert!(has(&run_on(&b, "hostname"), "Settings"));
    assert!(has(&run_on(&b, "aliases"), "Pages"));
}
