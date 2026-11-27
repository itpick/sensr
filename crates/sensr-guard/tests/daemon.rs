//! The daemon's logic against a fake kernel ([`Backend`]), and the pack
//! check against a local HTTP fixture.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::mem::{offset_of, size_of};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use minisign::KeyPair;
use semver::Version;
use sensr_guard::compile::Compiled;
use sensr_guard::daemon::{
    Backend, Daemon, HttpFetcher, KILL_SWITCH_STATE, LoadedPack, Options, StartError,
    auto_check_due, check_packs, parse_lockdown, record_attempt, sensr_release,
};
use sensr_guard::events::BootClock;
use sensr_guard::loader::ProgramStatus;
use sensr_guard::maps::GuardEvent;
use sensr_guard::packs::VerifiedPack;
use sensr_guard::proto::{PackSource, Reply, Request, RuleStatus, StatusView};
use serde_json::json;

/// One apply: rule ids in slot order, enabled flags, actions, kill switch.
type Apply = (Vec<String>, Vec<u8>, Vec<u8>, bool);

/// What the fake kernel saw.
#[derive(Default)]
struct Log {
    /// Versions loaded, in order.
    loads: Vec<String>,
    applies: Vec<Apply>,
}

#[derive(Default)]
struct Knobs {
    /// Program name -> attach error.
    unattached: HashMap<String, String>,
    /// Pack versions whose load fails.
    fail_load: Vec<String>,
    /// The next applies fail with this.
    fail_apply: Option<String>,
    /// Records waiting in the ring buffer.
    events: Vec<Vec<u8>>,
    boot_complete: bool,
    dropped: u64,
}

#[derive(Clone, Default)]
struct Fake {
    log: Arc<Mutex<Log>>,
    knobs: Arc<Mutex<Knobs>>,
}

struct FakePack {
    fake: Fake,
    last: Option<Compiled>,
}

const PROGRAMS: [(&str, &str); 14] = [
    ("guard_bind", "socket_bind"),
    ("guard_bpf", "bpf"),
    ("guard_connect", "socket_connect"),
    ("guard_exec", "bprm_check_security"),
    ("guard_exec_commit", "bprm_committed_creds"),
    ("guard_exec_inherit", "task_alloc"),
    ("guard_seed_exe", "iter/task"),
    ("guard_file_open", "file_open"),
    ("guard_listen", "socket_listen"),
    ("guard_module_data", "kernel_load_data"),
    ("guard_module_file", "kernel_read_file"),
    ("guard_path_rename", "path_rename"),
    ("guard_path_unlink", "path_unlink"),
    ("guard_setuid", "task_fix_setuid"),
];

impl Backend for Fake {
    fn load(&mut self, pack: &VerifiedPack) -> Result<Box<dyn LoadedPack>, String> {
        let v = pack.version.to_string();
        if self.knobs.lock().unwrap().fail_load.contains(&v) {
            return Err(format!("verifier rejected {v}"));
        }
        self.log.lock().unwrap().loads.push(v);
        Ok(Box::new(FakePack {
            fake: self.clone(),
            last: None,
        }))
    }

    fn boot_complete(&mut self) -> bool {
        self.knobs.lock().unwrap().boot_complete
    }
}

impl LoadedPack for FakePack {
    fn programs(&self) -> Vec<ProgramStatus> {
        let k = self.fake.knobs.lock().unwrap();
        PROGRAMS
            .iter()
            .map(|(name, hook)| {
                let reason = k.unattached.get(*name).cloned();
                ProgramStatus {
                    name: (*name).into(),
                    hook: (*hook).into(),
                    attached: reason.is_none(),
                    reason,
                }
            })
            .collect()
    }

    fn apply(&mut self, c: &Compiled, kill_switch: bool, own_tgid: u32) -> Result<(), String> {
        assert_eq!(own_tgid, 4242);
        if let Some(e) = self.fake.knobs.lock().unwrap().fail_apply.clone() {
            return Err(e);
        }
        self.fake.log.lock().unwrap().applies.push((
            c.meta.iter().map(|m| m.id.clone()).collect(),
            c.meta.iter().map(|m| m.meta.enabled).collect(),
            c.meta.iter().map(|m| m.meta.action).collect(),
            kill_switch,
        ));
        self.last = Some(c.clone());
        Ok(())
    }

    fn hits_by_id(&self) -> Result<HashMap<String, u64>, String> {
        Ok(self
            .last
            .iter()
            .flat_map(|c| c.meta.iter().map(|m| (m.id.clone(), 1)))
            .collect())
    }

    fn ringbuf_dropped(&self) -> Result<u64, String> {
        Ok(self.fake.knobs.lock().unwrap().dropped)
    }

    fn drain_events(&mut self, sink: &mut dyn FnMut(&[u8])) {
        let ev = std::mem::take(&mut self.fake.knobs.lock().unwrap().events);
        for e in ev {
            sink(&e);
        }
    }
}

const CORE_RULES: &str = r#"[
  {"id":"core-a","enabled":true,"hook":"exec","target":{"path_prefix":"/tmp"},"action":"alert"},
  {"id":"core-b","enabled":true,"hook":"listen","target":"any","action":"alert"}
]"#;

struct Env {
    dir: tempfile::TempDir,
    fake: Fake,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let core = dir.path().join("builtin/core");
        std::fs::create_dir_all(&core).unwrap();
        std::fs::write(
            core.join("manifest.json"),
            json!({"name":"core","version":"0.0.1","min_sensr":"0.0.0",
                   "programs":["core.bpf.o"],"rules":"rules.json"})
            .to_string(),
        )
        .unwrap();
        std::fs::write(core.join("core.bpf.o"), b"builtin object").unwrap();
        std::fs::write(core.join("rules.json"), CORE_RULES).unwrap();
        for d in ["state", "keys", "boot"] {
            std::fs::create_dir_all(dir.path().join(d)).unwrap();
        }
        std::fs::write(
            dir.path().join("lockdown"),
            "[none] integrity confidentiality\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("running-release"), "v1.0.0\n").unwrap();
        std::fs::write(dir.path().join("lsm"), "capability,landlock,yama,bpf").unwrap();
        let env = Env {
            dir,
            fake: Fake::default(),
        };
        env.config(json!({}));
        env
    }

    /// Another built-in pack with these rules.
    fn builtin(&self, name: &str, rules: serde_json::Value) {
        let d = self.p(&format!("builtin/{name}"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("manifest.json"),
            json!({"name":name,"version":"0.0.1","min_sensr":"0.0.0",
                   "programs":[format!("{name}.bpf.o")],"rules":"rules.json"})
            .to_string(),
        )
        .unwrap();
        std::fs::write(d.join(format!("{name}.bpf.o")), b"object").unwrap();
        std::fs::write(d.join("rules.json"), rules.to_string()).unwrap();
    }

    fn p(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    /// Write guard.json: the defaults merged with `extra`.
    fn config(&self, extra: serde_json::Value) {
        let mut c = json!({"enabled": true, "retention_days": 30, "max_rows": 200000});
        for (k, v) in extra.as_object().unwrap() {
            c[k] = v.clone();
        }
        std::fs::write(self.p("guard.json"), c.to_string()).unwrap();
    }

    fn opts(&self) -> Options {
        Options {
            config: self.p("guard.json"),
            state_dir: self.p("state"),
            builtin_dir: self.p("builtin"),
            keys_dir: self.p("keys"),
            kill_switch_file: self.p("boot/guard-off"),
            lockdown_file: self.p("lockdown"),
            release_file: self.p("running-release"),
            lsm_file: self.p("lsm"),
            confirm_window: WINDOW,
            own_tgid: 4242,
            clock: BootClock::new(1_700_000_000_000, 0),
            arch: "aarch64".into(),
        }
    }

    fn start(&self) -> Daemon<Fake> {
        Daemon::start(self.opts(), self.fake.clone()).unwrap_or_else(|e| panic!("{e}"))
    }

    fn last_apply(&self) -> Apply {
        self.fake
            .log
            .lock()
            .unwrap()
            .applies
            .last()
            .cloned()
            .unwrap()
    }

    fn applies(&self) -> usize {
        self.fake.log.lock().unwrap().applies.len()
    }

    fn knobs(&self) -> std::sync::MutexGuard<'_, Knobs> {
        self.fake.knobs.lock().unwrap()
    }
}

/// The confirm window the daemon gives a change that lets rules block again.
const WINDOW: Duration = Duration::from_secs(120);

fn rule<'a>(s: &'a StatusView, id: &str) -> &'a RuleStatus {
    s.rules
        .iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("no rule {id} in {:#?}", s.rules))
}

const OWNER: &str = "6d0de000-0000-4000-8000-000000000001";

fn owner_rule(hook: &str, target: serde_json::Value, action: &str) -> serde_json::Value {
    json!({"id": OWNER, "enabled": true, "hook": hook, "target": target, "action": action})
}

#[test]
fn starts_with_the_builtin_pack_and_merges_rules() {
    let env = Env::new();
    env.config(json!({"rules": [owner_rule("connect", json!({"net": {"cidr": "192.0.2.0/24"}}), "alert")]}));
    let d = env.start();
    let s = d.status();
    assert!(s.running && s.enforcing && !s.kill_switch, "{s:#?}");
    assert_eq!(s.reason, None);
    assert_eq!(s.lockdown, "none");
    assert_eq!(env.fake.log.lock().unwrap().loads, ["0.0.1"]);
    assert_eq!(s.packs.len(), 1);
    assert_eq!(s.packs[0].source, PackSource::Builtin);
    assert_eq!(s.packs[0].programs.len(), 14);
    let (ids, _, _, kill) = env.last_apply();
    assert_eq!(
        ids,
        ["core-a", "core-b", OWNER],
        "pack rules first, then the owner's"
    );
    assert!(!kill);
    assert_eq!(rule(&s, "core-a").pack.as_deref(), Some("core"));
    let o = rule(&s, OWNER);
    assert!(o.active && o.pack.is_none() && o.slot == Some(2), "{o:?}");
    assert_eq!(o.hits, 1, "hits are reported by rule id");
}

#[test]
fn rule_on_unattached_hook_is_inactive() {
    let env = Env::new();
    env.knobs()
        .unattached
        .insert("guard_connect".into(), "the verifier said no".into());
    env.config(json!({"rules": [owner_rule("connect", json!({"net": {"cidr": "192.0.2.0/24"}}), "block")]}));
    let d = env.start();
    let s = d.status();
    let o = rule(&s, OWNER);
    assert!(!o.active, "{o:?}");
    let why = o.reason.as_deref().unwrap();
    assert!(
        why.contains("guard_connect") && why.contains("the verifier said no"),
        "{why}"
    );
    assert!(rule(&s, "core-a").active, "exec still works");
    let p = s.packs[0]
        .programs
        .iter()
        .find(|p| p.name == "guard_connect")
        .unwrap();
    assert!(!p.attached);
}

#[test]
fn an_exe_rule_needs_exec_tracking() {
    let env = Env::new();
    env.knobs()
        .unattached
        .insert("guard_exec_inherit".into(), "no task_alloc".into());
    env.config(
        json!({"rules": [{"id": OWNER, "enabled": true, "hook": "connect",
        "process": {"exe_prefix": "/usr/bin"}, "target": "any", "action": "alert"}]}),
    );
    let s = env.start().status();
    assert!(!rule(&s, OWNER).active);
    assert!(
        rule(&s, OWNER)
            .reason
            .as_deref()
            .unwrap()
            .contains("task_alloc")
    );
}

#[test]
fn kill_switch_file_disables_blocking() {
    let env = Env::new();
    std::fs::write(env.p("boot/guard-off"), "").unwrap();
    env.config(json!({"rules": [owner_rule("connect", json!({"net": {"cidr": "192.0.2.0/24"}}), "block")]}));
    let mut d = env.start();
    let s = d.status();
    assert!(s.kill_switch);
    assert!(env.last_apply().3, "applied with the kill switch on");
    let o = rule(&s, OWNER);
    assert!(!o.active);
    assert!(
        o.reason.as_deref().unwrap().contains("kill switch"),
        "{o:?}"
    );
    assert!(rule(&s, "core-a").active, "alerts still apply");
    // the owner's file wins over a live "on"
    let Reply::Error(e) = d.handle(&Request::KillSwitch { on: false }) else {
        panic!("off must be refused while the file exists");
    };
    assert!(e.contains("guard-off"), "{e}");
    assert!(d.status().kill_switch);
}

#[test]
fn kill_switch_toggles_live_and_persists() {
    let env = Env::new();
    let mut d = env.start();
    assert!(!env.last_apply().3);
    assert_eq!(d.handle(&Request::KillSwitch { on: true }), Reply::Ok);
    assert!(env.last_apply().3 && d.status().kill_switch);
    assert!(env.p("state").join(KILL_SWITCH_STATE).exists());
    drop(d);
    let mut d = env.start();
    assert!(d.status().kill_switch, "a restart keeps it on");
    assert!(matches!(
        d.handle(&Request::KillSwitch { on: false }),
        Reply::Pending(_)
    ));
    assert!(!env.last_apply().3 && !d.status().kill_switch);
    assert_eq!(d.handle(&Request::Confirm), Reply::Ok);
    assert!(!env.p("state").join(KILL_SWITCH_STATE).exists());
}

#[test]
fn reload_with_bad_rule_keeps_previous() {
    let env = Env::new();
    env.config(json!({"rules": [owner_rule("connect", json!({"net": {"cidr": "192.0.2.0/24"}}), "alert")]}));
    let mut d = env.start();
    let before = env.applies();
    // a path target on the connect hook does not compile
    env.config(json!({"rules": [owner_rule("connect", json!({"path_prefix": "/etc"}), "block")]}));
    let Reply::Error(e) = d.handle(&Request::Reload) else {
        panic!("a bad rule must be refused");
    };
    assert!(e.contains(OWNER) && e.contains("kept"), "{e}");
    assert_eq!(env.applies(), before, "nothing was applied");
    let s = d.status();
    assert!(s.enforcing);
    assert!(rule(&s, OWNER).active);
    assert_eq!(rule(&s, OWNER).action, sensr_guard::rule::Action::Alert);
    // an unparseable file too
    std::fs::write(env.p("guard.json"), "{").unwrap();
    assert!(matches!(d.handle(&Request::Reload), Reply::Error(_)));
    // a good one goes through
    env.config(json!({"rules": [owner_rule("connect", json!({"net": {"cidr": "198.51.100.0/24"}}), "block")]}));
    assert_eq!(d.handle(&Request::Reload), Reply::Ok);
    assert_eq!(env.applies(), before + 1);
    assert_eq!(
        rule(&d.status(), OWNER).action,
        sensr_guard::rule::Action::Block
    );
}

#[test]
fn bad_owner_rules_at_start_still_run_the_pack_rules() {
    let env = Env::new();
    env.config(json!({"rules": [owner_rule("connect", json!({"path_prefix": "/etc"}), "block")]}));
    let s = env.start().status();
    assert_eq!(env.last_apply().0, ["core-a", "core-b"]);
    assert!(rule(&s, "core-a").active);
    let o = rule(&s, OWNER);
    assert!(!o.active && o.reason.as_deref().unwrap().contains("not applied"));
    assert!(s.reason.as_deref().unwrap().contains("owner"));
}

#[test]
fn pack_override_disables_default_rule() {
    let env = Env::new();
    env.config(json!({"pack_rules": [
        {"pack": "core", "rule_id": "core-a", "enabled": false},
        {"pack": "core", "rule_id": "core-b", "action": "block"},
        {"pack": "other", "rule_id": "core-b", "enabled": false}
    ]}));
    let s = env.start().status();
    let (ids, enabled, actions, _) = env.last_apply();
    assert_eq!(ids, ["core-a", "core-b"], "a disabled rule keeps its slot");
    assert_eq!(enabled, [0, 1]);
    assert_eq!(actions, [0, 1], "core-b now blocks");
    let a = rule(&s, "core-a");
    assert!(!a.active && a.reason.as_deref() == Some("disabled"));
    assert!(rule(&s, "core-b").active);
    assert_eq!(rule(&s, "core-b").action, sensr_guard::rule::Action::Block);
}

#[test]
fn pack_switched_off_loads_nothing() {
    let env = Env::new();
    env.config(json!({"packs": [{"name": "core", "enabled": false}],
        "rules": [owner_rule("exec", json!("any"), "alert")]}));
    let s = env.start().status();
    assert!(env.fake.log.lock().unwrap().loads.is_empty());
    assert!(!s.running && !s.enforcing);
    assert!(!s.packs[0].active && s.packs[0].reason.as_deref() == Some("switched off"));
    assert!(!rule(&s, OWNER).active);
}

#[test]
fn lockdown_confidentiality_refuses_start() {
    let env = Env::new();
    std::fs::write(env.p("lockdown"), "none integrity [confidentiality]\n").unwrap();
    let Err(e) = Daemon::start(env.opts(), env.fake.clone()) else {
        panic!("must refuse");
    };
    assert!(matches!(e, StartError::Lockdown(ref m) if m == "confidentiality"));
    assert!(e.to_string().contains("lockdown"), "{e}");
    assert!(
        env.fake.log.lock().unwrap().loads.is_empty(),
        "nothing loaded"
    );
    assert_eq!(
        parse_lockdown("none [integrity] confidentiality"),
        "integrity"
    );
    assert_eq!(parse_lockdown(""), "none");
    // integrity mode is fine
    std::fs::write(env.p("lockdown"), "none [integrity] confidentiality\n").unwrap();
    assert_eq!(env.start().status().lockdown, "integrity");
}

#[test]
fn apply_failure_reports_not_enforcing() {
    let env = Env::new();
    env.knobs().fail_apply = Some("map rules_meta: no space".into());
    let s = env.start().status();
    assert!(s.running && !s.enforcing, "{s:#?}");
    assert!(s.reason.as_deref().unwrap().contains("no space"));
    assert!(s.rules.iter().all(|r| !r.active));
}

// --- packs -----------------------------------------------------------------

fn keypair(env: &Env) -> KeyPair {
    let kp = KeyPair::generate_unencrypted_keypair().unwrap();
    std::fs::write(env.p("keys/test.pub"), kp.pk.to_box().unwrap().to_string()).unwrap();
    kp
}

fn sign(kp: &KeyPair, data: &[u8]) -> String {
    minisign::sign(Some(&kp.pk), &kp.sk, data, None, None)
        .unwrap()
        .to_string()
}

fn archive(version: &str, object: &[u8]) -> Vec<u8> {
    named_archive("core", version, object)
}

fn named_archive(name: &str, version: &str, object: &[u8]) -> Vec<u8> {
    full_archive(name, version, "0.0.0", CORE_RULES, object)
}

fn full_archive(name: &str, version: &str, min: &str, rules: &str, object: &[u8]) -> Vec<u8> {
    let manifest = json!({"name":name,"version":version,"min_sensr":min,
        "programs":["core.bpf.o"],"rules":"rules.json"})
    .to_string();
    let mut b = tar::Builder::new(Vec::new());
    for (name, data) in [
        ("manifest.json", manifest.as_bytes()),
        ("core.bpf.o", object),
        ("rules.json", rules.as_bytes()),
    ] {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, name, data).unwrap();
    }
    zstd::encode_all(&b.into_inner().unwrap()[..], 3).unwrap()
}

fn index(base: &str, entries: &[(&str, &str, &str)]) -> Vec<u8> {
    let packs: Vec<_> = entries
        .iter()
        .map(|(version, arch, file)| {
            json!({"name": "core", "version": version, "arch": arch,
                   "url": format!("{base}/{file}"), "sig_url": format!("{base}/{file}.minisig")})
        })
        .collect();
    json!({ "packs": packs }).to_string().into_bytes()
}

#[test]
fn check_packs_installs_newer_and_reloads() {
    let env = Env::new();
    let kp = keypair(&env);
    let a = archive("1.2.0", b"new object");
    let sig = sign(&kp, &a);
    let files = Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new()));
    let base = serve_shared(Arc::clone(&files));
    {
        let mut f = files.lock().unwrap();
        f.insert(
            "/guard-packs.json".into(),
            index(
                &base,
                &[
                    ("1.2.0", "aarch64", "core-1.2.0.tar.zst"),
                    // another architecture's newer build is not for us
                    ("9.0.0", "x86_64", "core-9.tar.zst"),
                ],
            ),
        );
        f.insert("/core-1.2.0.tar.zst".into(), a);
        f.insert("/core-1.2.0.tar.zst.minisig".into(), sig.into_bytes());
    }
    env.config(json!({"pack_index": format!("{base}/guard-packs.json")}));
    let d = Mutex::new(env.start());
    let Reply::Packs(r) = check_packs(&d, &HttpFetcher::allow_http()) else {
        panic!("expected per-pack results");
    };
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].name, "core");
    assert_eq!(r[0].current.as_deref(), Some("0.0.1"));
    assert_eq!(r[0].available.as_deref(), Some("1.2.0"));
    assert!(r[0].installed && r[0].error.is_none(), "{r:?}");
    assert_eq!(
        env.fake.log.lock().unwrap().loads,
        ["0.0.1", "1.2.0"],
        "reloaded"
    );
    let s = d.lock().unwrap().status();
    assert_eq!(s.packs[0].version, "1.2.0");
    assert_eq!(s.packs[0].source, PackSource::Signed);
    assert!(s.enforcing);
    assert!(
        !auto_check_due(&env.p("state"), now()),
        "the check was recorded"
    );
    // nothing newer now
    let Reply::Packs(r) = check_packs(&d, &HttpFetcher::allow_http()) else {
        panic!()
    };
    assert!(!r[0].installed && r[0].error.is_none());
    assert_eq!(env.fake.log.lock().unwrap().loads.len(), 2);
}

#[test]
fn check_packs_keeps_current_on_bad_sig() {
    let env = Env::new();
    let kp = keypair(&env);
    let other = KeyPair::generate_unencrypted_keypair().unwrap();
    let a = archive("1.2.0", b"new object");
    let files = Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new()));
    let base = serve_shared(Arc::clone(&files));
    {
        let mut f = files.lock().unwrap();
        f.insert(
            "/guard-packs.json".into(),
            index(&base, &[("1.2.0", "aarch64", "core.tar.zst")]),
        );
        // signed by a key the image does not trust
        f.insert(
            "/core.tar.zst.minisig".into(),
            sign(&other, &a).into_bytes(),
        );
        f.insert("/core.tar.zst".into(), a.clone());
    }
    let _ = &kp;
    env.config(json!({"pack_index": format!("{base}/guard-packs.json")}));
    let d = Mutex::new(env.start());
    let Reply::Packs(r) = check_packs(&d, &HttpFetcher::allow_http()) else {
        panic!()
    };
    assert!(!r[0].installed);
    assert!(
        r[0].error.as_deref().unwrap().contains("not trusted"),
        "{r:?}"
    );
    // a tampered archive with a trusted key's signature over the original
    {
        let mut f = files.lock().unwrap();
        f.insert("/core.tar.zst.minisig".into(), sign(&kp, &a).into_bytes());
        let mut bad = a;
        *bad.last_mut().unwrap() ^= 1;
        f.insert("/core.tar.zst".into(), bad);
    }
    let Reply::Packs(r) = check_packs(&d, &HttpFetcher::allow_http()) else {
        panic!()
    };
    assert!(
        r[0].error.as_deref().unwrap().contains("does not verify"),
        "{r:?}"
    );
    assert_eq!(env.fake.log.lock().unwrap().loads, ["0.0.1"], "no reload");
    let s = d.lock().unwrap().status();
    assert_eq!(s.packs[0].version, "0.0.1");
    assert!(s.enforcing);
    assert!(!env.p("state/packs/core/current").exists());
}

#[test]
fn check_packs_reports_an_unreachable_index() {
    let env = Env::new();
    let base = serve_shared(Arc::new(Mutex::new(HashMap::new())));
    env.config(json!({"pack_index": format!("{base}/guard-packs.json")}));
    let d = Mutex::new(env.start());
    let Reply::Error(e) = check_packs(&d, &HttpFetcher::allow_http()) else {
        panic!()
    };
    assert!(e.contains("404"), "{e}");
}

#[test]
fn load_failure_keeps_last_good() {
    let env = Env::new();
    let kp = keypair(&env);
    let a = archive("1.2.0", b"new object");
    sensr_guard::packs::install(
        &a,
        &sign(&kp, &a),
        &sensr_guard::packs::load_keys(&env.p("keys")).unwrap(),
        &env.p("state"),
        &Version::new(1, 0, 0),
        false,
    )
    .unwrap();
    // 1.2.0 is rejected by the kernel: the built-in copy runs, and says why
    env.knobs().fail_load.push("1.2.0".into());
    let mut d = env.start();
    let s = d.status();
    assert_eq!(s.packs[0].version, "0.0.1");
    assert!(s.packs[0].active && s.enforcing);
    assert!(
        s.packs[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("verifier rejected 1.2.0"),
        "{:?}",
        s.packs[0]
    );
    // now 1.2.0 loads; then 1.3.0 arrives and fails: 1.2.0 keeps running
    env.knobs().fail_load.clear();
    assert_eq!(d.handle(&Request::Reload), Reply::Ok);
    assert_eq!(d.status().packs[0].version, "1.2.0");
    let b = archive("1.3.0", b"newer object");
    sensr_guard::packs::install(
        &b,
        &sign(&kp, &b),
        &sensr_guard::packs::load_keys(&env.p("keys")).unwrap(),
        &env.p("state"),
        &Version::new(1, 0, 0),
        false,
    )
    .unwrap();
    env.knobs().fail_load.push("1.3.0".into());
    assert_eq!(d.handle(&Request::Reload), Reply::Ok);
    let s = d.status();
    assert_eq!(s.packs[0].version, "1.2.0");
    assert!(s.packs[0].reason.as_deref().unwrap().contains("1.3.0"));
    assert!(s.enforcing);
}

#[test]
fn auto_check_is_daily() {
    let dir = tempfile::tempdir().unwrap();
    assert!(auto_check_due(dir.path(), 1000), "never checked");
    std::fs::write(dir.path().join("last-pack-check"), "1000\n").unwrap();
    assert!(!auto_check_due(dir.path(), 1000 + 3600));
    assert!(auto_check_due(dir.path(), 1000 + 24 * 3600));
    assert!(auto_check_due(dir.path(), 10), "a clock that went back");
}

// --- events ----------------------------------------------------------------

fn raw_event(hook: u8, blocked: bool, target: &str) -> Vec<u8> {
    let mut b = vec![0u8; size_of::<GuardEvent>()];
    b[0..8].copy_from_slice(&5_000_000_000u64.to_le_bytes());
    b[offset_of!(GuardEvent, pid)..][..4].copy_from_slice(&42u32.to_le_bytes());
    b[offset_of!(GuardEvent, hook)] = hook;
    b[offset_of!(GuardEvent, action)] = u8::from(blocked);
    b[offset_of!(GuardEvent, blocked)] = u8::from(blocked);
    b[offset_of!(GuardEvent, exe)..][..7].copy_from_slice(b"/bin/sh");
    b[offset_of!(GuardEvent, target)..][..target.len()].copy_from_slice(target.as_bytes());
    b
}

#[test]
fn events_flow_into_batches_and_counters() {
    let env = Env::new();
    let mut d = env.start();
    let t0 = Instant::now();
    env.knobs().boot_complete = true;
    env.knobs().events = vec![raw_event(0, false, "/tmp/x"), raw_event(0, false, "/tmp/x")];
    env.knobs().dropped = 7;
    assert!(d.poll_events(t0).is_empty(), "the first batch waits");
    let s = d.status();
    assert_eq!(s.dropped_kernel, 7);
    assert!(s.boot_complete);
    let b = d.poll_events(t0 + Duration::from_secs(16));
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].rows.len(), 1);
    assert_eq!(b[0].rows[0].count, 2, "deduplicated");
    // a failed write goes back and leaves with the drain
    d.requeue(b[0].clone());
    let drained = d.drain().unwrap();
    assert_eq!(drained.rows, b[0].rows);
}

#[test]
fn module_events_wait_for_boot_complete() {
    let env = Env::new();
    let mut d = env.start();
    let t0 = Instant::now();
    env.knobs().events = vec![
        raw_event(5, false, "/lib/modules/x.ko"),
        raw_event(5, true, "/lib/modules/blocked.ko"),
        raw_event(0, false, "/tmp/x"),
    ];
    assert!(d.poll_events(t0).is_empty());
    assert!(!d.status().boot_complete);
    let rows = d.drain().unwrap().rows;
    let targets: Vec<_> = rows.iter().map(|r| r.target.as_str()).collect();
    assert!(
        targets.contains(&"/lib/modules/blocked.ko") && targets.contains(&"/tmp/x"),
        "{targets:?}"
    );
    assert!(!targets.contains(&"/lib/modules/x.ko"), "{targets:?}");
    // boot completes; checked at most once a second
    env.knobs().boot_complete = true;
    env.knobs().events = vec![raw_event(5, false, "/lib/modules/y.ko")];
    d.poll_events(t0 + Duration::from_millis(500));
    assert!(
        !d.status().boot_complete,
        "not checked again within a second"
    );
    assert!(d.drain().is_none());
    env.knobs().events = vec![raw_event(5, false, "/lib/modules/z.ko")];
    d.poll_events(t0 + Duration::from_secs(2));
    assert!(d.status().boot_complete);
    assert_eq!(d.drain().unwrap().rows[0].target, "/lib/modules/z.ko");
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// A tiny HTTP/1.1 server for `files` (path -> body, changeable while it
/// runs); 404 otherwise.
fn serve_shared(files: Arc<Mutex<HashMap<String, Vec<u8>>>>) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            if r.read_line(&mut line).is_err() {
                continue;
            }
            let path = line.split_whitespace().nth(1).unwrap_or("/").to_owned();
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                    break;
                }
            }
            let body = files.lock().unwrap().get(&path).cloned();
            let (status, body) = match body {
                Some(b) => ("200 OK", b),
                None => ("404 Not Found", b"no".to_vec()),
            };
            let _ = write!(
                s,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(&body);
            let _ = s.flush();
        }
    });
    base
}

// --- the socket ------------------------------------------------------------

#[tokio::test]
async fn socket_serves_status_kill_switch_and_errors() {
    use sensr_guard::server::{Shared, bind, serve};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};

    let env = Env::new();
    let sock = env.p("guard.sock");
    std::fs::write(&sock, "stale").unwrap();
    let uid = own_uid(&env);
    let shared = Arc::new(
        Shared::new(env.start(), Box::new(HttpFetcher::allow_http())).with_trusted(vec![uid]),
    );
    let l = bind(&sock).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
        0o660
    );
    tokio::spawn(serve(l, Arc::clone(&shared)));

    let s = tokio::net::UnixStream::connect(&sock).await.unwrap();
    let (r, mut w) = s.into_split();
    let mut r = TokioBufReader::new(r).lines();
    let mut ask = async |line: &str| -> Reply {
        w.write_all(format!("{line}\n").as_bytes()).await.unwrap();
        let reply = r.next_line().await.unwrap().unwrap();
        serde_json::from_str(&reply).unwrap_or_else(|e| panic!("{reply}: {e}"))
    };
    let Reply::Status(s) = ask(r#"{"op":"status"}"#).await else {
        panic!("status")
    };
    assert!(s.running && !s.kill_switch);
    assert_eq!(ask(r#"{"op":"kill_switch","on":true}"#).await, Reply::Ok);
    let Reply::Status(s) = ask(r#"{"op":"status"}"#).await else {
        panic!()
    };
    assert!(s.kill_switch);
    assert!(env.last_apply().3);
    let Reply::Error(e) = ask(r#"{"op":"nope"}"#).await else {
        panic!()
    };
    assert!(e.contains("bad request"), "{e}");
    assert_eq!(ask(r#"{"op":"reload"}"#).await, Reply::Ok);
    assert!(
        shared.lock().status().kill_switch,
        "reload keeps the kill switch"
    );
}

#[test]
fn builtin_wins_when_at_least_as_new() {
    let env = Env::new();
    let kp = keypair(&env);
    // an installed copy of the same version as the image's
    let a = archive("0.0.1", b"installed object");
    sensr_guard::packs::install(
        &a,
        &sign(&kp, &a),
        &sensr_guard::packs::load_keys(&env.p("keys")).unwrap(),
        &env.p("state"),
        &Version::new(1, 0, 0),
        false,
    )
    .unwrap();
    let s = env.start().status();
    assert_eq!(s.packs[0].source, PackSource::Builtin, "{:?}", s.packs[0]);
    assert_eq!(s.packs[0].version, "0.0.1");
}

// --- fix round 1 ------------------------------------------------------------

#[test]
fn reload_with_owner_id_clashing_with_pack_rule_keeps_previous() {
    let env = Env::new();
    env.config(json!({"rules": [owner_rule("connect", json!({"net": {"cidr": "192.0.2.0/24"}}), "alert")]}));
    let mut d = env.start();
    let before = env.applies();
    // compiles on its own, but core-a is already a pack rule id
    env.config(
        json!({"rules": [{"id": "core-a", "enabled": true, "hook": "exec",
        "target": "any", "action": "block"}]}),
    );
    let Reply::Error(e) = d.handle(&Request::Reload) else {
        panic!("a clashing rule id must be refused");
    };
    assert!(e.contains("core-a") && e.contains("kept"), "{e}");
    assert_eq!(env.applies(), before, "nothing was applied");
    let s = d.status();
    assert!(rule(&s, OWNER).active, "the previous owner rule still runs");
    assert!(s.reason.is_none(), "{:?}", s.reason);
}

#[test]
fn sensr_release_comes_from_the_updater_record() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("running-release");
    std::fs::write(&f, "v0.1.31\n").unwrap();
    assert_eq!(sensr_release(&f), Some(Version::new(0, 1, 31)));
    std::fs::write(&f, "0.2.0").unwrap();
    assert_eq!(sensr_release(&f), Some(Version::new(0, 2, 0)));
    std::fs::write(&f, "26.11.20261113.d5cc683").unwrap();
    assert_eq!(sensr_release(&f), None, "a nixos label is not a release");
    assert_eq!(sensr_release(&dir.path().join("missing")), None);
}

#[test]
fn fetch_refuses_plain_http() {
    let env = Env::new();
    let base = serve_shared(Arc::new(Mutex::new(HashMap::new())));
    env.config(json!({"pack_index": format!("{base}/guard-packs.json")}));
    let d = Mutex::new(env.start());
    let Reply::Error(e) = check_packs(&d, &HttpFetcher::default()) else {
        panic!()
    };
    assert!(e.contains("https"), "{e}");
}

#[test]
fn index_entries_must_be_https() {
    let env = Env::new();
    let kp = keypair(&env);
    let a = archive("1.2.0", b"new object");
    let files = Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new()));
    let base = serve_shared(Arc::clone(&files));
    let mut idx: serde_json::Value =
        serde_json::from_slice(&index(&base, &[("1.2.0", "aarch64", "core.tar.zst")])).unwrap();
    idx["packs"][0]["url"] = json!("ftp://example.test/core.tar.zst");
    files
        .lock()
        .unwrap()
        .insert("/guard-packs.json".into(), idx.to_string().into_bytes());
    files
        .lock()
        .unwrap()
        .insert("/core.tar.zst".into(), a.clone());
    files
        .lock()
        .unwrap()
        .insert("/core.tar.zst.minisig".into(), sign(&kp, &a).into_bytes());
    env.config(json!({"pack_index": format!("{base}/guard-packs.json")}));
    let d = Mutex::new(env.start());
    let Reply::Packs(r) = check_packs(&d, &HttpFetcher::allow_http()) else {
        panic!()
    };
    assert!(!r[0].installed);
    assert!(r[0].error.as_deref().unwrap().contains("ftp://"), "{r:?}");
}

#[test]
fn check_packs_refuses_an_archive_of_another_pack() {
    let env = Env::new();
    let kp = keypair(&env);
    let a = named_archive("extra", "1.2.0", b"other object");
    let files = Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new()));
    let base = serve_shared(Arc::clone(&files));
    {
        let mut f = files.lock().unwrap();
        f.insert(
            "/guard-packs.json".into(),
            index(&base, &[("1.2.0", "aarch64", "core.tar.zst")]),
        );
        f.insert("/core.tar.zst.minisig".into(), sign(&kp, &a).into_bytes());
        f.insert("/core.tar.zst".into(), a);
    }
    env.config(json!({"pack_index": format!("{base}/guard-packs.json")}));
    let d = Mutex::new(env.start());
    let Reply::Packs(r) = check_packs(&d, &HttpFetcher::allow_http()) else {
        panic!()
    };
    assert!(!r[0].installed);
    assert!(r[0].error.as_deref().unwrap().contains("extra"), "{r:?}");
    assert!(!env.p("state/packs/extra").exists(), "nothing installed");
}

#[test]
fn auto_check_backs_off_after_a_failed_attempt() {
    let dir = tempfile::tempdir().unwrap();
    record_attempt(dir.path(), 1000);
    assert!(!auto_check_due(dir.path(), 1000 + 600), "within the hour");
    assert!(auto_check_due(dir.path(), 1000 + 3600), "an hour later");
    // a success a day ago and an attempt just now: wait
    std::fs::write(dir.path().join("last-pack-check"), "0\n").unwrap();
    record_attempt(dir.path(), 100_000);
    assert!(!auto_check_due(dir.path(), 100_010));
}

#[test]
fn mutating_requests_need_a_trusted_peer() {
    use sensr_guard::server::authorize;
    let trusted = [0, 731];
    for req in [
        Request::Reload,
        Request::KillSwitch { on: true },
        Request::CheckPacks,
    ] {
        assert!(authorize(&req, Some(0), &trusted).is_ok());
        assert!(authorize(&req, Some(731), &trusted).is_ok());
        let e = authorize(&req, Some(1000), &trusted).unwrap_err();
        assert!(e.contains("uid 1000") && e.contains("not allowed"), "{e}");
        assert!(authorize(&req, None, &trusted).is_err(), "unknown peer");
    }
    assert!(authorize(&Request::Status, Some(1000), &trusted).is_ok());
    assert!(authorize(&Request::Status, None, &trusted).is_ok());
}

#[tokio::test]
async fn socket_refuses_mutations_from_untrusted_peers() {
    use sensr_guard::server::{Shared, bind, serve};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};

    let env = Env::new();
    let sock = env.p("guard.sock");
    // only root is trusted; this test does not run as root
    let shared = Arc::new(
        Shared::new(env.start(), Box::new(HttpFetcher::allow_http())).with_trusted(vec![0]),
    );
    if own_uid(&env) == 0 {
        return;
    }
    tokio::spawn(serve(bind(&sock).unwrap(), Arc::clone(&shared)));
    let s = tokio::net::UnixStream::connect(&sock).await.unwrap();
    let (r, mut w) = s.into_split();
    let mut r = TokioBufReader::new(r).lines();
    w.write_all(b"{\"op\":\"kill_switch\",\"on\":true}\n{\"op\":\"status\"}\n")
        .await
        .unwrap();
    let first: Reply = serde_json::from_str(&r.next_line().await.unwrap().unwrap()).unwrap();
    let Reply::Error(e) = first else {
        panic!("{first:?}")
    };
    assert!(e.contains("not allowed"), "{e}");
    let second: Reply = serde_json::from_str(&r.next_line().await.unwrap().unwrap()).unwrap();
    let Reply::Status(s) = second else { panic!() };
    assert!(!s.kill_switch, "nothing changed");
}

fn own_uid(env: &Env) -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(env.p("guard.json")).unwrap().uid()
}

// --- fix round 2 ------------------------------------------------------------

const EXTRA_RULES: &str =
    r#"[{"id":"x-1","enabled":true,"hook":"setuid","target":{"uid":0},"action":"alert"}]"#;

#[test]
fn reload_disabling_core_moves_owner_rules_to_the_next_pack() {
    let env = Env::new();
    env.builtin(
        "more",
        json!([{"id":"more-1","enabled":true,"hook":"bpf","target":"any","action":"alert"}]),
    );
    let owner = owner_rule("connect", json!({"net": {"cidr": "192.0.2.0/24"}}), "alert");
    env.config(json!({ "rules": [owner.clone()] }));
    let mut d = env.start();
    assert_eq!(env.last_apply().0, ["more-1"], "more: its own rules only");
    env.config(json!({"packs": [{"name": "core", "enabled": false}], "rules": [owner.clone()]}));
    assert_eq!(d.handle(&Request::Reload), Reply::Ok);
    let s = d.status();
    assert_eq!(
        env.last_apply().0,
        ["more-1", OWNER],
        "the owner's rules moved"
    );
    let o = rule(&s, OWNER);
    assert!(o.active && o.slot == Some(1), "{o:?}");
    assert!(s.reason.is_none(), "{:?}", s.reason);
    // with no pack left they are shown inactive, not dropped
    env.config(json!({"packs": [{"name": "core", "enabled": false},
        {"name": "more", "enabled": false}], "rules": [owner]}));
    assert_eq!(d.handle(&Request::Reload), Reply::Ok);
    let s = d.status();
    let o = rule(&s, OWNER);
    assert!(
        !o.active && o.reason.as_deref() == Some("no pack is loaded"),
        "{o:?}"
    );
}

#[test]
fn reload_enabling_a_clashing_pack_changes_nothing() {
    let env = Env::new();
    env.builtin("extra", serde_json::from_str(EXTRA_RULES).unwrap());
    // the owner's rule has the id of extra's rule
    let owner = json!({"id": "x-1", "enabled": true, "hook": "exec", "target": "any",
        "action": "alert"});
    env.config(json!({"packs": [{"name": "extra", "enabled": false}], "rules": [owner.clone()]}));
    let mut d = env.start();
    let before = env.applies();
    let loads = env.fake.log.lock().unwrap().loads.len();
    // core off, extra on: the owner's rules would go to extra and clash
    env.config(json!({"packs": [{"name": "core", "enabled": false},
        {"name": "extra", "enabled": true}], "rules": [owner]}));
    let Reply::Error(e) = d.handle(&Request::Reload) else {
        panic!("the clash must be refused");
    };
    assert!(e.contains("x-1") && e.contains("kept"), "{e}");
    assert_eq!(env.applies(), before);
    assert_eq!(
        env.fake.log.lock().unwrap().loads.len(),
        loads,
        "nothing loaded"
    );
    let s = d.status();
    assert!(s.packs.iter().any(|p| p.name == "core" && p.active));
    assert!(rule(&s, "x-1").active && rule(&s, "x-1").pack.is_none());
}

#[test]
fn check_packs_refuses_a_version_whose_rules_clash() {
    let env = Env::new();
    let kp = keypair(&env);
    let rules = format!(
        r#"[{{"id":"{OWNER}","enabled":true,"hook":"exec","target":"any","action":"alert"}}]"#
    );
    let a = full_archive("core", "1.2.0", "0.0.0", &rules, b"new object");
    let files = Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new()));
    let base = serve_shared(Arc::clone(&files));
    {
        let mut f = files.lock().unwrap();
        f.insert(
            "/guard-packs.json".into(),
            index(&base, &[("1.2.0", "aarch64", "core.tar.zst")]),
        );
        f.insert("/core.tar.zst.minisig".into(), sign(&kp, &a).into_bytes());
        f.insert("/core.tar.zst".into(), a);
    }
    env.config(json!({"pack_index": format!("{base}/guard-packs.json"),
        "rules": [owner_rule("connect", json!({"net": {"cidr": "192.0.2.0/24"}}), "alert")]}));
    let d = Mutex::new(env.start());
    let Reply::Packs(r) = check_packs(&d, &HttpFetcher::allow_http()) else {
        panic!()
    };
    assert!(!r[0].installed, "{r:?}");
    assert!(
        r[0].error.as_deref().unwrap().contains("do not merge"),
        "{r:?}"
    );
    assert!(!env.p("state/packs/core/current").exists());
    let s = d.lock().unwrap().status();
    assert_eq!(s.packs[0].version, "0.0.1");
    assert!(rule(&s, OWNER).active);
}

#[test]
fn packs_needing_a_release_wait_until_the_release_is_known() {
    let env = Env::new();
    std::fs::remove_file(env.p("running-release")).unwrap();
    let kp = keypair(&env);
    let a = full_archive("core", "1.2.0", "0.1.31", CORE_RULES, b"new object");
    let files = Arc::new(Mutex::new(HashMap::<String, Vec<u8>>::new()));
    let base = serve_shared(Arc::clone(&files));
    {
        let mut f = files.lock().unwrap();
        f.insert(
            "/guard-packs.json".into(),
            index(&base, &[("1.2.0", "aarch64", "core.tar.zst")]),
        );
        f.insert("/core.tar.zst.minisig".into(), sign(&kp, &a).into_bytes());
        f.insert("/core.tar.zst".into(), a);
    }
    env.config(json!({"pack_index": format!("{base}/guard-packs.json")}));
    let d = Mutex::new(env.start());
    let check = || {
        let Reply::Packs(r) = check_packs(&d, &HttpFetcher::allow_http()) else {
            panic!()
        };
        r
    };
    let r = check();
    assert!(!r[0].installed);
    assert!(
        r[0].error
            .as_deref()
            .unwrap()
            .contains("sensr release unknown"),
        "{r:?}"
    );
    // too old a release: refused, naming it
    std::fs::write(env.p("running-release"), "v0.1.30\n").unwrap();
    let r = check();
    assert!(
        !r[0].installed && r[0].error.as_deref().unwrap().contains("0.1.30"),
        "{r:?}"
    );
    // the updater records a new enough release: the next check installs it
    std::fs::write(env.p("running-release"), "v0.1.31\n").unwrap();
    let r = check();
    assert!(r[0].installed, "{r:?}");
    assert_eq!(d.lock().unwrap().status().packs[0].version, "1.2.0");
    // the record vanishes: a reload falls back to the built-in copy, saying why
    std::fs::remove_file(env.p("running-release")).unwrap();
    assert_eq!(d.lock().unwrap().handle(&Request::Reload), Reply::Ok);
    let s = d.lock().unwrap().status();
    assert_eq!(s.packs[0].version, "0.0.1");
    assert!(
        s.packs[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("sensr release unknown"),
        "{:?}",
        s.packs[0]
    );
}

// --- the kill switch's confirm window ----------------------------------------

/// A block rule, so turning the kill switch off really arms something.
fn blocking(env: &Env) {
    env.config(json!({"rules": [owner_rule("connect", json!({"net": {"cidr": "192.0.2.0/24"}}), "block")]}));
}

#[test]
fn kill_switch_off_rolls_back_unless_confirmed() {
    let env = Env::new();
    blocking(&env);
    let mut d = env.start();
    assert_eq!(d.handle(&Request::KillSwitch { on: true }), Reply::Ok);
    let t0 = Instant::now();
    let Reply::Pending(p) = d.handle(&Request::KillSwitch { on: false }) else {
        panic!("off lets rules block again: it must be confirmed");
    };
    assert!(p.kill_switch_off && p.released.is_empty(), "{p:?}");
    assert_eq!(p.window_secs, WINDOW.as_secs());
    let s = d.status();
    assert!(!s.kill_switch, "blocking in the window");
    assert!(!env.last_apply().3);
    assert_eq!(s.pending_confirm.as_ref(), Some(&p));
    assert!(rule(&s, OWNER).active);
    assert!(
        env.p("state").join(KILL_SWITCH_STATE).exists(),
        "a restart in the window comes back with the kill switch on"
    );
    // nothing yet before the deadline
    d.poll_events(t0 + WINDOW - Duration::from_secs(5));
    assert!(!d.status().kill_switch);
    // the deadline passes unconfirmed: on again, and it says why
    d.poll_events(t0 + WINDOW + Duration::from_secs(1));
    let s = d.status();
    assert!(s.kill_switch && s.pending_confirm.is_none(), "{s:#?}");
    assert!(env.last_apply().3);
    assert!(
        s.reason.as_deref().unwrap_or("").contains("not confirmed"),
        "{:?}",
        s.reason
    );
    assert!(matches!(d.handle(&Request::Confirm), Reply::Error(_)));
}

#[test]
fn kill_switch_off_confirmed_stays_off() {
    let env = Env::new();
    blocking(&env);
    let mut d = env.start();
    d.handle(&Request::KillSwitch { on: true });
    let t0 = Instant::now();
    assert!(matches!(
        d.handle(&Request::KillSwitch { on: false }),
        Reply::Pending(_)
    ));
    assert_eq!(d.handle(&Request::Confirm), Reply::Ok);
    assert!(!env.p("state").join(KILL_SWITCH_STATE).exists());
    d.poll_events(t0 + WINDOW * 2);
    let s = d.status();
    assert!(!s.kill_switch && s.pending_confirm.is_none());
    drop(d);
    assert!(!env.start().status().kill_switch, "kept across a restart");
}

#[test]
fn a_restart_in_the_window_comes_back_with_the_kill_switch_on() {
    let env = Env::new();
    blocking(&env);
    let mut d = env.start();
    d.handle(&Request::KillSwitch { on: true });
    assert!(matches!(
        d.handle(&Request::KillSwitch { on: false }),
        Reply::Pending(_)
    ));
    drop(d);
    let s = env.start().status();
    assert!(s.kill_switch && s.pending_confirm.is_none());
}

#[test]
fn kill_switch_on_in_the_window_ends_it() {
    let env = Env::new();
    blocking(&env);
    let mut d = env.start();
    d.handle(&Request::KillSwitch { on: true });
    d.handle(&Request::KillSwitch { on: false });
    assert_eq!(d.handle(&Request::KillSwitch { on: true }), Reply::Ok);
    let s = d.status();
    assert!(s.kill_switch && s.pending_confirm.is_none());
    assert!(matches!(d.handle(&Request::Confirm), Reply::Error(_)));
}

#[test]
fn off_when_already_off_or_with_nothing_to_confirm() {
    let env = Env::new();
    let mut d = env.start();
    assert_eq!(
        d.handle(&Request::KillSwitch { on: false }),
        Reply::Ok,
        "already off: nothing newly blocks"
    );
    let Reply::Error(e) = d.handle(&Request::Confirm) else {
        panic!("nothing is waiting")
    };
    assert!(e.contains("nothing"), "{e}");
}

// --- block rules a pack update brings ---------------------------------------

const BLOCKING_RULES: &str = r#"[
  {"id":"core-a","enabled":true,"hook":"exec","target":{"path_prefix":"/tmp"},"action":"block"},
  {"id":"core-b","enabled":true,"hook":"listen","target":"any","action":"alert"},
  {"id":"core-c","enabled":true,"hook":"connect","target":{"net":{"cidr":"203.0.113.0/24"}},"action":"block"},
  {"id":"core-d","enabled":false,"hook":"bpf","target":"any","action":"block"}
]"#;

/// A trusted key, known to the running daemon.
fn trusted_key(env: &Env, d: &mut Daemon<Fake>) -> KeyPair {
    let kp = keypair(env);
    assert_eq!(d.handle(&Request::Reload), Reply::Ok);
    kp
}

/// Install core `version` with `rules` as a pack check would.
fn update(kp: &KeyPair, d: &mut Daemon<Fake>, version: &str, rules: &str) {
    let a = full_archive("core", version, "0.0.0", rules, b"object");
    let sig = sign(kp, &a);
    let r = d.install_updates(vec![sensr_guard::daemon::Download {
        name: "core".into(),
        current: Some(Version::new(0, 0, 1)),
        available: Some(version.parse().unwrap()),
        fetched: Ok(Some((a, sig))),
    }]);
    assert!(r[0].installed && r[0].error.is_none(), "{r:?}");
}

fn action_of(env: &Env, id: &str) -> u8 {
    let (ids, _, actions, _) = env.last_apply();
    actions[ids.iter().position(|i| i == id).unwrap()]
}

#[test]
fn a_pack_update_holds_its_new_block_rules_as_alerts() {
    let env = Env::new();
    let mut d = env.start();
    let kp = trusted_key(&env, &mut d);
    update(&kp, &mut d, "1.1.0", BLOCKING_RULES);
    let s = d.status();
    assert_eq!(s.packs[0].version, "1.1.0");
    for id in ["core-a", "core-c"] {
        let r = rule(&s, id);
        assert!(r.held && r.active, "{r:?}");
        assert_eq!(r.action, sensr_guard::rule::Action::Alert);
        assert_eq!(action_of(&env, id), 0, "{id} is applied as an alert");
    }
    assert!(
        !rule(&s, "core-d").held,
        "a disabled block rule is not held"
    );
    assert_eq!(s.held.len(), 2);
    // held across a restart
    drop(d);
    let s = env.start().status();
    assert!(rule(&s, "core-c").held);
    assert_eq!(action_of(&env, "core-c"), 0);
}

#[test]
fn held_rules_block_once_released_and_confirmed() {
    let env = Env::new();
    let mut d = env.start();
    let kp = trusted_key(&env, &mut d);
    update(&kp, &mut d, "1.1.0", BLOCKING_RULES);
    let t0 = Instant::now();
    let Reply::Pending(p) = d.handle(&Request::ReleaseHeld) else {
        panic!("releasing lets rules block: it must be confirmed");
    };
    assert_eq!(p.released.len(), 2);
    assert!(!p.kill_switch_off);
    assert_eq!(action_of(&env, "core-c"), 1, "blocking in the window");
    let s = d.status();
    assert!(!rule(&s, "core-c").held);
    assert!(s.held.is_empty(), "released: not held in the window");
    assert_eq!(rule(&s, "core-c").action, sensr_guard::rule::Action::Block);
    // unconfirmed: held again
    d.poll_events(t0 + WINDOW + Duration::from_secs(1));
    assert!(rule(&d.status(), "core-c").held);
    assert_eq!(action_of(&env, "core-c"), 0);
    // released and confirmed: they block, also after a restart
    assert!(matches!(d.handle(&Request::ReleaseHeld), Reply::Pending(_)));
    assert_eq!(d.handle(&Request::Confirm), Reply::Ok);
    d.poll_events(Instant::now() + WINDOW * 2);
    assert_eq!(action_of(&env, "core-c"), 1);
    assert!(d.status().held.is_empty());
    drop(d);
    let s = env.start().status();
    assert!(!rule(&s, "core-c").held);
    assert_eq!(action_of(&env, "core-c"), 1);
}

#[test]
fn release_with_nothing_held_is_refused() {
    let env = Env::new();
    let mut d = env.start();
    assert!(matches!(d.handle(&Request::ReleaseHeld), Reply::Error(_)));
}

#[test]
fn an_owner_override_with_an_action_ends_the_hold() {
    let env = Env::new();
    let mut d = env.start();
    let kp = trusted_key(&env, &mut d);
    update(&kp, &mut d, "1.1.0", BLOCKING_RULES);
    env.config(json!({"pack_rules": [
        {"pack": "core", "rule_id": "core-c", "action": "block"},
        {"pack": "core", "rule_id": "core-a", "enabled": true}
    ]}));
    assert_eq!(d.handle(&Request::Reload), Reply::Ok);
    let s = d.status();
    assert!(
        !rule(&s, "core-c").held,
        "the owner chose block (commit-confirm)"
    );
    assert_eq!(action_of(&env, "core-c"), 1);
    assert!(
        rule(&s, "core-a").held,
        "enabled alone says nothing about the action"
    );
    assert_eq!(s.held.len(), 1);
}

#[test]
fn block_rules_the_running_version_already_had_are_not_held() {
    let env = Env::new();
    let mut d = env.start();
    let kp = trusted_key(&env, &mut d);
    update(&kp, &mut d, "1.1.0", BLOCKING_RULES);
    assert!(matches!(d.handle(&Request::ReleaseHeld), Reply::Pending(_)));
    assert_eq!(d.handle(&Request::Confirm), Reply::Ok);
    // 1.2.0: core-c unchanged, core-a now blocks something else
    let rules = BLOCKING_RULES.replace(r#"{"path_prefix":"/tmp"}"#, r#"{"path_prefix":"/var"}"#);
    update(&kp, &mut d, "1.2.0", &rules);
    let s = d.status();
    assert!(!rule(&s, "core-c").held, "the same block rule as before");
    assert!(
        rule(&s, "core-a").held,
        "a block rule that changed what it blocks"
    );
}

// --- the kernel's LSM list and exe seeding ----------------------------------

#[test]
fn without_the_bpf_lsm_nothing_is_enforced() {
    let env = Env::new();
    std::fs::write(env.p("lsm"), "capability,landlock,yama").unwrap();
    env.config(json!({"rules": [owner_rule("connect", json!({"net": {"cidr": "192.0.2.0/24"}}), "block")]}));
    let s = env.start().status();
    assert!(s.running && !s.enforcing, "{s:#?}");
    let why = s.reason.as_deref().unwrap();
    assert!(why.contains("BPF LSM") && why.contains("lsm="), "{why}");
    assert!(s.rules.iter().all(|r| !r.active), "{:#?}", s.rules);
    assert!(
        rule(&s, OWNER)
            .reason
            .as_deref()
            .unwrap()
            .contains("BPF LSM")
    );
}

#[test]
fn an_unreadable_lsm_list_is_not_a_reason_to_doubt() {
    let env = Env::new();
    std::fs::remove_file(env.p("lsm")).unwrap();
    let s = env.start().status();
    assert!(s.enforcing, "{s:#?}");
}

#[test]
fn unseeded_tasks_are_said_for_exe_rules() {
    let env = Env::new();
    env.knobs()
        .unattached
        .insert("guard_seed_exe".into(), "no iterators here".into());
    env.config(
        json!({"rules": [{"id": OWNER, "enabled": true, "hook": "connect",
        "process": {"exe_prefix": "/usr/bin"}, "target": "any", "action": "alert"}]}),
    );
    let s = env.start().status();
    assert!(rule(&s, OWNER).active, "it still applies to new processes");
    assert!(s.enforcing);
    let why = s.reason.as_deref().unwrap();
    assert!(
        why.contains("started after") && why.contains("no iterators here"),
        "{why}"
    );
}

#[test]
fn a_reload_keeps_the_loaded_packs() {
    let env = Env::new();
    let mut d = env.start();
    env.config(json!({"retention_days": 29}));
    assert_eq!(d.handle(&Request::Reload), Reply::Ok);
    assert_eq!(
        env.fake.log.lock().unwrap().loads,
        ["0.0.1"],
        "no new load: hits and task_exe stay"
    );
    assert_eq!(d.config().retention_days, 29);
}
