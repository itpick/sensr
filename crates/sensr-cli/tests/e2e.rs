//! End to end: a real `sensr-agent` (in-memory store, fake applier) on a temp
//! socket, driven by the real `sensr` binary.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sensr_agent::applier::FakeApplier;
use sensr_agent::store::MemStore;
use sensr_agent::{Agent, Running, Settings};
use serde_json::{Value, json};

const HOME_ROUTER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../sensr-import-opnsense/tests/fixtures/corpus/home-router.xml"
);

struct Fx {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    applier: FakeApplier,
    running: Option<Running>,
}

impl Fx {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let me = std::fs::metadata(dir.path()).unwrap().uid();
        let applier = FakeApplier::default();
        let settings = Settings {
            trusted_uids: vec![me],
            ..Settings::default()
        };
        let agent = Agent::new(MemStore::new(), applier.clone(), settings).unwrap();
        agent.boot().await.unwrap();
        let socket = dir.path().join("agent.sock");
        let running = sensr_agent::start(agent, &socket, 0o600, None).unwrap();
        Fx {
            _dir: dir,
            socket,
            applier,
            running: Some(running),
        }
    }

    fn applied(&self) -> Vec<Value> {
        self.applier.state.lock().unwrap().applied.clone()
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        // Tasks die with the runtime; nothing to await here.
        self.running.take();
    }
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

async fn sensr(socket: &Path, args: &[&str]) -> Out {
    let out = tokio::process::Command::new(env!("CARGO_BIN_EXE_sensr"))
        .args(args)
        .env("SENSR_AGENT_SOCKET", socket)
        .output()
        .await
        .unwrap();
    Out {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

async fn ok(socket: &Path, args: &[&str]) -> String {
    let o = sensr(socket, args).await;
    assert!(o.ok, "sensr {args:?} failed: {}{}", o.stdout, o.stderr);
    o.stdout
}

#[tokio::test(flavor = "multi_thread")]
async fn set_commit_confirm_then_timeout_rolls_back() {
    let fx = Fx::start().await;
    let s = fx.socket.as_path();

    // T-0401 shape: the root of an empty store is an object.
    let root: Value =
        serde_json::from_str(&ok(s, &["config", "get", "/", "--json"]).await).unwrap();
    assert!(root.is_object());

    ok(s, &["config", "set", "system.hostname", "fw1"]).await;
    ok(s, &["config", "set", "system.domain", "home.arpa"]).await;
    assert_eq!(ok(s, &["config", "get", "system.hostname"]).await, "fw1\n");
    let diff = ok(s, &["config", "diff"]).await;
    assert!(diff.contains("+    \"hostname\": \"fw1\""), "{diff}");
    let out = ok(s, &["config", "commit", "-m", "initial"]).await;
    assert!(out.contains("revision 1"), "{out}");

    // Provisional commit, confirmed in time.
    ok(s, &["config", "set", "system.hostname", "fw2"]).await;
    let out = ok(s, &["config", "commit", "--confirm", "60"]).await;
    assert!(out.contains("provisional"), "{out}");
    let st = ok(s, &["status"]).await;
    assert!(st.contains("rolls back to 1"), "{st}");
    assert!(
        ok(s, &["config", "confirm"])
            .await
            .contains("revision 2 confirmed")
    );
    assert!(!ok(s, &["status"]).await.contains("confirm:"));

    // Provisional commit, never confirmed: rolled back.
    ok(s, &["config", "set", "system.hostname", "lockout"]).await;
    ok(s, &["config", "commit", "--confirm", "1", "-m", "risky"]).await;
    assert_eq!(
        ok(
            s,
            &["config", "get", "system.hostname", "--source", "applied"]
        )
        .await,
        "lockout\n"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let st: Value = serde_json::from_str(&ok(s, &["status", "--json"]).await).unwrap();
        if st["pending_confirm"].is_null() && st["applied"] == json!(4) {
            break;
        }
        assert!(Instant::now() < deadline, "no rollback: {st}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        ok(
            s,
            &["config", "get", "system.hostname", "--source", "applied"]
        )
        .await,
        "fw2\n"
    );
    let hist = ok(s, &["config", "history"]).await;
    assert!(hist.contains("commit-confirm timeout"), "{hist}");
    let hosts: Vec<Value> = fx
        .applied()
        .iter()
        .map(|d| d["system"]["hostname"].clone())
        .collect();
    assert_eq!(
        hosts,
        [json!("fw1"), json!("fw2"), json!("lockout"), json!("fw2")]
    );

    // Explicit rollback to revision 1.
    assert!(
        ok(s, &["config", "rollback", "1"])
            .await
            .contains("revision 5")
    );
    assert_eq!(
        ok(s, &["config", "get", "system.hostname", "--source", "head"]).await,
        "fw1\n"
    );

    // Errors surface with a failing exit status.
    let e = sensr(s, &["config", "confirm"]).await;
    assert!(!e.ok);
    assert!(e.stderr.contains("no commit is waiting"), "{}", e.stderr);
    let e = sensr(s, &["config", "get", "no.such.path"]).await;
    assert!(!e.ok && e.stderr.contains("not set"));
}

#[tokio::test(flavor = "multi_thread")]
async fn import_dry_run_commit() {
    let fx = Fx::start().await;
    let s = fx.socket.as_path();
    let out = ok(s, &["import", "opnsense", HOME_ROUTER, "--report"]).await;
    assert!(out.contains("top-level sections"), "{out}");
    assert!(out.contains("staged"), "{out}");

    let plan = ok(s, &["apply", "--dry-run"]).await;
    assert!(plan.contains("# network"), "{plan}");
    assert!(plan.contains("add interface lan"), "{plan}");
    assert!(plan.contains("# nftables ruleset"), "{plan}");
    assert!(fx.applied().is_empty(), "dry run applied something");

    ok(s, &["config", "commit", "-m", "import home-router"]).await;
    assert_eq!(
        ok(s, &["config", "get", "interfaces.lan.ipaddr"]).await,
        "192.168.1.1\n"
    );
    assert_eq!(fx.applied().len(), 1);
    assert!(
        ok(s, &["apply", "--dry-run"])
            .await
            .contains("nothing to apply")
    );
    let lines = ok(s, &["config", "get", "system.user"]).await;
    assert!(lines.contains("system.user.0.name = root"), "{lines}");
}

/// Round-trip latency of the CLI (process spawn included) and of the raw
/// IPC client, printed for the record (`cargo test -- --nocapture`).
#[tokio::test(flavor = "multi_thread")]
async fn latency_report() {
    let fx = Fx::start().await;
    let s = fx.socket.as_path();
    ok(s, &["config", "set", "system.hostname", "fw"]).await;
    ok(s, &["config", "commit"]).await;

    let n = 20;
    let t = Instant::now();
    for _ in 0..n {
        ok(s, &["config", "get", "system.hostname"]).await;
    }
    let cli = t.elapsed() / n;

    let mut c = sensr_ipc::Client::connect(s, sensr_ipc::Principal::unix("t", 0))
        .await
        .unwrap();
    let n = 2000;
    let t = Instant::now();
    for _ in 0..n {
        c.call(sensr_ipc::Op::ConfigGet {
            path: "system.hostname".parse().unwrap(),
            source: sensr_ipc::Source::Head,
        })
        .await
        .unwrap();
    }
    let ipc = t.elapsed() / n;
    eprintln!("latency: cli round trip {cli:?}, ipc config.get {ipc:?}");
    // Generous bounds so slow CI never flakes, tight enough to catch a regression
    // of the 0.3 ms class (docs/research/07).
    assert!(ipc < Duration::from_millis(5), "ipc {ipc:?}");
    assert!(cli < Duration::from_millis(500), "cli {cli:?}");
}
