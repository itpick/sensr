//! End to end: a real `sensr-agent` (in-memory `sensr-config` store, fake
//! applier) on a temp socket, driven by the real `sensr` binary.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sensr_agent::applier::FakeApplier;
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
        Self::start_on(None).await
    }

    /// With `host_root` as the root the agent reads `sys/class/net` from.
    async fn start_on(host_root: Option<&Path>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let me = std::fs::metadata(dir.path()).unwrap().uid();
        let applier = FakeApplier::default();
        let settings = Settings {
            trusted_uids: vec![me],
            host_root: host_root.map_or_else(|| dir.path().to_owned(), Path::to_owned),
            ..Settings::default()
        };
        let agent = Agent::new(sensr_agent::store::in_memory(), applier.clone(), settings).unwrap();
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
        self.applier
            .state
            .lock()
            .unwrap()
            .applied
            .iter()
            .map(|d| serde_json::to_value(d).unwrap())
            .collect()
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
    sensr_in(socket, args, "").await
}

/// Runs `sensr` with `stdin` as its input (interactive prompts).
async fn sensr_in(socket: &Path, args: &[&str], stdin: &str) -> Out {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_sensr"))
        .args(args)
        .env("SENSR_AGENT_SOCKET", socket)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(stdin.as_bytes()).await.unwrap();
    drop(input);
    let out = child.wait_with_output().await.unwrap();
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

    // T-0401 shape: the root of a fresh (factory) store is an object.
    let root: Value =
        serde_json::from_str(&ok(s, &["config", "get", "/", "--json"]).await).unwrap();
    assert!(root.is_object());

    ok(s, &["config", "set", "system.hostname", "fw1"]).await;
    ok(s, &["config", "set", "system.domain", "home.arpa"]).await;
    assert_eq!(ok(s, &["config", "get", "system.hostname"]).await, "fw1\n");
    let diff = ok(s, &["config", "diff"]).await;
    assert!(diff.contains("+    \"hostname\": \"fw1\""), "{diff}");
    let out = ok(s, &["config", "commit", "-m", "initial"]).await;
    assert!(out.contains("revision 2"), "{out}");

    // Provisional commit, confirmed in time.
    ok(s, &["config", "set", "system.hostname", "fw2"]).await;
    let out = ok(s, &["config", "commit", "--confirm", "60"]).await;
    assert!(out.contains("provisional"), "{out}");
    let st = ok(s, &["status"]).await;
    assert!(st.contains("rolls back to 2"), "{st}");
    assert!(
        ok(s, &["config", "confirm"])
            .await
            .contains("revision 3 confirmed")
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
        if st["pending_confirm"].is_null() && st["applied"] == json!(5) {
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
        .skip(1) // the factory document, applied at boot
        .map(|d| d["system"]["hostname"].clone())
        .collect();
    assert_eq!(
        hosts,
        [json!("fw1"), json!("fw2"), json!("lockout"), json!("fw2")]
    );

    // Explicit rollback to revision 2.
    assert!(
        ok(s, &["config", "rollback", "2"])
            .await
            .contains("revision 6")
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
    assert!(out.starts_with("# sensr import report"), "{out}");
    assert!(out.contains("staged"), "{out}");

    let plan = ok(s, &["apply", "--dry-run"]).await;
    assert!(plan.contains("# network"), "{plan}");
    assert!(plan.contains("reconfigure interface lan"), "{plan}");
    assert!(plan.contains("# nftables ruleset"), "{plan}");
    assert_eq!(fx.applied().len(), 1, "dry run applied something");

    ok(s, &["config", "commit", "-m", "import home-router"]).await;
    assert_eq!(
        ok(s, &["config", "get", "interfaces.lan.ipv4.address"]).await,
        "192.168.1.1/24\n"
    );
    assert_eq!(fx.applied().len(), 2);
    assert!(
        ok(s, &["apply", "--dry-run"])
            .await
            .contains("nothing to apply")
    );
    let lines = ok(s, &["config", "get", "system.users"]).await;
    assert!(
        lines.contains("system.users.c493ce95-b248-400b-a46d-6c3c647a3b08.name = root"),
        "{lines}"
    );
    assert!(
        !lines.contains("synthetic.synthetic"),
        "hash leaked: {lines}"
    );
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

/// A fake `sys/class/net` entry backed by a device with a driver.
fn card(root: &Path, name: &str, mac: &str, bus: &str, slot: &str, driver: &str) {
    use std::os::unix::fs::symlink;
    let sys = root.join("sys");
    let subsystem = sys.join("bus").join(bus);
    let drv = subsystem.join("drivers").join(driver);
    std::fs::create_dir_all(&drv).unwrap();
    let dev = sys.join("devices").join(slot);
    std::fs::create_dir_all(&dev).unwrap();
    symlink(&subsystem, dev.join("subsystem")).unwrap();
    symlink(&drv, dev.join("driver")).unwrap();
    let net = sys.join("class/net").join(name);
    std::fs::create_dir_all(&net).unwrap();
    symlink(&dev, net.join("device")).unwrap();
    std::fs::write(net.join("address"), format!("{mac}\n")).unwrap();
    std::fs::write(net.join("operstate"), "down\n").unwrap();
}

/// `sensr interfaces`: real cards (from sysfs), assignment by MAC or kernel
/// name, and the interactive prompt.
#[tokio::test(flavor = "multi_thread")]
async fn interfaces_list_and_assign() {
    let host = tempfile::tempdir().unwrap();
    card(
        host.path(),
        "enp1s0",
        "52:54:00:aa:00:01",
        "pci",
        "0000:01:00.0",
        "igc",
    );
    card(
        host.path(),
        "enx00e04c680002",
        "00:e0:4c:68:00:02",
        "usb",
        "2-1:1.0",
        "r8152",
    );
    let fx = Fx::start_on(Some(host.path())).await;
    let s = fx.socket.as_path();

    let list = ok(s, &["interfaces", "list"]).await;
    assert!(
        list.contains("enp1s0") && list.contains("igc") && list.contains("pci 0000:01:00.0"),
        "{list}"
    );
    assert!(
        list.contains("r8152") && list.contains("usb 2-1:1.0"),
        "{list}"
    );
    let json: Value =
        serde_json::from_str(&ok(s, &["interfaces", "list", "--json"]).await).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 2);

    let out = ok(
        s,
        &[
            "interfaces",
            "assign",
            "wan=00:E0:4C:68:00:02",
            "lan=enp1s0",
            "--commit",
        ],
    )
    .await;
    assert!(out.contains("revision 2"), "{out}");
    assert_eq!(
        ok(s, &["config", "get", "interfaces.wan.device"]).await,
        "wan\n"
    );
    assert_eq!(
        ok(s, &["config", "get", "interfaces.wan.match_mac"]).await,
        "00:e0:4c:68:00:02\n"
    );
    let json: Value =
        serde_json::from_str(&ok(s, &["interfaces", "list", "--json"]).await).unwrap();
    let assigned: Vec<_> = json
        .as_array()
        .unwrap()
        .iter()
        .map(|n| (n["name"].clone(), n["assigned"].clone()))
        .collect();
    assert!(
        assigned.contains(&(json!("enp1s0"), json!("lan"))),
        "{assigned:?}"
    );

    // interactive: swap the cards (numbers from the list), keep the rest
    let o = sensr_in(s, &["interfaces", "assign"], "1\n2\n\n").await;
    assert!(o.ok, "{}{}", o.stdout, o.stderr);
    assert!(o.stdout.contains("card for wan"), "{}", o.stdout);
    assert_eq!(
        ok(s, &["config", "get", "interfaces.lan.match_mac"]).await,
        "00:e0:4c:68:00:02\n"
    );
    // an unknown card is refused and stages nothing new
    let e = sensr(s, &["interfaces", "assign", "opt1=aa:bb:cc:dd:ee:ff"]).await;
    assert!(
        !e.ok && e.stderr.contains("no network card matches"),
        "{}",
        e.stderr
    );
}
