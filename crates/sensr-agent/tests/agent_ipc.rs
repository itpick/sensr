//! The agent behind its real socket, over the `sensr-config` store (in
//! memory, or on disk for restarts) and the fake applier.

use std::os::unix::fs::MetadataExt;
use std::time::Duration;

use sensr_agent::applier::FakeApplier;
use sensr_agent::{Agent, Running, Settings};
use sensr_auth::password::hash_password;
use sensr_ipc::{
    Client, ClientError, Credential, ErrorKind, Event, Op, Principal, Response, Source, StreamItem,
};
use sensr_schema::Document;
use serde_json::{Value, json};

const USER: &str = "system.users.6f0c6f9e-0000-4000-8000-000000000101";
const WG: &str = "wireguard.servers.00000000-0000-0000-0000-000000000001";
const ALIAS_A: &str = "firewall.aliases.0b5e0000-0000-4000-8000-00000000000a";
const ALIAS_B: &str = "firewall.aliases.0b5e0000-0000-4000-8000-00000000000b";

struct Fx {
    dir: tempfile::TempDir,
    applier: FakeApplier,
    running: Option<Running>,
}

impl Fx {
    fn my_uid(dir: &tempfile::TempDir) -> u32 {
        std::fs::metadata(dir.path()).unwrap().uid()
    }

    async fn start(trust_me: bool) -> Self {
        Self::start_with(trust_me, true).await
    }

    async fn start_with(trust_me: bool, boot: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let applier = FakeApplier::default();
        let running = Self::spawn(&dir, applier.clone(), trust_me, false, boot).await;
        Fx {
            dir,
            applier,
            running: Some(running),
        }
    }

    async fn spawn(
        dir: &tempfile::TempDir,
        applier: FakeApplier,
        trust_me: bool,
        persistent: bool,
        boot: bool,
    ) -> Running {
        let settings = Settings {
            trusted_uids: if trust_me {
                vec![Self::my_uid(dir)]
            } else {
                vec![]
            },
            rollback_retry: Duration::from_millis(100),
            ..Settings::default()
        };
        let socket = dir.path().join("agent.sock");
        let store = if persistent {
            sensr_agent::store::open(
                &dir.path().join("config.db"),
                Some(dir.path().join("config.json")),
                Some(&dir.path().join("secrets.key")),
            )
            .unwrap()
        } else {
            sensr_agent::store::in_memory()
        };
        let agent = Agent::new(store, applier, settings).unwrap();
        if boot {
            agent.boot().await.unwrap();
        }
        sensr_agent::start(agent, &socket, 0o600, None).unwrap()
    }

    async fn client(&self) -> Client {
        Client::connect(
            &self.dir.path().join("agent.sock"),
            Principal::unix("tester", 0),
        )
        .await
        .unwrap()
    }

    fn applied(&self) -> Vec<Document> {
        self.applier.state.lock().unwrap().applied.clone()
    }

    fn applied_hosts(&self) -> Vec<String> {
        self.applied()
            .iter()
            .map(|d| d.system.hostname.to_string())
            .collect()
    }

    async fn stop(&mut self) {
        if let Some(r) = self.running.take() {
            r.shutdown().await;
        }
    }
}

fn factory_host() -> String {
    Document::factory().system.hostname.to_string()
}

async fn host(c: &mut Client, source: Source) -> Value {
    get(c, "system.hostname", source).await.unwrap()
}

async fn set(c: &mut Client, path: &str, value: Value) -> Response {
    try_set(c, path, value).await.unwrap()
}

async fn try_set(c: &mut Client, path: &str, value: Value) -> Result<Response, ClientError> {
    c.call(Op::ConfigSet {
        path: path.parse().unwrap(),
        value,
    })
    .await
}

async fn get(c: &mut Client, path: &str, source: Source) -> Option<Value> {
    match c
        .call(Op::ConfigGet {
            path: path.parse().unwrap(),
            source,
        })
        .await
        .unwrap()
    {
        Response::Value(v) => v,
        other => panic!("{other:?}"),
    }
}

async fn commit(c: &mut Client, confirm_secs: Option<u32>) -> Result<Response, ClientError> {
    c.call(Op::ConfigCommit {
        description: Some("test".into()),
        confirm_secs,
    })
    .await
}

async fn history(c: &mut Client) -> Vec<sensr_ipc::RevisionInfo> {
    let Response::History(h) = c.call(Op::ConfigHistory { limit: None }).await.unwrap() else {
        panic!()
    };
    h
}

fn agent_err(r: Result<Response, ClientError>) -> sensr_ipc::IpcError {
    match r {
        Err(ClientError::Agent(e)) => e,
        other => panic!("expected agent error, got {other:?}"),
    }
}

#[tokio::test]
async fn set_commit_history_get() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    // The store starts from the factory document, applied at boot.
    assert!(get(&mut c, "interfaces.lan", Source::Head).await.is_some());
    assert_eq!(fx.applied_hosts(), [factory_host()]);
    assert_eq!(
        set(&mut c, "system.hostname", json!("fw1")).await,
        Response::Staged { dirty: true }
    );
    assert_eq!(host(&mut c, Source::Candidate).await, json!("fw1"));
    assert_eq!(host(&mut c, Source::Head).await, json!(factory_host()));
    let Response::Committed(out) = commit(&mut c, None).await.unwrap() else {
        panic!()
    };
    assert_eq!(out.revision.id, 2);
    assert!(out.revision.username.ends_with("@unix"));
    assert_eq!(host(&mut c, Source::Head).await, json!("fw1"));
    assert_eq!(host(&mut c, Source::Applied).await, json!("fw1"));
    assert_eq!(fx.applied_hosts(), [factory_host(), "fw1".into()]);

    assert_eq!(
        agent_err(commit(&mut c, None).await).kind,
        ErrorKind::Conflict
    );

    set(&mut c, "system.hostname", json!("fw2")).await;
    let Response::Diff(d) = c
        .call(Op::ConfigDiff {
            from: Source::Head,
            to: Source::Candidate,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(d.changes.len(), 1);
    assert!(d.unified.contains("+    \"hostname\": \"fw2\""));
    commit(&mut c, None).await.unwrap();

    let h = history(&mut c).await;
    assert_eq!(h.iter().map(|r| r.id).collect::<Vec<_>>(), [3, 2, 1]);
    assert_eq!(h[0].parent, Some(2));

    let Response::Status(st) = c.call(Op::Status).await.unwrap() else {
        panic!()
    };
    assert_eq!(st.applied, Some(3));
    assert!(!st.candidate_dirty);
    assert_eq!(st.pending_confirm, None);
}

/// Every write is checked against the schema before it is staged: a value
/// that does not fit, an unknown field, and an edit that creates a
/// validation problem (a duplicate alias name) are refused, and the
/// candidate is left as it was.
#[tokio::test]
async fn writes_are_validated_against_the_schema() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;

    let e = agent_err(try_set(&mut c, "system.hostname", json!("not valid!")).await);
    assert_eq!(e.kind, ErrorKind::Validation);
    assert!(
        e.validations[0].path.starts_with("system.hostname"),
        "{e:?}"
    );
    let e = agent_err(try_set(&mut c, "system.bogus", json!(1)).await);
    assert_eq!(e.kind, ErrorKind::Validation);
    assert!(e.validations[0].message.contains("bogus"), "{e:?}");

    let alias = |name: &str| json!({"name": name, "content": {"type": "port", "entries": ["443"]}});
    set(&mut c, ALIAS_A, alias("web")).await;
    let e = agent_err(try_set(&mut c, ALIAS_B, alias("web")).await);
    assert_eq!(e.kind, ErrorKind::Validation);
    assert!(
        e.validations.iter().any(|v| v.path.contains("aliases")),
        "{e:?}"
    );
    assert!(get(&mut c, ALIAS_B, Source::Candidate).await.is_none());
    set(&mut c, ALIAS_B, alias("mail")).await;
    // Renaming into a clash is refused the same way.
    let e = agent_err(try_set(&mut c, &format!("{ALIAS_B}.name"), json!("web")).await);
    assert_eq!(e.kind, ErrorKind::Validation);
    commit(&mut c, None).await.unwrap();
    assert_eq!(
        get(&mut c, &format!("{ALIAS_B}.name"), Source::Head).await,
        Some(json!("mail"))
    );
    // A whole document with the clash is staged (load replaces everything)
    // but never committed.
    let mut doc = get(&mut c, "/", Source::Head).await.unwrap();
    doc["firewall"]["aliases"]["0b5e0000-0000-4000-8000-00000000000b"]["name"] = json!("web");
    c.call(Op::ConfigLoad { document: doc }).await.unwrap();
    let e = agent_err(commit(&mut c, None).await);
    assert_eq!(e.kind, ErrorKind::Validation);
    assert_eq!(history(&mut c).await.len(), 2);
    // The document root is not deletable.
    let e = agent_err(
        c.call(Op::ConfigDelete {
            path: "/".parse().unwrap(),
        })
        .await,
    );
    assert_eq!(e.kind, ErrorKind::BadRequest);
}

#[tokio::test]
async fn commit_confirm_then_confirm_keeps_change() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    set(&mut c, "system.hostname", json!("a")).await;
    commit(&mut c, None).await.unwrap();
    set(&mut c, "system.hostname", json!("b")).await;
    let Response::Committed(out) = commit(&mut c, Some(1)).await.unwrap() else {
        panic!()
    };
    let p = out.pending_confirm.unwrap();
    assert_eq!((p.revision, p.rollback_to), (3, 2));
    assert_eq!(
        c.call(Op::ConfigConfirm).await.unwrap(),
        Response::Confirmed(3)
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(host(&mut c, Source::Applied).await, json!("b"));
    assert_eq!(history(&mut c).await.len(), 3, "no rollback revision");
    assert_eq!(
        agent_err(c.call(Op::ConfigConfirm).await).kind,
        ErrorKind::Conflict
    );
}

#[tokio::test]
async fn commit_confirm_timeout_rolls_back() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    let mut events = fx.client().await;
    let mut stream = events.stream(Op::Subscribe).await.unwrap();

    set(&mut c, "system.hostname", json!("good")).await;
    commit(&mut c, None).await.unwrap();
    set(&mut c, "system.hostname", json!("bad")).await;
    commit(&mut c, Some(1)).await.unwrap();
    assert_eq!(host(&mut c, Source::Applied).await, json!("bad"));

    let rolled = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(StreamItem::Event(Event::RolledBack {
                abandoned,
                restored,
            })) = stream.next().await.unwrap()
            {
                return (abandoned, restored);
            }
        }
    })
    .await
    .expect("rollback within 5s");
    assert_eq!(rolled.0, 3);
    assert_eq!(rolled.1.id, 4);
    assert!(rolled.1.username.starts_with("sensr-agent@system"));
    assert!(rolled.1.description.contains("commit-confirm timeout"));
    assert!(rolled.1.description.contains("not confirmed"));

    assert_eq!(host(&mut c, Source::Applied).await, json!("good"));
    assert_eq!(host(&mut c, Source::Head).await, json!("good"));
    assert_eq!(
        fx.applied_hosts(),
        [factory_host(), "good".into(), "bad".into(), "good".into()]
    );
    let Response::Status(st) = c.call(Op::Status).await.unwrap() else {
        panic!()
    };
    assert_eq!(st.pending_confirm, None);
    assert_eq!(st.applied, Some(4));
}

#[tokio::test]
async fn second_provisional_commit_falls_back_to_last_confirmed() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    set(&mut c, "system.hostname", json!("h1")).await;
    commit(&mut c, None).await.unwrap();
    set(&mut c, "system.hostname", json!("h2")).await;
    commit(&mut c, Some(60)).await.unwrap();
    set(&mut c, "system.hostname", json!("h3")).await;
    let Response::Committed(out) = commit(&mut c, Some(1)).await.unwrap() else {
        panic!()
    };
    assert_eq!(out.pending_confirm.unwrap().rollback_to, 2);
    tokio::time::sleep(Duration::from_millis(1600)).await;
    assert_eq!(host(&mut c, Source::Applied).await, json!("h1"));
}

#[tokio::test]
async fn commit_confirm_without_baseline_is_refused() {
    // Not booted: nothing has been applied to fall back to.
    let fx = Fx::start_with(true, false).await;
    let mut c = fx.client().await;
    set(&mut c, "system.hostname", json!("h1")).await;
    assert_eq!(
        agent_err(commit(&mut c, Some(30)).await).kind,
        ErrorKind::Conflict
    );
    assert_eq!(
        agent_err(commit(&mut c, Some(0)).await).kind,
        ErrorKind::BadRequest
    );
}

#[tokio::test]
async fn rejected_plan_stores_nothing() {
    let fx = Fx::start(true).await;
    fx.applier.state.lock().unwrap().reject_paths = vec!["interfaces.opt1".parse().unwrap()];
    let mut c = fx.client().await;
    set(&mut c, "interfaces.opt1", json!({"device": "eth2"})).await;
    let e = agent_err(commit(&mut c, None).await);
    assert_eq!(e.kind, ErrorKind::Validation);
    assert_eq!(e.validations[0].path, "interfaces.opt1");
    assert_eq!(history(&mut c).await.len(), 1);
    // The candidate survives so the operator can fix it.
    assert_eq!(
        get(&mut c, "interfaces.opt1.device", Source::Candidate).await,
        Some(json!("eth2"))
    );
}

/// Incident 2026-11-23: one checker rejecting its config at agent start
/// kept every daemon down. The boot apply now holds back only what was
/// rejected and says so in `status`; commits stay all or nothing.
#[tokio::test]
async fn boot_apply_with_a_rejected_backend_still_applies_and_reports_it() {
    let dir = tempfile::tempdir().unwrap();
    let applier = FakeApplier::default();
    applier.state.lock().unwrap().reject_paths = vec!["system.hostname".parse().unwrap()];
    let running = Fx::spawn(&dir, applier.clone(), true, false, true).await;
    let mut c = Client::connect(&dir.path().join("agent.sock"), Principal::unix("t", 0))
        .await
        .unwrap();
    // the rest of head was applied and recorded
    assert_eq!(applier.state.lock().unwrap().applied.len(), 1);
    let Response::Status(st) = c.call(Op::Status).await.unwrap() else {
        panic!()
    };
    assert_eq!(st.applied, Some(1));
    let problem = st.last_apply_error.expect("degraded boot is reported");
    assert!(
        problem.contains("revision 1 applied at startup without part of its configuration"),
        "{problem}"
    );
    assert!(problem.contains("system.hostname"), "{problem}");

    // an interactive commit is still refused as a whole
    set(&mut c, "system.hostname", json!("h1")).await;
    let e = agent_err(commit(&mut c, None).await);
    assert_eq!(e.kind, ErrorKind::Validation);
    assert_eq!(history(&mut c).await.len(), 1);
    assert_eq!(applier.state.lock().unwrap().applied.len(), 1);

    // once the cause is gone, the next commit clears the problem
    applier.state.lock().unwrap().reject_paths.clear();
    commit(&mut c, None).await.unwrap();
    let Response::Status(st) = c.call(Op::Status).await.unwrap() else {
        panic!()
    };
    assert_eq!(st.last_apply_error, None);
    drop(c);
    running.shutdown().await;
}

#[tokio::test]
async fn failed_apply_restores_running_state() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    set(&mut c, "system.hostname", json!("h1")).await;
    commit(&mut c, None).await.unwrap();
    set(&mut c, "system.hostname", json!("h2")).await;
    fx.applier.state.lock().unwrap().fail_next_apply = Some("nft: busy".into());
    let e = agent_err(commit(&mut c, None).await);
    assert_eq!(e.kind, ErrorKind::ApplyFailed);
    assert!(e.message.contains("revision 3 stored but not applied"));
    assert_eq!(host(&mut c, Source::Applied).await, json!("h1"));
    assert_eq!(
        fx.applied_hosts(),
        [factory_host(), "h1".into(), "h1".into()]
    );
    let Response::Status(st) = c.call(Op::Status).await.unwrap() else {
        panic!()
    };
    assert_eq!(st.applied, Some(2));
    assert!(st.last_apply_error.unwrap().contains("nft: busy"));
}

#[tokio::test]
async fn explicit_rollback_is_a_new_revision() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    for v in 1..=3 {
        set(&mut c, "system.hostname", json!(format!("h{v}"))).await;
        commit(&mut c, None).await.unwrap();
    }
    let Response::Committed(out) = c.call(Op::ConfigRollback { to: None }).await.unwrap() else {
        panic!()
    };
    assert_eq!(out.revision.id, 5);
    assert_eq!(host(&mut c, Source::Head).await, json!("h2"));
    c.call(Op::ConfigRollback { to: Some(2) }).await.unwrap();
    assert_eq!(host(&mut c, Source::Applied).await, json!("h1"));
    assert_eq!(
        agent_err(c.call(Op::ConfigRollback { to: Some(99) }).await).kind,
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn untrusted_peer_is_read_only() {
    let fx = Fx::start(false).await;
    let mut c = fx.client().await;
    assert!(get(&mut c, "/", Source::Head).await.unwrap().is_object());
    let e = agent_err(try_set(&mut c, "system.hostname", json!("x")).await);
    assert_eq!(e.kind, ErrorKind::Forbidden);
    let auth = c
        .call(Op::Authenticate {
            credential: Credential::Password {
                user: "root".into(),
                password: "x".into(),
                otp: None,
            },
            remote_addr: None,
        })
        .await;
    assert_eq!(agent_err(auth).kind, ErrorKind::Forbidden);
}

#[tokio::test]
async fn trusted_peer_principal_is_recorded() {
    let fx = Fx::start(true).await;
    let mut c = Client::connect(
        &fx.dir.path().join("agent.sock"),
        Principal {
            user: "admin".into(),
            via: sensr_ipc::AuthMethod::ApiKey { key: "k".into() },
            impersonated_by: None,
            readonly: false,
        },
    )
    .await
    .unwrap();
    set(&mut c, "system.hostname", json!("h1")).await;
    let Response::Committed(out) = commit(&mut c, None).await.unwrap() else {
        panic!()
    };
    assert_eq!(out.revision.username, "admin@api");

    c.set_principal(Principal {
        readonly: true,
        ..c.principal().clone()
    });
    let e = agent_err(try_set(&mut c, "system.hostname", json!("h2")).await);
    assert_eq!(e.kind, ErrorKind::Forbidden);
}

#[tokio::test]
async fn authenticate_against_head_document() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    // The group first: a user may only join groups that exist.
    set(
        &mut c,
        "system.groups.6f0c6f9e-0000-4000-8000-0000000001a1",
        json!({"name": "admins", "gid": 1999, "privileges": ["page-all"]}),
    )
    .await;
    set(
        &mut c,
        USER,
        json!({"name": "admin", "uid": 1000, "groups": ["admins"],
               "password_hash": hash_password("s3cret").unwrap()}),
    )
    .await;
    commit(&mut c, None).await.unwrap();
    let cred = |pw: &str| Op::Authenticate {
        credential: Credential::Password {
            user: "admin".into(),
            password: pw.into(),
            otp: None,
        },
        remote_addr: None,
    };
    let Response::Authenticated(info) = c.call(cred("s3cret")).await.unwrap() else {
        panic!()
    };
    assert_eq!(info.privileges, ["page-all"]);
    assert_eq!(
        agent_err(c.call(cred("nope")).await).kind,
        ErrorKind::Unauthenticated
    );
}

#[tokio::test]
async fn dry_run_shows_plan_and_changes_nothing() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    set(&mut c, "interfaces.opt1", json!({"device": "eth2"})).await;
    let Response::Plan(plan) = c
        .call(Op::ApplyDryRun {
            source: Source::Candidate,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(plan.net, ["add interface opt1"]);
    assert_eq!(fx.applied().len(), 1, "only the boot apply");
}

/// The applied revision and a pending confirm live in the store: after a
/// restart the agent knows what runs and rolls back the unconfirmed change.
#[tokio::test]
async fn restart_with_pending_confirm_rolls_back_at_boot() {
    let dir = tempfile::tempdir().unwrap();
    let applier = FakeApplier::default();
    let running = Fx::spawn(&dir, applier.clone(), true, true, true).await;
    let mut c = Client::connect(&dir.path().join("agent.sock"), Principal::unix("t", 0))
        .await
        .unwrap();
    set(&mut c, "system.hostname", json!("good")).await;
    commit(&mut c, None).await.unwrap();
    set(&mut c, "system.hostname", json!("risky")).await;
    commit(&mut c, Some(3600)).await.unwrap();
    drop(c);
    running.shutdown().await;

    let running = Fx::spawn(&dir, applier.clone(), true, true, true).await;
    let mut c = Client::connect(&dir.path().join("agent.sock"), Principal::unix("t", 0))
        .await
        .unwrap();
    assert_eq!(host(&mut c, Source::Applied).await, json!("good"));
    let Response::Status(st) = c.call(Op::Status).await.unwrap() else {
        panic!()
    };
    assert_eq!(st.pending_confirm, None);
    assert_eq!(st.head.as_ref().unwrap().id, 4);
    assert_eq!(st.applied, Some(4));
    assert!(
        st.head
            .unwrap()
            .description
            .contains("agent restarted before revision 3 was confirmed")
    );
    // No side files: the store holds all of it.
    assert!(!dir.path().join("agent-state.json").exists());
    running.shutdown().await;

    // A plain restart keeps the applied revision.
    let running = Fx::spawn(&dir, applier, true, true, false).await;
    let mut c = Client::connect(&dir.path().join("agent.sock"), Principal::unix("t", 0))
        .await
        .unwrap();
    let Response::Status(st) = c.call(Op::Status).await.unwrap() else {
        panic!()
    };
    assert_eq!(st.applied, Some(4));
    running.shutdown().await;
}

#[tokio::test]
async fn shutdown_is_clean() {
    let mut fx = Fx::start(true).await;
    let mut c = fx.client().await;
    assert_eq!(c.call(Op::Ping).await.unwrap(), Response::Pong);
    tokio::time::timeout(Duration::from_secs(6), fx.stop())
        .await
        .unwrap();
}

/// Secrets never leave the agent; masked placeholders written back keep the
/// stored value (PLAN §2.4 item 7). The schema's `Secret` fields decide
/// what is masked.
#[tokio::test]
async fn secrets_are_masked_on_read_and_kept_on_write_back() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    let hash = hash_password("pw").unwrap();
    let private = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    set(
        &mut c,
        USER,
        json!({"name": "admin", "uid": 1000, "password_hash": hash, "description": "password"}),
    )
    .await;
    set(
        &mut c,
        WG,
        json!({"name": "wg0", "instance": 0, "private_key": private}),
    )
    .await;
    commit(&mut c, None).await.unwrap();

    let user = get(&mut c, USER, Source::Head).await.unwrap();
    let masked = user["password_hash"].as_str().unwrap().to_owned();
    assert!(masked.starts_with("***"), "{masked}");
    assert_eq!(user["description"], "password", "not a secret field");
    let key_path = format!("{WG}.private_key");
    let bare = get(&mut c, &key_path, Source::Head).await.unwrap();
    assert!(bare.as_str().unwrap().starts_with("***"));
    let whole = get(&mut c, "/", Source::Head).await.unwrap().to_string();
    assert!(!whole.contains(&hash) && !whole.contains(private));

    // Read-modify-write of the user keeps the hash; the bare placeholder
    // keeps the key.
    let mut edited = user.clone();
    edited["uid"] = json!(1001);
    set(&mut c, USER, edited).await;
    set(&mut c, &key_path, bare).await;
    commit(&mut c, None).await.unwrap();
    let applied = fx.applied();
    let last = serde_json::to_value(applied.last().unwrap()).unwrap();
    let u = &last["system"]["users"]["6f0c6f9e-0000-4000-8000-000000000101"];
    assert_eq!(u["password_hash"], json!(hash));
    assert_eq!(u["uid"], json!(1001));
    assert_eq!(
        last["wireguard"]["servers"]["00000000-0000-0000-0000-000000000001"]["private_key"],
        json!(private)
    );

    // A changed secret shows up in the diff as a changed marker only.
    let new_key = "cGBP0J1mfVpNsoN9dpzlnVRl0mW7Lnm0iQCw1ImeLHA=";
    set(&mut c, &key_path, json!(new_key)).await;
    let Response::Diff(d) = c
        .call(Op::ConfigDiff {
            from: Source::Head,
            to: Source::Candidate,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(d.changes.len(), 1);
    assert!(!d.unified.contains(new_key) && !d.unified.contains(private));
    let Response::Plan(p) = c
        .call(Op::ApplyDryRun {
            source: Source::Candidate,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    let shown = serde_json::to_string(&p).unwrap();
    assert!(!shown.contains(new_key) && !shown.contains(private));
}

#[tokio::test]
async fn runtime_hosts_section_round_trips() {
    let fx = Fx::start(true).await;
    let canned = json!({"now": 5, "hosts": [{"key": "aa:bb:cc:dd:ee:01", "online": true}]});
    fx.applier
        .state
        .lock()
        .unwrap()
        .runtime
        .push((sensr_ipc::RuntimeSection::Hosts, canned.clone()));
    let mut c = fx.client().await;
    let r = c
        .call(Op::Runtime {
            section: sensr_ipc::RuntimeSection::Hosts,
        })
        .await
        .unwrap();
    assert_eq!(r, Response::Value(Some(canned)));
}

#[tokio::test]
async fn host_forget_answers_forgotten_or_conflict() {
    let fx = Fx::start(true).await;
    fx.applier
        .state
        .lock()
        .unwrap()
        .forgettable
        .push("aa:bb:cc:dd:ee:01".into());
    let mut c = fx.client().await;
    let r = c
        .call(Op::HostForget {
            key: "aa:bb:cc:dd:ee:01".into(),
        })
        .await
        .unwrap();
    assert_eq!(r, Response::Value(Some(json!({"forgotten": true}))));
    let e = agent_err(
        c.call(Op::HostForget {
            key: "aa:bb:cc:dd:ee:01".into(),
        })
        .await,
    );
    assert_eq!(e.kind, ErrorKind::Conflict);
    assert_eq!(e.message, "host is reserved or unknown");
}

#[tokio::test]
async fn host_forget_is_refused_for_readonly() {
    let fx = Fx::start(true).await;
    fx.applier
        .state
        .lock()
        .unwrap()
        .forgettable
        .push("aa:bb:cc:dd:ee:01".into());
    let mut c = fx.client().await;
    c.set_principal(Principal {
        readonly: true,
        ..c.principal().clone()
    });
    let e = agent_err(
        c.call(Op::HostForget {
            key: "aa:bb:cc:dd:ee:01".into(),
        })
        .await,
    );
    assert_eq!(e.kind, ErrorKind::Forbidden);
    assert_eq!(
        fx.applier.state.lock().unwrap().forgettable,
        vec!["aa:bb:cc:dd:ee:01".to_owned()]
    );
}

const MODE_MAC: &str = "aa:bb:cc:dd:ee:01";

async fn mode_set(
    c: &mut Client,
    mode: Option<sensr_ipc::HostModeMode>,
    remote_addr: Option<std::net::IpAddr>,
) -> Result<Response, ClientError> {
    c.call(Op::HostModeSet {
        mac: MODE_MAC.to_uppercase(),
        mode,
        remote_addr,
    })
    .await
}

fn modes_of(doc: &Document) -> Vec<(String, sensr_schema::models::firewall::HostModeKind, bool)> {
    doc.firewall
        .host_modes
        .values()
        .map(|h| (h.mac.to_string(), h.mode, h.enabled))
        .collect()
}

#[tokio::test]
async fn mode_set_applies_on_clean_head() {
    use sensr_schema::models::firewall::HostModeKind;
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    let before = fx.applied().len();
    let r = mode_set(&mut c, Some(sensr_ipc::HostModeMode::Isolated), None)
        .await
        .unwrap();
    assert_eq!(r, Response::Value(Some(json!({"result": "applied"}))));
    let applied = fx.applied();
    assert_eq!(applied.len(), before + 1);
    assert_eq!(
        modes_of(applied.last().unwrap()),
        [(MODE_MAC.to_owned(), HostModeKind::Isolated, true)]
    );
    let h = history(&mut c).await;
    assert_eq!(
        h[0].description,
        format!("set host mode {MODE_MAC} → isolated")
    );

    // a new mode replaces the entry; Normal removes it
    mode_set(&mut c, Some(sensr_ipc::HostModeMode::Quarantine), None)
        .await
        .unwrap();
    assert_eq!(
        modes_of(fx.applied().last().unwrap()),
        [(MODE_MAC.to_owned(), HostModeKind::Quarantine, true)]
    );
    assert_eq!(
        history(&mut c).await[0].description,
        format!("set host mode {MODE_MAC} → quarantine")
    );
    let r = mode_set(&mut c, None, None).await.unwrap();
    assert_eq!(r, Response::Value(Some(json!({"result": "applied"}))));
    assert!(modes_of(fx.applied().last().unwrap()).is_empty());
    assert_eq!(
        history(&mut c).await[0].description,
        format!("set host mode {MODE_MAC} → normal")
    );
    let st = match c.call(Op::Status).await.unwrap() {
        Response::Status(s) => s,
        other => panic!("{other:?}"),
    };
    assert!(!st.candidate_dirty);

    // already Normal: nothing to change, nothing applied, no error
    let n = fx.applied().len();
    let r = mode_set(&mut c, None, None).await.unwrap();
    assert_eq!(r, Response::Value(Some(json!({"result": "applied"}))));
    assert_eq!(fx.applied().len(), n);
}

#[tokio::test]
async fn mode_set_stages_when_candidate_is_dirty() {
    use sensr_schema::models::firewall::HostModeKind;
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    set(&mut c, "system.hostname", json!("half-done")).await;
    let before = fx.applied().len();
    let r = mode_set(&mut c, Some(sensr_ipc::HostModeMode::Quarantine), None)
        .await
        .unwrap();
    assert_eq!(r, Response::Value(Some(json!({"result": "staged"}))));
    assert_eq!(fx.applied().len(), before, "nothing applied");
    // both edits wait in the candidate
    assert_eq!(host(&mut c, Source::Candidate).await, json!("half-done"));
    let modes = get(&mut c, "firewall.host_modes", Source::Candidate)
        .await
        .unwrap();
    let entry = modes.as_object().unwrap().values().next().unwrap().clone();
    assert_eq!(entry["mac"], MODE_MAC);
    assert_eq!(entry["mode"], "quarantine");
    commit(&mut c, None).await.unwrap();
    assert_eq!(
        modes_of(fx.applied().last().unwrap()),
        [(MODE_MAC.to_owned(), HostModeKind::Quarantine, true)]
    );
}

#[tokio::test]
async fn mode_set_stages_when_confirm_pending() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    set(&mut c, "system.hostname", json!("a")).await;
    commit(&mut c, None).await.unwrap();
    set(&mut c, "system.hostname", json!("b")).await;
    commit(&mut c, Some(60)).await.unwrap();
    let before = fx.applied().len();
    let r = mode_set(&mut c, Some(sensr_ipc::HostModeMode::Isolated), None)
        .await
        .unwrap();
    assert_eq!(r, Response::Value(Some(json!({"result": "staged"}))));
    assert_eq!(fx.applied().len(), before, "nothing applied");
    let st = match c.call(Op::Status).await.unwrap() {
        Response::Status(s) => s,
        other => panic!("{other:?}"),
    };
    assert!(st.candidate_dirty);
    assert!(
        st.pending_confirm.is_some(),
        "the provisional commit stands"
    );
}

#[tokio::test]
async fn mode_set_self_quarantine_refused() {
    let fx = Fx::start(true).await;
    let me: std::net::IpAddr = "192.168.1.50".parse().unwrap();
    fx.applier
        .state
        .lock()
        .unwrap()
        .client_macs
        .push((me, MODE_MAC.into()));
    let mut c = fx.client().await;
    let before = fx.applied().len();
    let e = agent_err(mode_set(&mut c, Some(sensr_ipc::HostModeMode::Quarantine), Some(me)).await);
    assert_eq!(e.kind, ErrorKind::Conflict);
    assert_eq!(
        e.message,
        "That's the device you're using — quarantine it from another device."
    );
    // the same client through a dual-stack listener
    let mapped: std::net::IpAddr = "::ffff:192.168.1.50".parse().unwrap();
    let e = agent_err(
        mode_set(
            &mut c,
            Some(sensr_ipc::HostModeMode::Quarantine),
            Some(mapped),
        )
        .await,
    );
    assert_eq!(e.kind, ErrorKind::Conflict);
    assert_eq!(fx.applied().len(), before);
    let st = match c.call(Op::Status).await.unwrap() {
        Response::Status(s) => s,
        other => panic!("{other:?}"),
    };
    assert!(!st.candidate_dirty, "nothing staged");
    // Isolating yourself is allowed (the GUI stays reachable), and so is
    // quarantining another device
    let r = mode_set(&mut c, Some(sensr_ipc::HostModeMode::Isolated), Some(me))
        .await
        .unwrap();
    assert_eq!(r, Response::Value(Some(json!({"result": "applied"}))));
    let other: std::net::IpAddr = "192.168.1.51".parse().unwrap();
    let r = mode_set(
        &mut c,
        Some(sensr_ipc::HostModeMode::Quarantine),
        Some(other),
    )
    .await
    .unwrap();
    assert_eq!(r, Response::Value(Some(json!({"result": "applied"}))));
}

#[tokio::test]
async fn mode_set_rejects_a_bad_mac() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    let e = agent_err(
        c.call(Op::HostModeSet {
            mac: "id:01aabb".into(),
            mode: Some(sensr_ipc::HostModeMode::Isolated),
            remote_addr: None,
        })
        .await,
    );
    assert_eq!(e.kind, ErrorKind::BadRequest);
}

#[tokio::test]
async fn mode_set_readonly_forbidden() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    c.set_principal(Principal {
        readonly: true,
        ..c.principal().clone()
    });
    let before = fx.applied().len();
    let e = agent_err(mode_set(&mut c, Some(sensr_ipc::HostModeMode::Isolated), None).await);
    assert_eq!(e.kind, ErrorKind::Forbidden);
    assert_eq!(fx.applied().len(), before);
}

const LABEL_MAC: &str = "aa:bb:cc:dd:ee:ff";

async fn label_set(
    c: &mut Client,
    kind: Option<sensr_schema::models::hosts::HostKind>,
    maker: Option<&str>,
) -> Result<Response, ClientError> {
    c.call(Op::HostLabelSet {
        mac: LABEL_MAC.to_uppercase(),
        kind,
        maker: maker.map(Into::into),
    })
    .await
}

fn labels_of(
    doc: &Document,
) -> Vec<(
    String,
    Option<sensr_schema::models::hosts::HostKind>,
    Option<String>,
)> {
    doc.hosts
        .labels
        .values()
        .map(|l| (l.mac.to_string(), l.kind, l.maker.clone()))
        .collect()
}

#[tokio::test]
async fn label_set_applies_on_clean_head() {
    use sensr_schema::models::hosts::HostKind;
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    let before = fx.applied().len();
    let r = label_set(&mut c, Some(HostKind::Camera), None)
        .await
        .unwrap();
    assert_eq!(r, Response::Value(Some(json!({"result": "applied"}))));
    let applied = fx.applied();
    assert_eq!(applied.len(), before + 1);
    assert_eq!(
        labels_of(applied.last().unwrap()),
        [(LABEL_MAC.to_owned(), Some(HostKind::Camera), None)]
    );
    assert_eq!(
        history(&mut c).await[0].description,
        format!("set host label {LABEL_MAC} → camera/auto")
    );

    // a second set edits the entry in place; the maker is trimmed
    label_set(&mut c, None, Some("  Wyze  ")).await.unwrap();
    assert_eq!(
        labels_of(fx.applied().last().unwrap()),
        [(LABEL_MAC.to_owned(), None, Some("Wyze".to_owned()))]
    );
    assert_eq!(
        history(&mut c).await[0].description,
        format!("set host label {LABEL_MAC} → auto/Wyze")
    );
    let st = match c.call(Op::Status).await.unwrap() {
        Response::Status(s) => s,
        other => panic!("{other:?}"),
    };
    assert!(!st.candidate_dirty);

    // the same label again: nothing to commit
    let n = fx.applied().len();
    let r = label_set(&mut c, None, Some("Wyze")).await.unwrap();
    assert_eq!(r, Response::Value(Some(json!({"result": "applied"}))));
    assert_eq!(fx.applied().len(), n);
}

#[tokio::test]
async fn label_set_both_none_removes_entry() {
    use sensr_schema::models::hosts::HostKind;
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    label_set(&mut c, Some(HostKind::Tv), Some("LG"))
        .await
        .unwrap();
    assert_eq!(labels_of(fx.applied().last().unwrap()).len(), 1);
    label_set(&mut c, None, None).await.unwrap();
    assert!(labels_of(fx.applied().last().unwrap()).is_empty());
    assert_eq!(
        history(&mut c).await[0].description,
        format!("set host label {LABEL_MAC} → auto/auto")
    );
    // a blank maker counts as unset
    label_set(&mut c, Some(HostKind::Tv), Some("   "))
        .await
        .unwrap();
    assert_eq!(
        labels_of(fx.applied().last().unwrap()),
        [(LABEL_MAC.to_owned(), Some(HostKind::Tv), None)]
    );
    label_set(&mut c, None, Some("  ")).await.unwrap();
    assert!(labels_of(fx.applied().last().unwrap()).is_empty());
}

#[tokio::test]
async fn label_set_rejects_a_bad_mac_and_a_long_maker() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    let e = agent_err(
        c.call(Op::HostLabelSet {
            mac: "id:01aabb".into(),
            kind: None,
            maker: Some("x".into()),
        })
        .await,
    );
    assert_eq!(e.kind, ErrorKind::BadRequest);
    let before = fx.applied().len();
    assert!(
        label_set(&mut c, None, Some(&"m".repeat(65)))
            .await
            .is_err()
    );
    assert_eq!(fx.applied().len(), before);
    // control characters inside the maker (a trailing newline is trimmed)
    for bad in ["Wy\nze", "Wy\tze", "Wyze\u{1b}[0m"] {
        let e = agent_err(label_set(&mut c, None, Some(bad)).await);
        assert_eq!(e.kind, ErrorKind::BadRequest, "{bad:?}");
    }
    assert_eq!(fx.applied().len(), before);
}

#[tokio::test]
async fn label_set_stages_when_candidate_is_dirty() {
    use sensr_schema::models::hosts::HostKind;
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    set(&mut c, "system.hostname", json!("half-done")).await;
    let before = fx.applied().len();
    let r = label_set(&mut c, Some(HostKind::Printer), None)
        .await
        .unwrap();
    assert_eq!(r, Response::Value(Some(json!({"result": "staged"}))));
    assert_eq!(fx.applied().len(), before, "nothing applied");
    assert_eq!(host(&mut c, Source::Candidate).await, json!("half-done"));
    let labels = get(&mut c, "hosts.labels", Source::Candidate)
        .await
        .unwrap();
    let entry = labels.as_object().unwrap().values().next().unwrap().clone();
    assert_eq!(entry["mac"], LABEL_MAC);
    assert_eq!(entry["kind"], "printer");
    commit(&mut c, None).await.unwrap();
    assert_eq!(
        labels_of(fx.applied().last().unwrap()),
        [(LABEL_MAC.to_owned(), Some(HostKind::Printer), None)]
    );
}

#[tokio::test]
async fn label_set_stages_when_confirm_pending() {
    use sensr_schema::models::hosts::HostKind;
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    set(&mut c, "system.hostname", json!("a")).await;
    commit(&mut c, None).await.unwrap();
    set(&mut c, "system.hostname", json!("b")).await;
    commit(&mut c, Some(60)).await.unwrap();
    let before = fx.applied().len();
    let r = label_set(&mut c, Some(HostKind::Speaker), None)
        .await
        .unwrap();
    assert_eq!(r, Response::Value(Some(json!({"result": "staged"}))));
    assert_eq!(fx.applied().len(), before, "nothing applied");
    let st = match c.call(Op::Status).await.unwrap() {
        Response::Status(s) => s,
        other => panic!("{other:?}"),
    };
    assert!(st.candidate_dirty);
    assert!(st.pending_confirm.is_some());
}

#[tokio::test]
async fn label_set_readonly_forbidden() {
    use sensr_schema::models::hosts::HostKind;
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    c.set_principal(Principal {
        readonly: true,
        ..c.principal().clone()
    });
    let before = fx.applied().len();
    let e = agent_err(label_set(&mut c, Some(HostKind::Tv), None).await);
    assert_eq!(e.kind, ErrorKind::Forbidden);
    assert_eq!(fx.applied().len(), before);
}

async fn override_set(
    c: &mut Client,
    suffix: &str,
    set: Option<(&str, sensr_schema::models::insight::Category)>,
) -> Result<Response, ClientError> {
    c.call(Op::ServiceOverrideSet {
        suffix: suffix.into(),
        service: set.map(|s| s.0.into()),
        category: set.map(|s| s.1),
    })
    .await
}

fn overrides_of(doc: &Document) -> Vec<(String, String, sensr_schema::models::insight::Category)> {
    doc.insight
        .dns
        .service_overrides
        .values()
        .map(|o| (o.suffix.clone(), o.service.clone(), o.category))
        .collect()
}

#[tokio::test]
async fn service_override_set_applies_edits_and_removes() {
    use sensr_schema::models::insight::Category;
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    let r = override_set(
        &mut c,
        " Some-Game-CDN.net. ",
        Some(("Fortnite", Category::Games)),
    )
    .await
    .unwrap();
    assert_eq!(r, Response::Value(Some(json!({"result": "applied"}))));
    assert_eq!(
        overrides_of(fx.applied().last().unwrap()),
        [(
            "some-game-cdn.net".to_owned(),
            "Fortnite".to_owned(),
            Category::Games
        )]
    );
    assert_eq!(
        history(&mut c).await[0].description,
        "set service override some-game-cdn.net → Fortnite/games"
    );
    // the same suffix again edits the entry in place
    override_set(&mut c, "some-game-cdn.net", Some(("Epic", Category::Other)))
        .await
        .unwrap();
    assert_eq!(
        overrides_of(fx.applied().last().unwrap()),
        [(
            "some-game-cdn.net".to_owned(),
            "Epic".to_owned(),
            Category::Other
        )]
    );
    override_set(&mut c, "some-game-cdn.net", None)
        .await
        .unwrap();
    assert!(overrides_of(fx.applied().last().unwrap()).is_empty());
    assert_eq!(
        history(&mut c).await[0].description,
        "remove service override some-game-cdn.net"
    );
}

#[tokio::test]
async fn service_override_set_stages_when_candidate_is_dirty() {
    use sensr_schema::models::insight::Category;
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    set(&mut c, "system.hostname", json!("half-done")).await;
    let before = fx.applied().len();
    let r = override_set(&mut c, "example.com", Some(("Example", Category::Shopping)))
        .await
        .unwrap();
    assert_eq!(r, Response::Value(Some(json!({"result": "staged"}))));
    assert_eq!(fx.applied().len(), before, "nothing applied");
    commit(&mut c, None).await.unwrap();
    assert_eq!(
        overrides_of(fx.applied().last().unwrap()),
        [(
            "example.com".to_owned(),
            "Example".to_owned(),
            Category::Shopping
        )]
    );
}

#[tokio::test]
async fn service_override_set_rejects_bad_input() {
    use sensr_schema::models::insight::Category;
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    let before = fx.applied().len();
    for (suffix, set) in [
        ("com", Some(("X", Category::Other))),
        ("bad domain.com", Some(("X", Category::Other))),
        ("example.com", Some(("", Category::Other))),
        ("example.com", Some(("a\nb", Category::Other))),
    ] {
        let e = agent_err(override_set(&mut c, suffix, set).await);
        assert_eq!(e.kind, ErrorKind::BadRequest, "{suffix:?} {set:?}");
    }
    let long = "x".repeat(49);
    let e = agent_err(override_set(&mut c, "example.com", Some((&long, Category::Other))).await);
    assert_eq!(e.kind, ErrorKind::BadRequest);
    // a service without a category
    let e = agent_err(
        c.call(Op::ServiceOverrideSet {
            suffix: "example.com".into(),
            service: Some("X".into()),
            category: None,
        })
        .await,
    );
    assert_eq!(e.kind, ErrorKind::BadRequest);
    assert_eq!(fx.applied().len(), before);
    // read-only principals may not
    c.set_principal(Principal {
        readonly: true,
        ..c.principal().clone()
    });
    let e = agent_err(override_set(&mut c, "example.com", Some(("X", Category::Other))).await);
    assert_eq!(e.kind, ErrorKind::Forbidden);
}

const GUARD_RULE: &str = "guard.rules.6a7e0000-0000-4000-8000-000000000001";

fn guard_rule(action: &str) -> Value {
    json!({"hook": "exec", "target": "any", "action": action})
}

impl Fx {
    /// Like `start`, but with the guard confirm window set to `window`.
    async fn start_guard_window(window: Duration) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let applier = FakeApplier::default();
        let settings = Settings {
            trusted_uids: vec![Self::my_uid(&dir)],
            rollback_retry: Duration::from_millis(100),
            guard_confirm: window,
            ..Settings::default()
        };
        let agent = Agent::new(sensr_agent::store::in_memory(), applier.clone(), settings).unwrap();
        agent.boot().await.unwrap();
        let running =
            sensr_agent::start(agent, &dir.path().join("agent.sock"), 0o600, None).unwrap();
        Fx {
            dir,
            applier,
            running: Some(running),
        }
    }
}

#[tokio::test]
async fn block_change_forces_confirm_window() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    set(&mut c, "system.hostname", json!("a")).await;
    commit(&mut c, None).await.unwrap();

    set(&mut c, GUARD_RULE, guard_rule("block")).await;
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let Response::Committed(out) = commit(&mut c, None).await.unwrap() else {
        panic!()
    };
    let p = out.pending_confirm.expect("a block change needs a confirm");
    assert!(
        (119_000..=121_000).contains(&(p.deadline_ms - before)),
        "{}",
        p.deadline_ms - before
    );
    assert!(out.confirm_reason.unwrap().contains("confirm within 120 s"));

    // An explicit window is the caller's to choose.
    set(&mut c, GUARD_RULE, guard_rule("alert")).await;
    c.call(Op::ConfigConfirm).await.unwrap();
    commit(&mut c, None).await.unwrap();
    set(&mut c, GUARD_RULE, guard_rule("block")).await;
    let Response::Committed(out) = commit(&mut c, Some(5)).await.unwrap() else {
        panic!()
    };
    assert_eq!(out.confirm_reason, None);
}

#[tokio::test]
async fn block_change_rolls_back_when_not_confirmed() {
    let fx = Fx::start_guard_window(Duration::from_secs(1)).await;
    let mut c = fx.client().await;
    set(&mut c, "system.hostname", json!("a")).await;
    commit(&mut c, None).await.unwrap();
    set(&mut c, GUARD_RULE, guard_rule("block")).await;
    commit(&mut c, None).await.unwrap();
    assert!(
        get(&mut c, GUARD_RULE, Source::Applied).await.is_some(),
        "applied provisionally"
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if get(&mut c, GUARD_RULE, Source::Head).await.is_none() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("rolled back");
    assert!(get(&mut c, GUARD_RULE, Source::Applied).await.is_none());
}

#[tokio::test]
async fn alert_only_change_commits_directly() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    set(&mut c, "system.hostname", json!("a")).await;
    commit(&mut c, None).await.unwrap();
    set(&mut c, GUARD_RULE, guard_rule("alert")).await;
    let Response::Committed(out) = commit(&mut c, None).await.unwrap() else {
        panic!()
    };
    assert_eq!(out.pending_confirm, None);
    assert_eq!(out.confirm_reason, None);
}

#[tokio::test]
async fn rollback_to_a_block_revision_forces_confirm_window() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    set(&mut c, "system.hostname", json!("a")).await;
    commit(&mut c, None).await.unwrap();
    set(&mut c, GUARD_RULE, guard_rule("block")).await;
    commit(&mut c, Some(1000)).await.unwrap();
    c.call(Op::ConfigConfirm).await.unwrap(); // rev 3 has the block rule
    set(&mut c, GUARD_RULE, guard_rule("alert")).await;
    let Response::Committed(out) = commit(&mut c, None).await.unwrap() else {
        panic!()
    };
    assert_eq!(out.pending_confirm, None);
    let Response::Committed(out) = c.call(Op::ConfigRollback { to: Some(3) }).await.unwrap() else {
        panic!()
    };
    assert!(out.pending_confirm.is_some(), "restoring a block rule");
    assert!(out.confirm_reason.unwrap().contains("confirm within"));
}

#[tokio::test]
async fn first_block_commit_without_a_baseline_has_no_window() {
    // Nothing applied yet: there is no revision to fall back to.
    let fx = Fx::start_with(true, false).await;
    let mut c = fx.client().await;
    set(&mut c, GUARD_RULE, guard_rule("block")).await;
    let Response::Committed(out) = commit(&mut c, None).await.unwrap() else {
        panic!()
    };
    assert_eq!(out.pending_confirm, None);
    assert_eq!(out.confirm_reason, None);
}
