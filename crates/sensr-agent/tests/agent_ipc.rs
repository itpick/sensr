//! The agent behind its real socket, with the in-memory store and the fake
//! applier.

use std::os::unix::fs::MetadataExt;
use std::time::Duration;

use sensr_agent::applier::FakeApplier;
use sensr_agent::store::{JsonDirStore, MemStore};
use sensr_agent::{Agent, Running, Settings};
use sensr_auth::password::hash_password;
use sensr_ipc::{
    Client, ClientError, Credential, ErrorKind, Event, Op, Principal, Response, Source, StreamItem,
};
use serde_json::{Value, json};

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
        let dir = tempfile::tempdir().unwrap();
        let applier = FakeApplier::default();
        let running = Self::spawn(&dir, applier.clone(), trust_me, false).await;
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
    ) -> Running {
        let settings = Settings {
            trusted_uids: if trust_me {
                vec![Self::my_uid(dir)]
            } else {
                vec![]
            },
            state_file: persistent.then(|| dir.path().join("agent-state.json")),
            rollback_retry: Duration::from_millis(100),
            ..Settings::default()
        };
        let socket = dir.path().join("agent.sock");
        if persistent {
            let store = JsonDirStore::open(&dir.path().join("revisions")).unwrap();
            let agent = Agent::new(store, applier, settings).unwrap();
            agent.boot().await.unwrap();
            sensr_agent::start(agent, &socket, 0o600, None).unwrap()
        } else {
            let agent = Agent::new(MemStore::new(), applier, settings).unwrap();
            agent.boot().await.unwrap();
            sensr_agent::start(agent, &socket, 0o600, None).unwrap()
        }
    }

    async fn client(&self) -> Client {
        Client::connect(
            &self.dir.path().join("agent.sock"),
            Principal::unix("tester", 0),
        )
        .await
        .unwrap()
    }

    fn applied(&self) -> Vec<Value> {
        self.applier.state.lock().unwrap().applied.clone()
    }

    async fn stop(&mut self) {
        if let Some(r) = self.running.take() {
            r.shutdown().await;
        }
    }
}

async fn set(c: &mut Client, path: &str, value: Value) -> Response {
    c.call(Op::ConfigSet {
        path: path.parse().unwrap(),
        value,
    })
    .await
    .unwrap()
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
    // Empty store: the root is still an object (T-0401 shape).
    assert_eq!(get(&mut c, "/", Source::Head).await, Some(json!({})));
    assert_eq!(
        set(&mut c, "system.hostname", json!("fw1")).await,
        Response::Staged { dirty: true }
    );
    assert_eq!(
        get(&mut c, "system.hostname", Source::Candidate).await,
        Some(json!("fw1"))
    );
    assert_eq!(get(&mut c, "system.hostname", Source::Head).await, None);

    let Response::Committed(out) = commit(&mut c, None).await.unwrap() else {
        panic!()
    };
    assert_eq!(out.revision.id, 1);
    assert!(out.revision.username.ends_with("@unix"));
    assert_eq!(
        get(&mut c, "system.hostname", Source::Head).await,
        Some(json!("fw1"))
    );
    assert_eq!(
        get(&mut c, "system.hostname", Source::Applied).await,
        Some(json!("fw1"))
    );
    assert_eq!(fx.applied(), vec![json!({"system": {"hostname": "fw1"}})]);

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

    let Response::History(h) = c.call(Op::ConfigHistory { limit: None }).await.unwrap() else {
        panic!()
    };
    assert_eq!(h.iter().map(|r| r.id).collect::<Vec<_>>(), [2, 1]);
    assert_eq!(h[0].parent, Some(1));

    let Response::Status(st) = c.call(Op::Status).await.unwrap() else {
        panic!()
    };
    assert_eq!(st.applied, Some(2));
    assert!(!st.candidate_dirty);
    assert_eq!(st.pending_confirm, None);
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
    assert_eq!((p.revision, p.rollback_to), (2, 1));
    assert_eq!(
        c.call(Op::ConfigConfirm).await.unwrap(),
        Response::Confirmed(2)
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        get(&mut c, "system.hostname", Source::Applied).await,
        Some(json!("b"))
    );
    let Response::History(h) = c.call(Op::ConfigHistory { limit: None }).await.unwrap() else {
        panic!()
    };
    assert_eq!(h.len(), 2, "no rollback revision");
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
    // A commit-confirm needs something known-good to return to.
    set(&mut c, "system.hostname", json!("bad")).await;
    commit(&mut c, Some(1)).await.unwrap();
    assert_eq!(
        get(&mut c, "system.hostname", Source::Applied).await,
        Some(json!("bad"))
    );

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
    assert_eq!(rolled.0, 2);
    assert_eq!(rolled.1.id, 3);
    assert!(rolled.1.username.starts_with("sensr-agent@system"));
    assert!(rolled.1.description.contains("not confirmed"));

    assert_eq!(
        get(&mut c, "system.hostname", Source::Applied).await,
        Some(json!("good"))
    );
    assert_eq!(
        get(&mut c, "system.hostname", Source::Head).await,
        Some(json!("good"))
    );
    let hosts: Vec<Value> = fx
        .applied()
        .iter()
        .map(|d| d["system"]["hostname"].clone())
        .collect();
    assert_eq!(hosts, [json!("good"), json!("bad"), json!("good")]);
    let Response::Status(st) = c.call(Op::Status).await.unwrap() else {
        panic!()
    };
    assert_eq!(st.pending_confirm, None);
    assert_eq!(st.applied, Some(3));
}

#[tokio::test]
async fn second_provisional_commit_falls_back_to_last_confirmed() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    set(&mut c, "v", json!(1)).await;
    commit(&mut c, None).await.unwrap();
    set(&mut c, "v", json!(2)).await;
    commit(&mut c, Some(60)).await.unwrap();
    set(&mut c, "v", json!(3)).await;
    let Response::Committed(out) = commit(&mut c, Some(1)).await.unwrap() else {
        panic!()
    };
    assert_eq!(out.pending_confirm.unwrap().rollback_to, 1);
    tokio::time::sleep(Duration::from_millis(1600)).await;
    assert_eq!(get(&mut c, "v", Source::Applied).await, Some(json!(1)));
}

#[tokio::test]
async fn commit_confirm_without_baseline_is_refused() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    set(&mut c, "v", json!(1)).await;
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
    fx.applier.state.lock().unwrap().reject_paths = vec!["bad".parse().unwrap()];
    let mut c = fx.client().await;
    set(&mut c, "bad", json!(true)).await;
    let e = agent_err(commit(&mut c, None).await);
    assert_eq!(e.kind, ErrorKind::Validation);
    assert_eq!(e.validations[0].path, "bad");
    let Response::History(h) = c.call(Op::ConfigHistory { limit: None }).await.unwrap() else {
        panic!()
    };
    assert!(h.is_empty());
    // The candidate survives so the operator can fix it.
    assert_eq!(
        get(&mut c, "bad", Source::Candidate).await,
        Some(json!(true))
    );
}

#[tokio::test]
async fn failed_apply_restores_running_state() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    set(&mut c, "v", json!(1)).await;
    commit(&mut c, None).await.unwrap();
    set(&mut c, "v", json!(2)).await;
    fx.applier.state.lock().unwrap().fail_next_apply = Some("nft: busy".into());
    let e = agent_err(commit(&mut c, None).await);
    assert_eq!(e.kind, ErrorKind::ApplyFailed);
    assert!(e.message.contains("revision 2 stored but not applied"));
    assert_eq!(get(&mut c, "v", Source::Applied).await, Some(json!(1)));
    assert_eq!(fx.applied(), [json!({"v": 1}), json!({"v": 1})]);
    let Response::Status(st) = c.call(Op::Status).await.unwrap() else {
        panic!()
    };
    assert_eq!(st.applied, Some(1));
    assert!(st.last_apply_error.unwrap().contains("nft: busy"));
}

#[tokio::test]
async fn explicit_rollback_is_a_new_revision() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    for v in 1..=3 {
        set(&mut c, "v", json!(v)).await;
        commit(&mut c, None).await.unwrap();
    }
    let Response::Committed(out) = c.call(Op::ConfigRollback { to: None }).await.unwrap() else {
        panic!()
    };
    assert_eq!(out.revision.id, 4);
    assert_eq!(get(&mut c, "v", Source::Head).await, Some(json!(2)));
    c.call(Op::ConfigRollback { to: Some(1) }).await.unwrap();
    assert_eq!(get(&mut c, "v", Source::Applied).await, Some(json!(1)));
    assert_eq!(
        agent_err(c.call(Op::ConfigRollback { to: Some(99) }).await).kind,
        ErrorKind::NotFound
    );
}

#[tokio::test]
async fn untrusted_peer_is_read_only() {
    let fx = Fx::start(false).await;
    let mut c = fx.client().await;
    assert_eq!(get(&mut c, "/", Source::Head).await, Some(json!({})));
    let e = agent_err(
        c.call(Op::ConfigSet {
            path: "a".parse().unwrap(),
            value: json!(1),
        })
        .await,
    );
    assert_eq!(e.kind, ErrorKind::Forbidden);
    let auth = c
        .call(Op::Authenticate {
            credential: Credential::Password {
                user: "root".into(),
                password: "x".into(),
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
    set(&mut c, "v", json!(1)).await;
    let Response::Committed(out) = commit(&mut c, None).await.unwrap() else {
        panic!()
    };
    assert_eq!(out.revision.username, "admin@api");

    c.set_principal(Principal {
        readonly: true,
        ..c.principal().clone()
    });
    let e = agent_err(set_raw(&mut c).await);
    assert_eq!(e.kind, ErrorKind::Forbidden);
}

async fn set_raw(c: &mut Client) -> Result<Response, ClientError> {
    c.call(Op::ConfigSet {
        path: "v".parse().unwrap(),
        value: json!(2),
    })
    .await
}

#[tokio::test]
async fn authenticate_against_head_document() {
    let fx = Fx::start(true).await;
    let mut c = fx.client().await;
    c.call(Op::ConfigLoad {
        document: json!({"system": {
            "user": [{"name": "admin", "uid": "1000", "password": hash_password("s3cret").unwrap()}],
            "group": [{"name": "admins", "member": "1000", "priv": "page-all"}],
        }}),
    })
    .await
    .unwrap();
    commit(&mut c, None).await.unwrap();
    let cred = |pw: &str| Op::Authenticate {
        credential: Credential::Password {
            user: "admin".into(),
            password: pw.into(),
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
    set(
        &mut c,
        "filter.rule",
        json!([{"type": "pass", "interface": "lan"}]),
    )
    .await;
    set(&mut c, "unbound.enable", json!("1")).await;
    let Response::Plan(plan) = c
        .call(Op::ApplyDryRun {
            source: Source::Candidate,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert!(plan.nft.contains("+  # filter"));
    assert_eq!(plan.services[0].unit, "unbound.service");
    assert!(fx.applied().is_empty());
}

/// Persisted pending confirm + restart = immediate rollback at boot.
#[tokio::test]
async fn restart_with_pending_confirm_rolls_back_at_boot() {
    let dir = tempfile::tempdir().unwrap();
    let applier = FakeApplier::default();
    let running = Fx::spawn(&dir, applier.clone(), true, true).await;
    let mut c = Client::connect(&dir.path().join("agent.sock"), Principal::unix("t", 0))
        .await
        .unwrap();
    set(&mut c, "v", json!("good")).await;
    commit(&mut c, None).await.unwrap();
    set(&mut c, "v", json!("risky")).await;
    commit(&mut c, Some(3600)).await.unwrap();
    drop(c);
    running.shutdown().await;

    let running = Fx::spawn(&dir, applier.clone(), true, true).await;
    let mut c = Client::connect(&dir.path().join("agent.sock"), Principal::unix("t", 0))
        .await
        .unwrap();
    assert_eq!(get(&mut c, "v", Source::Applied).await, Some(json!("good")));
    let Response::Status(st) = c.call(Op::Status).await.unwrap() else {
        panic!()
    };
    assert_eq!(st.pending_confirm, None);
    assert_eq!(st.head.unwrap().id, 3);
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
