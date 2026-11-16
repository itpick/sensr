//! Client ↔ server over a real Unix socket.

use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use std::time::Duration;

use sensr_ipc::frame::{self, ClientBody, Envelope, ServerBody, StreamItem};
use sensr_ipc::server::{self, Handler, PeerCred, Reply};
use sensr_ipc::{Client, ClientError, ErrorKind, Op, Principal, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, watch};

/// Answers `Ping` with `Pong`, `Status` by echoing the peer uid in an error
/// message (lets the test see `SO_PEERCRED`), `Subscribe` with an endless
/// numbered stream, and sleeps 200 ms on `ConfigDiscard` to test draining.
struct Echo;

impl Handler for Echo {
    async fn handle(&self, peer: PeerCred, req: Request) -> Reply {
        match req.op {
            Op::Ping => Response::Pong.into(),
            Op::Status => Response::Error(sensr_ipc::IpcError::new(
                ErrorKind::Internal,
                format!("uid={}", peer.uid),
            ))
            .into(),
            Op::Subscribe => {
                let (tx, rx) = mpsc::channel(4);
                tokio::spawn(async move {
                    for n in 0.. {
                        if tx.send(StreamItem::Line(format!("{n}"))).await.is_err() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                });
                Reply::Stream(rx)
            }
            Op::ConfigDiscard => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                Response::Staged { dirty: false }.into()
            }
            _ => Response::Error(sensr_ipc::IpcError::new(ErrorKind::BadRequest, "nope")).into(),
        }
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

fn start() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.sock");
    let listener = server::bind(&path, 0o660).unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server::serve(listener, Arc::new(Echo), rx));
    Fixture {
        _dir: dir,
        path,
        stop,
        task,
    }
}

fn me() -> Principal {
    Principal::unix("tester", 1000)
}

#[tokio::test]
async fn ping_and_peer_cred() {
    let fx = start();
    let mut c = Client::connect(&fx.path, me()).await.unwrap();
    assert_eq!(c.call(Op::Ping).await.unwrap(), Response::Pong);
    // The socket file is ours, so its owner uid is the uid we connect as.
    let my_uid = std::fs::metadata(&fx.path).unwrap().uid();
    match c.call(Op::Status).await {
        Err(ClientError::Agent(e)) => assert_eq!(e.message, format!("uid={my_uid}")),
        other => panic!("{other:?}"),
    }
    let mode = std::fs::metadata(&fx.path).unwrap().mode() & 0o777;
    assert_eq!(mode, 0o660);
}

/// configd ended every reply with `\n\0\0\0` so a reader knew where it
/// stopped. Here a request the agent cannot decode still gets exactly one
/// complete, length-delimited error frame, and the connection stays usable.
#[tokio::test]
async fn reply_to_unknown_request_is_one_complete_frame_t0317() {
    let fx = start();
    let mut s = UnixStream::connect(&fx.path).await.unwrap();
    let bogus = frame::encode(&Envelope::new(42, "NoSuchOp")).unwrap();
    s.write_all(&bogus).await.unwrap();

    let mut len = [0u8; 4];
    s.read_exact(&mut len).await.unwrap();
    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut body).await.unwrap();
    let env: Envelope<ServerBody> = frame::decode(&body).unwrap();
    assert_eq!(env.id, 42);
    match env.body {
        ServerBody::Response(Response::Error(e)) => assert_eq!(e.kind, ErrorKind::BadRequest),
        other => panic!("{other:?}"),
    }

    // Same connection, next request works: nothing was left half-read.
    let ping = Envelope::new(
        43,
        ClientBody::Request(Request {
            principal: me(),
            op: Op::Ping,
        }),
    );
    frame::write_frame(&mut s, &ping).await.unwrap();
    let env: Envelope<ServerBody> = frame::read_frame(&mut s).await.unwrap().unwrap();
    assert_eq!(env.id, 43);
    assert_eq!(env.body, ServerBody::Response(Response::Pong));
}

#[tokio::test]
async fn version_mismatch_is_reported() {
    let fx = start();
    let mut s = UnixStream::connect(&fx.path).await.unwrap();
    let mut env = Envelope::new(
        5,
        ClientBody::Request(Request {
            principal: me(),
            op: Op::Ping,
        }),
    );
    env.v = 999;
    frame::write_frame(&mut s, &env).await.unwrap();
    let reply: Envelope<ServerBody> = frame::read_frame(&mut s).await.unwrap().unwrap();
    match reply.body {
        ServerBody::Response(Response::Error(e)) => assert_eq!(e.kind, ErrorKind::VersionMismatch),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn stream_then_cancel_then_reuse() {
    let fx = start();
    let mut c = Client::connect(&fx.path, me()).await.unwrap();
    let mut stream = c.stream(Op::Subscribe).await.unwrap();
    for want in 0..3 {
        assert_eq!(
            stream.next().await.unwrap(),
            Some(StreamItem::Line(want.to_string()))
        );
    }
    stream.cancel().await.unwrap();
    assert_eq!(c.call(Op::Ping).await.unwrap(), Response::Pong);
}

#[tokio::test]
async fn shutdown_drains_in_flight_request() {
    let fx = start();
    let mut c = Client::connect(&fx.path, me()).await.unwrap();
    let slow = tokio::spawn(async move { c.call(Op::ConfigDiscard).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    fx.stop.send(true).unwrap();
    assert_eq!(
        slow.await.unwrap().unwrap(),
        Response::Staged { dirty: false }
    );
    tokio::time::timeout(Duration::from_secs(2), fx.task)
        .await
        .unwrap()
        .unwrap();
    assert!(UnixStream::connect(&fx.path).await.is_err());
}

#[tokio::test]
async fn many_concurrent_clients() {
    let fx = start();
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let path = fx.path.clone();
        tasks.push(tokio::spawn(async move {
            let mut c = Client::connect(&path, me()).await.unwrap();
            for _ in 0..20 {
                assert_eq!(c.call(Op::Ping).await.unwrap(), Response::Pong);
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}
