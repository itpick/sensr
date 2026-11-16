//! The client side, used by `sensr-api` and the `sensr` CLI.

use std::path::{Path, PathBuf};

use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

use crate::frame::{
    ClientBody, Envelope, FrameError, ServerBody, StreamItem, read_frame, write_frame,
};
use crate::proto::{IpcError, Op, Principal, Request, Response};

/// Where the agent listens unless configured otherwise.
pub const DEFAULT_SOCKET: &str = "/run/sensr/agent.sock";

/// Environment variable overriding [`DEFAULT_SOCKET`].
pub const SOCKET_ENV: &str = "SENSR_AGENT_SOCKET";

/// The agent socket path: `$SENSR_AGENT_SOCKET` or [`DEFAULT_SOCKET`].
pub fn default_socket_path() -> PathBuf {
    std::env::var_os(SOCKET_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET))
}

/// Client-side failures.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Could not reach the agent.
    #[error("cannot connect to sensr-agent at {path}: {source}")]
    Connect {
        /// Socket path.
        path: PathBuf,
        /// Cause.
        source: std::io::Error,
    },
    /// Transport or decoding failure.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// The agent answered with an error.
    #[error("{}", .0.message)]
    Agent(IpcError),
    /// The agent closed the connection mid-request.
    #[error("sensr-agent closed the connection")]
    Closed,
    /// A reply that does not fit the request (protocol bug).
    #[error("unexpected reply from sensr-agent: {0}")]
    Unexpected(String),
}

/// One connection to the agent. Requests on a connection are sequential;
/// open several clients for concurrency.
pub struct Client {
    rd: OwnedReadHalf,
    wr: OwnedWriteHalf,
    next_id: u64,
    principal: Principal,
}

impl Client {
    /// Connects to the agent socket; requests are made as `principal`.
    pub async fn connect(path: &Path, principal: Principal) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(path)
            .await
            .map_err(|source| ClientError::Connect {
                path: path.to_owned(),
                source,
            })?;
        let (rd, wr) = stream.into_split();
        Ok(Self {
            rd,
            wr,
            next_id: 1,
            principal,
        })
    }

    /// The principal requests are sent as.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Replaces the principal for subsequent requests.
    pub fn set_principal(&mut self, principal: Principal) {
        self.principal = principal;
    }

    async fn send(&mut self, op: Op) -> Result<u64, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        let req = Request {
            principal: self.principal.clone(),
            op,
        };
        write_frame(&mut self.wr, &Envelope::new(id, ClientBody::Request(req))).await?;
        Ok(id)
    }

    async fn recv(&mut self, id: u64) -> Result<ServerBody, ClientError> {
        loop {
            let env: Envelope<ServerBody> =
                read_frame(&mut self.rd).await?.ok_or(ClientError::Closed)?;
            // Frames for other ids can only be leftovers of a cancelled
            // stream; skip them.
            if env.id == id {
                return Ok(env.body);
            }
        }
    }

    /// Sends one request and waits for its response. An agent-side error
    /// becomes [`ClientError::Agent`].
    pub async fn call(&mut self, op: Op) -> Result<Response, ClientError> {
        let id = self.send(op).await?;
        match self.recv(id).await? {
            ServerBody::Response(Response::Error(e)) => Err(ClientError::Agent(e)),
            ServerBody::Response(r) => Ok(r),
            other => Err(ClientError::Unexpected(format!("{other:?}"))),
        }
    }

    /// Opens a stream (e.g. [`Op::Subscribe`]). The connection is dedicated
    /// to it until the stream ends or is cancelled.
    pub async fn stream(&mut self, op: Op) -> Result<Stream<'_>, ClientError> {
        match self.call(op).await? {
            Response::StreamOpened => {}
            other => return Err(ClientError::Unexpected(format!("{other:?}"))),
        }
        let id = self.next_id - 1;
        Ok(Stream {
            client: self,
            id,
            done: false,
        })
    }
}

/// An open stream on a [`Client`].
pub struct Stream<'a> {
    client: &'a mut Client,
    id: u64,
    done: bool,
}

impl Stream<'_> {
    /// The next item, or `None` once the agent ended the stream.
    pub async fn next(&mut self) -> Result<Option<StreamItem>, ClientError> {
        if self.done {
            return Ok(None);
        }
        match self.client.recv(self.id).await? {
            ServerBody::Item(item) => Ok(Some(item)),
            ServerBody::End(None) => {
                self.done = true;
                Ok(None)
            }
            ServerBody::End(Some(e)) => {
                self.done = true;
                Err(ClientError::Agent(e))
            }
            ServerBody::Response(r) => Err(ClientError::Unexpected(format!("{r:?}"))),
        }
    }

    /// Asks the agent to end the stream and drains it, leaving the
    /// connection ready for further requests.
    pub async fn cancel(mut self) -> Result<(), ClientError> {
        if self.done {
            return Ok(());
        }
        write_frame(
            &mut self.client.wr,
            &Envelope::new(self.id, ClientBody::Cancel),
        )
        .await?;
        while self.next().await?.is_some() {}
        Ok(())
    }
}
