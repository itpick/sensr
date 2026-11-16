//! A small pool of agent connections.
//!
//! Each request needs one IPC round trip; reusing connections keeps that a
//! single write + read (no connect) so reads stay in the sub-millisecond
//! class measured in docs/research/07.

use std::path::PathBuf;
use std::sync::Mutex;

use sensr_ipc::{Client, ClientError, Op, Principal, Response};

/// Idle connections kept for reuse.
const MAX_IDLE: usize = 16;

/// Pooled access to `sensr-agent`.
pub struct AgentPool {
    socket: PathBuf,
    idle: Mutex<Vec<Client>>,
}

impl AgentPool {
    /// A pool for the agent at `socket`. Connects lazily.
    pub fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            idle: Mutex::new(Vec::new()),
        }
    }

    fn take(&self) -> Option<Client> {
        self.idle.lock().unwrap_or_else(|e| e.into_inner()).pop()
    }

    fn give_back(&self, c: Client) {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        if idle.len() < MAX_IDLE {
            idle.push(c);
        }
    }

    /// Sends `op` as `principal`. A pooled connection the agent has since
    /// closed (agent restart) is retried once on a fresh connection.
    pub async fn call(&self, principal: Principal, op: Op) -> Result<Response, ClientError> {
        if let Some(mut c) = self.take() {
            c.set_principal(principal.clone());
            match c.call(op.clone()).await {
                Ok(r) => {
                    self.give_back(c);
                    return Ok(r);
                }
                Err(ClientError::Agent(e)) => {
                    self.give_back(c);
                    return Err(ClientError::Agent(e));
                }
                // Transport failure: fall through to a fresh connection.
                Err(_) => {}
            }
        }
        let mut c = Client::connect(&self.socket, principal).await?;
        let r = c.call(op).await;
        if matches!(r, Ok(_) | Err(ClientError::Agent(_))) {
            self.give_back(c);
        }
        r
    }
}
