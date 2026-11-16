//! Typed IPC between `sensr-api` / the `sensr` CLI and the privileged
//! `sensr-agent` (docs/PLAN.md §2.3).
//!
//! - **Transport:** a Unix stream socket (`/run/sensr/agent.sock`). The agent
//!   learns the peer's uid/gid from `SO_PEERCRED` ([`server::PeerCred`]) and
//!   decides how far to trust the [`Principal`] a request claims.
//! - **Framing:** `u32` big-endian length + CBOR [`Envelope`] carrying the
//!   protocol version and a request id ([`frame`]).
//! - **Vocabulary:** [`Request`] = principal + [`Op`]; [`Response`] per op;
//!   streams answer [`Response::StreamOpened`] followed by
//!   [`ServerBody::Item`] frames and one [`ServerBody::End`]; the client
//!   sends [`ClientBody::Cancel`] to stop one.
//!
//! OPNsense counterpart: configd's socket protocol (`\0\0\0`-terminated text
//! replies). Length prefixes replace the terminator, so a reply can never be
//! truncated or run into the next one (T-0317).

pub mod client;
pub mod frame;
pub mod path;
pub mod proto;
pub mod server;

pub use client::{Client, ClientError, default_socket_path};
pub use frame::{ClientBody, Envelope, PROTOCOL_VERSION, ServerBody, StreamItem};
pub use path::ConfigPath;
pub use proto::*;
pub use server::{Handler, PeerCred, Reply};
