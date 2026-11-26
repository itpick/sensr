//! Port scanner service (Diagnostics › Port Scan).
//!
//! Without features only the shared contract is built: [`config`] (what the
//! agent writes for the daemon), [`proto`] (the JSON-lines protocol on the
//! daemon's unix socket) and [`target`] (scan target parsing and safety
//! checks). Storage, the daemon and the blocking socket client sit behind the
//! `store`, `daemon` and `client` features.

pub mod config;
pub mod discover;
pub mod ident;
pub mod ports;
pub mod proto;
pub mod target;
pub mod types;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "daemon")]
pub mod pace;
#[cfg(feature = "daemon")]
pub mod queue;
#[cfg(feature = "daemon")]
pub mod runner;
#[cfg(feature = "daemon")]
pub mod server;
#[cfg(feature = "store")]
pub mod store;
#[cfg(feature = "daemon")]
pub mod tcp;
#[cfg(feature = "daemon")]
pub mod udp;
#[cfg(feature = "daemon")]
pub mod udp_probes;
