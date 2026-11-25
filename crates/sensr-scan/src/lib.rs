//! Port scanner service (Diagnostics › Port Scan).
//!
//! Without features only the shared contract is built: [`config`] (what the
//! agent writes for the daemon), [`proto`] (the JSON-lines protocol on the
//! daemon's unix socket) and [`target`] (scan target parsing and safety
//! checks). Storage and the daemon sit behind the `store` and `daemon`
//! features.

pub mod config;
pub mod ident;
pub mod ports;
pub mod proto;
pub mod target;
pub mod types;

#[cfg(feature = "daemon")]
pub mod pace;
#[cfg(feature = "store")]
pub mod store;
#[cfg(feature = "daemon")]
pub mod tcp;
#[cfg(feature = "daemon")]
pub mod udp;
#[cfg(feature = "daemon")]
pub mod udp_probes;
