//! Runtime guard: dynamic eBPF packs that watch or block process, network,
//! file, module and `bpf()` activity. The contract types (`rule`, `config`,
//! `proto`) compile with no features; the store and daemon sit behind the
//! `store` and `daemon` features.

pub mod compile;
pub mod config;
#[cfg(feature = "daemon")]
pub mod daemon;
pub mod events;
#[cfg(feature = "daemon")]
pub mod loader;
pub mod maps;
pub mod packs;
pub mod proto;
pub mod rule;
#[cfg(feature = "daemon")]
pub mod server;
#[cfg(feature = "store")]
pub mod store;
