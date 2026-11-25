//! Runtime guard: dynamic eBPF packs that watch or block process, network,
//! file, module and `bpf()` activity. The contract types (`rule`, `config`,
//! `proto`) compile with no features; the store and daemon sit behind the
//! `store` and `daemon` features.

pub mod compile;
pub mod config;
pub mod maps;
pub mod proto;
pub mod rule;
