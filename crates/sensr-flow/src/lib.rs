//! Traffic accounting and IDS alert storage (Reporting › Insight, Services ›
//! Intrusion Detection › Alerts).
//!
//! **Counting happens in the kernel.** The agent loads table `inet
//! sensr_flow` ([`nft::ruleset`]): dynamic sets with a counter per element,
//! keyed by local host, by local host + service (protocol and the
//! connection's original destination port), by remote address and by local
//! host + remote address (for per-host service attribution), updated
//! from the forward hook for traffic in from or out to a local interface.
//! `sensr-insight` reads the sets every few seconds (one `nft -j list
//! table`), turns counter values into deltas and adds them to 1-minute,
//! 1-hour and 1-day buckets in SQLite ([`store`]). Per-interface rates come
//! from the kernel's interface counters. No packet capture, no flow export
//! through localhost: ntopng cost about half a core on a Pi 5 under load;
//! this costs a set lookup per packet in the kernel and a few milliseconds
//! of user time per sample.
//!
//! **Alerts** are Suricata's `eve.json` lines, tailed (rotation-safe) into
//! their own database with retention ([`eve`]).
//!
//! Without the default `store` feature only the contract the agent needs is
//! built: [`config`] (what the agent writes for the daemon) and [`nft`]
//! (the accounting table).

pub mod attrib;
pub mod config;
pub mod dnstap;
#[cfg(feature = "store")]
pub mod eve;
pub mod feed;
pub mod nft;
pub mod services;
#[cfg(feature = "store")]
pub mod store;
#[cfg(all(feature = "store", unix))]
pub mod tap;
