//! sensr's DNS runtime jobs next to Unbound (OPNsense counterparts: the
//! `unbound-dnsbl` Python module and `blocklists.py`, `unbound_watcher.py`,
//! `stats.py`):
//!
//! - [`compile`]: blocklist policies compiled into Unbound local zones and
//!   views, from lists [`fetch`]ed and [`parse`]d here;
//! - [`update`]: the scheduled refresh, swapping the result in without
//!   restarting the resolver;
//! - [`leases`]: Kea's leases registered as names;
//! - [`stats`]: resolver counters for the web UI.
//!
//! The renderer (`sensr_apply::appliers::unbound`) describes the jobs in
//! `sensr-dns.json` ([`sensr_apply::appliers::dns_runtime`]).

pub mod compile;
pub mod control;
pub mod fetch;
pub mod leases;
pub mod name;
pub mod parse;
pub mod stats;
pub mod update;
