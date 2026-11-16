//! Firewall rule IR, alias resolution and the nftables renderer (OPNsense
//! counterpart: `Firewall/FilterRule`, `filter.inc`, `filter.lib.inc`).
//!
//! Pipeline:
//!
//! ```text
//! OPNsense rule arrays (conf)  ─┐
//!                               ├─ normalize ─► ir::FilterRule ─┬─ render::pf   (oracle)
//! typed models (sensr-schema) ──┘                               └─ compile ─► render::nft (JSON)
//! ```

pub mod compile;
pub mod conf;
pub mod icmp;
pub mod ir;
pub mod nat;
pub mod normalize;
pub mod proto;
pub mod render;
pub mod ruleset;
pub mod services;
pub mod system_rules;
