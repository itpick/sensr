//! Authentication and authorization for sensr (docs/PLAN.md §2.2, Phase 0:
//! ACL; Phase 1: the rest of the auth backends).
//!
//! - [`acl`]: OPNsense privilege names, URL patterns and user/group
//!   resolution, used by `sensr-api` before a request leaves the process and
//!   by `sensr-agent` when it re-checks the declared principal.
//! - [`password`]: argon2id hashes, bcrypt import.
//! - [`apikey`]: `key:secret` API keys with OPNsense's storage format.

pub mod acl;
pub mod apikey;
pub mod password;
