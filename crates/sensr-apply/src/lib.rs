//! The sensr apply engine (OPNsense counterpart: configd, `template.py`,
//! `actions.d`, `rc.syshook`).
//!
//! - [`cmd`]: typed commands and the [`cmd::Runner`] that executes them; the
//!   only module allowed to spawn processes.
//! - [`actions`]: the typed action registry (`configctl` equivalent).
//! - [`plan`]: desired-state plans, diffs and stage ordering.
//! - [`templates`]: minijinja modules with `Targets`, staged into
//!   `/run/sensr/<daemon>/.next/` and swapped atomically.
//! - [`hooks`]: operator drop-ins per hook level.
//! - [`confirm`]: the commit-confirm timer.
//! - [`clock`]: injectable time.

pub mod actions;
pub mod clock;
pub mod cmd;
pub mod confirm;
pub mod hooks;
pub mod plan;
pub mod templates;
