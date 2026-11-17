//! Network model and runtime network state for sensr.
//!
//! Phase 0 holds only [`ipv6::pd`]: prefix-delegation maths and the persisted
//! PD state machine (docs/PLAN.md §8 task 8, ISS-C-002). Interface, route and
//! gateway reconciliation land here in Phase 1.

pub mod ipv6;
