//! Service identification.
//!
//! The result types live in [`crate::types`] so they build without features
//! (the store, API and UI read them); the probing functions join this module
//! behind the `daemon` feature.

pub use crate::types::{Ident, TlsInfo, sanitize};
