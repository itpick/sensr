//! Typed configuration models for the routing slice, and the [`Document`]
//! root that holds them.
//!
//! The importer maps OPNsense `config.xml` into these types and the renderers
//! (nftables, Kea, Unbound, WireGuard, networkd) read from them. Changes after
//! publication are additive only: new fields carry `#[serde(default)]` so
//! older documents keep loading; anything else goes through a migration.
//!
//! JSON conventions: field names are `snake_case`; optional values are
//! omitted when unset; enums with data are internally tagged (`"mode"`,
//! `"type"`, `"rr"`); list items are UUID-keyed objects
//! ([`ArrayField`](crate::ArrayField)).

pub mod devices;
pub mod dhcp;
pub mod dhcpv6;
pub mod dns;
pub mod dnsbl;
pub mod firewall;
pub mod gateways;
pub mod ids;
pub mod insight;
pub mod interfaces;
pub mod nat;
pub mod ntp;
pub mod routes;
pub mod system;
pub mod trust;
pub mod wireguard;

pub(crate) mod check;
mod document;

pub use document::{Document, SCHEMA_VERSION, SchemaVersion, Section};

/// `#[serde(default = "yes")]` for booleans that default to true.
pub(crate) fn yes() -> bool {
    true
}
