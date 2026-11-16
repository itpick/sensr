//! Reference resolution for validation (OPNsense: the config lookups behind
//! `InterfaceField`, `NetworkAliasField`, `ModelRelationField`).

use crate::array::Uuid;
use crate::fields::{AliasName, GroupName, InterfaceId};
use crate::models::firewall::AliasType;

/// Which collection a UUID reference points into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ItemKind {
    /// `dhcpv4.subnets`.
    Dhcp4Subnet,
    /// `wireguard.peers`.
    WgPeer,
    /// `wireguard.servers`.
    WgServer,
    /// `firewall.rules`.
    FilterRule,
}

/// What a model may ask about the rest of the document while validating.
///
/// [`crate::Document`] implements it; tests and the UI (validating one form
/// against a cached snapshot) can supply their own.
pub trait RefContext {
    /// True if a logical interface with this id is configured.
    fn has_interface(&self, id: &InterfaceId) -> bool;
    /// The type of the alias with this name, if one exists.
    fn alias_type(&self, name: &AliasName) -> Option<AliasType>;
    /// True if an item with `id` exists in the collection `kind`.
    fn has_item(&self, kind: ItemKind, id: &Uuid) -> bool;
    /// True if a local group with this name exists.
    fn has_group(&self, name: &GroupName) -> bool;
}

/// Validation of a model (or part of one) against the document.
///
/// `at` is the model's own path; implementations report failures at
/// `at.join(field)` so messages carry full dotted paths.
pub trait Validate {
    /// Appends every failure to `out`.
    fn validate(&self, ctx: &dyn RefContext, at: &crate::FieldPath, out: &mut crate::Validations);
}
