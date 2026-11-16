//! Validation helpers shared by the models.

use std::collections::HashMap;
use std::hash::Hash;

use crate::fields::{InterfaceId, NetOrAlias, PortSpec};
use crate::models::firewall::AliasType;
use crate::refs::RefContext;
use crate::validation::{FieldPath, Validations, ValidatorKind, messages};

/// Reports a missing interface.
pub(crate) fn interface(
    ctx: &dyn RefContext,
    id: &InterfaceId,
    at: &FieldPath,
    out: &mut Validations,
) {
    if !ctx.has_interface(id) {
        out.add(at, ValidatorKind::Callback, messages::UNKNOWN_INTERFACE);
    }
}

/// Reports missing interfaces in a list.
pub(crate) fn interfaces(
    ctx: &dyn RefContext,
    ids: &[InterfaceId],
    at: &FieldPath,
    out: &mut Validations,
) {
    for id in ids {
        if !ctx.has_interface(id) {
            out.add(
                at,
                ValidatorKind::Callback,
                format!("Interface {id} does not exist."),
            );
        }
    }
}

/// Checks an address operand: interfaces exist, aliases exist and hold
/// addresses (a port alias cannot stand where a network is expected).
pub(crate) fn net_or_alias(
    ctx: &dyn RefContext,
    v: &NetOrAlias,
    at: &FieldPath,
    out: &mut Validations,
) {
    match v {
        NetOrAlias::InterfaceNet(i) | NetOrAlias::InterfaceAddr(i) => interface(ctx, i, at, out),
        NetOrAlias::Alias(a) => match ctx.alias_type(a) {
            None => out.add(at, ValidatorKind::Callback, messages::UNKNOWN_ALIAS),
            Some(t) if !t.holds_addresses() => out.add(
                at,
                ValidatorKind::Callback,
                format!("Alias {a} does not contain addresses."),
            ),
            Some(_) => {}
        },
        NetOrAlias::Any | NetOrAlias::This | NetOrAlias::Net(_) => {}
    }
}

/// Checks a port operand: a referenced alias exists and is a port alias.
pub(crate) fn port_spec(ctx: &dyn RefContext, v: &PortSpec, at: &FieldPath, out: &mut Validations) {
    if let PortSpec::Alias(a) = v {
        match ctx.alias_type(a) {
            None => out.add(at, ValidatorKind::Callback, messages::UNKNOWN_ALIAS),
            Some(AliasType::Port) => {}
            Some(_) => out.add(
                at,
                ValidatorKind::Callback,
                format!("Alias {a} is not a port alias."),
            ),
        }
    }
}

/// Reports every item whose `key` repeats an earlier one (OPNsense
/// `UniqueConstraint`: one message per offending item, T-0066). `None` keys
/// (empty values) are never duplicates.
pub(crate) fn unique<'a, K, I>(items: I, field: &str, message: &str, out: &mut Validations)
where
    K: Eq + Hash,
    I: IntoIterator<Item = (FieldPath, Option<K>)>,
    K: 'a,
{
    let mut seen: HashMap<K, Vec<FieldPath>> = HashMap::new();
    let mut order = Vec::new();
    for (path, key) in items {
        if let Some(k) = key {
            let entry = seen.entry(k).or_default();
            entry.push(path.clone());
            order.push(path);
        }
    }
    let dupes: std::collections::HashSet<&FieldPath> = seen
        .values()
        .filter(|paths| paths.len() > 1)
        .flatten()
        .collect();
    for path in order.iter().filter(|p| dupes.contains(p)) {
        out.add(&path.join(field), ValidatorKind::Constraint, message);
    }
}

/// Reports a number outside `range` with OPNsense's MinMax wording.
pub(crate) fn range<T>(
    v: T,
    range: std::ops::RangeInclusive<T>,
    at: &FieldPath,
    out: &mut Validations,
) where
    T: PartialOrd + std::fmt::Display + Copy,
{
    if !range.contains(&v) {
        out.add(
            at,
            ValidatorKind::MinMax,
            format!(
                "Please specify a value between {} and {}.",
                range.start(),
                range.end()
            ),
        );
    }
}
