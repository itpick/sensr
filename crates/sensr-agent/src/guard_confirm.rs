//! Block rules are the one guard change that can cut the box off from its
//! own management: when a commit may newly turn something into a block, it
//! goes through commit-confirm even if the caller did not ask.

use std::collections::BTreeSet;
use std::time::Duration;

use sensr_schema::Document;
use sensr_schema::models::guard::{Guard, GuardAction, GuardPackRule, GuardRule};

/// The window imposed on a commit that may newly block.
pub const GUARD_CONFIRM: Duration = Duration::from_secs(120);

/// What the caller is told when the window was imposed.
pub fn reason(window: Duration) -> String {
    format!(
        "blocking rules changed: confirm within {} s or the change rolls back",
        window.as_secs()
    )
}

fn pack_rule_blocks(r: &GuardPackRule) -> bool {
    r.enabled != Some(false)
        && (r.action == Some(GuardAction::Block)
            || (r.enabled == Some(true) && r.action != Some(GuardAction::Alert)))
}

/// An owner rule that blocks, and is not the very same block rule as before
/// (its `description` aside): widening the target or the process, or
/// switching the hook, changes what is blocked.
fn rule_newly_blocks(old: Option<&GuardRule>, new: &GuardRule) -> bool {
    new.enabled
        && new.action == GuardAction::Block
        && !old.is_some_and(|o| {
            o.enabled
                && o.action == GuardAction::Block
                && o.hook == new.hook
                && o.process == new.process
                && o.target == new.target
        })
}

/// A pack-rule override that may block and differs from the old one.
fn pack_rule_newly_blocks(old: Option<&GuardPackRule>, new: &GuardPackRule) -> bool {
    pack_rule_blocks(new) && !old.is_some_and(|o| o == new)
}

/// True when going from `head` to `candidate` may newly block something:
/// an owner rule that blocks and is new or changed, a pack-rule override
/// that blocks (or is enabled, its own action unknown here) and is new or
/// changed, or any pack newly enabled / the guard switched on (pack
/// contents are not inspected, so any of them may carry a block rule).
pub fn guard_needs_confirm(head: &Document, candidate: &Document) -> bool {
    let (h, c) = (&head.guard, &candidate.guard);
    if !c.enabled {
        return false;
    }
    if !h.enabled {
        return true;
    }
    let enabled_packs = |g: &Guard| {
        g.packs
            .values()
            .filter(|p| p.enabled)
            .map(|p| p.name.clone())
            .collect::<BTreeSet<_>>()
    };
    if !enabled_packs(c).is_subset(&enabled_packs(h)) {
        return true;
    }
    c.rules
        .iter()
        .any(|(id, r)| rule_newly_blocks(h.rules.get(id), r))
        || c.pack_rules
            .iter()
            .any(|(id, r)| pack_rule_newly_blocks(h.pack_rules.get(id), r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensr_schema::models::guard::{GuardHook, GuardPack, GuardProcess, GuardTarget};

    fn rule(enabled: bool, action: GuardAction) -> GuardRule {
        GuardRule {
            enabled,
            description: String::new(),
            hook: GuardHook::Exec,
            process: GuardProcess::default(),
            target: GuardTarget::Any,
            action,
        }
    }

    fn pr(enabled: Option<bool>, action: Option<GuardAction>) -> GuardPackRule {
        GuardPackRule {
            pack: "p".into(),
            rule_id: "r".into(),
            enabled,
            action,
        }
    }

    fn pair() -> (Document, Document) {
        (Document::factory(), Document::factory())
    }

    #[test]
    fn identical_documents_need_nothing() {
        let (h, c) = pair();
        assert!(!guard_needs_confirm(&h, &c));
    }

    #[test]
    fn new_block_rule_needs_confirm_new_alert_rule_does_not() {
        let (h, mut c) = pair();
        c.guard.rules.push(rule(true, GuardAction::Alert));
        assert!(!guard_needs_confirm(&h, &c));
        c.guard.rules.push(rule(true, GuardAction::Block));
        assert!(guard_needs_confirm(&h, &c));
    }

    #[test]
    fn disabled_new_block_rule_is_fine() {
        let (h, mut c) = pair();
        c.guard.rules.push(rule(false, GuardAction::Block));
        assert!(!guard_needs_confirm(&h, &c));
    }

    #[test]
    fn alert_to_block_and_enabling_a_block_rule_need_confirm() {
        let (mut h, mut c) = pair();
        let id = h.guard.rules.push(rule(true, GuardAction::Alert));
        c.guard.rules.insert(id, rule(true, GuardAction::Block));
        assert!(guard_needs_confirm(&h, &c));

        let (mut h, mut c) = pair();
        let id = h.guard.rules.push(rule(false, GuardAction::Block));
        c.guard.rules.insert(id, rule(true, GuardAction::Block));
        assert!(guard_needs_confirm(&h, &c));
    }

    #[test]
    fn unchanged_or_relaxed_block_rule_needs_nothing() {
        let (mut h, mut c) = pair();
        let id = h.guard.rules.push(rule(true, GuardAction::Block));
        c.guard.rules.insert(id, rule(true, GuardAction::Block));
        assert!(!guard_needs_confirm(&h, &c));
        c.guard.rules.insert(id, rule(true, GuardAction::Alert));
        assert!(!guard_needs_confirm(&h, &c));
    }

    #[test]
    fn pack_rule_overrides() {
        let (h, mut c) = pair();
        c.guard.pack_rules.push(pr(None, Some(GuardAction::Alert)));
        assert!(!guard_needs_confirm(&h, &c));

        let (h, mut c) = pair();
        c.guard.pack_rules.push(pr(None, Some(GuardAction::Block)));
        assert!(guard_needs_confirm(&h, &c));

        let (h, mut c) = pair();
        c.guard.pack_rules.push(pr(Some(true), None));
        assert!(guard_needs_confirm(&h, &c));

        let (h, mut c) = pair();
        c.guard
            .pack_rules
            .push(pr(Some(false), Some(GuardAction::Block)));
        assert!(!guard_needs_confirm(&h, &c));

        let (mut h, mut c) = pair();
        let id = h.guard.pack_rules.push(pr(None, Some(GuardAction::Alert)));
        c.guard
            .pack_rules
            .insert(id, pr(None, Some(GuardAction::Block)));
        assert!(guard_needs_confirm(&h, &c));

        let (mut h, mut c) = pair();
        let id = h.guard.pack_rules.push(pr(None, Some(GuardAction::Block)));
        c.guard
            .pack_rules
            .insert(id, pr(None, Some(GuardAction::Block)));
        assert!(!guard_needs_confirm(&h, &c));
    }

    #[test]
    fn enabling_a_pack_or_the_guard_needs_confirm() {
        let (h, mut c) = pair();
        c.guard.packs.push(GuardPack {
            name: "x".into(),
            enabled: true,
        });
        assert!(guard_needs_confirm(&h, &c));

        let (h, mut c) = pair();
        c.guard.packs.push(GuardPack {
            name: "x".into(),
            enabled: false,
        });
        assert!(!guard_needs_confirm(&h, &c));

        let (mut h, mut c) = pair();
        h.guard.enabled = false;
        c.guard.enabled = true;
        assert!(guard_needs_confirm(&h, &c));
    }

    #[test]
    fn already_enabled_pack_and_disabling_need_nothing() {
        let (mut h, mut c) = pair();
        let p = || GuardPack {
            name: "x".into(),
            enabled: true,
        };
        h.guard.packs.push(p());
        c.guard.packs.push(p());
        assert!(!guard_needs_confirm(&h, &c));
        c.guard.enabled = false;
        c.guard.rules.push(rule(true, GuardAction::Block));
        assert!(!guard_needs_confirm(&h, &c));
    }

    fn changed_block(f: impl FnOnce(&mut GuardRule)) -> bool {
        let (mut h, mut c) = pair();
        let mut r = rule(true, GuardAction::Block);
        r.target = GuardTarget::PathPrefix("/x".into());
        r.process.exe_prefix = Some("/usr/bin".into());
        let id = h.guard.rules.push(r.clone());
        f(&mut r);
        c.guard.rules.insert(id, r);
        guard_needs_confirm(&h, &c)
    }

    #[test]
    fn an_existing_block_rule_that_changes_scope_needs_confirm() {
        assert!(changed_block(|r| r.target = GuardTarget::Any));
        assert!(changed_block(|r| r.process.exe_prefix = None));
        assert!(changed_block(|r| r.hook = GuardHook::Connect));
        assert!(!changed_block(|r| r.description = "reworded".into()));
        assert!(!changed_block(|_| {}));
    }

    #[test]
    fn a_changed_block_pack_override_needs_confirm() {
        let (mut h, mut c) = pair();
        let id = h.guard.pack_rules.push(pr(None, Some(GuardAction::Block)));
        c.guard
            .pack_rules
            .insert(id, pr(Some(true), Some(GuardAction::Block)));
        assert!(guard_needs_confirm(&h, &c));
    }
}
