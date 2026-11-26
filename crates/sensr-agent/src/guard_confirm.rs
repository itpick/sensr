//! Block rules are the one guard change that can cut the box off from its
//! own management: when a commit may newly turn something into a block, it
//! goes through commit-confirm even if the caller did not ask.

use std::time::Duration;

use sensr_schema::Document;
use sensr_schema::models::guard::{GuardAction, GuardPackRule};

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
            || r.enabled == Some(true) && r.action != Some(GuardAction::Alert))
}

/// True when going from `head` to `candidate` may newly block something:
/// an owner rule that is enabled with action block and was not before, a
/// pack-rule override that becomes block (or is enabled, its own action
/// unknown here), or any pack newly enabled / the guard switched on (pack
/// contents are not inspected, so any of them may carry a block rule).
pub fn guard_needs_confirm(head: &Document, candidate: &Document) -> bool {
    let (h, c) = (&head.guard, &candidate.guard);
    if !h.enabled && c.enabled {
        return true;
    }
    if !c.enabled {
        return false;
    }
    let enabled_packs = |g: &sensr_schema::models::guard::Guard| {
        g.packs
            .values()
            .filter(|p| p.enabled)
            .map(|p| p.name.clone())
            .collect::<std::collections::BTreeSet<_>>()
    };
    let before = enabled_packs(h);
    if enabled_packs(c).difference(&before).next().is_some() {
        return true;
    }
    let blocking =
        |r: &sensr_schema::models::guard::GuardRule| r.enabled && r.action == GuardAction::Block;
    if c.rules
        .iter()
        .any(|(id, r)| blocking(r) && !h.rules.get(id).is_some_and(blocking))
    {
        return true;
    }
    c.pack_rules.iter().any(|(id, r)| {
        pack_rule_blocks(r)
            && match h.pack_rules.get(id) {
                None => true,
                Some(old) => {
                    // Became block, or was explicitly off and is on again.
                    r.action == Some(GuardAction::Block) && old.action != Some(GuardAction::Block)
                        || r.enabled != Some(false) && old.enabled == Some(false)
                        || r.enabled == Some(true) && old.enabled != Some(true)
                }
            }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensr_schema::models::guard::{GuardHook, GuardPack, GuardProcess, GuardRule, GuardTarget};

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
}
