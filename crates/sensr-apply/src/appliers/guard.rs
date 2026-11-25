//! Runtime guard: the `sensr-guard` daemon's configuration.

use sensr_guard::config::{Config, PackRuleOverride, PackToggle};
use sensr_guard::rule::{Action, Hook, ProcessMatch, Rule, Target};
use sensr_schema::Document;
use sensr_schema::models::guard::{GuardAction, GuardHook, GuardTarget};

/// Live directory of the daemon's files.
pub const DIR: &str = "run/sensr/guard";
/// The daemon's configuration (`sensr_guard::config::CONFIG_PATH`).
pub const CONFIG: &str = "guard.json";
/// The daemon.
pub const UNIT: &str = "sensr-guard.service";

fn action(a: GuardAction) -> Action {
    match a {
        GuardAction::Alert => Action::Alert,
        GuardAction::Block => Action::Block,
    }
}

fn hook(h: GuardHook) -> Hook {
    match h {
        GuardHook::Exec => Hook::Exec,
        GuardHook::Connect => Hook::Connect,
        GuardHook::Listen => Hook::Listen,
        GuardHook::FileWrite => Hook::FileWrite,
        GuardHook::Setuid => Hook::Setuid,
        GuardHook::Module => Hook::Module,
        GuardHook::Bpf => Hook::Bpf,
    }
}

fn target(t: &GuardTarget) -> Target {
    match t {
        GuardTarget::Any => Target::Any,
        GuardTarget::PathPrefix(p) => Target::PathPrefix(p.clone()),
        GuardTarget::Net { cidr, ports } => Target::Net {
            cidr: *cidr,
            ports: ports.clone(),
        },
        GuardTarget::Uid(u) => Target::Uid(*u),
    }
}

/// The daemon's configuration (`None`: the guard is off).
pub fn config(doc: &Document) -> Option<Config> {
    let g = &doc.guard;
    g.enabled.then(|| Config {
        enabled: true,
        packs: g
            .packs
            .values()
            .map(|p| PackToggle {
                name: p.name.clone(),
                enabled: p.enabled,
            })
            .collect(),
        pack_rules: g
            .pack_rules
            .values()
            .map(|o| PackRuleOverride {
                pack: o.pack.clone(),
                rule_id: o.rule_id.clone(),
                enabled: o.enabled,
                action: o.action.map(action),
            })
            .collect(),
        rules: g
            .rules
            .iter()
            .filter(|(_, r)| r.enabled)
            .map(|(id, r)| Rule {
                id: id.to_string(),
                enabled: true,
                description: r.description.clone(),
                hook: hook(r.hook),
                process: ProcessMatch {
                    exe_prefix: r.process.exe_prefix.clone(),
                    unit: r.process.unit.clone(),
                },
                target: target(&r.target),
                action: action(r.action),
            })
            .collect(),
        retention_days: g.retention_days,
        max_rows: g.max_rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const U1: &str = "6d0de000-0000-4000-8000-000000000001";
    const U2: &str = "6d0de000-0000-4000-8000-000000000002";

    #[test]
    fn maps_enabled_rules_with_uuid_ids() {
        let mut d = Document::factory();
        d.guard = serde_json::from_value(json!({
            "packs": {U1: {"name": "core", "enabled": false}},
            "pack_rules": {U1: {"pack": "core", "rule_id": "x", "action": "block"}},
            "rules": {
                U1: {"hook": "connect", "action": "block", "description": "no ssh",
                     "process": {"unit": "a.service"},
                     "target": {"net": {"cidr": "10.0.0.0/8", "ports": [22]}}},
                U2: {"enabled": false, "hook": "exec", "target": "any"}
            },
            "retention_days": 7, "max_rows": 5000
        }))
        .unwrap();
        let c = config(&d).unwrap();
        assert!(c.enabled);
        assert_eq!((c.retention_days, c.max_rows), (7, 5000));
        assert_eq!(
            c.packs,
            [PackToggle {
                name: "core".into(),
                enabled: false
            }]
        );
        assert_eq!(c.pack_rules[0].action, Some(Action::Block));
        assert_eq!(c.pack_rules[0].enabled, None);
        assert_eq!(c.rules.len(), 1, "disabled rules are left out");
        let r = &c.rules[0];
        assert_eq!(r.id, U1);
        assert_eq!((r.hook, r.action), (Hook::Connect, Action::Block));
        assert_eq!(r.process.unit.as_deref(), Some("a.service"));
        assert_eq!(
            r.target,
            Target::Net {
                cidr: "10.0.0.0/8".parse().unwrap(),
                ports: vec![22]
            }
        );
    }

    #[test]
    fn none_when_disabled() {
        let mut d = Document::factory();
        assert!(config(&d).is_some(), "on by default");
        d.guard.enabled = false;
        assert!(config(&d).is_none());
    }
}
