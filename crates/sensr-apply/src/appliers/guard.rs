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
        pack_index: g.pack_index.clone(),
        pack_auto_check: g.pack_auto_check,
    })
}

/// What the daemon's compiler refuses in the owner's rules, as (path,
/// message) pairs: a hook/target mismatch, a unit name over 63 bytes, a
/// path with `.`/`..` components or too long for the maps, the reserved uid
/// 4294967295, too many rules. The daemon would drop every owner rule on
/// such a configuration, so the agent refuses it up front (staging treats
/// these as validation problems).
pub fn rule_problems(doc: &Document) -> Vec<(String, String)> {
    let Some(cfg) = config(doc) else {
        return Vec::new();
    };
    let words = |e: &sensr_guard::compile::CompileError, id: &str| {
        let text = e.to_string();
        let text = text
            .strip_prefix(&format!("rule {id}: "))
            .unwrap_or(&text)
            .to_owned();
        format!("sensr-guard cannot compile this rule: {text}.")
    };
    let mut out: Vec<(String, String)> = cfg
        .rules
        .iter()
        .filter_map(|r| {
            sensr_guard::compile::compile(std::slice::from_ref(r))
                .err()
                .map(|e| (format!("guard.rules.{}", r.id), words(&e, &r.id)))
        })
        .collect();
    if out.is_empty()
        && let Err(e) = sensr_guard::compile::compile(&cfg.rules)
    {
        out.push(("guard.rules".into(), words(&e, "")));
    }
    out
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
            "retention_days": 7, "max_rows": 5000,
            "pack_index": "https://mirror.example/guard-packs.json", "pack_auto_check": true
        }))
        .unwrap();
        let c = config(&d).unwrap();
        assert!(c.enabled);
        assert_eq!((c.retention_days, c.max_rows), (7, 5000));
        assert_eq!(c.pack_index, "https://mirror.example/guard-packs.json");
        assert!(c.pack_auto_check);
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

    fn with_rule(rule: serde_json::Value) -> Document {
        let mut d = Document::factory();
        d.guard = serde_json::from_value(json!({"rules": {U1: rule}})).unwrap();
        d
    }

    #[test]
    fn rules_the_daemon_cannot_compile_are_problems() {
        let long = format!("/{}", "a".repeat(300));
        for (rule, what) in [
            (
                json!({"hook": "connect", "target": {"path_prefix": "/etc"}}),
                "does not fit",
            ),
            (
                json!({"hook": "exec", "process": {"unit": "u".repeat(64)}, "target": "any"}),
                "unit",
            ),
            (
                json!({"hook": "file_write", "target": {"path_prefix": "/etc/../root"}}),
                "absolute path",
            ),
            (
                json!({"hook": "exec", "process": {"exe_prefix": "/usr/./bin"}, "target": "any"}),
                "absolute path",
            ),
            (
                json!({"hook": "file_write", "target": {"path_prefix": long}}),
                "too long",
            ),
            (
                json!({"hook": "setuid", "target": {"uid": 4294967295u32}}),
                "reserved",
            ),
        ] {
            let p = rule_problems(&with_rule(rule.clone()));
            assert_eq!(p.len(), 1, "{rule}: {p:?}");
            assert_eq!(p[0].0, format!("guard.rules.{U1}"), "{rule}");
            assert!(p[0].1.contains(what), "{rule}: {}", p[0].1);
            assert!(!p[0].1.contains(U1), "the path names the rule: {}", p[0].1);
        }
    }

    #[test]
    fn rules_that_compile_and_disabled_or_off_guards_are_fine() {
        assert!(
            rule_problems(&with_rule(
                json!({"hook": "connect", "target": {"net": {"cidr": "10.0.0.0/8", "ports": [22]}}})
            ))
            .is_empty()
        );
        // left out of guard.json, so never compiled
        assert!(
            rule_problems(&with_rule(
                json!({"enabled": false, "hook": "connect", "target": {"path_prefix": "/etc"}})
            ))
            .is_empty()
        );
        let mut d = with_rule(json!({"hook": "connect", "target": {"path_prefix": "/etc"}}));
        d.guard.enabled = false;
        assert!(rule_problems(&d).is_empty());
    }

    #[test]
    fn none_when_disabled() {
        let mut d = Document::factory();
        assert!(config(&d).is_some(), "on by default");
        d.guard.enabled = false;
        assert!(config(&d).is_none());
    }
}
