//! Runtime guard settings (`sensr-guard`): which eBPF packs run, owner
//! overrides of a pack's default rules, and the owner's own rules.

use ipnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{check, yes};
use crate::array::ArrayField;
use crate::refs::{RefContext, Validate};
use crate::validation::{FieldPath, Validations, ValidatorKind};

/// A pack switched on or off by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuardPack {
    /// Pack name.
    pub name: String,
    /// Whether the pack is loaded.
    #[serde(default = "yes")]
    pub enabled: bool,
}

/// What a rule does on a match.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GuardAction {
    /// Record an event only.
    #[default]
    Alert,
    /// Deny the operation.
    Block,
}

/// An owner override of one of a pack's default rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuardPackRule {
    /// Pack name.
    pub pack: String,
    /// The pack rule's id.
    pub rule_id: String,
    /// Switch the rule on or off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Change the rule's action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<GuardAction>,
}

/// The kernel event a rule watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GuardHook {
    /// Program execution.
    Exec,
    /// Outbound connect.
    Connect,
    /// Listening socket.
    Listen,
    /// Write-open of a file.
    FileWrite,
    /// Privilege change by setuid.
    Setuid,
    /// Kernel module load.
    Module,
    /// The bpf() syscall.
    Bpf,
}

/// Which processes a rule applies to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuardProcess {
    /// Absolute path prefix of the executable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe_prefix: Option<String>,
    /// systemd unit (leaf cgroup name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

/// What the hook's subject is matched against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GuardTarget {
    /// Anything.
    Any,
    /// An absolute path prefix.
    PathPrefix(String),
    /// A network and ports (empty: every port).
    Net {
        /// The network.
        #[schemars(with = "String")]
        cidr: IpNet,
        /// Ports.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ports: Vec<u16>,
    },
    /// A user id.
    Uid(u32),
}

/// One owner rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GuardRule {
    /// Whether the rule is in force.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// What the rule is for.
    #[serde(default)]
    pub description: String,
    /// The watched hook.
    pub hook: GuardHook,
    /// Process filter.
    #[serde(default)]
    pub process: GuardProcess,
    /// Subject filter.
    pub target: GuardTarget,
    /// Alert (the default) or block.
    #[serde(default)]
    pub action: GuardAction,
}

/// Runtime guard settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Guard {
    /// Run the guard.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Packs switched on or off.
    #[serde(default, skip_serializing_if = "ArrayField::is_empty")]
    pub packs: ArrayField<GuardPack>,
    /// Overrides of pack default rules.
    #[serde(default, skip_serializing_if = "ArrayField::is_empty")]
    pub pack_rules: ArrayField<GuardPackRule>,
    /// The owner's own rules.
    #[serde(default, skip_serializing_if = "ArrayField::is_empty")]
    pub rules: ArrayField<GuardRule>,
    /// Days of events kept (1-365).
    #[serde(default = "retention_days")]
    pub retention_days: u16,
    /// Most event rows kept (1000-5000000).
    #[serde(default = "max_rows")]
    pub max_rows: u32,
    /// The signed packs' index (`guard-packs.json`, https).
    #[serde(default = "pack_index")]
    pub pack_index: String,
    /// Check for pack updates once a day.
    #[serde(default)]
    pub pack_auto_check: bool,
}

/// The default pack index: the latest release's `guard-packs.json`.
pub const PACK_INDEX: &str =
    "https://github.com/itpick/sensr/releases/latest/download/guard-packs.json";

fn pack_index() -> String {
    PACK_INDEX.to_owned()
}

fn retention_days() -> u16 {
    30
}
fn max_rows() -> u32 {
    200_000
}

impl Default for Guard {
    fn default() -> Self {
        Self {
            enabled: true,
            packs: ArrayField::default(),
            pack_rules: ArrayField::default(),
            rules: ArrayField::default(),
            retention_days: retention_days(),
            max_rows: max_rows(),
            pack_index: pack_index(),
            pack_auto_check: false,
        }
    }
}

impl Guard {
    /// True when nothing differs from the defaults (the section is then
    /// omitted).
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

fn absolute(p: &str) -> bool {
    p.starts_with('/')
}

impl Validate for Guard {
    fn validate(&self, _ctx: &dyn RefContext, at: &FieldPath, out: &mut Validations) {
        check::range(
            self.retention_days,
            1..=365,
            &at.join("retention_days"),
            out,
        );
        check::range(self.max_rows, 1000..=5_000_000, &at.join("max_rows"), out);
        if !self.pack_index.starts_with("https://") || self.pack_index.len() <= "https://".len() {
            out.add(
                &at.join("pack_index"),
                ValidatorKind::Callback,
                "The pack index must be an https:// URL.",
            );
        }
        let rules = at.join("rules");
        for (id, r) in &self.rules {
            let rp = rules.join(id);
            if let GuardTarget::PathPrefix(p) = &r.target
                && !absolute(p)
            {
                out.add(
                    &rp.join("target"),
                    ValidatorKind::Callback,
                    "A path prefix must be an absolute path (start with /).",
                );
            }
            if let Some(p) = &r.process.exe_prefix
                && !absolute(p)
            {
                out.add(
                    &rp.join("process").join("exe_prefix"),
                    ValidatorKind::Callback,
                    "The executable prefix must be an absolute path (start with /).",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Document;
    use serde_json::json;

    const U1: &str = "6d0de000-0000-4000-8000-000000000001";

    #[test]
    fn defaults_deserialize_from_empty_object() {
        let g: Guard = serde_json::from_str("{}").unwrap();
        assert_eq!(g, Guard::default());
        assert!(g.enabled && g.is_empty());
        assert_eq!((g.retention_days, g.max_rows), (30, 200_000));
        assert_eq!(
            g.pack_index,
            "https://github.com/itpick/sensr/releases/latest/download/guard-packs.json"
        );
        assert!(!g.pack_auto_check);
        let mut d = Document::factory();
        assert!(d.guard.is_empty() && d.validate().is_empty());
        assert!(serde_json::to_value(&d).unwrap().get("guard").is_none());
        d.guard.enabled = false;
        assert!(serde_json::to_value(&d).unwrap().get("guard").is_some());
    }

    fn doc_with_rule(rule: serde_json::Value) -> Document {
        let mut d = Document::factory();
        d.guard = serde_json::from_value(json!({ "rules": { U1: rule } })).unwrap();
        d
    }

    #[test]
    fn relative_path_prefix_fails_at_target() {
        let d = doc_with_rule(json!({"hook":"file_write","target":{"path_prefix":"etc"}}));
        let v = format!("{:?}", d.validate());
        assert!(v.contains(&format!("guard.rules.{U1}.target")), "{v}");
        let d = doc_with_rule(json!({"hook":"file_write","target":{"path_prefix":"/etc"}}));
        assert!(d.validate().is_empty());
    }

    #[test]
    fn relative_exe_prefix_fails() {
        let d =
            doc_with_rule(json!({"hook":"exec","process":{"exe_prefix":"bin/x"},"target":"any"}));
        let v = format!("{:?}", d.validate());
        assert!(
            v.contains(&format!("guard.rules.{U1}.process.exe_prefix")),
            "{v}"
        );
    }

    #[test]
    fn ranges_enforced() {
        for (k, bad, good) in [
            ("retention_days", 0, 365),
            ("retention_days", 366, 1),
            ("max_rows", 999, 1000),
            ("max_rows", 5_000_001, 5_000_000),
        ] {
            let mut d = Document::factory();
            d.guard = serde_json::from_value(json!({ k: bad })).unwrap();
            assert!(format!("{}", d.validate()).contains("between"), "{k}={bad}");
            d.guard = serde_json::from_value(json!({ k: good })).unwrap();
            assert!(d.validate().is_empty(), "{k}={good}");
        }
    }

    #[test]
    fn pack_index_must_be_https() {
        let mut d = Document::factory();
        d.guard =
            serde_json::from_value(json!({"pack_index": "http://x/guard-packs.json"})).unwrap();
        let v = format!("{:?}", d.validate());
        assert!(v.contains("guard.pack_index"), "{v}");
        d.guard = serde_json::from_value(
            json!({"pack_index": "https://mirror.example/guard-packs.json", "pack_auto_check": true}),
        )
        .unwrap();
        assert!(d.validate().is_empty());
        assert!(d.guard.pack_auto_check && !d.guard.is_empty());
    }

    #[test]
    fn new_rule_defaults_to_alert_and_round_trips() {
        let d = doc_with_rule(
            json!({"hook":"connect","target":{"net":{"cidr":"10.0.0.0/8","ports":[22]}}}),
        );
        let r = d.guard.rules.iter().next().unwrap().1;
        assert!(r.enabled);
        assert_eq!(r.action, GuardAction::Alert);
        let out = serde_json::to_value(&d.guard).unwrap();
        assert_eq!(serde_json::from_value::<Guard>(out).unwrap(), d.guard);
    }
}
