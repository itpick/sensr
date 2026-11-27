//! The daemon's configuration, rendered by sensr-apply from `guard`.

use serde::{Deserialize, Serialize};

use crate::rule::{Action, Rule};

/// The rendered configuration file.
pub const CONFIG_PATH: &str = "/run/sensr/guard/guard.json";
/// The daemon's state directory.
pub const STATE_DIR: &str = "/var/lib/sensr-guard";
/// The event database, inside [`STATE_DIR`].
pub const EVENTS_DB: &str = "events.db";
/// The control socket.
pub const SOCKET: &str = "/run/sensr-guard/guard.sock";
/// While this file exists nothing blocks.
pub const KILL_SWITCH: &str = "/boot/firmware/sensr/guard-off";
/// The signed packs' index (`guard-packs.json`), by default.
pub const PACK_INDEX: &str =
    "https://github.com/itpick/sensr/releases/latest/download/guard-packs.json";
/// The public keys packs are verified against, in the image.
pub const KEYS_DIR: &str = "/run/current-system/sw/share/sensr-guard/keys";
/// Packs built into the image.
pub const BUILTIN_PACKS: &str = "/run/current-system/sw/share/sensr-guard/packs";

/// A pack switched on or off by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackToggle {
    /// Pack name.
    pub name: String,
    /// Whether the pack is loaded.
    pub enabled: bool,
}

/// An owner override of one of a pack's default rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackRuleOverride {
    /// Pack name.
    pub pack: String,
    /// The pack rule's id.
    pub rule_id: String,
    /// Switch the rule on or off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Change the rule's action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
}

/// What the daemon runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Master switch.
    pub enabled: bool,
    /// Pack toggles.
    #[serde(default)]
    pub packs: Vec<PackToggle>,
    /// Overrides of pack default rules.
    #[serde(default)]
    pub pack_rules: Vec<PackRuleOverride>,
    /// The owner's own rules.
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Days of events kept.
    pub retention_days: u16,
    /// Most event rows kept.
    pub max_rows: u32,
    /// Where [`crate::proto::Request::CheckPacks`] fetches the pack index.
    #[serde(default = "pack_index")]
    pub pack_index: String,
    /// Check for pack updates once a day.
    #[serde(default)]
    pub pack_auto_check: bool,
}

fn pack_index() -> String {
    PACK_INDEX.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{Hook, ProcessMatch, Target};

    #[test]
    fn config_round_trips_and_rejects_unknown_fields() {
        let c = Config {
            enabled: true,
            packs: vec![PackToggle {
                name: "core".into(),
                enabled: false,
            }],
            pack_rules: vec![PackRuleOverride {
                pack: "core".into(),
                rule_id: "x".into(),
                enabled: None,
                action: Some(Action::Block),
            }],
            rules: vec![Rule {
                id: "u".into(),
                enabled: true,
                description: String::new(),
                hook: Hook::Exec,
                process: ProcessMatch::default(),
                target: Target::Any,
                action: Action::Alert,
            }],
            retention_days: 30,
            max_rows: 200_000,
            pack_index: "https://example.test/guard-packs.json".into(),
            pack_auto_check: true,
        };
        let s = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<Config>(&s).unwrap(), c);
        let mut v: serde_json::Value = serde_json::from_str(&s).unwrap();
        v["bogus"] = 1.into();
        assert!(serde_json::from_value::<Config>(v).is_err());
    }

    #[test]
    fn pack_index_and_auto_check_default() {
        let c: Config =
            serde_json::from_str(r#"{"enabled":true,"retention_days":30,"max_rows":1000}"#)
                .unwrap();
        assert_eq!(
            c.pack_index,
            "https://github.com/itpick/sensr/releases/latest/download/guard-packs.json"
        );
        assert!(!c.pack_auto_check);
    }

    #[test]
    fn paths() {
        assert_eq!(CONFIG_PATH, "/run/sensr/guard/guard.json");
        assert_eq!(KILL_SWITCH, "/boot/firmware/sensr/guard-off");
        assert_eq!(EVENTS_DB, "events.db");
    }
}
