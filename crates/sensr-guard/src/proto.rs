//! The control protocol: JSON lines over [`crate::config::SOCKET`].

use serde::{Deserialize, Serialize};

use crate::rule::Action;

/// A request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Report status.
    Status,
    /// Re-read the configuration.
    Reload,
    /// Turn the kill switch on or off.
    KillSwitch {
        /// The new state.
        on: bool,
    },
    /// Fetch the pack index, install any newer pack that verifies, reload.
    CheckPacks,
}

/// A reply (adjacently tagged: `{"op":"status","data":{..}}`, since an
/// internal tag cannot carry the bare string of `Error`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", content = "data", rename_all = "snake_case")]
pub enum Reply {
    /// Done.
    Ok,
    /// The status.
    Status(StatusView),
    /// The outcome of [`Request::CheckPacks`], per pack.
    Packs(Vec<PackCheck>),
    /// Failed, with the reason.
    Error(String),
}

/// Where a pack came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackSource {
    /// Built into the image.
    Builtin,
    /// Delivered with a signature.
    Signed,
}

/// One pack's outcome of [`Request::CheckPacks`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackCheck {
    /// Pack name.
    pub name: String,
    /// The version that was in use before the check (`None`: none).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    /// The version the index offers (`None`: not in the index).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available: Option<String>,
    /// Whether the offered version was installed.
    pub installed: bool,
    /// Why it was not, when it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One program of a pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramView {
    /// Program name, e.g. `guard_connect`.
    pub name: String,
    /// LSM hook, e.g. `socket_connect`.
    pub hook: String,
    /// Whether it is attached.
    pub attached: bool,
    /// Why not, when it is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A loaded (or refused) pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackStatus {
    /// Pack name.
    pub name: String,
    /// Pack version.
    pub version: String,
    /// Where it came from.
    pub source: PackSource,
    /// Whether its signature (or built-in trust) checked out.
    pub verified: bool,
    /// Whether it is loaded.
    pub active: bool,
    /// Why not, when inactive (or a note, such as a fallback, when active).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Its programs (empty when not loaded).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub programs: Vec<ProgramView>,
}

/// A rule's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleStatus {
    /// Rule id.
    pub id: String,
    /// The pack whose default rule this is (`None`: an owner rule).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack: Option<String>,
    /// Its slot in the pack's maps (the `rule_id` of its events), while
    /// loaded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<u32>,
    /// Alert or block.
    pub action: Action,
    /// Whether it is enforced now.
    pub active: bool,
    /// Why not, when inactive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Matches so far.
    pub hits: u64,
}

/// The daemon's status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusView {
    /// Whether programs are loaded.
    pub running: bool,
    /// Whether every loaded pack holds the configured rules. False after a
    /// failed apply (the changed rules are left disabled: fail open) or
    /// while nothing is loaded.
    pub enforcing: bool,
    /// Why not enforcing, or what is degraded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether the kill switch is on (alerts only).
    pub kill_switch: bool,
    /// The kernel lockdown mode.
    pub lockdown: String,
    /// Packs.
    pub packs: Vec<PackStatus>,
    /// Rules.
    pub rules: Vec<RuleStatus>,
    /// Events the kernel ring buffer had no room for.
    pub dropped_kernel: u64,
    /// Events dropped by the userspace rate cap or pending bound.
    pub dropped_rate: u64,
    /// Blocked events lost to the pending bound.
    pub dropped_blocked: u64,
    /// Whether boot-complete.target was reached (module-load alerts are
    /// recorded only after it).
    pub boot_complete: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn requests_are_op_tagged() {
        assert_eq!(
            serde_json::to_value(Request::Status).unwrap(),
            json!({"op": "status"})
        );
        assert_eq!(
            serde_json::to_value(Request::KillSwitch { on: true }).unwrap(),
            json!({"op": "kill_switch", "on": true})
        );
        assert_eq!(
            serde_json::to_value(Request::CheckPacks).unwrap(),
            json!({"op": "check_packs"})
        );
        for r in [
            Request::Status,
            Request::Reload,
            Request::KillSwitch { on: false },
            Request::CheckPacks,
        ] {
            let s = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), r);
        }
    }

    #[test]
    fn replies_round_trip() {
        let view = StatusView {
            running: true,
            enforcing: false,
            reason: Some("apply failed".into()),
            kill_switch: false,
            lockdown: "none".into(),
            packs: vec![PackStatus {
                name: "core".into(),
                version: "1".into(),
                source: PackSource::Builtin,
                verified: true,
                active: false,
                reason: Some("off".into()),
                programs: vec![ProgramView {
                    name: "guard_connect".into(),
                    hook: "socket_connect".into(),
                    attached: false,
                    reason: Some("verifier".into()),
                }],
            }],
            rules: vec![RuleStatus {
                id: "r".into(),
                pack: Some("core".into()),
                slot: Some(0),
                action: Action::Alert,
                active: true,
                reason: None,
                hits: 3,
            }],
            dropped_kernel: 1,
            dropped_rate: 2,
            dropped_blocked: 3,
            boot_complete: true,
        };
        let checks = vec![PackCheck {
            name: "core".into(),
            current: Some("1.0.0".into()),
            available: Some("1.1.0".into()),
            installed: false,
            error: Some("bad signature".into()),
        }];
        assert_eq!(
            serde_json::to_value(&view).unwrap()["enforcing"],
            json!(false)
        );
        for r in [
            Reply::Ok,
            Reply::Status(view),
            Reply::Packs(checks),
            Reply::Error("no".into()),
        ] {
            let s = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<Reply>(&s).unwrap(), r, "{s}");
        }
        assert_eq!(
            serde_json::to_value(Reply::Ok).unwrap(),
            json!({"op": "ok"})
        );
        assert_eq!(
            serde_json::to_value(Reply::Error("no".into())).unwrap(),
            json!({"op": "error", "data": "no"})
        );
    }
}
