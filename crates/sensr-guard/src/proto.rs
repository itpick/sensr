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
    /// Turn the kill switch on or off. Off lets block rules block again,
    /// so it opens a confirm window ([`Reply::Pending`]): unless
    /// [`Request::Confirm`] comes in time, the kill switch turns back on.
    KillSwitch {
        /// The new state.
        on: bool,
    },
    /// Fetch the pack index, install any newer pack that verifies, reload.
    /// Block rules that a new pack version brings are held as alerts.
    CheckPacks,
    /// Keep what the pending confirm window let block.
    Confirm,
    /// Let the held block rules block, in a confirm window
    /// ([`Reply::Pending`]).
    ReleaseHeld,
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
    /// Done, and blocking again until the deadline: confirm it
    /// ([`Request::Confirm`]) or it is undone.
    Pending(PendingConfirm),
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

/// A change that lets rules block again, waiting for the owner's
/// confirmation. Unconfirmed at the deadline, it is undone: the kill switch
/// goes back on and released rules are held again. A restart of the daemon
/// undoes it too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingConfirm {
    /// When it is undone, unix seconds.
    pub deadline: u64,
    /// The window it was given, seconds.
    pub window_secs: u64,
    /// The kill switch was turned off.
    pub kill_switch_off: bool,
    /// Held block rules that block in the window.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub released: Vec<HeldRule>,
}

/// A pack's default block rule that a pack update brought: it runs as an
/// alert until the owner releases it ([`Request::ReleaseHeld`] and a
/// confirm) or sets the rule's action in `guard.pack_rules`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HeldRule {
    /// The pack.
    pub pack: String,
    /// The rule id.
    pub rule_id: String,
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
    /// A pack's block rule held as an alert (see [`HeldRule`]); `action`
    /// is then `alert`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub held: bool,
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
    /// A change waiting for confirmation, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_confirm: Option<PendingConfirm>,
    /// Block rules held as alerts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub held: Vec<HeldRule>,
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
        assert_eq!(
            serde_json::to_value(Request::Confirm).unwrap(),
            json!({"op": "confirm"})
        );
        assert_eq!(
            serde_json::to_value(Request::ReleaseHeld).unwrap(),
            json!({"op": "release_held"})
        );
        for r in [
            Request::Status,
            Request::Reload,
            Request::KillSwitch { on: false },
            Request::CheckPacks,
            Request::Confirm,
            Request::ReleaseHeld,
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
                held: true,
            }],
            dropped_kernel: 1,
            dropped_rate: 2,
            dropped_blocked: 3,
            boot_complete: true,
            pending_confirm: Some(PendingConfirm {
                deadline: 1_700_000_120,
                window_secs: 120,
                kill_switch_off: true,
                released: vec![HeldRule {
                    pack: "core".into(),
                    rule_id: "r".into(),
                }],
            }),
            held: vec![HeldRule {
                pack: "core".into(),
                rule_id: "r".into(),
            }],
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
            Reply::Pending(PendingConfirm {
                deadline: 9,
                window_secs: 120,
                kill_switch_off: true,
                released: Vec::new(),
            }),
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
