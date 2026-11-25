//! The control protocol: JSON lines over [`crate::config::SOCKET`].

use serde::{Deserialize, Serialize};

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
    /// Why not, when inactive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A rule's state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleStatus {
    /// Rule id.
    pub id: String,
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
    /// Whether the kill switch is on (alerts only).
    pub kill_switch: bool,
    /// The kernel lockdown mode.
    pub lockdown: String,
    /// Packs.
    pub packs: Vec<PackStatus>,
    /// Rules.
    pub rules: Vec<RuleStatus>,
    /// Events dropped by the rate cap.
    pub dropped: u64,
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
        for r in [
            Request::Status,
            Request::Reload,
            Request::KillSwitch { on: false },
        ] {
            let s = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<Request>(&s).unwrap(), r);
        }
    }

    #[test]
    fn replies_round_trip() {
        let view = StatusView {
            running: true,
            kill_switch: false,
            lockdown: "none".into(),
            packs: vec![PackStatus {
                name: "core".into(),
                version: "1".into(),
                source: PackSource::Builtin,
                verified: true,
                active: false,
                reason: Some("off".into()),
            }],
            rules: vec![RuleStatus {
                id: "r".into(),
                active: true,
                reason: None,
                hits: 3,
            }],
            dropped: 2,
        };
        for r in [Reply::Ok, Reply::Status(view), Reply::Error("no".into())] {
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
