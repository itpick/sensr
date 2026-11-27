//! A guard rule: which hook, which process, which target, and what to do.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// The kernel event a rule watches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hook {
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

/// Which processes a rule applies to (all set fields must match).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessMatch {
    /// Absolute path prefix of the executable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe_prefix: Option<String>,
    /// systemd unit (leaf cgroup name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

/// What the hook's subject is matched against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    /// Anything.
    Any,
    /// A path prefix.
    PathPrefix(String),
    /// A network and ports (empty: any port).
    Net {
        /// The network.
        cidr: IpNet,
        /// Ports; empty means every port.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        ports: Vec<u16>,
    },
    /// A user id.
    Uid(u32),
}

/// What happens on a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Record an event only.
    Alert,
    /// Deny the operation (and record it).
    Block,
}

/// One rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable id.
    pub id: String,
    /// Whether the rule is in force.
    pub enabled: bool,
    /// What it is for.
    #[serde(default)]
    pub description: String,
    /// The watched hook.
    pub hook: Hook,
    /// Process filter.
    #[serde(default)]
    pub process: ProcessMatch,
    /// Subject filter.
    pub target: Target,
    /// Alert or block.
    pub action: Action,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rt(r: &Rule) {
        let s = serde_json::to_string(r).unwrap();
        assert_eq!(&serde_json::from_str::<Rule>(&s).unwrap(), r, "{s}");
    }

    fn rule(target: Target) -> Rule {
        Rule {
            id: "r1".into(),
            enabled: true,
            description: "d".into(),
            hook: Hook::Connect,
            process: ProcessMatch {
                exe_prefix: Some("/usr/bin".into()),
                unit: Some("x.service".into()),
            },
            target,
            action: Action::Block,
        }
    }

    #[test]
    fn every_target_round_trips() {
        rt(&rule(Target::Any));
        rt(&rule(Target::PathPrefix("/etc".into())));
        rt(&rule(Target::Net {
            cidr: "10.0.0.0/8".parse().unwrap(),
            ports: vec![22, 443],
        }));
        rt(&rule(Target::Net {
            cidr: "2001:db8::/32".parse().unwrap(),
            ports: vec![],
        }));
        rt(&rule(Target::Uid(0)));
    }

    #[test]
    fn wire_format_is_stable() {
        let r = rule(Target::Net {
            cidr: "10.0.0.0/8".parse().unwrap(),
            ports: vec![22],
        });
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({
                "id": "r1", "enabled": true, "description": "d", "hook": "connect",
                "process": {"exe_prefix": "/usr/bin", "unit": "x.service"},
                "target": {"net": {"cidr": "10.0.0.0/8", "ports": [22]}},
                "action": "block"
            })
        );
        let any: Rule = serde_json::from_value(json!({
            "id": "a", "enabled": false, "hook": "file_write", "target": "any", "action": "alert"
        }))
        .unwrap();
        assert_eq!(any.hook, Hook::FileWrite);
        assert_eq!(any.process, ProcessMatch::default());
        assert_eq!(any.target, Target::Any);
    }

    #[test]
    fn all_hooks_use_snake_case() {
        for (h, s) in [
            (Hook::Exec, "exec"),
            (Hook::Connect, "connect"),
            (Hook::Listen, "listen"),
            (Hook::FileWrite, "file_write"),
            (Hook::Setuid, "setuid"),
            (Hook::Module, "module"),
            (Hook::Bpf, "bpf"),
        ] {
            assert_eq!(serde_json::to_value(h).unwrap(), json!(s));
        }
    }

    #[test]
    fn unknown_rule_field_rejected() {
        assert!(
            serde_json::from_value::<Rule>(json!({
                "id": "a", "enabled": true, "hook": "exec", "target": "any",
                "action": "alert", "bogus": 1
            }))
            .is_err()
        );
    }
}
