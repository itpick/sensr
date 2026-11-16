//! Typed actions: sensr's counterpart of configd's `actions.d/*.conf`.
//!
//! Upstream reads INI files whose `command:` lines become shell strings.
//! sensr registers actions in code: each one declares who may run it, whether
//! its output may be cached or is streamed, and either a typed command builder
//! or an "inline" operation the agent performs itself (apply, rollback, …).
//! Lookup follows configd's rule: the longest registered prefix of the
//! requested words is the action, the remaining words are its parameters.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::clock::Clock;
use crate::cmd::{Cmd, CmdError, Output, Runner};

/// The message configd sends for both unknown and forbidden actions. Using one
/// message for both avoids telling a caller which actions exist (T-0318).
pub const NOT_ALLOWED_OR_MISSING: &str = "Action not allowed or missing";

/// Who is asking (from `SO_PEERCRED` / the API session).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Principal {
    /// User name.
    pub user: String,
    /// Group memberships.
    pub groups: BTreeSet<String>,
}

impl Principal {
    /// A principal with the given user and groups.
    pub fn new<I, S>(user: impl Into<String>, groups: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Principal {
            user: user.into(),
            groups: groups.into_iter().map(Into::into).collect(),
        }
    }
}

/// Who may run an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    /// Any authenticated local caller (read-only status/list actions).
    Any,
    /// Members of at least one of these groups.
    Groups(&'static [&'static str]),
}

/// The group allowed to run state-changing actions.
pub const ADMIN_GROUPS: &[&str] = &["admins", "wheel"];

impl Privilege {
    fn allows(&self, who: &Principal) -> bool {
        match self {
            Privilege::Any => true,
            Privilege::Groups(gs) => gs.iter().any(|g| who.groups.contains(*g)),
        }
    }
}

/// Operations the agent performs in-process rather than by running a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum InlineOp {
    /// Render and atomically load the firewall ruleset.
    FilterReload,
    /// Re-resolve aliases and replace their set contents.
    FilterRefreshAliases,
    /// Re-render template modules (all, or the one named in the parameter).
    TemplateReload,
    /// Apply forwarding/conntrack sysctls.
    SysctlApply,
    /// Apply queueing disciplines.
    QdiscApply,
    /// Reconfigure one interface (parameter) or all.
    InterfaceReconfigure,
    /// Confirm a provisional (commit-confirm) apply.
    ApplyConfirm,
    /// Roll back to the last confirmed revision now.
    ApplyRollback,
    /// Run operator hook drop-ins for a level (parameter).
    HooksRun,
    /// List registered actions (configd `actions`).
    ListActions,
}

/// How an action is carried out.
#[derive(Debug, Clone, Copy)]
pub enum Handler {
    /// Run a typed command built from the parameters.
    Command(fn(&[&str]) -> Result<Cmd, ActionError>),
    /// Hand the operation back to the agent.
    Inline(InlineOp),
}

/// One registered action.
#[derive(Debug, Clone)]
pub struct Action {
    /// Space-separated words, e.g. `"service unbound restart"`.
    pub name: &'static str,
    /// Human description for `actions` listings.
    pub description: &'static str,
    /// Who may run it.
    pub privilege: Privilege,
    /// Cache successful output this long (configd `cache_ttl`).
    pub cache_ttl: Option<Duration>,
    /// Output is a stream (live logs, captures) rather than one reply.
    pub streaming: bool,
    /// Maximum number of parameters accepted.
    pub max_params: usize,
    /// What it does.
    pub handler: Handler,
}

/// What executing an action produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A command ran; its output (possibly from cache).
    Ran {
        /// The command's output.
        output: Output,
        /// Whether it was served from the cache.
        cached: bool,
    },
    /// The agent must perform this operation with these parameters.
    Inline(InlineOp, Vec<String>),
}

/// Action failures.
#[derive(Debug, thiserror::Error)]
pub enum ActionError {
    /// Unknown action or caller lacks the privilege (deliberately the same).
    #[error("{NOT_ALLOWED_OR_MISSING}")]
    NotAllowedOrMissing,
    /// More parameters than the action takes (configd "Parameter mismatch").
    #[error("Parameter mismatch")]
    ParameterMismatch,
    /// A parameter failed validation.
    #[error("invalid parameter {0:?}")]
    InvalidParameter(String),
    /// The command could not be run.
    #[error(transparent)]
    Cmd(#[from] CmdError),
    /// Two registrations with the same name.
    #[error("action {0:?} registered twice")]
    Duplicate(&'static str),
}

/// Action name plus parameters.
type CacheKey = (&'static str, Vec<String>);

/// The set of known actions plus their output cache.
pub struct ActionRegistry {
    actions: BTreeMap<&'static str, Action>,
    cache: Mutex<HashMap<CacheKey, (Instant, Output)>>,
}

impl std::fmt::Debug for ActionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionRegistry")
            .field("actions", &self.actions.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl Default for ActionRegistry {
    fn default() -> Self {
        Self::empty()
    }
}

impl ActionRegistry {
    /// A registry with no actions.
    pub fn empty() -> Self {
        ActionRegistry {
            actions: BTreeMap::new(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// A registry with every built-in action.
    pub fn builtin() -> Self {
        let mut r = Self::empty();
        for a in builtin_actions() {
            // Built-in names are unique by construction; a test checks it.
            let _ = r.register(a);
        }
        r
    }

    /// Add an action.
    pub fn register(&mut self, action: Action) -> Result<(), ActionError> {
        if self.actions.contains_key(action.name) {
            return Err(ActionError::Duplicate(action.name));
        }
        self.actions.insert(action.name, action);
        Ok(())
    }

    /// Number of registered actions.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// True when nothing is registered.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Every action, sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = &Action> {
        self.actions.values()
    }

    /// Resolve `words` to the action with the longest matching prefix and the
    /// remaining words (its parameters).
    pub fn find<'w>(&self, words: &'w [&'w str]) -> Option<(&Action, &'w [&'w str])> {
        (1..=words.len()).rev().find_map(|n| {
            self.actions
                .get(words[..n].join(" ").as_str())
                .map(|a| (a, &words[n..]))
        })
    }

    /// Execute `words` on behalf of `who`.
    pub fn execute(
        &self,
        words: &[&str],
        who: &Principal,
        runner: &dyn Runner,
        clock: &dyn Clock,
    ) -> Result<Outcome, ActionError> {
        let (action, params) = self.find(words).ok_or(ActionError::NotAllowedOrMissing)?;
        if !action.privilege.allows(who) {
            return Err(ActionError::NotAllowedOrMissing);
        }
        if params.len() > action.max_params {
            return Err(ActionError::ParameterMismatch);
        }
        match action.handler {
            Handler::Inline(op) => Ok(Outcome::Inline(
                op,
                params.iter().map(|s| (*s).to_owned()).collect(),
            )),
            Handler::Command(build) => {
                let key = (
                    action.name,
                    params.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
                );
                if let Some(ttl) = action.cache_ttl {
                    let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
                    if let Some((at, out)) = cache.get(&key)
                        && clock.now().saturating_duration_since(*at) < ttl
                    {
                        return Ok(Outcome::Ran {
                            output: out.clone(),
                            cached: true,
                        });
                    }
                }
                let cmd = build(params)?;
                let output = runner.run(&cmd, None)?;
                if action.cache_ttl.is_some() && output.success() {
                    self.cache
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .insert(key, (clock.now(), output.clone()));
                }
                Ok(Outcome::Ran {
                    output,
                    cached: false,
                })
            }
        }
    }

    /// Drop cached output (after an apply changes what status commands report).
    pub fn flush_cache(&self) {
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

/// Units managed through systemd for the routing slice (as nix/modules/sensr.nix
/// defines them).
const SERVICES: &[(&str, &str)] = &[
    ("kea", "sensr-kea-dhcp4.service"),
    ("unbound", "sensr-unbound.service"),
    ("networkd", "systemd-networkd.service"),
];

fn unit_for(service: &str) -> &'static str {
    SERVICES
        .iter()
        .find(|(s, _)| *s == service)
        .map(|(_, u)| *u)
        .unwrap_or("")
}

macro_rules! service_actions {
    ($($svc:literal),*) => {
        vec![$(
            service_action(concat!("service ", $svc, " start"), |_| Ok(Cmd::new("systemctl").args(["start", unit_for($svc)]))),
            service_action(concat!("service ", $svc, " stop"), |_| Ok(Cmd::new("systemctl").args(["stop", unit_for($svc)]))),
            service_action(concat!("service ", $svc, " restart"), |_| Ok(Cmd::new("systemctl").args(["restart", unit_for($svc)]))),
            service_action(concat!("service ", $svc, " reload"), |_| Ok(Cmd::new("systemctl").args(["reload-or-restart", unit_for($svc)]))),
            Action {
                name: concat!("service ", $svc, " status"),
                description: concat!("Report whether ", $svc, " is running"),
                privilege: Privilege::Any,
                cache_ttl: None,
                streaming: false,
                max_params: 0,
                handler: Handler::Command(|_| Ok(Cmd::new("systemctl").args(["is-active", unit_for($svc)]))),
            },
        )*]
    };
}

fn service_action(name: &'static str, build: fn(&[&str]) -> Result<Cmd, ActionError>) -> Action {
    Action {
        name,
        description: "Control a service unit",
        privilege: Privilege::Groups(ADMIN_GROUPS),
        cache_ttl: None,
        streaming: false,
        max_params: 0,
        handler: Handler::Command(build),
    }
}

fn inline(
    name: &'static str,
    description: &'static str,
    op: InlineOp,
    max_params: usize,
    privilege: Privilege,
) -> Action {
    Action {
        name,
        description,
        privilege,
        cache_ttl: None,
        streaming: false,
        max_params,
        handler: Handler::Inline(op),
    }
}

/// Interface names are passed to commands as single argv entries, but are
/// still validated so a bogus name is a clear error rather than a tool error.
fn valid_ifname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn builtin_actions() -> Vec<Action> {
    let admin = Privilege::Groups(ADMIN_GROUPS);
    let mut v = vec![
        inline(
            "filter reload",
            "Render and load the firewall ruleset",
            InlineOp::FilterReload,
            0,
            admin,
        ),
        inline(
            "filter refresh_aliases",
            "Update and reload firewall aliases",
            InlineOp::FilterRefreshAliases,
            0,
            admin,
        ),
        Action {
            name: "filter list ruleset",
            description: "Show the loaded nftables ruleset (JSON)",
            privilege: Privilege::Any,
            cache_ttl: Some(Duration::from_secs(5)),
            streaming: false,
            max_params: 0,
            handler: Handler::Command(|_| Ok(Cmd::new("nft").args(["-j", "list", "ruleset"]))),
        },
        Action {
            name: "filter list counters",
            description: "Show rule counters",
            privilege: Privilege::Any,
            cache_ttl: None,
            streaming: false,
            max_params: 0,
            handler: Handler::Command(|_| Ok(Cmd::new("nft").args(["-j", "list", "counters"]))),
        },
        inline(
            "template reload",
            "Render template modules",
            InlineOp::TemplateReload,
            1,
            admin,
        ),
        inline(
            "system sysctl apply",
            "Apply kernel tunables",
            InlineOp::SysctlApply,
            0,
            admin,
        ),
        inline(
            "system qdisc apply",
            "Apply queueing disciplines",
            InlineOp::QdiscApply,
            0,
            admin,
        ),
        inline(
            "interface reconfigure",
            "Reconfigure interfaces",
            InlineOp::InterfaceReconfigure,
            1,
            admin,
        ),
        Action {
            name: "interface list addresses",
            description: "Show interface addresses (JSON)",
            privilege: Privilege::Any,
            cache_ttl: Some(Duration::from_secs(2)),
            streaming: false,
            max_params: 1,
            handler: Handler::Command(|p| {
                let cmd = Cmd::new("ip").args(["-j", "address", "show"]);
                match p.first() {
                    None => Ok(cmd),
                    Some(i) if valid_ifname(i) => Ok(cmd.args(["dev", i])),
                    Some(i) => Err(ActionError::InvalidParameter((*i).to_owned())),
                }
            }),
        },
        Action {
            name: "interface routes list",
            description: "Show the routing table (JSON)",
            privilege: Privilege::Any,
            cache_ttl: None,
            streaming: false,
            max_params: 0,
            handler: Handler::Command(|_| Ok(Cmd::new("ip").args(["-j", "route", "show"]))),
        },
        Action {
            name: "wireguard show",
            description: "Show WireGuard tunnel status",
            privilege: admin,
            cache_ttl: None,
            streaming: false,
            max_params: 1,
            handler: Handler::Command(|p| {
                let cmd = Cmd::new("wg").arg("show");
                match p.first() {
                    None => Ok(cmd.arg("all").arg("dump")),
                    Some(i) if valid_ifname(i) => Ok(cmd.args([*i, "dump"])),
                    Some(i) => Err(ActionError::InvalidParameter((*i).to_owned())),
                }
            }),
        },
        inline(
            "apply confirm",
            "Confirm a provisional apply",
            InlineOp::ApplyConfirm,
            0,
            admin,
        ),
        inline(
            "apply rollback",
            "Revert to the last confirmed revision",
            InlineOp::ApplyRollback,
            0,
            admin,
        ),
        inline(
            "hooks run",
            "Run operator hooks for a level",
            InlineOp::HooksRun,
            1,
            admin,
        ),
        inline(
            "configd actions",
            "List registered actions",
            InlineOp::ListActions,
            0,
            Privilege::Any,
        ),
    ];
    v.extend(service_actions!("kea", "unbound", "networkd"));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;
    use crate::cmd::FakeRunner;

    fn admin() -> Principal {
        Principal::new("root", ["admins"])
    }

    #[test]
    fn unknown_action_error_t0318() {
        let r = ActionRegistry::builtin();
        let err = r
            .execute(&["xxxxxx"], &admin(), &FakeRunner::new(), &FakeClock::new())
            .unwrap_err();
        assert!(matches!(err, ActionError::NotAllowedOrMissing));
        assert_eq!(err.to_string(), "Action not allowed or missing");
    }

    #[test]
    fn forbidden_action_reports_same_error_as_unknown() {
        let r = ActionRegistry::builtin();
        let nobody = Principal::new("www", ["www"]);
        let err = r
            .execute(
                &["filter", "reload"],
                &nobody,
                &FakeRunner::new(),
                &FakeClock::new(),
            )
            .unwrap_err();
        assert_eq!(err.to_string(), NOT_ALLOWED_OR_MISSING);
    }

    #[test]
    fn registry_lists_all_builtin_actions_t0319() {
        let r = ActionRegistry::builtin();
        assert!(r.len() > 10, "only {} actions", r.len());
        assert_eq!(r.len(), builtin_actions().len(), "duplicate builtin names");
        let names: Vec<_> = r.iter().map(|a| a.name).collect();
        for want in [
            "filter reload",
            "service kea restart",
            "service unbound status",
            "apply confirm",
            "apply rollback",
        ] {
            assert!(names.contains(&want), "missing {want}");
        }
    }

    #[test]
    fn longest_prefix_wins_and_rest_are_params() {
        let r = ActionRegistry::builtin();
        let words = ["interface", "list", "addresses", "eth0"];
        let (a, params) = r.find(&words).unwrap();
        assert_eq!(a.name, "interface list addresses");
        assert_eq!(params, ["eth0"]);
    }

    #[test]
    fn command_actions_build_typed_commands() {
        let r = ActionRegistry::builtin();
        let run = FakeRunner::new();
        r.execute(
            &["service", "unbound", "restart"],
            &admin(),
            &run,
            &FakeClock::new(),
        )
        .unwrap();
        r.execute(
            &["interface", "list", "addresses", "eth0"],
            &admin(),
            &run,
            &FakeClock::new(),
        )
        .unwrap();
        assert_eq!(
            run.call_lines(),
            [
                "systemctl 'restart' 'sensr-unbound.service'",
                "ip '-j' 'address' 'show' 'dev' 'eth0'"
            ]
        );
    }

    #[test]
    fn parameters_are_validated_and_counted() {
        let r = ActionRegistry::builtin();
        let run = FakeRunner::new();
        let c = FakeClock::new();
        let bad = r.execute(&["wireguard", "show", "wg0; rm -rf /"], &admin(), &run, &c);
        assert!(matches!(bad, Err(ActionError::InvalidParameter(_))));
        let many = r.execute(&["filter", "reload", "a"], &admin(), &run, &c);
        assert!(matches!(many, Err(ActionError::ParameterMismatch)));
        assert!(run.calls().is_empty());
    }

    #[test]
    fn inline_actions_return_to_agent() {
        let r = ActionRegistry::builtin();
        let out = r
            .execute(
                &["template", "reload", "unbound"],
                &admin(),
                &FakeRunner::new(),
                &FakeClock::new(),
            )
            .unwrap();
        assert_eq!(
            out,
            Outcome::Inline(InlineOp::TemplateReload, vec!["unbound".into()])
        );
    }

    #[test]
    fn cache_ttl_serves_cached_output_until_expiry() {
        let r = ActionRegistry::builtin();
        let run = FakeRunner::new();
        let clock = FakeClock::new();
        let w = ["filter", "list", "ruleset"];
        let first = r.execute(&w, &admin(), &run, &clock).unwrap();
        assert!(matches!(first, Outcome::Ran { cached: false, .. }));
        let second = r.execute(&w, &admin(), &run, &clock).unwrap();
        assert!(matches!(second, Outcome::Ran { cached: true, .. }));
        clock.advance(Duration::from_secs(6));
        let third = r.execute(&w, &admin(), &run, &clock).unwrap();
        assert!(matches!(third, Outcome::Ran { cached: false, .. }));
        assert_eq!(run.calls().len(), 2);
    }

    #[test]
    fn duplicate_registration_is_rejected() {
        let mut r = ActionRegistry::builtin();
        let dup = builtin_actions().remove(0);
        assert!(matches!(r.register(dup), Err(ActionError::Duplicate(_))));
    }
}
