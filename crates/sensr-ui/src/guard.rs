//! Services › Runtime Guard: the status of `sensr-guard`, the rules (the owner's and the
//! packs'), the events it recorded and its packs.
//!
//! The page is server-rendered with plain forms that come back to `/ui/guard` with codes
//! only (see [`GuardQuery`]): no island code, so the browser bundle needs none of this. On
//! the server, status and the switches go through the daemon's control socket and events
//! are read from the database it writes ([`crate::api::Backend::guard_status`],
//! [`crate::api::Backend::guard_events`]). While the daemon is down the page still lists
//! the configured rules, every one inactive.
//!
//! Executable paths, targets and units come from the processes the guard watched: views
//! carry them as plain text, and the page renders them only as text.

use crate::api::FieldError;
use crate::form::{FieldKind as K, FieldSpec as F, FormModel};
use serde::{Deserialize, Serialize};

/// What the page says while the daemon's socket cannot be used.
pub const NOT_RUNNING: &str = "sensr-guard is not running";
/// Shown with a Block choice: a change that makes a rule block goes through commit-confirm.
pub const CONFIRM_WARNING: &str = "Blocking: you'll have 2 minutes to confirm";
/// Events per page.
pub const PER_PAGE: u32 = 50;

/// The hooks a rule can watch, `(value, label)`.
pub const HOOKS: &[(&str, &str)] = &[
    ("exec", "Program start (exec)"),
    ("connect", "Outbound connection"),
    ("listen", "Listening socket"),
    ("file_write", "File write"),
    ("setuid", "Privilege change (setuid)"),
    ("module", "Kernel module load"),
    ("bpf", "bpf() call"),
];

/// What a rule's target can be.
pub const TARGET_KINDS: &[(&str, &str)] = &[
    ("any", "Anything"),
    ("path_prefix", "Path prefix"),
    ("net", "Network and ports"),
    ("uid", "User id"),
];

/// What a rule does on a match.
pub const ACTIONS: &[(&str, &str)] = &[
    ("alert", "Alert: record an event"),
    ("block", "Block: deny and record"),
];

/// Event time ranges, `(value, label, seconds back; 0 for all)`.
pub const RANGES: &[(&str, &str, i64)] = &[
    ("all", "Any time", 0),
    ("1h", "Last hour", 3_600),
    ("24h", "Last 24 hours", 86_400),
    ("7d", "Last 7 days", 604_800),
];

fn label(table: &[(&'static str, &'static str)], v: &str) -> String {
    table
        .iter()
        .find(|(k, _)| *k == v)
        .map_or_else(|| v.to_owned(), |(_, l)| (*l).to_owned())
}

/// The short name of a hook for tables (`exec`, `file write`).
pub fn hook_name(h: &str) -> String {
    h.replace('_', " ")
}

/// One owner rule as the add/edit form edits it (`guard.rules.<id>`, flattened: the
/// target kind, its value and ports are separate fields).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardRuleForm {
    /// Whether the rule is in force.
    pub enabled: bool,
    /// What it is for.
    pub description: String,
    /// The watched hook ([`HOOKS`]).
    pub hook: String,
    /// Executable path prefix the rule is limited to.
    pub exe_prefix: String,
    /// systemd unit the rule is limited to.
    pub unit: String,
    /// [`TARGET_KINDS`].
    pub target_kind: String,
    /// The path prefix, network or user id.
    pub target: String,
    /// Ports of a network target, comma separated (empty: every port).
    pub ports: String,
    /// [`ACTIONS`].
    pub action: String,
}

impl Default for GuardRuleForm {
    fn default() -> Self {
        Self {
            enabled: true,
            description: String::new(),
            hook: "exec".into(),
            exe_prefix: String::new(),
            unit: String::new(),
            target_kind: "any".into(),
            target: String::new(),
            ports: String::new(),
            // new rules default to alert
            action: "alert".into(),
        }
    }
}

/// A path prefix as sensr-guard compiles it (`compile.rs` `path_keys`): absolute, no NUL,
/// no `.`, `..` or empty components (the kernel's paths are canonical, so they would
/// never match), and at most 254 bytes without the trailing slash.
fn absolute(p: &str) -> bool {
    let base = p.trim_end_matches('/');
    p.starts_with('/')
        && !p.contains('\0')
        && !base
            .split('/')
            .skip(1)
            .any(|c| matches!(c, "" | "." | ".."))
        && base.len() <= 254
}

fn is_cidr(s: &str) -> bool {
    match s.split_once('/') {
        Some((a, l)) => match (a.parse::<std::net::IpAddr>(), l.parse::<u8>()) {
            (Ok(std::net::IpAddr::V4(_)), Ok(l)) => l <= 32,
            (Ok(std::net::IpAddr::V6(_)), Ok(l)) => l <= 128,
            _ => false,
        },
        None => false,
    }
}

/// The ports of `s` (comma or space separated), or `None` if one is not 1 to 65535.
pub fn parse_ports(s: &str) -> Option<Vec<u16>> {
    s.split([',', ' '])
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| p.parse::<u16>().ok().filter(|n| *n > 0))
        .collect()
}

/// Whether a target kind fits a hook (as sensr-guard compiles rules).
fn fits(hook: &str, kind: &str) -> bool {
    match kind {
        "any" => true,
        "path_prefix" => matches!(hook, "exec" | "file_write" | "module"),
        "net" => matches!(hook, "connect" | "listen"),
        "uid" => hook == "setuid",
        _ => false,
    }
}

impl FormModel for GuardRuleForm {
    fn fields() -> &'static [F] {
        const FIELDS: &[F] = &[
            F::new("enabled", "Enabled", K::Checkbox),
            F::new("description", "Description", K::Text),
            F::new("hook", "Watch", K::Select(HOOKS)).required(),
            F::new("exe_prefix", "Program", K::Text)
                .help("Only programs under this path, e.g. /usr/bin/curl. Leave empty for any."),
            F::new("unit", "Service", K::Text)
                .help("Only this systemd unit, e.g. nginx.service. Leave empty for any."),
            F::new("target_kind", "Target", K::Select(TARGET_KINDS)).required().help(
                "A path prefix fits program starts, file writes and module loads; a network fits connections and listening sockets; a user id fits setuid.",
            ),
            F::new("target", "Path, network or user id", K::Text)
                .help("For example /etc/, 10.0.0.0/8 or 0. Empty for Anything."),
            F::new("ports", "Ports", K::Text)
                .help("For a network: ports separated by commas. Empty for every port."),
            F::new("action", "Action", K::Select(ACTIONS))
                .required()
                .help(CONFIRM_WARNING),
        ];
        FIELDS
    }

    fn validate(&self) -> Vec<FieldError> {
        let mut out = Vec::new();
        let target = self.target.trim();
        if !self.exe_prefix.trim().is_empty() && !absolute(self.exe_prefix.trim()) {
            out.push(FieldError::new("exe_prefix", invalid_message("exe_prefix")));
        }
        let unit = self.unit.trim();
        if !unit.is_empty()
            && (unit.len() > 63
                || !unit
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"@._:-\\".contains(&b)))
        {
            out.push(FieldError::new("unit", invalid_message("unit")));
        }
        if !fits(&self.hook, &self.target_kind) {
            out.push(FieldError::new(
                "target_kind",
                invalid_message("target_kind"),
            ));
        }
        let ok = match self.target_kind.as_str() {
            "path_prefix" => absolute(target),
            "net" => is_cidr(target),
            "uid" => target.parse::<u32>().is_ok_and(|u| u != u32::MAX),
            _ => true,
        };
        if !ok {
            out.push(FieldError::new("target", invalid_message("target")));
        }
        let ports = parse_ports(&self.ports);
        if ports.is_none() || (self.target_kind != "net" && ports.is_some_and(|p| !p.is_empty())) {
            out.push(FieldError::new("ports", invalid_message("ports")));
        }
        out
    }
}

/// The message for a rule field the form came back with as invalid (codes only travel in
/// the URL); `None` for a field the form does not have.
pub fn invalid_message(field: &str) -> &'static str {
    match field {
        "description" => "The description is too long.",
        "hook" | "action" => "Choose one of the listed options.",
        "exe_prefix" => {
            "The program must be an absolute path (start with /) without . or .. parts or double slashes, at most 254 characters."
        }
        "unit" => "Enter a systemd unit name such as nginx.service (at most 63 characters).",
        "target_kind" => {
            "This target does not fit what the rule watches: a path prefix fits program starts, file writes and module loads; a network fits connections and listening sockets; a user id fits setuid."
        }
        "target" => {
            "Check the target: a path prefix starts with / (no . or .. parts or double slashes, at most 254 characters), a network looks like 10.0.0.0/8, a user id is a number."
        }
        "ports" => "Ports are numbers from 1 to 65535 separated by commas, for a network only.",
        _ => "The rule could not be saved.",
    }
}

/// Services › Runtime Guard. Rows carry display text only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardView {
    /// The daemon's state.
    pub status: StatusRow,
    /// The caller may change rules, switches and packs.
    pub can_write: bool,
    /// Owner rules (from the configuration), then pack rules (from the daemon).
    pub rules: Vec<RuleRow>,
    /// Packs.
    pub packs: Vec<PackRow>,
    /// One page of events.
    pub events: EventsPage,
    /// A commit waiting for confirmation.
    pub confirm: Option<ConfirmRow>,
    /// The guard settings have staged changes.
    pub staged: bool,
    /// Every section with staged changes (Apply commits them all).
    pub staged_sections: Vec<String>,
    /// The caller may run Check for pack updates.
    pub can_check: bool,
    /// The owner rule being edited (`?edit=`), with its form values.
    pub edit: Option<RuleEdit>,
}

/// The daemon's state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusRow {
    /// Programs are loaded.
    pub running: bool,
    /// Every loaded pack holds the configured rules.
    pub enforcing: bool,
    /// Why not enforcing, or what is degraded.
    pub reason: Option<String>,
    /// Nothing blocks (alerts only).
    pub kill_switch: bool,
    /// The kernel lockdown mode.
    pub lockdown: String,
    /// Events the kernel ring buffer had no room for.
    pub dropped_kernel: u64,
    /// Events dropped by the rate cap.
    pub dropped_rate: u64,
    /// Blocked events that could not be recorded.
    pub dropped_blocked: u64,
    /// Why the status is unknown ([`NOT_RUNNING`] or another failure).
    pub note: Option<String>,
    /// A change the daemon let block again, waiting for confirmation.
    pub pending: Option<PendingRow>,
    /// How many pack block rules are held as alerts.
    pub held: usize,
}

/// What the daemon's own confirm window (kill switch off, released rules)
/// covers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRow {
    /// Seconds until it is undone.
    pub seconds_left: u64,
    /// The kill switch was turned off.
    pub kill_switch_off: bool,
    /// Held block rules released in the window.
    pub released: usize,
}

impl PendingRow {
    /// What the card says.
    pub fn text(&self) -> String {
        let what = match (self.kill_switch_off, self.released) {
            (true, 0) => "the kill switch turns back on".to_owned(),
            (false, n) => format!(
                "{} back to alerts",
                plural(n, "the released rule goes", "the released rules go")
            ),
            (true, n) => format!(
                "the kill switch turns back on and {} back to alerts",
                plural(n, "the released rule goes", "the released rules go")
            ),
        };
        format!(
            "Rules block again. Confirm within {} or {what}.",
            duration_words(self.seconds_left)
        )
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        one.to_owned()
    } else {
        many.to_owned()
    }
}

/// One rule in the Rules table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRow {
    /// The configuration key of an owner rule (editable); `None` for a pack rule.
    pub key: Option<String>,
    /// The pack whose default rule this is.
    pub pack: Option<String>,
    /// The description (a pack rule's id).
    pub description: String,
    /// The hook, or empty when the pack defines it.
    pub hook: String,
    /// The process filter in words (empty: any).
    pub process: String,
    /// The target in words.
    pub target: String,
    /// `alert` or `block`.
    pub action: String,
    /// Enforced now.
    pub active: bool,
    /// Why not.
    pub reason: Option<String>,
    /// Matches so far.
    pub hits: u64,
    /// How the staged rule differs from what runs: `changed` (the running version has
    /// [`RuleRow::live_action`]), `added` or `removed` (still active until applied).
    pub change: Option<String>,
    /// The running version's action, when a change alters it.
    pub live_action: Option<String>,
    /// A pack's block rule held as an alert after a pack update.
    pub held: bool,
}

impl RuleRow {
    /// The change in words, for the State column.
    pub fn change_text(&self) -> Option<String> {
        Some(match self.change.as_deref()? {
            "changed" => match &self.live_action {
                Some(a) => format!("changed — not applied yet (running: {a})"),
                None => "changed — not applied yet".to_owned(),
            },
            "removed" => "removed — still active until applied".to_owned(),
            _ => "added — not applied yet".to_owned(),
        })
    }
}

/// One pack.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackRow {
    /// Pack name.
    pub name: String,
    /// Version (empty when the daemon does not report the pack).
    pub version: String,
    /// `built in` or `signed`.
    pub source: String,
    /// The signature (or built-in trust) checked out.
    pub verified: bool,
    /// Loaded.
    pub active: bool,
    /// Why not, or a note.
    pub reason: Option<String>,
    /// Switched on in `guard.packs` (a pack not listed there is on).
    pub enabled: bool,
}

/// One page of events, newest first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsPage {
    /// The database exists (the guard has run).
    pub available: bool,
    /// The rows.
    pub rows: Vec<EventRow>,
    /// Events matching the filter.
    pub total: u64,
    /// The first row's position.
    pub offset: u32,
    /// Why the events could not be read.
    pub note: Option<String>,
}

/// One event row (a run of identical events within 10 s).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRow {
    /// `YYYY-MM-DD HH:MM:SS UTC`.
    pub time: String,
    /// The hook.
    pub hook: String,
    /// The operation was denied.
    pub blocked: bool,
    /// The rule (description or id), when known.
    pub rule: String,
    /// Executable.
    pub exe: String,
    /// Target.
    pub target: String,
    /// Unit.
    pub unit: String,
    /// Pid and uid of the first event.
    pub pid: u32,
    pub uid: u32,
    /// Events folded into this row.
    pub count: u32,
}

/// A commit on probation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfirmRow {
    /// The revision.
    pub revision: u64,
    /// Seconds until it rolls back.
    pub seconds_left: u64,
}

/// The owner rule being edited.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleEdit {
    /// Its configuration key.
    pub key: String,
    /// Form values by field path.
    pub inputs: crate::form::Inputs,
}

/// One pack's outcome of Check for pack updates, as it travels in the URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckLine {
    /// Pack name.
    pub name: String,
    /// The version before the check.
    pub current: String,
    /// The version the index offers.
    pub available: String,
    /// `installed`, `current`, `missing`, `bad_signature`, `untrusted_key`, `too_new`,
    /// `downgrade` or `failed`.
    pub code: String,
}

const CHECK_CODES: [&str; 9] = [
    "installed",
    "installed_inactive",
    "current",
    "missing",
    "bad_signature",
    "untrusted_key",
    "too_new",
    "downgrade",
    "failed",
];

fn pack_name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

/// A pack name as packs are named (`[a-z0-9_-]+`).
pub fn is_pack_name(s: &str) -> bool {
    pack_name_ok(s)
}

fn version_ok(s: &str) -> bool {
    s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))
}

/// A configuration key as the UI and agent make them (hex and hyphens).
pub fn is_key(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

impl CheckLine {
    /// `name~current~available~code`.
    pub fn encode(&self) -> String {
        format!(
            "{}~{}~{}~{}",
            self.name, self.current, self.available, self.code
        )
    }

    /// The inverse of [`CheckLine::encode`]; `None` for anything else.
    pub fn decode(s: &str) -> Option<Self> {
        let mut it = s.split('~');
        let (name, current, available, code) = (it.next()?, it.next()?, it.next()?, it.next()?);
        (it.next().is_none()
            && pack_name_ok(name)
            && version_ok(current)
            && version_ok(available)
            && CHECK_CODES.contains(&code))
        .then(|| Self {
            name: name.to_owned(),
            current: current.to_owned(),
            available: available.to_owned(),
            code: code.to_owned(),
        })
    }

    /// The line the page shows.
    pub fn message(&self) -> String {
        let (n, cur, avail) = (&self.name, &self.current, &self.available);
        let why = match self.code.as_str() {
            "installed" => {
                return if cur.is_empty() {
                    format!("{n}: {avail} installed.")
                } else {
                    format!("{n}: {avail} installed (was {cur}).")
                };
            }
            "installed_inactive" => {
                return format!("{n}: {avail} installed, but it does not run (see Packs).");
            }
            "current" => return format!("{n}: {cur} is the latest."),
            "missing" => return format!("{n}: not offered by the pack index."),
            "bad_signature" => "its signature does not verify",
            "untrusted_key" => "it is signed by a key this router does not trust",
            "too_new" => "it needs a newer sensr",
            "downgrade" => "it is older than the installed version",
            _ => "the install failed (see the sensr-guard log)",
        };
        format!("{n}: {avail} not installed: {why}.")
    }
}

/// What the Runtime Guard page was sent back with after a form post (`/ui/guard?…`), and
/// the event filter. Only codes, numbers and names that parse travel in the URL: messages
/// are rebuilt from them, so no free text is reflected (the event search box gets its own
/// text back as its value).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuardQuery {
    /// Events of this hook only.
    pub hook: Option<String>,
    /// Text in the executable, target or unit.
    pub q: String,
    /// [`RANGES`] value.
    pub range: String,
    /// First event shown.
    pub offset: u32,
    /// The owner rule to edit.
    pub edit: Option<String>,
    /// A rule was saved (and blocks).
    pub saved: bool,
    pub block: bool,
    /// A rule was deleted.
    pub deleted: bool,
    /// Rule fields that were refused.
    pub invalid: Vec<String>,
    /// The kill switch was turned on or off.
    pub kill: Option<bool>,
    /// A pack was switched (staged).
    pub pack: Option<(String, bool)>,
    /// Check for pack updates ran.
    pub checked: Option<Vec<CheckLine>>,
    /// This revision was applied, with a confirm window the agent imposed.
    pub applied: Option<u64>,
    pub imposed: bool,
    /// The imposed window, seconds.
    pub window: Option<u64>,
    /// The pending commit was confirmed.
    pub confirmed: bool,
    /// The kill switch went off in a confirm window (the daemon's).
    pub kill_pending: bool,
    /// The held block rules were released (in a confirm window).
    pub released: bool,
    /// The daemon's confirm window was confirmed.
    pub blocks_confirmed: bool,
    /// `not_running`, `forbidden`, `refused`, `nothing`, `no_rule` or another failure.
    pub error: Option<String>,
}

const FIELD_CODES: [&str; 9] = [
    "enabled",
    "description",
    "hook",
    "exe_prefix",
    "unit",
    "target_kind",
    "target",
    "ports",
    "action",
];

impl GuardQuery {
    /// Reads the query (each value through `get`).
    pub fn from_query(get: impl Fn(&str) -> Option<String>) -> Self {
        let flag = |k: &str| get(k).is_some_and(|v| v == "1");
        let q: String = get("q").unwrap_or_default().trim().to_owned();
        GuardQuery {
            hook: get("hook").filter(|h| HOOKS.iter().any(|(k, _)| k == h)),
            q: if q.chars().count() > 100 {
                String::new()
            } else {
                q
            },
            range: get("range")
                .filter(|r| RANGES.iter().any(|(k, _, _)| k == r))
                .unwrap_or_else(|| "all".to_owned()),
            offset: get("offset").and_then(|v| v.parse().ok()).unwrap_or(0),
            edit: get("edit").filter(|k| is_key(k)),
            saved: flag("saved"),
            block: flag("block"),
            deleted: flag("deleted"),
            invalid: get("invalid")
                .map(|v| {
                    v.split(',')
                        .filter(|f| FIELD_CODES.contains(f))
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            kill: get("kill").and_then(|v| match v.as_str() {
                "on" => Some(true),
                "off" => Some(false),
                _ => None,
            }),
            pack: get("pack")
                .filter(|n| pack_name_ok(n))
                .map(|n| (n, flag("pack_on"))),
            checked: get("checked").map(|v| {
                v.split(',')
                    .filter(|s| !s.is_empty())
                    .filter_map(CheckLine::decode)
                    .collect()
            }),
            applied: get("applied").and_then(|v| v.parse().ok()),
            imposed: flag("imposed"),
            window: get("window")
                .and_then(|v| v.parse().ok())
                .filter(|w| (1..=86_400).contains(w)),
            confirmed: flag("confirmed"),
            kill_pending: flag("kill_pending"),
            released: flag("released"),
            blocks_confirmed: flag("blocks_confirmed"),
            error: get("error"),
        }
    }

    /// The message to show: `(is an error, text)`.
    pub fn message(&self) -> Option<(bool, String)> {
        if let Some(e) = &self.error {
            return Some((
                true,
                match e.as_str() {
                    "not_running" => format!("{NOT_RUNNING}."),
                    "forbidden" => "You may not change the runtime guard.".to_owned(),
                    "refused" => "sensr-guard refused the change (see its log).".to_owned(),
                    "boot_file" => format!(
                        "The file {BOOT_FILE} exists: remove it from the SD card to let rules block again."
                    ),
                    "nothing" => "There is nothing to apply.".to_owned(),
                    "no_rule" => "That rule no longer exists.".to_owned(),
                    "check_failed" => {
                        "Checking for pack updates failed (see the sensr-guard log).".to_owned()
                    }
                    "confirm" | "nothing_pending" => {
                        "There is no change waiting for confirmation.".to_owned()
                    }
                    "nothing_held" => "No block rule is held.".to_owned(),
                    _ => "The change could not be made.".to_owned(),
                },
            ));
        }
        if !self.invalid.is_empty() {
            return Some((
                true,
                "The rule was not saved: check the marked fields.".into(),
            ));
        }
        if self.saved {
            return Some((
                false,
                if self.block {
                    format!(
                        "Rule saved. Apply the change to start it. {CONFIRM_WARNING} once it is applied."
                    )
                } else {
                    "Rule saved. Apply the change to start it.".to_owned()
                },
            ));
        }
        if self.deleted {
            return Some((false, "Rule deleted. Apply the change to remove it.".into()));
        }
        if let Some(on) = self.kill {
            return Some((
                false,
                if on {
                    "Kill switch on: nothing is blocked, alerts only.".to_owned()
                } else if self.kill_pending {
                    "Kill switch off: block rules are enforced again. Confirm it below, or the kill switch turns back on by itself.".to_owned()
                } else {
                    "Kill switch off: block rules are enforced again.".to_owned()
                },
            ));
        }
        if self.released {
            return Some((
                false,
                "The held block rules block now. Confirm it below, or they go back to alerts by itself.".to_owned(),
            ));
        }
        if self.blocks_confirmed {
            return Some((false, "Confirmed: rules keep blocking.".to_owned()));
        }
        if let Some((name, on)) = &self.pack {
            let state = if *on { "on" } else { "off" };
            return Some((
                false,
                format!("Pack {name} turned {state}. Apply the change for it to take effect."),
            ));
        }
        if let Some(rev) = self.applied {
            return Some((
                false,
                if self.imposed {
                    format!("Revision {rev} applied. {}.", self.confirm_heading())
                } else {
                    format!("Revision {rev} applied.")
                },
            ));
        }
        if self.confirmed {
            return Some((false, "Change confirmed: it stays.".into()));
        }
        self.checked.as_ref().map(|lines| {
            (
                false,
                if lines.is_empty() {
                    "Checked for pack updates: the index lists no packs.".to_owned()
                } else {
                    "Checked for pack updates.".to_owned()
                },
            )
        })
    }

    /// What the confirm card says after a commit the agent gave a window: from the
    /// window it reported (`window=`), else in general words.
    pub fn confirm_heading(&self) -> String {
        match self.window {
            Some(w) => format!("Blocking: you'll have {} to confirm", duration_words(w)),
            None => "Blocking: confirm the change before its window closes".to_owned(),
        }
    }

    /// The event filter as query pairs (for the paging links), at `offset`.
    pub fn filter_query(&self, offset: u32) -> String {
        let mut pairs: Vec<(&str, String)> = Vec::new();
        if let Some(h) = &self.hook {
            pairs.push(("hook", h.clone()));
        }
        if !self.q.is_empty() {
            pairs.push(("q", self.q.clone()));
        }
        if self.range != "all" {
            pairs.push(("range", self.range.clone()));
        }
        if offset > 0 {
            pairs.push(("offset", offset.to_string()));
        }
        pairs
            .iter()
            .map(|(k, v)| format!("{k}={}", crate::pages::url_encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }
}

/// The kill-switch file on the boot partition (sensr-guard's `KILL_SWITCH`).
pub const BOOT_FILE: &str = "/boot/firmware/sensr/guard-off";

/// `2 minutes`, `1 minute`, `90 seconds`.
pub fn duration_words(secs: u64) -> String {
    match (secs % 60, secs / 60) {
        (0, 1) => "1 minute".to_owned(),
        (0, m) if m > 1 => format!("{m} minutes"),
        _ if secs == 1 => "1 second".to_owned(),
        _ => format!("{secs} seconds"),
    }
}

/// The window a commit was given, seconds: from its deadline (unix seconds)
/// and the time now (`None` when it has passed).
pub fn window_left(deadline: u64, now: u64) -> Option<u64> {
    Some(deadline.saturating_sub(now)).filter(|w| *w > 0)
}

/// The hook's label for the filter.
pub fn hook_label(h: &str) -> String {
    label(HOOKS, h)
}

#[cfg(feature = "ssr")]
pub use server::*;

#[cfg(feature = "ssr")]
mod server {
    use super::*;
    use crate::form::Inputs;
    use sensr_guard::proto::{PackCheck, PackSource, StatusView};
    use sensr_guard::store::StoredEvent;
    use serde_json::{Map, Value, json};
    use std::collections::HashMap;

    fn s(v: &Value, k: &str) -> String {
        v.get(k)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }

    /// The target of a stored rule (`"any"`, `{"path_prefix": p}`, `{"net": {cidr, ports}}`,
    /// `{"uid": n}`) as `(kind, value, ports)`.
    pub fn target_parts(t: &Value) -> (String, String, String) {
        match t {
            Value::String(k) => (k.clone(), String::new(), String::new()),
            Value::Object(m) => match m.iter().next() {
                Some((k, Value::String(p))) => (k.clone(), p.clone(), String::new()),
                Some((k, Value::Number(n))) => (k.clone(), n.to_string(), String::new()),
                Some((k, Value::Object(net))) => (
                    k.clone(),
                    net.get("cidr")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    net.get("ports")
                        .and_then(Value::as_array)
                        .map(|p| {
                            p.iter()
                                .map(|x| x.to_string())
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default(),
                ),
                _ => ("any".into(), String::new(), String::new()),
            },
            _ => ("any".into(), String::new(), String::new()),
        }
    }

    /// The target in words: `anything`, `/etc/…`, `10.0.0.0/8 port 22, 443`, `uid 0`.
    pub fn target_text(t: &Value) -> String {
        let (kind, v, ports) = target_parts(t);
        match kind.as_str() {
            "path_prefix" => format!("{v}…"),
            "net" if ports.is_empty() => v,
            "net" => format!("{v} port {ports}"),
            "uid" => format!("uid {v}"),
            _ => "anything".to_owned(),
        }
    }

    /// The process filter in words (`/usr/bin/curl…, in nginx.service`; empty for any).
    pub fn process_text(rule: &Value) -> String {
        let p = rule.get("process").cloned().unwrap_or(Value::Null);
        let exe = s(&p, "exe_prefix");
        let unit = s(&p, "unit");
        match (exe.is_empty(), unit.is_empty()) {
            (true, true) => String::new(),
            (false, true) => format!("{exe}…"),
            (true, false) => format!("in {unit}"),
            (false, false) => format!("{exe}…, in {unit}"),
        }
    }

    /// The form values of a stored rule.
    pub fn rule_inputs(rule: &Value) -> Inputs {
        let (kind, target, ports) =
            target_parts(rule.get("target").unwrap_or(&Value::String("any".into())));
        let p = rule.get("process").cloned().unwrap_or(Value::Null);
        let pairs = [
            (
                "enabled",
                rule.get("enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(true)
                    .to_string(),
            ),
            ("description", s(rule, "description")),
            ("hook", s(rule, "hook")),
            ("exe_prefix", s(&p, "exe_prefix")),
            ("unit", s(&p, "unit")),
            ("target_kind", kind),
            ("target", target),
            ("ports", ports),
            ("action", {
                let a = s(rule, "action");
                if a.is_empty() { "alert".into() } else { a }
            }),
        ];
        pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
    }

    /// The stored rule (schema shape) for a validated form.
    pub fn rule_value(f: &GuardRuleForm) -> Value {
        let target = f.target.trim();
        let target = match f.target_kind.as_str() {
            "path_prefix" => json!({"path_prefix": target}),
            "net" => {
                let ports = parse_ports(&f.ports).unwrap_or_default();
                if ports.is_empty() {
                    json!({"net": {"cidr": target}})
                } else {
                    json!({"net": {"cidr": target, "ports": ports}})
                }
            }
            "uid" => json!({"uid": target.parse::<u32>().unwrap_or(0)}),
            _ => json!("any"),
        };
        let mut process = Map::new();
        for (k, v) in [("exe_prefix", &f.exe_prefix), ("unit", &f.unit)] {
            if !v.trim().is_empty() {
                process.insert(k.into(), Value::String(v.trim().to_owned()));
            }
        }
        json!({
            "enabled": f.enabled,
            "description": f.description.trim(),
            "hook": f.hook,
            "process": process,
            "target": target,
            "action": f.action,
        })
    }

    /// The form field a backend validation path (`guard.rules.<key>.<field>…`) belongs to.
    pub fn field_of(path: &str) -> &'static str {
        let rest = path
            .strip_prefix("guard.rules.")
            .and_then(|r| r.split_once('.'))
            .map_or("", |(_, f)| f);
        match rest.split('.').next().unwrap_or("") {
            "process" if rest.ends_with("unit") => "unit",
            "process" => "exe_prefix",
            "target" => "target",
            "hook" => "hook",
            "action" => "action",
            "description" => "description",
            _ => "",
        }
    }

    fn action_name(a: sensr_guard::rule::Action) -> String {
        match a {
            sensr_guard::rule::Action::Block => "block".to_owned(),
            sensr_guard::rule::Action::Alert => "alert".to_owned(),
        }
    }

    /// The Rules table: the configured owner rules (`rules`, the staged `guard.rules` map)
    /// joined with the daemon's state, then owner rules still running that the staged
    /// configuration removes, then the packs' rules. `head` is the applied `guard.rules`:
    /// a staged rule that differs from it is marked changed (its state, hits and, when it
    /// differs, action are the running version's). Without a status (the daemon is down)
    /// every owner rule is inactive.
    pub fn rule_rows(rules: &Value, head: &Value, status: Option<&StatusView>) -> Vec<RuleRow> {
        let live: HashMap<&str, &sensr_guard::proto::RuleStatus> = status
            .map(|s| {
                s.rules
                    .iter()
                    .filter(|r| r.pack.is_none())
                    .map(|r| (r.id.as_str(), r))
                    .collect()
            })
            .unwrap_or_default();
        let staged = rules.as_object().cloned().unwrap_or_default();
        let row = |key: &str, r: &Value| RuleRow {
            key: Some(key.to_owned()),
            description: s(r, "description"),
            hook: s(r, "hook"),
            process: process_text(r),
            target: target_text(r.get("target").unwrap_or(&Value::Null)),
            action: if s(r, "action") == "block" {
                "block".to_owned()
            } else {
                "alert".to_owned()
            },
            ..RuleRow::default()
        };
        let mut out: Vec<RuleRow> = staged
            .iter()
            .map(|(key, r)| {
                let enabled = r.get("enabled").and_then(Value::as_bool).unwrap_or(true);
                let changed = head.get(key).is_some_and(|h| h != r);
                let l = live.get(key.as_str());
                let (active, reason, hits) = match (status, l) {
                    (None, _) => (false, Some(NOT_RUNNING.to_owned()), 0),
                    (Some(_), Some(l)) => (l.active, l.reason.clone(), l.hits),
                    (Some(_), None) if !enabled => (false, Some("turned off".to_owned()), 0),
                    (Some(_), None) => (
                        false,
                        Some("not applied yet: apply the change to start it".to_owned()),
                        0,
                    ),
                };
                let mut row = row(key, r);
                row.live_action = l
                    .map(|l| action_name(l.action))
                    .filter(|a| changed && *a != row.action);
                row.change = changed.then(|| "changed".to_owned());
                RuleRow {
                    active,
                    reason,
                    hits,
                    ..row
                }
            })
            .collect();
        // removed from the staged configuration, still running until applied
        for (key, h) in head.as_object().into_iter().flatten() {
            if staged.contains_key(key) {
                continue;
            }
            if let Some(l) = live.get(key.as_str()) {
                out.push(RuleRow {
                    key: None,
                    action: action_name(l.action),
                    active: l.active,
                    reason: l.reason.clone(),
                    hits: l.hits,
                    change: Some("removed".to_owned()),
                    ..row(key, h)
                });
            }
        }
        out.extend(
            status
                .into_iter()
                .flat_map(|s| s.rules.iter())
                .filter(|r| r.pack.is_some())
                .map(|r| RuleRow {
                    key: None,
                    pack: r.pack.clone(),
                    description: r.id.clone(),
                    action: action_name(r.action),
                    active: r.active,
                    reason: r.reason.clone(),
                    hits: r.hits,
                    held: r.held,
                    ..RuleRow::default()
                }),
        );
        out
    }

    /// Whether `packs` (the `guard.packs` map) switches `name` on (unlisted: on).
    pub fn pack_enabled(packs: &Value, name: &str) -> bool {
        packs
            .as_object()
            .into_iter()
            .flatten()
            .find(|(_, p)| s(p, "name") == name)
            .is_none_or(|(_, p)| p.get("enabled").and_then(Value::as_bool).unwrap_or(true))
    }

    /// The Packs table: the daemon's packs, then packs the configuration names that the
    /// daemon does not report.
    pub fn pack_rows(packs: &Value, status: Option<&StatusView>) -> Vec<PackRow> {
        let mut out: Vec<PackRow> = status
            .into_iter()
            .flat_map(|s| s.packs.iter())
            .map(|p| PackRow {
                name: p.name.clone(),
                version: p.version.clone(),
                source: match p.source {
                    PackSource::Builtin => "built in".to_owned(),
                    PackSource::Signed => "signed".to_owned(),
                },
                verified: p.verified,
                active: p.active,
                reason: p.reason.clone(),
                enabled: pack_enabled(packs, &p.name),
            })
            .collect();
        for p in packs.as_object().into_iter().flatten().map(|(_, p)| p) {
            let name = s(p, "name");
            if name.is_empty() || out.iter().any(|r| r.name == name) {
                continue;
            }
            out.push(PackRow {
                enabled: pack_enabled(packs, &name),
                reason: Some(if status.is_none() {
                    NOT_RUNNING.to_owned()
                } else {
                    "not loaded".to_owned()
                }),
                name,
                ..PackRow::default()
            });
        }
        out
    }

    /// The status card of a daemon that answered, at `now` (unix seconds).
    pub fn status_row(v: &StatusView, now: u64) -> StatusRow {
        StatusRow {
            pending: v.pending_confirm.as_ref().map(|p| PendingRow {
                seconds_left: p.deadline.saturating_sub(now),
                kill_switch_off: p.kill_switch_off,
                released: p.released.len(),
            }),
            held: v.held.len(),
            running: v.running,
            enforcing: v.enforcing,
            reason: v.reason.clone(),
            kill_switch: v.kill_switch,
            lockdown: v.lockdown.clone(),
            dropped_kernel: v.dropped_kernel,
            dropped_rate: v.dropped_rate,
            dropped_blocked: v.dropped_blocked,
            note: None,
        }
    }

    /// Rule names by event slot: an owner rule's description (or id), a pack rule's id.
    /// A slot two packs share names no rule.
    pub fn slot_names(rules: &Value, status: Option<&StatusView>) -> HashMap<u32, String> {
        let mut m: HashMap<u32, Option<String>> = HashMap::new();
        for r in status.into_iter().flat_map(|s| s.rules.iter()) {
            if let Some(slot) = r.slot {
                let name = rules
                    .get(&r.id)
                    .filter(|_| r.pack.is_none())
                    .map(|c| s(c, "description"))
                    .filter(|d| !d.is_empty())
                    .unwrap_or_else(|| r.id.clone());
                m.entry(slot)
                    .and_modify(|e| *e = None)
                    .or_insert(Some(name));
            }
        }
        m.into_iter().filter_map(|(k, v)| Some((k, v?))).collect()
    }

    /// An event as a row.
    pub fn event_row(e: &StoredEvent, slots: &HashMap<u32, String>) -> EventRow {
        let r = &e.row;
        EventRow {
            time: crate::runtime::fmt_time(u64::try_from(r.ts).unwrap_or(0)),
            hook: r.hook.clone(),
            blocked: r.blocked,
            rule: slots.get(&r.rule_id).cloned().unwrap_or_default(),
            exe: r.exe.clone(),
            target: r.target.clone(),
            unit: r.unit.clone(),
            pid: r.pid,
            uid: r.uid,
            count: r.count,
        }
    }

    /// The store filter of `q` at `now` (unix seconds).
    pub fn filter(q: &GuardQuery, now: i64) -> sensr_guard::store::Filter {
        let back = RANGES
            .iter()
            .find(|(k, _, _)| *k == q.range)
            .map_or(0, |(_, _, s)| *s);
        sensr_guard::store::Filter {
            hook: q.hook.clone(),
            text: Some(q.q.clone()).filter(|t| !t.is_empty()),
            since_ms: (back > 0).then(|| (now - back) * 1000),
            ..Default::default()
        }
    }

    /// The URL code of one pack's check outcome.
    pub fn check_line(c: &PackCheck) -> CheckLine {
        // PackCheck carries the error as text only: match the forms sensr-guard's
        // PackError gives, anything else is a failure
        let code = match (&c.error, c.installed, &c.available) {
            (None, true, _) => "installed",
            (Some(_), true, _) => "installed_inactive",
            (None, false, None) => "missing",
            (None, false, Some(_)) => "current",
            (Some(e), false, _) => {
                if e == "pack signature does not verify" {
                    "bad_signature"
                } else if e == "pack is signed by a key that is not trusted" {
                    "untrusted_key"
                } else if e.starts_with("pack needs sensr ") {
                    "too_new"
                } else if e.starts_with("pack ") && e.contains(" is older than the installed ") {
                    "downgrade"
                } else {
                    "failed"
                }
            }
        };
        let v = |x: &Option<String>| x.clone().filter(|v| version_ok(v)).unwrap_or_default();
        let line = CheckLine {
            name: c.name.clone(),
            current: v(&c.current),
            available: v(&c.available),
            code: code.to_owned(),
        };
        if CheckLine::decode(&line.encode()).is_some() {
            return line;
        }
        // a name that would not travel: still shown, as a failure
        CheckLine {
            name: "unnamed".to_owned(),
            current: String::new(),
            available: String::new(),
            code: "failed".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::form::{Inputs, apply_inputs};

    fn inputs(pairs: &[(&str, &str)]) -> Inputs {
        pairs
            .iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    }

    fn paths(r: Result<GuardRuleForm, Vec<FieldError>>) -> Vec<String> {
        r.err()
            .unwrap_or_default()
            .into_iter()
            .map(|e| e.path)
            .collect()
    }

    #[test]
    fn new_rules_default_to_alert() {
        assert_eq!(GuardRuleForm::default().action, "alert");
        let f: GuardRuleForm = apply_inputs(&serde_json::json!({}), &inputs(&[])).unwrap();
        assert_eq!(f.action, "alert");
    }

    #[test]
    fn the_form_checks_targets_against_the_hook() {
        let ok = |p: &[(&str, &str)]| {
            apply_inputs::<GuardRuleForm>(&serde_json::json!({}), &inputs(p)).is_ok()
        };
        assert!(ok(&[
            ("hook", "exec"),
            ("target_kind", "path_prefix"),
            ("target", "/tmp/")
        ]));
        assert!(ok(&[
            ("hook", "connect"),
            ("target_kind", "net"),
            ("target", "10.0.0.0/8"),
            ("ports", "22, 443")
        ]));
        assert!(ok(&[
            ("hook", "setuid"),
            ("target_kind", "uid"),
            ("target", "0")
        ]));
        let r = apply_inputs::<GuardRuleForm>(
            &serde_json::json!({}),
            &inputs(&[
                ("hook", "exec"),
                ("target_kind", "net"),
                ("target", "10.0.0.0/8"),
            ]),
        );
        assert_eq!(paths(r), ["target_kind"]);
        let r = apply_inputs::<GuardRuleForm>(
            &serde_json::json!({}),
            &inputs(&[
                ("hook", "file_write"),
                ("target_kind", "path_prefix"),
                ("target", "etc"),
                ("exe_prefix", "bin"),
                ("unit", "bad unit"),
                ("ports", "22"),
            ]),
        );
        assert_eq!(paths(r), ["exe_prefix", "unit", "target", "ports"]);
        let r = apply_inputs::<GuardRuleForm>(
            &serde_json::json!({}),
            &inputs(&[
                ("hook", "listen"),
                ("target_kind", "net"),
                ("target", "::/0"),
                ("ports", "0, 70000"),
            ]),
        );
        assert_eq!(paths(r), ["ports"]);
        let r = apply_inputs::<GuardRuleForm>(
            &serde_json::json!({}),
            &inputs(&[("action", "explode")]),
        );
        assert_eq!(paths(r), ["action"]);
    }

    #[test]
    fn paths_are_checked_as_sensr_guard_compiles_them() {
        let target = |t: &str| {
            apply_inputs::<GuardRuleForm>(
                &serde_json::json!({}),
                &inputs(&[
                    ("hook", "exec"),
                    ("target_kind", "path_prefix"),
                    ("target", t),
                ]),
            )
            .is_ok()
        };
        let long = format!("/{}", "a".repeat(253));
        assert!(target("/") && target("/etc/") && target(&long));
        for bad in ["/etc/../x", "//etc", "/a/./b", "/a//b", "etc", "/a\0"] {
            assert!(!target(bad), "{bad:?}");
        }
        assert!(!target(&format!("{long}a")), "255 bytes");
        let exe = |e: &str| {
            apply_inputs::<GuardRuleForm>(&serde_json::json!({}), &inputs(&[("exe_prefix", e)]))
                .is_ok()
        };
        assert!(exe("/usr/bin/curl") && !exe("/usr/../bin") && !exe(&format!("{long}a")));
    }

    #[test]
    fn the_daemon_window_says_what_it_undoes() {
        let p = |k, r| PendingRow {
            seconds_left: 120,
            kill_switch_off: k,
            released: r,
        };
        assert_eq!(
            p(true, 0).text(),
            "Rules block again. Confirm within 2 minutes or the kill switch turns back on."
        );
        assert!(
            p(false, 1)
                .text()
                .ends_with("the released rule goes back to alerts.")
        );
        assert!(
            p(true, 3)
                .text()
                .contains("kill switch turns back on and the released rules go back")
        );
        let v = sensr_guard::proto::StatusView {
            running: true,
            enforcing: true,
            reason: None,
            kill_switch: false,
            lockdown: "none".into(),
            packs: Vec::new(),
            rules: Vec::new(),
            dropped_kernel: 0,
            dropped_rate: 0,
            dropped_blocked: 0,
            boot_complete: true,
            pending_confirm: Some(sensr_guard::proto::PendingConfirm {
                deadline: 1_090,
                window_secs: 120,
                kill_switch_off: true,
                released: Vec::new(),
            }),
            held: vec![sensr_guard::proto::HeldRule {
                pack: "core".into(),
                rule_id: "x".into(),
            }],
        };
        let row = status_row(&v, 1_000);
        assert_eq!(row.pending.unwrap().seconds_left, 90);
        assert_eq!(row.held, 1);
    }

    #[test]
    fn windows_read_as_words() {
        assert_eq!(duration_words(120), "2 minutes");
        assert_eq!(duration_words(60), "1 minute");
        assert_eq!(duration_words(90), "90 seconds");
        // the window comes from the deadline, not the reason's prose
        assert_eq!(window_left(1_000_120, 1_000_000), Some(120));
        assert_eq!(window_left(1_000_000, 1_000_000), None);
        assert_eq!(window_left(5, 1_000_000), None);
        let q = GuardQuery {
            window: Some(300),
            ..GuardQuery::default()
        };
        assert_eq!(
            q.confirm_heading(),
            "Blocking: you'll have 5 minutes to confirm"
        );
    }

    #[test]
    fn pack_check_lines_travel_as_codes() {
        let l = CheckLine {
            name: "core".into(),
            current: "1.0.0".into(),
            available: "1.1.0".into(),
            code: "installed".into(),
        };
        assert_eq!(l.encode(), "core~1.0.0~1.1.0~installed");
        assert_eq!(CheckLine::decode(&l.encode()), Some(l.clone()));
        assert_eq!(l.message(), "core: 1.1.0 installed (was 1.0.0).");
        for bad in [
            "core~1~2~pwned",
            "Core~1~2~installed",
            "core~1~2",
            "core~<b>~2~installed",
            "core~1~2~installed~x",
        ] {
            assert_eq!(CheckLine::decode(bad), None, "{bad}");
        }
        let l = CheckLine::decode("net~1.0.0~1.2.0~bad_signature").unwrap();
        assert_eq!(
            l.message(),
            "net: 1.2.0 not installed: its signature does not verify."
        );
        let l = CheckLine::decode("core~1.0.0~1.0.0~current").unwrap();
        assert_eq!(l.message(), "core: 1.0.0 is the latest.");
    }

    #[test]
    fn the_query_keeps_only_what_parses() {
        let pairs = [
            ("hook", "<script>"),
            ("range", "forever"),
            ("edit", "../../x"),
            ("invalid", "target,<b>,ports"),
            ("pack", "Bad Name"),
            ("kill", "maybe"),
            ("offset", "-3"),
        ];
        let q = GuardQuery::from_query(|k| pairs.iter().find(|p| p.0 == k).map(|p| p.1.to_owned()));
        assert_eq!(q.hook, None);
        assert_eq!(q.range, "all");
        assert_eq!(q.edit, None);
        assert_eq!(q.invalid, ["target", "ports"]);
        assert_eq!(q.pack, None);
        assert_eq!(q.kill, None);
        assert_eq!(q.offset, 0);
        let q = GuardQuery {
            hook: Some("exec".into()),
            q: "a b&c".into(),
            range: "24h".into(),
            ..GuardQuery::default()
        };
        assert_eq!(
            q.filter_query(50),
            "hook=exec&q=a%20b%26c&range=24h&offset=50"
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn check_outcomes_keep_every_pack() {
        use sensr_guard::proto::PackCheck;
        let c = |name: &str, installed, error: Option<&str>| PackCheck {
            name: name.into(),
            current: Some("1.0.0".into()),
            available: Some("1.1.0".into()),
            installed,
            error: error.map(Into::into),
        };
        let code = |p: PackCheck| check_line(&p).code;
        assert_eq!(code(c("core", true, None)), "installed");
        assert_eq!(
            code(c("core", true, Some("no program attached"))),
            "installed_inactive"
        );
        assert_eq!(
            code(c("core", false, Some("pack signature does not verify"))),
            "bad_signature"
        );
        assert_eq!(
            code(c(
                "core",
                false,
                Some("pack is signed by a key that is not trusted")
            )),
            "untrusted_key"
        );
        assert_eq!(
            code(c(
                "core",
                false,
                Some("pack needs sensr 2.0.0, this is 1.0.0")
            )),
            "too_new"
        );
        assert_eq!(
            code(c(
                "core",
                false,
                Some("pack 1.0.0 is older than the installed 1.1.0")
            )),
            "downgrade"
        );
        // loose words no longer pass for a known refusal
        assert_eq!(
            code(c("core", false, Some("https://x/key.pub: HTTP 404"))),
            "failed"
        );
        let l = check_line(&c("Not A Name", false, None));
        assert_eq!((l.name.as_str(), l.code.as_str()), ("unnamed", "failed"));
        assert!(CheckLine::decode(&l.encode()).is_some());
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn rules_round_trip_through_the_form() {
        let stored = serde_json::json!({
            "enabled": true, "description": "ssh out", "hook": "connect",
            "process": {"exe_prefix": "/usr/bin/ssh"},
            "target": {"net": {"cidr": "10.0.0.0/8", "ports": [22]}}, "action": "block"
        });
        let i = rule_inputs(&stored);
        assert_eq!(i["target_kind"], "net");
        assert_eq!(i["target"], "10.0.0.0/8");
        assert_eq!(i["ports"], "22");
        let f: GuardRuleForm = apply_inputs(&serde_json::json!({}), &i).unwrap();
        assert_eq!(rule_value(&f), stored);
        assert_eq!(target_text(&stored["target"]), "10.0.0.0/8 port 22");
        assert_eq!(process_text(&stored), "/usr/bin/ssh…");
        assert_eq!(target_text(&serde_json::json!("any")), "anything");
        assert_eq!(target_text(&serde_json::json!({"uid": 0})), "uid 0");
        assert_eq!(
            field_of("guard.rules.ab-1.process.exe_prefix"),
            "exe_prefix"
        );
        assert_eq!(field_of("guard.rules.ab-1.target"), "target");
    }
}
