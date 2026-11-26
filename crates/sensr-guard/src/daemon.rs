//! The daemon's logic, without the kernel: which packs run, which rules go
//! where, the kill switch, reloads, pack updates and the event flow.
//!
//! The kernel is behind [`Backend`] (load a verified pack) and
//! [`LoadedPack`] (apply rules, read counters and events), so everything
//! here is unit-tested with a fake; [`kernel`] is the real one (Linux).
//!
//! # Packs and rules
//!
//! The packs are the built-in ones (`--builtin`) plus the installed ones
//! (`<state>/packs`) plus any named in `guard.packs`. A built-in pack is on
//! unless switched off; any other pack is off unless switched on. Each pack
//! that is on is resolved with [`packs::resolve`] (the installed version if
//! it still verifies, else the built-in copy; the built-in copy also wins
//! when it is at least as new) and loaded from the verified bytes. A pack that fails to resolve is inactive with the reason; one
//! that fails to load keeps the version already running (or falls back to
//! the built-in copy), so a bad update never takes protection away.
//!
//! Each loaded pack gets its own default rules with the `guard.pack_rules`
//! overrides; the owner's rules go to the first loaded pack (`core` first).
//! A pack's rules are compiled and applied to its maps with the kill switch
//! and this process's pid. If the apply fails the changed rules are left
//! disabled (fail open) and the status says `enforcing: false` with the
//! error.
//!
//! A rule is reported active only when it is enabled, applied, every
//! program its hook needs is attached, and (for a block rule) the kill
//! switch is off.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::compile::{Compiled, compile};
use crate::config::Config;
use crate::events::{Batch, BootClock, Pipeline, decode};
use crate::loader::ProgramStatus;
use crate::packs::{self, PackSource as Source, PublicKey, VerifiedPack};
use crate::proto::{PackCheck, PackSource, PackStatus, ProgramView, Reply, RuleStatus, StatusView};
use crate::rule::{Action, Hook, Rule};

/// The persisted live kill switch, inside the state directory.
pub const KILL_SWITCH_STATE: &str = "kill-switch";
/// Unix seconds of the last pack check, inside the state directory.
pub const LAST_PACK_CHECK: &str = "last-pack-check";
/// How often the automatic pack check runs.
pub const AUTO_CHECK_EVERY: Duration = Duration::from_secs(24 * 3600);
/// How often boot-complete.target is checked until it is reached.
pub const BOOT_CHECK_EVERY: Duration = Duration::from_secs(1);
/// Largest pack index accepted.
pub const MAX_INDEX: u64 = 1024 * 1024;
/// Largest pack archive accepted.
pub const MAX_ARCHIVE: u64 = 16 * 1024 * 1024;
/// Largest signature accepted.
pub const MAX_SIG: u64 = 4096;
/// The kernel's lockdown file.
pub const LOCKDOWN: &str = "/sys/kernel/security/lockdown";

/// The kernel: loads verified packs.
pub trait Backend: Send {
    /// Load and attach a pack from its verified bytes. A program that does
    /// not attach is reported in [`LoadedPack::programs`]; `Err` means
    /// nothing of the pack runs.
    fn load(&mut self, pack: &VerifiedPack) -> Result<Box<dyn LoadedPack>, String>;
    /// Whether `boot-complete.target` is active.
    fn boot_complete(&mut self) -> bool;
}

/// A loaded pack. Dropping it detaches its programs.
pub trait LoadedPack: Send {
    /// Every program and whether it is attached.
    fn programs(&self) -> Vec<ProgramStatus>;
    /// Put `c` into the maps (see [`crate::loader`]).
    fn apply(&mut self, c: &Compiled, kill_switch: bool, own_tgid: u32) -> Result<(), String>;
    /// Hits per rule id of the applied rules.
    fn hits_by_id(&self) -> Result<HashMap<String, u64>, String>;
    /// Events the ring buffer had no room for.
    fn ringbuf_dropped(&self) -> Result<u64, String>;
    /// Hand every record waiting in the ring buffer to `sink`.
    fn drain_events(&mut self, sink: &mut dyn FnMut(&[u8]));
}

/// Where the daemon finds its files.
#[derive(Debug, Clone)]
pub struct Options {
    /// The rendered configuration (`guard.json`).
    pub config: PathBuf,
    /// The state directory (installed packs, events.db, kill switch).
    pub state_dir: PathBuf,
    /// The built-in packs.
    pub builtin_dir: PathBuf,
    /// The trusted public keys (`*.pub`).
    pub keys_dir: PathBuf,
    /// While this file exists nothing blocks ([`crate::config::KILL_SWITCH`]).
    pub kill_switch_file: PathBuf,
    /// The kernel's lockdown file ([`LOCKDOWN`]).
    pub lockdown_file: PathBuf,
    /// This sensr's version (packs' `min_sensr`).
    pub sensr_version: Version,
    /// sensr-guard's own pid (never blocked, its bpf() calls ignored).
    pub own_tgid: u32,
    /// Boot time to wall time for events.
    pub clock: BootClock,
    /// The architecture pack index entries must match.
    pub arch: String,
}

/// Why the daemon does not start.
#[derive(Debug, thiserror::Error)]
pub enum StartError {
    /// Kernel lockdown forbids what the programs need.
    #[error(
        "kernel lockdown is {0}: BPF LSM programs cannot read kernel memory in this mode, so sensr-guard does not start (boot without lockdown=confidentiality)"
    )]
    Lockdown(String),
    /// The configuration could not be read.
    #[error("{0}")]
    Config(String),
}

/// The active lockdown mode in the text of the lockdown file
/// (`none integrity [confidentiality]`); `none` when nothing is bracketed.
pub fn parse_lockdown(text: &str) -> String {
    text.split_whitespace()
        .find_map(|w| w.strip_prefix('[').and_then(|w| w.strip_suffix(']')))
        .unwrap_or("none")
        .to_owned()
}

/// The lockdown mode; `none` when the kernel has no lockdown LSM.
pub fn read_lockdown(path: &Path) -> String {
    std::fs::read_to_string(path).map_or_else(|_| "none".to_owned(), |t| parse_lockdown(&t))
}

/// Read and parse the configuration.
pub fn read_config(path: &Path) -> Result<Config, String> {
    let text = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    serde_json::from_slice(&text).map_err(|e| format!("parsing {}: {e}", path.display()))
}

/// The LSM hooks whose programs a rule needs attached: its hook's, plus
/// exec and fork tracking when it matches by executable.
pub fn required_hooks(rule: &Rule) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = match rule.hook {
        Hook::Exec => vec!["bprm_check_security"],
        Hook::Connect => vec!["socket_connect"],
        Hook::Listen => vec!["socket_bind", "socket_listen"],
        Hook::FileWrite => vec!["file_open", "path_unlink", "path_rename"],
        Hook::Setuid => vec!["task_fix_setuid"],
        Hook::Module => vec!["kernel_read_file", "kernel_load_data"],
        Hook::Bpf => vec!["bpf"],
    };
    if rule.process.exe_prefix.is_some() {
        for h in ["bprm_check_security", "task_alloc"] {
            if !v.contains(&h) {
                v.push(h);
            }
        }
    }
    v
}

/// Why a rule cannot be enforced by these programs, if it cannot.
pub fn missing_program(rule: &Rule, programs: &[ProgramStatus]) -> Option<String> {
    for hook in required_hooks(rule) {
        let on_hook: Vec<_> = programs.iter().filter(|p| p.hook == hook).collect();
        if on_hook.is_empty() {
            return Some(format!("no program for the {hook} hook is loaded"));
        }
        if let Some(p) = on_hook.iter().find(|p| !p.attached) {
            return Some(format!(
                "program {} ({hook}) is not attached: {}",
                p.name,
                p.reason.as_deref().unwrap_or("unknown reason")
            ));
        }
    }
    None
}

/// A pack's default rules with the owner's overrides applied.
pub fn with_overrides(
    pack: &str,
    rules: &[Rule],
    overrides: &[crate::config::PackRuleOverride],
) -> Vec<Rule> {
    rules
        .iter()
        .map(|r| {
            let mut r = r.clone();
            for o in overrides
                .iter()
                .filter(|o| o.pack == pack && o.rule_id == r.id)
            {
                if let Some(e) = o.enabled {
                    r.enabled = e;
                }
                if let Some(a) = o.action {
                    r.action = a;
                }
            }
            r
        })
        .collect()
}

fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

fn subdirs(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().to_str().map(str::to_owned))
        .filter(|n| valid_name(n))
        .collect()
}

/// The same pack contents (a changed fallback reason alone is no reload).
fn same_pack(a: &VerifiedPack, b: &VerifiedPack) -> bool {
    a.name == b.name
        && a.version == b.version
        && a.source == b.source
        && a.manifest == b.manifest
        && a.object == b.object
        && a.rules == b.rules
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// A pack that runs.
struct Running {
    pack: VerifiedPack,
    loaded: Box<dyn LoadedPack>,
    /// A fallback or a failed update, shown with the pack.
    note: Option<String>,
    /// The rules last given to the pack, in slot order, with whether each
    /// is the pack's own (`true`) or the owner's.
    rules: Vec<(Rule, bool)>,
    /// Whether `rules` are in the maps; the error when not.
    applied: Result<(), String>,
    /// The ring buffer's dropped count at the last poll.
    last_dropped: u64,
}

enum PackState {
    Running(Box<Running>),
    Inactive {
        version: Option<String>,
        source: PackSource,
        verified: bool,
        reason: String,
    },
}

struct Pack {
    name: String,
    state: PackState,
}

/// One pack's download for [`Daemon::install_updates`].
#[derive(Debug, Clone)]
pub struct Download {
    /// Pack name.
    pub name: String,
    /// The version in use before.
    pub current: Option<Version>,
    /// What the index offers.
    pub available: Option<Version>,
    /// The archive and its signature, if a newer version was fetched; the
    /// error if fetching failed.
    pub fetched: Result<Option<(Vec<u8>, String)>, String>,
}

/// The pack index (`guard-packs.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackIndex {
    /// The packs on offer.
    pub packs: Vec<IndexEntry>,
}

/// One pack on offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    /// Pack name.
    pub name: String,
    /// Its version.
    pub version: Version,
    /// The `.tar.zst` archive.
    pub url: String,
    /// Its minisign signature.
    pub sig_url: String,
    /// The architecture it was built for (`x86_64`, `aarch64`); absent:
    /// any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
}

/// Something that GETs URLs (tests serve a local fixture).
pub trait Fetcher: Send + Sync {
    /// The body of `url` (status 200), at most `max` bytes.
    fn get(&self, url: &str, max: u64) -> Result<Vec<u8>, String>;
}

/// [`Fetcher`] over HTTP(S) with `ureq` (rustls, webpki roots).
pub struct HttpFetcher {
    agent: ureq::Agent,
}

impl Default for HttpFetcher {
    fn default() -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(120)))
            .timeout_resolve(Some(Duration::from_secs(10)))
            .timeout_connect(Some(Duration::from_secs(10)))
            .http_status_as_error(false)
            .user_agent(concat!("sensr-guard/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Self { agent }
    }
}

impl Fetcher for HttpFetcher {
    fn get(&self, url: &str, max: u64) -> Result<Vec<u8>, String> {
        let mut resp = self
            .agent
            .get(url)
            .call()
            .map_err(|e| format!("{url}: {e}"))?;
        match resp.status().as_u16() {
            200 => resp
                .body_mut()
                .with_config()
                .limit(max)
                .read_to_vec()
                .map_err(|e| format!("{url}: reading the body: {e}")),
            s => Err(format!("{url}: HTTP status {s}")),
        }
    }
}

/// Fetch the index and every newer pack among `wanted` (name, version in
/// use). Runs without the daemon's lock: it only downloads.
pub fn fetch_updates(
    index_url: &str,
    arch: &str,
    wanted: &[(String, Option<Version>)],
    fetcher: &dyn Fetcher,
) -> Result<Vec<Download>, String> {
    let body = fetcher.get(index_url, MAX_INDEX)?;
    let index: PackIndex =
        serde_json::from_slice(&body).map_err(|e| format!("the pack index: {e}"))?;
    Ok(wanted
        .iter()
        .map(|(name, current)| {
            let offer = index
                .packs
                .iter()
                .filter(|e| e.name == *name && e.arch.as_deref().is_none_or(|a| a == arch))
                .max_by(|a, b| a.version.cmp(&b.version));
            let available = offer.map(|e| e.version.clone());
            let newer = offer.filter(|e| current.as_ref().is_none_or(|c| e.version > *c));
            let fetched = match newer {
                None => Ok(None),
                Some(e) => fetcher.get(&e.url, MAX_ARCHIVE).and_then(|archive| {
                    let sig = fetcher.get(&e.sig_url, MAX_SIG)?;
                    let sig = String::from_utf8(sig)
                        .map_err(|_| format!("{}: the signature is not text", e.sig_url))?;
                    Ok(Some((archive, sig)))
                }),
            };
            Download {
                name: name.clone(),
                current: current.clone(),
                available,
                fetched,
            }
        })
        .collect())
}

/// Whether the daily check is due, given the state directory's record.
pub fn auto_check_due(state_dir: &Path, now: i64) -> bool {
    let last = std::fs::read_to_string(state_dir.join(LAST_PACK_CHECK))
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok());
    last.is_none_or(|l| now.saturating_sub(l) >= AUTO_CHECK_EVERY.as_secs() as i64 || l > now)
}

/// The whole check: what to look for (under the lock), the downloads
/// (without it), then the installs and the reload (under it again).
pub fn check_packs<B: Backend>(d: &Mutex<Daemon<B>>, fetcher: &dyn Fetcher) -> Reply {
    let lock = || d.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (url, arch, wanted) = {
        let d = lock();
        (
            d.config.pack_index.clone(),
            d.opts.arch.clone(),
            d.wanted_packs(),
        )
    };
    match fetch_updates(&url, &arch, &wanted, fetcher) {
        Ok(downloads) => Reply::Packs(lock().install_updates(downloads)),
        Err(e) => Reply::Error(format!("pack check failed: {e}")),
    }
}

/// The daemon's state.
pub struct Daemon<B: Backend> {
    opts: Options,
    backend: B,
    config: Config,
    keys: Vec<PublicKey>,
    keys_error: Option<String>,
    lockdown: String,
    kill_switch: bool,
    packs: Vec<Pack>,
    /// Why the owner's rules are not applied, when they are not.
    owner_error: Option<String>,
    pipeline: Pipeline,
    boot_complete: bool,
    last_boot_check: Option<Instant>,
    /// Ring-buffer drops of packs no longer loaded.
    dropped_kernel_base: u64,
}

impl<B: Backend> Daemon<B> {
    /// Check lockdown, read the configuration and the kill switch, load the
    /// packs and apply the rules.
    pub fn start(opts: Options, backend: B) -> Result<Self, StartError> {
        let lockdown = read_lockdown(&opts.lockdown_file);
        if lockdown == "confidentiality" {
            return Err(StartError::Lockdown(lockdown));
        }
        let config = read_config(&opts.config).map_err(StartError::Config)?;
        let kill_switch =
            opts.kill_switch_file.exists() || opts.state_dir.join(KILL_SWITCH_STATE).exists();
        let pipeline = Pipeline::new(opts.clock, Instant::now());
        let mut d = Self {
            opts,
            backend,
            owner_error: compile(&config.rules)
                .err()
                .map(|e| format!("the owner's rules are not applied: {e}")),
            config,
            keys: Vec::new(),
            keys_error: None,
            lockdown,
            kill_switch,
            packs: Vec::new(),
            pipeline,
            boot_complete: false,
            last_boot_check: None,
            dropped_kernel_base: 0,
        };
        d.load_keys();
        d.reconcile_packs();
        d.apply_all();
        Ok(d)
    }

    /// The configuration in use.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The options.
    pub fn options(&self) -> &Options {
        &self.opts
    }

    fn load_keys(&mut self) {
        match packs::load_keys(&self.opts.keys_dir) {
            Ok(k) => {
                self.keys = k;
                self.keys_error = None;
            }
            Err(e) => {
                self.keys = Vec::new();
                self.keys_error = Some(format!(
                    "keys in {}: {e}; only built-in packs load",
                    self.opts.keys_dir.display()
                ));
            }
        }
    }

    /// Re-read the configuration and re-apply. A configuration that does
    /// not parse, or owner rules that do not compile, change nothing.
    pub fn reload(&mut self) -> Result<(), String> {
        let config = read_config(&self.opts.config)?;
        if let Err(e) = compile(&config.rules) {
            return Err(format!("{e}; the running rules are kept"));
        }
        self.config = config;
        self.owner_error = None;
        self.load_keys();
        self.reconcile_packs();
        self.apply_all();
        Ok(())
    }

    /// Turn the kill switch on or off, live; it persists across restarts
    /// in the state directory. Off is refused while the kill-switch file
    /// exists (the owner put it there on purpose).
    pub fn set_kill_switch(&mut self, on: bool) -> Result<(), String> {
        let state = self.opts.state_dir.join(KILL_SWITCH_STATE);
        if on {
            std::fs::write(&state, b"on\n")
                .map_err(|e| format!("recording the kill switch in {}: {e}", state.display()))?;
        } else {
            if self.opts.kill_switch_file.exists() {
                return Err(format!(
                    "{} exists: remove it to let rules block again",
                    self.opts.kill_switch_file.display()
                ));
            }
            match std::fs::remove_file(&state) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("clearing {}: {e}", state.display())),
            }
        }
        self.kill_switch = on;
        self.apply_all();
        Ok(())
    }

    fn pack_names(&self) -> Vec<String> {
        let mut names: BTreeSet<String> = subdirs(&self.opts.builtin_dir).into_iter().collect();
        names.extend(subdirs(&self.opts.state_dir.join("packs")));
        names.extend(
            self.config
                .packs
                .iter()
                .map(|p| p.name.clone())
                .filter(|n| valid_name(n)),
        );
        let mut v: Vec<String> = names.into_iter().collect();
        // core first: the owner's rules go to the first loaded pack
        v.sort_by_key(|n| (n != "core", n.clone()));
        v
    }

    fn enabled(&self, name: &str) -> bool {
        if !self.config.enabled {
            return false;
        }
        self.config
            .packs
            .iter()
            .rev()
            .find(|p| p.name == name)
            .map_or_else(|| self.opts.builtin_dir.join(name).is_dir(), |p| p.enabled)
    }

    /// Load `vp`; on failure the pack comes back with the error.
    #[allow(clippy::result_large_err)]
    fn load_from(&mut self, vp: VerifiedPack) -> Result<Box<Running>, (VerifiedPack, String)> {
        match self.backend.load(&vp) {
            Ok(loaded) => Ok(Box::new(Running {
                note: vp.fallback_reason.clone(),
                pack: vp,
                loaded,
                rules: Vec::new(),
                applied: Ok(()),
                last_dropped: 0,
            })),
            Err(e) => Err((vp, e)),
        }
    }

    /// Bring the loaded packs in line with the configuration and the disk.
    fn reconcile_packs(&mut self) {
        let names = self.pack_names();
        let mut old: HashMap<String, Pack> = std::mem::take(&mut self.packs)
            .into_iter()
            .map(|p| (p.name.clone(), p))
            .collect();
        let mut new = Vec::new();
        for name in names {
            let prev = old.remove(&name).and_then(|p| match p.state {
                PackState::Running(r) => Some(r),
                PackState::Inactive { .. } => None,
            });
            let state = self.next_state(&name, prev);
            new.push(Pack { name, state });
        }
        for p in old.into_values() {
            self.retire(p.state);
        }
        self.packs = new;
    }

    fn retire(&mut self, state: PackState) {
        if let PackState::Running(r) = state {
            self.dropped_kernel_base += r.last_dropped;
        }
    }

    fn next_state(&mut self, name: &str, prev: Option<Box<Running>>) -> PackState {
        if !self.enabled(name) {
            let reason = if self.config.enabled {
                "switched off"
            } else {
                "the guard is off"
            };
            let state = PackState::Inactive {
                version: None,
                source: PackSource::Builtin,
                verified: false,
                reason: reason.into(),
            };
            if let Some(r) = prev {
                self.retire(PackState::Running(r));
            }
            return state;
        }
        let resolved = packs::resolve(
            name,
            &self.opts.builtin_dir,
            &self.opts.state_dir,
            &self.keys,
            &self.opts.sensr_version,
        );
        let vp = match resolved {
            // the image's own copy wins when it is at least as new (an
            // installed pack from an older release must not replace it)
            Ok(vp) if matches!(vp.source, Source::Installed(_)) => {
                match packs::read_pack_dir(&self.opts.builtin_dir.join(name)) {
                    Ok(b) if b.version >= vp.version => b,
                    _ => vp,
                }
            }
            Ok(vp) => vp,
            Err(e) => {
                if let Some(r) = prev {
                    self.retire(PackState::Running(r));
                }
                return PackState::Inactive {
                    version: None,
                    source: PackSource::Builtin,
                    verified: false,
                    reason: format!("not loaded: {e}"),
                };
            }
        };
        if let Some(mut r) = prev {
            if same_pack(&r.pack, &vp) {
                r.note = vp.fallback_reason;
                return PackState::Running(r);
            }
            // a new version: the running one stays if the new one fails
            return match self.load_from(vp) {
                Ok(n) => {
                    self.retire(PackState::Running(r));
                    PackState::Running(n)
                }
                Err((vp, e)) => {
                    r.note = Some(format!(
                        "{} {} did not load ({e}); {} keeps running",
                        name, vp.version, r.pack.version
                    ));
                    PackState::Running(r)
                }
            };
        }
        match self.load_from(vp) {
            Ok(n) => PackState::Running(n),
            Err((vp, e)) if vp.source != Source::Builtin => {
                // the installed version does not load here: the image's copy
                let why = format!("{} {} did not load ({e})", name, vp.version);
                match packs::read_pack_dir(&self.opts.builtin_dir.join(name)) {
                    Ok(mut b) => {
                        b.fallback_reason = Some(why.clone());
                        match self.load_from(b) {
                            Ok(n) => PackState::Running(n),
                            Err((b, e2)) => PackState::Inactive {
                                version: Some(b.version.to_string()),
                                source: PackSource::Builtin,
                                verified: true,
                                reason: format!(
                                    "{why}; the built-in copy did not load either ({e2})"
                                ),
                            },
                        }
                    }
                    Err(_) => PackState::Inactive {
                        version: Some(vp.version.to_string()),
                        source: PackSource::Signed,
                        verified: true,
                        reason: why,
                    },
                }
            }
            Err((vp, e)) => PackState::Inactive {
                version: Some(vp.version.to_string()),
                source: PackSource::Builtin,
                verified: true,
                reason: format!("did not load: {e}"),
            },
        }
    }

    /// Compile and apply every loaded pack's rules.
    fn apply_all(&mut self) {
        let owner: Vec<Rule> = if self.owner_error.is_none() {
            self.config.rules.clone()
        } else {
            Vec::new()
        };
        let overrides = self.config.pack_rules.clone();
        let (kill, tgid) = (self.kill_switch, self.opts.own_tgid);
        let mut primary = true;
        let mut owner_conflict = None;
        for p in &mut self.packs {
            let PackState::Running(r) = &mut p.state else {
                continue;
            };
            let mut rules: Vec<(Rule, bool)> = with_overrides(&p.name, &r.pack.rules, &overrides)
                .into_iter()
                .map(|r| (r, true))
                .collect();
            let own_only = rules.clone();
            if primary {
                rules.extend(owner.iter().cloned().map(|r| (r, false)));
            }
            let plain = |v: &[(Rule, bool)]| v.iter().map(|(r, _)| r.clone()).collect::<Vec<_>>();
            let compiled = match compile(&plain(&rules)) {
                Ok(c) => Ok(c),
                Err(e) if primary && !owner.is_empty() => {
                    // e.g. an owner rule id that a pack rule already uses
                    owner_conflict = Some(format!("the owner's rules are not applied: {e}"));
                    rules = own_only;
                    compile(&plain(&rules))
                }
                Err(e) => Err(e),
            };
            primary = false;
            r.applied = match compiled {
                Ok(c) => r.loaded.apply(&c, kill, tgid),
                Err(e) => Err(format!("the pack's rules do not compile: {e}")),
            };
            r.rules = rules;
        }
        if owner_conflict.is_some() {
            self.owner_error = owner_conflict;
        }
    }

    /// The packs to look for in the index, with the version in use.
    pub fn wanted_packs(&self) -> Vec<(String, Option<Version>)> {
        self.packs
            .iter()
            .filter(|p| self.enabled(&p.name))
            .map(|p| {
                let v = match &p.state {
                    PackState::Running(r) => Some(r.pack.version.clone()),
                    PackState::Inactive { version, .. } => {
                        version.as_deref().and_then(|v| Version::parse(v).ok())
                    }
                };
                (p.name.clone(), v)
            })
            .collect()
    }

    /// Install what [`fetch_updates`] brought (each archive must verify
    /// against the image's keys, and may not be older than the installed
    /// version), record the check, and reload the packs if anything was
    /// installed.
    pub fn install_updates(&mut self, downloads: Vec<Download>) -> Vec<PackCheck> {
        let mut installed_any = false;
        let mut out = Vec::new();
        for d in downloads {
            let mut check = PackCheck {
                name: d.name.clone(),
                current: d.current.as_ref().map(ToString::to_string),
                available: d.available.as_ref().map(ToString::to_string),
                installed: false,
                error: None,
            };
            match d.fetched {
                Ok(None) => {}
                Err(e) => check.error = Some(e),
                Ok(Some((archive, sig))) => match packs::install(
                    &archive,
                    &sig,
                    &self.keys,
                    &self.opts.state_dir,
                    &self.opts.sensr_version,
                    false,
                ) {
                    Ok(s) if s.name != d.name => {
                        installed_any = true;
                        check.error =
                            Some(format!("the archive holds pack {}, not {}", s.name, d.name));
                    }
                    Ok(_) => {
                        installed_any = true;
                        check.installed = true;
                    }
                    Err(e) => check.error = Some(e.to_string()),
                },
            }
            out.push(check);
        }
        let _ = std::fs::write(
            self.opts.state_dir.join(LAST_PACK_CHECK),
            format!("{}\n", unix_now()),
        );
        if installed_any {
            self.reconcile_packs();
            self.apply_all();
            // a pack that was installed but does not run says why
            for c in out.iter_mut().filter(|c| c.installed) {
                if let Some(p) = self.packs.iter().find(|p| p.name == c.name) {
                    c.error = match &p.state {
                        PackState::Running(r) => r.note.clone(),
                        PackState::Inactive { reason, .. } => Some(reason.clone()),
                    };
                }
            }
        }
        out
    }

    /// Drain the ring buffers into the pipeline and return the batches that
    /// are due. Module-load alerts are skipped until boot-complete.target
    /// is reached (blocked module loads are always kept).
    pub fn poll_events(&mut self, now: Instant) -> Vec<Batch> {
        if !self.boot_complete
            && self
                .last_boot_check
                .is_none_or(|t| now.saturating_duration_since(t) >= BOOT_CHECK_EVERY)
        {
            self.last_boot_check = Some(now);
            self.boot_complete = self.backend.boot_complete();
        }
        let boot_complete = self.boot_complete;
        let mut batches = Vec::new();
        let mut dropped = self.dropped_kernel_base;
        for p in &mut self.packs {
            let PackState::Running(r) = &mut p.state else {
                continue;
            };
            let pipeline = &mut self.pipeline;
            r.loaded.drain_events(&mut |raw| {
                let Some(e) = decode(raw) else { return };
                if e.hook == 5 && !e.blocked && !boot_complete {
                    return;
                }
                if let Some(b) = pipeline.push(e, now) {
                    batches.push(b);
                }
            });
            if let Ok(n) = r.loaded.ringbuf_dropped() {
                r.last_dropped = n;
            }
            dropped += r.last_dropped;
        }
        self.pipeline.set_dropped_kernel(dropped);
        batches.extend(self.pipeline.tick(now));
        batches
    }

    /// Hand back a batch whose write failed.
    pub fn requeue(&mut self, batch: Batch) {
        self.pipeline.requeue(batch);
    }

    /// Everything pending (shutdown).
    pub fn drain(&mut self) -> Option<Batch> {
        self.pipeline.drain()
    }

    /// The status.
    pub fn status(&self) -> StatusView {
        let mut packs = Vec::new();
        let mut rules = Vec::new();
        let mut reasons: Vec<String> = Vec::new();
        let mut running = false;
        let mut enforcing = true;
        let mut owner_placed = false;
        for p in &self.packs {
            match &p.state {
                PackState::Inactive {
                    version,
                    source,
                    verified,
                    reason,
                } => packs.push(PackStatus {
                    name: p.name.clone(),
                    version: version.clone().unwrap_or_default(),
                    source: *source,
                    verified: *verified,
                    active: false,
                    reason: Some(reason.clone()),
                    programs: Vec::new(),
                }),
                PackState::Running(r) => {
                    running = true;
                    let programs = r.loaded.programs();
                    let hits = r.loaded.hits_by_id().unwrap_or_default();
                    if let Err(e) = &r.applied {
                        enforcing = false;
                        reasons.push(format!(
                            "pack {}: {e} (its changed rules fail open)",
                            p.name
                        ));
                    }
                    for (slot, (rule, own)) in r.rules.iter().enumerate() {
                        owner_placed |= !own;
                        let why = if !rule.enabled {
                            Some("disabled".to_owned())
                        } else if let Err(e) = &r.applied {
                            Some(format!("not applied: {e}"))
                        } else if let Some(m) = missing_program(rule, &programs) {
                            Some(m)
                        } else if self.kill_switch && rule.action == Action::Block {
                            Some("the kill switch is on: alerts only".to_owned())
                        } else {
                            None
                        };
                        rules.push(RuleStatus {
                            id: rule.id.clone(),
                            pack: own.then(|| p.name.clone()),
                            slot: u32::try_from(slot).ok(),
                            action: rule.action,
                            active: why.is_none(),
                            reason: why,
                            hits: hits.get(&rule.id).copied().unwrap_or(0),
                        });
                    }
                    packs.push(PackStatus {
                        name: p.name.clone(),
                        version: r.pack.version.to_string(),
                        source: match r.pack.source {
                            Source::Builtin => PackSource::Builtin,
                            Source::Installed(_) => PackSource::Signed,
                        },
                        verified: true,
                        active: true,
                        reason: r.note.clone(),
                        programs: programs
                            .into_iter()
                            .map(|s| ProgramView {
                                name: s.name,
                                hook: s.hook,
                                attached: s.attached,
                                reason: s.reason,
                            })
                            .collect(),
                    });
                }
            }
        }
        if !owner_placed {
            let why = self
                .owner_error
                .clone()
                .unwrap_or_else(|| "no pack is loaded".to_owned());
            for rule in &self.config.rules {
                rules.push(RuleStatus {
                    id: rule.id.clone(),
                    pack: None,
                    slot: None,
                    action: rule.action,
                    active: false,
                    reason: Some(why.clone()),
                    hits: 0,
                });
            }
        }
        if let Some(e) = &self.owner_error {
            reasons.push(e.clone());
        }
        if !running {
            enforcing = false;
            reasons.push(if self.config.enabled {
                "no pack is loaded".to_owned()
            } else {
                "the guard is off".to_owned()
            });
        }
        if let Some(e) = &self.keys_error {
            reasons.push(e.clone());
        }
        StatusView {
            running,
            enforcing,
            reason: (!reasons.is_empty()).then(|| reasons.join("; ")),
            kill_switch: self.kill_switch,
            lockdown: self.lockdown.clone(),
            packs,
            rules,
            dropped_kernel: self.pipeline.dropped_kernel(),
            dropped_rate: self.pipeline.dropped_rate(),
            dropped_blocked: self.pipeline.dropped_blocked(),
            boot_complete: self.boot_complete,
        }
    }

    /// Answer a request (other than [`crate::proto::Request::CheckPacks`],
    /// which needs the lock released while it downloads: see
    /// [`check_packs`]).
    pub fn handle(&mut self, req: &crate::proto::Request) -> Reply {
        use crate::proto::Request;
        match req {
            Request::Status => Reply::Status(self.status()),
            Request::Reload => self.reload().map_or_else(Reply::Error, |()| Reply::Ok),
            Request::KillSwitch { on } => self
                .set_kill_switch(*on)
                .map_or_else(Reply::Error, |()| Reply::Ok),
            Request::CheckPacks => Reply::Error("check_packs is handled by the server".into()),
        }
    }
}

/// The kernel backend (aya).
#[cfg(target_os = "linux")]
pub mod kernel {
    use std::collections::HashMap;

    use aya::maps::{MapData, RingBuf};

    use super::{Backend, LoadedPack};
    use crate::compile::Compiled;
    use crate::loader::{Loaded, ProgramStatus, load_bytes};
    use crate::packs::VerifiedPack;

    /// Loads packs into the running kernel.
    #[derive(Debug, Default)]
    pub struct Kernel;

    struct Pack {
        loaded: Loaded,
        ring: RingBuf<MapData>,
    }

    impl Backend for Kernel {
        fn load(&mut self, pack: &VerifiedPack) -> Result<Box<dyn LoadedPack>, String> {
            let mut loaded = load_bytes(pack).map_err(|e| e.to_string())?;
            let ring = loaded.ringbuf().map_err(|e| e.to_string())?;
            Ok(Box::new(Pack { loaded, ring }))
        }

        fn boot_complete(&mut self) -> bool {
            std::process::Command::new("systemctl")
                .args(["is-active", "--quiet", "boot-complete.target"])
                .status()
                .is_ok_and(|s| s.success())
        }
    }

    impl LoadedPack for Pack {
        fn programs(&self) -> Vec<ProgramStatus> {
            self.loaded.status()
        }

        fn apply(&mut self, c: &Compiled, kill_switch: bool, own_tgid: u32) -> Result<(), String> {
            self.loaded
                .apply(c, kill_switch, own_tgid)
                .map_err(|e| e.to_string())
        }

        fn hits_by_id(&self) -> Result<HashMap<String, u64>, String> {
            self.loaded.hits_by_id().map_err(|e| e.to_string())
        }

        fn ringbuf_dropped(&self) -> Result<u64, String> {
            self.loaded.ringbuf_dropped().map_err(|e| e.to_string())
        }

        fn drain_events(&mut self, sink: &mut dyn FnMut(&[u8])) {
            while let Some(item) = self.ring.next() {
                sink(&item);
            }
        }
    }
}
