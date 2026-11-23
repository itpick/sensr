//! The slice apply engine: document → plan → check → commit, in stage order,
//! against a root directory and a [`Runner`] (both injectable, so the whole
//! sequence is tested without root). OPNsense counterpart: configd's
//! reconfigure actions plus `rc.filter_configure`.
//!
//! Order of a commit: secrets → sysctls → MAC pins (`.link` files, kept
//! for the next boot, and renames of cards that carry the wrong name) →
//! interface files + networkd →
//! qdiscs → nft ruleset (one atomic transaction) → service files → WireGuard
//! links → unit reloads → `config` hooks. Only what the delta against the
//! last committed plan touches runs, so an unchanged document is a no-op.
//! Any failure leaves the engine without an applied state, so the agent's
//! rollback (re-applying the previous revision) runs every stage again.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sensr_rules::document::{self, Runtime};
use sensr_rules::host_modes::{self, HostModeSets};
use sensr_rules::ir::IfAddr;
use sensr_rules::render::nft as rules_nft;
use sensr_schema::Document;

use crate::appliers::convert::{self, ConvertError, SecretsDir};
use crate::appliers::interfaces::InterfacesModel;
use crate::appliers::sysctl::{Sysctl, SysctlApplyError};
use crate::appliers::{
    SliceError, SliceModels, emergency, insight, kea, nft, ntp, suricata, unbound,
};
use crate::cmd::{Cmd, CmdError, Runner};
use crate::hooks::{HookLevel, Hooks};
use crate::plan::{FileSpec, Plan, UnitAction, UnitSpec};
use crate::templates::{Staging, TemplateError, Templates, write_atomic};

/// A config-file checker: `Ok(None)` when absent, `Ok(Some(""))` when accepted.
type Checker = fn(&dyn Runner, &Path) -> Result<Option<String>, CmdError>;

/// Engine failures, each naming the stage.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The document cannot be turned into models.
    #[error("converting the document: {0}")]
    Convert(#[from] ConvertError),
    /// Rendering the plan.
    #[error("planning: {0}")]
    Plan(#[from] SliceError),
    /// A template or file write.
    #[error(transparent)]
    Template(#[from] TemplateError),
    /// A checker rejected the configuration (nothing was changed).
    #[error("{backend} rejected the configuration: {message}")]
    Rejected {
        /// `nft`, `kea-dhcp4`, `unbound-checkconf`
        backend: &'static str,
        /// the checker's message
        message: String,
    },
    /// A command could not be run.
    #[error(transparent)]
    Cmd(#[from] CmdError),
    /// A command ran and failed during commit.
    #[error("{cmd} failed: {message}")]
    Failed {
        /// the command
        cmd: String,
        /// its stderr
        message: String,
    },
    /// The nft load failed (the kernel kept the previous ruleset).
    #[error(transparent)]
    Nft(#[from] nft::NftError),
    /// Setting kernel tunables.
    #[error(transparent)]
    Sysctl(#[from] SysctlApplyError),
    /// The IDS section cannot be resolved.
    #[error(transparent)]
    Ids(#[from] suricata::SuricataError),
    /// I/O.
    #[error("{path}: {source}")]
    Io {
        /// path
        path: PathBuf,
        /// error
        source: std::io::Error,
    },
}

/// Engine settings.
#[derive(Debug, Clone)]
pub struct EngineOptions {
    /// Filesystem root (`/` on the box, a temp dir in tests).
    pub root: PathBuf,
    /// Where secret files go.
    pub secrets: SecretsDir,
    /// Run the backend checkers (`nft -c`, `kea-dhcp4 -t`,
    /// `unbound-checkconf`) before committing.
    pub check: bool,
}

impl Default for EngineOptions {
    fn default() -> Self {
        EngineOptions {
            root: PathBuf::from("/"),
            secrets: SecretsDir::default(),
            check: true,
        }
    }
}

#[derive(Debug, Clone)]
struct Applied {
    plan: Plan,
    models: SliceModels,
    interfaces: InterfacesModel,
}

/// A document turned into everything a commit needs.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// the desired-state plan
    pub plan: Plan,
    /// slice service models
    pub models: SliceModels,
    /// networkd model
    pub interfaces: InterfacesModel,
    /// the rendered nft ruleset (JSON)
    pub ruleset: Vec<u8>,
    /// rule degradations (`label: message`)
    pub warnings: Vec<String>,
    /// aliases whose contents could not be resolved (kept from before)
    pub alias_failed: Vec<String>,
    /// alias contents the ruleset was rendered with
    pub aliases: BTreeMap<String, rules_nft::ResolvedAlias>,
    /// host-mode MAC sets the ruleset was rendered with (the locked
    /// addresses are empty: [`Engine::update_host_mode_sets`] fills them)
    pub host_modes: HostModeSets,
    /// devices of the enabled non-WAN interfaces (the emergency firewall
    /// serves them)
    pub inside: Vec<String>,
    secrets: Vec<(PathBuf, String)>,
}

/// What a commit did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitReport {
    /// commands run, in order (display form)
    pub commands: Vec<String>,
    /// files written
    pub files: Vec<PathBuf>,
    /// the ruleset was reloaded
    pub nft_loaded: bool,
}

/// Something the boot apply could not bring up as planned
/// ([`Engine::commit_isolated`]); the rest of the system applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Degraded {
    /// Who refused: the checker (`nft`, `kea-dhcp4`, `unbound-checkconf`,
    /// `ntp-ctl`), or `systemctl` / `nft` for a start or load that failed.
    pub backend: &'static str,
    /// The unit (or table) concerned; `None` for the main ruleset.
    pub unit: Option<String>,
    /// The checker's or command's message.
    pub message: String,
    /// What runs instead.
    pub outcome: Outcome,
}

/// What runs in place of a held-back part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The unit was (re)started with the file already on disk (an agent
    /// restart within a boot).
    KeptPrevious,
    /// The unit was left stopped (fresh boot, nothing to fall back to).
    NotStarted,
    /// The ruleset was rejected; the kernel keeps the sensr ruleset it
    /// already had (an agent restart within a boot).
    PreviousFirewall,
    /// The ruleset was rejected and the kernel had none: the emergency
    /// firewall ([`emergency`]) is loaded.
    EmergencyFirewall,
    /// The unit's start/restart failed.
    StartFailed,
    /// A ruleset load failed (IDS queue, accounting, the emergency table).
    LoadFailed,
}

/// Longest message shown per problem (the UI banner keeps one line each).
const MAX_MESSAGE: usize = 300;

/// `s` on one line, cut at [`MAX_MESSAGE`] characters with an ellipsis.
fn one_line(s: &str) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= MAX_MESSAGE {
        return flat;
    }
    let mut cut: String = flat.chars().take(MAX_MESSAGE - 1).collect();
    cut.push('…');
    cut
}

impl std::fmt::Display for Degraded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = one_line(&self.message);
        let unit = self.unit.as_deref().unwrap_or("the ruleset");
        let b = self.backend;
        match self.outcome {
            Outcome::KeptPrevious => write!(
                f,
                "{b} rejected the configuration; {unit} runs its previous configuration: {msg}"
            ),
            Outcome::NotStarted => write!(
                f,
                "{b} rejected the configuration; {unit} was not started: {msg}"
            ),
            Outcome::PreviousFirewall => write!(
                f,
                "{b} rejected the ruleset; the firewall keeps the ruleset loaded before: {msg}"
            ),
            Outcome::EmergencyFirewall => write!(f, "emergency firewall active: {msg}"),
            Outcome::StartFailed => write!(f, "{unit} failed to start: {msg}"),
            Outcome::LoadFailed => write!(f, "{unit} could not be loaded: {msg}"),
        }
    }
}

/// What a fault-isolated commit held back.
#[derive(Debug, Default)]
struct Isolation {
    degraded: Vec<Degraded>,
    /// planned files not written (their checker rejected them)
    withheld_files: std::collections::BTreeSet<PathBuf>,
    /// units not started (rejected, and no previous file to run with)
    withheld_units: std::collections::BTreeSet<String>,
    /// the ruleset was rejected (with this message): not loaded
    nft_rejected: Option<String>,
}

impl Isolation {
    /// Holds `path` back; the units reading it run their previous file if
    /// there is one, else stay stopped.
    fn withhold(&mut self, plan: &Plan, path: &Path, backend: &'static str, message: String) {
        self.withheld_files.insert(path.to_owned());
        let kept = path.exists();
        for (unit, spec) in &plan.units {
            if !spec.inputs.contains(path) {
                continue;
            }
            if !kept {
                self.withheld_units.insert(unit.clone());
            }
            self.degraded.push(Degraded {
                backend,
                unit: Some(unit.clone()),
                message: message.clone(),
                outcome: if kept {
                    Outcome::KeptPrevious
                } else {
                    Outcome::NotStarted
                },
            });
        }
    }
}

/// In a fault-isolated commit, records a failed step and carries on;
/// otherwise fails.
fn isolate(
    iso: Option<&mut Isolation>,
    result: Result<(), EngineError>,
    backend: &'static str,
    unit: &str,
    outcome: Outcome,
) -> Result<(), EngineError> {
    match (result, iso) {
        (Ok(()), _) => Ok(()),
        (Err(e), Some(iso)) => {
            iso.degraded.push(Degraded {
                backend,
                unit: Some(unit.to_owned()),
                message: match e {
                    EngineError::Failed { message, .. } => message,
                    other => other.to_string(),
                },
                outcome,
            });
            Ok(())
        }
        (Err(e), None) => Err(e),
    }
}

/// Units started first by a commit: name service and leases matter most.
const FIRST_UNITS: &[&str] = &["sensr-unbound.service", "sensr-kea-dhcp4.service"];

/// The checker for a rendered file, by file name.
fn checker_for(name: &str) -> Option<(&'static str, Checker)> {
    match name {
        "kea-dhcp4.conf" => Some(("kea-dhcp4", kea::check)),
        "unbound.conf" => Some(("unbound-checkconf", unbound::check)),
        "ntp.toml" => Some(("ntp-ctl", ntp::check)),
        _ => None,
    }
}

/// The apply engine.
pub struct Engine {
    opts: EngineOptions,
    templates: Templates,
    staging: Staging,
    runner: Arc<dyn Runner>,
    applied: Option<Applied>,
}

impl Engine {
    /// An engine with the built-in templates.
    pub fn new(opts: EngineOptions, runner: Arc<dyn Runner>) -> Result<Engine, EngineError> {
        Ok(Engine {
            staging: Staging::new(&opts.root),
            templates: Templates::builtin()?,
            opts,
            runner,
            applied: None,
        })
    }

    /// Forget the applied state: the next commit runs every stage.
    pub fn reset(&mut self) {
        self.applied = None;
    }

    /// Turns a document into a plan and its inputs. Changes nothing.
    pub fn prepare(&self, doc: &Document, rt: &Runtime<'_>) -> Result<Prepared, EngineError> {
        let compiled = document::compile(doc, rt);
        let mut ruleset = Vec::with_capacity(64 * 1024);
        let report = compiled
            .render_nft(&mut ruleset)
            .map_err(|source| EngineError::Io {
                path: PathBuf::from("<nft ruleset>"),
                source,
            })?;
        let models = SliceModels::from_document(doc, &self.opts.secrets)?;
        let interfaces = InterfacesModel::from_document(doc).with_routing(doc, &compiled.routing);
        let summary = format!(
            "{} rules → {} nft rules, {} verdict maps",
            report.stats.filter_rules, report.stats.nft_rules, report.stats.vmaps
        );
        let mut plan = models.plan(
            &self.templates,
            &self.staging,
            Some((&ruleset, summary.as_str())),
        )?;
        plan.files.extend(
            self.staging
                .plan_files(&interfaces.render(&self.templates)?),
        );
        // the system hostname is a kernel tunable too
        plan.sysctls
            .insert("kernel.hostname".into(), doc.system.hostname.to_string());
        self.plan_ids(doc, rt, &mut plan)?;
        self.plan_insight(doc, &mut plan);
        let secrets = convert::secret_files(doc, &self.opts.secrets)
            .into_iter()
            .map(|(p, c)| (self.rooted(&p), c))
            .collect();
        Ok(Prepared {
            plan,
            models,
            interfaces,
            ruleset,
            warnings: report
                .warnings
                .iter()
                .map(|w| format!("{}: {}", w.label, w.message))
                .collect(),
            alias_failed: compiled.aliases.failed.iter().cloned().collect(),
            aliases: compiled.aliases.aliases.clone(),
            host_modes: compiled.host_modes.clone(),
            inside: doc
                .interfaces
                .iter()
                .filter(|(_, i)| {
                    i.enabled && i.role != sensr_schema::models::interfaces::InterfaceRole::Wan
                })
                .map(|(_, i)| i.device.as_str().to_owned())
                .collect(),
            secrets,
        })
    }

    /// Suricata's files and units (nothing when IDS is off). HOME_NET is
    /// computed from `rt.addrs`, so it holds the WAN's current lease.
    fn plan_ids(
        &self,
        doc: &Document,
        rt: &Runtime<'_>,
        plan: &mut Plan,
    ) -> Result<(), EngineError> {
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
        let Some(m) = suricata::SuricataModel::from_document(doc, &rt.addrs, cpus)? else {
            return Ok(());
        };
        let files = self.staging.plan_files(&m.render(&self.templates)?);
        let mut restart = std::collections::BTreeSet::new();
        let mut reload = std::collections::BTreeSet::new();
        let mut update = std::collections::BTreeSet::new();
        for path in files.keys() {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            match name.as_deref().and_then(suricata::action_for) {
                Some(UnitAction::Restart) => restart.insert(path.clone()),
                Some(UnitAction::Reload) => reload.insert(path.clone()),
                None => update.insert(path.clone()),
            };
        }
        plan.files.extend(files);
        plan.files.insert(
            self.staging.live_dir(suricata::DIR).join(suricata::IPS_NFT),
            FileSpec {
                contents: m.ips_ruleset().into_bytes(),
                mode: 0o600,
            },
        );
        let unit = |action, inputs| UnitSpec { action, inputs };
        plan.units
            .insert(suricata::UNIT.into(), unit(UnitAction::Restart, restart));
        plan.units.insert(
            suricata::RELOAD_UNIT.into(),
            unit(UnitAction::Restart, reload),
        );
        plan.units.insert(
            suricata::TRIGGER_UNIT.into(),
            unit(UnitAction::Restart, update),
        );
        if doc.ids.updates.enabled {
            let dropin = self.rooted(Path::new(suricata::TIMER_DROPIN));
            plan.files.insert(
                dropin.clone(),
                FileSpec {
                    contents: suricata::timer_dropin(&doc.ids.updates).into_bytes(),
                    mode: 0o644,
                },
            );
            plan.units.insert(
                suricata::TIMER_UNIT.into(),
                unit(UnitAction::Restart, [dropin].into()),
            );
        }
        Ok(())
    }

    /// The insight daemon's config and the accounting table (nothing when
    /// neither accounting nor IDS is on).
    fn plan_insight(&self, doc: &Document, plan: &mut Plan) {
        let Some(cfg) = insight::config(doc) else {
            return;
        };
        let dir = self.staging.live_dir(insight::DIR);
        let conf = dir.join(insight::CONFIG);
        plan.files.insert(
            conf.clone(),
            FileSpec {
                contents: serde_json::to_vec_pretty(&cfg).unwrap_or_default(),
                mode: 0o644,
            },
        );
        plan.files.insert(
            dir.join(insight::NFT),
            FileSpec {
                contents: insight::ruleset(&cfg).into_bytes(),
                mode: 0o600,
            },
        );
        plan.units.insert(
            insight::UNIT.into(),
            UnitSpec {
                action: UnitAction::Restart,
                inputs: [conf].into(),
            },
        );
    }

    /// Rewrites HOME_NET when the box's addresses changed (a new WAN lease)
    /// and reloads Suricata's rules; `Ok(false)` when nothing changed or IDS
    /// is off. The agent's address watcher calls this.
    pub fn update_ids_home_net(
        &self,
        doc: &Document,
        addrs: &BTreeMap<String, Vec<IfAddr>>,
    ) -> Result<bool, EngineError> {
        let Some(m) = suricata::SuricataModel::from_document(doc, addrs, 1)? else {
            return Ok(false);
        };
        let Some(vars) = m
            .render(&self.templates)?
            .into_iter()
            .find(|r| r.dest.as_os_str() == "vars.yaml")
        else {
            return Ok(false);
        };
        let path = self.staging.live_dir(suricata::DIR).join("vars.yaml");
        if std::fs::read(&path).ok().as_deref() == Some(vars.contents.as_bytes()) {
            return Ok(false);
        }
        write_atomic(&path, vars.contents.as_bytes(), 0o644)?;
        let mut report = CommitReport::default();
        self.run(
            &Cmd::new("systemctl").args(["restart", suricata::RELOAD_UNIT]),
            &mut report,
        )?;
        Ok(true)
    }

    fn rooted(&self, p: &Path) -> PathBuf {
        self.opts.root.join(p.strip_prefix("/").unwrap_or(p))
    }

    /// The work a commit of `p` would do.
    pub fn delta(&self, p: &Prepared) -> Plan {
        match &self.applied {
            Some(a) => p.plan.diff(&a.plan),
            None => p.plan.diff(&Plan::default()),
        }
    }

    /// Human-readable dry run of [`delta`](Self::delta).
    pub fn dry_run(&self, p: &Prepared) -> String {
        let applied = self
            .applied
            .as_ref()
            .map(|a| a.plan.clone())
            .unwrap_or_default();
        p.plan.diff(&applied).dry_run(&applied)
    }

    /// Runs the backend checkers that can judge `p` before anything goes
    /// live: `nft -c` and `unbound-checkconf`. Kea's check needs its
    /// interfaces to exist, so [`commit`](Self::commit) runs it after the
    /// links stage.
    pub fn check(&self, p: &Prepared) -> Result<(), EngineError> {
        let r = self.runner.as_ref();
        if r.has_program("nft") {
            nft::check(r, &p.ruleset).map_err(|e| match e {
                nft::NftError::Rejected { message, .. } => EngineError::Rejected {
                    backend: "nft",
                    message,
                },
                other => EngineError::Nft(other),
            })?;
        }
        self.check_files(p, &["unbound.conf", "ntp.toml"])
    }

    /// Stages the named files, runs their checkers, throws the copies away.
    fn check_files(&self, p: &Prepared, which: &[&str]) -> Result<(), EngineError> {
        for (path, spec) in &p.plan.files {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            if !name.as_deref().is_some_and(|n| which.contains(&n)) {
                continue;
            }
            if let Some((backend, message)) = self.check_file(path, spec)? {
                return Err(EngineError::Rejected { backend, message });
            }
        }
        Ok(())
    }

    /// Runs the checker of one planned file on a scratch copy: the
    /// checker's name and complaint when it rejects the file, `None` when it
    /// accepts it (or the file has no checker, or the checker is absent).
    fn check_file(
        &self,
        path: &Path,
        spec: &FileSpec,
    ) -> Result<Option<(&'static str, String)>, EngineError> {
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            return Ok(None);
        };
        let Some((backend, f)) = checker_for(&name) else {
            return Ok(None);
        };
        let scratch = self.opts.root.join("run/sensr/.check");
        let mut staged = Vec::new();
        let result = (|| {
            let mut contents = spec.contents.clone();
            if backend == "unbound-checkconf" {
                contents = self.unbound_check_copy(&contents, &scratch, &mut staged)?;
            }
            let tmp = scratch.join(&name);
            write_atomic(&tmp, &contents, spec.mode)?;
            staged.push(tmp.clone());
            Ok(f(self.runner.as_ref(), &tmp)?
                .filter(|m| !m.is_empty())
                .map(|m| (backend, m)))
        })();
        for s in &staged {
            let _ = std::fs::remove_file(s);
        }
        result
    }

    /// [`check`](Self::check) for a fault-isolated commit: a rejection is
    /// recorded in `iso` instead of failing.
    fn check_isolated(&self, p: &Prepared, iso: &mut Isolation) -> Result<(), EngineError> {
        let r = self.runner.as_ref();
        if r.has_program("nft") {
            // a checker that cannot run counts as a rejection too
            match nft::check(r, &p.ruleset) {
                Ok(()) => {}
                Err(nft::NftError::Rejected { message, .. }) => iso.nft_rejected = Some(message),
                Err(other) => iso.nft_rejected = Some(other.to_string()),
            }
        }
        for (path, spec) in &p.plan.files {
            let early = path
                .file_name()
                .is_some_and(|n| n == "unbound.conf" || n == "ntp.toml");
            if !early {
                continue;
            }
            if let Some((backend, message)) = self.check_file_isolated(path, spec) {
                iso.withhold(&p.plan, path, backend, message);
            }
        }
        Ok(())
    }

    /// [`check_file`](Self::check_file) where a checker that cannot run
    /// (spawn failure, scratch copy not writable) rejects the file.
    fn check_file_isolated(&self, path: &Path, spec: &FileSpec) -> Option<(&'static str, String)> {
        match self.check_file(path, spec) {
            Ok(r) => r,
            Err(e) => {
                let name = path.file_name()?.to_string_lossy().into_owned();
                let (backend, _) = checker_for(&name)?;
                Some((backend, format!("the check could not run: {e}")))
            }
        }
    }

    /// Whether the kernel holds the sensr ruleset's table.
    fn sensr_table_loaded(&self) -> bool {
        let table = rules_nft::Options::default().table;
        self.runner
            .run(
                &Cmd::new("nft").args(["list", "table", "inet", table.as_str()]),
                None,
            )
            .is_ok_and(|o| o.success())
    }

    /// unbound-checkconf follows `directory:` and `include:`, which only
    /// exist once the unit runs (its state directory) or the files are live:
    /// check a copy pointing at the scratch directory instead.
    fn unbound_check_copy(
        &self,
        conf: &[u8],
        scratch: &Path,
        staged: &mut Vec<PathBuf>,
    ) -> Result<Vec<u8>, EngineError> {
        let text = String::from_utf8_lossy(conf);
        let mut out = String::with_capacity(text.len());
        for line in text.lines() {
            let t = line.trim_start();
            let quoted = |k: &str| {
                t.strip_prefix(k)
                    .map(|v| v.trim().trim_matches('"').to_owned())
            };
            if let Some(dir) = quoted("directory:") {
                let _ = dir;
                out.push_str(&format!("  directory: \"{}\"\n", scratch.display()));
            } else if let Some(file) = quoted("logfile:").filter(|f| !f.is_empty()) {
                // the query log lives in the unit's runtime directory, which
                // only exists while Unbound runs: a stopped resolver (boot, or
                // a switch that stopped it) must not fail the check
                let local = scratch.join(Path::new(&file).file_name().unwrap_or_default());
                staged.push(local.clone());
                out.push_str(&format!("  logfile: \"{}\"\n", local.display()));
            } else if let Some((key, file)) = ["include:", "auto-trust-anchor-file:"]
                .iter()
                .find_map(|k| quoted(k).map(|f| (*k, f)))
            {
                // the lease include and the root anchor appear at run time
                let local = scratch.join(Path::new(&file).file_name().unwrap_or_default());
                write_atomic(&local, b"", 0o644)?;
                staged.push(local.clone());
                if key == "auto-trust-anchor-file:" {
                    // an empty anchor file is not an anchor: check without it
                    out.push_str("  # auto-trust-anchor-file checked at unit start\n");
                } else {
                    out.push_str(&format!("  {key} \"{}\"\n", local.display()));
                }
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        Ok(out.into_bytes())
    }

    fn run(&self, cmd: &Cmd, report: &mut CommitReport) -> Result<(), EngineError> {
        let out = self.runner.run(cmd, None)?;
        report.commands.push(cmd.display());
        if !out.success() {
            return Err(EngineError::Failed {
                cmd: cmd.display(),
                message: out.stderr_text(),
            });
        }
        Ok(())
    }

    fn write(
        &self,
        path: &Path,
        spec: &FileSpec,
        report: &mut CommitReport,
    ) -> Result<(), EngineError> {
        write_atomic(path, &spec.contents, spec.mode)?;
        report.files.push(path.to_owned());
        Ok(())
    }

    /// Checks (when enabled), then makes the system match `p`. All or
    /// nothing: any checker's rejection changes nothing.
    pub fn commit(&mut self, p: Prepared) -> Result<CommitReport, EngineError> {
        if self.opts.check {
            self.check(&p)?;
        }
        let result = self.commit_inner(&p, None);
        match &result {
            Ok(_) => {
                self.applied = Some(Applied {
                    plan: p.plan,
                    models: p.models,
                    interfaces: p.interfaces,
                })
            }
            // part of the system may be new: the next commit redoes everything
            Err(_) => self.applied = None,
        }
        result
    }

    /// The boot apply: makes the system match `p` from scratch, isolating
    /// checker rejections instead of refusing everything. Every stage runs
    /// (the applied state is forgotten first), so units that were stopped
    /// (a NixOS switch stops them with the agent) are started even when
    /// their files did not change. A daemon whose file its checker rejects
    /// does not get the new file: it is restarted with the file already on
    /// disk if there is one, else left stopped. A checker that cannot run
    /// counts as that backend's rejection. A rejected ruleset is not loaded:
    /// the kernel keeps the sensr ruleset it has (agent restart) or, when it
    /// has none (fresh boot), gets the [`emergency`] firewall, so the box is
    /// never left unfiltered; everything else still applies. A unit that
    /// fails to start or a side table that fails to load is recorded and the
    /// rest carries on. What was held back is returned, and left out of the
    /// applied state so the next commit writes (and checks) it again; that
    /// commit's ruleset load also drops the emergency table.
    pub fn commit_isolated(
        &mut self,
        mut p: Prepared,
    ) -> Result<(CommitReport, Vec<Degraded>), EngineError> {
        self.applied = None;
        let mut iso = Isolation::default();
        if self.opts.check {
            self.check_isolated(&p, &mut iso)?;
        }
        let report = self.commit_inner(&p, Some(&mut iso))?;
        for f in &iso.withheld_files {
            p.plan.files.remove(f);
        }
        for u in &iso.withheld_units {
            p.plan.units.remove(u);
        }
        if iso.nft_rejected.is_some() {
            p.plan.nft = None;
        }
        self.applied = Some(Applied {
            plan: p.plan,
            models: p.models,
            interfaces: p.interfaces,
        });
        Ok((report, iso.degraded))
    }

    fn commit_inner(
        &self,
        p: &Prepared,
        mut iso: Option<&mut Isolation>,
    ) -> Result<CommitReport, EngineError> {
        let mut report = CommitReport::default();
        let mut delta = self.delta(p);
        if let Some(iso) = iso.as_deref() {
            delta.files.retain(|f, _| !iso.withheld_files.contains(f));
            delta.units.retain(|u, _| !iso.withheld_units.contains(u));
            if iso.nft_rejected.is_some() {
                delta.nft = None;
            }
        }
        let empty = Applied {
            plan: Plan::default(),
            models: SliceModels::default(),
            interfaces: InterfacesModel::default(),
        };
        let applied = self.applied.as_ref().unwrap_or(&empty);
        let r = self.runner.as_ref();

        // networkd (user systemd-network) reads the WireGuard key files:
        // files 0640 and every directory below the secrets root 0750, group
        // systemd-network
        let network_gid = group_id(&self.opts.root, "systemd-network");
        let secrets_root = self.rooted(&self.opts.secrets.0);
        for (path, contents) in &p.secrets {
            write_atomic(path, contents.as_bytes(), 0o640)?;
            let Some(gid) = network_gid else { continue };
            let dirs = path
                .ancestors()
                .skip(1)
                .take_while(|d| d.starts_with(&secrets_root));
            for p in std::iter::once(path.as_path()).chain(dirs) {
                let io = |source| EngineError::Io {
                    path: p.to_owned(),
                    source,
                };
                std::os::unix::fs::chown(p, None, Some(gid)).map_err(io)?;
                if p != path.as_path() {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o750))
                        .map_err(io)?;
                }
            }
        }

        let sysctl = Sysctl::new(&self.opts.root);
        let own = p.models.sysctl.to_map().unwrap_or_default();
        // a key leaving the model is no delta, but a redirect switch sensr
        // turned off must still come back on
        if !delta.sysctls.is_empty() || !sysctl.restores(&own).is_empty() {
            sysctl.apply(&p.models.sysctl)?;
            // the rest (qdisc default, hostname) are written as they are
            for (k, v) in delta.sysctls.iter().filter(|(k, _)| !own.contains_key(*k)) {
                let path = self.opts.root.join("proc/sys").join(k.replace('.', "/"));
                std::fs::write(&path, format!("{v}\n"))
                    .map_err(|source| EngineError::Io { path, source })?;
            }
        }

        // links first: everything else refers to devices and addresses
        let net_dir = self.staging.live_dir("run/systemd/network");
        let renamed = self.pin_cards(p, &net_dir, &mut report)?;
        let is_iface_file = |path: &Path| {
            path.starts_with(&net_dir)
                && path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("40-sensr-"))
        };
        for (path, spec) in delta.files.iter().filter(|(p, _)| is_iface_file(p)) {
            self.write(path, spec, &mut report)?;
        }
        for path in delta.remove_files.iter().filter(|p| is_iface_file(p)) {
            let _ = std::fs::remove_file(path);
        }
        let mut cmds = p.interfaces.commands(&applied.interfaces);
        if !renamed.is_empty()
            && !cmds
                .iter()
                .any(|c| c.display().starts_with("networkctl 'reload'"))
        {
            // the renamed cards now match their .network files
            cmds.insert(0, Cmd::new("networkctl").arg("reload"));
        }
        for c in cmds {
            self.run(&c, &mut report)?;
        }
        // a renamed card was taken down to rename it; networkd brings it
        // up again only when told to look at it
        for name in &renamed {
            self.run(
                &Cmd::new("networkctl").args(["reconfigure", name.as_str()]),
                &mut report,
            )?;
        }
        if self.opts.check && delta.files.keys().any(|f| f.ends_with("kea-dhcp4.conf")) {
            // networkd creates VLANs asynchronously after the reload
            self.wait_for_links(&p.interfaces);
            match iso.as_deref_mut() {
                None => self.check_files(p, &["kea-dhcp4.conf"])?,
                Some(iso) => {
                    let kea: Vec<_> = delta
                        .files
                        .iter()
                        .filter(|(f, _)| f.ends_with("kea-dhcp4.conf"))
                        .map(|(f, spec)| (f.clone(), spec.clone()))
                        .collect();
                    for (path, spec) in kea {
                        if let Some((backend, message)) = self.check_file_isolated(&path, &spec) {
                            iso.withhold(&p.plan, &path, backend, message);
                            delta.files.remove(&path);
                        }
                    }
                    delta.units.retain(|u, _| !iso.withheld_units.contains(u));
                }
            }
        }

        if !delta.qdiscs.is_empty() || p.models.qdisc != applied.models.qdisc {
            for c in p.models.qdisc.commands(&applied.models.qdisc) {
                self.run(&c, &mut report)?;
            }
        }

        if delta.nft.is_some() {
            nft::load(r, &p.ruleset)?;
            report.commands.push("nft -j -f -".into());
            report.nft_loaded = true;
            if applied.plan.nft.is_none() {
                // first ruleset of this engine, or after a boot that had
                // to run the emergency firewall: drop it if it is there
                nft::load(r, emergency::removal().as_bytes())?;
                report
                    .commands
                    .push("nft -j -f - (emergency firewall removed)".into());
            }
        } else if let Some(iso) = iso.as_deref_mut()
            && let Some(message) = iso.nft_rejected.clone()
        {
            // a rejected ruleset never leaves the box unfiltered
            if self.sensr_table_loaded() {
                iso.degraded.push(Degraded {
                    backend: "nft",
                    unit: None,
                    message,
                    outcome: Outcome::PreviousFirewall,
                });
            } else {
                let loaded = nft::load(r, emergency::ruleset(&p.inside).as_bytes());
                match loaded {
                    Ok(_) => {
                        report
                            .commands
                            .push("nft -j -f - (emergency firewall)".into());
                        iso.degraded.push(Degraded {
                            backend: "nft",
                            unit: None,
                            message,
                            outcome: Outcome::EmergencyFirewall,
                        });
                    }
                    Err(e) => iso.degraded.push(Degraded {
                        backend: "nft",
                        unit: Some(format!("inet {}", emergency::TABLE)),
                        message: format!("{e} (after the ruleset was rejected: {message})"),
                        outcome: Outcome::LoadFailed,
                    }),
                }
            }
        }

        for (path, spec) in delta.files.iter().filter(|(p, _)| !is_iface_file(p)) {
            self.write(path, spec, &mut report)?;
        }
        for path in delta.remove_files.iter().filter(|p| !is_iface_file(p)) {
            let _ = std::fs::remove_file(path);
        }

        for c in p.models.wireguard.commands(&applied.models.wireguard) {
            self.run(&c, &mut report)?;
        }

        let unit_dir = self.rooted(Path::new("/run/systemd/system"));
        if delta
            .files
            .keys()
            .chain(&delta.remove_files)
            .any(|f| f.starts_with(&unit_dir))
        {
            self.run(&Cmd::new("systemctl").arg("daemon-reload"), &mut report)?;
        }

        let mut units: Vec<_> = delta.units.iter().collect();
        units.sort_by_key(|(u, _)| {
            FIRST_UNITS
                .iter()
                .position(|f| f == u)
                .unwrap_or(FIRST_UNITS.len())
        });
        for (unit, spec) in units {
            let verb = match spec.action {
                UnitAction::Reload => "reload-or-restart",
                UnitAction::Restart => "restart",
            };
            let started = self.run(
                &Cmd::new("systemctl").args([verb, unit.as_str()]),
                &mut report,
            );
            isolate(
                iso.as_deref_mut(),
                started,
                "systemctl",
                unit,
                Outcome::StartFailed,
            )?;
        }

        // units a document no longer wants (IDS switched off)
        for unit in suricata::OWNED_UNITS.iter().chain(&[insight::UNIT]) {
            if applied.plan.units.contains_key(*unit) && !p.plan.units.contains_key(*unit) {
                self.run(&Cmd::new("systemctl").args(["stop", unit]), &mut report)?;
            }
        }
        // the IPS queue goes live after Suricata (re)started: without
        // fail-open a queue nobody reads drops everything
        let ips = self.staging.live_dir(suricata::DIR).join(suricata::IPS_NFT);
        if let Some(f) = delta.files.get(&ips) {
            let loaded = nft::load(r, f.contents.as_slice()).map(|_| ());
            if loaded.is_ok() {
                report.commands.push("nft -j -f - (ids queue)".into());
            }
            isolate(
                iso.as_deref_mut(),
                loaded.map_err(EngineError::from),
                "nft",
                "the IDS queue",
                Outcome::LoadFailed,
            )?;
        } else if delta.remove_files.contains(&ips) {
            nft::load(r, suricata::ips_removal().as_str())?;
            report
                .commands
                .push("nft -j -f - (ids queue removed)".into());
        }

        let flow = self.staging.live_dir(insight::DIR).join(insight::NFT);
        if let Some(f) = delta.files.get(&flow) {
            let loaded = nft::load(r, f.contents.as_slice()).map(|_| ());
            if loaded.is_ok() {
                report.commands.push("nft -j -f - (accounting)".into());
            }
            isolate(
                iso,
                loaded.map_err(EngineError::from),
                "nft",
                "the accounting table",
                Outcome::LoadFailed,
            )?;
        } else if delta.remove_files.contains(&flow) {
            nft::load(r, sensr_flow::nft::removal().as_str())?;
            report
                .commands
                .push("nft -j -f - (accounting removed)".into());
        }

        if delta.hooks.contains(&HookLevel::Config) {
            let hooks = Hooks::new(&self.opts.root);
            if let Ok(h) = hooks.run(HookLevel::Config, &[], r) {
                for res in h.results {
                    report.commands.push(format!("hook {}", res.name));
                }
            }
        }
        Ok(report)
    }

    /// Writes the `.link` files of MAC-pinned cards for udev, mirrors them
    /// to `<root>/var/lib/sensr/links` (the boot unit copies that into
    /// `/run/systemd/network` before udev names the cards; `/run` is empty
    /// at boot), and renames cards that carry the wrong name now. Returns
    /// the names of the cards that were renamed.
    fn pin_cards(
        &self,
        p: &Prepared,
        net_dir: &Path,
        report: &mut CommitReport,
    ) -> Result<Vec<String>, EngineError> {
        let is_link = |path: &Path| {
            path.starts_with(net_dir)
                && path.file_name().is_some_and(|n| {
                    let n = n.to_string_lossy();
                    n.starts_with("10-sensr-") && n.ends_with(".link")
                })
        };
        let keep = self.rooted(Path::new("/var/lib/sensr/links"));
        let io = |path: &Path| {
            let path = path.to_owned();
            move |source| EngineError::Io { path, source }
        };
        let wanted: BTreeMap<&Path, &FileSpec> = p
            .plan
            .files
            .iter()
            .filter(|(path, _)| is_link(path))
            .map(|(path, spec)| (path.as_path(), spec))
            .collect();
        if !wanted.is_empty() || keep.exists() {
            std::fs::create_dir_all(&keep).map_err(io(&keep))?;
            std::fs::create_dir_all(net_dir).map_err(io(net_dir))?;
        }
        for (path, spec) in &wanted {
            let Some(name) = path.file_name() else {
                continue;
            };
            for dest in [path.to_path_buf(), keep.join(name)] {
                if std::fs::read(&dest).ok().as_deref() != Some(&spec.contents[..]) {
                    self.write(&dest, spec, report)?;
                }
            }
        }
        // pins that went away
        for dir in [net_dir.to_path_buf(), keep] {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in entries.filter_map(Result::ok) {
                let path = e.path();
                let ours = path.file_name().is_some_and(|n| {
                    let n = n.to_string_lossy();
                    n.starts_with("10-sensr-") && n.ends_with(".link")
                });
                let live = net_dir.join(e.file_name());
                if ours && !wanted.contains_key(live.as_path()) {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        let pins = p.interfaces.pin_map();
        if pins.is_empty() {
            return Ok(Vec::new());
        }
        let nics = crate::inventory::discover(&self.opts.root, self.runner.as_ref());
        let cmds = crate::inventory::renames(&pins, &nics);
        for c in &cmds {
            self.run(c, report)?;
        }
        // the cards that now carry a pinned name they did not have
        Ok(pins
            .iter()
            .filter(|(mac, want)| {
                nics.iter()
                    .any(|n| n.pin_mac() == mac.as_str() && n.name != **want)
            })
            .map(|(_, want)| want.clone())
            .collect())
    }

    /// Waits (up to 10 s) until every VLAN device of `m` exists.
    fn wait_for_links(&self, m: &InterfacesModel) {
        if m.vlans.is_empty() {
            return;
        }
        for _ in 0..20 {
            let Ok(out) = self
                .runner
                .run(&Cmd::new("ip").args(["-j", "link", "show"]), None)
            else {
                return;
            };
            let links =
                serde_json::from_slice::<Vec<serde_json::Value>>(&out.stdout).unwrap_or_default();
            // VLANs that exist and are administratively up
            let up: Vec<&str> = links
                .iter()
                .filter(|l| {
                    l.get("flags")
                        .and_then(|f| f.as_array())
                        .is_some_and(|f| f.iter().any(|x| x == "UP"))
                })
                .filter_map(|l| l.get("ifname")?.as_str())
                .collect();
            if m.vlans.iter().all(|v| up.contains(&v.name.as_str()))
                || !out.success()
                || links.is_empty()
            {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    /// Current global addresses of the document's interfaces (`ip -j addr`),
    /// as [`Runtime::addrs`] wants them: what DHCP or SLAAC gave a link.
    pub fn current_addrs(
        &self,
        doc: &Document,
    ) -> Result<BTreeMap<String, Vec<IfAddr>>, EngineError> {
        let out = self
            .runner
            .run(&Cmd::new("ip").args(["-j", "addr", "show"]), None)?;
        if !out.success() {
            return Err(EngineError::Failed {
                cmd: "ip -j addr show".into(),
                message: out.stderr_text(),
            });
        }
        Ok(parse_ip_addr_json(&out.stdout, doc))
    }

    /// Pushes current interface addresses into the ruleset's sets (one
    /// transaction, no re-render): what to run when DHCP renews with a new
    /// address.
    pub fn update_interface_sets(
        &self,
        doc: &Document,
        addrs: &BTreeMap<String, Vec<IfAddr>>,
    ) -> Result<(), EngineError> {
        let compiled = document::compile(
            doc,
            &Runtime {
                addrs: addrs.clone(),
                sources: None,
            },
        );
        let updates: Vec<_> = compiled
            .interfaces
            .iter()
            .flat_map(|(name, i)| rules_nft::interface_set_updates(name, i))
            .collect();
        let mut buf = Vec::new();
        rules_nft::render_set_updates(&compiled.options.table, &updates, &mut buf).map_err(
            |source| EngineError::Io {
                path: PathBuf::from("<nft set update>"),
                source,
            },
        )?;
        nft::load(self.runner.as_ref(), &buf)?;
        Ok(())
    }
}

impl Engine {
    /// Replaces the contents of the named aliases' sets in one transaction
    /// (alias refresh): no re-render, conntrack state untouched.
    pub fn update_alias_sets(
        &self,
        updates: &[(String, rules_nft::ResolvedAlias)],
    ) -> Result<(), EngineError> {
        if updates.is_empty() {
            return Ok(());
        }
        let sets: Vec<_> = updates
            .iter()
            .flat_map(|(name, a)| rules_nft::alias_set_updates(name, a))
            .collect();
        let mut buf = Vec::new();
        rules_nft::render_set_updates(&rules_nft::Options::default().table, &sets, &mut buf)
            .map_err(|source| EngineError::Io {
                path: PathBuf::from("<nft alias update>"),
                source,
            })?;
        nft::load(self.runner.as_ref(), &buf)?;
        Ok(())
    }
}

impl Engine {
    /// Replaces the contents of the six host-mode sets in one transaction
    /// (the MACs, the locked and the quarantined hosts' current addresses):
    /// no re-render.
    /// Does nothing when no host is in a mode, since the ruleset then
    /// declares none of the sets.
    pub fn update_host_mode_sets(&self, sets: &HostModeSets) -> Result<(), EngineError> {
        if sets.is_empty() {
            return Ok(());
        }
        let mut buf = Vec::new();
        rules_nft::render_set_updates(
            &rules_nft::Options::default().table,
            &host_modes::host_mode_set_updates(sets),
            &mut buf,
        )
        .map_err(|source| EngineError::Io {
            path: PathBuf::from("<nft host-mode update>"),
            source,
        })?;
        nft::load(self.runner.as_ref(), &buf)?;
        Ok(())
    }

    /// Cuts the established flows of `addrs` (a host entering Isolated or
    /// Quarantine): without this they keep matching the conntrack entry and
    /// skip the new rules. Runs `conntrack -D -s <ip>`, `-D -d <ip>` and
    /// `-D -r <ip>` per address: the reply source catches a flow that was
    /// destination-NATed to the host (a port forward, 1:1 NAT), whose
    /// original destination is the router's address. Deleting a conntrack
    /// entry also drops its flowtable offload (the offloaded flow is torn
    /// down with the entry), so no separate flowtable delete is needed.
    /// `conntrack` exits non-zero when nothing matched ("0 flow entries");
    /// that is not an error. A box without the binary (a dev machine) is
    /// skipped with a warning. A command that fails to run is logged and the
    /// rest still run: one address must not keep the others' flows alive.
    pub fn cut_host(&self, addrs: &[IpAddr]) -> Result<(), EngineError> {
        if addrs.is_empty() {
            return Ok(());
        }
        if !self.runner.has_program("conntrack") {
            tracing::warn!("conntrack not found; established flows of locked hosts are not cut");
            return Ok(());
        }
        for addr in addrs {
            let ip = addr.to_string();
            for flag in ["-s", "-d", "-r"] {
                let cmd = Cmd::new("conntrack").args(["-D", flag, ip.as_str()]);
                let out = match self.runner.run(&cmd, None) {
                    Ok(out) => out,
                    Err(e) => {
                        tracing::warn!(cmd = %cmd.display(), error = %e, "conntrack delete did not run");
                        continue;
                    }
                };
                if out.code != Some(0) {
                    let err = String::from_utf8_lossy(&out.stderr);
                    if !err.contains("0 flow entries") {
                        tracing::warn!(cmd = %cmd.display(), stderr = %err.trim(), "conntrack delete failed");
                    }
                }
            }
        }
        Ok(())
    }
}

/// A group's id from `<root>/etc/group`.
fn group_id(root: &Path, name: &str) -> Option<u32> {
    std::fs::read_to_string(root.join("etc/group"))
        .ok()?
        .lines()
        .find_map(|l| {
            let mut f = l.split(':');
            (f.next()? == name).then(|| f.nth(1)?.parse().ok())?
        })
}

/// `ip -j addr show` → logical interface → global addresses.
pub fn parse_ip_addr_json(json: &[u8], doc: &Document) -> BTreeMap<String, Vec<IfAddr>> {
    #[derive(serde::Deserialize)]
    struct Link {
        ifname: String,
        #[serde(default)]
        addr_info: Vec<AddrInfo>,
    }
    #[derive(serde::Deserialize)]
    struct AddrInfo {
        local: Option<IpAddr>,
        prefixlen: Option<u8>,
        scope: Option<String>,
    }
    let links: Vec<Link> = serde_json::from_slice(json).unwrap_or_default();
    let by_dev: BTreeMap<&str, &str> = doc
        .interfaces
        .iter()
        .map(|(id, i)| (i.device.as_str(), id.as_str()))
        .collect();
    let mut out: BTreeMap<String, Vec<IfAddr>> = BTreeMap::new();
    for l in links {
        let Some(id) = by_dev.get(l.ifname.as_str()) else {
            continue;
        };
        for a in l.addr_info {
            if let (Some(addr), Some(prefix_len), Some("global")) =
                (a.local, a.prefixlen, a.scope.as_deref())
            {
                out.entry((*id).to_owned())
                    .or_default()
                    .push(IfAddr { addr, prefix_len });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::{FakeRunner, Output};

    fn home_router() -> Document {
        serde_json::from_str(include_str!(
            "../../sensr-import-opnsense/tests/golden/home-router.sensr.json"
        ))
        .unwrap()
    }

    fn engine(root: &Path) -> (Engine, Arc<FakeRunner>) {
        let runner = Arc::new(FakeRunner::new());
        // a fake /proc/sys with every tunable the slice sets
        let mut keys: Vec<String> = crate::appliers::sysctl::SysctlModel::default()
            .to_map()
            .unwrap()
            .into_keys()
            .collect();
        keys.push("net.core.default_qdisc".into());
        keys.push("kernel.hostname".into());
        for k in keys {
            let path = root.join("proc/sys").join(k.replace('.', "/"));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "0\n").unwrap();
        }
        let e = Engine::new(
            EngineOptions {
                root: root.to_owned(),
                // the path as the box sees it; files land under `root`
                secrets: SecretsDir::default(),
                check: true,
            },
            runner.clone(),
        )
        .unwrap();
        (e, runner)
    }

    #[test]
    fn unbound_check_copy_moves_the_query_log_into_scratch() {
        let root = tempfile::tempdir().unwrap();
        let (e, _) = engine(root.path());
        let scratch = root.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        let mut staged = Vec::new();
        let conf = b"server:\n  logfile: \"/run/unbound/query.log\"\n  log-queries: yes\n";
        let out = e.unbound_check_copy(conf, &scratch, &mut staged).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("/run/unbound"), "{out}");
        assert!(
            out.contains(&format!(
                "logfile: \"{}\"",
                scratch.join("query.log").display()
            )),
            "{out}"
        );
        assert!(out.contains("log-queries: yes"));
        // an empty logfile (logging to stderr/syslog) is left alone
        let out = e
            .unbound_check_copy(b"server:\n  logfile: \"\"\n", &scratch, &mut staged)
            .unwrap();
        assert!(String::from_utf8(out).unwrap().contains("logfile: \"\""));
    }

    #[test]
    fn pinned_cards_get_link_files_for_boot_and_are_renamed_now() {
        use sensr_schema::PathAccess;
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        let (mut e, runner) = engine(r);
        // WAN's card enumerated as eth2, LAN's sits on igc0 (WAN's name)
        crate::inventory::tests::card(
            r,
            "eth2",
            "52:54:00:aa:00:01",
            "pci",
            &["pci0000:00", "0000:00:11.0"],
            "igc",
        );
        crate::inventory::tests::card(
            r,
            "igc0",
            "52:54:00:aa:00:02",
            "usb",
            &["usb2", "2-1:1.0"],
            "r8152",
        );
        let mut doc = home_router();
        doc.set_by_path(
            "interfaces.wan.match_mac",
            serde_json::json!("52:54:00:aa:00:01"),
        )
        .unwrap();
        doc.set_by_path(
            "interfaces.lan.match_mac",
            serde_json::json!("52:54:00:aa:00:02"),
        )
        .unwrap();
        let p = e.prepare(&doc, &Runtime::default()).unwrap();
        e.commit(p).unwrap();
        for dir in ["run/systemd/network", "var/lib/sensr/links"] {
            let f = std::fs::read_to_string(r.join(dir).join("10-sensr-igc0.link")).unwrap();
            assert!(f.contains("PermanentMACAddress=52:54:00:aa:00:01"), "{f}");
            assert!(r.join(dir).join("10-sensr-igc1.link").exists());
        }
        let lines = runner.call_lines();
        let pos = |needle: &str| {
            lines
                .iter()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("{needle} not run: {lines:#?}"))
        };
        // LAN's card frees igc0 through a temporary name, then both move
        assert!(
            pos("'igc0' 'name' 'sensrtmp0'") < pos("'eth2' 'name' 'igc0'"),
            "{lines:#?}"
        );
        assert!(
            pos("'sensrtmp0' 'name' 'igc1'") < pos("networkctl 'reload'"),
            "{lines:#?}"
        );
        assert!(
            pos("networkctl 'reload'") < pos("'reconfigure' 'igc0'"),
            "{lines:#?}"
        );

        // dropping a pin removes its files
        doc.set_by_path("interfaces.lan.match_mac", serde_json::Value::Null)
            .unwrap();
        let p = e.prepare(&doc, &Runtime::default()).unwrap();
        e.commit(p).unwrap();
        for dir in ["run/systemd/network", "var/lib/sensr/links"] {
            assert!(r.join(dir).join("10-sensr-igc0.link").exists());
            assert!(!r.join(dir).join("10-sensr-igc1.link").exists(), "{dir}");
        }
    }

    #[test]
    fn first_commit_runs_every_stage_in_order_then_noop() {
        let root = tempfile::tempdir().unwrap();
        let (mut e, runner) = engine(root.path());
        let doc = home_router();
        let p = e.prepare(&doc, &Runtime::default()).unwrap();
        assert!(p.warnings.is_empty(), "{:?}", p.warnings);
        let report = e.commit(p).unwrap();
        assert!(report.nft_loaded);
        let lines = runner.call_lines();
        let pos = |needle: &str| {
            lines
                .iter()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("{needle} not run: {lines:#?}"))
        };
        // links before the ruleset, the ruleset before the services
        // (the checkers run first: `nft -c`, then the commit)
        assert!(pos("nft '-c'") < pos("networkctl"), "{lines:#?}");
        assert!(pos("networkctl") < pos("nft '-j'"), "{lines:#?}");
        assert!(pos("nft '-j'") < pos("systemctl"), "{lines:#?}");
        assert!(
            root.path()
                .join("run/systemd/network/40-sensr-igc1.network")
                .exists()
        );
        assert!(root.path().join("run/sensr/kea/kea-dhcp4.conf").exists());
        assert!(
            root.path()
                .join("var/lib/sensr/secrets/wireguard/wg0.key")
                .exists()
        );
        assert_eq!(
            std::fs::read_to_string(root.path().join("proc/sys/net/ipv4/ip_forward"))
                .unwrap()
                .trim(),
            "1"
        );
        assert_eq!(
            std::fs::read_to_string(root.path().join("proc/sys/kernel/hostname"))
                .unwrap()
                .trim(),
            doc.system.hostname.to_string()
        );

        // the same document again: nothing to do
        let before = runner.calls().len();
        let p = e.prepare(&doc, &Runtime::default()).unwrap();
        assert!(e.delta(&p).is_empty(), "{}", e.dry_run(&p));
        let again = e.commit(p).unwrap();
        assert!(!again.nft_loaded);
        let new_calls: Vec<String> = runner.call_lines()[before..].to_vec();
        // only the checkers ran (nft -c and friends), no changes
        assert!(
            new_calls
                .iter()
                .all(|c| c.contains("-c") || c.contains("-t") || c.contains("checkconf")),
            "{new_calls:#?}"
        );
    }

    #[test]
    fn ids_lifecycle_detect_prevent_off() {
        use sensr_schema::models::ids::IdsMode;
        let root = tempfile::tempdir().unwrap();
        let (mut e, runner) = engine(root.path());
        let mut doc = home_router();
        doc.ids.enabled = true;
        let p = e.prepare(&doc, &Runtime::default()).unwrap();
        e.commit(p).unwrap();
        let dir = root.path().join("run/sensr/suricata");
        for f in [
            "suricata.yaml",
            "vars.yaml",
            "threshold.config",
            "update.args",
        ] {
            assert!(dir.join(f).exists(), "{f}");
        }
        assert!(
            root.path()
                .join("run/systemd/system/sensr-suricata-update.timer.d/50-sensr.conf")
                .exists()
        );
        let lines = runner.call_lines();
        let has = |l: &[String], needle: &str| l.iter().any(|c| c.contains(needle));
        assert!(has(&lines, "daemon-reload"), "{lines:#?}");
        assert!(
            has(&lines, "'restart' 'sensr-suricata.service'"),
            "{lines:#?}"
        );
        assert!(has(
            &lines,
            "'restart' 'sensr-suricata-update-trigger.service'"
        ));

        // detect -> prevent: restart, and the queue table goes in after it
        let before = runner.calls().len();
        doc.ids.mode = IdsMode::Prevent;
        let p = e.prepare(&doc, &Runtime::default()).unwrap();
        let r = e.commit(p).unwrap();
        let new = runner.call_lines()[before..].to_vec();
        assert!(has(&new, "'restart' 'sensr-suricata.service'"), "{new:#?}");
        let restart = r
            .commands
            .iter()
            .position(|c| c.contains("sensr-suricata.service"));
        let queue = r.commands.iter().position(|c| c.contains("ids queue"));
        assert!(restart < queue && queue.is_some(), "{:#?}", r.commands);
        assert!(
            !has(&new, "update-trigger"),
            "rule lists unchanged: no download"
        );

        // a new WAN lease only rewrites HOME_NET and reloads the rules
        let before = runner.calls().len();
        let addrs = BTreeMap::from([(
            "wan".to_owned(),
            vec![IfAddr {
                addr: "198.51.100.7".parse().unwrap(),
                prefix_len: 24,
            }],
        )]);
        assert!(e.update_ids_home_net(&doc, &addrs).unwrap());
        assert!(!e.update_ids_home_net(&doc, &addrs).unwrap(), "idempotent");
        let vars = std::fs::read_to_string(dir.join("vars.yaml")).unwrap();
        assert!(vars.contains("198.51.100.7/32"), "{vars}");
        let new = runner.call_lines()[before..].to_vec();
        assert_eq!(new.len(), 1, "{new:#?}");
        assert!(new[0].contains("sensr-suricata-reload.service"));

        // off: units stopped, queue table removed, files gone
        let before = runner.calls().len();
        doc.ids.enabled = false;
        let p = e.prepare(&doc, &Runtime::default()).unwrap();
        let r = e.commit(p).unwrap();
        let new = runner.call_lines()[before..].to_vec();
        assert!(has(&new, "'stop' 'sensr-suricata.service'"), "{new:#?}");
        assert!(
            has(&new, "'stop' 'sensr-suricata-update.timer'"),
            "{new:#?}"
        );
        assert!(r.commands.iter().any(|c| c.contains("ids queue removed")));
        assert!(!dir.join("suricata.yaml").exists());
    }

    /// Makes `program`'s checker reject everything while `on` holds.
    fn reject_while(
        runner: &FakeRunner,
        program: &'static str,
        on: Arc<std::sync::atomic::AtomicBool>,
    ) {
        runner.respond(move |cmd, _| {
            (cmd.display().starts_with(&format!("{program} "))
                && on.load(std::sync::atomic::Ordering::SeqCst))
            .then(|| Output::failed(1, format!("{program}: environment problem")))
        });
    }

    fn has(lines: &[String], needle: &str) -> bool {
        lines.iter().any(|l| l.contains(needle))
    }

    const UNBOUND_CONF: &str = "run/sensr/unbound/unbound.conf";

    #[test]
    fn boot_apply_on_a_fresh_boot_skips_only_the_rejected_daemon() {
        let root = tempfile::tempdir().unwrap();
        let (mut e, runner) = engine(root.path());
        let failing = Arc::new(std::sync::atomic::AtomicBool::new(true));
        reject_while(&runner, "unbound-checkconf", failing.clone());
        let doc = home_router();
        let p = e.prepare(&doc, &Runtime::default()).unwrap();
        let (report, degraded) = e.commit_isolated(p).unwrap();

        // everything else applied and started
        assert!(report.nft_loaded);
        let lines = runner.call_lines();
        assert!(has(&lines, "nft '-j'"), "{lines:#?}");
        assert!(
            has(&lines, "'reload-or-restart' 'sensr-kea-dhcp4.service'"),
            "{lines:#?}"
        );
        assert!(has(&lines, "'restart' 'sensr-ntpd.service'"), "{lines:#?}");
        assert!(root.path().join("run/sensr/kea/kea-dhcp4.conf").exists());
        assert!(root.path().join("run/sensr/ntp/ntp.toml").exists());
        // unbound: no file to fall back to, so not started
        assert!(!root.path().join(UNBOUND_CONF).exists());
        assert!(!has(&lines, "sensr-unbound.service"), "{lines:#?}");
        assert_eq!(degraded.len(), 1, "{degraded:?}");
        assert_eq!(degraded[0].backend, "unbound-checkconf");
        assert_eq!(degraded[0].unit.as_deref(), Some("sensr-unbound.service"));
        assert_eq!(degraded[0].outcome, Outcome::NotStarted);
        assert!(degraded[0].message.contains("environment problem"));
        assert!(
            degraded[0].to_string().contains("was not started"),
            "{}",
            degraded[0]
        );

        // an interactive commit stays all or nothing while the checker
        // still rejects it
        let p = e.prepare(&doc, &Runtime::default()).unwrap();
        let err = e.commit(p).unwrap_err();
        assert!(
            matches!(
                err,
                EngineError::Rejected {
                    backend: "unbound-checkconf",
                    ..
                }
            ),
            "{err}"
        );
        // once the checker accepts it, the next commit of the same document
        // writes the held-back file and starts the resolver
        failing.store(false, std::sync::atomic::Ordering::SeqCst);
        let before = runner.calls().len();
        let p = e.prepare(&doc, &Runtime::default()).unwrap();
        e.commit(p).unwrap();
        let lines = runner.call_lines()[before..].to_vec();
        assert!(root.path().join(UNBOUND_CONF).exists());
        assert!(
            has(&lines, "'reload-or-restart' 'sensr-unbound.service'"),
            "{lines:#?}"
        );
    }

    #[test]
    fn boot_apply_restarts_a_rejected_daemon_with_its_previous_file() {
        let root = tempfile::tempdir().unwrap();
        let (mut e, runner) = engine(root.path());
        let conf = root.path().join(UNBOUND_CONF);
        std::fs::create_dir_all(conf.parent().unwrap()).unwrap();
        std::fs::write(&conf, "server:\n  # previous\n").unwrap();
        reject_while(
            &runner,
            "unbound-checkconf",
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        );
        let p = e.prepare(&home_router(), &Runtime::default()).unwrap();
        let (_, degraded) = e.commit_isolated(p).unwrap();
        assert_eq!(
            std::fs::read_to_string(&conf).unwrap(),
            "server:\n  # previous\n"
        );
        let lines = runner.call_lines();
        assert!(
            has(&lines, "'reload-or-restart' 'sensr-unbound.service'"),
            "{lines:#?}"
        );
        assert!(
            has(&lines, "'reload-or-restart' 'sensr-kea-dhcp4.service'"),
            "{lines:#?}"
        );
        assert_eq!(degraded.len(), 1, "{degraded:?}");
        assert_eq!(degraded[0].outcome, Outcome::KeptPrevious);
        assert!(degraded[0].to_string().contains("previous configuration"));
    }

    /// `nft -c` rejects every ruleset; `fresh`: the kernel holds no
    /// `inet sensr` table (`nft list table` fails).
    fn reject_nft(runner: &FakeRunner, fresh: bool) {
        runner.respond(move |cmd, _| {
            let line = cmd.display();
            if !line.starts_with("nft ") {
                return None;
            }
            if line.contains("'-c'") {
                return Some(Output::failed(1, "Error: syntax error\n  in line 3"));
            }
            (fresh && line.contains("'list'"))
                .then(|| Output::failed(1, "Error: No such file or directory"))
        });
    }

    /// The rulesets fed to `nft -j -f -` (not `-c`), in order.
    fn nft_loads(runner: &FakeRunner) -> Vec<String> {
        runner
            .calls()
            .into_iter()
            .filter(|c| c.cmd.display() == "nft '-j' '-f' '-'")
            .map(|c| String::from_utf8(c.stdin.unwrap_or_default()).unwrap())
            .collect()
    }

    #[test]
    fn boot_apply_isolates_kea_and_nft_rejections() {
        let root = tempfile::tempdir().unwrap();
        let (mut e, runner) = engine(root.path());
        reject_while(
            &runner,
            "kea-dhcp4",
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
        );
        reject_nft(&runner, true);
        let p = e.prepare(&home_router(), &Runtime::default()).unwrap();
        let inside = p.inside.clone();
        assert!(inside.contains(&"igc1".to_owned()) && !inside.contains(&"igc0".to_owned()));
        let (report, degraded) = e.commit_isolated(p).unwrap();
        // the real ruleset is not loaded; the emergency firewall is
        assert!(!report.nft_loaded);
        let loads = nft_loads(&runner);
        assert_eq!(loads.len(), 1, "{loads:#?}");
        assert_eq!(loads[0], emergency::ruleset(&inside));
        let lines = runner.call_lines();
        assert!(!has(&lines, "sensr-kea-dhcp4.service"), "{lines:#?}");
        assert!(!root.path().join("run/sensr/kea/kea-dhcp4.conf").exists());
        assert!(
            has(&lines, "'reload-or-restart' 'sensr-unbound.service'"),
            "{lines:#?}"
        );
        assert!(has(&lines, "'restart' 'sensr-ntpd.service'"), "{lines:#?}");
        // links still came up
        assert!(
            root.path()
                .join("run/systemd/network/40-sensr-igc1.network")
                .exists()
        );
        let got: Vec<_> = degraded.iter().map(|d| (d.backend, d.outcome)).collect();
        assert_eq!(
            got,
            [
                ("kea-dhcp4", Outcome::NotStarted),
                ("nft", Outcome::EmergencyFirewall)
            ],
            "{degraded:?}"
        );
        assert_eq!(
            degraded[1].to_string(),
            "emergency firewall active: Error: syntax error in line 3"
        );
    }

    #[test]
    fn boot_apply_after_an_agent_restart_keeps_the_loaded_ruleset() {
        let root = tempfile::tempdir().unwrap();
        let (mut e, runner) = engine(root.path());
        reject_nft(&runner, false);
        let p = e.prepare(&home_router(), &Runtime::default()).unwrap();
        let (_, degraded) = e.commit_isolated(p).unwrap();
        assert!(nft_loads(&runner).is_empty(), "{:#?}", nft_loads(&runner));
        assert_eq!(degraded.len(), 1, "{degraded:?}");
        assert_eq!(degraded[0].outcome, Outcome::PreviousFirewall);
    }

    #[test]
    fn the_next_good_commit_replaces_the_emergency_firewall() {
        let root = tempfile::tempdir().unwrap();
        let (mut e, runner) = engine(root.path());
        let rejecting = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let on = rejecting.clone();
        runner.respond(move |cmd, _| {
            let line = cmd.display();
            (line.starts_with("nft ") && on.load(std::sync::atomic::Ordering::SeqCst))
                .then(|| Output::failed(1, "Error: syntax error"))
                .filter(|_| line.contains("'-c'") || line.contains("'list'"))
        });
        let doc = home_router();
        let p = e.prepare(&doc, &Runtime::default()).unwrap();
        e.commit_isolated(p).unwrap();
        assert_eq!(nft_loads(&runner).len(), 1);
        rejecting.store(false, std::sync::atomic::Ordering::SeqCst);
        let p = e.prepare(&doc, &Runtime::default()).unwrap();
        let report = e.commit(p).unwrap();
        assert!(report.nft_loaded);
        let loads = nft_loads(&runner);
        assert_eq!(loads.len(), 3, "{loads:#?}");
        assert!(loads[1].contains("\"name\":\"sensr\""));
        assert_eq!(loads[2], emergency::removal());
    }

    #[test]
    fn boot_apply_carries_on_past_a_unit_that_fails_to_start() {
        let root = tempfile::tempdir().unwrap();
        let (mut e, runner) = engine(root.path());
        runner.respond(|cmd, _| {
            let line = cmd.display();
            (line.starts_with("systemctl ")
                && (line.contains("sensr-kea-dhcp4") || line.contains("'sensr-suricata.service'")))
            .then(|| Output::failed(1, "Job failed.\nSee journalctl -xeu for details."))
        });
        let mut doc = home_router();
        doc.ids.enabled = true;
        let p = e.prepare(&doc, &Runtime::default()).unwrap();
        let (report, degraded) = e.commit_isolated(p).unwrap();
        let lines = runner.call_lines();
        let pos = |needle: &str| {
            lines
                .iter()
                .position(|l| l.contains(needle))
                .unwrap_or_else(|| panic!("{needle} not run: {lines:#?}"))
        };
        // resolver and DHCP first, then the rest, failures or not
        assert!(pos("'sensr-unbound.service'") < pos("'sensr-kea-dhcp4.service'"));
        assert!(pos("'sensr-kea-dhcp4.service'") < pos("'sensr-ntpd.service'"));
        assert!(has(&lines, "'restart' 'sensr-ntpd.service'"), "{lines:#?}");
        assert!(has(&lines, "'sensr-dns-watch.service'"), "{lines:#?}");
        // the IDS queue still loaded after the failed Suricata start
        assert!(
            report.commands.iter().any(|c| c.ends_with("(ids queue)")),
            "{:#?}",
            report.commands
        );
        let failed: Vec<_> = degraded
            .iter()
            .map(|d| (d.unit.as_deref().unwrap(), d.outcome))
            .collect();
        assert_eq!(
            failed,
            [
                ("sensr-kea-dhcp4.service", Outcome::StartFailed),
                ("sensr-suricata.service", Outcome::StartFailed)
            ],
            "{degraded:?}"
        );
        assert_eq!(
            degraded[0].to_string(),
            "sensr-kea-dhcp4.service failed to start: Job failed. See journalctl -xeu for details."
        );

        // a commit still stops at the first failure
        let root = tempfile::tempdir().unwrap();
        let (mut e, runner) = engine(root.path());
        runner.respond(|cmd, _| {
            cmd.display()
                .contains("sensr-kea-dhcp4")
                .then(|| Output::failed(1, "Job failed."))
        });
        let p = e.prepare(&home_router(), &Runtime::default()).unwrap();
        assert!(matches!(e.commit(p), Err(EngineError::Failed { .. })));
    }

    #[test]
    fn boot_apply_treats_a_checker_that_cannot_run_as_its_rejection() {
        use crate::cmd::{CmdError, StdinWriter};
        /// unbound-checkconf cannot be spawned
        struct NoUnbound(FakeRunner);
        impl Runner for NoUnbound {
            fn run(&self, cmd: &Cmd, stdin: Option<StdinWriter<'_>>) -> Result<Output, CmdError> {
                if cmd.display().starts_with("unbound-checkconf ") {
                    return Err(CmdError::Spawn {
                        cmd: cmd.display(),
                        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                    });
                }
                self.0.run(cmd, stdin)
            }
            fn has_program(&self, p: &str) -> bool {
                self.0.has_program(p)
            }
        }
        let root = tempfile::tempdir().unwrap();
        let (base, _) = engine(root.path());
        drop(base); // only for the fake /proc/sys
        let runner = Arc::new(NoUnbound(FakeRunner::new()));
        let mut e = Engine::new(
            EngineOptions {
                root: root.path().to_owned(),
                secrets: SecretsDir::default(),
                check: true,
            },
            runner.clone(),
        )
        .unwrap();
        // ntp's scratch copy cannot be written: a directory sits there
        std::fs::create_dir_all(root.path().join("run/sensr/.check/ntp.toml/x")).unwrap();
        let p = e.prepare(&home_router(), &Runtime::default()).unwrap();
        let (_, degraded) = e.commit_isolated(p).unwrap();
        let got: Vec<_> = degraded
            .iter()
            .map(|d| (d.backend, d.unit.as_deref().unwrap(), d.outcome))
            .collect();
        assert_eq!(
            got,
            [
                ("ntp-ctl", "sensr-ntpd.service", Outcome::NotStarted),
                (
                    "unbound-checkconf",
                    "sensr-unbound.service",
                    Outcome::NotStarted
                )
            ],
            "{degraded:?}"
        );
        assert!(degraded.iter().all(|d| d.message.contains("could not run")));
        let lines = runner.0.call_lines();
        assert!(
            has(&lines, "'reload-or-restart' 'sensr-kea-dhcp4.service'"),
            "{lines:#?}"
        );
        assert!(has(&lines, "nft '-j'"), "{lines:#?}");

        // a commit: the same failure refuses everything
        let p = e.prepare(&home_router(), &Runtime::default()).unwrap();
        assert!(e.commit(p).is_err());
    }

    #[test]
    fn degraded_messages_are_one_short_line() {
        let d = Degraded {
            backend: "unbound-checkconf",
            unit: Some("sensr-unbound.service".into()),
            message: format!("line 1\n\tline 2 {}", "x".repeat(400)),
            outcome: Outcome::NotStarted,
        };
        let text = d.to_string();
        assert!(!text.contains('\n') && !text.contains('\t'), "{text}");
        assert!(text.contains(": line 1 line 2 xxx"), "{text}");
        assert!(text.ends_with('…'), "{text}");
        let msg = text.split_once(": ").unwrap().1;
        assert_eq!(msg.chars().count(), MAX_MESSAGE);
    }

    #[test]
    fn boot_apply_starts_every_daemon_even_when_nothing_changed() {
        // A NixOS switch stops the daemons with the agent (PartOf=); the
        // files in /run/sensr and the engine's own view are unchanged, but
        // the restarted agent must still start them.
        let root = tempfile::tempdir().unwrap();
        let (mut e, runner) = engine(root.path());
        let doc = home_router();
        let p = e.prepare(&doc, &Runtime::default()).unwrap();
        e.commit(p).unwrap();
        let before = runner.calls().len();
        let p = e.prepare(&doc, &Runtime::default()).unwrap();
        assert!(e.delta(&p).is_empty());
        let (_, degraded) = e.commit_isolated(p).unwrap();
        assert!(degraded.is_empty(), "{degraded:?}");
        let lines = runner.call_lines()[before..].to_vec();
        for unit in [
            "sensr-unbound.service",
            "sensr-kea-dhcp4.service",
            "sensr-ntpd.service",
            "sensr-dns-watch.service",
        ] {
            assert!(has(&lines, &format!("' '{unit}'")), "{unit}: {lines:#?}");
        }
        assert!(has(&lines, "nft '-j'"), "{lines:#?}");
    }

    #[test]
    fn rejected_ruleset_changes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let (mut e, runner) = engine(root.path());
        runner.push("nft", Output::failed(1, "Error: syntax error"));
        let p = e.prepare(&home_router(), &Runtime::default()).unwrap();
        let err = e.commit(p).unwrap_err();
        assert!(
            matches!(err, EngineError::Rejected { backend: "nft", .. }),
            "{err}"
        );
        assert!(!root.path().join("run/systemd/network").exists());
    }

    #[test]
    fn cut_host_deletes_conntrack() {
        let root = tempfile::tempdir().unwrap();
        let (e, runner) = engine(root.path());
        runner.push(
            "conntrack",
            Output::failed(
                1,
                "conntrack v1.4.8 (conntrack-tools): 0 flow entries have been deleted.",
            ),
        );
        e.cut_host(&["192.168.68.50".parse().unwrap()]).unwrap();
        assert_eq!(
            runner.call_lines(),
            [
                "conntrack '-D' '-s' '192.168.68.50'",
                "conntrack '-D' '-d' '192.168.68.50'",
                "conntrack '-D' '-r' '192.168.68.50'"
            ]
        );
        e.cut_host(&[]).unwrap();
        assert_eq!(runner.calls().len(), 3, "no addresses, no commands");
    }

    /// One command that fails to run does not abort the others.
    #[test]
    fn cut_host_continues_past_a_spawn_error() {
        use crate::cmd::{CmdError, Runner, StdinWriter};
        struct FailFirst(FakeRunner, std::sync::Mutex<bool>);
        impl Runner for FailFirst {
            fn run(&self, cmd: &Cmd, stdin: Option<StdinWriter<'_>>) -> Result<Output, CmdError> {
                let out = self.0.run(cmd, stdin);
                if std::mem::replace(&mut *self.1.lock().unwrap(), false) {
                    return Err(CmdError::Spawn {
                        cmd: cmd.display(),
                        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
                    });
                }
                out
            }
            fn has_program(&self, p: &str) -> bool {
                self.0.has_program(p)
            }
        }
        let root = tempfile::tempdir().unwrap();
        let runner = Arc::new(FailFirst(FakeRunner::new(), std::sync::Mutex::new(true)));
        let e = Engine::new(
            EngineOptions {
                root: root.path().to_owned(),
                ..EngineOptions::default()
            },
            runner.clone(),
        )
        .unwrap();
        e.cut_host(&[
            "192.168.68.50".parse().unwrap(),
            "fd00::51".parse().unwrap(),
        ])
        .unwrap();
        assert_eq!(
            runner.0.call_lines(),
            [
                "conntrack '-D' '-s' '192.168.68.50'",
                "conntrack '-D' '-d' '192.168.68.50'",
                "conntrack '-D' '-r' '192.168.68.50'",
                "conntrack '-D' '-s' 'fd00::51'",
                "conntrack '-D' '-d' 'fd00::51'",
                "conntrack '-D' '-r' 'fd00::51'"
            ]
        );
    }

    #[test]
    fn cut_host_skips_a_missing_conntrack() {
        let root = tempfile::tempdir().unwrap();
        let (e, runner) = engine(root.path());
        runner.without_program("conntrack");
        e.cut_host(&["fd00::20".parse().unwrap()]).unwrap();
        assert!(runner.calls().is_empty());
    }

    #[test]
    fn host_mode_sets_are_pushed_only_when_a_host_is_in_a_mode() {
        let root = tempfile::tempdir().unwrap();
        let (e, runner) = engine(root.path());
        e.update_host_mode_sets(&HostModeSets::default()).unwrap();
        assert!(
            runner.calls().is_empty(),
            "no sets declared, nothing pushed"
        );
        let sets = HostModeSets {
            quarantine: vec!["02:00:00:00:00:01".parse().unwrap()],
            locked_v4: vec!["192.168.1.20".parse().unwrap()],
            locked_v6: vec!["fd00::20".parse().unwrap()],
            quarantine_v4: vec!["192.168.1.20".parse().unwrap()],
            ..HostModeSets::default()
        };
        e.update_host_mode_sets(&sets).unwrap();
        let calls = runner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].cmd.display(), "nft '-j' '-f' '-'");
        let text = String::from_utf8(calls[0].stdin.clone().unwrap()).unwrap();
        for set in [
            "host_isolated",
            "host_quarantine",
            "host_locked_v4",
            "host_locked_v6",
            "host_quarantine_v4",
            "host_quarantine_v6",
            "02:00:00:00:00:01",
            "192.168.1.20",
            "fd00::20",
        ] {
            assert!(text.contains(set), "{set} missing from {text}");
        }
    }

    #[test]
    fn ip_addr_json_maps_devices_to_interfaces() {
        let json = br#"[{"ifname":"igc0","addr_info":[{"family":"inet","local":"203.0.113.2","prefixlen":24,"scope":"global"},{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]},{"ifname":"eth9","addr_info":[]}]"#;
        let m = parse_ip_addr_json(json, &home_router());
        assert_eq!(m.len(), 1);
        assert_eq!(m["wan"][0].addr.to_string(), "203.0.113.2");
    }
}
