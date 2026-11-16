//! The slice apply engine: document → plan → check → commit, in stage order,
//! against a root directory and a [`Runner`] (both injectable, so the whole
//! sequence is tested without root). OPNsense counterpart: configd's
//! reconfigure actions plus `rc.filter_configure`.
//!
//! Order of a commit: secrets → sysctls → interface files + networkd →
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
use sensr_rules::ir::IfAddr;
use sensr_rules::render::nft as rules_nft;
use sensr_schema::Document;

use crate::appliers::convert::{self, ConvertError, SecretsDir};
use crate::appliers::interfaces::InterfacesModel;
use crate::appliers::sysctl::{Sysctl, SysctlApplyError};
use crate::appliers::{SliceError, SliceModels, kea, nft, unbound};
use crate::cmd::{Cmd, CmdError, Runner};
use crate::hooks::{HookLevel, Hooks};
use crate::plan::{FileSpec, Plan, UnitAction};
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
        let interfaces = InterfacesModel::from_document(doc);
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
            secrets,
        })
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

    /// Runs every backend checker on `p`; nothing goes live.
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
        // stage the files a checker reads, check, throw the copies away
        let scratch = self.opts.root.join("run/sensr/.check");
        let mut staged = Vec::new();
        for (path, spec) in &p.plan.files {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            let checker: Option<(&'static str, Checker)> = match name.as_deref() {
                Some("kea-dhcp4.conf") => Some(("kea-dhcp4", kea::check)),
                Some("unbound.conf") => Some(("unbound-checkconf", unbound::check)),
                _ => None,
            };
            if let Some((backend, f)) = checker {
                let tmp = scratch.join(name.unwrap_or_default());
                write_atomic(&tmp, &spec.contents, spec.mode)?;
                staged.push(tmp.clone());
                if let Some(msg) = f(r, &tmp)?
                    && !msg.is_empty()
                {
                    for s in &staged {
                        let _ = std::fs::remove_file(s);
                    }
                    return Err(EngineError::Rejected {
                        backend,
                        message: msg,
                    });
                }
            }
        }
        for s in &staged {
            let _ = std::fs::remove_file(s);
        }
        Ok(())
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

    /// Checks (when enabled), then makes the system match `p`.
    pub fn commit(&mut self, p: Prepared) -> Result<CommitReport, EngineError> {
        if self.opts.check {
            self.check(&p)?;
        }
        let result = self.commit_inner(&p);
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

    fn commit_inner(&self, p: &Prepared) -> Result<CommitReport, EngineError> {
        let mut report = CommitReport::default();
        let delta = self.delta(p);
        let empty = Applied {
            plan: Plan::default(),
            models: SliceModels::default(),
            interfaces: InterfacesModel::default(),
        };
        let applied = self.applied.as_ref().unwrap_or(&empty);
        let r = self.runner.as_ref();

        for (path, contents) in &p.secrets {
            write_atomic(path, contents.as_bytes(), 0o640)?;
        }

        if !delta.sysctls.is_empty() {
            Sysctl::new(&self.opts.root).apply(&p.models.sysctl)?;
            for (k, v) in p.models.qdisc.sysctls() {
                if delta.sysctls.contains_key(&k) {
                    let path = self.opts.root.join("proc/sys").join(k.replace('.', "/"));
                    std::fs::write(&path, format!("{v}\n"))
                        .map_err(|source| EngineError::Io { path, source })?;
                }
            }
        }

        // links first: everything else refers to devices and addresses
        let net_dir = self.staging.live_dir("run/systemd/network");
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
        for c in p.interfaces.commands(&applied.interfaces) {
            self.run(&c, &mut report)?;
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

        for (unit, spec) in &delta.units {
            let verb = match spec.action {
                UnitAction::Reload => "reload-or-restart",
                UnitAction::Restart => "restart",
            };
            self.run(
                &Cmd::new("systemctl").args([verb, unit.as_str()]),
                &mut report,
            )?;
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
    fn ip_addr_json_maps_devices_to_interfaces() {
        let json = br#"[{"ifname":"igc0","addr_info":[{"family":"inet","local":"203.0.113.2","prefixlen":24,"scope":"global"},{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]},{"ifname":"eth9","addr_info":[]}]"#;
        let m = parse_ip_addr_json(json, &home_router());
        assert_eq!(m.len(), 1);
        assert_eq!(m["wan"][0].addr.to_string(), "203.0.113.2");
    }
}
