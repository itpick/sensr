//! The real apply pipeline for the routing slice: [`sensr_apply::engine`]
//! (networkd links, the `sensr-rules` nft ruleset, Kea, Unbound, WireGuard,
//! sysctls, qdiscs) behind the agent's [`Applier`] boundary.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sensr_apply::cmd::{Runner, SystemRunner};
use sensr_apply::engine::{Engine, EngineError, EngineOptions, Prepared};
use sensr_apply::plan::UnitAction;
use sensr_ipc::{FileDiff, PlanView, ServiceAction, ServiceChange, ValidationIssue};
use sensr_rules::document::Runtime;
use sensr_rules::ir::IfAddr;
use sensr_schema::Document;
use serde_json::Value;

use crate::applier::{Applier, ApplyError};
use crate::diff::unified_text;

/// The applied document and the link addresses its ruleset knows.
type Applied = Option<(Document, BTreeMap<String, Vec<IfAddr>>)>;

/// Applies documents to the host through [`Engine`].
pub struct SliceApplier {
    engine: Arc<Mutex<Engine>>,
    applied: Arc<Mutex<Applied>>,
    watch: Option<Duration>,
    watching: bool,
}

/// How often link addresses are compared with the ruleset's sets.
const ADDRESS_POLL: Duration = Duration::from_secs(2);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // a panic mid-apply leaves nothing half-held worth protecting
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl SliceApplier {
    /// On the host (`/`, real commands), following address changes.
    pub fn system() -> Result<SliceApplier, EngineError> {
        let opts = EngineOptions {
            // under /run/sensr (0755): networkd must reach the WireGuard
            // keys, which /var/lib/sensr (0700) would hide
            secrets: sensr_apply::appliers::convert::SecretsDir("/run/sensr/secrets".into()),
            ..EngineOptions::default()
        };
        let mut a = Self::new(opts, Arc::new(SystemRunner))?;
        a.watch = Some(ADDRESS_POLL);
        Ok(a)
    }

    /// With explicit options and runner, without the address watcher (tests).
    pub fn new(opts: EngineOptions, runner: Arc<dyn Runner>) -> Result<SliceApplier, EngineError> {
        Ok(SliceApplier {
            engine: Arc::new(Mutex::new(Engine::new(opts, runner)?)),
            applied: Arc::new(Mutex::new(None)),
            watch: None,
            watching: false,
        })
    }

    fn engine(&self) -> std::sync::MutexGuard<'_, Engine> {
        lock(&self.engine)
    }

    /// Links get their addresses after the apply (DHCP, SLAAC, tracked
    /// prefixes) and keep changing them; the ruleset's interface sets follow
    /// without a re-render.
    fn start_watcher(&mut self) {
        let (Some(every), false) = (self.watch, self.watching) else {
            return;
        };
        self.watching = true;
        let engine = Arc::clone(&self.engine);
        let applied = Arc::clone(&self.applied);
        std::thread::Builder::new()
            .name("sensr-addr-watch".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(every);
                    let mut cur = lock(&applied);
                    let Some((doc, known)) = cur.as_mut() else {
                        continue;
                    };
                    let e = lock(&engine);
                    let Ok(now) = e.current_addrs(doc) else {
                        continue;
                    };
                    if now == *known {
                        continue;
                    }
                    match e.update_interface_sets(doc, &now) {
                        Ok(()) => {
                            tracing::info!(addresses = ?now, "interface sets updated");
                            *known = now;
                        }
                        Err(err) => tracing::warn!(error = %err, "updating interface sets"),
                    }
                }
            })
            .map(|_| ())
            .unwrap_or_else(|e| tracing::error!(error = %e, "address watcher not started"));
    }
}

fn issue(path: &str, message: impl Into<String>) -> ValidationIssue {
    let mut message = message.into();
    if !message.ends_with('.') {
        message.push('.');
    }
    ValidationIssue {
        path: path.to_owned(),
        message,
    }
}

/// Parses and validates a stored document.
fn document(v: &Value) -> Result<Document, ApplyError> {
    let doc: Document = serde_json::from_value(v.clone())
        .map_err(|e| ApplyError::Invalid(vec![issue("", format!("not a sensr document: {e}"))]))?;
    let v = doc.validate();
    if !v.is_empty() {
        tracing::warn!(issues = ?v, "document does not validate");
        return Err(ApplyError::Invalid(
            v.iter()
                .flat_map(|(path, errs)| {
                    errs.iter()
                        .map(move |e| issue(&path.to_string(), e.message.clone()))
                })
                .collect(),
        ));
    }
    Ok(doc)
}

fn prepare(
    engine: &Engine,
    doc: &Document,
) -> Result<(Prepared, BTreeMap<String, Vec<IfAddr>>), EngineError> {
    // what DHCP/SLAAC gave the links right now; sets follow later changes
    let addrs = engine.current_addrs(doc).unwrap_or_default();
    let p = engine.prepare(
        doc,
        &Runtime {
            addrs: addrs.clone(),
            sources: None,
        },
    )?;
    Ok((p, addrs))
}

fn rejected(e: EngineError) -> ApplyError {
    tracing::warn!(error = %e, "apply engine");
    match e {
        EngineError::Rejected { backend, message } => {
            ApplyError::Invalid(vec![issue(backend, message.trim().to_owned())])
        }
        other => ApplyError::Failed(other.to_string()),
    }
}

impl Applier for SliceApplier {
    fn plan(&self, running: Option<&Value>, next: &Value) -> Result<PlanView, ApplyError> {
        let doc = document(next)?;
        let engine = self.engine();
        let (p, _) = prepare(&engine, &doc).map_err(rejected)?;
        engine.check(&p).map_err(rejected)?;
        let delta = engine.delta(&p);
        let old_ruleset = match running.map(document) {
            Some(Ok(old)) => prepare(&engine, &old)
                .map(|(o, _)| String::from_utf8_lossy(&o.ruleset).into_owned())
                .unwrap_or_default(),
            _ => String::new(),
        };
        let nft = if delta.nft.is_some() {
            unified_text(
                &pretty(&old_ruleset),
                &pretty(&String::from_utf8_lossy(&p.ruleset)),
                "running",
                "planned",
            )
        } else {
            String::new()
        };
        let net = delta
            .files
            .keys()
            .filter(|f| f.starts_with("/run/systemd/network"))
            .map(|f| format!("write {}", f.display()))
            .chain(
                delta
                    .remove_files
                    .iter()
                    .filter(|f| f.starts_with("/run/systemd/network"))
                    .map(|f| format!("remove {}", f.display())),
            )
            .collect();
        let services = delta
            .units
            .iter()
            .map(|(unit, spec)| ServiceChange {
                unit: unit.clone(),
                action: match spec.action {
                    UnitAction::Reload => ServiceAction::Reload,
                    UnitAction::Restart => ServiceAction::Restart,
                },
                files: spec
                    .inputs
                    .iter()
                    .filter_map(|path| {
                        let f = delta.files.get(path)?;
                        Some(FileDiff {
                            path: path.display().to_string(),
                            unified: unified_text(
                                "",
                                &String::from_utf8_lossy(&f.contents),
                                "running",
                                "planned",
                            ),
                        })
                    })
                    .collect(),
            })
            .collect();
        Ok(PlanView { nft, net, services })
    }

    fn apply(&mut self, _running: Option<&Value>, next: &Value) -> Result<(), ApplyError> {
        let doc = document(next)?;
        let mut engine = self.engine();
        let (p, addrs) = prepare(&engine, &doc).map_err(rejected)?;
        for w in &p.warnings {
            tracing::warn!(rule = %w, "firewall rule degraded");
        }
        if !p.alias_failed.is_empty() {
            tracing::warn!(aliases = ?p.alias_failed, "aliases kept their previous contents");
        }
        let report = engine.commit(p).map_err(rejected)?;
        tracing::info!(
            commands = report.commands.len(),
            files = report.files.len(),
            nft = report.nft_loaded,
            "applied"
        );
        drop(engine);
        *lock(&self.applied) = Some((doc, addrs));
        self.start_watcher();
        Ok(())
    }
}

/// One nft command per line, for a readable ruleset diff.
fn pretty(json: &str) -> String {
    let v: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    v.get("nftables")
        .and_then(Value::as_array)
        .map(|cmds| {
            cmds.iter()
                .map(|c| c.to_string() + "\n")
                .collect::<String>()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensr_apply::cmd::FakeRunner;

    fn home_router() -> Value {
        serde_json::from_str(include_str!(
            "../../sensr-import-opnsense/tests/golden/home-router.sensr.json"
        ))
        .unwrap()
    }

    #[test]
    fn plans_and_applies_the_home_router() {
        let root = tempfile::tempdir().unwrap();
        let mut keys: Vec<String> = sensr_apply::appliers::sysctl::SysctlModel::default()
            .to_map()
            .unwrap()
            .into_keys()
            .collect();
        keys.push("net.core.default_qdisc".into());
        keys.push("kernel.hostname".into());
        for k in keys {
            let p = root.path().join("proc/sys").join(k.replace('.', "/"));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "0\n").unwrap();
        }
        let runner = Arc::new(FakeRunner::new());
        let mut a = SliceApplier::new(
            EngineOptions {
                root: root.path().to_owned(),
                ..EngineOptions::default()
            },
            runner.clone(),
        )
        .unwrap();
        let doc = home_router();
        let plan = a.plan(None, &doc).unwrap();
        assert!(!plan.nft.is_empty());
        assert!(
            plan.services
                .iter()
                .any(|s| s.unit == "sensr-kea-dhcp4.service")
        );
        a.apply(None, &doc).unwrap();
        assert!(
            runner
                .call_lines()
                .iter()
                .any(|l| l.starts_with("nft '-j'"))
        );
        assert!(a.plan(Some(&doc), &doc).unwrap().is_empty());
    }

    #[test]
    fn invalid_documents_are_rejected_with_paths() {
        let a = SliceApplier::new(EngineOptions::default(), Arc::new(FakeRunner::new())).unwrap();
        let err = a
            .plan(None, &serde_json::json!({"nonsense": 1}))
            .unwrap_err();
        assert!(matches!(err, ApplyError::Invalid(_)), "{err:?}");
    }
}
