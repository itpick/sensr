//! The apply-pipeline boundary.
//!
//! The real pipeline ([`crate::slice_applier::SliceApplier`]: `sensr-apply`
//! plans, the `sensr-rules` nft renderer, service templates) plugs in behind
//! [`Applier`]. [`PreviewApplier`] computes a plan of the same shape from the
//! document but changes nothing on the host.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use sensr_ipc::{FileDiff, PlanView, ServiceAction, ServiceChange, ValidationIssue};
use sensr_schema::Document;
use serde_json::Value;

use crate::diff::unified_text;

/// Apply failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ApplyError {
    /// The document cannot be applied as it stands (checker rejected it,
    /// e.g. `nft -c` or `kea-dhcp4 -t`). Nothing was changed.
    #[error("validation failed")]
    Invalid(Vec<ValidationIssue>),
    /// Applying failed part-way; the agent re-applies the previous revision.
    #[error("apply failed: {0}")]
    Failed(String),
}

/// What the agent needs from the apply pipeline.
pub trait Applier: Send + 'static {
    /// Plans moving the system from `running` (`None` at first boot) to
    /// `next`, running every backend checker, without changing anything.
    fn plan(&self, running: Option<&Document>, next: &Document) -> Result<PlanView, ApplyError>;

    /// Makes the system match `next`. Must be idempotent.
    fn apply(&mut self, running: Option<&Document>, next: &Document) -> Result<(), ApplyError>;

    /// The boot apply (agent start, `SIGHUP`): makes the system match
    /// `next` from scratch, starting every service even when its files did
    /// not change. Fault-isolated where the pipeline can be: a backend whose
    /// own checker rejects its configuration is held back and described in
    /// the returned list, and the rest still applies, so one bad or
    /// unverifiable daemon config cannot keep the whole network down. The
    /// default plans and applies all or nothing.
    fn apply_boot(&mut self, next: &Document) -> Result<Vec<String>, ApplyError> {
        self.plan(None, next)?;
        self.apply(None, next)?;
        Ok(Vec::new())
    }

    /// Run-time state of a subsystem (gateway status, alias feeds, PD), as
    /// JSON; `None` when this pipeline has none.
    fn runtime(&self, _section: sensr_ipc::RuntimeSection) -> Option<Value> {
        None
    }

    /// Drops an unreserved host from the inventory; `false` when `key` is
    /// reserved or unknown (or this pipeline keeps no inventory).
    fn forget_host(&mut self, _key: &str) -> Result<bool, ApplyError> {
        Ok(false)
    }

    /// The port scan's results for the host with `mac` as JSON
    /// (`{last_scan, scanning, all_filtered, ports}`); `None` when the host
    /// is unknown (or this pipeline has no port scan).
    fn host_ports(&self, _mac: &str) -> Option<Value> {
        None
    }

    /// Starts a port scan of the host with `mac` in the background.
    fn host_scan_now(&self, _mac: &str) -> Result<(), crate::portscan::ScanNowError> {
        Err(crate::portscan::ScanNowError::NotReady)
    }

    /// The MAC of the inventory host holding `ip` (lowercase), if any: who a
    /// request comes from, for the self-quarantine guard.
    fn client_mac(&self, _ip: std::net::IpAddr) -> Option<String> {
        None
    }
}

/// Sections and the unit that serves them, for the preview plan.
const SERVICES: &[(&str, &str)] = &[
    ("dhcpv4", "kea-dhcp4-server.service"),
    ("dns", "unbound.service"),
    ("wireguard", "wireguard.service"),
];

/// Renders the firewall-relevant sections as a stand-in ruleset text.
fn ruleset_text(doc: &Value) -> String {
    let mut out = String::from("table inet sensr {\n");
    for section in ["firewall", "filter", "nat"] {
        if let Some(v) = doc.get(section) {
            out += &format!("  # {section}\n");
            for line in serde_json::to_string_pretty(v).unwrap_or_default().lines() {
                out += &format!("  # {line}\n");
            }
        }
    }
    out += "}\n";
    out
}

/// The plan both fakes compute: ruleset diff, interface steps and per-unit
/// service changes derived from which sections changed.
pub fn preview_plan(running: Option<&Document>, next: &Document) -> PlanView {
    // The preview shows section contents verbatim, so it works on masked
    // copies: a plan must never print a private key.
    let running = &running
        .map(crate::redact::masked)
        .unwrap_or_else(|| Value::Object(Default::default()));
    let next = &crate::redact::masked(next);
    let nft = unified_text(
        &ruleset_text(running),
        &ruleset_text(next),
        "running",
        "planned",
    );

    let mut net = Vec::new();
    let ifaces = |d: &Value| {
        d.get("interfaces")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default()
    };
    let (old_if, new_if) = (ifaces(running), ifaces(next));
    let names: BTreeSet<&String> = old_if.keys().chain(new_if.keys()).collect();
    for name in names {
        match (old_if.get(name), new_if.get(name)) {
            (None, Some(_)) => net.push(format!("add interface {name}")),
            (Some(_), None) => net.push(format!("remove interface {name}")),
            (Some(a), Some(b)) if a != b => net.push(format!("reconfigure interface {name}")),
            _ => {}
        }
    }

    let mut services: Vec<ServiceChange> = Vec::new();
    for (section, unit) in SERVICES {
        let (a, b) = (running.get(*section), next.get(*section));
        let action = match (a, b) {
            (None, Some(_)) => ServiceAction::Start,
            (Some(_), None) => ServiceAction::Stop,
            (Some(a), Some(b)) if a != b => ServiceAction::Reload,
            _ => continue,
        };
        let text = |v: Option<&Value>| {
            v.map(|v| serde_json::to_string_pretty(v).unwrap_or_default() + "\n")
                .unwrap_or_default()
        };
        let file = FileDiff {
            path: format!("/run/sensr/{section}.json"),
            unified: unified_text(&text(a), &text(b), "running", "planned"),
        };
        match services.iter_mut().find(|s| s.unit == *unit) {
            Some(existing) => existing.files.push(file),
            None => services.push(ServiceChange {
                unit: (*unit).to_owned(),
                action,
                files: vec![file],
            }),
        }
    }
    PlanView { nft, net, services }
}

/// Plans like the real pipeline would, applies nothing. Default for the
/// agent binary until `sensr-apply` is wired.
#[derive(Debug, Default)]
pub struct PreviewApplier;

impl Applier for PreviewApplier {
    fn plan(&self, running: Option<&Document>, next: &Document) -> Result<PlanView, ApplyError> {
        Ok(preview_plan(running, next))
    }

    fn apply(&mut self, running: Option<&Document>, next: &Document) -> Result<(), ApplyError> {
        let plan = preview_plan(running, next);
        tracing::info!(
            nft_changed = !plan.nft.is_empty(),
            net_steps = plan.net.len(),
            services = plan.services.len(),
            "preview applier: plan computed, host left unchanged"
        );
        Ok(())
    }
}

/// Shared, inspectable state of a [`FakeApplier`].
#[derive(Debug, Default)]
pub struct FakeState {
    /// Every document successfully applied, in order.
    pub applied: Vec<Document>,
    /// When set, the next `apply` fails with this message (then clears).
    pub fail_next_apply: Option<String>,
    /// Paths whose presence in a document makes `plan` reject it.
    pub reject_paths: Vec<sensr_ipc::ConfigPath>,
    /// Canned answers for [`Applier::runtime`].
    pub runtime: Vec<(sensr_ipc::RuntimeSection, Value)>,
    /// Host keys [`Applier::forget_host`] accepts (each once).
    pub forgettable: Vec<String>,
    /// Answers for [`Applier::client_mac`].
    pub client_macs: Vec<(std::net::IpAddr, String)>,
    /// Canned [`Applier::host_ports`] answers by MAC; a MAC without one is
    /// unknown.
    pub ports: Vec<(String, Value)>,
    /// Errors [`Applier::host_scan_now`] gives by MAC; the others start (and
    /// are listed in `scans`).
    pub scan_errors: Vec<(String, crate::portscan::ScanNowError)>,
    /// MACs [`Applier::host_scan_now`] started a scan of.
    pub scans: Vec<String>,
}

/// Test double: records applies, can be told to fail.
#[derive(Debug, Clone, Default)]
pub struct FakeApplier {
    /// Inspect or steer from the test.
    pub state: Arc<Mutex<FakeState>>,
}

impl FakeApplier {
    fn lock(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl FakeApplier {
    /// What `reject_paths` makes the test checker reject in `doc`.
    fn rejections(&self, doc: &Document) -> Vec<ValidationIssue> {
        let json = serde_json::to_value(doc).unwrap_or(Value::Null);
        self.lock()
            .reject_paths
            .iter()
            .filter(|p| p.lookup(&json).is_some())
            .map(|p| ValidationIssue {
                path: p.to_string(),
                message: "Rejected by the test applier.".into(),
            })
            .collect()
    }
}

impl Applier for FakeApplier {
    fn plan(&self, running: Option<&Document>, next: &Document) -> Result<PlanView, ApplyError> {
        let issues = self.rejections(next);
        if !issues.is_empty() {
            return Err(ApplyError::Invalid(issues));
        }
        Ok(preview_plan(running, next))
    }

    fn apply(&mut self, _running: Option<&Document>, next: &Document) -> Result<(), ApplyError> {
        let mut st = self.lock();
        if let Some(msg) = st.fail_next_apply.take() {
            return Err(ApplyError::Failed(msg));
        }
        st.applied.push(next.clone());
        Ok(())
    }

    /// Like the real pipeline: rejected paths are held back and reported,
    /// the rest applies.
    fn apply_boot(&mut self, next: &Document) -> Result<Vec<String>, ApplyError> {
        let held = self
            .rejections(next)
            .into_iter()
            .map(|i| format!("{}: {}", i.path, i.message))
            .collect();
        self.apply(None, next)?;
        Ok(held)
    }

    fn runtime(&self, section: sensr_ipc::RuntimeSection) -> Option<Value> {
        self.lock()
            .runtime
            .iter()
            .find(|(s, _)| *s == section)
            .map(|(_, v)| v.clone())
    }

    fn forget_host(&mut self, key: &str) -> Result<bool, ApplyError> {
        let mut st = self.lock();
        let before = st.forgettable.len();
        st.forgettable.retain(|k| k != key);
        Ok(st.forgettable.len() != before)
    }

    fn host_ports(&self, mac: &str) -> Option<Value> {
        let mac = mac.to_ascii_lowercase();
        let st = self.lock();
        let (_, v) = st.ports.iter().find(|(m, _)| *m == mac)?;
        let mut v = v.clone();
        v["scanning"] = st.scans.contains(&mac).into();
        Some(v)
    }

    fn host_scan_now(&self, mac: &str) -> Result<(), crate::portscan::ScanNowError> {
        use crate::portscan::ScanNowError;
        let mac = mac.to_ascii_lowercase();
        let mut st = self.lock();
        if !st.ports.iter().any(|(m, _)| *m == mac) {
            return Err(ScanNowError::Unknown);
        }
        if let Some((_, e)) = st.scan_errors.iter().find(|(m, _)| *m == mac) {
            return Err(*e);
        }
        if st.scans.contains(&mac) {
            return Err(ScanNowError::Busy);
        }
        st.scans.push(mac);
        Ok(())
    }

    fn client_mac(&self, ip: std::net::IpAddr) -> Option<String> {
        self.lock()
            .client_macs
            .iter()
            .find(|(a, _)| *a == ip)
            .map(|(_, m)| m.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sensr_schema::PathAccess;
    use serde_json::json;

    #[test]
    fn preview_plan_reports_nft_net_and_services() {
        let old = Document::factory();
        let mut new = old.clone();
        new.set_by_path("interfaces.lan.mtu", json!(1400)).unwrap();
        new.set_by_path("interfaces.opt1", json!({"device": "eth2"}))
            .unwrap();
        new.set_by_path("wireguard.enabled", json!(true)).unwrap();
        let p = preview_plan(Some(&old), &new);
        assert_eq!(p.net, ["reconfigure interface lan", "add interface opt1"]);
        let svc: Vec<_> = p
            .services
            .iter()
            .map(|s| (s.unit.as_str(), s.action))
            .collect();
        assert_eq!(svc, [("wireguard.service", ServiceAction::Reload)]);
        assert!(preview_plan(Some(&new), &new).is_empty());
    }

    #[test]
    fn fake_applier_fails_once_and_rejects_paths() {
        let doc = Document::factory();
        let mut f = FakeApplier::default();
        f.state.lock().unwrap().fail_next_apply = Some("boom".into());
        assert_eq!(f.apply(None, &doc), Err(ApplyError::Failed("boom".into())));
        assert_eq!(f.apply(None, &doc), Ok(()));
        assert_eq!(f.state.lock().unwrap().applied, vec![doc.clone()]);
        f.state.lock().unwrap().reject_paths = vec!["system.hostname".parse().unwrap()];
        assert!(matches!(f.plan(None, &doc), Err(ApplyError::Invalid(_))));
    }
}
