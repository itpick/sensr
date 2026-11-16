//! The apply-pipeline boundary.
//!
//! The real pipeline (`sensr-apply` plans + `sensr-rules` nft renderer +
//! service templates) plugs in behind [`Applier`]. Until it lands the agent
//! runs [`PreviewApplier`], which computes the same kind of plan from the
//! document but changes nothing on the host.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use sensr_ipc::{FileDiff, PlanView, ServiceAction, ServiceChange, ValidationIssue};
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
    fn plan(&self, running: Option<&Value>, next: &Value) -> Result<PlanView, ApplyError>;

    /// Makes the system match `next`. Must be idempotent.
    fn apply(&mut self, running: Option<&Value>, next: &Value) -> Result<(), ApplyError>;
}

/// Sections and the unit that serves them, for the preview plan.
const SERVICES: &[(&str, &str)] = &[
    ("dhcpd", "kea-dhcp4-server.service"),
    ("kea", "kea-dhcp4-server.service"),
    ("unbound", "unbound.service"),
    ("wireguard", "wireguard.service"),
];

/// Renders the firewall-relevant sections as a stand-in ruleset text.
fn ruleset_text(doc: &Value) -> String {
    let mut out = String::from("table inet sensr {\n");
    for section in ["filter", "nat"] {
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
pub fn preview_plan(running: Option<&Value>, next: &Value) -> PlanView {
    let empty = Value::Object(Default::default());
    let running = running.unwrap_or(&empty);
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
    fn plan(&self, running: Option<&Value>, next: &Value) -> Result<PlanView, ApplyError> {
        Ok(preview_plan(running, next))
    }

    fn apply(&mut self, running: Option<&Value>, next: &Value) -> Result<(), ApplyError> {
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
    pub applied: Vec<Value>,
    /// When set, the next `apply` fails with this message (then clears).
    pub fail_next_apply: Option<String>,
    /// Paths whose presence in a document makes `plan` reject it.
    pub reject_paths: Vec<sensr_ipc::ConfigPath>,
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

impl Applier for FakeApplier {
    fn plan(&self, running: Option<&Value>, next: &Value) -> Result<PlanView, ApplyError> {
        let issues: Vec<ValidationIssue> = self
            .lock()
            .reject_paths
            .iter()
            .filter(|p| p.lookup(next).is_some())
            .map(|p| ValidationIssue {
                path: p.to_string(),
                message: "Rejected by the test applier.".into(),
            })
            .collect();
        if !issues.is_empty() {
            return Err(ApplyError::Invalid(issues));
        }
        Ok(preview_plan(running, next))
    }

    fn apply(&mut self, _running: Option<&Value>, next: &Value) -> Result<(), ApplyError> {
        let mut st = self.lock();
        if let Some(msg) = st.fail_next_apply.take() {
            return Err(ApplyError::Failed(msg));
        }
        st.applied.push(next.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn preview_plan_reports_nft_net_and_services() {
        let old =
            json!({"interfaces": {"lan": {"ipaddr": "192.168.1.1"}}, "unbound": {"enable": "1"}});
        let new = json!({
            "interfaces": {"lan": {"ipaddr": "192.168.2.1"}, "wan": {"ipaddr": "dhcp"}},
            "filter": {"rule": [{"type": "pass"}]},
            "dhcpd": {"lan": {}},
        });
        let p = preview_plan(Some(&old), &new);
        assert!(p.nft.contains("+  # filter"));
        assert_eq!(p.net, ["reconfigure interface lan", "add interface wan"]);
        let svc: Vec<_> = p
            .services
            .iter()
            .map(|s| (s.unit.as_str(), s.action))
            .collect();
        assert_eq!(
            svc,
            [
                ("kea-dhcp4-server.service", ServiceAction::Start),
                ("unbound.service", ServiceAction::Stop),
            ]
        );
        assert!(preview_plan(Some(&new), &new).is_empty());
    }

    #[test]
    fn fake_applier_fails_once_and_rejects_paths() {
        let mut f = FakeApplier::default();
        f.state.lock().unwrap().fail_next_apply = Some("boom".into());
        assert_eq!(
            f.apply(None, &json!({})),
            Err(ApplyError::Failed("boom".into()))
        );
        assert_eq!(f.apply(None, &json!({"a": 1})), Ok(()));
        assert_eq!(f.state.lock().unwrap().applied, vec![json!({"a": 1})]);
        f.state.lock().unwrap().reject_paths = vec!["bad".parse().unwrap()];
        assert!(matches!(
            f.plan(None, &json!({"bad": 1})),
            Err(ApplyError::Invalid(_))
        ));
    }
}
