//! Apply plans: what an apply will change, in which order.
//!
//! A [`Plan`] is the *desired* state of everything the agent owns (rendered
//! files, the nft ruleset digest, sysctls, qdiscs, units to reload, hook
//! levels). Applying is "diff against what was last applied, then execute the
//! delta in [`Stage`] order". Diffing a plan against itself is empty, which is
//! what makes every apply idempotent.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::hooks::HookLevel;

/// Apply stages in execution order (PLAN.md §2.4): links first, services last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Physical links (rename, MTU, up).
    Physical,
    /// VLAN sub-interfaces.
    Vlan,
    /// Bonds/LAGG.
    Bond,
    /// Bridges.
    Bridge,
    /// PPPoE sessions.
    Ppp,
    /// Interface addresses.
    Addresses,
    /// Routes and policy routing tables.
    Routes,
    /// Tunnels (WireGuard netdevs, GRE, …).
    Tunnels,
    /// The nftables ruleset. Loaded before forwarding is switched on so the
    /// box never forwards unfiltered.
    Firewall,
    /// Kernel tunables (forwarding, conntrack).
    Sysctl,
    /// Queueing disciplines.
    Qdisc,
    /// Rendered service configuration files.
    Files,
    /// Service reloads/restarts.
    Services,
    /// Operator hooks.
    Hooks,
}

/// A rendered file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSpec {
    /// Contents.
    pub contents: Vec<u8>,
    /// Unix permission bits.
    pub mode: u32,
}

/// The ruleset to load, identified by digest so plans stay small.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NftSpec {
    /// Content digest of the rendered JSON.
    pub digest: String,
    /// Human summary (`"57 rules, 4 sets"`).
    pub summary: String,
}

/// What to do to a unit when its inputs change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitAction {
    /// `systemctl reload-or-restart`.
    Reload,
    /// `systemctl restart`.
    Restart,
}

/// A unit and the files it reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitSpec {
    /// What to do when any input changes.
    pub action: UnitAction,
    /// Files whose change triggers the action.
    pub inputs: BTreeSet<PathBuf>,
}

/// Desired state of everything an apply touches.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    /// Files to write.
    pub files: BTreeMap<PathBuf, FileSpec>,
    /// Files to delete (only meaningful in a delta).
    pub remove_files: BTreeSet<PathBuf>,
    /// Ruleset to load.
    pub nft: Option<NftSpec>,
    /// Units to reload/restart.
    pub units: BTreeMap<String, UnitSpec>,
    /// Kernel tunables.
    pub sysctls: BTreeMap<String, String>,
    /// Queueing discipline per interface (rendered `tc` spec).
    pub qdiscs: BTreeMap<String, String>,
    /// Hook levels to run after the apply.
    pub hooks: BTreeSet<HookLevel>,
}

/// One executable step of a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// Unique id (`file:/run/…`, `unit:unbound.service`, …).
    pub id: String,
    /// Its stage.
    pub stage: Stage,
    /// Ids that must run first.
    pub deps: Vec<String>,
}

/// Why steps could not be ordered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OrderError {
    /// A dependency on an id that is not in the plan.
    #[error("{step} depends on unknown step {dep}")]
    UnknownDep {
        /// The dependent step.
        step: String,
        /// The missing dependency.
        dep: String,
    },
    /// A dependency on a step of a later stage.
    #[error("{step} ({stage:?}) cannot depend on {dep} of later stage {dep_stage:?}")]
    StageInversion {
        /// The dependent step.
        step: String,
        /// Its stage.
        stage: Stage,
        /// The dependency.
        dep: String,
        /// The dependency's stage.
        dep_stage: Stage,
    },
    /// The dependencies form a cycle.
    #[error("dependency cycle among {0:?}")]
    Cycle(Vec<String>),
}

/// Order steps: stages ascending; within a stage, a topological sort of the
/// declared dependencies with ties broken by id, so the order is deterministic.
pub fn order(steps: &[Step]) -> Result<Vec<usize>, OrderError> {
    let index: HashMap<&str, usize> = steps
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id.as_str(), i))
        .collect();
    for s in steps {
        for d in &s.deps {
            let Some(&di) = index.get(d.as_str()) else {
                return Err(OrderError::UnknownDep {
                    step: s.id.clone(),
                    dep: d.clone(),
                });
            };
            if steps[di].stage > s.stage {
                return Err(OrderError::StageInversion {
                    step: s.id.clone(),
                    stage: s.stage,
                    dep: d.clone(),
                    dep_stage: steps[di].stage,
                });
            }
        }
    }
    let mut by_stage: BTreeMap<Stage, Vec<usize>> = BTreeMap::new();
    for (i, s) in steps.iter().enumerate() {
        by_stage.entry(s.stage).or_default().push(i);
    }
    let mut out = Vec::with_capacity(steps.len());
    let mut done = vec![false; steps.len()];
    for (_, members) in by_stage {
        // Kahn within the stage; deps in earlier stages are already done.
        let mut pending: BTreeSet<(&str, usize)> =
            members.iter().map(|&i| (steps[i].id.as_str(), i)).collect();
        while !pending.is_empty() {
            let ready = pending
                .iter()
                .copied()
                .find(|&(_, i)| steps[i].deps.iter().all(|d| done[index[d.as_str()]]));
            let Some(item) = ready else {
                return Err(OrderError::Cycle(
                    pending.iter().map(|(id, _)| (*id).to_owned()).collect(),
                ));
            };
            pending.remove(&item);
            done[item.1] = true;
            out.push(item.1);
        }
    }
    Ok(out)
}

impl Plan {
    /// True when there is nothing to do.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
            && self.remove_files.is_empty()
            && self.nft.is_none()
            && self.units.is_empty()
            && self.sysctls.is_empty()
            && self.qdiscs.is_empty()
            && self.hooks.is_empty()
    }

    /// The delta from `applied` (what is live) to `self` (what is wanted).
    ///
    /// Units appear only when one of their inputs changed or the unit is new;
    /// hooks run only when something else changed.
    pub fn diff(&self, applied: &Plan) -> Plan {
        let files: BTreeMap<_, _> = self
            .files
            .iter()
            .filter(|(p, f)| applied.files.get(*p) != Some(*f))
            .map(|(p, f)| (p.clone(), f.clone()))
            .collect();
        let remove_files: BTreeSet<_> = applied
            .files
            .keys()
            .filter(|p| !self.files.contains_key(*p))
            .cloned()
            .collect();
        let touched = |p: &PathBuf| files.contains_key(p) || remove_files.contains(p);
        let units = self
            .units
            .iter()
            .filter(|(name, u)| {
                applied.units.get(*name) != Some(*u) || u.inputs.iter().any(touched)
            })
            .map(|(n, u)| (n.clone(), u.clone()))
            .collect();
        let nft = match (&self.nft, &applied.nft) {
            (Some(a), Some(b)) if a.digest == b.digest => None,
            (a, _) => a.clone(),
        };
        let changed_map = |want: &BTreeMap<String, String>, have: &BTreeMap<String, String>| {
            want.iter()
                .filter(|(k, v)| have.get(*k) != Some(*v))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<BTreeMap<_, _>>()
        };
        let mut delta = Plan {
            files,
            remove_files,
            nft,
            units,
            sysctls: changed_map(&self.sysctls, &applied.sysctls),
            qdiscs: changed_map(&self.qdiscs, &applied.qdiscs),
            hooks: BTreeSet::new(),
        };
        if !delta.is_empty() {
            delta.hooks = self.hooks.clone();
        }
        delta
    }

    /// Steps of this plan with their dependencies, unordered.
    pub fn steps(&self) -> Vec<Step> {
        let mut v = Vec::new();
        if self.nft.is_some() {
            v.push(step("nft:ruleset", Stage::Firewall, vec![]));
        }
        for k in self.sysctls.keys() {
            v.push(step(&format!("sysctl:{k}"), Stage::Sysctl, vec![]));
        }
        for k in self.qdiscs.keys() {
            v.push(step(&format!("qdisc:{k}"), Stage::Qdisc, vec![]));
        }
        for p in &self.files {
            v.push(step(
                &format!("file:{}", p.0.display()),
                Stage::Files,
                vec![],
            ));
        }
        for p in &self.remove_files {
            v.push(step(&format!("rm:{}", p.display()), Stage::Files, vec![]));
        }
        for (name, u) in &self.units {
            let deps = u
                .inputs
                .iter()
                .filter_map(|p| {
                    if self.files.contains_key(p) {
                        Some(format!("file:{}", p.display()))
                    } else if self.remove_files.contains(p) {
                        Some(format!("rm:{}", p.display()))
                    } else {
                        None
                    }
                })
                .collect();
            v.push(step(&format!("unit:{name}"), Stage::Services, deps));
        }
        for h in &self.hooks {
            v.push(step(&format!("hooks:{h}"), Stage::Hooks, vec![]));
        }
        v
    }

    /// Steps in execution order.
    pub fn ordered_steps(&self) -> Result<Vec<Step>, OrderError> {
        let steps = self.steps();
        Ok(order(&steps)?
            .into_iter()
            .map(|i| steps[i].clone())
            .collect())
    }

    /// `sensr apply --dry-run` text for this delta, given what is live.
    pub fn dry_run(&self, applied: &Plan) -> String {
        let mut out = String::new();
        let steps = match self.ordered_steps() {
            Ok(s) => s,
            Err(e) => return format!("plan error: {e}\n"),
        };
        if steps.is_empty() {
            out.push_str("nothing to apply\n");
            return out;
        }
        let _ = writeln!(out, "{} change(s):", steps.len());
        for s in steps {
            let (kind, key) = s.id.split_once(':').unwrap_or((&s.id, ""));
            let detail = match kind {
                "nft" => {
                    let n = self.nft.as_ref();
                    let was = applied.nft.as_ref().map(|x| short(&x.digest));
                    format!(
                        "load ruleset {} ({}){}",
                        n.map(|x| short(&x.digest)).unwrap_or_default(),
                        n.map(|x| x.summary.as_str()).unwrap_or_default(),
                        was.map(|w| format!(", replacing {w}")).unwrap_or_default()
                    )
                }
                "sysctl" => format!(
                    "{key} = {}{}",
                    self.sysctls[key],
                    was(applied.sysctls.get(key))
                ),
                "qdisc" => format!(
                    "{key}: {}{}",
                    self.qdiscs[key],
                    was(applied.qdiscs.get(key))
                ),
                "file" => {
                    let new = !applied.files.contains_key(&PathBuf::from(key));
                    let size = self.files[&PathBuf::from(key)].contents.len();
                    format!(
                        "{} {key} ({size} bytes)",
                        if new { "create" } else { "update" }
                    )
                }
                "rm" => format!("remove {key}"),
                "unit" => format!(
                    "{} {key}",
                    match self.units[key].action {
                        UnitAction::Reload => "reload",
                        UnitAction::Restart => "restart",
                    }
                ),
                "hooks" => format!("run {key} hooks"),
                _ => s.id.clone(),
            };
            let _ = writeln!(out, "  [{:?}] {detail}", s.stage);
        }
        out
    }
}

fn step(id: &str, stage: Stage, deps: Vec<String>) -> Step {
    Step {
        id: id.to_owned(),
        stage,
        deps,
    }
}

fn short(d: &str) -> String {
    d.chars().take(12).collect()
}

fn was(v: Option<&String>) -> String {
    v.map(|v| format!(" (was {v})"))
        .unwrap_or_else(|| " (new)".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample() -> Plan {
        let mut p = Plan::default();
        p.files.insert(
            "/run/sensr/unbound/unbound.conf".into(),
            FileSpec {
                contents: b"server:\n".to_vec(),
                mode: 0o644,
            },
        );
        p.units.insert(
            "unbound.service".into(),
            UnitSpec {
                action: UnitAction::Reload,
                inputs: ["/run/sensr/unbound/unbound.conf".into()].into(),
            },
        );
        p.nft = Some(NftSpec {
            digest: "aaaaaaaaaaaaaaaa".into(),
            summary: "3 rules".into(),
        });
        p.sysctls.insert("net.ipv4.ip_forward".into(), "1".into());
        p.qdiscs
            .insert("wan0".into(), "cake bandwidth 100mbit".into());
        p.hooks.insert(HookLevel::Config);
        p
    }

    #[test]
    fn diff_against_self_is_empty_idempotent() {
        let p = sample();
        assert!(p.diff(&p).is_empty());
        assert_eq!(p.diff(&p).dry_run(&p), "nothing to apply\n");
    }

    #[test]
    fn diff_from_nothing_is_everything_in_stage_order() {
        let p = sample();
        let d = p.diff(&Plan::default());
        assert_eq!(d, p);
        let ids: Vec<_> = d
            .ordered_steps()
            .unwrap()
            .into_iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(
            ids,
            [
                "nft:ruleset",
                "sysctl:net.ipv4.ip_forward",
                "qdisc:wan0",
                "file:/run/sensr/unbound/unbound.conf",
                "unit:unbound.service",
                "hooks:config"
            ]
        );
        insta::assert_snapshot!(d.dry_run(&Plan::default()));
    }

    #[test]
    fn unit_reloads_only_when_its_inputs_change() {
        let old = sample();
        let mut new = sample();
        new.sysctls.insert("net.ipv4.ip_forward".into(), "0".into());
        let d = new.diff(&old);
        assert!(d.units.is_empty());
        assert_eq!(d.sysctls.len(), 1);
        assert!(d.hooks.contains(&HookLevel::Config));

        new.files.insert(
            "/run/sensr/unbound/unbound.conf".into(),
            FileSpec {
                contents: b"server:\n  verbosity: 2\n".to_vec(),
                mode: 0o644,
            },
        );
        let d = new.diff(&old);
        assert!(d.units.contains_key("unbound.service"));
        insta::assert_snapshot!(d.dry_run(&old));
    }

    #[test]
    fn removed_files_are_deleted_and_trigger_their_unit() {
        let old = sample();
        let mut new = sample();
        new.files.clear();
        let d = new.diff(&old);
        assert_eq!(d.remove_files.len(), 1);
        assert!(d.units.contains_key("unbound.service"));
        let ids: Vec<_> = d
            .ordered_steps()
            .unwrap()
            .into_iter()
            .map(|s| s.id)
            .collect();
        let rm = ids.iter().position(|i| i.starts_with("rm:")).unwrap();
        let unit = ids.iter().position(|i| i.starts_with("unit:")).unwrap();
        assert!(rm < unit);
    }

    #[test]
    fn order_rejects_cycles_unknown_deps_and_stage_inversions() {
        let s = |id: &str, st, deps: &[&str]| Step {
            id: id.into(),
            stage: st,
            deps: deps.iter().map(|d| (*d).into()).collect(),
        };
        assert!(matches!(
            order(&[s("a", Stage::Files, &["b"]), s("b", Stage::Files, &["a"])]),
            Err(OrderError::Cycle(_))
        ));
        assert!(matches!(
            order(&[s("a", Stage::Files, &["zz"])]),
            Err(OrderError::UnknownDep { .. })
        ));
        assert!(matches!(
            order(&[
                s("a", Stage::Firewall, &["b"]),
                s("b", Stage::Services, &[])
            ]),
            Err(OrderError::StageInversion { .. })
        ));
    }

    const STAGES: [Stage; 14] = [
        Stage::Physical,
        Stage::Vlan,
        Stage::Bond,
        Stage::Bridge,
        Stage::Ppp,
        Stage::Addresses,
        Stage::Routes,
        Stage::Tunnels,
        Stage::Firewall,
        Stage::Sysctl,
        Stage::Qdisc,
        Stage::Files,
        Stage::Services,
        Stage::Hooks,
    ];

    proptest! {
        /// Generate a DAG (deps only to earlier-generated steps of the same or
        /// an earlier stage), shuffle it, and check the order respects it.
        #[test]
        fn prop_order_is_topological(
            spec in proptest::collection::vec((0usize..14, proptest::collection::vec(any::<prop::sample::Index>(), 0..3)), 1..40),
            seed in any::<u64>(),
        ) {
            let mut steps: Vec<Step> = Vec::new();
            for (i, (st, deps)) in spec.iter().enumerate() {
                let stage = STAGES[*st];
                let mut d: Vec<String> = Vec::new();
                if i > 0 {
                    for ix in deps {
                        let j = ix.index(i);
                        if steps[j].stage <= stage && !d.contains(&steps[j].id) {
                            d.push(steps[j].id.clone());
                        }
                    }
                }
                steps.push(Step { id: format!("s{i:03}"), stage, deps: d });
            }
            // Deterministic shuffle.
            let mut x = seed | 1;
            for i in (1..steps.len()).rev() {
                x ^= x << 13; x ^= x >> 7; x ^= x << 17;
                steps.swap(i, (x % (i as u64 + 1)) as usize);
            }
            let ord = order(&steps).unwrap();
            prop_assert_eq!(ord.len(), steps.len());
            let pos: HashMap<&str, usize> = ord.iter().enumerate().map(|(p, &i)| (steps[i].id.as_str(), p)).collect();
            for (p, &i) in ord.iter().enumerate() {
                for d in &steps[i].deps {
                    prop_assert!(pos[d.as_str()] < p);
                }
                if p > 0 {
                    prop_assert!(steps[ord[p - 1]].stage <= steps[i].stage);
                }
            }
            // Same input, same order.
            prop_assert_eq!(order(&steps).unwrap(), ord);
        }
    }
}
