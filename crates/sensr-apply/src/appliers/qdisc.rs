//! Queueing disciplines: fq_codel everywhere by default, CAKE on shaped WANs.
//!
//! Research note 07 measured Linux's default fq_codel as the reason latency
//! under load is ~10x lower than OPNsense (1.6 ms vs 15 ms p50), so sensr keeps
//! it on by default and makes it explicit (`net.core.default_qdisc`). A WAN
//! with a known uplink rate gets CAKE with that bandwidth, which also fixes
//! bufferbloat when the bottleneck is the modem rather than the NIC.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::cmd::{Cmd, CmdError, Runner};
use sensr_schema::fields::DeviceName;

/// The default qdisc for new interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultQdisc {
    /// fq_codel (default).
    #[default]
    FqCodel,
    /// CAKE without a bandwidth limit.
    Cake,
    /// fq (pacing; useful for hosts more than routers).
    Fq,
}

impl DefaultQdisc {
    /// sysctl value.
    pub fn as_str(self) -> &'static str {
        match self {
            DefaultQdisc::FqCodel => "fq_codel",
            DefaultQdisc::Cake => "cake",
            DefaultQdisc::Fq => "fq",
        }
    }
}

/// CAKE priority handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Diffserv {
    /// Single tin.
    #[default]
    Besteffort,
    /// Four tins by DSCP.
    Diffserv4,
}

/// An egress shaper on one interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shaper {
    /// Interface.
    pub iface: DeviceName,
    /// Egress bandwidth in kbit/s (set slightly below the line rate);
    /// `None` runs CAKE unshaped.
    pub bandwidth_kbit: Option<u64>,
    /// The interface does NAT: shape per internal host, not per conntrack tuple.
    pub nat: bool,
    /// Priority tins.
    pub diffserv: Diffserv,
    /// Link-layer overhead compensation in bytes (`None`: CAKE default).
    pub overhead: Option<i16>,
}

/// Desired queueing setup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QdiscModel {
    /// Default qdisc.
    pub default: DefaultQdisc,
    /// Shaped interfaces.
    pub shapers: Vec<Shaper>,
}

impl Shaper {
    fn tc_args(&self) -> Vec<String> {
        let mut a = vec!["cake".to_owned()];
        match self.bandwidth_kbit {
            Some(b) => a.extend(["bandwidth".to_owned(), format!("{b}kbit")]),
            None => a.push("unlimited".to_owned()),
        }
        a.push(
            match self.diffserv {
                Diffserv::Besteffort => "besteffort",
                Diffserv::Diffserv4 => "diffserv4",
            }
            .to_owned(),
        );
        if self.nat {
            a.push("nat".into());
        }
        if let Some(o) = self.overhead {
            a.push("overhead".into());
            a.push(o.to_string());
        }
        a
    }
}

impl QdiscModel {
    /// The sysctl this model needs.
    pub fn sysctls(&self) -> BTreeMap<String, String> {
        [(
            "net.core.default_qdisc".to_owned(),
            self.default.as_str().to_owned(),
        )]
        .into()
    }

    /// Plan entries: interface → rendered qdisc spec.
    pub fn plan_entries(&self) -> BTreeMap<String, String> {
        self.shapers
            .iter()
            .map(|s| (s.iface.to_string(), s.tc_args().join(" ")))
            .collect()
    }

    /// Commands to go from `applied` to `self`: `tc qdisc replace` for new or
    /// changed shapers, `tc qdisc del` (back to the default) for removed ones.
    pub fn commands(&self, applied: &QdiscModel) -> Vec<Cmd> {
        let want = self.plan_entries();
        let have = applied.plan_entries();
        let mut cmds = Vec::new();
        for s in &self.shapers {
            let key = s.iface.to_string();
            if have.get(&key) != want.get(&key) {
                cmds.push(
                    Cmd::new("tc")
                        .args(["qdisc", "replace", "dev", s.iface.as_str(), "root"])
                        .args(s.tc_args()),
                );
            }
        }
        for iface in have.keys().filter(|k| !want.contains_key(*k)) {
            cmds.push(Cmd::new("tc").args(["qdisc", "del", "dev", iface, "root"]));
        }
        cmds
    }

    /// Run [`commands`](Self::commands).
    pub fn apply(&self, applied: &QdiscModel, runner: &dyn Runner) -> Result<Vec<Cmd>, QdiscError> {
        let cmds = self.commands(applied);
        for c in &cmds {
            let out = runner.run(c, None)?;
            if !out.success() {
                return Err(QdiscError::Tc {
                    cmd: c.display(),
                    message: out.stderr_text(),
                });
            }
        }
        Ok(cmds)
    }
}

/// qdisc errors.
#[derive(Debug, thiserror::Error)]
pub enum QdiscError {
    /// tc failed.
    #[error("{cmd}: {message}")]
    Tc {
        /// Command.
        cmd: String,
        /// tc's stderr.
        message: String,
    },
    /// tc could not run.
    #[error(transparent)]
    Cmd(#[from] CmdError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::FakeRunner;

    fn wan(kbit: u64) -> Shaper {
        Shaper {
            iface: "wan0".parse().unwrap(),
            bandwidth_kbit: Some(kbit),
            nat: true,
            diffserv: Diffserv::Diffserv4,
            overhead: Some(18),
        }
    }

    #[test]
    fn fq_codel_is_the_default() {
        assert_eq!(
            QdiscModel::default().sysctls()["net.core.default_qdisc"],
            "fq_codel"
        );
        assert!(
            QdiscModel::default()
                .commands(&QdiscModel::default())
                .is_empty()
        );
    }

    #[test]
    fn cake_replace_then_idempotent_then_removed() {
        let none = QdiscModel::default();
        let shaped = QdiscModel {
            shapers: vec![wan(95_000)],
            ..Default::default()
        };
        let run = FakeRunner::new();
        shaped.apply(&none, &run).unwrap();
        assert_eq!(
            run.call_lines(),
            [
                "tc 'qdisc' 'replace' 'dev' 'wan0' 'root' 'cake' 'bandwidth' '95000kbit' 'diffserv4' 'nat' 'overhead' '18'"
            ]
        );
        assert!(shaped.commands(&shaped).is_empty());
        let faster = QdiscModel {
            shapers: vec![wan(190_000)],
            ..Default::default()
        };
        assert_eq!(faster.commands(&shaped).len(), 1);
        assert_eq!(
            none.commands(&shaped)[0].display(),
            "tc 'qdisc' 'del' 'dev' 'wan0' 'root'"
        );
    }
}
