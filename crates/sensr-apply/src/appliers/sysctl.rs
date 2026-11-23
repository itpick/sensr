//! Kernel tunables: forwarding, reverse-path filtering, conntrack sizing.
//!
//! The desired values are written to `/run/sensr/sysctl.d/50-sensr.conf`
//! (so `systemd-sysctl` reapplies them if anything resets them) and the ones
//! that differ from the live kernel are written to `/proc/sys` directly.
//! Writing `/proc/sys` needs no subprocess and makes the diff exact.
//!
//! A key that leaves the model keeps its live value, with one exception:
//! an ICMP redirect switch sensr turned off (`send_redirects = 0` in the
//! previous conf file) goes back to the kernel default, 1. The previous
//! conf file lives in `/run`, so it outlasts an agent restart and is gone
//! exactly when the kernel's own state is (a reboot).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::templates::{TemplateError, write_atomic};

/// Reverse-path filter mode (`rp_filter`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RpFilter {
    /// No source validation.
    Off,
    /// RFC 3704 strict mode: drops asymmetric routing (multi-WAN breaks).
    Strict,
    /// Loose mode: source must be routable via any interface. The default,
    /// because strict mode silently breaks multi-WAN and policy routing.
    #[default]
    Loose,
}

impl RpFilter {
    fn value(self) -> &'static str {
        match self {
            RpFilter::Off => "0",
            RpFilter::Strict => "1",
            RpFilter::Loose => "2",
        }
    }
}

/// Desired tunables for the routing slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysctlModel {
    /// Route IPv4 between interfaces.
    pub forward_v4: bool,
    /// Route IPv6 between interfaces.
    pub forward_v6: bool,
    /// Reverse-path filtering.
    pub rp_filter: RpFilter,
    /// `nf_conntrack_max`; `None` keeps the kernel default (scaled to RAM).
    pub conntrack_max: Option<u32>,
    /// Extra operator tunables (OPNsense "System: Settings: Tunables").
    pub extra: BTreeMap<String, String>,
    /// Devices that must not send ICMP redirects (internal links while
    /// hosts are locked: same-LAN traffic is routed through us on purpose).
    /// Non-empty also turns redirects off for `all` and `default`.
    pub send_redirects_off: Vec<String>,
}

impl Default for SysctlModel {
    fn default() -> Self {
        SysctlModel {
            forward_v4: true,
            forward_v6: true,
            rp_filter: RpFilter::Loose,
            conntrack_max: None,
            extra: BTreeMap::new(),
            send_redirects_off: Vec::new(),
        }
    }
}

/// Invalid tunable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SysctlError {
    /// Key outside `[a-z0-9_.-]`, or one that would escape `/proc/sys`.
    #[error("invalid sysctl key {0:?}")]
    BadKey(String),
    /// Value with control characters.
    #[error("invalid value for {0}")]
    BadValue(String),
}

fn valid_key(k: &str) -> bool {
    !k.is_empty()
        && !k.starts_with('.')
        && !k.ends_with('.')
        && !k.contains("..")
        && k.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        })
}

/// A device name as a sysctl key segment, using the sysctl(8) convention of
/// swapping `.` and `/` (the kernel's `conf/vlan0.100` is `vlan0/100`).
/// `None` for names the key syntax cannot carry. Unlike [`valid_key`],
/// uppercase is fine: device names are not folded.
fn device_segment(dev: &str) -> Option<String> {
    let ok = !dev.is_empty()
        && dev != "."
        && dev != ".."
        && dev
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    ok.then(|| dev.replace('.', "/"))
}

impl SysctlModel {
    /// The full key → value map, validated.
    pub fn to_map(&self) -> Result<BTreeMap<String, String>, SysctlError> {
        let b = |v: bool| if v { "1" } else { "0" }.to_owned();
        let mut m = BTreeMap::new();
        m.insert("net.ipv4.ip_forward".into(), b(self.forward_v4));
        m.insert("net.ipv6.conf.all.forwarding".into(), b(self.forward_v6));
        // Router advertisements must still be accepted on a forwarding WAN
        // (SLAAC/PD); 2 = accept even with forwarding on.
        m.insert("net.ipv6.conf.default.accept_ra".into(), "2".into());
        let rp = self.rp_filter.value().to_owned();
        m.insert("net.ipv4.conf.all.rp_filter".into(), rp.clone());
        m.insert("net.ipv4.conf.default.rp_filter".into(), rp);
        if let Some(max) = self.conntrack_max {
            m.insert("net.netfilter.nf_conntrack_max".into(), max.to_string());
        }
        if !self.send_redirects_off.is_empty() {
            for scope in ["all", "default"] {
                m.insert(format!("net.ipv4.conf.{scope}.send_redirects"), "0".into());
            }
            for dev in &self.send_redirects_off {
                let Some(seg) = device_segment(dev) else {
                    tracing::warn!(device = %dev, "cannot express device as a sysctl key; leaving its redirects alone");
                    continue;
                };
                m.insert(format!("net.ipv4.conf.{seg}.send_redirects"), "0".into());
            }
        }
        for (k, v) in &self.extra {
            if !valid_key(k) {
                return Err(SysctlError::BadKey(k.clone()));
            }
            if v.chars().any(char::is_control) {
                return Err(SysctlError::BadValue(k.clone()));
            }
            m.insert(k.clone(), v.trim().to_owned());
        }
        Ok(m)
    }
}

/// Render a `sysctl.d` file.
pub fn render_conf(map: &BTreeMap<String, String>) -> String {
    let mut s = String::from("# Generated by sensr; do not edit.\n");
    for (k, v) in map {
        let _ = writeln!(s, "{k} = {v}");
    }
    s
}

/// `k = v` lines of a [`render_conf`] file.
fn parse_conf(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let (k, v) = l.split_once('=')?;
            Some((k.trim().to_owned(), v.trim().to_owned()))
        })
        .collect()
}

/// An IPv4 ICMP redirect switch (`net.ipv4.conf.<scope>.send_redirects`).
fn is_send_redirects(key: &str) -> bool {
    key.starts_with("net.ipv4.conf.") && key.ends_with(".send_redirects")
}

/// Swap `.` and `/`: sysctl keys use `.` between segments and `/` inside
/// them, paths the reverse.
fn swap_dots_slashes(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            '.' => '/',
            '/' => '.',
            c => c,
        })
        .collect()
}

/// The sysctl applier, rooted at `/` in production.
#[derive(Debug, Clone)]
pub struct Sysctl {
    root: PathBuf,
}

/// Path of the generated sysctl.d file, relative to the root.
pub const CONF_PATH: &str = "run/sensr/sysctl.d/50-sensr.conf";

/// One differing tunable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysctlChange {
    /// Key.
    pub key: String,
    /// Live value (`None` if the key does not exist on this kernel).
    pub current: Option<String>,
    /// Desired value.
    pub wanted: String,
}

/// Apply errors.
#[derive(Debug, thiserror::Error)]
pub enum SysctlApplyError {
    /// Invalid model.
    #[error(transparent)]
    Model(#[from] SysctlError),
    /// Writing the conf file failed.
    #[error(transparent)]
    File(#[from] TemplateError),
    /// Writing `/proc/sys/...` failed.
    #[error("{key}: {source}")]
    Proc {
        /// Key.
        key: String,
        /// OS error.
        source: std::io::Error,
    },
}

impl Sysctl {
    /// Applier rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Sysctl { root: root.into() }
    }

    /// `/proc/sys` path of a key (dots and slashes swapped, see
    /// [`device_segment`]).
    fn proc_path(&self, key: &str) -> PathBuf {
        self.root
            .join("proc/sys")
            .join(Path::new(&swap_dots_slashes(key)))
    }

    /// Current kernel value.
    pub fn read(&self, key: &str) -> Option<String> {
        std::fs::read_to_string(self.proc_path(key))
            .ok()
            .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
    }

    /// The redirect switches to turn back on: `send_redirects = 0` in the
    /// conf file sensr last wrote, absent from `wanted`, and still present
    /// on this kernel (a removed device has no key). Empty when sensr never
    /// turned redirects off.
    pub fn restores(&self, wanted: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        let Ok(prev) = std::fs::read_to_string(self.root.join(CONF_PATH)) else {
            return BTreeMap::new();
        };
        parse_conf(&prev)
            .into_iter()
            .filter(|(k, v)| is_send_redirects(k) && v == "0" && !wanted.contains_key(k))
            .filter(|(k, _)| self.read(k).is_some())
            .map(|(k, _)| (k, "1".to_owned()))
            .collect()
    }

    /// Tunables whose live value differs from `wanted`.
    pub fn diff(&self, wanted: &BTreeMap<String, String>) -> Vec<SysctlChange> {
        wanted
            .iter()
            .filter_map(|(k, v)| {
                let cur = self.read(k);
                (cur.as_deref() != Some(v.as_str())).then(|| SysctlChange {
                    key: k.clone(),
                    current: cur,
                    wanted: v.clone(),
                })
            })
            .collect()
    }

    /// Write the conf file and set every differing tunable, plus the
    /// [`restores`](Self::restores). Returns what changed; applying again
    /// returns nothing.
    pub fn apply(&self, model: &SysctlModel) -> Result<Vec<SysctlChange>, SysctlApplyError> {
        let map = model.to_map()?;
        let restores = self.restores(&map);
        write_atomic(
            &self.root.join(CONF_PATH),
            render_conf(&map).as_bytes(),
            0o644,
        )?;
        let mut changes = self.diff(&map);
        changes.extend(self.diff(&restores));
        for c in &changes {
            std::fs::write(self.proc_path(&c.key), format!("{}\n", c.wanted)).map_err(
                |source| SysctlApplyError::Proc {
                    key: c.key.clone(),
                    source,
                },
            )?;
        }
        Ok(changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_proc(root: &Path, keys: &[(&str, &str)]) {
        for (k, v) in keys {
            let p = root.join("proc/sys").join(k.replace('.', "/"));
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, format!("{v}\n")).unwrap();
        }
    }

    #[test]
    fn send_redirects_off_when_hosts_locked() {
        let m = SysctlModel {
            send_redirects_off: vec!["eth1".into()],
            ..Default::default()
        }
        .to_map()
        .unwrap();
        for k in ["all", "default", "eth1"] {
            assert_eq!(m[&format!("net.ipv4.conf.{k}.send_redirects")], "0");
        }
    }

    #[test]
    fn dotted_device_maps_to_its_proc_path() {
        let m = SysctlModel {
            send_redirects_off: vec!["vlan0.100".into()],
            ..Default::default()
        };
        let map = m.to_map().unwrap();
        let key = "net.ipv4.conf.vlan0/100.send_redirects";
        assert_eq!(map[key], "0");
        let root = tempfile::tempdir().unwrap();
        let live = root.path().join("proc/sys/net/ipv4/conf/vlan0.100");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("send_redirects"), "1\n").unwrap();
        for d in ["all", "default"] {
            let p = root.path().join(format!("proc/sys/net/ipv4/conf/{d}"));
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("send_redirects"), "1\n").unwrap();
        }
        let s = Sysctl::new(root.path());
        assert_eq!(s.read(key).as_deref(), Some("1"));
        // The live file is found (not a missing `vlan0/100/` tree).
        assert!(
            s.diff(&map)
                .iter()
                .any(|c| c.key == key && c.current.as_deref() == Some("1"))
        );
    }

    #[test]
    fn uppercase_device_does_not_fail_and_odd_device_is_skipped() {
        let m = SysctlModel {
            send_redirects_off: vec!["ETH1".into(), "we!rd".into(), "..".into()],
            ..Default::default()
        };
        let map = m.to_map().unwrap();
        assert_eq!(map["net.ipv4.conf.ETH1.send_redirects"], "0");
        assert!(
            map.keys()
                .all(|k| !k.contains("we!rd") && !k.contains(".."))
        );
    }

    /// The default model's keys at their values (so they never change).
    fn base_proc(root: &Path) {
        let m = SysctlModel::default().to_map().unwrap();
        let pairs: Vec<(&str, &str)> = m.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        fake_proc(root, &pairs);
    }

    fn redirect_proc(root: &Path, devs: &[&str]) {
        base_proc(root);
        let keys: Vec<String> = ["all", "default"]
            .iter()
            .chain(devs)
            .map(|d| format!("net.ipv4.conf.{d}.send_redirects"))
            .collect();
        let pairs: Vec<(&str, &str)> = keys.iter().map(|k| (k.as_str(), "1")).collect();
        fake_proc(root, &pairs);
    }

    fn redirects(s: &Sysctl, devs: &[&str]) -> Vec<String> {
        ["all", "default"]
            .iter()
            .chain(devs)
            .map(|d| {
                s.read(&format!("net.ipv4.conf.{d}.send_redirects"))
                    .unwrap_or_default()
            })
            .collect()
    }

    /// Unlocking the last host (or turning interception off: the model
    /// loses the devices either way) turns redirects back on.
    #[test]
    fn redirects_return_to_one_when_interception_stops() {
        let root = tempfile::tempdir().unwrap();
        redirect_proc(root.path(), &["eth1", "eth2"]);
        let s = Sysctl::new(root.path());
        let locked = SysctlModel {
            send_redirects_off: vec!["eth1".into(), "eth2".into()],
            ..Default::default()
        };
        s.apply(&locked).unwrap();
        assert_eq!(redirects(&s, &["eth1", "eth2"]), ["0", "0", "0", "0"]);

        // one link leaves (an interface no longer internal): only it returns
        let one = SysctlModel {
            send_redirects_off: vec!["eth1".into()],
            ..Default::default()
        };
        let c = s.apply(&one).unwrap();
        assert_eq!(c.len(), 1, "{c:?}");
        assert_eq!(c[0].key, "net.ipv4.conf.eth2.send_redirects");
        assert_eq!(redirects(&s, &["eth1", "eth2"]), ["0", "0", "0", "1"]);

        // interception stops: a fresh applier (an agent restart) still knows
        let s = Sysctl::new(root.path());
        let c = s.apply(&SysctlModel::default()).unwrap();
        assert_eq!(c.len(), 3, "{c:?}");
        assert!(
            c.iter()
                .all(|c| c.wanted == "1" && c.current.as_deref() == Some("0"))
        );
        assert_eq!(redirects(&s, &["eth1", "eth2"]), ["1", "1", "1", "1"]);
        // nothing is held back: the next apply restores nothing
        assert!(
            s.restores(&SysctlModel::default().to_map().unwrap())
                .is_empty()
        );
        assert!(s.apply(&SysctlModel::default()).unwrap().is_empty());
        let conf = std::fs::read_to_string(root.path().join(CONF_PATH)).unwrap();
        assert!(!conf.contains("send_redirects"), "{conf}");
    }

    /// A device that vanished with its link is not restored (no key).
    #[test]
    fn a_removed_device_is_not_restored() {
        let root = tempfile::tempdir().unwrap();
        redirect_proc(root.path(), &["eth1"]);
        let s = Sysctl::new(root.path());
        s.apply(&SysctlModel {
            send_redirects_off: vec!["eth1".into()],
            ..Default::default()
        })
        .unwrap();
        std::fs::remove_dir_all(root.path().join("proc/sys/net/ipv4/conf/eth1")).unwrap();
        let c = s.apply(&SysctlModel::default()).unwrap();
        assert_eq!(c.len(), 2, "all and default only: {c:?}");
    }

    /// Factory: sensr never turned redirects off, so it emits and writes
    /// nothing for them, even where the kernel holds 0.
    #[test]
    fn factory_touches_no_redirect_keys() {
        let root = tempfile::tempdir().unwrap();
        base_proc(root.path());
        fake_proc(root.path(), &[("net.ipv4.conf.all.send_redirects", "0")]);
        let s = Sysctl::new(root.path());
        let map = SysctlModel::default().to_map().unwrap();
        assert!(s.restores(&map).is_empty());
        let c = s.apply(&SysctlModel::default()).unwrap();
        assert!(c.iter().all(|c| !c.key.contains("send_redirects")), "{c:?}");
        assert_eq!(
            s.read("net.ipv4.conf.all.send_redirects").as_deref(),
            Some("0")
        );
    }

    #[test]
    fn no_redirect_keys_by_default() {
        let m = SysctlModel::default().to_map().unwrap();
        assert!(m.keys().all(|k| !k.contains("send_redirects")));
    }

    #[test]
    fn default_model_golden() {
        let m = SysctlModel {
            conntrack_max: Some(262_144),
            ..Default::default()
        };
        insta::assert_snapshot!(render_conf(&m.to_map().unwrap()));
    }

    #[test]
    fn apply_writes_only_differences_and_is_idempotent() {
        let root = tempfile::tempdir().unwrap();
        fake_proc(
            root.path(),
            &[
                ("net.ipv4.ip_forward", "0"),
                ("net.ipv6.conf.all.forwarding", "1"),
                ("net.ipv6.conf.default.accept_ra", "1"),
                ("net.ipv4.conf.all.rp_filter", "2"),
                ("net.ipv4.conf.default.rp_filter", "2"),
            ],
        );
        let s = Sysctl::new(root.path());
        let changes = s.apply(&SysctlModel::default()).unwrap();
        let keys: Vec<_> = changes.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(
            keys,
            ["net.ipv4.ip_forward", "net.ipv6.conf.default.accept_ra"]
        );
        assert_eq!(changes[0].current.as_deref(), Some("0"));
        assert_eq!(s.read("net.ipv4.ip_forward").as_deref(), Some("1"));
        assert!(s.apply(&SysctlModel::default()).unwrap().is_empty());
        assert!(root.path().join(CONF_PATH).is_file());
    }

    #[test]
    fn bad_keys_cannot_escape_proc() {
        for k in ["../../etc/passwd", "net..x", "Net.IPv4", ".x", "a/b"] {
            let m = SysctlModel {
                extra: [(k.to_owned(), "1".to_owned())].into(),
                ..Default::default()
            };
            assert!(matches!(m.to_map(), Err(SysctlError::BadKey(_))), "{k}");
        }
        let m = SysctlModel {
            extra: [("kernel.x".to_owned(), "1\n2".to_owned())].into(),
            ..Default::default()
        };
        assert!(matches!(m.to_map(), Err(SysctlError::BadValue(_))));
    }
}
