//! Load a pack's BPF object, attach its LSM programs, and apply compiled
//! rules to its maps (`bpf/guard/README.md` is the map contract).
//!
//! A pack has one object: the core pack's programs are linked into
//! `core.bpf.o` at build time, so every program shares one instance of each
//! map. Nothing is pinned: dropping [`Loaded`] closes every link and map, so
//! the programs live and die with the process (fail open).
//!
//! [`apply`](Loaded::apply) follows a plan computed here, without the
//! kernel, so its ordering and hit attribution are unit-tested anywhere:
//!
//! 1. with the kill switch on, `config` first (nothing blocks meanwhile);
//! 2. every slot whose rule id changes is disabled and its `hits` zeroed,
//!    so a count always belongs to the rule id now in that slot;
//! 3. every new dimension entry is inserted or overwritten;
//! 4. only then are the stale keys deleted;
//! 5. the new `rules_meta` is written, which enables the new rules;
//! 6. `config` last (kill switch off).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;

use crate::compile::Compiled;
use crate::maps::{GuardConfig, GuardRuleMeta};

#[cfg(target_os = "linux")]
mod kernel;
#[cfg(target_os = "linux")]
pub use kernel::{ApplyError, LoadError, Loaded, load};

/// One program of the pack, and whether it is attached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProgramStatus {
    /// The program (function) name, e.g. `guard_connect`.
    pub name: String,
    /// The LSM hook, e.g. `socket_connect`.
    pub hook: String,
    /// Whether it is loaded and attached.
    pub attached: bool,
    /// Why not, when it is not.
    pub reason: Option<String>,
}

/// The dimension maps, in the order [`ApplyPlan::upserts`] lists them.
pub const DIMENSION_MAPS: [&str; 7] = [
    "exe_prefix_lpm",
    "path_prefix_lpm",
    "net4_lpm",
    "net6_lpm",
    "port_rules",
    "unit_rules",
    "uid_rules",
];

/// What the maps hold after the last [`apply`](Loaded::apply), as far as
/// userspace knows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Applied {
    /// The rule id in each slot; `None` when unknown (a failed apply), which
    /// the next apply treats as changed.
    pub ids: Vec<Option<String>>,
    /// The keys written to each dimension map.
    pub keys: BTreeMap<&'static str, BTreeSet<Vec<u8>>>,
}

/// The map writes of one apply, in the order they are made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyPlan {
    /// Write `config` before everything else (the kill switch goes on).
    pub config_first: bool,
    /// Slots to disable and whose hits to zero, before any other write.
    pub reset_slots: Vec<u32>,
    /// Dimension entries to insert or overwrite: (map, key, rule set).
    pub upserts: Vec<(&'static str, Vec<u8>, [u8; 128])>,
    /// Stale dimension keys to delete, after every upsert.
    pub deletes: Vec<(&'static str, Vec<u8>)>,
    /// The new `rules_meta`, slot by slot.
    pub meta: Vec<(u32, [u8; 8])>,
    /// The `config[0]` value.
    pub config: [u8; 8],
}

/// Every dimension map's entries in `c`, as raw key and value bytes.
fn dimension_entries(c: &Compiled) -> [Vec<(Vec<u8>, [u8; 128])>; 7] {
    fn raw<K, const N: usize>(
        v: &[(K, crate::maps::RuleSet)],
        f: impl Fn(&K) -> [u8; N],
    ) -> Vec<(Vec<u8>, [u8; 128])> {
        v.iter()
            .map(|(k, s)| (f(k).to_vec(), s.as_bytes()))
            .collect()
    }
    [
        raw(&c.exe_lpm, |k| k.as_bytes()),
        raw(&c.path_lpm, |k| k.as_bytes()),
        raw(&c.net4, |k| k.as_bytes()),
        raw(&c.net6, |k| k.as_bytes()),
        raw(&c.ports, |k| k.as_bytes()),
        raw(&c.units, |k| k.as_bytes()),
        raw(&c.uids, |k| k.as_bytes()),
    ]
}

/// The slots whose rule id differs between `prev` and `c` (including
/// slots that only one of them has, and slots `prev` does not know).
pub fn changed_slots(prev: &[Option<String>], c: &Compiled) -> Vec<u32> {
    let n = prev.len().max(c.meta.len());
    (0..n)
        .filter(|&s| {
            let old = prev.get(s).and_then(|o| o.as_deref());
            let new = c.meta.get(s).map(|m| m.id.as_str());
            old.is_none() || old != new
        })
        .map(|s| s as u32)
        .collect()
}

/// The `config[0]` bytes.
pub fn config_bytes(kill_switch: bool, guard_tgid: u32) -> [u8; 8] {
    GuardConfig {
        kill_switch: u8::from(kill_switch),
        _pad: [0; 3],
        guard_tgid,
    }
    .as_bytes()
}

/// The `rules_meta` value of a slot that matches nothing.
pub fn disabled_meta(slot: u32) -> [u8; 8] {
    GuardRuleMeta {
        id: slot,
        ..GuardRuleMeta::default()
    }
    .as_bytes()
}

/// Plan the writes that take the maps from `prev` to `c`.
pub fn plan(prev: &Applied, c: &Compiled, kill_switch: bool, guard_tgid: u32) -> ApplyPlan {
    let entries = dimension_entries(c);
    let mut upserts = Vec::new();
    let mut deletes = Vec::new();
    for (map, new) in DIMENSION_MAPS.iter().zip(entries) {
        let new_keys: BTreeSet<&[u8]> = new.iter().map(|(k, _)| k.as_slice()).collect();
        if let Some(old) = prev.keys.get(map) {
            deletes.extend(
                old.iter()
                    .filter(|k| !new_keys.contains(k.as_slice()))
                    .map(|k| (*map, k.clone())),
            );
        }
        upserts.extend(new.into_iter().map(|(k, v)| (*map, k, v)));
    }
    ApplyPlan {
        config_first: kill_switch,
        reset_slots: changed_slots(&prev.ids, c),
        upserts,
        deletes,
        meta: c
            .meta
            .iter()
            .enumerate()
            .map(|(s, m)| (s as u32, m.meta.as_bytes()))
            .collect(),
        config: config_bytes(kill_switch, guard_tgid),
    }
}

impl Applied {
    /// The state after `c` was applied in full.
    pub fn after(c: &Compiled) -> Self {
        let keys = DIMENSION_MAPS
            .iter()
            .zip(dimension_entries(c))
            .map(|(m, e)| (*m, e.into_iter().map(|(k, _)| k).collect()))
            .collect();
        Self {
            ids: c.meta.iter().map(|m| Some(m.id.clone())).collect(),
            keys,
        }
    }

    /// The state after applying `c` failed part way: any key of either side
    /// may be present, and no slot's rule id is known.
    pub fn after_failure(prev: &Self, c: &Compiled) -> Self {
        let mut keys = prev.keys.clone();
        for (m, k) in Self::after(c).keys {
            keys.entry(m).or_default().extend(k);
        }
        Self {
            ids: vec![None; prev.ids.len().max(c.meta.len())],
            keys,
        }
    }
}

/// Per-slot hit counts turned into per-rule-id counts (slots with no known
/// rule id are left out).
pub fn hits_by_id(ids: &[Option<String>], per_slot: &HashMap<u32, u64>) -> HashMap<String, u64> {
    ids.iter()
        .enumerate()
        .filter_map(|(s, id)| {
            let id = id.as_ref()?;
            Some((id.clone(), per_slot.get(&(s as u32)).copied().unwrap_or(0)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::compile;
    use crate::rule::{Action, Hook, ProcessMatch, Rule, Target};

    fn net(id: &str, cidr: &str, ports: &[u16], action: Action) -> Rule {
        Rule {
            id: id.into(),
            enabled: true,
            description: String::new(),
            hook: Hook::Connect,
            process: ProcessMatch::default(),
            target: Target::Net {
                cidr: cidr.parse().unwrap(),
                ports: ports.to_vec(),
            },
            action,
        }
    }

    fn keys_of<'a>(p: &'a [(&'static str, Vec<u8>, [u8; 128])], map: &str) -> Vec<&'a [u8]> {
        p.iter()
            .filter(|(m, ..)| *m == map)
            .map(|(_, k, _)| k.as_slice())
            .collect()
    }

    #[test]
    fn first_apply_writes_everything_and_resets_every_slot() {
        let c = compile(&[
            net("a", "192.0.2.1/32", &[80], Action::Block),
            net("b", "198.51.100.0/24", &[], Action::Alert),
        ])
        .unwrap();
        let p = plan(&Applied::default(), &c, false, 42);
        assert_eq!(p.reset_slots, vec![0, 1]);
        assert!(p.deletes.is_empty());
        let total: usize = dimension_entries(&c).iter().map(Vec::len).sum();
        assert_eq!(p.upserts.len(), total);
        // the /32 block's key is there, at 192.0.2.1
        let mut k = 32u32.to_le_bytes().to_vec();
        k.extend([192, 0, 2, 1]);
        assert!(keys_of(&p.upserts, "net4_lpm").contains(&k.as_slice()));
        // port 80 and the any-port wildcard (for "b")
        let ports = keys_of(&p.upserts, "port_rules");
        assert!(ports.contains(&80u32.to_le_bytes().as_slice()));
        assert!(ports.contains(&0x10000u32.to_le_bytes().as_slice()));
        assert_eq!(p.meta.len(), 2);
        assert_eq!(p.meta[0], (0, c.meta[0].meta.as_bytes()));
        assert!(!p.config_first);
        assert_eq!(p.config, [0, 0, 0, 0, 42, 0, 0, 0]);
    }

    #[test]
    fn upserts_cover_every_dimension_map_in_order() {
        let c = compile(&[net("a", "2001:db8::/32", &[443], Action::Alert)]).unwrap();
        let p = plan(&Applied::default(), &c, false, 1);
        let mut maps: Vec<&str> = p.upserts.iter().map(|(m, ..)| *m).collect();
        maps.dedup();
        // every map the rule touches, in DIMENSION_MAPS order
        let pos: Vec<usize> = maps
            .iter()
            .map(|m| DIMENSION_MAPS.iter().position(|d| d == m).unwrap())
            .collect();
        assert!(pos.windows(2).all(|w| w[0] < w[1]), "{maps:?}");
        assert!(maps.contains(&"net6_lpm") && maps.contains(&"exe_prefix_lpm"));
    }

    #[test]
    fn stale_keys_are_deleted_and_kept_keys_are_not() {
        let old = compile(&[
            net("a", "192.0.2.1/32", &[80], Action::Block),
            net("b", "198.51.100.0/24", &[22], Action::Alert),
        ])
        .unwrap();
        let new = compile(&[net("a", "192.0.2.1/32", &[80], Action::Block)]).unwrap();
        let p = plan(&Applied::after(&old), &new, false, 1);
        let del4: Vec<_> = p
            .deletes
            .iter()
            .filter(|(m, _)| *m == "net4_lpm")
            .map(|(_, k)| k.clone())
            .collect();
        let mut gone = 24u32.to_le_bytes().to_vec();
        gone.extend([198, 51, 100, 0]);
        assert_eq!(del4, vec![gone]);
        let delp: Vec<_> = p
            .deletes
            .iter()
            .filter(|(m, _)| *m == "port_rules")
            .map(|(_, k)| k.clone())
            .collect();
        assert_eq!(delp, vec![22u32.to_le_bytes().to_vec()]);
        // nothing still in use is deleted
        let now = Applied::after(&new);
        for (m, k) in &p.deletes {
            assert!(!now.keys[m].contains(k), "{m} {k:?}");
        }
        // slot 0 keeps "a"; slot 1 lost "b"
        assert_eq!(p.reset_slots, vec![1]);
        assert_eq!(p.meta.len(), 1);
    }

    #[test]
    fn same_rules_again_change_nothing_but_overwrite() {
        let c = compile(&[net("a", "192.0.2.1/32", &[80], Action::Block)]).unwrap();
        let p = plan(&Applied::after(&c), &c, false, 1);
        assert!(p.reset_slots.is_empty());
        assert!(p.deletes.is_empty());
        assert!(!p.upserts.is_empty());
    }

    #[test]
    fn slots_whose_rule_id_changes_are_reset() {
        // "b" moves from slot 1 to 0 and "a" from 0 to 1; "c" keeps slot 2
        let old = compile(&[
            net("a", "192.0.2.1/32", &[], Action::Alert),
            net("b", "192.0.2.2/32", &[], Action::Alert),
            net("c", "192.0.2.3/32", &[], Action::Alert),
        ])
        .unwrap();
        let new = compile(&[
            net("b", "192.0.2.2/32", &[], Action::Alert),
            net("a", "192.0.2.1/32", &[], Action::Alert),
            net("c", "192.0.2.3/32", &[], Action::Alert),
            net("d", "192.0.2.4/32", &[], Action::Alert),
        ])
        .unwrap();
        let p = plan(&Applied::after(&old), &new, false, 1);
        assert_eq!(p.reset_slots, vec![0, 1, 3]);
    }

    #[test]
    fn disabled_rule_keeps_its_slot_and_its_hits() {
        let mut b = net("b", "192.0.2.2/32", &[], Action::Block);
        let a = net("a", "192.0.2.1/32", &[], Action::Alert);
        let old = compile(&[a.clone(), b.clone()]).unwrap();
        b.enabled = false;
        let new = compile(&[a, b]).unwrap();
        let p = plan(&Applied::after(&old), &new, false, 1);
        assert!(p.reset_slots.is_empty());
        assert_eq!(p.meta[1].1[6], 0, "slot 1 written as disabled");
    }

    #[test]
    fn fewer_rules_reset_the_trailing_slots() {
        let old = compile(&[
            net("a", "192.0.2.1/32", &[], Action::Alert),
            net("b", "192.0.2.2/32", &[], Action::Alert),
            net("c", "192.0.2.3/32", &[], Action::Alert),
        ])
        .unwrap();
        let new = compile(&[net("a", "192.0.2.1/32", &[], Action::Alert)]).unwrap();
        let p = plan(&Applied::after(&old), &new, false, 1);
        assert_eq!(p.reset_slots, vec![1, 2]);
        assert_eq!(disabled_meta(2), [2, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn kill_switch_goes_on_first_and_off_last() {
        let c = compile(&[net("a", "192.0.2.1/32", &[80], Action::Block)]).unwrap();
        let on = plan(&Applied::default(), &c, true, 7);
        assert!(on.config_first);
        assert_eq!(on.config, [1, 0, 0, 0, 7, 0, 0, 0]);
        let off = plan(&Applied::after(&c), &c, false, 7);
        assert!(!off.config_first);
        assert_eq!(off.config[0], 0);
    }

    #[test]
    fn failed_apply_forgets_slot_ids_and_keeps_every_key() {
        let old = compile(&[net("a", "192.0.2.1/32", &[22], Action::Alert)]).unwrap();
        let new = compile(&[net("a", "198.51.100.0/24", &[80], Action::Alert)]).unwrap();
        let prev = Applied::after(&old);
        let f = Applied::after_failure(&prev, &new);
        assert_eq!(f.ids, vec![None]);
        let a = Applied::after(&old);
        let b = Applied::after(&new);
        for m in DIMENSION_MAPS {
            let want: BTreeSet<_> = a.keys[m].union(&b.keys[m]).cloned().collect();
            assert_eq!(f.keys[m], want, "{m}");
        }
        // so the next apply of `new` resets slot 0 again and deletes old keys
        let p = plan(&f, &new, false, 1);
        assert_eq!(p.reset_slots, vec![0]);
        assert!(p.deletes.iter().any(|(m, _)| *m == "port_rules"));
    }

    #[test]
    fn hits_are_reported_by_rule_id() {
        let ids = vec![Some("a".to_string()), None, Some("c".to_string())];
        let per_slot = HashMap::from([(0, 5), (1, 9), (2, 0)]);
        let h = hits_by_id(&ids, &per_slot);
        assert_eq!(h, HashMap::from([("a".into(), 5), ("c".into(), 0)]));
    }
}
