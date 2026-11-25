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
//! 2. every slot that changes is disabled in `rules_meta`: its rule id
//!    changed (then its `hits` are zeroed too, so a count always belongs to
//!    the rule id now in that slot), or the same rule now matches something
//!    else or has another hook, action or enabled flag. Between the
//!    dimension writes such a rule could match a mix of its old and new
//!    keys; disabled, it fails open instead;
//! 3. in a map where the old and new keys together exceed its capacity,
//!    the stale keys are deleted first (and then every slot is disabled in
//!    step 2, since any rule may briefly miss entries);
//! 4. every new dimension entry is inserted or overwritten;
//! 5. only then are the remaining stale keys deleted;
//! 6. the new `rules_meta` is written, which enables the new rules;
//! 7. `config` last (kill switch off).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;

use crate::compile::Compiled;
use crate::maps::{
    GuardConfig, GuardRuleMeta, MAX_NET_KEYS, MAX_PATH_KEYS, MAX_PORT_KEYS, MAX_UID_KEYS,
    MAX_UNIT_KEYS,
};

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

/// A dimension map's `max_entries` (common.h).
pub fn capacity(map: &str) -> usize {
    match map {
        "exe_prefix_lpm" | "path_prefix_lpm" => MAX_PATH_KEYS,
        "net4_lpm" | "net6_lpm" => MAX_NET_KEYS,
        "port_rules" => MAX_PORT_KEYS,
        "unit_rules" => MAX_UNIT_KEYS,
        "uid_rules" => MAX_UID_KEYS,
        _ => 0,
    }
}

/// What one slot held after the last apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotState {
    /// The rule id.
    pub id: String,
    /// Its `rules_meta` value.
    pub meta: [u8; 8],
    /// What it matches ([`crate::compile::RuleMeta::matches`]).
    pub matches: Vec<(&'static str, Vec<u8>)>,
}

/// What the maps hold after the last [`apply`](Loaded::apply), as far as
/// userspace knows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Applied {
    /// Each slot; `None` when unknown (a failed apply), which the next
    /// apply treats as a changed rule id.
    pub slots: Vec<Option<SlotState>>,
    /// The keys written to each dimension map.
    pub keys: BTreeMap<&'static str, BTreeSet<Vec<u8>>>,
}

/// The map writes of one apply, in the order they are made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyPlan {
    /// Write `config` before everything else (the kill switch goes on).
    pub config_first: bool,
    /// Slots to disable in `rules_meta` before any dimension write.
    pub disable_slots: Vec<u32>,
    /// Slots whose hits to zero (their rule id changed); a subset of
    /// `disable_slots`.
    pub zero_hits: Vec<u32>,
    /// Stale keys deleted before the upserts, in maps that could not hold
    /// the old and new keys together.
    pub early_deletes: Vec<(&'static str, Vec<u8>)>,
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

fn slot_states(c: &Compiled) -> Vec<Option<SlotState>> {
    c.meta
        .iter()
        .map(|m| {
            Some(SlotState {
                id: m.id.clone(),
                meta: m.meta.as_bytes(),
                matches: m.matches.clone(),
            })
        })
        .collect()
}

/// The slots whose rule id differs between `prev` and `c` (including
/// slots that only one of them has, and slots `prev` does not know).
pub fn changed_slots(prev: &[Option<SlotState>], c: &Compiled) -> Vec<u32> {
    let n = prev.len().max(c.meta.len());
    (0..n)
        .filter(|&s| {
            let old = prev.get(s).and_then(|o| o.as_ref()).map(|o| o.id.as_str());
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
    plan_with(prev, c, kill_switch, guard_tgid, capacity)
}

/// [`plan`] with the maps' capacities given (tests use small ones).
pub fn plan_with(
    prev: &Applied,
    c: &Compiled,
    kill_switch: bool,
    guard_tgid: u32,
    capacity: impl Fn(&str) -> usize,
) -> ApplyPlan {
    let entries = dimension_entries(c);
    let mut upserts = Vec::new();
    let mut deletes = Vec::new();
    let mut early_deletes = Vec::new();
    for (map, new) in DIMENSION_MAPS.iter().zip(entries) {
        let new_keys: BTreeSet<&[u8]> = new.iter().map(|(k, _)| k.as_slice()).collect();
        if let Some(old) = prev.keys.get(map) {
            let stale: Vec<_> = old
                .iter()
                .filter(|k| !new_keys.contains(k.as_slice()))
                .map(|k| (*map, k.clone()))
                .collect();
            // the map would hold old + new keys between the upserts and
            // the deletes
            if new_keys.len() + stale.len() > capacity(map) {
                early_deletes.extend(stale);
            } else {
                deletes.extend(stale);
            }
        }
        upserts.extend(new.into_iter().map(|(k, v)| (*map, k, v)));
    }

    let zero_hits = changed_slots(&prev.slots, c);
    let n = prev.slots.len().max(c.meta.len());
    let disable_slots = if early_deletes.is_empty() {
        let now = slot_states(c);
        (0..n)
            .filter(|&s| {
                let old = prev.slots.get(s).and_then(|o| o.as_ref());
                let new = now.get(s).and_then(|o| o.as_ref());
                old.is_none() || old != new
            })
            .map(|s| s as u32)
            .collect()
    } else {
        // deleting first takes entries away that unchanged rules still
        // use: every rule waits for the final rules_meta write
        (0..n as u32).collect()
    };

    ApplyPlan {
        config_first: kill_switch,
        disable_slots,
        zero_hits,
        early_deletes,
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
            slots: slot_states(c),
            keys,
        }
    }

    /// The state after applying `c` failed part way: any key of either side
    /// may be present, and no slot is known.
    pub fn after_failure(prev: &Self, c: &Compiled) -> Self {
        let mut keys = prev.keys.clone();
        for (m, k) in Self::after(c).keys {
            keys.entry(m).or_default().extend(k);
        }
        Self {
            slots: vec![None; prev.slots.len().max(c.meta.len())],
            keys,
        }
    }

    /// The rule id of each slot (`None`: unknown).
    pub fn ids(&self) -> Vec<Option<String>> {
        self.slots
            .iter()
            .map(|s| s.as_ref().map(|s| s.id.clone()))
            .collect()
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
        assert_eq!(p.disable_slots, vec![0, 1]);
        assert_eq!(p.zero_hits, vec![0, 1]);
        assert!(p.early_deletes.is_empty());
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
        assert_eq!(p.zero_hits, vec![1]);
        assert_eq!(p.disable_slots, vec![1]);
        assert_eq!(p.meta.len(), 1);
    }

    #[test]
    fn same_rules_again_change_nothing_but_overwrite() {
        let c = compile(&[net("a", "192.0.2.1/32", &[80], Action::Block)]).unwrap();
        let p = plan(&Applied::after(&c), &c, false, 1);
        assert!(p.disable_slots.is_empty() && p.zero_hits.is_empty());
        assert!(p.deletes.is_empty() && p.early_deletes.is_empty());
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
        assert_eq!(p.zero_hits, vec![0, 1, 3]);
        assert_eq!(p.disable_slots, vec![0, 1, 3]);
    }

    #[test]
    fn disabled_rule_keeps_its_slot_and_its_hits() {
        let mut b = net("b", "192.0.2.2/32", &[], Action::Block);
        let a = net("a", "192.0.2.1/32", &[], Action::Alert);
        let old = compile(&[a.clone(), b.clone()]).unwrap();
        b.enabled = false;
        let new = compile(&[a, b]).unwrap();
        let p = plan(&Applied::after(&old), &new, false, 1);
        assert!(p.zero_hits.is_empty(), "hits kept");
        assert_eq!(
            p.disable_slots,
            vec![1],
            "disabled before the dimension writes"
        );
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
        assert_eq!(p.zero_hits, vec![1, 2]);
        assert_eq!(p.disable_slots, vec![1, 2]);
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
        assert_eq!(f.slots, vec![None]);
        assert_eq!(f.ids(), vec![None]);
        let a = Applied::after(&old);
        let b = Applied::after(&new);
        for m in DIMENSION_MAPS {
            let want: BTreeSet<_> = a.keys[m].union(&b.keys[m]).cloned().collect();
            assert_eq!(f.keys[m], want, "{m}");
        }
        // so the next apply of `new` resets slot 0 again and deletes old keys
        let p = plan(&f, &new, false, 1);
        assert_eq!(p.zero_hits, vec![0]);
        assert_eq!(p.disable_slots, vec![0]);
        assert!(p.deletes.iter().any(|(m, _)| *m == "port_rules"));
    }

    #[test]
    fn hits_are_reported_by_rule_id() {
        let ids = vec![Some("a".to_string()), None, Some("c".to_string())];
        let per_slot = HashMap::from([(0, 5), (1, 9), (2, 0)]);
        let h = hits_by_id(&ids, &per_slot);
        assert_eq!(h, HashMap::from([("a".into(), 5), ("c".into(), 0)]));
    }

    /// Run `p` against a model of the kernel maps holding `keys`: every
    /// write must fit the capacity. Returns the keys at the end.
    fn simulate(
        mut keys: BTreeMap<&'static str, BTreeSet<Vec<u8>>>,
        p: &ApplyPlan,
        cap: impl Fn(&str) -> usize,
    ) -> Result<BTreeMap<&'static str, BTreeSet<Vec<u8>>>, String> {
        for (m, k) in &p.early_deletes {
            keys.entry(m).or_default().remove(k);
        }
        for (m, k, _) in &p.upserts {
            let set = keys.entry(m).or_default();
            if !set.contains(k) && set.len() >= cap(m) {
                return Err(format!("{m} full"));
            }
            set.insert(k.clone());
        }
        for (m, k) in &p.deletes {
            keys.entry(m).or_default().remove(k);
        }
        Ok(keys)
    }

    fn port_rules(id: &str, ports: &[u16]) -> Rule {
        net(id, "192.0.2.0/24", ports, Action::Alert)
    }

    #[test]
    fn a_full_map_deletes_stale_keys_first_and_fails_open() {
        // port_rules holds 4: {1, 2, 3} -> {4, 5, 6} needs 6 if inserted first
        let cap = |m: &str| if m == "port_rules" { 4 } else { 100 };
        let old = compile(&[port_rules("a", &[1, 2, 3]), port_rules("b", &[7])]).unwrap();
        let new = compile(&[port_rules("a", &[4, 5, 6]), port_rules("b", &[7])]).unwrap();
        let prev = Applied::after(&old);
        let p = plan_with(&prev, &new, false, 1, cap);
        let early: Vec<_> = p.early_deletes.iter().map(|(m, k)| (*m, k[0])).collect();
        assert_eq!(
            early,
            vec![("port_rules", 1), ("port_rules", 2), ("port_rules", 3)]
        );
        assert!(p.deletes.iter().all(|(m, _)| *m != "port_rules"));
        // every rule waits for the final rules_meta write, hits are kept
        assert_eq!(p.disable_slots, vec![0, 1]);
        assert!(p.zero_hits.is_empty());
        let end = simulate(prev.keys.clone(), &p, cap).unwrap();
        assert_eq!(end, Applied::after(&new).keys);
        // the insert-first order would not fit
        let mut naive = p.clone();
        naive
            .deletes
            .extend(std::mem::take(&mut naive.early_deletes));
        assert!(simulate(prev.keys, &naive, cap).is_err());
    }

    #[test]
    fn an_apply_after_a_failure_at_capacity_succeeds() {
        let cap = |m: &str| if m == "port_rules" { 4 } else { 100 };
        let old = compile(&[port_rules("a", &[1, 2, 3])]).unwrap();
        let new = compile(&[port_rules("a", &[4, 5, 6])]).unwrap();
        // the failed apply may have left any of old and new in the map
        let failed = Applied::after_failure(&Applied::after(&old), &new);
        assert_eq!(failed.keys["port_rules"].len(), 6);
        let p = plan_with(&failed, &new, false, 1, cap);
        assert_eq!(p.early_deletes.len(), 3);
        assert_eq!(p.disable_slots, vec![0]);
        assert_eq!(p.zero_hits, vec![0]);
        // whatever subset of the union is really there, the plan fits
        let mut there = Applied::after(&old).keys;
        there
            .get_mut("port_rules")
            .unwrap()
            .insert(4u32.to_le_bytes().to_vec());
        let end = simulate(there, &p, cap).unwrap();
        assert_eq!(end, Applied::after(&new).keys);
    }

    #[test]
    fn a_rule_that_changes_its_target_is_disabled_meanwhile() {
        // same id and slot: {10/8:80} -> {192.0.2.1:443}; between the writes
        // 10/8:443 and 192.0.2.1:80 would match
        let old = compile(&[net("a", "10.0.0.0/8", &[80], Action::Block)]).unwrap();
        let new = compile(&[net("a", "192.0.2.1/32", &[443], Action::Block)]).unwrap();
        let p = plan(&Applied::after(&old), &new, false, 1);
        assert_eq!(p.disable_slots, vec![0]);
        assert!(p.zero_hits.is_empty(), "same rule id: hits kept");
        assert_eq!(p.meta, vec![(0, new.meta[0].meta.as_bytes())]);
    }

    #[test]
    fn a_rule_that_changes_its_action_or_process_is_disabled_meanwhile() {
        let a = net("a", "192.0.2.1/32", &[80], Action::Alert);
        let mut blocking = a.clone();
        blocking.action = Action::Block;
        let mut scoped = a.clone();
        scoped.process.unit = Some("x.service".into());
        let old = compile(std::slice::from_ref(&a)).unwrap();
        for changed in [blocking, scoped] {
            let new = compile(&[changed]).unwrap();
            let p = plan(&Applied::after(&old), &new, false, 1);
            assert_eq!(p.disable_slots, vec![0]);
            assert!(p.zero_hits.is_empty());
        }
    }

    #[test]
    fn unrelated_changes_leave_other_rules_live() {
        let a = net("a", "192.0.2.1/32", &[80], Action::Block);
        let old = compile(std::slice::from_ref(&a)).unwrap();
        let new = compile(&[a, net("b", "198.51.100.0/24", &[], Action::Alert)]).unwrap();
        let p = plan(&Applied::after(&old), &new, false, 1);
        assert_eq!(p.disable_slots, vec![1], "only the new slot");
    }

    #[test]
    fn capacities_match_common_h() {
        for m in DIMENSION_MAPS {
            assert!(capacity(m) > 0, "{m}");
        }
        assert_eq!(capacity("port_rules"), 4096);
        assert_eq!(capacity("unit_rules"), 1025);
    }
}
