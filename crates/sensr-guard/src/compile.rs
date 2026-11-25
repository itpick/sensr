//! Compile rules into the BPF map entries described in `bpf/guard/README.md`.
//! Pure and deterministic: the same rules give the same entries, sorted by key.

use std::collections::BTreeMap;

use ipnet::IpNet;

use crate::maps::{
    GuardRuleMeta, MAX_NET_KEYS, MAX_PATH_KEYS, MAX_PORT_KEYS, MAX_RULES, MAX_UID_KEYS,
    MAX_UNIT_KEYS, Net4Key, Net6Key, PATH_LEN, PORT_ANY, PathKey, PortKey, RuleSet, UID_ANY,
    UNIT_LEN, UidKey, UnitKey,
};
use crate::rule::{Action, Hook, Rule, Target};

/// Why a rule set could not be compiled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompileError {
    /// More rules than slots.
    #[error("{0} rules, at most {MAX_RULES} fit")]
    TooMany(usize),
    /// A path prefix whose slash-terminated key does not fit in 255 bytes.
    #[error("rule {rule}: path {path:?} is too long (at most {max} bytes)", max = PATH_LEN - 2)]
    PathTooLong {
        /// The rule id.
        rule: String,
        /// The offending path.
        path: String,
    },
    /// A path that is not absolute or holds a NUL.
    #[error("rule {rule}: {path:?} is not an absolute path without NUL bytes")]
    BadPath {
        /// The rule id.
        rule: String,
        /// The offending path.
        path: String,
    },
    /// A unit name that is empty, has a NUL, or exceeds 63 bytes.
    #[error("rule {rule}: unit {unit:?} must be 1 to {max} bytes without NUL", max = UNIT_LEN - 1)]
    BadUnit {
        /// The rule id.
        rule: String,
        /// The offending unit.
        unit: String,
    },
    /// The target kind does not fit the hook.
    #[error("rule {rule}: a {target} target does not fit the {hook:?} hook")]
    TargetMismatch {
        /// The rule id.
        rule: String,
        /// The hook.
        hook: Hook,
        /// The target kind.
        target: &'static str,
    },
    /// 0xffffffff is the any-uid key.
    #[error("rule {0}: uid 4294967295 is reserved")]
    ReservedUid(String),
    /// Two rules share an id.
    #[error("duplicate rule id {0}")]
    DuplicateId(String),
    /// A map would exceed its capacity.
    #[error("{map} needs {needed} entries, at most {max} fit")]
    TooManyKeys {
        /// The map.
        map: &'static str,
        /// Entries needed.
        needed: usize,
        /// Capacity.
        max: usize,
    },
}

/// One slot of `rules_meta`, with the rule id it stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMeta {
    /// The rule id (userspace only; the BPF side knows the slot).
    pub id: String,
    /// The `rules_meta[slot]` value; `meta.id` is the slot.
    pub meta: GuardRuleMeta,
}

impl Compiled {
    /// The slot of a rule id (disabled rules keep theirs).
    pub fn slot_of(&self, id: &str) -> Option<u32> {
        self.meta.iter().position(|m| m.id == id).map(|i| i as u32)
    }
}

/// Every map's contents. Entries are sorted by key; LPM values are
/// cumulative (README, "LPM values are cumulative").
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Compiled {
    /// `rules_meta`, indexed by slot.
    pub meta: Vec<RuleMeta>,
    /// `exe_prefix_lpm`.
    pub exe_lpm: Vec<(PathKey, RuleSet)>,
    /// `path_prefix_lpm`.
    pub path_lpm: Vec<(PathKey, RuleSet)>,
    /// `net4_lpm`.
    pub net4: Vec<(Net4Key, RuleSet)>,
    /// `net6_lpm`.
    pub net6: Vec<(Net6Key, RuleSet)>,
    /// `port_rules`.
    pub ports: Vec<(PortKey, RuleSet)>,
    /// `unit_rules`.
    pub units: Vec<(UnitKey, RuleSet)>,
    /// `uid_rules`.
    pub uids: Vec<(UidKey, RuleSet)>,
}

/// The `enum guard_hook` number.
fn hook_number(h: Hook) -> u8 {
    match h {
        Hook::Exec => 0,
        Hook::Connect => 1,
        Hook::Listen => 2,
        Hook::FileWrite => 3,
        Hook::Setuid => 4,
        Hook::Module => 5,
        Hook::Bpf => 6,
    }
}

/// The `enum guard_action` number.
fn action_number(a: Action) -> u8 {
    match a {
        Action::Alert => 0,
        Action::Block => 1,
    }
}

/// An LPM key: a bit prefix of `data`.
trait LpmKey {
    fn plen(&self) -> u32;
    fn data(&self) -> &[u8];
}

impl LpmKey for PathKey {
    fn plen(&self) -> u32 {
        self.prefixlen
    }
    fn data(&self) -> &[u8] {
        &self.path
    }
}
impl LpmKey for Net4Key {
    fn plen(&self) -> u32 {
        self.prefixlen
    }
    fn data(&self) -> &[u8] {
        &self.addr
    }
}
impl LpmKey for Net6Key {
    fn plen(&self) -> u32 {
        self.prefixlen
    }
    fn data(&self) -> &[u8] {
        &self.addr
    }
}

/// Whether `a` is a bit prefix of `b` (so `a` covers every lookup `b` does).
fn covers<K: LpmKey>(a: &K, b: &K) -> bool {
    let n = a.plen();
    if n > b.plen() {
        return false;
    }
    let (full, rest) = ((n / 8) as usize, n % 8);
    if a.data()[..full] != b.data()[..full] {
        return false;
    }
    rest == 0 || {
        let mask = 0xffu8 << (8 - rest);
        (a.data()[full] ^ b.data()[full]) & mask == 0
    }
}

/// Make every entry's value the union of its own rules and those of every
/// shorter entry that covers it. Output is sorted by key.
fn cumulative<K: LpmKey + Ord + Copy>(own: BTreeMap<K, RuleSet>) -> Vec<(K, RuleSet)> {
    own.iter()
        .map(|(k, v)| {
            let mut set = *v;
            for (k2, v2) in &own {
                if k2 != k && covers(k2, k) {
                    set.union_with(v2);
                }
            }
            (*k, set)
        })
        .collect()
}

fn sorted<K: Ord, V>(m: BTreeMap<K, V>) -> Vec<(K, V)> {
    m.into_iter().collect()
}

fn add<K: Ord>(m: &mut BTreeMap<K, RuleSet>, k: K, slot: u32) {
    m.entry(k).or_default().insert(slot);
}

/// A path prefix as its two LPM keys: `"/p/"` and the exact `"/p\0"`
/// (the root is the single key `"/"`).
fn path_keys(rule: &str, p: &str) -> Result<Vec<PathKey>, CompileError> {
    // bpf_d_path is canonical: `.`, `..` and empty components never match.
    let bad_component = p
        .trim_end_matches('/')
        .split('/')
        .skip(1)
        .any(|c| matches!(c, "" | "." | ".."));
    if !p.starts_with('/') || p.contains('\0') || bad_component {
        return Err(CompileError::BadPath {
            rule: rule.into(),
            path: p.into(),
        });
    }
    let base = p.trim_end_matches('/');
    // The slash-terminated key must fit in 255 bytes, or no truncated
    // lookup key (at most 255 bytes) could ever reach it.
    if base.len() + 1 > PATH_LEN - 1 {
        return Err(CompileError::PathTooLong {
            rule: rule.into(),
            path: p.into(),
        });
    }
    if base.is_empty() {
        return Ok(vec![PathKey::from_bytes(b"/")]);
    }
    let mut prefix = base.as_bytes().to_vec();
    prefix.push(b'/');
    let mut exact = base.as_bytes().to_vec();
    exact.push(0);
    Ok(vec![
        PathKey::from_bytes(&prefix),
        PathKey::from_bytes(&exact),
    ])
}

fn unit_key(rule: &str, unit: &str) -> Result<UnitKey, CompileError> {
    if unit.is_empty() || unit.len() > UNIT_LEN - 1 || unit.contains('\0') {
        return Err(CompileError::BadUnit {
            rule: rule.into(),
            unit: unit.into(),
        });
    }
    let mut name = [0; UNIT_LEN];
    name[..unit.len()].copy_from_slice(unit.as_bytes());
    Ok(UnitKey { name })
}

fn target_kind(t: &Target) -> &'static str {
    match t {
        Target::Any => "any",
        Target::PathPrefix(_) => "path_prefix",
        Target::Net { .. } => "net",
        Target::Uid(_) => "uid",
    }
}

fn fits(hook: Hook, t: &Target) -> bool {
    matches!(
        (hook, t),
        (_, Target::Any)
            | (
                Hook::Exec | Hook::FileWrite | Hook::Module,
                Target::PathPrefix(_)
            )
            | (Hook::Connect | Hook::Listen, Target::Net { .. })
            | (Hook::Setuid, Target::Uid(_))
    )
}

#[derive(Default)]
struct Builder {
    exe: BTreeMap<PathKey, RuleSet>,
    path: BTreeMap<PathKey, RuleSet>,
    net4: BTreeMap<Net4Key, RuleSet>,
    net6: BTreeMap<Net6Key, RuleSet>,
    ports: BTreeMap<PortKey, RuleSet>,
    units: BTreeMap<UnitKey, RuleSet>,
    uids: BTreeMap<UidKey, RuleSet>,
}

impl Builder {
    fn add_net(&mut self, cidr: &IpNet, slot: u32) {
        match cidr.trunc() {
            IpNet::V4(n) => add(
                &mut self.net4,
                Net4Key {
                    prefixlen: u32::from(n.prefix_len()),
                    addr: n.network().octets(),
                },
                slot,
            ),
            IpNet::V6(n) => {
                let plen = u32::from(n.prefix_len());
                // The BPF side looks mapped addresses up in net4_lpm only, so an
                // explicit ::ffff:a.b.c.d/>=96 rule is a net4 rule. Any other v6
                // CIDR (even ::/0) matches native IPv6 only.
                if let (true, Some(v4)) = (plen >= 96, n.network().to_ipv4_mapped()) {
                    add(
                        &mut self.net4,
                        Net4Key {
                            prefixlen: plen - 96,
                            addr: v4.octets(),
                        },
                        slot,
                    );
                    return;
                }
                add(
                    &mut self.net6,
                    Net6Key {
                        prefixlen: plen,
                        addr: n.network().octets(),
                    },
                    slot,
                );
            }
        }
    }

    fn add_net_any(&mut self, slot: u32) {
        add(
            &mut self.net4,
            Net4Key {
                prefixlen: 0,
                addr: [0; 4],
            },
            slot,
        );
        add(
            &mut self.net6,
            Net6Key {
                prefixlen: 0,
                addr: [0; 16],
            },
            slot,
        );
        add(&mut self.ports, PortKey { port: PORT_ANY }, slot);
    }
}

fn check_cap(map: &'static str, needed: usize, max: usize) -> Result<(), CompileError> {
    if needed > max {
        return Err(CompileError::TooManyKeys { map, needed, max });
    }
    Ok(())
}

/// Compile the rules. Slot `n` is the n-th rule in input order, enabled or
/// not, so toggling a rule never renumbers the others. A disabled rule keeps
/// its slot with `enabled = 0`, contributes no map entries, and is still
/// validated.
pub fn compile(rules: &[Rule]) -> Result<Compiled, CompileError> {
    if rules.len() > MAX_RULES {
        return Err(CompileError::TooMany(rules.len()));
    }
    let mut live = Builder::default();
    let mut dead = Builder::default();
    let mut meta = Vec::with_capacity(rules.len());
    let mut seen = std::collections::HashSet::new();
    for (i, r) in rules.iter().enumerate() {
        let slot = i as u32;
        let b = if r.enabled { &mut live } else { &mut dead };
        if !seen.insert(r.id.as_str()) {
            return Err(CompileError::DuplicateId(r.id.clone()));
        }
        if !fits(r.hook, &r.target) {
            return Err(CompileError::TargetMismatch {
                rule: r.id.clone(),
                hook: r.hook,
                target: target_kind(&r.target),
            });
        }
        meta.push(RuleMeta {
            id: r.id.clone(),
            meta: GuardRuleMeta {
                id: slot,
                hook: hook_number(r.hook),
                action: action_number(r.action),
                enabled: u8::from(r.enabled),
                _pad: 0,
            },
        });
        // exe dimension
        match &r.process.exe_prefix {
            Some(p) => {
                for k in path_keys(&r.id, p)? {
                    add(&mut b.exe, k, slot);
                }
            }
            None => add(&mut b.exe, PathKey::wildcard(), slot),
        }
        // unit dimension
        let uk = match &r.process.unit {
            Some(u) => unit_key(&r.id, u)?,
            None => UnitKey {
                name: [0; UNIT_LEN],
            },
        };
        add(&mut b.units, uk, slot);
        // target dimensions
        match &r.target {
            Target::Any => match r.hook {
                Hook::Exec | Hook::FileWrite | Hook::Module => {
                    add(&mut b.path, PathKey::wildcard(), slot);
                }
                Hook::Connect | Hook::Listen => b.add_net_any(slot),
                Hook::Setuid => add(&mut b.uids, UidKey { uid: UID_ANY }, slot),
                Hook::Bpf => {}
            },
            Target::PathPrefix(p) => {
                for k in path_keys(&r.id, p)? {
                    add(&mut b.path, k, slot);
                }
            }
            Target::Net { cidr, ports } => {
                b.add_net(cidr, slot);
                if ports.is_empty() {
                    add(&mut b.ports, PortKey { port: PORT_ANY }, slot);
                }
                for p in ports {
                    add(
                        &mut b.ports,
                        PortKey {
                            port: u32::from(*p),
                        },
                        slot,
                    );
                }
            }
            Target::Uid(u) => {
                if *u == UID_ANY {
                    return Err(CompileError::ReservedUid(r.id.clone()));
                }
                add(&mut b.uids, UidKey { uid: *u }, slot);
            }
        }
    }
    check_cap("exe_prefix_lpm", live.exe.len(), MAX_PATH_KEYS)?;
    check_cap("path_prefix_lpm", live.path.len(), MAX_PATH_KEYS)?;
    check_cap("net4_lpm", live.net4.len(), MAX_NET_KEYS)?;
    check_cap("net6_lpm", live.net6.len(), MAX_NET_KEYS)?;
    check_cap("port_rules", live.ports.len(), MAX_PORT_KEYS)?;
    check_cap("unit_rules", live.units.len(), MAX_UNIT_KEYS)?;
    check_cap("uid_rules", live.uids.len(), MAX_UID_KEYS)?;
    Ok(Compiled {
        meta,
        exe_lpm: cumulative(live.exe),
        path_lpm: cumulative(live.path),
        net4: cumulative(live.net4),
        net6: cumulative(live.net6),
        ports: sorted(live.ports),
        units: sorted(live.units),
        uids: sorted(live.uids),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::ProcessMatch;

    fn rule(id: &str, hook: Hook, target: Target) -> Rule {
        Rule {
            id: id.into(),
            enabled: true,
            description: String::new(),
            hook,
            process: ProcessMatch::default(),
            target,
            action: Action::Block,
        }
    }

    fn pfx(p: &str) -> Target {
        Target::PathPrefix(p.into())
    }

    /// The kernel's LPM: the longest entry that covers the lookup key.
    fn lpm<'a, K: LpmKey>(entries: &'a [(K, RuleSet)], q: &K) -> Option<&'a RuleSet> {
        entries
            .iter()
            .filter(|(k, _)| covers(k, q))
            .max_by_key(|(k, _)| k.plen())
            .map(|(_, v)| v)
    }

    /// A lookup key as the BPF programs build it.
    fn path_q(p: &str) -> PathKey {
        let b = p.as_bytes();
        if b.len() > 255 {
            return PathKey::from_bytes(&b[..255]);
        }
        let mut v = b.to_vec();
        v.push(0);
        PathKey::from_bytes(&v)
    }

    fn path_hit(c: &Compiled, p: &str, slot: u32) -> bool {
        lpm(&c.path_lpm, &path_q(p)).is_some_and(|s| s.contains(slot))
    }

    #[test]
    fn prefix_matches_on_component_boundary() {
        let c = compile(&[rule("a", Hook::FileWrite, pfx("/nix/store"))]).unwrap();
        assert!(path_hit(&c, "/nix/store/x", 0));
        assert!(path_hit(&c, "/nix/store", 0));
        assert!(path_hit(&c, "/nix/store/a/b/c", 0));
        assert!(!path_hit(&c, "/nix/storefoo", 0));
        assert!(!path_hit(&c, "/nix", 0));
        assert!(!path_hit(&c, "/etc/passwd", 0));
        // The two keys the README specifies, both with prefixlen 8 * 11.
        let keys: Vec<_> = c.path_lpm.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            keys,
            vec![
                PathKey::from_bytes(b"/nix/store\0"),
                PathKey::from_bytes(b"/nix/store/")
            ]
        );
    }

    #[test]
    fn trailing_slash_equivalent() {
        let a = compile(&[rule("a", Hook::Exec, pfx("/nix/store"))]).unwrap();
        let b = compile(&[rule("a", Hook::Exec, pfx("/nix/store/"))]).unwrap();
        let c = compile(&[rule("a", Hook::Exec, pfx("/nix/store//"))]).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn root_prefix_matches_everything() {
        let c = compile(&[rule("a", Hook::FileWrite, pfx("/"))]).unwrap();
        assert_eq!(c.path_lpm.len(), 1);
        assert_eq!(c.path_lpm[0].0, PathKey::from_bytes(b"/"));
        assert!(path_hit(&c, "/", 0));
        assert!(path_hit(&c, "/etc/passwd", 0));
        let c2 = compile(&[rule("a", Hook::FileWrite, pfx("//"))]).unwrap();
        assert_eq!(c, c2);
    }

    #[test]
    fn path_lpm_values_are_cumulative() {
        let rules = [
            rule("any", Hook::FileWrite, Target::Any),
            rule("nix", Hook::FileWrite, pfx("/nix")),
            rule("store", Hook::FileWrite, pfx("/nix/store")),
        ];
        let c = compile(&rules).unwrap();
        let slots =
            |p: &str| -> Vec<u32> { lpm(&c.path_lpm, &path_q(p)).unwrap().slots().collect() };
        assert_eq!(slots("/etc/x"), vec![0]);
        assert_eq!(slots("/nix/a"), vec![0, 1]);
        assert_eq!(slots("/nix/store/a"), vec![0, 1, 2]);
        assert_eq!(slots("/nix/store"), vec![0, 1, 2]);
        // The wildcard entry exists at prefixlen 0.
        assert!(c.path_lpm.iter().any(|(k, _)| k.prefixlen == 0));
    }

    #[test]
    fn long_truncated_path_matches_prefix_not_exact() {
        let base = format!("/{}", "a".repeat(100));
        let c = compile(&[rule("a", Hook::FileWrite, pfx(&base))]).unwrap();
        let long = format!("{base}/{}", "b".repeat(300));
        assert!(path_hit(&c, &long, 0));
    }

    #[test]
    fn path_length_limit() {
        // 254 bytes: key with trailing slash is 255, fits.
        let ok = format!("/{}", "a".repeat(253));
        assert_eq!(ok.len(), 254);
        let c = compile(&[rule("a", Hook::FileWrite, pfx(&ok))]).unwrap();
        let long = format!("{ok}/zzz");
        assert!(path_hit(&c, &long, 0));
        // 255 and 256 bytes: the slash-terminated key could never match.
        for n in [255usize, 256, 1000] {
            let p = format!("/{}", "a".repeat(n - 1));
            assert!(
                matches!(
                    compile(&[rule("a", Hook::FileWrite, pfx(&p))]),
                    Err(CompileError::PathTooLong { .. })
                ),
                "{n}"
            );
        }
        let mut r = rule("a", Hook::Exec, Target::Any);
        r.process.exe_prefix = Some(format!("/{}", "a".repeat(300)));
        assert!(matches!(
            compile(&[r]),
            Err(CompileError::PathTooLong { .. })
        ));
    }

    #[test]
    fn bad_paths_rejected() {
        for p in ["relative/x", "", "/a\0b"] {
            assert!(
                matches!(
                    compile(&[rule("a", Hook::Exec, pfx(p))]),
                    Err(CompileError::BadPath { .. })
                ),
                "{p:?}"
            );
        }
    }

    #[test]
    fn exe_prefix_goes_to_exe_lpm_and_wildcard_otherwise() {
        let mut r0 = rule("a", Hook::Bpf, Target::Any);
        r0.process.exe_prefix = Some("/usr/bin".into());
        let r1 = rule("b", Hook::Bpf, Target::Any);
        let c = compile(&[r0, r1]).unwrap();
        let q = PathKey::from_bytes(b"/usr/bin/ls\0");
        assert_eq!(
            lpm(&c.exe_lpm, &q).unwrap().slots().collect::<Vec<_>>(),
            vec![0, 1]
        );
        let q = PathKey::from_bytes(b"/opt/x\0");
        assert_eq!(
            lpm(&c.exe_lpm, &q).unwrap().slots().collect::<Vec<_>>(),
            vec![1]
        );
        let q = PathKey::from_bytes(b"/usr/binx\0");
        assert_eq!(
            lpm(&c.exe_lpm, &q).unwrap().slots().collect::<Vec<_>>(),
            vec![1]
        );
        // Bpf has no path/net/uid dimension.
        assert!(c.path_lpm.is_empty() && c.net4.is_empty() && c.uids.is_empty());
    }

    #[test]
    fn units_with_wildcard() {
        let mut r0 = rule("a", Hook::Bpf, Target::Any);
        r0.process.unit = Some("nginx.service".into());
        let r1 = rule("b", Hook::Bpf, Target::Any);
        let c = compile(&[r0, r1]).unwrap();
        assert_eq!(c.units.len(), 2);
        let mut name = [0u8; 64];
        assert_eq!(c.units[0].0, UnitKey { name });
        assert_eq!(c.units[0].1.slots().collect::<Vec<_>>(), vec![1]);
        name[..13].copy_from_slice(b"nginx.service");
        assert_eq!(c.units[1].0, UnitKey { name });
        // Units are not cumulative: the program ORs the wildcard in itself.
        assert_eq!(c.units[1].1.slots().collect::<Vec<_>>(), vec![0]);
    }

    #[test]
    fn bad_units_rejected() {
        for u in ["", &"u".repeat(64), "a\0b"] {
            let mut r = rule("a", Hook::Bpf, Target::Any);
            r.process.unit = Some(u.into());
            assert!(
                matches!(compile(&[r]), Err(CompileError::BadUnit { .. })),
                "{u:?}"
            );
        }
        let mut r = rule("a", Hook::Bpf, Target::Any);
        r.process.unit = Some("u".repeat(63));
        assert!(compile(&[r]).is_ok());
    }

    fn net(cidr: &str, ports: &[u16]) -> Target {
        Target::Net {
            cidr: cidr.parse().unwrap(),
            ports: ports.to_vec(),
        }
    }

    fn port_slots(c: &Compiled, p: u32) -> Vec<u32> {
        c.ports
            .iter()
            .find(|(k, _)| k.port == p)
            .map(|(_, s)| s.slots().collect())
            .unwrap_or_default()
    }

    #[test]
    fn cidr_and_ports() {
        let c = compile(&[rule("a", Hook::Connect, net("10.0.0.0/8", &[22]))]).unwrap();
        assert_eq!(c.net4.len(), 1);
        assert_eq!(
            c.net4[0].0,
            Net4Key {
                prefixlen: 8,
                addr: [10, 0, 0, 0]
            }
        );
        assert_eq!(c.net4[0].1.slots().collect::<Vec<_>>(), vec![0]);
        assert_eq!(c.ports.len(), 1);
        assert_eq!(c.ports[0].0, PortKey { port: 22 });
        assert!(c.net6.is_empty());
    }

    #[test]
    fn empty_ports_use_port_wildcard_and_cidr_is_masked() {
        let c = compile(&[rule("a", Hook::Listen, net("10.1.2.3/8", &[]))]).unwrap();
        assert_eq!(c.net4[0].0.addr, [10, 0, 0, 0]);
        assert_eq!(c.ports.len(), 1);
        assert_eq!(c.ports[0].0.port, PORT_ANY);
    }

    #[test]
    fn ports_are_deduplicated_and_sorted() {
        let c = compile(&[rule("a", Hook::Connect, net("10.0.0.0/8", &[443, 22, 443]))]).unwrap();
        let ps: Vec<u32> = c.ports.iter().map(|(k, _)| k.port).collect();
        assert_eq!(ps, vec![22, 443]);
    }

    #[test]
    fn net_any_target_fills_every_net_dimension() {
        let c = compile(&[rule("a", Hook::Connect, Target::Any)]).unwrap();
        assert_eq!(
            c.net4,
            vec![(
                Net4Key {
                    prefixlen: 0,
                    addr: [0; 4]
                },
                one(0)
            )]
        );
        assert_eq!(
            c.net6,
            vec![(
                Net6Key {
                    prefixlen: 0,
                    addr: [0; 16]
                },
                one(0)
            )]
        );
        assert_eq!(c.ports, vec![(PortKey { port: PORT_ANY }, one(0))]);
    }

    fn one(s: u32) -> RuleSet {
        let mut r = RuleSet::default();
        r.insert(s);
        r
    }

    #[test]
    fn net4_lpm_cumulative_and_port_rules_per_port() {
        let rules = [
            rule("any", Hook::Connect, Target::Any),
            rule("ten", Hook::Connect, net("10.0.0.0/8", &[22])),
            rule("ten1", Hook::Connect, net("10.1.0.0/16", &[22, 80])),
        ];
        let c = compile(&rules).unwrap();
        let q = |a: [u8; 4]| Net4Key {
            prefixlen: 32,
            addr: a,
        };
        let s = |a| lpm(&c.net4, &q(a)).unwrap().slots().collect::<Vec<_>>();
        assert_eq!(s([192, 168, 0, 1]), vec![0]);
        assert_eq!(s([10, 9, 0, 1]), vec![0, 1]);
        assert_eq!(s([10, 1, 0, 1]), vec![0, 1, 2]);
        assert_eq!(port_slots(&c, 22), vec![1, 2]);
        assert_eq!(port_slots(&c, 80), vec![2]);
        assert_eq!(port_slots(&c, PORT_ANY), vec![0]);
    }

    #[test]
    fn net6_entry_and_wildcard() {
        let rules = [
            rule("any", Hook::Listen, Target::Any),
            rule("doc", Hook::Listen, net("2001:db8::1/32", &[])),
        ];
        let c = compile(&rules).unwrap();
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        let q = Net6Key {
            prefixlen: 128,
            addr: a,
        };
        assert_eq!(
            lpm(&c.net6, &q).unwrap().slots().collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert!(c.net6.iter().any(|(k, _)| k.prefixlen == 32 && k.addr == a));
        let q = Net6Key {
            prefixlen: 128,
            addr: [1; 16],
        };
        assert_eq!(
            lpm(&c.net6, &q).unwrap().slots().collect::<Vec<_>>(),
            vec![0]
        );
    }

    #[test]
    fn v4_mapped_v6_cidr_goes_to_net4() {
        let c = compile(&[rule("a", Hook::Connect, net("::ffff:10.0.0.0/104", &[]))]).unwrap();
        assert!(c.net6.is_empty());
        assert_eq!(
            c.net4,
            vec![(
                Net4Key {
                    prefixlen: 8,
                    addr: [10, 0, 0, 0]
                },
                one(0)
            )]
        );
    }

    #[test]
    fn broad_v6_cidr_matches_native_v6_only() {
        let c = compile(&[rule("a", Hook::Connect, net("::/0", &[]))]).unwrap();
        assert_eq!(c.net6.len(), 1);
        assert!(c.net4.is_empty());
        let c = compile(&[rule("a", Hook::Connect, net("2001:db8::/32", &[]))]).unwrap();
        assert!(c.net4.is_empty());
    }

    #[test]
    fn uid_rules_and_wildcard() {
        let rules = [
            rule("any", Hook::Setuid, Target::Any),
            rule("root", Hook::Setuid, Target::Uid(0)),
        ];
        let c = compile(&rules).unwrap();
        assert_eq!(
            c.uids,
            vec![
                (UidKey { uid: 0 }, one(1)),
                (UidKey { uid: UID_ANY }, one(0)),
            ]
        );
        assert!(matches!(
            compile(&[rule("a", Hook::Setuid, Target::Uid(u32::MAX))]),
            Err(CompileError::ReservedUid(_))
        ));
    }

    #[test]
    fn meta_per_slot() {
        let mut a = rule("a", Hook::Exec, Target::Any);
        a.action = Action::Alert;
        let b = rule("b", Hook::Bpf, Target::Any);
        let c = compile(&[a, b]).unwrap();
        assert_eq!(
            c.meta,
            vec![
                RuleMeta {
                    id: "a".into(),
                    meta: GuardRuleMeta {
                        id: 0,
                        hook: 0,
                        action: 0,
                        enabled: 1,
                        _pad: 0
                    }
                },
                RuleMeta {
                    id: "b".into(),
                    meta: GuardRuleMeta {
                        id: 1,
                        hook: 6,
                        action: 1,
                        enabled: 1,
                        _pad: 0
                    }
                },
            ]
        );
    }

    #[test]
    fn hook_numbers() {
        use Hook::*;
        for (h, n) in [
            (Exec, 0),
            (Connect, 1),
            (Listen, 2),
            (FileWrite, 3),
            (Setuid, 4),
            (Module, 5),
            (Bpf, 6),
        ] {
            assert_eq!(hook_number(h), n);
        }
    }

    #[test]
    fn disabled_rules_not_compiled() {
        let mut off = rule("off", Hook::FileWrite, pfx("/etc"));
        off.enabled = false;
        let on = rule("on", Hook::FileWrite, pfx("/var"));
        let c = compile(&[off, on]).unwrap();
        assert_eq!(c.meta.len(), 2);
        assert_eq!(c.meta[0].meta.enabled, 0);
        assert_eq!(c.meta[1].meta.enabled, 1);
        assert!(path_hit(&c, "/var/x", 1));
        assert!(!path_hit(&c, "/etc/x", 0));
        assert!(c.path_lpm.iter().all(|(_, s)| !s.contains(0)));
        assert!(c.exe_lpm.iter().all(|(_, s)| !s.contains(0)));
        assert!(c.units.iter().all(|(_, s)| !s.contains(0)));
    }

    #[test]
    fn disabled_rules_are_still_validated() {
        let mut bad = rule("bad", Hook::Exec, Target::Uid(1));
        bad.enabled = false;
        assert!(matches!(
            compile(&[bad]),
            Err(CompileError::TargetMismatch { .. })
        ));
        let mut bad = rule("bad", Hook::Exec, pfx("/a/../b"));
        bad.enabled = false;
        assert!(matches!(compile(&[bad]), Err(CompileError::BadPath { .. })));
    }

    #[test]
    fn disabling_a_rule_keeps_other_slots() {
        let mk = |second_on: bool| {
            let a = rule("a", Hook::FileWrite, pfx("/a"));
            let mut b = rule("b", Hook::FileWrite, pfx("/b"));
            b.enabled = second_on;
            let c = rule("c", Hook::FileWrite, pfx("/c"));
            compile(&[a, b, c]).unwrap()
        };
        let (on, off) = (mk(true), mk(false));
        for c in [&on, &off] {
            assert_eq!(c.slot_of("a"), Some(0));
            assert_eq!(c.slot_of("b"), Some(1));
            assert_eq!(c.slot_of("c"), Some(2));
            assert_eq!(c.slot_of("zzz"), None);
            assert!(path_hit(c, "/c/x", 2));
        }
        assert!(path_hit(&on, "/b/x", 1));
        assert!(!path_hit(&off, "/b/x", 1));
        assert_eq!(off.meta[1].meta.enabled, 0);
    }

    #[test]
    fn too_many_rules_errors() {
        let mk = |n: usize| -> Vec<Rule> {
            (0..n)
                .map(|i| rule(&format!("r{i}"), Hook::Bpf, Target::Any))
                .collect()
        };
        assert!(compile(&mk(1024)).is_ok());
        assert_eq!(compile(&mk(1025)), Err(CompileError::TooMany(1025)));
        // Disabled rules hold a slot too.
        let mut v = mk(1025);
        v[3].enabled = false;
        assert_eq!(compile(&v), Err(CompileError::TooMany(1025)));
    }

    #[test]
    fn dot_components_rejected() {
        for p in ["/a/./b", "/a/../b", "/..", "/a//b", "/a/.", "/."] {
            assert!(
                matches!(
                    compile(&[rule("a", Hook::FileWrite, pfx(p))]),
                    Err(CompileError::BadPath { .. })
                ),
                "{p}"
            );
        }
        // Dots inside a name are fine.
        assert!(compile(&[rule("a", Hook::FileWrite, pfx("/a/.hidden/..x/b.c"))]).is_ok());
    }

    #[test]
    fn nested_exe_prefix_cumulative() {
        let mk = |id: &str, p: Option<&str>| {
            let mut r = rule(id, Hook::Bpf, Target::Any);
            r.process.exe_prefix = p.map(Into::into);
            r
        };
        let c = compile(&[
            mk("any", None),
            mk("usr", Some("/usr")),
            mk("bin", Some("/usr/bin")),
        ])
        .unwrap();
        let s = |p: &str| -> Vec<u32> { lpm(&c.exe_lpm, &path_q(p)).unwrap().slots().collect() };
        assert_eq!(s("/opt/x"), vec![0]);
        assert_eq!(s("/usr/lib/x"), vec![0, 1]);
        assert_eq!(s("/usr/bin/ls"), vec![0, 1, 2]);
        assert_eq!(s("/usr/bin"), vec![0, 1, 2]);
        assert_eq!(s("/usr/binx"), vec![0, 1]);
        assert_eq!(s("/usr"), vec![0, 1]);
    }

    #[test]
    fn slot_1023_sets_last_bit() {
        let rules: Vec<Rule> = (0..1024)
            .map(|i| rule(&format!("r{i}"), Hook::Bpf, Target::Any))
            .collect();
        let c = compile(&rules).unwrap();
        assert_eq!(c.units[0].1.bits[15], u64::MAX);
    }

    #[test]
    fn deterministic_output() {
        let rules = vec![
            rule("a", Hook::FileWrite, pfx("/etc")),
            rule("b", Hook::Connect, net("10.0.0.0/8", &[443, 22])),
            rule("c", Hook::Setuid, Target::Uid(5)),
            rule("d", Hook::Exec, pfx("/usr/bin")),
        ];
        let first = compile(&rules).unwrap();
        for _ in 0..5 {
            assert_eq!(compile(&rules).unwrap(), first);
        }
        for v in [&first.path_lpm, &first.exe_lpm] {
            assert!(v.windows(2).all(|w| w[0].0 < w[1].0));
        }
        assert!(first.ports.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn target_must_fit_hook() {
        use Hook::*;
        let n = || net("10.0.0.0/8", &[]);
        let bad = [
            (Exec, n()),
            (Exec, Target::Uid(1)),
            (Connect, pfx("/x")),
            (Connect, Target::Uid(1)),
            (Listen, pfx("/x")),
            (FileWrite, n()),
            (Module, n()),
            (Setuid, pfx("/x")),
            (Setuid, n()),
            (Bpf, pfx("/x")),
            (Bpf, n()),
            (Bpf, Target::Uid(1)),
            (FileWrite, Target::Uid(1)),
        ];
        for (h, t) in bad {
            assert!(
                matches!(
                    compile(&[rule("a", h, t.clone())]),
                    Err(CompileError::TargetMismatch { .. })
                ),
                "{h:?} {t:?}"
            );
        }
        let good = [
            (Exec, pfx("/x")),
            (FileWrite, pfx("/x")),
            (Module, pfx("/x")),
            (Connect, n()),
            (Listen, n()),
            (Setuid, Target::Uid(1)),
            (Exec, Target::Any),
            (Connect, Target::Any),
            (Listen, Target::Any),
            (FileWrite, Target::Any),
            (Setuid, Target::Any),
            (Module, Target::Any),
            (Bpf, Target::Any),
        ];
        for (h, t) in good {
            assert!(compile(&[rule("a", h, t.clone())]).is_ok(), "{h:?} {t:?}");
        }
    }

    #[test]
    fn duplicate_ids_rejected() {
        let r = rule("a", Hook::Bpf, Target::Any);
        assert_eq!(
            compile(&[r.clone(), r]),
            Err(CompileError::DuplicateId("a".into()))
        );
    }

    #[test]
    fn too_many_port_keys() {
        // 1024 rules x 5 distinct ports = 5120 port keys > 4096.
        let rules: Vec<Rule> = (0..1024u32)
            .map(|i| {
                let ports: Vec<u16> = (0..5).map(|j| (i * 5 + j) as u16).collect();
                rule(&format!("r{i}"), Hook::Connect, net("10.0.0.0/8", &ports))
            })
            .collect();
        assert!(matches!(
            compile(&rules),
            Err(CompileError::TooManyKeys {
                map: "port_rules",
                needed: 5120,
                max: 4096
            })
        ));
    }
}
