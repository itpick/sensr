//! `#[repr(C)]` mirrors of the structs in `bpf/guard/common.h`. Sizes and
//! offsets are asserted in the tests, the same numbers as the C
//! `_Static_assert`s. Change both sides together.

/// `GUARD_MAX_RULES`: rule slots, and the bits of a [`RuleSet`].
pub const MAX_RULES: usize = 1024;
/// `GUARD_RULE_WORDS`.
pub const RULE_WORDS: usize = MAX_RULES / 64;
/// `GUARD_PATH_LEN`: the bytes of a path key.
pub const PATH_LEN: usize = 256;
/// `GUARD_UNIT_LEN`: the bytes of a unit key.
pub const UNIT_LEN: usize = 64;
/// `GUARD_MAX_PATH_KEYS`.
pub const MAX_PATH_KEYS: usize = 4096;
/// `GUARD_MAX_NET_KEYS`.
pub const MAX_NET_KEYS: usize = 2048;
/// `GUARD_MAX_PORT_KEYS`.
pub const MAX_PORT_KEYS: usize = 4096;
/// `GUARD_MAX_UNIT_KEYS`.
pub const MAX_UNIT_KEYS: usize = 1025;
/// `GUARD_MAX_UID_KEYS`.
pub const MAX_UID_KEYS: usize = 1025;
/// `GUARD_PORT_ANY`: the `port_rules` key for any port.
pub const PORT_ANY: u32 = 0x10000;
/// `GUARD_UID_ANY`: the `uid_rules` key for any uid.
pub const UID_ANY: u32 = 0xffff_ffff;

/// `rules_meta[slot]` (`struct guard_rule_meta`, 8 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuardRuleMeta {
    /// Equals the slot.
    pub id: u32,
    /// `enum guard_hook`.
    pub hook: u8,
    /// `enum guard_action`.
    pub action: u8,
    /// 0: never matches.
    pub enabled: u8,
    /// Explicit padding (always 0), so a written value has no stray bytes.
    pub _pad: u8,
}

impl GuardRuleMeta {
    /// The map value bytes, padding zeroed.
    pub fn as_bytes(&self) -> [u8; 8] {
        let mut b = [0; 8];
        b[..4].copy_from_slice(&self.id.to_le_bytes());
        b[4] = self.hook;
        b[5] = self.action;
        b[6] = self.enabled;
        b
    }
}

/// A set of rule slots (`struct guard_rule_set`, 128 bytes): slot `s` is bit
/// `s % 64` of `bits[s / 64]`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct RuleSet {
    /// The bitmap.
    pub bits: [u64; RULE_WORDS],
}

impl RuleSet {
    /// The map value bytes (little-endian words).
    pub fn as_bytes(&self) -> [u8; 128] {
        let mut b = [0; 128];
        for (i, w) in self.bits.iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        b
    }

    /// Add a slot. Slots at or above [`MAX_RULES`] are a bug in the caller.
    pub fn insert(&mut self, slot: u32) {
        assert!((slot as usize) < MAX_RULES, "slot {slot} out of range");
        self.bits[slot as usize / 64] |= 1 << (slot % 64);
    }

    /// Whether the slot is in the set.
    pub fn contains(&self, slot: u32) -> bool {
        (slot as usize) < MAX_RULES && self.bits[slot as usize / 64] & (1 << (slot % 64)) != 0
    }

    /// Add every slot of `other`.
    pub fn union_with(&mut self, other: &RuleSet) {
        for (a, b) in self.bits.iter_mut().zip(other.bits) {
            *a |= b;
        }
    }

    /// Whether no slot is set.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|w| *w == 0)
    }

    /// The slots, ascending.
    pub fn slots(&self) -> impl Iterator<Item = u32> + '_ {
        (0..MAX_RULES as u32).filter(|s| self.contains(*s))
    }
}

/// `struct guard_path_key` (260 bytes): `prefixlen` in bits, then the path.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathKey {
    /// Prefix length in bits.
    pub prefixlen: u32,
    /// The path bytes, zero-padded.
    pub path: [u8; PATH_LEN],
}

impl PathKey {
    /// The map key bytes.
    pub fn as_bytes(&self) -> [u8; 4 + PATH_LEN] {
        let mut b = [0; 4 + PATH_LEN];
        b[..4].copy_from_slice(&self.prefixlen.to_le_bytes());
        b[4..].copy_from_slice(&self.path);
        b
    }

    /// The wildcard key (`prefixlen = 0`).
    pub fn wildcard() -> Self {
        Self {
            prefixlen: 0,
            path: [0; PATH_LEN],
        }
    }

    /// A key of the first `bytes.len()` bytes with `prefixlen = 8 * len`.
    /// `bytes` may include a trailing NUL. Panics above [`PATH_LEN`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() <= PATH_LEN, "path key too long");
        let mut path = [0; PATH_LEN];
        path[..bytes.len()].copy_from_slice(bytes);
        Self {
            prefixlen: 8 * bytes.len() as u32,
            path,
        }
    }
}

/// `{ u32 prefixlen; u8 addr[4]; }`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Net4Key {
    /// Prefix length in bits.
    pub prefixlen: u32,
    /// Network byte order.
    pub addr: [u8; 4],
}

impl Net4Key {
    /// The map key bytes.
    pub fn as_bytes(&self) -> [u8; 8] {
        let mut b = [0; 8];
        b[..4].copy_from_slice(&self.prefixlen.to_le_bytes());
        b[4..].copy_from_slice(&self.addr);
        b
    }
}

/// `{ u32 prefixlen; u8 addr[16]; }`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Net6Key {
    /// Prefix length in bits.
    pub prefixlen: u32,
    /// Network byte order.
    pub addr: [u8; 16],
}

impl Net6Key {
    /// The map key bytes.
    pub fn as_bytes(&self) -> [u8; 20] {
        let mut b = [0; 20];
        b[..4].copy_from_slice(&self.prefixlen.to_le_bytes());
        b[4..].copy_from_slice(&self.addr);
        b
    }
}

/// `{ u32 port; }` ([`PORT_ANY`] for any port).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortKey {
    /// Host order.
    pub port: u32,
}

impl PortKey {
    /// The map key bytes.
    pub fn as_bytes(&self) -> [u8; 4] {
        self.port.to_le_bytes()
    }
}

/// `{ char name[64]; }`: the leaf cgroup name, zero-padded; all zero is the
/// wildcard.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnitKey {
    /// The name bytes.
    pub name: [u8; UNIT_LEN],
}

impl UnitKey {
    /// The map key bytes.
    pub fn as_bytes(&self) -> [u8; UNIT_LEN] {
        self.name
    }
}

/// `{ u32 uid; }` ([`UID_ANY`] for any uid).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UidKey {
    /// The uid.
    pub uid: u32,
}

impl UidKey {
    /// The map key bytes.
    pub fn as_bytes(&self) -> [u8; 4] {
        self.uid.to_le_bytes()
    }
}

/// `config[0]` (`struct guard_config`, 8 bytes, `guard_tgid` at offset 4).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuardConfig {
    /// 1: nothing blocks.
    pub kill_switch: u8,
    /// Explicit padding (always 0).
    pub _pad: [u8; 3],
    /// sensr-guard's pid.
    pub guard_tgid: u32,
}

impl GuardConfig {
    /// The map value bytes, padding zeroed.
    pub fn as_bytes(&self) -> [u8; 8] {
        let mut b = [0; 8];
        b[0] = self.kill_switch;
        b[4..].copy_from_slice(&self.guard_tgid.to_le_bytes());
        b
    }
}

/// One ring buffer record (`struct guard_event`, 624 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardEvent {
    /// CLOCK_BOOTTIME ns.
    pub ts: u64,
    /// Tgid.
    pub pid: u32,
    /// Parent tgid.
    pub ppid: u32,
    /// Current uid.
    pub uid: u32,
    /// The slot.
    pub rule_id: u32,
    /// `enum guard_hook`.
    pub hook: u8,
    /// `enum guard_action`.
    pub action: u8,
    /// Whether the operation was denied.
    pub blocked: u8,
    /// Cached exe, NUL-terminated.
    pub exe: [u8; PATH_LEN],
    /// Path, uid in decimal, or the bpf op.
    pub target: [u8; PATH_LEN],
    /// Network order.
    pub addr: [u8; 16],
    /// Host order.
    pub port: u16,
    /// 2, 10 or 0.
    pub family: u8,
    /// Leaf cgroup name.
    pub unit: [u8; UNIT_LEN],
    /// Explicit trailing padding.
    pub _pad: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn sizes_match_common_h() {
        assert_eq!(size_of::<GuardRuleMeta>(), 8);
        assert_eq!(size_of::<RuleSet>(), 128);
        assert_eq!(size_of::<PathKey>(), 260);
        assert_eq!(size_of::<Net4Key>(), 8);
        assert_eq!(size_of::<Net6Key>(), 20);
        assert_eq!(size_of::<PortKey>(), 4);
        assert_eq!(size_of::<UnitKey>(), 64);
        assert_eq!(size_of::<UidKey>(), 4);
        assert_eq!(size_of::<GuardConfig>(), 8);
        assert_eq!(size_of::<GuardEvent>(), 624);
    }

    #[test]
    fn offsets_match_common_h() {
        assert_eq!(offset_of!(GuardRuleMeta, hook), 4);
        assert_eq!(offset_of!(GuardRuleMeta, action), 5);
        assert_eq!(offset_of!(GuardRuleMeta, enabled), 6);
        assert_eq!(offset_of!(GuardRuleMeta, _pad), 7);
        assert_eq!(offset_of!(GuardConfig, _pad), 1);
        assert_eq!(offset_of!(PathKey, path), 4);
        assert_eq!(offset_of!(Net4Key, addr), 4);
        assert_eq!(offset_of!(Net6Key, addr), 4);
        assert_eq!(offset_of!(GuardConfig, guard_tgid), 4);
        assert_eq!(offset_of!(GuardEvent, ts), 0);
        assert_eq!(offset_of!(GuardEvent, pid), 8);
        assert_eq!(offset_of!(GuardEvent, ppid), 12);
        assert_eq!(offset_of!(GuardEvent, uid), 16);
        assert_eq!(offset_of!(GuardEvent, rule_id), 20);
        assert_eq!(offset_of!(GuardEvent, hook), 24);
        assert_eq!(offset_of!(GuardEvent, action), 25);
        assert_eq!(offset_of!(GuardEvent, blocked), 26);
        assert_eq!(offset_of!(GuardEvent, exe), 27);
        assert_eq!(offset_of!(GuardEvent, target), 283);
        assert_eq!(offset_of!(GuardEvent, addr), 539);
        assert_eq!(offset_of!(GuardEvent, port), 556);
        assert_eq!(offset_of!(GuardEvent, family), 558);
        assert_eq!(offset_of!(GuardEvent, unit), 559);
        assert_eq!(offset_of!(GuardEvent, _pad), 623);
    }

    #[test]
    fn as_bytes_has_no_stray_bytes() {
        let m = GuardRuleMeta {
            id: 0x0102_0304,
            hook: 5,
            action: 1,
            enabled: 1,
            _pad: 0,
        };
        assert_eq!(m.as_bytes(), [4, 3, 2, 1, 5, 1, 1, 0]);
        let c = GuardConfig {
            kill_switch: 1,
            _pad: [0; 3],
            guard_tgid: 0x0a0b_0c0d,
        };
        assert_eq!(c.as_bytes(), [1, 0, 0, 0, 0x0d, 0x0c, 0x0b, 0x0a]);
        let mut s = RuleSet::default();
        s.insert(1);
        s.insert(64);
        let b = s.as_bytes();
        assert_eq!((b[0], b[8]), (2, 1));
        assert_eq!(b.iter().filter(|x| **x != 0).count(), 2);
        let k = PathKey::from_bytes(b"/a/");
        let b = k.as_bytes();
        assert_eq!(&b[..8], &[24, 0, 0, 0, b'/', b'a', b'/', 0]);
        assert_eq!(b.len(), 260);
        assert_eq!(
            Net4Key {
                prefixlen: 8,
                addr: [10, 0, 0, 0]
            }
            .as_bytes(),
            [8, 0, 0, 0, 10, 0, 0, 0]
        );
        assert_eq!(
            Net6Key {
                prefixlen: 1,
                addr: [7; 16]
            }
            .as_bytes()[4..],
            [7; 16]
        );
        assert_eq!(PortKey { port: 0x10000 }.as_bytes(), [0, 0, 1, 0]);
        assert_eq!(UidKey { uid: 1 }.as_bytes(), [1, 0, 0, 0]);
        assert_eq!(UnitKey { name: [3; 64] }.as_bytes(), [3; 64]);
    }

    #[test]
    fn rule_set_bit_layout() {
        let mut s = RuleSet::default();
        assert!(s.is_empty());
        s.insert(0);
        s.insert(65);
        s.insert(1023);
        assert_eq!(s.bits[0], 1);
        assert_eq!(s.bits[1], 2);
        assert_eq!(s.bits[15], 1 << 63);
        assert_eq!(s.slots().collect::<Vec<_>>(), vec![0, 65, 1023]);
        assert!(s.contains(65) && !s.contains(64) && !s.contains(5000));
        let mut t = RuleSet::default();
        t.insert(64);
        t.union_with(&s);
        assert_eq!(t.slots().count(), 4);
    }
}
