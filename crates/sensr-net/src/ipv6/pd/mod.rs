//! IPv6 prefix delegation (PD): prefix maths and the persisted state machine.
//!
//! The uplink's DHCPv6 client (systemd-networkd today) obtains a delegated
//! prefix. Everything sensr derives from it lives here:
//!
//! - pure maths: which /64 a LAN with a given prefix ID gets
//!   ([`calculate_prefix`]), how many /64s a delegation holds
//!   ([`delegation_size`]), and the largest aligned block a LAN may use
//!   ([`usable_prefix_length`], [`allocated_prefix`]);
//! - [`PdState`]: one state machine per uplink that turns observations of
//!   what the uplink holds into [`PdEvent`]s and into the prefixes each LAN
//!   must advertise, including deprecated ones after a change (RFC 9096);
//! - [`PdStore`]: atomic JSON persistence, so a reboot does not forget which
//!   prefix the LANs were using;
//! - [`observe`]: parsers for `ip -j -6 route` / `ip -j -6 addr` output that
//!   turn what networkd left in the kernel into an [`Observation`].
//!
//! See `crates/sensr-net/docs/pd.md` for the derived behaviour and the
//! differences from OPNsense.

pub mod observe;
mod state;
mod store;

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;
use serde::{Deserialize, Serialize};

pub use state::{
    AdvertisedPrefix, DelegatedPrefix, ND_PREFERRED_LIMIT, ND_VALID_LIMIT, Observation, PdEvent,
    PdState, RENEW_TOLERANCE_SECS, StalePrefix, StaleSignal,
};
pub use store::{LoadIssue, Loaded, PdStore, StoreError};

/// The DHCPv6 "infinity" lifetime (RFC 8415 §7.7).
pub const INFINITE_LIFETIME: u32 = u32::MAX;

/// A LAN (or the uplink itself, for a PD-only WAN) that takes a /64 from the
/// delegated prefix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Consumer {
    /// Logical interface id, e.g. `"lan"`, `"opt1"`.
    pub interface: String,
    /// Subnet index inside the delegation (OPNsense `track6-prefix-id`,
    /// networkd `SubnetId=`). Stored as a number; UIs show it in hex.
    pub prefix_id: u64,
}

impl Consumer {
    /// Convenience constructor.
    pub fn new(interface: impl Into<String>, prefix_id: u64) -> Self {
        Self {
            interface: interface.into(),
            prefix_id,
        }
    }
}

/// Number of /64 subnets a delegated prefix of length `prefix_len` holds.
///
/// `None` for lengths longer than /64 (nothing to carve) and for /0, whose
/// 2^64 subnets do not fit a `u64`.
pub fn delegation_size(prefix_len: u8) -> Option<u64> {
    match prefix_len {
        1..=64 => Some(1u64 << (64 - u32::from(prefix_len))),
        _ => None,
    }
}

/// The on-link /64 that subnet `prefix_id` selects inside `delegated`.
///
/// The ID fills the bits between the delegated length and /64, so
/// `2001:db8:1234:ab00::/56` with ID 16 (0x10) gives `2001:db8:1234:ab10::/64`.
/// Host bits set in `delegated` are ignored.
///
/// `None` when `delegated` is longer than /64 or the ID does not fit in the
/// available bits: OPNsense silently drops the high bits of an oversized ID
/// and hands out an overlapping subnet; sensr refuses instead.
pub fn calculate_prefix(delegated: Ipv6Net, prefix_id: u64) -> Option<Ipv6Net> {
    carve(delegated, prefix_id, 64)
}

/// The largest aligned block a consumer starting at `prefix_id` may use,
/// bounded by `range` /64 slots (OPNsense `track6_prefix_range`; `None`
/// means one slot) and by the end of the delegation.
///
/// Example: in a /56, ID 0 with range 16 may use a /60; ID 10 (0x0a) with
/// range 16 only a /63, because 10 is aligned to 2 slots only.
///
/// `None` when the delegation is longer than /64 or the ID lies outside it.
pub fn usable_prefix_length(delegated_len: u8, prefix_id: u64, range: Option<u64>) -> Option<u8> {
    let size = if delegated_len == 0 {
        // A /0 "delegation" holds 2^64 subnets; any u64 ID fits.
        u128::from(u64::MAX) + 1
    } else {
        u128::from(delegation_size(delegated_len)?)
    };
    let id = u128::from(prefix_id);
    if id >= size {
        return None;
    }
    // An empty or zero range still gives the consumer its own /64.
    let available = u128::from(range.unwrap_or(1).max(1)).min(size - id);
    let mut bits: u8 = 0;
    while bits < 64 - delegated_len {
        let next = 1u128 << (bits + 1);
        if next > available || !id.is_multiple_of(next) {
            break;
        }
        bits += 1;
    }
    Some(64 - bits)
}

/// The block [`usable_prefix_length`] allows, as a prefix: OPNsense's
/// `prefix_allocated`.
pub fn allocated_prefix(delegated: Ipv6Net, prefix_id: u64, range: Option<u64>) -> Option<Ipv6Net> {
    let len = usable_prefix_length(delegated.prefix_len(), prefix_id, range)?;
    carve(delegated, prefix_id, len)
}

fn carve(delegated: Ipv6Net, prefix_id: u64, len: u8) -> Option<Ipv6Net> {
    let dlen = delegated.prefix_len();
    if dlen > 64 {
        return None;
    }
    let id_bits = 64 - u32::from(dlen);
    if id_bits < 64 && prefix_id >> id_bits != 0 {
        return None;
    }
    let base = u128::from(delegated.trunc().addr());
    let addr = base | (u128::from(prefix_id) << 64);
    Ipv6Net::new(Ipv6Addr::from(addr), len)
        .ok()
        .map(|n| n.trunc())
}

/// Covers: IF-007 (Identity Association prefix ID), RA-001 (advertised
/// prefixes), ISS-C-002 (single PD state machine).
#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;

    fn net(s: &str) -> Ipv6Net {
        s.parse().unwrap()
    }

    #[test]
    fn prefix_id_into_56_t0009() {
        let d = net("2001:db8:1234:ab00::/56");
        for (id, want) in [
            (0, "2001:db8:1234:ab00::/64"),
            (1, "2001:db8:1234:ab01::/64"),
            (10, "2001:db8:1234:ab0a::/64"),
            (15, "2001:db8:1234:ab0f::/64"),
            // Stored as decimal 16, shown as hex 10.
            (16, "2001:db8:1234:ab10::/64"),
            (255, "2001:db8:1234:abff::/64"),
        ] {
            assert_eq!(calculate_prefix(d, id), Some(net(want)), "id {id}");
        }
    }

    #[test]
    fn delegation_sizes_t0010() {
        assert_eq!(
            calculate_prefix(net("2001:db8:1234:a000::/52"), 16),
            Some(net("2001:db8:1234:a010::/64"))
        );
        assert_eq!(
            calculate_prefix(net("2001:db8:1234::/48"), 16),
            Some(net("2001:db8:1234:10::/64"))
        );
        assert_eq!(
            calculate_prefix(net("2001:db8:1234::/48"), 48879),
            Some(net("2001:db8:1234:beef::/64"))
        );
        assert_eq!(delegation_size(48), Some(65536));
        assert_eq!(delegation_size(52), Some(4096));
        assert_eq!(delegation_size(56), Some(256));
        assert_eq!(delegation_size(60), Some(16));
        assert_eq!(delegation_size(64), Some(1));
        assert_eq!(delegation_size(65), None);
        assert_eq!(delegation_size(0), None);
    }

    #[test]
    fn usable_prefix_length_t0011() {
        assert_eq!(usable_prefix_length(56, 0, None), Some(64));
        assert_eq!(usable_prefix_length(56, 0, Some(1)), Some(64));
        assert_eq!(usable_prefix_length(56, 0, Some(2)), Some(63));
        assert_eq!(usable_prefix_length(56, 0, Some(4)), Some(62));
        assert_eq!(usable_prefix_length(56, 0, Some(16)), Some(60));
        assert_eq!(usable_prefix_length(56, 16, Some(16)), Some(60));
        // 10 = 0x0a is aligned to 2 slots only.
        assert_eq!(usable_prefix_length(56, 10, Some(16)), Some(63));
        assert_eq!(
            allocated_prefix(net("2001:db8:1234:ab00::/56"), 16, Some(16)),
            Some(net("2001:db8:1234:ab10::/60"))
        );
    }

    #[test]
    fn oversized_ids_and_long_prefixes_are_refused() {
        let d = net("2001:db8:1234:ab00::/56");
        assert_eq!(calculate_prefix(d, 256), None);
        assert_eq!(usable_prefix_length(56, 256, None), None);
        assert_eq!(calculate_prefix(net("2001:db8::/65"), 0), None);
        assert_eq!(
            calculate_prefix(net("2001:db8:1:2::/64"), 0),
            Some(net("2001:db8:1:2::/64"))
        );
        assert_eq!(calculate_prefix(net("2001:db8:1:2::/64"), 1), None);
    }

    #[test]
    fn host_bits_in_the_delegation_are_ignored() {
        assert_eq!(
            calculate_prefix(net("2001:db8:1234:ab01::1/56"), 2),
            Some(net("2001:db8:1234:ab02::/64"))
        );
    }

    #[test]
    fn range_is_bounded_by_the_end_of_the_delegation() {
        // ID 0xfe in a /56 has 2 slots left whatever the range says.
        assert_eq!(usable_prefix_length(56, 0xfe, Some(16)), Some(63));
        assert_eq!(usable_prefix_length(56, 0xff, Some(16)), Some(64));
        // A /64 delegation never aggregates.
        assert_eq!(usable_prefix_length(64, 0, Some(16)), Some(64));
    }

    proptest! {
        #[test]
        fn prop_usable_length_alignment_t0011(
            dlen in 44u8..=64,
            id_seed in any::<u64>(),
            range in proptest::option::of(0u64..5000),
        ) {
            let size = delegation_size(dlen).unwrap();
            let id = id_seed % size;
            let len = usable_prefix_length(dlen, id, range).unwrap();
            prop_assert!(len >= dlen && len <= 64);
            let slots = 1u64 << (64 - len);
            let allowed = range.unwrap_or(1).max(1);
            // aligned, inside the range, inside the delegation
            prop_assert_eq!(id % slots, 0);
            prop_assert!(slots <= allowed);
            prop_assert!(id + slots <= size);
            // maximal: the next bigger block breaks one of the three
            if len > dlen {
                let bigger = slots * 2;
                prop_assert!(!id.is_multiple_of(bigger) || bigger > allowed || id + bigger > size);
            }
            // the allocated block contains the on-link /64
            let d = Ipv6Net::new("2001:db8::".parse().unwrap(), dlen).unwrap();
            let on_link = calculate_prefix(d, id).unwrap();
            let block = allocated_prefix(d, id, range).unwrap();
            prop_assert!(block.contains(&on_link));
            prop_assert!(d.contains(&block));
        }

        #[test]
        fn prop_distinct_ids_give_distinct_subnets(dlen in 48u8..=63, a in any::<u64>(), b in any::<u64>()) {
            let size = delegation_size(dlen).unwrap();
            let (a, b) = (a % size, b % size);
            let d = Ipv6Net::new("2001:db8::".parse().unwrap(), dlen).unwrap();
            let (pa, pb) = (calculate_prefix(d, a).unwrap(), calculate_prefix(d, b).unwrap());
            prop_assert_eq!(a == b, pa == pb);
            prop_assert!(d.contains(&pa));
        }
    }
}
