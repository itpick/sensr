//! Gateway group member selection (OPNsense `GatewayGroups`).

use serde::{Deserialize, Serialize};

use crate::Status;

/// When a group member stops carrying traffic (OPNsense `trigger`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    /// Only when the member is down ("Member Down").
    #[default]
    Down,
    /// Down, or loss above the low threshold ("Packet Loss").
    DownLoss,
    /// Down, or latency above the low threshold ("High Latency").
    DownLatency,
    /// Down, loss or latency ("Packet Loss and High Latency").
    DownLossLatency,
}

impl Trigger {
    fn on_loss(self) -> bool {
        matches!(self, Self::DownLoss | Self::DownLossLatency)
    }

    fn on_latency(self) -> bool {
        matches!(self, Self::DownLatency | Self::DownLossLatency)
    }

    /// Whether a member with `status` is usable under this trigger. A
    /// `delay+loss` member fails a trigger that watches either condition.
    pub fn is_up(self, status: Status) -> bool {
        match status {
            Status::Down | Status::ForceDown | Status::Pending => false,
            Status::DelayLoss => !self.on_loss() && !self.on_latency(),
            Status::Delay => !self.on_latency(),
            Status::Loss => !self.on_loss(),
            Status::Online => true,
        }
    }

    /// Whether a member going `from` → `to` changes its usability, i.e.
    /// whether the gateway watcher raises an alarm for this group
    /// (`GatewayGroups::gatewayStateChange`).
    pub fn crossed(self, from: Status, to: Status) -> bool {
        self.is_up(from) != self.is_up(to)
    }
}

/// One group member with its current status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupMember<'a> {
    /// Gateway name.
    pub gateway: &'a str,
    /// Tier 1..=5; lower is preferred.
    pub tier: u8,
    /// Load-balancing weight 1..=10 (0 is treated as 1, like an empty
    /// weight upstream).
    pub weight: u8,
    /// Current monitor status.
    pub status: Status,
}

/// A member that carries the group's traffic.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ActiveMember {
    /// Gateway name.
    pub gateway: String,
    /// Load-balancing weight.
    pub weight: u8,
    /// Fraction of new connections this member gets: weight / total weight.
    pub share: f64,
}

/// Result of [`select_group`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct GroupSelection {
    /// The tier in use, `None` for a group without members.
    pub tier: Option<u8>,
    /// Members of that tier carrying traffic, in configuration order.
    pub members: Vec<ActiveMember>,
    /// No member of any tier is up: `members` is the whole lowest tier as a
    /// last resort (upstream keeps routing to the first tier in that case).
    pub all_down: bool,
}

/// Picks the members of a group that carry traffic: the up members of the
/// lowest tier that has any, sharing by weight. When nothing is up, every
/// member of the lowest tier is returned with `all_down` set.
pub fn select_group(trigger: Trigger, members: &[GroupMember<'_>]) -> GroupSelection {
    let mut tiers: Vec<u8> = members.iter().map(|m| m.tier).collect();
    tiers.sort_unstable();
    tiers.dedup();

    let pick = |tier: u8, only_up: bool| -> Vec<&GroupMember<'_>> {
        members
            .iter()
            .filter(|m| m.tier == tier && (!only_up || trigger.is_up(m.status)))
            .collect()
    };

    for &tier in &tiers {
        let up = pick(tier, true);
        if !up.is_empty() {
            return GroupSelection {
                tier: Some(tier),
                members: weigh(&up),
                all_down: false,
            };
        }
    }
    match tiers.first() {
        Some(&tier) => GroupSelection {
            tier: Some(tier),
            members: weigh(&pick(tier, false)),
            all_down: true,
        },
        None => GroupSelection {
            tier: None,
            members: Vec::new(),
            all_down: true,
        },
    }
}

fn weigh(members: &[&GroupMember<'_>]) -> Vec<ActiveMember> {
    let weight = |m: &GroupMember<'_>| m.weight.max(1);
    let total: u32 = members.iter().map(|m| u32::from(weight(m))).sum();
    members
        .iter()
        .map(|m| ActiveMember {
            gateway: m.gateway.to_string(),
            weight: weight(m),
            share: f64::from(weight(m)) / f64::from(total.max(1)),
        })
        .collect()
}

/// Covers: SYS-GW-003
#[cfg(test)]
mod tests {
    use super::*;
    use Status::*;
    use proptest::prelude::*;

    #[test]
    fn trigger_table() {
        // (status, [down, downloss, downlatency, downlosslatency]) → is_up
        let table = [
            (Online, [true, true, true, true]),
            (Delay, [true, true, false, false]),
            (Loss, [true, false, true, false]),
            (DelayLoss, [true, false, false, false]),
            (Down, [false, false, false, false]),
            (ForceDown, [false, false, false, false]),
            (Pending, [false, false, false, false]),
        ];
        let triggers = [
            Trigger::Down,
            Trigger::DownLoss,
            Trigger::DownLatency,
            Trigger::DownLossLatency,
        ];
        for (status, want) in table {
            for (t, w) in triggers.iter().zip(want) {
                assert_eq!(t.is_up(status), w, "{t:?} {status:?}");
            }
        }
    }

    #[test]
    fn crossed_only_when_usability_changes() {
        assert!(Trigger::Down.crossed(Online, Down));
        assert!(!Trigger::Down.crossed(Online, Loss));
        assert!(Trigger::DownLoss.crossed(Online, Loss));
        assert!(!Trigger::DownLoss.crossed(Loss, DelayLoss));
        assert!(Trigger::DownLatency.crossed(Loss, DelayLoss));
        assert!(!Trigger::DownLossLatency.crossed(Down, ForceDown));
    }

    fn m(gateway: &str, tier: u8, weight: u8, status: Status) -> GroupMember<'_> {
        GroupMember {
            gateway,
            tier,
            weight,
            status,
        }
    }

    fn names(sel: &GroupSelection) -> Vec<&str> {
        sel.members.iter().map(|a| a.gateway.as_str()).collect()
    }

    #[test]
    fn failover_tiers_per_trigger() {
        struct Case {
            trigger: Trigger,
            members: Vec<GroupMember<'static>>,
            tier: Option<u8>,
            active: Vec<&'static str>,
            all_down: bool,
        }
        let cases = [
            Case {
                trigger: Trigger::Down,
                members: vec![m("wan1", 1, 1, Online), m("wan2", 2, 1, Online)],
                tier: Some(1),
                active: vec!["wan1"],
                all_down: false,
            },
            Case {
                trigger: Trigger::Down,
                members: vec![m("wan1", 1, 1, Down), m("wan2", 2, 1, Online)],
                tier: Some(2),
                active: vec!["wan2"],
                all_down: false,
            },
            Case {
                trigger: Trigger::Down,
                members: vec![m("wan1", 1, 1, Loss), m("wan2", 2, 1, Online)],
                tier: Some(1),
                active: vec!["wan1"],
                all_down: false,
            },
            Case {
                trigger: Trigger::DownLoss,
                members: vec![m("wan1", 1, 1, Loss), m("wan2", 2, 1, Online)],
                tier: Some(2),
                active: vec!["wan2"],
                all_down: false,
            },
            Case {
                trigger: Trigger::DownLoss,
                members: vec![m("wan1", 1, 1, Delay), m("wan2", 2, 1, Online)],
                tier: Some(1),
                active: vec!["wan1"],
                all_down: false,
            },
            Case {
                trigger: Trigger::DownLatency,
                members: vec![m("wan1", 1, 1, Delay), m("wan2", 2, 1, Online)],
                tier: Some(2),
                active: vec!["wan2"],
                all_down: false,
            },
            Case {
                trigger: Trigger::DownLatency,
                members: vec![m("wan1", 1, 1, Loss), m("wan2", 2, 1, Online)],
                tier: Some(1),
                active: vec!["wan1"],
                all_down: false,
            },
            Case {
                trigger: Trigger::DownLossLatency,
                members: vec![
                    m("wan1", 1, 1, DelayLoss),
                    m("wan2", 2, 1, Loss),
                    m("wan3", 3, 1, Online),
                ],
                tier: Some(3),
                active: vec!["wan3"],
                all_down: false,
            },
            Case {
                // Nothing up: the whole lowest tier stays as a last resort.
                trigger: Trigger::Down,
                members: vec![
                    m("wan2", 2, 1, Down),
                    m("wan1", 1, 1, Down),
                    m("wan1b", 1, 1, ForceDown),
                ],
                tier: Some(1),
                active: vec!["wan1", "wan1b"],
                all_down: true,
            },
            Case {
                trigger: Trigger::Down,
                members: vec![],
                tier: None,
                active: vec![],
                all_down: true,
            },
            Case {
                // Pending members (no data yet) are not usable.
                trigger: Trigger::Down,
                members: vec![m("wan1", 1, 1, Pending), m("wan2", 2, 1, Online)],
                tier: Some(2),
                active: vec!["wan2"],
                all_down: false,
            },
        ];
        for c in cases {
            let sel = select_group(c.trigger, &c.members);
            assert_eq!(sel.tier, c.tier, "{:?} {:?}", c.trigger, c.members);
            assert_eq!(names(&sel), c.active, "{:?} {:?}", c.trigger, c.members);
            assert_eq!(sel.all_down, c.all_down);
        }
    }

    #[test]
    fn same_tier_shares_by_weight() {
        let members = [
            m("a", 1, 3, Online),
            m("b", 1, 1, Online),
            m("c", 1, 0, Down),
            m("d", 2, 9, Online),
        ];
        let sel = select_group(Trigger::Down, &members);
        assert_eq!(sel.tier, Some(1));
        assert_eq!(names(&sel), ["a", "b"]);
        assert_eq!(sel.members[0].share, 0.75);
        assert_eq!(sel.members[1].share, 0.25);
    }

    fn status_strategy() -> impl Strategy<Value = Status> {
        prop_oneof![
            Just(Pending),
            Just(Online),
            Just(Delay),
            Just(Loss),
            Just(DelayLoss),
            Just(Down),
            Just(ForceDown),
        ]
    }

    fn trigger_strategy() -> impl Strategy<Value = Trigger> {
        prop_oneof![
            Just(Trigger::Down),
            Just(Trigger::DownLoss),
            Just(Trigger::DownLatency),
            Just(Trigger::DownLossLatency),
        ]
    }

    proptest! {
        #[test]
        fn lowest_up_tier_is_chosen(
            trigger in trigger_strategy(),
            spec in proptest::collection::vec((1u8..=5, 0u8..=10, status_strategy()), 0..12),
        ) {
            let names: Vec<String> = (0..spec.len()).map(|i| format!("gw{i}")).collect();
            let members: Vec<GroupMember<'_>> = spec
                .iter()
                .zip(&names)
                .map(|(&(tier, weight, status), name)| m(name, tier, weight, status))
                .collect();
            let sel = select_group(trigger, &members);
            let lowest_up = members.iter().filter(|m| trigger.is_up(m.status)).map(|m| m.tier).min();
            match lowest_up {
                Some(tier) => {
                    prop_assert_eq!(sel.tier, Some(tier));
                    prop_assert!(!sel.all_down);
                    let want: Vec<&str> = members
                        .iter()
                        .filter(|m| m.tier == tier && trigger.is_up(m.status))
                        .map(|m| m.gateway)
                        .collect();
                    prop_assert_eq!(sel.members.iter().map(|a| a.gateway.as_str()).collect::<Vec<_>>(), want);
                    let total: f64 = sel.members.iter().map(|a| a.share).sum();
                    prop_assert!((total - 1.0).abs() < 1e-9);
                }
                None => prop_assert!(sel.all_down),
            }
        }
    }
}
