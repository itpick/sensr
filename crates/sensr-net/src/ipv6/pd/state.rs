//! The per-uplink PD state machine.
//!
//! Inputs are observations of what the uplink currently holds; outputs are
//! events (for the reconciler) and the set of prefixes every consumer must
//! advertise. The clock is always an argument (`now`, wall-clock seconds
//! since the Unix epoch) so the logic is deterministic under test and the
//! deadlines survive a reboot.

use std::collections::BTreeMap;

use ipnet::Ipv6Net;
use serde::{Deserialize, Serialize};

use super::{Consumer, INFINITE_LIFETIME, calculate_prefix};

/// RFC 9096 §4: upper bound for the Preferred Lifetime a CE router puts in
/// a PIO (45 minutes).
pub const ND_PREFERRED_LIMIT: u32 = 2700;

/// RFC 9096 §4: upper bound for the Valid Lifetime a CE router puts in a
/// PIO (90 minutes, 2 × ND_PREFERRED_LIMIT). Also how long a stale prefix
/// keeps being advertised as deprecated (RFC 9096 §3.5 with L-16 capping).
pub const ND_VALID_LIMIT: u32 = 5400;

/// Observations whose deadlines differ from the stored ones by at most this
/// many seconds are the same lease. Remaining lifetimes read from the kernel
/// are whole seconds sampled at slightly different instants, so the derived
/// absolute deadline jitters by a second or so between polls.
pub const RENEW_TOLERANCE_SECS: u64 = 2;

/// What the uplink holds right now, as read from the DHCPv6 client or the
/// kernel. Lifetimes are remaining seconds with DHCPv6 semantics:
/// [`INFINITE_LIFETIME`] means forever, a valid lifetime of 0 means the
/// server withdrew the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// The delegated prefix (e.g. a /56 or /60).
    pub prefix: Ipv6Net,
    /// Remaining preferred lifetime in seconds.
    pub preferred_lifetime: u32,
    /// Remaining valid lifetime in seconds.
    pub valid_lifetime: u32,
    /// IA_PD identifier, when the source knows it (the kernel does not).
    pub iaid: Option<u32>,
}

/// The prefix currently delegated to the uplink. Times are wall-clock
/// seconds since the Unix epoch; `u64::MAX` means infinite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedPrefix {
    /// The delegated prefix.
    pub prefix: Ipv6Net,
    /// When the prefix stops being preferred.
    pub preferred_until: u64,
    /// When the prefix stops being valid.
    pub valid_until: u64,
    /// IA_PD identifier, if known.
    pub iaid: Option<u32>,
    /// When sensr first saw this prefix (kept across renewals).
    pub obtained_at: u64,
    /// When the lifetimes were last refreshed.
    pub renewed_at: u64,
}

/// A prefix that was delegated before but no longer is. Its subnets are
/// advertised as deprecated until `deprecate_until` (RFC 9096 §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StalePrefix {
    /// The formerly delegated prefix.
    pub prefix: Ipv6Net,
    /// When sensr noticed it was gone.
    pub stale_since: u64,
    /// When sensr stops advertising it.
    pub deprecate_until: u64,
}

/// How the Valid Lifetime of a stale prefix is signalled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StaleSignal {
    /// Valid Lifetime counts down to 0 at `deprecate_until`. Hosts that
    /// follow the RFC 4862 two-hour rule treat this the same as 0, and RA
    /// daemons that reject a zero valid lifetime can still render it.
    #[default]
    CountDown,
    /// Valid Lifetime 0, as RFC 9096 §3.5 literally specifies.
    Zero,
}

/// What changed in one [`PdState::observe`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "event", content = "data", rename_all = "kebab-case")]
pub enum PdEvent {
    /// A prefix appeared where there was none.
    Acquired(DelegatedPrefix),
    /// The same prefix, with refreshed lifetimes (or confirmed again after a
    /// restart or a loss). Not a change: consumers keep their subnets.
    Renewed(DelegatedPrefix),
    /// The uplink now holds a different prefix; `old` is deprecated.
    Changed {
        /// The prefix that became stale.
        old: Ipv6Net,
        /// The new delegation.
        new: DelegatedPrefix,
    },
    /// The uplink no longer reports the prefix. If the server withdrew it
    /// (valid lifetime 0) it is deprecated at once; otherwise it stays in
    /// use until its valid lifetime runs out, since the lease may come back.
    Lost(Ipv6Net),
    /// A current or stale prefix reached its deadline and was dropped.
    Expired(Ipv6Net),
}

/// One prefix to put in a Router Advertisement PIO on one interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvertisedPrefix {
    /// The on-link /64.
    pub prefix: Ipv6Net,
    /// PIO Preferred Lifetime, already capped (RFC 9096 L-16).
    pub preferred_lifetime_secs: u32,
    /// PIO Valid Lifetime, already capped (RFC 9096 L-16).
    pub valid_lifetime_secs: u32,
    /// True for a subnet of a stale prefix.
    pub deprecated: bool,
}

/// The PD state of one uplink. See the module docs and `docs/pd.md`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdState {
    current: Option<DelegatedPrefix>,
    /// Whether the last observation showed `current` on the uplink. False
    /// after a restart or a loss until the uplink confirms it again.
    confirmed: bool,
    stale: Vec<StalePrefix>,
    /// The latest `now` seen, to notice the clock stepping backwards.
    last_now: Option<u64>,
    #[serde(default)]
    stale_signal: StaleSignal,
}

fn deadline(now: u64, lifetime: u32) -> u64 {
    if lifetime == INFINITE_LIFETIME {
        u64::MAX
    } else {
        now.saturating_add(u64::from(lifetime))
    }
}

fn remaining(now: u64, until: u64) -> u64 {
    until.saturating_sub(now)
}

fn capped(secs: u64, cap: u32) -> u32 {
    u32::try_from(secs).unwrap_or(u32::MAX).min(cap)
}

fn shift_back(t: u64, by: u64) -> u64 {
    if t == u64::MAX {
        t
    } else {
        t.saturating_sub(by)
    }
}

impl PdState {
    /// A fresh state with no prefix.
    pub fn new() -> Self {
        Self::default()
    }

    /// Choose how stale Valid Lifetimes are signalled.
    pub fn with_stale_signal(mut self, signal: StaleSignal) -> Self {
        self.stale_signal = signal;
        self
    }

    /// The current delegation, if any (possibly unconfirmed, see
    /// [`PdState::is_confirmed`]).
    pub fn current(&self) -> Option<&DelegatedPrefix> {
        self.current.as_ref()
    }

    /// Whether the uplink confirmed the current prefix in the last
    /// observation.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed && self.current.is_some()
    }

    /// Prefixes being deprecated.
    pub fn stale(&self) -> &[StalePrefix] {
        &self.stale
    }

    /// The earliest moment at which [`PdState::advertised`] output changes
    /// by itself (a preferred lifetime ends, something expires). The agent
    /// should re-evaluate no later than this, in addition to its polling.
    pub fn next_deadline(&self) -> Option<u64> {
        let cur = self
            .current
            .iter()
            .flat_map(|c| [c.preferred_until, c.valid_until]);
        let stale = self.stale.iter().map(|s| s.deprecate_until);
        cur.chain(stale).filter(|t| *t != u64::MAX).min()
    }

    /// Forget whether the uplink holds the prefix, as after a restart: the
    /// next observation of the same prefix reports [`PdEvent::Renewed`].
    pub(crate) fn mark_unconfirmed(&mut self) {
        self.confirmed = false;
    }

    /// If the wall clock went backwards (a Pi without an RTC boots with a
    /// clock older than the persisted deadlines, or NTP steps back), assume
    /// no time passed since the last call and move every deadline back by
    /// the step. This keeps stale prefixes deprecated at least as long as
    /// needed; a later forward step only makes them expire sooner.
    fn rebase_clock(&mut self, now: u64) {
        if let Some(last) = self.last_now
            && now < last
        {
            let by = last - now;
            if let Some(c) = &mut self.current {
                c.preferred_until = shift_back(c.preferred_until, by);
                c.valid_until = shift_back(c.valid_until, by);
                c.obtained_at = c.obtained_at.saturating_sub(by);
                c.renewed_at = c.renewed_at.saturating_sub(by);
            }
            for s in &mut self.stale {
                s.stale_since = s.stale_since.saturating_sub(by);
                s.deprecate_until = shift_back(s.deprecate_until, by);
            }
        }
        self.last_now = Some(now);
    }

    /// Drop everything whose deadline has passed.
    pub fn expire(&mut self, now: u64) -> Vec<PdEvent> {
        self.rebase_clock(now);
        let mut events = Vec::new();
        self.stale.retain(|s| {
            let keep = s.deprecate_until > now;
            if !keep {
                events.push(PdEvent::Expired(s.prefix));
            }
            keep
        });
        if let Some(c) = self.current
            && c.valid_until <= now
        {
            // Hosts were never told a lifetime beyond valid_until, so their
            // addresses are gone too: nothing left to deprecate.
            self.current = None;
            self.confirmed = false;
            events.push(PdEvent::Expired(c.prefix));
        }
        events
    }

    /// Feed what the uplink holds now (`None`: no delegated prefix seen).
    pub fn observe(&mut self, now: u64, observation: Option<Observation>) -> Vec<PdEvent> {
        let mut events = self.expire(now);
        match observation {
            None => {
                if let Some(c) = &self.current
                    && self.confirmed
                {
                    self.confirmed = false;
                    events.push(PdEvent::Lost(c.prefix));
                }
            }
            Some(o) if o.valid_lifetime == 0 => {
                // RFC 9096 §3.5: a prefix the server delegates with a zero
                // valid lifetime is stale now.
                if let Some(c) = self.current
                    && c.prefix == o.prefix.trunc()
                {
                    self.current = None;
                    self.confirmed = false;
                    self.make_stale(now, &c);
                    events.push(PdEvent::Lost(c.prefix));
                }
            }
            Some(o) => events.extend(self.observe_held(now, o)),
        }
        events
    }

    fn observe_held(&mut self, now: u64, o: Observation) -> Option<PdEvent> {
        let prefix = o.prefix.trunc();
        let valid_until = deadline(now, o.valid_lifetime);
        let preferred_until = deadline(now, o.preferred_lifetime).min(valid_until);
        match self.current {
            Some(c) if c.prefix == prefix => {
                // Two deadlines already in the past are equal: "no longer
                // preferred" either way.
                let close = |a: u64, b: u64| {
                    a.abs_diff(b) <= RENEW_TOLERANCE_SECS || (a <= now && b <= now)
                };
                let same_lease = close(c.valid_until, valid_until)
                    && close(c.preferred_until, preferred_until)
                    && (o.iaid.is_none() || o.iaid == c.iaid);
                if same_lease && self.confirmed {
                    // ISS-C-003: polling the same lease is a no-op.
                    return None;
                }
                let renewed = DelegatedPrefix {
                    preferred_until,
                    valid_until,
                    iaid: o.iaid.or(c.iaid),
                    renewed_at: now,
                    ..c
                };
                self.current = Some(renewed);
                self.confirmed = true;
                Some(PdEvent::Renewed(renewed))
            }
            previous => {
                // A prefix coming back must not be advertised twice.
                self.stale.retain(|s| s.prefix != prefix);
                let new = DelegatedPrefix {
                    prefix,
                    preferred_until,
                    valid_until,
                    iaid: o.iaid,
                    obtained_at: now,
                    renewed_at: now,
                };
                self.current = Some(new);
                self.confirmed = true;
                Some(match previous {
                    Some(old) => {
                        self.make_stale(now, &old);
                        PdEvent::Changed {
                            old: old.prefix,
                            new,
                        }
                    }
                    None => PdEvent::Acquired(new),
                })
            }
        }
    }

    fn make_stale(&mut self, now: u64, old: &DelegatedPrefix) {
        // L-16 capped every Valid Lifetime we advertised at ND_VALID_LIMIT,
        // and never past valid_until, so hosts hold these addresses no
        // longer than this.
        let until = old
            .valid_until
            .min(now.saturating_add(u64::from(ND_VALID_LIMIT)));
        if until <= now {
            return;
        }
        self.stale.retain(|s| s.prefix != old.prefix);
        self.stale.push(StalePrefix {
            prefix: old.prefix,
            stale_since: now,
            deprecate_until: until,
        });
    }

    /// The prefixes each consumer must advertise at `now`: the current
    /// prefix's /64 with its remaining lifetimes, then each stale prefix's
    /// /64 as deprecated. Lifetimes are capped per RFC 9096 L-16. Consumers
    /// whose prefix ID does not fit a delegation get nothing from it; an
    /// interface with nothing to advertise is absent from the map.
    pub fn advertised(
        &self,
        now: u64,
        consumers: &[Consumer],
    ) -> BTreeMap<String, Vec<AdvertisedPrefix>> {
        let mut out: BTreeMap<String, Vec<AdvertisedPrefix>> = BTreeMap::new();
        for consumer in consumers {
            let mut list: Vec<AdvertisedPrefix> = Vec::new();
            if let Some(c) = &self.current
                && c.valid_until > now
                && let Some(p) = calculate_prefix(c.prefix, consumer.prefix_id)
            {
                list.push(AdvertisedPrefix {
                    prefix: p,
                    preferred_lifetime_secs: capped(
                        remaining(now, c.preferred_until),
                        ND_PREFERRED_LIMIT,
                    ),
                    valid_lifetime_secs: capped(remaining(now, c.valid_until), ND_VALID_LIMIT),
                    deprecated: false,
                });
            }
            for s in &self.stale {
                if s.deprecate_until <= now {
                    continue;
                }
                let Some(p) = calculate_prefix(s.prefix, consumer.prefix_id) else {
                    continue;
                };
                // A shorter/longer delegation from the same base can map a
                // stale subnet onto a live one; the live entry wins.
                if list.iter().any(|a| a.prefix == p) {
                    continue;
                }
                let valid = match self.stale_signal {
                    StaleSignal::CountDown => {
                        capped(remaining(now, s.deprecate_until), ND_VALID_LIMIT)
                    }
                    StaleSignal::Zero => 0,
                };
                list.push(AdvertisedPrefix {
                    prefix: p,
                    preferred_lifetime_secs: 0,
                    valid_lifetime_secs: valid,
                    deprecated: true,
                });
            }
            if !list.is_empty() {
                out.entry(consumer.interface.clone())
                    .or_default()
                    .extend(list);
            }
        }
        out
    }
}
