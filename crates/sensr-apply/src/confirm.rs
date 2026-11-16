//! Commit-confirm: an apply that could cut off management is provisional
//! until confirmed; if nobody confirms before the deadline, the last
//! confirmed revision is re-applied (PLAN.md §2.4 step 4, ISS-C-016).
//!
//! This is pure state-machine logic over an injectable [`Clock`]; the agent
//! drives it by sleeping until [`CommitConfirm::deadline`] and calling
//! [`CommitConfirm::poll`].

use std::fmt::Debug;
use std::time::{Duration, Instant};

use crate::clock::Clock;

/// Default confirmation window.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pending<R> {
    applied: R,
    known_good: R,
    deadline: Instant,
}

/// Result of [`CommitConfirm::confirm`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confirmed<R> {
    /// The provisional revision is now the known-good one.
    Kept(R),
    /// Nothing was pending (already confirmed, rolled back, or never provisional).
    NothingPending,
}

/// The commit-confirm timer. `R` identifies a configuration revision.
#[derive(Debug)]
pub struct CommitConfirm<R, C> {
    clock: C,
    window: Duration,
    pending: Option<Pending<R>>,
}

impl<R: Clone + PartialEq + Debug, C: Clock> CommitConfirm<R, C> {
    /// A timer with the default 5-minute window.
    pub fn new(clock: C) -> Self {
        Self::with_window(clock, DEFAULT_WINDOW)
    }

    /// A timer with a custom default window.
    pub fn with_window(clock: C, window: Duration) -> Self {
        CommitConfirm {
            clock,
            window,
            pending: None,
        }
    }

    /// Record that `applied` was just applied provisionally on top of
    /// `previous`. Returns the deadline.
    ///
    /// If another apply is already pending, its deadline is replaced but the
    /// rollback target stays the revision that was last *confirmed*: the
    /// pending one was never proven to keep management reachable.
    pub fn begin(&mut self, applied: R, previous: R, window: Option<Duration>) -> Instant {
        let deadline = self.clock.now() + window.unwrap_or(self.window);
        let known_good = match self.pending.take() {
            Some(p) => p.known_good,
            None => previous,
        };
        self.pending = Some(Pending {
            applied,
            known_good,
            deadline,
        });
        deadline
    }

    /// Confirm the pending apply (from a working session).
    pub fn confirm(&mut self) -> Confirmed<R> {
        match self.pending.take() {
            Some(p) => Confirmed::Kept(p.applied),
            None => Confirmed::NothingPending,
        }
    }

    /// The pending deadline, if any.
    pub fn deadline(&self) -> Option<Instant> {
        self.pending.as_ref().map(|p| p.deadline)
    }

    /// Time left before rollback.
    pub fn remaining(&self) -> Option<Duration> {
        self.deadline()
            .map(|d| d.saturating_duration_since(self.clock.now()))
    }

    /// The provisional revision, if one is pending.
    pub fn pending(&self) -> Option<&R> {
        self.pending.as_ref().map(|p| &p.applied)
    }

    /// If the deadline has passed, clear the pending state and return the
    /// revision to roll back to.
    pub fn poll(&mut self) -> Option<R> {
        match &self.pending {
            Some(p) if self.clock.now() >= p.deadline => self.pending.take().map(|p| p.known_good),
            _ => None,
        }
    }

    /// [`poll`](Self::poll), then run `rollback` with the target revision. If
    /// the rollback fails the target stays pending so the next poll retries.
    pub fn poll_and_rollback<E>(
        &mut self,
        rollback: impl FnOnce(&R) -> Result<(), E>,
    ) -> Result<Option<R>, E> {
        let snapshot = self.pending.clone();
        let Some(target) = self.poll() else {
            return Ok(None);
        };
        match rollback(&target) {
            Ok(()) => Ok(Some(target)),
            Err(e) => {
                self.pending = snapshot;
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;
    use std::sync::Arc;

    impl Clock for Arc<FakeClock> {
        fn now(&self) -> Instant {
            (**self).now()
        }
    }

    fn timer() -> (Arc<FakeClock>, CommitConfirm<u32, Arc<FakeClock>>) {
        let c = Arc::new(FakeClock::new());
        (c.clone(), CommitConfirm::new(c))
    }

    #[test]
    fn confirm_timer_reverts_on_timeout() {
        let (clock, mut t) = timer();
        t.begin(2, 1, None);
        clock.advance(Duration::from_secs(299));
        assert_eq!(t.poll(), None);
        clock.advance(Duration::from_secs(1));
        let mut rolled = None;
        let r: Result<_, ()> = t.poll_and_rollback(|rev| {
            rolled = Some(*rev);
            Ok(())
        });
        assert_eq!(r, Ok(Some(1)));
        assert_eq!(rolled, Some(1));
        assert_eq!(t.pending(), None);
        assert_eq!(t.poll(), None, "rollback happens once");
    }

    #[test]
    fn confirm_before_deadline_keeps() {
        let (clock, mut t) = timer();
        t.begin(2, 1, Some(Duration::from_secs(60)));
        clock.advance(Duration::from_secs(59));
        assert_eq!(t.remaining(), Some(Duration::from_secs(1)));
        assert_eq!(t.confirm(), Confirmed::Kept(2));
        clock.advance(Duration::from_secs(3600));
        assert_eq!(t.poll(), None);
    }

    #[test]
    fn double_confirm_is_idempotent() {
        let (_clock, mut t) = timer();
        t.begin(2, 1, None);
        assert_eq!(t.confirm(), Confirmed::Kept(2));
        assert_eq!(t.confirm(), Confirmed::NothingPending);
    }

    #[test]
    fn new_apply_during_pending_replaces_deadline_keeps_known_good() {
        let (clock, mut t) = timer();
        t.begin(2, 1, None);
        clock.advance(Duration::from_secs(200));
        let d2 = t.begin(3, 2, None);
        assert_eq!(t.deadline(), Some(d2));
        clock.advance(Duration::from_secs(200));
        assert_eq!(t.poll(), None, "old deadline no longer applies");
        assert_eq!(t.pending(), Some(&3));
        clock.advance(Duration::from_secs(100));
        // Revision 2 was never confirmed, so roll back to 1.
        assert_eq!(t.poll(), Some(1));
    }

    #[test]
    fn failed_rollback_retries() {
        let (clock, mut t) = timer();
        t.begin(2, 1, None);
        clock.advance(DEFAULT_WINDOW);
        assert_eq!(t.poll_and_rollback(|_| Err("nft busy")), Err("nft busy"));
        assert_eq!(t.pending(), Some(&2));
        assert_eq!(t.poll_and_rollback(|_| Ok::<_, ()>(())), Ok(Some(1)));
    }
}
