//! Scan pacing: a connects-per-second token bucket plus an in-flight cap.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::config::PaceLimits;

/// Hands out permits no faster than the configured rate and never more than
/// `in_flight` at once. A permit is held for the life of one probe; a probe
/// that sends again (a retry) takes another rate token with [`Pacer::tick`].
///
/// Clones share the same rate and slots.
#[derive(Debug, Clone)]
pub struct Pacer {
    interval: Duration,
    next: Arc<Mutex<Instant>>,
    slots: Arc<Semaphore>,
}

/// One in-flight slot; dropping it frees the slot.
#[derive(Debug)]
pub struct PacerPermit {
    _slot: OwnedSemaphorePermit,
}

impl Pacer {
    /// A pacer for `l`. Zero limits are treated as one.
    #[must_use]
    pub fn new(l: PaceLimits) -> Pacer {
        let rate = l.connects_per_sec.max(1);
        Pacer {
            interval: Duration::from_secs(1) / rate,
            next: Arc::new(Mutex::new(Instant::now())),
            slots: Arc::new(Semaphore::new(usize::from(l.in_flight.max(1)))),
        }
    }

    /// Wait for an in-flight slot, then for the next start time.
    ///
    /// Cancel-safe: dropping the future gives up the slot.
    pub async fn permit(&self) -> PacerPermit {
        let slot = Arc::clone(&self.slots)
            .acquire_owned()
            .await
            .expect("pacer semaphore is never closed");
        self.tick().await;
        PacerPermit { _slot: slot }
    }

    /// Wait for the next start time only (no slot): for a probe that holds
    /// a permit and sends again.
    pub async fn tick(&self) {
        let at = {
            let mut next = self.next.lock().await;
            let at = (*next).max(Instant::now());
            *next = at + self.interval;
            at
        };
        tokio::time::sleep_until(at).await;
    }
}
