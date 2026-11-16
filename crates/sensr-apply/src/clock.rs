//! Injectable monotonic time, so timers (commit-confirm, action caches) are
//! testable without sleeping.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A monotonic clock.
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> Instant;
}

/// The real monotonic clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// A clock that only moves when told to.
#[derive(Debug)]
pub struct FakeClock {
    base: Instant,
    offset: Mutex<Duration>,
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeClock {
    /// A clock frozen at an arbitrary starting instant.
    pub fn new() -> Self {
        FakeClock {
            base: Instant::now(),
            offset: Mutex::new(Duration::ZERO),
        }
    }

    /// Move time forward.
    pub fn advance(&self, by: Duration) {
        let mut o = self.offset.lock().unwrap_or_else(|e| e.into_inner());
        *o += by;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        self.base + *self.offset.lock().unwrap_or_else(|e| e.into_inner())
    }
}
