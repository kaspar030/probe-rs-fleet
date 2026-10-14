//! Clock seam so the scheduler's epoch-seconds time source is injectable.
//!
//! The pure scheduler in `probefleet-core` takes `now: u64` (epoch seconds) on every
//! time-sensitive call; the coordinator owns the actual clock. Keeping it
//! behind a tiny trait lets tests drive deterministic time without touching the
//! wall clock.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A source of epoch-seconds timestamps.
pub trait Clock: Send + Sync {
    /// The current time in seconds since the Unix epoch.
    fn now_secs(&self) -> u64;
}

/// The real wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
}

/// A shared, cheaply-cloneable clock handle.
pub type SharedClock = Arc<dyn Clock>;

/// The current wall-clock time in epoch seconds.
///
/// Returns `0` if the system clock is set before the Unix epoch (which never
/// happens in practice).
#[must_use]
pub fn now_epoch_secs() -> u64 {
    SystemClock.now_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A test clock that returns a fixed (settable) time.
    pub struct FixedClock(pub AtomicU64);

    impl Clock for FixedClock {
        fn now_secs(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn system_clock_is_after_2020() {
        // 2020-01-01 in epoch seconds; sanity check the real clock works.
        assert!(SystemClock.now_secs() > 1_577_836_800);
    }

    #[test]
    fn fixed_clock_returns_set_value() {
        let c = FixedClock(AtomicU64::new(42));
        assert_eq!(c.now_secs(), 42);
        c.0.store(100, Ordering::SeqCst);
        assert_eq!(c.now_secs(), 100);
    }
}
