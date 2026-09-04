//! Node-token rotation policy.
//!
//! A node token is long-lived, which is exactly what makes a leak valuable. The
//! coordinator therefore pushes a replacement down the established connection
//! periodically, so a token stolen from a Pi's disk stops working within one
//! rotation interval.
//!
//! # Ack-then-retire
//!
//! The coordinator **must not** retire the old hash when it sends the
//! replacement. The push is lost precisely when the connection dies mid-write,
//! and a proxy reaping idle `WebSocket`s on a timeout we do not control makes that
//! the *expected* case, not an exotic one. Retiring eagerly would mean a lost
//! push de-enrolls a headless Pi in a lab — physical re-provisioning as the
//! price of a few seconds' less exposure on a 7-day schedule.
//!
//! So: mint, hold the replacement in memory on the connection, push
//! `RotateNodeToken { rotation_id, .. }`, and promote it only on the matching
//! `TokenRotated { rotation_id }` ack. A lost push costs one retry.
//!
//! The agent closes the mirror-image window (ack lost *after* it persisted) by
//! keeping its previous token and retrying once with it — client-side, no server
//! state.

use std::time::Duration;

/// When to rotate a node token, and how long to wait for the ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPolicy {
    /// Rotate once a token is older than this (seconds).
    pub max_age_secs: u64,
    /// Discard an unacked pending rotation after this long and retry later.
    pub ack_timeout_secs: u64,
}

impl RotationPolicy {
    /// The default policy: rotate weekly, give the node 60 s to ack.
    pub const DEFAULT: Self = Self {
        max_age_secs: 7 * 24 * 60 * 60,
        ack_timeout_secs: 60,
    };

    /// The ack timeout as a [`Duration`].
    #[must_use]
    pub fn ack_timeout(&self) -> Duration {
        Duration::from_secs(self.ack_timeout_secs)
    }
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Whether a node token issued at `issued_at` should be rotated at `now`.
///
/// A token whose `issued_at` is in the future (clock skew, or a row written by a
/// machine with a wrong clock) is **not** rotated: `now - issued_at` would
/// underflow into "very old" and rotate on every check.
#[must_use]
pub fn should_rotate(issued_at: u64, now: u64, policy: RotationPolicy) -> bool {
    now.saturating_sub(issued_at) >= policy.max_age_secs && now >= issued_at
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: RotationPolicy = RotationPolicy {
        max_age_secs: 100,
        ack_timeout_secs: 10,
    };

    #[test]
    fn rotates_at_and_after_the_boundary() {
        assert!(!should_rotate(0, 99, P));
        assert!(should_rotate(0, 100, P));
        assert!(should_rotate(0, 10_000, P));
    }

    #[test]
    fn a_future_issued_at_does_not_rotate() {
        // saturating_sub would otherwise report age 0 — the belt; the explicit
        // `now >= issued_at` is the braces.
        assert!(!should_rotate(1_000, 500, P));
    }

    #[test]
    fn default_policy_is_weekly_with_a_minute_of_ack_slack() {
        let d = RotationPolicy::default();
        assert_eq!(d.max_age_secs, 604_800);
        assert_eq!(d.ack_timeout(), Duration::from_secs(60));
    }
}
