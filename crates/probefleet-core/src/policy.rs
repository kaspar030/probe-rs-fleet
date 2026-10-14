//! Lease policy configuration and the pure cap-application logic.
//!
//! The [`Policy`] struct holds the knobs the coordinator loads from its config;
//! this module only defines the type and the *pure* functions that apply caps.
//! No clock, no I/O — all duration math is deterministic given the inputs.

use fleet_proto::lease::Priority;
use serde::{Deserialize, Serialize};

/// Leasing policy: duration caps per priority class, a per-subject
/// concurrency cap, and a default TTL used when a request omits a duration.
///
/// Values are supplied by coordinator config; this type only models them and
/// the [`Policy::cap_duration`] application logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Maximum lease duration (seconds) for [`Priority::Soak`] requests.
    pub max_duration_soak: u64,
    /// Maximum lease duration (seconds) for [`Priority::Ci`] requests.
    pub max_duration_ci: u64,
    /// Maximum lease duration (seconds) for [`Priority::Interactive`] requests.
    pub max_duration_interactive: u64,
    /// Maximum number of concurrently-held leases per subject, keyed by
    /// [`fleet_proto::ids::SubjectKey`].
    pub max_concurrent_per_subject: u32,
    /// Default TTL (seconds) applied when a request's `duration_secs` is `0`.
    pub default_ttl_secs: u64,
}

impl Default for Policy {
    /// Sensible defaults: Soak gets the longest window, Interactive the
    /// shortest; concurrency capped at 2; a 15-minute default TTL.
    fn default() -> Self {
        Self {
            max_duration_soak: 24 * 60 * 60,
            max_duration_ci: 60 * 60,
            max_duration_interactive: 4 * 60 * 60,
            max_concurrent_per_subject: 2,
            default_ttl_secs: 15 * 60,
        }
    }
}

impl Policy {
    /// The maximum lease duration (seconds) allowed for the given priority.
    #[must_use]
    pub fn max_duration_for(&self, priority: Priority) -> u64 {
        match priority {
            Priority::Soak => self.max_duration_soak,
            Priority::Ci => self.max_duration_ci,
            Priority::Interactive => self.max_duration_interactive,
        }
    }

    /// Resolve the effective lease duration (seconds) for a request.
    ///
    /// A `requested` of `0` falls back to [`Policy::default_ttl_secs`]; the
    /// result is then clamped to the priority-class maximum. The return value
    /// is always `>= 1` as long as the configured caps are non-zero.
    #[must_use]
    pub fn cap_duration(&self, priority: Priority, requested: u64) -> u64 {
        let wanted = if requested == 0 {
            self.default_ttl_secs
        } else {
            requested
        };
        wanted.min(self.max_duration_for(priority))
    }
}
