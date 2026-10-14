//! Per-node probe adoption policy (architecture §4.2, §8).
//!
//! Revision 1 made every probe wait for a `boards.toml` declaration. That is
//! right for a lab and pure friction for a laptop, so whether an *undeclared*
//! probe becomes a leasable board is now a per-node setting rather than a
//! global gate.
//!
//! The enum lives in `probefleet-proto` because three crates name it: the agent
//! (which decides whether to synthesise board metadata for undeclared probes),
//! the coordinator (which stores it on the `node` row and enforces it), and
//! `probefleet` (which writes it into `node/node.toml` and sends it at
//! registration).
//!
//! **The coordinator's row is authoritative for enforcement.** The node's local
//! copy governs only what it *reports*; editing `node.toml` does not change
//! what the coordinator will adopt.

use serde::{Deserialize, Serialize};

/// What a node does with a probe that `boards.toml` does not declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdoptPolicy {
    /// Adopt discovered probes automatically, with tags inferred from the
    /// probe. The default for nodes created by `probefleet share`: plug in
    /// a board and it is usable.
    Auto,
    /// Report undeclared probes but keep them unleasable until they are
    /// declared in `boards.toml`. The default for auth-key / lab nodes, so CI
    /// gets stable ids and no surprises.
    #[default]
    Declared,
}

impl AdoptPolicy {
    /// The stored/wire label (`"auto"` / `"declared"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            AdoptPolicy::Auto => "auto",
            AdoptPolicy::Declared => "declared",
        }
    }

    /// Parse a stored/wire label.
    ///
    /// Deliberately **strict**: an unrecognised value is `None`, never a
    /// silent default. A typo'd `adopt = "delcared"` quietly meaning `auto`
    /// would be exactly the wrong failure — it would open a node's probes to
    /// adoption its operator did not ask for.
    ///
    /// Note in particular that revision 2's schema placeholder `'manual'` is
    /// **not** accepted; migration `0004_adopt_policy.sql` rewrites those rows
    /// to `declared`.
    #[must_use]
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(AdoptPolicy::Auto),
            "declared" => Some(AdoptPolicy::Declared),
            _ => None,
        }
    }
}

impl std::fmt::Display for AdoptPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_round_trip() {
        for policy in [AdoptPolicy::Auto, AdoptPolicy::Declared] {
            assert_eq!(AdoptPolicy::from_label(policy.as_str()), Some(policy));
        }
    }

    /// The conservative policy is the default, so a value that was never set
    /// cannot silently open a node's probes up.
    #[test]
    fn the_default_is_declared() {
        assert_eq!(AdoptPolicy::default(), AdoptPolicy::Declared);
    }

    /// Strictness is the point: `'manual'` was revision 2's schema placeholder
    /// and must fail loudly rather than resolve to either policy.
    #[test]
    fn unknown_labels_are_rejected_including_the_old_placeholder() {
        assert_eq!(AdoptPolicy::from_label("manual"), None);
        assert_eq!(AdoptPolicy::from_label("delcared"), None);
        assert_eq!(AdoptPolicy::from_label(""), None);
    }

    #[test]
    fn serde_uses_the_same_lowercase_labels() {
        let json = serde_json::to_string(&AdoptPolicy::Auto).unwrap();
        assert_eq!(json, "\"auto\"");
        let back: AdoptPolicy = serde_json::from_str("\"declared\"").unwrap();
        assert_eq!(back, AdoptPolicy::Declared);
    }
}
