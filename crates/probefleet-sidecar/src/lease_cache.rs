//! Time-based lease sharing cache.
//!
//! A lease is *not* tied to a single `probe-rs` invocation (see
//! `docs/architecture.md` §6): a subject claims a board and holds it across
//! many invocations so remote DX feels local. This cache lets repeated sidecar
//! invocations reuse an existing lease instead of re-leasing on every
//! `probe-rs run`.
//!
//! Entries are keyed by `(selector fingerprint, subject key)` so that two
//! different selectors — or two different callers — never share a lease. The
//! subject key is `(org, kind, id)`, so two same-named users in different orgs
//! never collide either. The
//! cache is pure logic with an injected clock; persistence (e.g. a file under
//! `$XDG_RUNTIME_DIR/probe-rs-fleet/leases`) is a separate concern layered on
//! top and is intentionally not implemented here.

use std::collections::HashMap;

use probefleet_proto::ids::SubjectKey;
use probefleet_proto::lease::{Constraint, LeaseGrant};

/// Cache key: a stable fingerprint of the selector plus the calling subject.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Canonical, stable string form of the board selector.
    pub selector: String,
    /// The stable identity of the subject that holds the lease.
    pub subject: SubjectKey,
}

impl CacheKey {
    /// Build a key from a board [`Constraint`] and a [`SubjectKey`].
    #[must_use]
    pub fn new(select: &Constraint, subject: &SubjectKey) -> Self {
        Self {
            selector: fingerprint(select),
            subject: subject.clone(),
        }
    }
}

/// Produce a stable, collision-resistant-enough string fingerprint for a board
/// selector. Tags are sorted so set-equal selectors map to the same key.
///
/// # Not the same job as `Constraint`'s `Display`
///
/// [`probefleet_proto::lease::Constraint`] gained a canonical, **round-trippable**
/// rendering in architecture §6.5, which is what a grant stores and what the
/// evaluator re-parses. This function is a *cache key*: it sorts and dedups
/// tags for set-equality, which is exactly what a cache wants and exactly what
/// a round trip must not do (it would change the selector). The two must stay
/// separate; unifying them would make one of them wrong.
///
/// Also note what a cached `CachedLease.grant.token` is since §6.5: an identity
/// and delegation artefact, **not** a data-plane credential. Those come per
/// channel in `ChannelOpened`: its `token` (the capability the node verifies)
/// and its `serve_token` (what `probe-rs serve` accepts).
#[must_use]
pub fn fingerprint(select: &Constraint) -> String {
    match select {
        Constraint::Id(b) => format!("id:{}", b.0),
        Constraint::Model(m) => format!("model:{m}"),
        Constraint::Chip(c) => format!("chip:{c}"),
        Constraint::Tags(tags) => {
            let mut sorted = tags.clone();
            sorted.sort();
            sorted.dedup();
            format!("tags:{}", sorted.join(","))
        }
    }
}

/// A cached lease grant plus the safety margin used when judging validity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedLease {
    /// The granted lease as returned by the coordinator.
    pub grant: LeaseGrant,
    /// Refresh the lease (heartbeat) once it is within this many seconds of
    /// expiry; an entry inside the margin is treated as no longer valid for
    /// reuse so the caller re-leases or re-heartbeats.
    pub refresh_margin_secs: u64,
}

impl CachedLease {
    /// Default safety margin (30s) before expiry at which a lease is considered
    /// stale for reuse.
    pub const DEFAULT_REFRESH_MARGIN_SECS: u64 = 30;

    /// Wrap a [`LeaseGrant`] with the default refresh margin.
    #[must_use]
    pub fn new(grant: LeaseGrant) -> Self {
        Self {
            grant,
            refresh_margin_secs: Self::DEFAULT_REFRESH_MARGIN_SECS,
        }
    }

    /// Whether this lease is still safely usable at `now_secs` (epoch seconds),
    /// accounting for the refresh margin.
    #[must_use]
    pub fn is_valid(&self, now_secs: u64) -> bool {
        self.grant.expires.saturating_sub(self.refresh_margin_secs) > now_secs
    }
}

/// An in-memory cache of leases keyed by selector + subject.
#[derive(Debug, Default)]
pub struct LeaseCache {
    entries: HashMap<CacheKey, CachedLease>,
}

impl LeaseCache {
    /// Create an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert (or replace) a lease for the given selector + subject.
    pub fn insert(&mut self, select: &Constraint, subject: &SubjectKey, lease: CachedLease) {
        self.entries.insert(CacheKey::new(select, subject), lease);
    }

    /// Fetch a still-valid lease for the selector + subject at `now_secs`.
    ///
    /// Returns `None` if there is no entry, or if the entry has expired (or is
    /// within its refresh margin). Expired entries are evicted on access.
    #[must_use]
    pub fn get(
        &mut self,
        select: &Constraint,
        subject: &SubjectKey,
        now_secs: u64,
    ) -> Option<&CachedLease> {
        let key = CacheKey::new(select, subject);
        match self.entries.get(&key) {
            Some(entry) if entry.is_valid(now_secs) => self.entries.get(&key),
            Some(_) => {
                self.entries.remove(&key);
                None
            }
            None => None,
        }
    }

    /// Remove a lease (e.g. on explicit release), returning it if present.
    pub fn remove(&mut self, select: &Constraint, subject: &SubjectKey) -> Option<CachedLease> {
        self.entries.remove(&CacheKey::new(select, subject))
    }

    /// Drop every entry that is no longer valid at `now_secs`.
    pub fn evict_expired(&mut self, now_secs: u64) {
        self.entries.retain(|_, lease| lease.is_valid(now_secs));
    }

    /// Number of entries currently held (valid or not).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use probefleet_proto::ids::{
        BoardName, BoardRef, LeaseId, NodeId, OrgId, SubjectKey, SubjectKind,
    };

    fn subject(holder: &str) -> SubjectKey {
        subject_in("default", holder)
    }

    fn subject_in(ns: &str, holder: &str) -> SubjectKey {
        SubjectKey::new(Some(ns), SubjectKind::User, holder).unwrap()
    }

    fn grant(expires: u64, holder: &str) -> LeaseGrant {
        LeaseGrant {
            lease: LeaseId(1),
            board: BoardRef::new(
                OrgId("default".to_owned()),
                NodeId("node-1".to_owned()),
                "nrf52840-dk-3",
            ),
            node: NodeId("node-1".to_owned()),
            holder: subject(holder),
            expires,
            token: vec![1, 2, 3],
        }
    }

    fn board_sel() -> Constraint {
        Constraint::Id(BoardName("nrf52840-dk-3".to_owned()))
    }

    #[test]
    fn insert_then_get_when_valid() {
        let mut cache = LeaseCache::new();
        let p = subject("dev");
        cache.insert(&board_sel(), &p, CachedLease::new(grant(1000, "dev")));
        // now well before expiry minus margin.
        let got = cache.get(&board_sel(), &p, 500);
        assert!(got.is_some());
        assert_eq!(got.unwrap().grant.expires, 1000);
    }

    #[test]
    fn expired_entry_is_evicted_on_get() {
        let mut cache = LeaseCache::new();
        let p = subject("dev");
        cache.insert(&board_sel(), &p, CachedLease::new(grant(1000, "dev")));
        // now past expiry.
        assert!(cache.get(&board_sel(), &p, 2000).is_none());
        assert!(cache.is_empty());
    }

    #[test]
    fn within_refresh_margin_is_invalid() {
        let lease = CachedLease::new(grant(1000, "dev"));
        // default margin 30s: valid strictly before 970.
        assert!(lease.is_valid(969));
        assert!(!lease.is_valid(970));
        assert!(!lease.is_valid(1001));
    }

    #[test]
    fn key_includes_subject() {
        let mut cache = LeaseCache::new();
        let alice = subject("alice");
        let bob = subject("bob");
        cache.insert(&board_sel(), &alice, CachedLease::new(grant(1000, "alice")));
        // bob shares the selector but must NOT see alice's lease.
        assert!(cache.get(&board_sel(), &bob, 500).is_none());
        assert!(cache.get(&board_sel(), &alice, 500).is_some());
    }

    /// Two same-named users in different orgs must not share a cached lease:
    /// the key is the full `SubjectKey`, org included.
    #[test]
    fn key_includes_org() {
        let mut cache = LeaseCache::new();
        let alice_a = subject_in("org-a", "alice");
        let alice_b = subject_in("org-b", "alice");
        cache.insert(
            &board_sel(),
            &alice_a,
            CachedLease::new(grant(1000, "alice")),
        );
        assert!(cache.get(&board_sel(), &alice_b, 500).is_none());
        assert!(cache.get(&board_sel(), &alice_a, 500).is_some());
    }

    #[test]
    fn key_includes_selector() {
        let mut cache = LeaseCache::new();
        let p = subject("dev");
        cache.insert(&board_sel(), &p, CachedLease::new(grant(1000, "dev")));
        let other = Constraint::Chip("STM32F407".to_owned());
        assert!(cache.get(&other, &p, 500).is_none());
    }

    #[test]
    fn tags_fingerprint_is_order_independent() {
        let a = Constraint::Tags(vec!["nrf52".to_owned(), "bluetooth".to_owned()]);
        let b = Constraint::Tags(vec!["bluetooth".to_owned(), "nrf52".to_owned()]);
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    /// An instance and a model selector spelling the same word are different
    /// selectors, so they must be different cache keys — `id:x` and `model:x`,
    /// never a shared `board:` prefix.
    #[test]
    fn an_id_and_a_model_never_share_a_key() {
        let id = Constraint::Id(BoardName("nrf52840dk".to_owned()));
        let model = Constraint::Model("nrf52840dk".to_owned());
        assert_eq!(fingerprint(&id), "id:nrf52840dk");
        assert_eq!(fingerprint(&model), "model:nrf52840dk");
        assert_ne!(fingerprint(&id), fingerprint(&model));

        let mut cache = LeaseCache::new();
        let p = subject("dev");
        cache.insert(&id, &p, CachedLease::new(grant(1000, "dev")));
        assert!(cache.get(&model, &p, 500).is_none());
    }

    #[test]
    fn remove_returns_entry() {
        let mut cache = LeaseCache::new();
        let p = subject("dev");
        cache.insert(&board_sel(), &p, CachedLease::new(grant(1000, "dev")));
        let removed = cache.remove(&board_sel(), &p);
        assert!(removed.is_some());
        assert!(cache.is_empty());
    }

    #[test]
    fn evict_expired_drops_only_stale() {
        let mut cache = LeaseCache::new();
        let p = subject("dev");
        cache.insert(&board_sel(), &p, CachedLease::new(grant(1000, "dev")));
        cache.insert(
            &Constraint::Chip("c".to_owned()),
            &p,
            CachedLease::new(grant(3000, "dev")),
        );
        cache.evict_expired(1500);
        assert_eq!(cache.len(), 1);
        assert!(cache
            .get(&Constraint::Chip("c".to_owned()), &p, 1500)
            .is_some());
    }
}
