//! In-memory, deterministic lease scheduler — the pure heart of the fleet.
//!
//! The [`Scheduler`] owns the fleet view (the set of [`Board`]s and their lease
//! state) and decides who gets which board. It is intentionally free of I/O,
//! async, and clocks: every method that cares about time takes `now: u64`
//! (epoch seconds) from the caller, which makes the whole crate trivially
//! unit-testable and deterministic.
//!
//! ## Core vs coordinator split
//!
//! The scheduler never builds the wire [`fleet_proto::LeaseGrant`], because the
//! grant carries a signed capability `token` that is the coordinator's
//! responsibility. Instead the scheduler returns value objects —
//! [`GrantedLease`] (which mirrors `LeaseGrant` minus `token`) and
//! [`ExpiredLease`] — and the coordinator mints the token and constructs the
//! wire type from them.
//!
//! ## Queue model
//!
//! A single global FIFO queue of [`Waiter`]s is kept. Promotion (on release or
//! expiry) scans the queue for waiters whose constraint matches the freed
//! board and whose holder is under the concurrency cap, then picks the highest
//! priority, breaking ties by enqueue order (FIFO within a class). The
//! `position` reported in [`LeaseDecision::Queued`] is the 0-based index among
//! already-queued waiters sharing the same `select` constraint.
//!
//! ## Exclusivity
//!
//! v1 treats every board as single-lease: a board is grantable only while
//! [`BoardState::Idle`]. The `exclusive` flag is honored by this
//! single-lease-per-board rule; non-exclusive *shared* leasing is a future
//! extension and is not implemented here.

use std::collections::BTreeMap;

use fleet_proto::board::{Board, BoardState};
use fleet_proto::ids::{AgentId, BoardId, LeaseId, Principal};
use fleet_proto::lease::{Constraint, LeaseRequest, Priority};

/// A lease the scheduler has granted, minus the signed wire token.
///
/// Maps onto [`fleet_proto::LeaseGrant`] field-for-field except `token`, which
/// the coordinator fills in. Returned from [`Scheduler::request_lease`],
/// [`Scheduler::release_lease`], and [`Scheduler::expire`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedLease {
    /// The allocated lease id.
    pub lease: LeaseId,
    /// The board handed to the holder.
    pub board: BoardId,
    /// The agent that owns the board.
    pub agent: AgentId,
    /// The principal that now holds the lease.
    pub holder: Principal,
    /// Expiry as epoch seconds.
    pub expires: u64,
}

/// A lease that the scheduler has freed during [`Scheduler::expire`].
///
/// The coordinator uses this to trigger agent-side cleanup (power-cycle/erase)
/// for the board that was reclaimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpiredLease {
    /// The lease that expired.
    pub lease: LeaseId,
    /// The board that was freed.
    pub board: BoardId,
    /// The agent that owns the board.
    pub agent: AgentId,
    /// The principal that had held the lease.
    pub holder: Principal,
}

/// The outcome of a [`Scheduler::request_lease`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseDecision {
    /// A board was available and has been leased to the requester.
    Granted(GrantedLease),
    /// No matching board was free; the request was queued.
    Queued {
        /// 0-based position among waiters sharing the same constraint.
        position: u32,
    },
}

/// The result of an [`Scheduler::expire`] sweep.
///
/// A board may appear in both `freed` and (via a [`GrantedLease`]) `granted`
/// when it is reclaimed and immediately handed to a waiter in the same sweep.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExpireResult {
    /// Leases reclaimed because they passed their expiry.
    pub freed: Vec<ExpiredLease>,
    /// New grants made by draining the queue onto just-freed boards.
    pub granted: Vec<GrantedLease>,
}

/// Bookkeeping for one active lease, indexed by [`LeaseId`].
#[derive(Debug, Clone)]
struct LeaseInfo {
    board: BoardId,
    holder: Principal,
    priority: Priority,
    expires: u64,
}

/// A queued request waiting for a matching board to free up.
#[derive(Debug, Clone)]
struct Waiter {
    holder: Principal,
    request: LeaseRequest,
    seq: u64,
}

/// In-memory lease scheduler. See the [module docs](self) for the model.
#[derive(Debug, Clone)]
pub struct Scheduler {
    boards: BTreeMap<BoardId, Board>,
    leases: BTreeMap<LeaseId, LeaseInfo>,
    queue: Vec<Waiter>,
    policy: crate::policy::Policy,
    next_lease_id: u64,
    next_seq: u64,
}

/// Does `board` satisfy `constraint`? (Ignores board state — see
/// [`Scheduler::is_candidate`] for the Idle check.)
fn matches(board: &Board, constraint: &Constraint) -> bool {
    match constraint {
        Constraint::Board(id) => &board.id == id,
        Constraint::Tags(tags) => tags.iter().all(|t| board.tags.contains(t)),
        Constraint::Chip(chip) => &board.chip == chip,
    }
}

impl Scheduler {
    /// Create a scheduler with the given [`crate::policy::Policy`] and an empty
    /// fleet view.
    #[must_use]
    pub fn new(policy: crate::policy::Policy) -> Self {
        Self {
            boards: BTreeMap::new(),
            leases: BTreeMap::new(),
            queue: Vec::new(),
            policy,
            next_lease_id: 1,
            next_seq: 0,
        }
    }

    /// All known boards, ordered by [`BoardId`].
    pub fn boards(&self) -> impl Iterator<Item = &Board> {
        self.boards.values()
    }

    /// Look up a single board by id.
    #[must_use]
    pub fn board(&self, id: &BoardId) -> Option<&Board> {
        self.boards.get(id)
    }

    /// The configured policy.
    #[must_use]
    pub fn policy(&self) -> &crate::policy::Policy {
        &self.policy
    }

    /// Insert or update a board from an agent inventory report.
    ///
    /// The agent reports inventory and identity; the scheduler owns lease
    /// state. Reconciliation rule: if the board is already known and currently
    /// [`BoardState::Leased`], the live lease state is preserved (the reported
    /// `state` is ignored). Otherwise the reported board — including its
    /// `state` — is taken as-is.
    pub fn upsert_board(&mut self, mut board: Board) {
        if let Some(existing) = self.boards.get(&board.id) {
            if matches!(existing.state, BoardState::Leased { .. }) {
                board.state = existing.state.clone();
            }
        }
        self.boards.insert(board.id.clone(), board);
    }

    /// Remove a board entirely (e.g. an agent dropped it from inventory).
    ///
    /// If the board was leased, the lease entry is dropped too. The removed
    /// board is returned so the caller can clean up; any active lease on it is
    /// silently discarded (the lease becomes unknown to [`extend_lease`] etc.).
    ///
    /// [`extend_lease`]: Scheduler::extend_lease
    pub fn remove_board(&mut self, id: &BoardId) -> Option<Board> {
        let board = self.boards.remove(id)?;
        self.leases.retain(|_, info| info.board != *id);
        Some(board)
    }

    /// Count the leases currently held by `principal`.
    fn active_for(&self, principal: &Principal) -> u32 {
        u32::try_from(
            self.leases
                .values()
                .filter(|info| &info.holder == principal)
                .count(),
        )
        .unwrap_or(u32::MAX)
    }

    /// Is `board` a grant candidate for `constraint`? (Idle and matching.)
    fn is_candidate(board: &Board, constraint: &Constraint) -> bool {
        board.state == BoardState::Idle && matches(board, constraint)
    }

    /// Find the first idle board (by [`BoardId`] order) matching `constraint`.
    fn find_idle(&self, constraint: &Constraint) -> Option<BoardId> {
        self.boards
            .values()
            .find(|b| Self::is_candidate(b, constraint))
            .map(|b| b.id.clone())
    }

    /// Allocate the next lease id.
    fn alloc_lease(&mut self) -> LeaseId {
        let id = LeaseId(self.next_lease_id);
        self.next_lease_id += 1;
        id
    }

    /// Mark `board` leased to `holder` and record the lease. Returns the value
    /// object describing the grant.
    fn grant(
        &mut self,
        board_id: &BoardId,
        holder: Principal,
        priority: Priority,
        expires: u64,
    ) -> GrantedLease {
        let lease = self.alloc_lease();
        let board = self
            .boards
            .get_mut(board_id)
            .expect("grant target board must exist");
        board.state = BoardState::Leased {
            lease,
            by: holder.clone(),
            expires,
        };
        let agent = board.agent.clone();
        self.leases.insert(
            lease,
            LeaseInfo {
                board: board_id.clone(),
                holder: holder.clone(),
                priority,
                expires,
            },
        );
        GrantedLease {
            lease,
            board: board_id.clone(),
            agent,
            holder,
            expires,
        }
    }

    /// Position a new waiter would take among waiters sharing `select`.
    fn queue_position(&self, select: &Constraint) -> u32 {
        u32::try_from(self.queue.iter().filter(|w| &w.request.select == select).count())
            .unwrap_or(u32::MAX)
    }

    /// Request a lease for `principal`.
    ///
    /// If the principal is at or above its concurrency cap, the request is
    /// queued rather than rejected, so it drains naturally when the principal
    /// releases a board. Otherwise the first matching idle board is granted; if
    /// none is free the request is queued FIFO.
    pub fn request_lease(
        &mut self,
        principal: Principal,
        request: LeaseRequest,
        now: u64,
    ) -> LeaseDecision {
        let at_cap = self.active_for(&principal) >= self.policy.max_concurrent_per_principal;

        if !at_cap {
            if let Some(board_id) = self.find_idle(&request.select) {
                let dur = self.policy.cap_duration(request.priority, request.duration_secs);
                let grant = self.grant(&board_id, principal, request.priority, now + dur);
                return LeaseDecision::Granted(grant);
            }
        }

        let position = self.queue_position(&request.select);
        let seq = self.next_seq;
        self.next_seq += 1;
        self.queue.push(Waiter {
            holder: principal,
            request,
            seq,
        });
        LeaseDecision::Queued { position }
    }

    /// Extend an active lease's expiry to `now + max_duration_for(priority)`.
    ///
    /// The renewal re-applies the priority-class cap from `now`, so a lease may
    /// be held indefinitely across many probe-rs invocations as long as it is
    /// extended before it expires. Updates both the lease index and the board's
    /// [`BoardState::Leased`] expiry. Returns the new expiry, or `None` if the
    /// lease is unknown.
    pub fn extend_lease(&mut self, lease: LeaseId, now: u64) -> Option<u64> {
        let info = self.leases.get_mut(&lease)?;
        let new_expires = now + self.policy.max_duration_for(info.priority);
        info.expires = new_expires;
        if let Some(board) = self.boards.get_mut(&info.board) {
            if let BoardState::Leased { expires, .. } = &mut board.state {
                *expires = new_expires;
            }
        }
        Some(new_expires)
    }

    /// Release an active lease, freeing its board, then promote the
    /// highest-priority eligible waiter onto it (if any).
    ///
    /// Returns the [`GrantedLease`] for the promoted waiter, or `None` if the
    /// lease was unknown or no queued waiter matched the freed board. In either
    /// non-error case the freed board ends up `Idle` (then possibly re-leased).
    pub fn release_lease(&mut self, lease: LeaseId, now: u64) -> Option<GrantedLease> {
        let info = self.leases.remove(&lease)?;
        if let Some(board) = self.boards.get_mut(&info.board) {
            board.state = BoardState::Idle;
        }
        self.promote_one(&info.board, now)
    }

    /// Sweep expired leases, freeing boards, then drain the queue onto the
    /// freed (now idle) boards.
    ///
    /// A lease is expired when `expires <= now`. Freeing happens first, so a
    /// board reclaimed in this sweep can be handed to a waiter in the same
    /// call — such a board appears in [`ExpireResult::freed`] and the new
    /// holder in [`ExpireResult::granted`].
    ///
    /// # Panics
    ///
    /// Does not panic in practice: the only `expect` operates on lease ids
    /// gathered from the current lease table moments earlier.
    pub fn expire(&mut self, now: u64) -> ExpireResult {
        let expired: Vec<LeaseId> = self
            .leases
            .iter()
            .filter(|(_, info)| info.expires <= now)
            .map(|(id, _)| *id)
            .collect();

        let mut result = ExpireResult::default();
        let mut freed_boards = Vec::new();

        for lease in expired {
            let info = self
                .leases
                .remove(&lease)
                .expect("lease id came from current leases");
            let agent = self.boards.get(&info.board).map(|b| b.agent.clone());
            if let Some(board) = self.boards.get_mut(&info.board) {
                board.state = BoardState::Idle;
            }
            if let Some(agent) = agent {
                result.freed.push(ExpiredLease {
                    lease,
                    board: info.board.clone(),
                    agent,
                    holder: info.holder,
                });
                freed_boards.push(info.board);
            }
        }

        for board_id in freed_boards {
            if let Some(grant) = self.promote_one(&board_id, now) {
                result.granted.push(grant);
            }
        }

        result
    }

    /// Promote the best eligible waiter onto a now-idle board.
    ///
    /// "Best" = highest priority, then earliest enqueue (`seq`) within a class.
    /// A waiter is eligible if its constraint matches the board and its holder
    /// is under the concurrency cap. Mutates state and returns the grant, or
    /// `None` if the board is missing/not idle or no waiter matched.
    fn promote_one(&mut self, board_id: &BoardId, now: u64) -> Option<GrantedLease> {
        let board = self.boards.get(board_id)?;
        if board.state != BoardState::Idle {
            return None;
        }

        let best = self
            .queue
            .iter()
            .enumerate()
            .filter(|(_, w)| {
                matches(board, &w.request.select)
                    && self.active_for(&w.holder) < self.policy.max_concurrent_per_principal
            })
            .max_by(|(_, a), (_, b)| {
                a.request
                    .priority
                    .cmp(&b.request.priority)
                    .then(b.seq.cmp(&a.seq))
            })
            .map(|(idx, _)| idx)?;

        let waiter = self.queue.remove(best);
        let dur = self
            .policy
            .cap_duration(waiter.request.priority, waiter.request.duration_secs);
        let grant = self.grant(board_id, waiter.holder, waiter.request.priority, now + dur);
        Some(grant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::board::PowerKind;

    fn board(id: &str, chip: &str, tags: &[&str]) -> Board {
        Board {
            id: BoardId(id.to_string()),
            agent: AgentId("agent-1".to_string()),
            chip: chip.to_string(),
            tags: tags.iter().map(|t| (*t).to_string()).collect(),
            exclusive: true,
            power: PowerKind::None,
            state: BoardState::Idle,
        }
    }

    fn req(select: Constraint, duration_secs: u64, priority: Priority) -> LeaseRequest {
        LeaseRequest {
            select,
            duration_secs,
            priority,
        }
    }

    fn principal(name: &str) -> Principal {
        Principal(name.to_string())
    }

    fn sched() -> Scheduler {
        Scheduler::new(crate::policy::Policy::default())
    }

    fn by_board(id: &str) -> Constraint {
        Constraint::Board(BoardId(id.to_string()))
    }

    #[test]
    fn grants_when_idle() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &["a"]));
        let d = s.request_lease(principal("p1"), req(by_board("b1"), 100, Priority::Ci), 1000);
        match d {
            LeaseDecision::Granted(g) => {
                assert_eq!(g.board, BoardId("b1".into()));
                assert_eq!(g.holder, principal("p1"));
                assert_eq!(g.expires, 1100);
                assert_eq!(g.lease, LeaseId(1));
            }
            LeaseDecision::Queued { .. } => panic!("expected grant"),
        }
        assert!(matches!(
            s.board(&BoardId("b1".into())).unwrap().state,
            BoardState::Leased { .. }
        ));
    }

    #[test]
    fn queues_when_contended() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let _ = s.request_lease(principal("p1"), req(by_board("b1"), 100, Priority::Ci), 0);
        let d2 = s.request_lease(principal("p2"), req(by_board("b1"), 100, Priority::Ci), 0);
        let d3 = s.request_lease(principal("p3"), req(by_board("b1"), 100, Priority::Ci), 0);
        assert_eq!(d2, LeaseDecision::Queued { position: 0 });
        assert_eq!(d3, LeaseDecision::Queued { position: 1 });
    }

    #[test]
    fn release_hands_to_highest_priority_waiter() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match s.request_lease(principal("p1"), req(by_board("b1"), 100, Priority::Ci), 0) {
            LeaseDecision::Granted(g) => g,
            LeaseDecision::Queued { .. } => panic!(),
        };
        // Soak queued first, then Interactive.
        let _ = s.request_lease(principal("soak"), req(by_board("b1"), 100, Priority::Soak), 0);
        let _ = s.request_lease(
            principal("inter"),
            req(by_board("b1"), 100, Priority::Interactive),
            0,
        );
        let promoted = s.release_lease(g.lease, 10).expect("a waiter promoted");
        assert_eq!(promoted.holder, principal("inter"));
    }

    #[test]
    fn fifo_within_class() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match s.request_lease(principal("p1"), req(by_board("b1"), 100, Priority::Ci), 0) {
            LeaseDecision::Granted(g) => g,
            LeaseDecision::Queued { .. } => panic!(),
        };
        let _ = s.request_lease(principal("first"), req(by_board("b1"), 100, Priority::Ci), 0);
        let _ = s.request_lease(principal("second"), req(by_board("b1"), 100, Priority::Ci), 0);
        let promoted = s.release_lease(g.lease, 10).expect("a waiter promoted");
        assert_eq!(promoted.holder, principal("first"));
    }

    #[test]
    fn expiry_frees_and_drains_queue() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match s.request_lease(principal("p1"), req(by_board("b1"), 100, Priority::Ci), 0) {
            LeaseDecision::Granted(g) => g,
            LeaseDecision::Queued { .. } => panic!(),
        };
        let _ = s.request_lease(principal("p2"), req(by_board("b1"), 100, Priority::Ci), 0);
        // Before expiry: nothing happens.
        assert!(s.expire(50).freed.is_empty());
        // After expiry: board freed, then re-granted to the waiter.
        let r = s.expire(200);
        assert_eq!(r.freed.len(), 1);
        assert_eq!(r.freed[0].lease, g.lease);
        assert_eq!(r.freed[0].board, BoardId("b1".into()));
        assert_eq!(r.granted.len(), 1);
        assert_eq!(r.granted[0].holder, principal("p2"));
    }

    #[test]
    fn extend_pushes_expiry() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match s.request_lease(principal("p1"), req(by_board("b1"), 100, Priority::Ci), 0) {
            LeaseDecision::Granted(g) => g,
            LeaseDecision::Queued { .. } => panic!(),
        };
        assert_eq!(g.expires, 100);
        // Extend at now=50; new expiry = 50 + ci cap (3600).
        let new = s.extend_lease(g.lease, 50).expect("extended");
        assert_eq!(new, 50 + 3600);
        if let BoardState::Leased { expires, .. } = &s.board(&BoardId("b1".into())).unwrap().state {
            assert_eq!(*expires, 50 + 3600);
        } else {
            panic!("still leased");
        }
        // An expire before the new expiry does nothing.
        assert!(s.expire(150).freed.is_empty());
        assert!(s.extend_lease(LeaseId(999), 0).is_none());
    }

    #[test]
    fn per_principal_concurrency_cap() {
        let policy = crate::policy::Policy {
            max_concurrent_per_principal: 1,
            ..crate::policy::Policy::default()
        };
        let mut s = Scheduler::new(policy);
        s.upsert_board(board("b1", "nrf52", &[]));
        s.upsert_board(board("b2", "nrf52", &[]));

        let g1 = match s.request_lease(principal("p1"), req(Constraint::Chip("nrf52".into()), 100, Priority::Ci), 0) {
            LeaseDecision::Granted(g) => g,
            LeaseDecision::Queued { .. } => panic!(),
        };
        // Same principal hits the cap even though b2 is idle.
        let d2 = s.request_lease(principal("p1"), req(Constraint::Chip("nrf52".into()), 100, Priority::Ci), 0);
        assert_eq!(d2, LeaseDecision::Queued { position: 0 });
        // Releasing the first lease lets the queued one be promoted.
        let promoted = s.release_lease(g1.lease, 10).expect("promoted");
        assert_eq!(promoted.holder, principal("p1"));
    }

    #[test]
    fn duration_capped_by_policy() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        // Request way over the Ci cap (3600).
        let g = match s.request_lease(principal("p1"), req(by_board("b1"), 1_000_000, Priority::Ci), 100) {
            LeaseDecision::Granted(g) => g,
            LeaseDecision::Queued { .. } => panic!(),
        };
        assert_eq!(g.expires, 100 + 3600);

        // duration 0 => default ttl (900).
        s.upsert_board(board("b2", "nrf52", &[]));
        let g2 = match s.request_lease(principal("p2"), req(by_board("b2"), 0, Priority::Ci), 100) {
            LeaseDecision::Granted(g) => g,
            LeaseDecision::Queued { .. } => panic!(),
        };
        assert_eq!(g2.expires, 100 + 900);
    }

    #[test]
    fn board_constraint_matching() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        // Exact match grants.
        assert!(matches!(
            s.request_lease(principal("p1"), req(by_board("b1"), 100, Priority::Ci), 0),
            LeaseDecision::Granted(_)
        ));
        // Wrong id queues.
        assert!(matches!(
            s.request_lease(principal("p2"), req(by_board("nope"), 100, Priority::Ci), 0),
            LeaseDecision::Queued { .. }
        ));
    }

    #[test]
    fn tag_constraint_matching() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &["nrf52", "bluetooth", "extra"]));
        // Superset match (board has extra tags).
        assert!(matches!(
            s.request_lease(
                principal("p1"),
                req(Constraint::Tags(vec!["nrf52".into(), "bluetooth".into()]), 100, Priority::Ci),
                0
            ),
            LeaseDecision::Granted(_)
        ));
        // Missing-tag negative.
        s.upsert_board(board("b2", "nrf52", &["nrf52"]));
        assert!(matches!(
            s.request_lease(
                principal("p2"),
                req(Constraint::Tags(vec!["nrf52".into(), "wifi".into()]), 100, Priority::Ci),
                0
            ),
            LeaseDecision::Queued { .. }
        ));
    }

    #[test]
    fn chip_constraint_matching() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        // Wrong chip queues.
        assert!(matches!(
            s.request_lease(principal("p1"), req(Constraint::Chip("stm32".into()), 100, Priority::Ci), 0),
            LeaseDecision::Queued { .. }
        ));
        // Right chip grants.
        assert!(matches!(
            s.request_lease(principal("p2"), req(Constraint::Chip("nrf52".into()), 100, Priority::Ci), 0),
            LeaseDecision::Granted(_)
        ));
    }

    #[test]
    fn faulted_and_disabled_never_granted() {
        let mut s = sched();
        let mut b1 = board("b1", "nrf52", &[]);
        b1.state = BoardState::Faulted {
            reason: "smoke".into(),
        };
        s.upsert_board(b1);
        let mut b2 = board("b2", "nrf52", &[]);
        b2.state = BoardState::Disabled;
        s.upsert_board(b2);
        assert!(matches!(
            s.request_lease(principal("p1"), req(Constraint::Chip("nrf52".into()), 100, Priority::Ci), 0),
            LeaseDecision::Queued { .. }
        ));
    }

    #[test]
    fn remove_board_while_leased_drops_lease() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match s.request_lease(principal("p1"), req(by_board("b1"), 100, Priority::Ci), 0) {
            LeaseDecision::Granted(g) => g,
            LeaseDecision::Queued { .. } => panic!(),
        };
        let removed = s.remove_board(&BoardId("b1".into())).expect("removed");
        assert_eq!(removed.id, BoardId("b1".into()));
        // Lease is gone: extend fails.
        assert!(s.extend_lease(g.lease, 0).is_none());
    }

    #[test]
    fn upsert_preserves_live_lease_state() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &["a"]));
        let _ = s.request_lease(principal("p1"), req(by_board("b1"), 100, Priority::Ci), 0);
        // Agent re-reports the board as Idle with updated tags.
        let mut reported = board("b1", "nrf52", &["a", "b"]);
        reported.state = BoardState::Idle;
        s.upsert_board(reported);
        let b = s.board(&BoardId("b1".into())).unwrap();
        assert!(matches!(b.state, BoardState::Leased { .. }));
        assert_eq!(b.tags, vec!["a".to_string(), "b".to_string()]);
    }
}
