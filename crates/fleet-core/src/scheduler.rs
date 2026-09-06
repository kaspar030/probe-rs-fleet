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
//! board and whose holder is under the per-subject concurrency cap, then picks
//! the highest priority, breaking ties by enqueue order (FIFO within a class).
//!
//! **Only one of the four [`LeaseDecision`] outcomes enqueues.** A request is
//! queued precisely when boards the caller may reach *do* match the selector
//! but none is idle — genuine contention, which waiting can resolve. A selector
//! that matches nothing ([`LeaseDecision::NoCandidate`]) and a caller already at
//! its concurrency cap ([`LeaseDecision::AtCap`]) are told so instead: waiting
//! cannot help with either, and queueing them made the scheduler blame the fleet
//! for the caller's own budget. The `position` reported in
//! [`LeaseDecision::Queued`] is the 0-based index among already-queued waiters
//! sharing the same `select` constraint.
//!
//! Each waiter also carries an opaque [`RequesterId`] minted by the caller, so
//! that a queued request can be dropped when the connection that made it goes
//! away ([`Scheduler::remove_waiters`]) and a promotion can be routed back to
//! it ([`Promotion::requester`]).
//!
//! ## Ownership
//!
//! Leases are owned by a [`Subject`] and identified for ownership purposes by
//! its [`SubjectKey`] (`(org, kind, id)` — groups excluded). Extending and
//! releasing a lease require the holder's key; a non-holder gets
//! [`LeaseAuthError::NotHolder`]. The org-admin override
//! of architecture §6.5 lives in the coordinator, which knows the membership
//! table — this crate stays pure.
//!
//! ## Who may reach which board
//!
//! Candidacy takes an [`Access`] (from [`crate::access`]) rather than a bare
//! `OrgId`: architecture §6.5 lets a *grant* admit a board in another org, so
//! "the caller's org" is no longer the whole answer. The tenancy fence did not
//! weaken, it moved: [`Access`] is built solely from the authenticated subject,
//! and a grant only ever covers boards belonging to the granting org. Every
//! candidacy check in this file is `Access::may_use(board) && selector match`,
//! with the org comparison living inside the first half.
//!
//! ## Exclusivity
//!
//! v1 treats every board as single-lease: a board is grantable only while
//! [`BoardState::Idle`]. The `exclusive` flag is honored by this
//! single-lease-per-board rule; non-exclusive *shared* leasing is a future
//! extension and is not implemented here.

use std::collections::BTreeMap;

use fleet_proto::board::{Board, BoardState};
use fleet_proto::ids::{AgentId, BoardRef, LeaseId, Subject, SubjectKey};
use fleet_proto::lease::{Constraint, LeaseRequest, Priority};

use crate::access::{selector_matches, Access};

/// Why a lease operation was refused by the scheduler.
///
/// Both variants are deliberately coarse: the coordinator renders them as one
/// flat message so an unknown lease and someone else's lease are
/// indistinguishable to a caller (otherwise the error is an enumeration
/// oracle across orgs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LeaseAuthError {
    /// No such lease is active.
    #[error("no such lease")]
    Unknown,
    /// The lease exists but the caller does not hold it.
    #[error("caller does not hold this lease")]
    NotHolder,
}

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
    pub board: BoardRef,
    /// The agent that owns the board.
    pub agent: AgentId,
    /// The subject that now holds the lease.
    pub holder: Subject,
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
    pub board: BoardRef,
    /// The agent that owns the board.
    pub agent: AgentId,
    /// The subject that had held the lease.
    pub holder: Subject,
}

/// An opaque, caller-minted handle for "which connection asked".
///
/// The scheduler never interprets it: it only stores it on a [`Waiter`], hands
/// it back on [`Promotion`], and matches on it in
/// [`Scheduler::remove_waiters`]. That keeps this crate free of coordinator
/// types while still letting the coordinator drop a disconnected caller's
/// queued requests and push a promotion to the right socket.
///
/// Deliberately *not* a [`SubjectKey`]: one subject may have several live
/// connections at once (a queued `probe-rs run` and an ad-hoc `ctl list` are
/// the same subject), and closing one must not cancel the other's request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequesterId(pub u64);

impl RequesterId {
    /// A requester that can never be notified.
    ///
    /// For call paths that cannot create a waiter (every non-lease verb) and
    /// for tests that do not care about promotion routing. Using it is a claim
    /// that nothing will ever need to be pushed back to this caller — it is not
    /// "0 is fine".
    pub const DETACHED: Self = Self(0);
}

/// A waiter that has just been promoted onto a freed board, plus the handle of
/// the connection that asked for it.
///
/// The routing handle is kept *beside* [`GrantedLease`] rather than inside it:
/// `GrantedLease` mirrors the wire `LeaseGrant` field-for-field and must not
/// grow a coordinator-only routing field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Promotion {
    /// The connection that queued the request, for the promotion push.
    pub requester: RequesterId,
    /// The grant handed to the promoted waiter.
    pub grant: GrantedLease,
}

/// The outcome of a [`Scheduler::request_lease`] call.
///
/// Four outcomes, of which exactly one — [`LeaseDecision::Queued`] — enqueues.
/// The split exists because "queued" used to mean all three of "the board is
/// busy", "no such board exists" and "you are at your own cap", and a caller
/// cannot act on a message that conflates a fleet problem with its own budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseDecision {
    /// A board was available and has been leased to the requester.
    Granted(GrantedLease),
    /// Boards the caller may reach match the selector, but none is idle:
    /// genuine contention. **The only variant that enqueues** (and even that
    /// one does not, from [`Scheduler::try_lease`]).
    Queued {
        /// 0-based position among waiters sharing the same constraint.
        position: u32,
    },
    /// Nothing in the caller's [`Access`] matches the selector at all, whatever
    /// its [`BoardState`].
    ///
    /// Distinct from [`LeaseDecision::Queued`] because waiting cannot help: no
    /// release will ever produce a board this selector matches. Nothing is
    /// enqueued.
    NoCandidate {
        /// How many boards the caller can reach at all, so the client can say
        /// "`ctl list` shows N boards you can reach" without a second round
        /// trip.
        reachable: u32,
    },
    /// The subject already holds `held` leases against a cap of `cap`, so the
    /// selector was **never evaluated**.
    ///
    /// Checked before candidacy precisely so this message stays honest: the
    /// fleet is not the problem, the caller's own budget is. Nothing is
    /// enqueued.
    AtCap {
        /// Leases the subject currently holds.
        held: u32,
        /// The configured `max_concurrent_per_subject`.
        cap: u32,
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
    /// New grants made by draining the queue onto just-freed boards, each with
    /// the [`RequesterId`] of the connection that queued it.
    pub granted: Vec<Promotion>,
}

/// Bookkeeping for one active lease, indexed by [`LeaseId`].
#[derive(Debug, Clone)]
struct LeaseInfo {
    board: BoardRef,
    holder: Subject,
    priority: Priority,
    expires: u64,
    /// The **granted** hold length in seconds (already `cap_duration`-clamped
    /// at grant time). [`Scheduler::extend_lease`] renews by *this*, not by the
    /// priority-class maximum, so a heartbeat cannot silently promote a short
    /// lease into a cap-length one.
    duration: u64,
}

/// A queued request waiting for a matching board to free up.
#[derive(Debug, Clone)]
struct Waiter {
    holder: Subject,
    /// Which connection asked. Opaque here; see [`RequesterId`].
    requester: RequesterId,
    /// The requester's access as it stood when the request was queued.
    ///
    /// A snapshot, re-checked against `now` at promotion time so an *expired*
    /// grant cannot be promoted onto. A snapshot cannot notice a *revocation*,
    /// so the coordinator's revocation cascade pushes a fresh one in via
    /// [`Scheduler::refresh_waiter_access`].
    access: Access,
    request: LeaseRequest,
    seq: u64,
}

/// In-memory lease scheduler. See the [module docs](self) for the model.
#[derive(Debug, Clone)]
pub struct Scheduler {
    boards: BTreeMap<BoardRef, Board>,
    leases: BTreeMap<LeaseId, LeaseInfo>,
    queue: Vec<Waiter>,
    policy: crate::policy::Policy,
    next_lease_id: u64,
    next_seq: u64,
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

    /// All known boards, ordered by [`BoardRef`] — i.e. lexicographically by
    /// `(org, node, name)`.
    pub fn boards(&self) -> impl Iterator<Item = &Board> {
        self.boards.values()
    }

    /// Look up a single board by id.
    #[must_use]
    pub fn board(&self, id: &BoardRef) -> Option<&Board> {
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
    pub fn remove_board(&mut self, id: &BoardRef) -> Option<Board> {
        let board = self.boards.remove(id)?;
        self.leases.retain(|_, info| info.board != *id);
        Some(board)
    }

    /// Count the leases currently held by the subject identified by `key`.
    ///
    /// Keyed by [`SubjectKey`] rather than the whole [`Subject`] so a group
    /// change does not silently reset a caller's concurrency budget.
    fn active_for(&self, key: &SubjectKey) -> u32 {
        u32::try_from(
            self.leases
                .values()
                .filter(|info| info.holder.key() == *key)
                .count(),
        )
        .unwrap_or(u32::MAX)
    }

    /// The subject holding `lease`, if it is active.
    #[must_use]
    pub fn lease_holder(&self, lease: LeaseId) -> Option<&Subject> {
        self.leases.get(&lease).map(|info| &info.holder)
    }

    /// The board and owning agent a lease is bound to, if it is active.
    ///
    /// Replaces scanning [`Scheduler::boards`] for a matching lease id, which
    /// is both O(n) and easy to get wrong.
    #[must_use]
    pub fn lease_target(&self, lease: LeaseId) -> Option<(&BoardRef, &AgentId)> {
        let info = self.leases.get(&lease)?;
        let board = self.boards.get(&info.board)?;
        Some((&info.board, &board.agent))
    }

    /// Is `board` a grant candidate for a caller with `access`?
    ///
    /// Three conjuncts, and all three are load-bearing: the board must be
    /// **idle**, the caller's [`Access`] must admit it *at `now`* (this is
    /// where tenancy lives, now that the selector match is org-blind), and the
    /// selector must match.
    fn is_candidate(board: &Board, access: &Access, constraint: &Constraint, now: u64) -> bool {
        board.state == BoardState::Idle
            && access.may_use(board, now)
            && selector_matches(board, constraint)
    }

    /// Does *any* board the caller may reach match `constraint`, whatever its
    /// [`BoardState`]?
    ///
    /// Deliberately **not** [`Scheduler::is_candidate`], and the difference is
    /// one conjunct: this drops the `BoardState::Idle` requirement. That single
    /// missing clause is the whole distinction between "every matching board is
    /// busy" (worth queueing for) and "no such board exists for you" (waiting
    /// cannot help) — the two predicates look almost identical at a glance, so
    /// check which one you want before reusing either.
    fn has_candidate(&self, access: &Access, constraint: &Constraint, now: u64) -> bool {
        self.boards
            .values()
            .any(|b| access.may_use(b, now) && selector_matches(b, constraint))
    }

    /// How many boards the caller may reach at all, ignoring both selector and
    /// state. Reported in [`LeaseDecision::NoCandidate`] so the client can say
    /// how much fleet the caller actually sees.
    fn reachable_count(&self, access: &Access, now: u64) -> u32 {
        u32::try_from(self.boards.values().filter(|b| access.may_use(b, now)).count())
            .unwrap_or(u32::MAX)
    }

    /// Find the first idle board the caller may use (by [`BoardRef`] order,
    /// i.e. `(org, node, name)`) matching `constraint`.
    ///
    /// Scoped by [`Access`] rather than by a bare org: an ordinary member sees
    /// only their own org's boards, a grantee additionally sees the boards
    /// their live grants cover, and a subject with neither sees none.
    fn find_idle(&self, access: &Access, constraint: &Constraint, now: u64) -> Option<BoardRef> {
        self.boards
            .values()
            .find(|b| Self::is_candidate(b, access, constraint, now))
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
    ///
    /// `duration` is the already-clamped hold length (see
    /// [`crate::policy::Policy::cap_duration`]); the expiry is `now + duration`
    /// and the duration is remembered so renewals can re-apply it.
    fn grant(
        &mut self,
        board_id: &BoardRef,
        holder: Subject,
        priority: Priority,
        now: u64,
        duration: u64,
    ) -> GrantedLease {
        let expires = now + duration;
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
                duration,
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

    /// Request a lease for `subject`, whose reach is described by `access`,
    /// **queueing on contention**.
    ///
    /// Decision order, and the order is load-bearing:
    ///
    /// 1. at or above `max_concurrent_per_subject` → [`LeaseDecision::AtCap`],
    ///    with the selector deliberately **never evaluated**;
    /// 2. a matching idle board → [`LeaseDecision::Granted`];
    /// 3. nothing the caller may reach matches the selector at all →
    ///    [`LeaseDecision::NoCandidate`];
    /// 4. otherwise the matching boards are all busy →
    ///    [`LeaseDecision::Queued`], and **only here** is a waiter pushed.
    ///
    /// An earlier version queued in cases 1 and 3 too, on the reasoning that an
    /// at-cap request "drains naturally when the subject releases a board".
    /// That was removed on purpose: the caller was handed "board contended;
    /// queued at position N" for three unrelated situations, so it could not
    /// tell a busy fleet from a selector typo from its own concurrency budget
    /// — and in the at-cap case the fleet was blamed for the caller's own
    /// spending. Cases 1 and 3 cannot be resolved by waiting, so they are
    /// reported rather than parked.
    ///
    /// `requester` identifies the *connection* making the request, so a waiter
    /// can later be dropped ([`Scheduler::remove_waiters`]) or notified
    /// ([`Promotion`]). Pass [`RequesterId::DETACHED`] only where nothing will
    /// ever be pushed back.
    ///
    /// Candidate boards are exactly those `access` admits, so a tag/chip/name
    /// constraint can never reach hardware the caller has no path to — not even
    /// to deny-of-service it by holding it, and not even when the caller's own
    /// org has no board of that name. Passing [`Access::none`] therefore always
    /// yields [`LeaseDecision::NoCandidate`] (and never grants), which is the
    /// deny-by-default behaviour.
    ///
    /// The caller is responsible for having resolved `subject` and built
    /// `access` from it; the scheduler only ever compares subjects, it never
    /// invents one and never decides who may reach what.
    pub fn request_lease(
        &mut self,
        subject: Subject,
        requester: RequesterId,
        access: &Access,
        request: LeaseRequest,
        now: u64,
    ) -> LeaseDecision {
        self.decide(subject, requester, access, request, now, true)
    }

    /// Ask the same question as [`Scheduler::request_lease`] but **never**
    /// enqueue.
    ///
    /// For verbs that cannot wait: `ctl delegate` hands a capability token to a
    /// sandbox and returns immediately, so a waiter it left behind would sit in
    /// the queue, eligible for promotion, and hand a board to a caller that
    /// walked away — held by nobody until TTL.
    ///
    /// Expressed as its own entry point rather than a `queue: bool` parameter
    /// on `request_lease`: a bare bool reads as
    /// `request_lease(subject, id, access, req, now, false)` at the call site
    /// and tells a reader nothing, whereas `try_lease` names the intent
    /// wherever it appears. "This verb does not queue" is then a property of
    /// the function you called, not of an argument you have to go and look up.
    ///
    /// Returns [`LeaseDecision::Queued`] with the position the request *would*
    /// have taken, having pushed **nothing** — a `Queued` that did not queue is
    /// surprising, so it is stated here and at the one call site that matters.
    pub fn try_lease(
        &mut self,
        subject: Subject,
        access: &Access,
        request: LeaseRequest,
        now: u64,
    ) -> LeaseDecision {
        self.decide(
            subject,
            RequesterId::DETACHED,
            access,
            request,
            now,
            false,
        )
    }

    /// The shared body of [`Scheduler::request_lease`] and
    /// [`Scheduler::try_lease`]; `enqueue` is the only difference between them.
    fn decide(
        &mut self,
        subject: Subject,
        requester: RequesterId,
        access: &Access,
        request: LeaseRequest,
        now: u64,
        enqueue: bool,
    ) -> LeaseDecision {
        let held = self.active_for(&subject.key());
        let cap = self.policy.max_concurrent_per_subject;
        if held >= cap {
            // Before any candidacy work, so the message can honestly say the
            // selector was never the problem.
            return LeaseDecision::AtCap { held, cap };
        }

        if let Some(board_id) = self.find_idle(access, &request.select, now) {
            let dur = self.policy.cap_duration(request.priority, request.duration_secs);
            let grant = self.grant(&board_id, subject, request.priority, now, dur);
            return LeaseDecision::Granted(grant);
        }

        if !self.has_candidate(access, &request.select, now) {
            return LeaseDecision::NoCandidate {
                reachable: self.reachable_count(access, now),
            };
        }

        let position = self.queue_position(&request.select);
        if enqueue {
            let seq = self.next_seq;
            self.next_seq += 1;
            self.queue.push(Waiter {
                holder: subject,
                requester,
                access: access.clone(),
                request,
                seq,
            });
        }
        LeaseDecision::Queued { position }
    }

    /// Drop every queued request made by `requester`, returning how many were
    /// removed.
    ///
    /// Called when a connection goes away. A waiter whose requester is provably
    /// gone must not stay promotable: promoting it would hand a board to nobody
    /// and leave it held until TTL, which is the same board-held-by-nobody
    /// defect at one remove.
    ///
    /// **Held leases deliberately survive**, and this method cannot touch them:
    /// it only walks the queue. A lease outlives a single connection (a sidecar
    /// may reconnect, and `ctl` opens one connection per command) and is
    /// reclaimed by expiry, not by a socket closing. Queued *requests* are the
    /// opposite: nobody is left to receive the promotion.
    ///
    /// Keyed by [`RequesterId`], **not** [`SubjectKey`]: see `RequesterId`'s
    /// docs for why one subject's second connection must not cancel the first's
    /// request.
    ///
    /// Contrast [`Scheduler::refresh_waiter_access`], which faces a subject
    /// whose *grants* changed and who did nothing wrong; that one refreshes
    /// rather than drops. These are different questions and the answers are
    /// deliberately different.
    pub fn remove_waiters(&mut self, requester: RequesterId) -> usize {
        let before = self.queue.len();
        self.queue.retain(|w| w.requester != requester);
        before - self.queue.len()
    }

    /// The active leases held by `key`, as `(lease, board)` pairs.
    ///
    /// Used by the coordinator's revocation cascade to find what a grantee is
    /// still holding on hardware it just lost access to.
    #[must_use]
    pub fn leases_held_by(&self, key: &SubjectKey) -> Vec<(LeaseId, BoardRef)> {
        self.leases
            .iter()
            .filter(|(_, info)| info.holder.key() == *key)
            .map(|(id, info)| (*id, info.board.clone()))
            .collect()
    }

    /// Replace the [`Access`] snapshot on every queued request from `key`,
    /// returning how many waiters were refreshed.
    ///
    /// This is what closes revoke-while-queued. A queued waiter carries a snapshot
    /// taken when the request was made, which by construction cannot notice a
    /// later revocation, so the revoking caller pushes the new access in.
    ///
    /// # Why refresh rather than drop
    ///
    /// Dropping the subject's queued requests outright would be simpler and is
    /// wrong in two directions:
    ///
    /// * it is **too broad** — a grantee's pending request for a board in
    ///   *their own org* has nothing to do with a grant revoked in someone
    ///   else's, and cancelling it is collateral damage across a tenancy
    ///   boundary. Worse, it is silent: the request simply never gets granted,
    ///   to somebody who did nothing wrong and is not watching;
    /// * it is **too coarse** — a subject covered by two overlapping grants
    ///   keeps its access when one is revoked, and should keep its place in the
    ///   queue with it.
    ///
    /// Refreshing handles both exactly rather than approximately: the waiter
    /// stays, and promotion re-checks the new snapshot, so it is promoted onto
    /// precisely the boards the subject may still use.
    ///
    /// **This is not the same question as [`Scheduler::remove_waiters`]**, and
    /// the two must not be re-conflated. Here the subject is present and
    /// blameless; only what they may reach has changed, so the request is
    /// re-evaluated. There the *caller has disconnected*, so there is nobody
    /// left to hand a board to and the request is dropped. Same queue, opposite
    /// answers, for reasons that do not generalise from one to the other.
    pub fn refresh_waiter_access(&mut self, key: &SubjectKey, access: &Access) -> usize {
        let mut refreshed = 0;
        for waiter in &mut self.queue {
            if waiter.holder.key() == *key {
                waiter.access = access.clone();
                refreshed += 1;
            }
        }
        refreshed
    }

    /// Extend an active lease's expiry to `now +` **the lease's own granted
    /// duration** (still clamped by the priority-class cap).
    ///
    /// The renewal re-derives the hold length from what was actually granted,
    /// not from `max_duration_for(priority)`: a lease granted the 900s policy
    /// default renews for another 900s, never for the 4h Interactive cap. The
    /// cap is re-applied (`cap_duration` is idempotent on an already-capped
    /// value) so tightening policy at runtime takes effect on the next renewal.
    ///
    /// Consequences, both deliberate:
    ///
    /// * A lease may be held indefinitely across many probe-rs invocations as
    ///   long as it is extended before it expires. This is **not new** — the
    ///   previous `now + cap` formula allowed exactly the same thing; the
    ///   change strictly *shortens* each renewal window. Do not "fix" it by
    ///   restoring the cap-based extend.
    /// * A holder that stops heartbeating — killed, crashed, disconnected —
    ///   loses the board after one granted TTL rather than after a full
    ///   priority cap. That is the point (task 3595): a dead sidecar must not
    ///   sit on a board for hours.
    ///
    /// Updates both the lease index and the board's [`BoardState::Leased`]
    /// expiry.
    ///
    /// **Ownership is enforced here**: `by` must be the holder's
    /// [`SubjectKey`]. The "or an org admin" override of architecture §6.5 is
    /// deliberately *not* implemented in this crate — the scheduler has no
    /// membership table and must stay pure. The coordinator checks admin-ness
    /// itself and, when it applies, passes the *holder's* key obtained from
    /// [`Scheduler::lease_holder`].
    ///
    /// # Errors
    ///
    /// [`LeaseAuthError::Unknown`] if no such lease is active,
    /// [`LeaseAuthError::NotHolder`] if `by` does not hold it. On either error
    /// nothing is mutated.
    pub fn extend_lease(
        &mut self,
        lease: LeaseId,
        by: &SubjectKey,
        now: u64,
    ) -> Result<u64, LeaseAuthError> {
        let info = self.leases.get_mut(&lease).ok_or(LeaseAuthError::Unknown)?;
        if info.holder.key() != *by {
            return Err(LeaseAuthError::NotHolder);
        }
        let new_expires = now + self.policy.cap_duration(info.priority, info.duration);
        info.expires = new_expires;
        if let Some(board) = self.boards.get_mut(&info.board) {
            if let BoardState::Leased { expires, .. } = &mut board.state {
                *expires = new_expires;
            }
        }
        Ok(new_expires)
    }

    /// Release an active lease, freeing its board, then promote the
    /// highest-priority eligible waiter onto it (if any).
    ///
    /// Returns `Ok(Some(promotion))` for the promoted waiter — grant plus the
    /// [`RequesterId`] to push it to — or `Ok(None)` if no queued waiter
    /// matched the freed board. Either way the freed board ends up `Idle`
    /// (then possibly re-leased).
    ///
    /// **Ownership is enforced here** exactly as in
    /// [`Scheduler::extend_lease`]: `by` must be the holder's key, and the
    /// admin override is the coordinator's job.
    ///
    /// # Errors
    ///
    /// [`LeaseAuthError::Unknown`] if no such lease is active,
    /// [`LeaseAuthError::NotHolder`] if `by` does not hold it. On either error
    /// nothing is mutated.
    pub fn release_lease(
        &mut self,
        lease: LeaseId,
        by: &SubjectKey,
        now: u64,
    ) -> Result<Option<Promotion>, LeaseAuthError> {
        match self.leases.get(&lease) {
            None => return Err(LeaseAuthError::Unknown),
            Some(info) if info.holder.key() != *by => return Err(LeaseAuthError::NotHolder),
            Some(_) => {}
        }
        let Some(info) = self.leases.remove(&lease) else {
            return Err(LeaseAuthError::Unknown);
        };
        if let Some(board) = self.boards.get_mut(&info.board) {
            board.state = BoardState::Idle;
        }
        Ok(self.promote_one(&info.board, now))
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
    /// A waiter is eligible if its [`Access`] snapshot **still admits the board
    /// at `now`**, its constraint matches, and its holder is under the
    /// concurrency cap. Mutates state and returns the grant, or `None` if the
    /// board is missing/not idle or no waiter matched. The returned
    /// [`Promotion`] carries the waiter's [`RequesterId`] so the caller can
    /// push the grant to the connection that asked for it.
    ///
    /// The access check is what stops a queued waiter from being handed a board
    /// it could not have leased at the front door — the back door onto the same
    /// hardware that [`Scheduler::request_lease`] closes. Re-evaluating at `now`
    /// additionally means an *expired* grant is never promoted onto; a
    /// *revoked* one is handled by [`Scheduler::refresh_waiter_access`], because
    /// a snapshot cannot see a revocation.
    fn promote_one(&mut self, board_id: &BoardRef, now: u64) -> Option<Promotion> {
        let board = self.boards.get(board_id)?;
        if board.state != BoardState::Idle {
            return None;
        }

        let best = self
            .queue
            .iter()
            .enumerate()
            .filter(|(_, w)| {
                Self::is_candidate(board, &w.access, &w.request.select, now)
                    && self.active_for(&w.holder.key()) < self.policy.max_concurrent_per_subject
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
        let grant = self.grant(board_id, waiter.holder, waiter.request.priority, now, dur);
        Some(Promotion {
            requester: waiter.requester,
            grant,
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::board::PowerKind;
    use crate::access::GrantScope;
    use fleet_proto::ids::{BoardName, Group, OrgId, SubjectKind};
    use fleet_proto::token::AllowedOp;

    const ORG: &str = "org1";

    fn org(name: &str) -> OrgId {
        OrgId(name.to_owned())
    }

    fn board_ref(org_name: &str, id: &str) -> BoardRef {
        BoardRef::new(org(org_name), AgentId("agent-1".to_owned()), id)
    }

    fn board(id: &str, chip: &str, tags: &[&str]) -> Board {
        Board {
            id: board_ref(ORG, id),
            agent: AgentId("agent-1".to_string()),
            chip: chip.to_string(),
            model: None,
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

    /// A `User` subject in the default test org.
    fn subject(name: &str) -> Subject {
        subject_in(ORG, name)
    }

    fn subject_in(org_name: &str, name: &str) -> Subject {
        Subject::new(org(org_name), SubjectKind::User, name)
    }

    fn sched() -> Scheduler {
        Scheduler::new(crate::policy::Policy::default())
    }

    /// Request a lease as an ordinary member of the subject's own org, with no
    /// grants — the access every test that predates sharing implies.
    ///
    /// Uses [`RequesterId::DETACHED`]: these tests never route a promotion back
    /// to a connection. The ones that care about requester identity call
    /// `request_lease` directly with a minted id.
    fn request_as(
        s: &mut Scheduler,
        subject: Subject,
        request: LeaseRequest,
        now: u64,
    ) -> LeaseDecision {
        let access = Access::own_org(subject.org.clone());
        s.request_lease(subject, RequesterId::DETACHED, &access, request, now)
    }

    fn by_id(id: &str) -> Constraint {
        Constraint::Id(BoardName(id.to_string()))
    }

    /// A board of a declared model.
    fn modelled_board(id: &str, model: &str) -> Board {
        Board {
            model: Some(model.to_string()),
            ..board(id, "nRF52840_xxAA", &[])
        }
    }

    /// The point of `board=<model>`: a *generic* selector beats contention.
    /// Two boards of the same model, one already leased — the model selector
    /// hands out the other, where `id=` would have queued.
    #[test]
    fn a_model_selector_routes_around_a_leased_board() {
        let mut s = sched();
        s.upsert_board(modelled_board("dk-1", "nrf52840dk"));
        s.upsert_board(modelled_board("dk-2", "nrf52840dk"));
        s.upsert_board(modelled_board("pico-1", "rpi-pico"));

        let model = Constraint::Model("nrf52840dk".to_owned());
        let first = match request_as(&mut s, subject("p1"), req(model.clone(), 100, Priority::Ci), 0)
        {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        let second =
            match request_as(&mut s, subject("p2"), req(model.clone(), 100, Priority::Ci), 0) {
                LeaseDecision::Granted(g) => g,
                other => panic!(
                    "the second board of the model must be granted, got {other:?}"
                ),
            };
        assert_ne!(first.board, second.board, "two requests, two boards");
        for b in [&first.board, &second.board] {
            assert_ne!(b.name, "pico-1", "another model must never be granted");
        }

        // Both boards of the model are now held: the third request queues
        // rather than spilling onto the other model.
        match request_as(&mut s, subject("p3"), req(model, 100, Priority::Ci), 0) {
            LeaseDecision::Queued { .. } => {}
            other => {
                panic!("both boards of the model are held; expected a queue slip, got {other:?}")
            }
        }
    }

    /// A board that declares no model (every adopted board) is unreachable by
    /// `board=` — the documented trade, identical to `chip=`.
    #[test]
    fn a_board_without_a_model_is_never_granted_by_a_model_selector() {
        let mut s = sched();
        s.upsert_board(board("adopted-1", "", &["auto"]));
        let d = request_as(
            &mut s,
            subject("p1"),
            req(
                Constraint::Model("nrf52840dk".to_owned()),
                100,
                Priority::Ci,
            ),
            0,
        );
        assert!(
            matches!(d, LeaseDecision::NoCandidate { .. }),
            "a modelless board must not satisfy board=, got {d:?}"
        );
    }

    #[test]
    fn grants_when_idle() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &["a"]));
        let d = request_as(&mut s, subject("p1"), req(by_id("b1"), 100, Priority::Ci), 1000);
        match d {
            LeaseDecision::Granted(g) => {
                assert_eq!(g.board, board_ref(ORG, "b1"));
                assert_eq!(g.holder, subject("p1"));
                assert_eq!(g.expires, 1100);
                assert_eq!(g.lease, LeaseId(1));
            }
            other => panic!("expected a grant, got {other:?}"),
        }
        assert!(matches!(
            s.board(&board_ref(ORG, "b1")).unwrap().state,
            BoardState::Leased { .. }
        ));
    }

    /// Genuine contention still queues, and still enqueues: the regression
    /// guard on the decision split not over-reaching.
    #[test]
    fn queues_when_contended() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let _ = request_as(&mut s, subject("p1"), req(by_id("b1"), 100, Priority::Ci), 0);
        let d2 = request_as(&mut s, subject("p2"), req(by_id("b1"), 100, Priority::Ci), 0);
        let d3 = request_as(&mut s, subject("p3"), req(by_id("b1"), 100, Priority::Ci), 0);
        assert_eq!(d2, LeaseDecision::Queued { position: 0 });
        assert_eq!(d3, LeaseDecision::Queued { position: 1 });
        assert_eq!(s.queue.len(), 2, "contention is the case that enqueues");
    }

    /// A selector that matches nothing is `NoCandidate`, **and nothing is
    /// queued**: waiting for a board that does not exist is a request that can
    /// only ever time out.
    #[test]
    fn a_selector_matching_nothing_is_no_candidate_and_does_not_enqueue() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        s.upsert_board(board("b2", "nrf52", &[]));
        let d = request_as(
            &mut s,
            subject("p1"),
            req(by_id("does-not-exist"), 100, Priority::Ci),
            0,
        );
        assert_eq!(d, LeaseDecision::NoCandidate { reachable: 2 });
        assert!(s.queue.is_empty());
    }

    /// A board that exists but is *busy* is contention, not `NoCandidate` —
    /// the conjunct `has_candidate` deliberately drops.
    #[test]
    fn a_busy_matching_board_is_contention_not_no_candidate() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let _ = request_as(&mut s, subject("p1"), req(by_id("b1"), 100, Priority::Ci), 0);
        let d = request_as(&mut s, subject("p2"), req(by_id("b1"), 100, Priority::Ci), 0);
        assert_eq!(d, LeaseDecision::Queued { position: 0 });
    }

    /// At-cap is decided **before** the selector is looked at, and this pins
    /// that order: the request below has a selector that matches nothing, so a
    /// scheduler that evaluated candidacy first would answer `NoCandidate`.
    /// `AtCap` is the honest answer — the caller's budget is the binding
    /// constraint, and fixing the selector would not help.
    #[test]
    fn at_cap_is_decided_before_the_selector_is_evaluated() {
        let policy = crate::policy::Policy {
            max_concurrent_per_subject: 1,
            ..crate::policy::Policy::default()
        };
        let mut s = Scheduler::new(policy);
        s.upsert_board(board("b1", "nrf52", &[]));
        let LeaseDecision::Granted(_) =
            request_as(&mut s, subject("p1"), req(by_id("b1"), 100, Priority::Ci), 0)
        else {
            panic!("expected a grant");
        };
        let d = request_as(
            &mut s,
            subject("p1"),
            req(by_id("no-such-board"), 100, Priority::Ci),
            0,
        );
        assert_eq!(d, LeaseDecision::AtCap { held: 1, cap: 1 });
        assert!(s.queue.is_empty(), "an at-cap request must not enqueue");
    }

    /// `try_lease` answers the same question and pushes nothing — the #452 fix
    /// at the scheduler level.
    #[test]
    fn try_lease_reports_contention_without_enqueueing() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let _ = request_as(&mut s, subject("p1"), req(by_id("b1"), 100, Priority::Ci), 0);
        let before = s.queue.len();
        let access = Access::own_org(org(ORG));
        let d = s.try_lease(
            subject("p2"),
            &access,
            req(by_id("b1"), 100, Priority::Ci),
            0,
        );
        assert_eq!(d, LeaseDecision::Queued { position: 0 });
        assert_eq!(s.queue.len(), before, "try_lease must never enqueue");

        // It still grants when it can.
        s.upsert_board(board("b2", "nrf52", &[]));
        let d = s.try_lease(
            subject("p2"),
            &access,
            req(by_id("b2"), 100, Priority::Ci),
            0,
        );
        assert!(matches!(d, LeaseDecision::Granted(_)));
    }

    /// `remove_waiters` drops exactly one connection's queued requests.
    ///
    /// The second half is the case that motivated keying on `RequesterId`
    /// rather than `SubjectKey`: the *same subject* on another connection (a
    /// developer running `ctl list` while `probe-rs run` waits) keeps its
    /// waiter.
    #[test]
    fn remove_waiters_drops_one_connections_requests_only() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let access = Access::own_org(org(ORG));
        let _ = request_as(&mut s, subject("holder"), req(by_id("b1"), 100, Priority::Ci), 0);

        let conn_a = RequesterId(1);
        let conn_b = RequesterId(2);
        // Two connections of the same subject, plus an unrelated one.
        let _ = s.request_lease(subject("dev"), conn_a, &access, req(by_id("b1"), 100, Priority::Ci), 0);
        let _ = s.request_lease(subject("dev"), conn_b, &access, req(by_id("b1"), 100, Priority::Ci), 0);
        let _ = s.request_lease(subject("other"), RequesterId(3), &access, req(by_id("b1"), 100, Priority::Ci), 0);
        assert_eq!(s.queue.len(), 3);

        assert_eq!(s.remove_waiters(conn_a), 1);
        assert_eq!(s.queue.len(), 2);
        assert!(
            s.queue.iter().any(|w| w.requester == conn_b),
            "the same subject's other connection must keep its waiter"
        );
        // Idempotent: a second disconnect notification removes nothing.
        assert_eq!(s.remove_waiters(conn_a), 0);
    }

    /// A *held* lease survives its requester going away. Deliberate v1
    /// behaviour: a lease outlives one connection and is reclaimed by expiry.
    #[test]
    fn remove_waiters_leaves_a_held_lease_alone() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let access = Access::own_org(org(ORG));
        let conn = RequesterId(7);
        let LeaseDecision::Granted(g) = s.request_lease(
            subject("p1"),
            conn,
            &access,
            req(by_id("b1"), 100, Priority::Ci),
            0,
        ) else {
            panic!("expected a grant");
        };
        assert_eq!(s.remove_waiters(conn), 0);
        assert_eq!(s.lease_holder(g.lease), Some(&subject("p1")));
        assert!(matches!(
            s.board(&board_ref(ORG, "b1")).unwrap().state,
            BoardState::Leased { .. }
        ));
        // ...and it still goes away on its own, at TTL.
        assert_eq!(s.expire(g.expires).freed.len(), 1);
    }

    /// After a disconnected waiter is dropped, the freed board goes to the
    /// *next* waiter rather than to the ghost (#381, at the scheduler level).
    #[test]
    fn after_removing_a_waiter_the_board_goes_to_the_next_one() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let access = Access::own_org(org(ORG));
        let LeaseDecision::Granted(g) = request_as(
            &mut s,
            subject("holder"),
            req(by_id("b1"), 100, Priority::Ci),
            0,
        ) else {
            panic!("expected a grant");
        };
        let ghost = RequesterId(1);
        // The ghost queues first and at a higher priority, so it would win.
        let _ = s.request_lease(subject("ghost"), ghost, &access, req(by_id("b1"), 100, Priority::Interactive), 0);
        let _ = s.request_lease(subject("next"), RequesterId(2), &access, req(by_id("b1"), 100, Priority::Ci), 0);

        assert_eq!(s.remove_waiters(ghost), 1);
        let promoted = s
            .release_lease(g.lease, &subject("holder").key(), 10)
            .expect("holder may release")
            .expect("the surviving waiter is promoted");
        assert_eq!(promoted.grant.holder, subject("next"));
        assert_eq!(promoted.requester, RequesterId(2));
    }

    #[test]
    fn release_hands_to_highest_priority_waiter() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match request_as(&mut s, subject("p1"), req(by_id("b1"), 100, Priority::Ci), 0) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        // Soak queued first, then Interactive.
        let _ = request_as(&mut s, subject("soak"), req(by_id("b1"), 100, Priority::Soak), 0);
        let _ = request_as(&mut s, 
            subject("inter"),
            req(by_id("b1"), 100, Priority::Interactive),
            0,
        );
        let promoted = s
            .release_lease(g.lease, &subject("p1").key(), 10)
            .expect("holder may release")
            .expect("a waiter promoted");
        assert_eq!(promoted.grant.holder, subject("inter"));
    }

    #[test]
    fn fifo_within_class() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match request_as(&mut s, subject("p1"), req(by_id("b1"), 100, Priority::Ci), 0) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        let _ = request_as(&mut s, subject("first"), req(by_id("b1"), 100, Priority::Ci), 0);
        let _ = request_as(&mut s, subject("second"), req(by_id("b1"), 100, Priority::Ci), 0);
        let promoted = s
            .release_lease(g.lease, &subject("p1").key(), 10)
            .expect("holder may release")
            .expect("a waiter promoted");
        assert_eq!(promoted.grant.holder, subject("first"));
    }

    #[test]
    fn expiry_frees_and_drains_queue() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match request_as(&mut s, subject("p1"), req(by_id("b1"), 100, Priority::Ci), 0) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        let _ = request_as(&mut s, subject("p2"), req(by_id("b1"), 100, Priority::Ci), 0);
        // Before expiry: nothing happens.
        assert!(s.expire(50).freed.is_empty());
        // After expiry: board freed, then re-granted to the waiter.
        let r = s.expire(200);
        assert_eq!(r.freed.len(), 1);
        assert_eq!(r.freed[0].lease, g.lease);
        assert_eq!(r.freed[0].board, board_ref(ORG, "b1"));
        assert_eq!(r.granted.len(), 1);
        assert_eq!(r.granted[0].grant.holder, subject("p2"));
    }

    #[test]
    fn extend_pushes_expiry() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match request_as(&mut s, subject("p1"), req(by_id("b1"), 100, Priority::Ci), 0) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        assert_eq!(g.expires, 100);
        // Extend at now=50; the new expiry re-applies the lease's *own* granted
        // duration (100s), not the Ci class cap.
        let new = s
            .extend_lease(g.lease, &subject("p1").key(), 50)
            .expect("extended");
        assert_eq!(new, 50 + 100);
        if let BoardState::Leased { expires, .. } = &s.board(&board_ref(ORG, "b1")).unwrap().state {
            assert_eq!(*expires, 50 + 100);
        } else {
            panic!("still leased");
        }
        // An expire before the new expiry does nothing.
        assert!(s.expire(100).freed.is_empty());
        assert_eq!(
            s.extend_lease(LeaseId(999), &subject("p1").key(), 0),
            Err(LeaseAuthError::Unknown)
        );
    }

    /// Regression for task 3595: a heartbeat must renew a lease by the duration
    /// it was *granted*, never by the priority-class maximum. Renewing by the
    /// cap would turn the sidecar's 900s policy-default lease into a 4h hold on
    /// its first heartbeat — strictly worse than the hardcoded 3600s the task
    /// removes.
    #[test]
    fn extend_reapplies_the_granted_duration_not_the_cap() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match request_as(
            &mut s,
            subject("p1"),
            req(by_id("b1"), 900, Priority::Interactive),
            0,
        ) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        assert_eq!(g.expires, 900);
        let new = s
            .extend_lease(g.lease, &subject("p1").key(), 500)
            .expect("extended");
        assert_eq!(new, 500 + 900);
        let cap = crate::policy::Policy::default().max_duration_interactive;
        assert_ne!(new, 500 + cap, "renewal must not promote to the class cap");
    }

    /// The priority-class cap still bounds every renewal: a CI workload that
    /// asks for four hours is clamped to `max_duration_ci` at grant time, and
    /// the clamp survives extension.
    #[test]
    fn extend_stays_clamped_by_the_priority_cap() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match request_as(
            &mut s,
            subject("p1"),
            req(by_id("b1"), 4 * 60 * 60, Priority::Ci),
            0,
        ) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        let ci_cap = crate::policy::Policy::default().max_duration_ci;
        assert_eq!(g.expires, ci_cap);
        assert_eq!(
            s.extend_lease(g.lease, &subject("p1").key(), 1_000),
            Ok(1_000 + ci_cap)
        );
    }

    /// `duration_secs: 0` means "whatever the operator's policy says" — the
    /// shape the sidecar now requests. Both the grant and every renewal use
    /// `default_ttl_secs`.
    #[test]
    fn a_policy_default_lease_extends_by_the_policy_default() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match request_as(
            &mut s,
            subject("p1"),
            req(by_id("b1"), 0, Priority::Interactive),
            0,
        ) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        let ttl = crate::policy::Policy::default().default_ttl_secs;
        assert_eq!(g.expires, ttl);
        assert_eq!(
            s.extend_lease(g.lease, &subject("p1").key(), 700),
            Ok(700 + ttl)
        );
    }

    /// A subject that does not hold the lease cannot extend it, and the
    /// expiry is left untouched.
    #[test]
    fn other_subject_cannot_extend() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match request_as(&mut s, subject("alice"), req(by_id("b1"), 100, Priority::Ci), 0) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        assert_eq!(
            s.extend_lease(g.lease, &subject("bob").key(), 50),
            Err(LeaseAuthError::NotHolder)
        );
        // Expiry unchanged, on both the lease index and the board.
        assert_eq!(s.extend_lease(g.lease, &subject("alice").key(), 0), Ok(100));
        let BoardState::Leased { expires, by, .. } = &s.board(&board_ref(ORG, "b1")).unwrap().state
        else {
            panic!("still leased");
        };
        assert_eq!(*expires, 100);
        assert_eq!(by, &subject("alice"));
    }

    /// A subject that does not hold the lease cannot release it, and the board
    /// stays leased to its actual holder.
    #[test]
    fn other_subject_cannot_release() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match request_as(&mut s, subject("alice"), req(by_id("b1"), 100, Priority::Ci), 0) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        assert_eq!(
            s.release_lease(g.lease, &subject("bob").key(), 10),
            Err(LeaseAuthError::NotHolder)
        );
        let BoardState::Leased { by, lease, .. } = &s.board(&board_ref(ORG, "b1")).unwrap().state
        else {
            panic!("board must still be leased");
        };
        assert_eq!(*lease, g.lease);
        assert_eq!(by, &subject("alice"));
        assert_eq!(s.lease_holder(g.lease), Some(&subject("alice")));
    }

    /// Tenant isolation: the same id in a different org is a different subject
    /// and may not touch the lease. Without this the whole model is decorative.
    #[test]
    fn same_id_different_org_is_a_different_subject() {
        let mut s = sched();
        // The board belongs to org-b, so alice@org-b legitimately holds it.
        let mut b = board("b1", "nrf52", &[]);
        b.id = board_ref("org-b", "b1");
        s.upsert_board(b);
        let g = match request_as(&mut s, 
            subject_in("org-b", "alice"),
            req(by_id("b1"), 100, Priority::Ci),
            0,
        ) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        // Same id, different org: still someone else.
        let intruder = subject_in("org-a", "alice").key();
        assert_eq!(
            s.extend_lease(g.lease, &intruder, 50),
            Err(LeaseAuthError::NotHolder)
        );
        assert_eq!(
            s.release_lease(g.lease, &intruder, 50),
            Err(LeaseAuthError::NotHolder)
        );
    }

    /// Groups are not part of a subject's identity: gaining a group must not
    /// orphan the lease it holds.
    #[test]
    fn groups_do_not_affect_holder_identity() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match request_as(&mut s, subject("alice"), req(by_id("b1"), 100, Priority::Ci), 0) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        let mut regrouped = subject("alice");
        regrouped.groups.push(Group("firmware".to_owned()));
        assert_ne!(regrouped, subject("alice"));
        assert_eq!(s.extend_lease(g.lease, &regrouped.key(), 50), Ok(50 + 100));
    }

    #[test]
    fn concurrency_cap_is_per_subject_key() {
        let policy = crate::policy::Policy {
            max_concurrent_per_subject: 1,
            ..crate::policy::Policy::default()
        };
        let mut s = Scheduler::new(policy);
        s.upsert_board(board("b1", "nrf52", &[]));
        s.upsert_board(board("b2", "nrf52", &[]));
        // A board of the *other* org, so the cross-org assertion below tests the
        // concurrency cap rather than accidentally testing tenant isolation.
        let mut other = board("b3", "nrf52", &[]);
        other.id = board_ref("other-org", "b3");
        s.upsert_board(other);

        let g1 = match request_as(&mut s, 
            subject("p1"),
            req(Constraint::Chip("nrf52".into()), 100, Priority::Ci),
            0,
        ) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        // Same subject hits the cap even though b2 is idle. This is now
        // `AtCap`, **not** `Queued { position: 0 }`: a deliberate behaviour
        // change. The old answer parked the request in the queue and told the
        // caller the board was contended, which blamed the fleet for the
        // caller's own concurrency budget — and b2 was idle the whole time.
        let d2 = request_as(&mut s, 
            subject("p1"),
            req(Constraint::Chip("nrf52".into()), 100, Priority::Ci),
            0,
        );
        assert_eq!(d2, LeaseDecision::AtCap { held: 1, cap: 1 });
        assert_eq!(s.queue.len(), 0, "an at-cap request must not enqueue");
        // A same-named subject in another org is NOT capped by p1's lease (and
        // is served from its own org's board).
        let d3 = request_as(&mut s, 
            subject_in("other-org", "p1"),
            req(Constraint::Chip("nrf52".into()), 100, Priority::Ci),
            0,
        );
        assert!(matches!(d3, LeaseDecision::Granted(_)));
        // Releasing the first lease frees the budget, so the same subject can
        // ask again and is served immediately. (Nothing is promoted: the
        // at-cap request was refused, not parked.)
        let promoted = s
            .release_lease(g1.lease, &subject("p1").key(), 10)
            .expect("holder may release");
        assert!(promoted.is_none(), "nothing was ever queued");
        let d4 = request_as(&mut s, 
            subject("p1"),
            req(Constraint::Chip("nrf52".into()), 100, Priority::Ci),
            10,
        );
        assert!(matches!(d4, LeaseDecision::Granted(_)));
    }

    #[test]
    fn duration_capped_by_policy() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        // Request way over the Ci cap (3600).
        let g = match request_as(&mut s, 
            subject("p1"),
            req(by_id("b1"), 1_000_000, Priority::Ci),
            100,
        ) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        assert_eq!(g.expires, 100 + 3600);

        // duration 0 => default ttl (900).
        s.upsert_board(board("b2", "nrf52", &[]));
        let g2 = match request_as(&mut s, subject("p2"), req(by_id("b2"), 0, Priority::Ci), 100) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        assert_eq!(g2.expires, 100 + 900);
    }

    #[test]
    fn board_constraint_matching() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        // Exact match grants.
        assert!(matches!(
            request_as(&mut s, subject("p1"), req(by_id("b1"), 100, Priority::Ci), 0),
            LeaseDecision::Granted(_)
        ));
        // A selector that matches no board at all is `NoCandidate`, not a
        // queue slip: no release can ever produce a board called "nope".
        assert!(matches!(
            request_as(&mut s, subject("p2"), req(by_id("nope"), 100, Priority::Ci), 0),
            LeaseDecision::NoCandidate { reachable: 1 }
        ));
    }

    #[test]
    fn tag_constraint_matching() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &["nrf52", "bluetooth", "extra"]));
        // Superset match (board has extra tags).
        assert!(matches!(
            request_as(&mut s, 
                subject("p1"),
                req(Constraint::Tags(vec!["nrf52".into(), "bluetooth".into()]), 100, Priority::Ci),
                0
            ),
            LeaseDecision::Granted(_)
        ));
        // Missing-tag negative: no board carries both tags, in any state.
        s.upsert_board(board("b2", "nrf52", &["nrf52"]));
        assert!(matches!(
            request_as(&mut s, 
                subject("p2"),
                req(Constraint::Tags(vec!["nrf52".into(), "wifi".into()]), 100, Priority::Ci),
                0
            ),
            LeaseDecision::NoCandidate { .. }
        ));
    }

    #[test]
    fn chip_constraint_matching() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        // Wrong chip: no such board exists for this caller.
        assert!(matches!(
            request_as(&mut s, subject("p1"), req(Constraint::Chip("stm32".into()), 100, Priority::Ci), 0),
            LeaseDecision::NoCandidate { reachable: 1 }
        ));
        // Right chip grants.
        assert!(matches!(
            request_as(&mut s, subject("p2"), req(Constraint::Chip("nrf52".into()), 100, Priority::Ci), 0),
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
            request_as(&mut s, subject("p1"), req(Constraint::Chip("nrf52".into()), 100, Priority::Ci), 0),
            LeaseDecision::Queued { .. }
        ));
    }

    #[test]
    fn remove_board_while_leased_drops_lease() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match request_as(&mut s, subject("p1"), req(by_id("b1"), 100, Priority::Ci), 0) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        let removed = s.remove_board(&board_ref(ORG, "b1")).expect("removed");
        assert_eq!(removed.id, board_ref(ORG, "b1"));
        // Lease is gone: extend fails as unknown.
        assert_eq!(
            s.extend_lease(g.lease, &subject("p1").key(), 0),
            Err(LeaseAuthError::Unknown)
        );
    }

    #[test]
    fn upsert_preserves_live_lease_state() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &["a"]));
        let _ = request_as(&mut s, subject("p1"), req(by_id("b1"), 100, Priority::Ci), 0);
        // Agent re-reports the board as Idle with updated tags.
        let mut reported = board("b1", "nrf52", &["a", "b"]);
        reported.state = BoardState::Idle;
        s.upsert_board(reported);
        let b = s.board(&board_ref(ORG, "b1")).unwrap();
        assert!(matches!(b.state, BoardState::Leased { .. }));
        assert_eq!(b.tags, vec!["a".to_string(), "b".to_string()]);
    }

    /// Two orgs may each host a board called `nrf52840-dk`; they are distinct
    /// boards and a constraint resolves within one org's board set only.
    #[test]
    fn same_board_name_in_two_orgs_are_distinct_boards() {
        let mut s = sched();
        let mut a = board("dk", "nrf52", &[]);
        a.id = board_ref("org-a", "dk");
        let mut b = board("dk", "nrf52", &[]);
        b.id = board_ref("org-b", "dk");
        s.upsert_board(a);
        s.upsert_board(b);
        assert_eq!(s.boards().count(), 2);
        assert!(s.board(&board_ref("org-a", "dk")).is_some());
        assert!(s.board(&board_ref("org-b", "dk")).is_some());
    }

    #[test]
    fn lease_target_resolves_board_and_agent() {
        let mut s = sched();
        s.upsert_board(board("b1", "nrf52", &[]));
        let g = match request_as(&mut s, subject("p1"), req(by_id("b1"), 100, Priority::Ci), 0) {
            LeaseDecision::Granted(g) => g,
            other => panic!("expected a grant, got {other:?}"),
        };
        let (board_id, agent) = s.lease_target(g.lease).expect("active lease");
        assert_eq!(board_id, &board_ref(ORG, "b1"));
        assert_eq!(agent, &AgentId("agent-1".to_owned()));
        assert!(s.lease_target(LeaseId(999)).is_none());
    }

    /// B1 regression: a chip/tag constraint must not reach across orgs. org-A
    /// owns the only nrf52 board; an org-B subject asking for that chip must be
    /// refused, and org-A's board must stay Idle.
    #[test]
    fn cross_org_chip_constraint_does_not_grant() {
        let mut s = sched();
        let mut b = board("b1", "nrf52", &[]);
        b.id = board_ref("org-a", "b1");
        s.upsert_board(b);

        let d = request_as(&mut s, 
            subject_in("org-b", "mallory"),
            req(Constraint::Chip("nrf52".into()), 100, Priority::Ci),
            0,
        );
        // `reachable: 0` — org-B's subject can see none of the fleet, which is
        // the tenancy fence stated as a number.
        assert_eq!(d, LeaseDecision::NoCandidate { reachable: 0 });
        assert_eq!(
            s.board(&board_ref("org-a", "b1")).unwrap().state,
            BoardState::Idle,
            "another org's board must not be leased out"
        );
    }

    /// The same hole via a board-name constraint: org-B has no `b1`, so a bare
    /// name must not resolve onto org-A's `b1`.
    #[test]
    fn cross_org_board_name_constraint_does_not_grant() {
        let mut s = sched();
        let mut b = board("b1", "nrf52", &[]);
        b.id = board_ref("org-a", "b1");
        s.upsert_board(b);

        let d = request_as(&mut s, 
            subject_in("org-b", "mallory"),
            req(by_id("b1"), 100, Priority::Ci),
            0,
        );
        assert_eq!(d, LeaseDecision::NoCandidate { reachable: 0 });
        assert_eq!(
            s.board(&board_ref("org-a", "b1")).unwrap().state,
            BoardState::Idle
        );
    }

    /// B1 regression, promotion path: a queued cross-org waiter must never be
    /// promoted onto a board freed by release or by expiry.
    #[test]
    fn cross_org_waiter_is_not_promoted() {
        let mut s = sched();
        let mut b = board("b1", "nrf52", &[]);
        b.id = board_ref("org-a", "b1");
        s.upsert_board(b);

        let alice = subject_in("org-a", "alice");
        let LeaseDecision::Granted(g) =
            request_as(&mut s, alice.clone(), req(by_id("b1"), 100, Priority::Ci), 0)
        else {
            panic!("expected grant");
        };
        // org-B queues behind it, at the highest priority so it would win any
        // fair contest that did not consider the org.
        let d = request_as(&mut s, 
            subject_in("org-b", "mallory"),
            req(by_id("b1"), 100, Priority::Interactive),
            0,
        );
        // Nothing org-B may reach matches, so there is no waiter to promote in
        // the first place — a stronger property than "queued but skipped".
        assert_eq!(d, LeaseDecision::NoCandidate { reachable: 0 });

        // Release: the board must come back Idle, with nobody promoted.
        let promoted = s
            .release_lease(g.lease, &alice.key(), 10)
            .expect("holder may release");
        assert!(
            promoted.is_none(),
            "a cross-org waiter must not be promoted onto a freed board"
        );
        assert_eq!(
            s.board(&board_ref("org-a", "b1")).unwrap().state,
            BoardState::Idle
        );

        // Expiry takes the same path; re-lease then let it lapse.
        let LeaseDecision::Granted(g2) =
            request_as(&mut s, alice.clone(), req(by_id("b1"), 100, Priority::Ci), 20)
        else {
            panic!("expected grant");
        };
        let result = s.expire(g2.expires + 1);
        assert_eq!(result.freed.len(), 1);
        assert!(
            result.granted.is_empty(),
            "expiry must not promote a cross-org waiter either"
        );
        assert_eq!(
            s.board(&board_ref("org-a", "b1")).unwrap().state,
            BoardState::Idle
        );
    }

    /// The legitimate case still works: a same-org waiter is promoted normally.
    #[test]
    fn same_org_waiter_is_still_promoted() {
        let mut s = sched();
        let mut b = board("b1", "nrf52", &[]);
        b.id = board_ref("org-a", "b1");
        s.upsert_board(b);

        let alice = subject_in("org-a", "alice");
        let bob = subject_in("org-a", "bob");
        let LeaseDecision::Granted(g) =
            request_as(&mut s, alice.clone(), req(by_id("b1"), 100, Priority::Ci), 0)
        else {
            panic!("expected grant");
        };
        let _ = request_as(&mut s, bob.clone(), req(by_id("b1"), 100, Priority::Ci), 0);
        let promoted = s
            .release_lease(g.lease, &alice.key(), 10)
            .expect("holder may release")
            .expect("same-org waiter promoted");
        assert_eq!(promoted.grant.holder, bob);
    }

    // ---------------------------------------------------------------------
    // Sharing (architecture §6.5): a grant is the *only* thing that admits a
    // board in another org, and it must behave identically at the front door
    // (request) and the back one (promotion).
    // ---------------------------------------------------------------------

    /// An access with one live grant from `org_name` covering `tag`.
    fn granted(subject_org: &str, org_name: &str, tag: &str, expires: Option<u64>) -> Access {
        Access {
            own_org: Some(org(subject_org)),
            grants: vec![GrantScope {
                id: "g1".to_owned(),
                org: org(org_name),
                selector: Constraint::Tags(vec![tag.to_owned()]),
                ops: vec![AllowedOp::Attach],
                expires,
            }],
        }
    }

    fn tagged_board_in(org_name: &str, name: &str, tag: &str) -> Board {
        let mut b = board(name, "nrf52", &[tag]);
        b.id = board_ref(org_name, name);
        b
    }

    #[test]
    fn a_grantee_is_granted_a_board_in_another_org() {
        let mut s = sched();
        s.upsert_board(tagged_board_in("org-a", "b1", "nrf52"));
        let bob = subject_in("org-b", "bob");

        let access = granted("org-b", "org-a", "nrf52", None);
        let d = s.request_lease(
            bob.clone(),
            RequesterId::DETACHED,
            &access,
            req(Constraint::Tags(vec!["nrf52".to_owned()]), 100, Priority::Ci),
            0,
        );
        let LeaseDecision::Granted(g) = d else {
            panic!("a grantee must reach the granted board");
        };
        assert_eq!(g.board, board_ref("org-a", "b1"));
        assert_eq!(g.holder, bob);
    }

    /// The same request without the grant is still refused — the fence moved
    /// into `Access`, it did not disappear.
    #[test]
    fn the_same_request_without_a_grant_is_still_denied() {
        let mut s = sched();
        s.upsert_board(tagged_board_in("org-a", "b1", "nrf52"));
        let d = request_as(
            &mut s,
            subject_in("org-b", "bob"),
            req(Constraint::Tags(vec!["nrf52".to_owned()]), 100, Priority::Ci),
            0,
        );
        assert_eq!(d, LeaseDecision::NoCandidate { reachable: 0 });
        assert_eq!(
            s.board(&board_ref("org-a", "b1")).unwrap().state,
            BoardState::Idle
        );
    }

    #[test]
    fn a_queued_grantee_is_promoted_onto_the_granted_board() {
        let mut s = sched();
        s.upsert_board(tagged_board_in("org-a", "b1", "nrf52"));
        let alice = subject_in("org-a", "alice");
        let bob = subject_in("org-b", "bob");

        let LeaseDecision::Granted(g) =
            request_as(&mut s, alice.clone(), req(by_id("b1"), 100, Priority::Ci), 0)
        else {
            panic!("expected grant");
        };
        let access = granted("org-b", "org-a", "nrf52", Some(10_000));
        let d = s.request_lease(
            bob.clone(),
            RequesterId::DETACHED,
            &access,
            req(Constraint::Tags(vec!["nrf52".to_owned()]), 100, Priority::Ci),
            0,
        );
        assert_eq!(d, LeaseDecision::Queued { position: 0 });

        let promoted = s
            .release_lease(g.lease, &alice.key(), 10)
            .expect("holder may release")
            .expect("the grantee is promoted");
        assert_eq!(promoted.grant.holder, bob);
    }

    /// Promotion re-evaluates the snapshot at `now`, so a grant that lapsed
    /// while the request sat in the queue cannot be promoted onto.
    #[test]
    fn a_waiter_whose_grant_expired_is_not_promoted() {
        let mut s = sched();
        s.upsert_board(tagged_board_in("org-a", "b1", "nrf52"));
        let alice = subject_in("org-a", "alice");

        let LeaseDecision::Granted(g) =
            request_as(&mut s, alice.clone(), req(by_id("b1"), 100, Priority::Ci), 0)
        else {
            panic!("expected grant");
        };
        // Grant expires at t=50; the board frees at t=60.
        let access = granted("org-b", "org-a", "nrf52", Some(50));
        let _ = s.request_lease(
            subject_in("org-b", "bob"),
            RequesterId::DETACHED,
            &access,
            req(Constraint::Tags(vec!["nrf52".to_owned()]), 100, Priority::Interactive),
            0,
        );
        let promoted = s
            .release_lease(g.lease, &alice.key(), 60)
            .expect("holder may release");
        assert!(
            promoted.is_none(),
            "an expired grant must not be promoted onto"
        );
    }

    /// `refresh_waiter_access` is the revocation half: a snapshot cannot notice
    /// a revoked grant, so the revoking caller pushes a fresh one in and
    /// promotion re-decides per board.
    #[test]
    fn refreshing_a_waiters_access_stops_it_being_promoted() {
        let mut s = sched();
        s.upsert_board(tagged_board_in("org-a", "b1", "nrf52"));
        let alice = subject_in("org-a", "alice");
        let bob = subject_in("org-b", "bob");

        let LeaseDecision::Granted(g) =
            request_as(&mut s, alice.clone(), req(by_id("b1"), 100, Priority::Ci), 0)
        else {
            panic!("expected grant");
        };
        let carol = subject_in("org-a", "carol");
        let _ = request_as(&mut s, carol.clone(), req(by_id("b1"), 100, Priority::Ci), 0);
        // Bob queues at the highest priority, so he would win any fair contest
        // his access still admitted.
        let access = granted("org-b", "org-a", "nrf52", None);
        let _ = s.request_lease(
            bob.clone(),
            RequesterId::DETACHED,
            &access,
            req(Constraint::Tags(vec!["nrf52".to_owned()]), 100, Priority::Interactive),
            0,
        );

        // Revoked: bob's access is now his own org only.
        assert_eq!(
            s.refresh_waiter_access(&bob.key(), &Access::own_org(org("org-b"))),
            1
        );

        let promoted = s
            .release_lease(g.lease, &alice.key(), 10)
            .expect("holder may release")
            .expect("carol is still queued");
        assert_eq!(
            promoted.grant.holder, carol,
            "bob is skipped on the board he lost, and the other waiter is untouched"
        );
    }

    /// The collateral-damage property: revoking a grant must not cancel the
    /// subject's pending requests for boards the grant had nothing to do with.
    ///
    /// Dropping the waiters outright (the obvious implementation) fails this:
    /// bob's queued request for his *own org's* board would silently never be
    /// granted, to somebody who did nothing wrong and is not watching.
    #[test]
    fn refreshing_leaves_a_waiters_own_org_request_intact() {
        let mut s = sched();
        s.upsert_board(tagged_board_in("org-a", "shared", "nrf52"));
        s.upsert_board(tagged_board_in("org-b", "mine", "nrf52"));
        let alice = subject_in("org-a", "alice");
        let bob_boss = subject_in("org-b", "boss");
        let bob = subject_in("org-b", "bob");

        // Both boards are busy, so bob queues for each.
        let LeaseDecision::Granted(shared) =
            request_as(&mut s, alice.clone(), req(by_id("shared"), 100, Priority::Ci), 0)
        else {
            panic!("expected grant");
        };
        let LeaseDecision::Granted(mine) =
            request_as(&mut s, bob_boss.clone(), req(by_id("mine"), 100, Priority::Ci), 0)
        else {
            panic!("expected grant");
        };

        let access = granted("org-b", "org-a", "nrf52", None);
        let _ = s.request_lease(bob.clone(), RequesterId::DETACHED, &access, req(by_id("shared"), 100, Priority::Ci), 0);
        let _ = s.request_lease(bob.clone(), RequesterId::DETACHED, &access, req(by_id("mine"), 100, Priority::Ci), 0);

        // Alice revokes her grant. Bob keeps his own org's membership.
        assert_eq!(
            s.refresh_waiter_access(&bob.key(), &Access::own_org(org("org-b"))),
            2,
            "both of bob's waiters are refreshed, neither is dropped"
        );

        // The shared board: bob is no longer eligible.
        assert!(
            s.release_lease(shared.lease, &alice.key(), 10)
                .expect("holder may release")
                .is_none(),
            "bob must not be promoted onto the board he lost access to"
        );
        // His own org's board: still his, still queued, still promoted.
        let promoted = s
            .release_lease(mine.lease, &bob_boss.key(), 10)
            .expect("holder may release")
            .expect("bob is still queued for his own org's board");
        assert_eq!(
            promoted.grant.holder, bob,
            "revoking a grant in another org must not cancel this request"
        );
    }

    /// A subject covered by two overlapping grants keeps its access — and its
    /// place in the queue — when only one is revoked.
    #[test]
    fn a_partially_revoked_grantee_keeps_its_queue_position() {
        let mut s = sched();
        s.upsert_board(tagged_board_in("org-a", "b1", "nrf52"));
        let alice = subject_in("org-a", "alice");
        let bob = subject_in("org-b", "bob");

        let LeaseDecision::Granted(g) =
            request_as(&mut s, alice.clone(), req(by_id("b1"), 100, Priority::Ci), 0)
        else {
            panic!("expected grant");
        };
        let both = Access {
            own_org: Some(org("org-b")),
            grants: vec![
                GrantScope {
                    id: "g1".to_owned(),
                    org: org("org-a"),
                    selector: Constraint::Tags(vec!["nrf52".to_owned()]),
                    ops: vec![AllowedOp::Attach],
                    expires: None,
                },
                GrantScope {
                    id: "g2".to_owned(),
                    org: org("org-a"),
                    selector: Constraint::Id(BoardName("b1".to_owned())),
                    ops: vec![AllowedOp::Gdb],
                    expires: None,
                },
            ],
        };
        let _ = s.request_lease(bob.clone(), RequesterId::DETACHED, &both, req(by_id("b1"), 100, Priority::Ci), 0);

        // g1 is revoked; g2 still covers the board.
        let mut remaining = both.clone();
        remaining.grants.retain(|g| g.id == "g2");
        assert_eq!(s.refresh_waiter_access(&bob.key(), &remaining), 1);

        let promoted = s
            .release_lease(g.lease, &alice.key(), 10)
            .expect("holder may release")
            .expect("the second grant still covers the board");
        assert_eq!(promoted.grant.holder, bob);
    }

    #[test]
    fn leases_held_by_reports_the_subjects_boards_only() {
        let mut s = sched();
        s.upsert_board(tagged_board_in("org-a", "b1", "nrf52"));
        s.upsert_board(tagged_board_in("org-a", "b2", "nrf52"));
        let alice = subject_in("org-a", "alice");
        let bob = subject_in("org-b", "bob");

        let LeaseDecision::Granted(ga) =
            request_as(&mut s, alice.clone(), req(by_id("b1"), 100, Priority::Ci), 0)
        else {
            panic!("expected grant");
        };
        let access = granted("org-b", "org-a", "nrf52", None);
        let LeaseDecision::Granted(gb) = s.request_lease(
            bob.clone(),
            RequesterId::DETACHED,
            &access,
            req(by_id("b2"), 100, Priority::Ci),
            0,
        ) else {
            panic!("expected grant");
        };

        assert_eq!(
            s.leases_held_by(&bob.key()),
            vec![(gb.lease, board_ref("org-a", "b2"))]
        );
        assert_eq!(
            s.leases_held_by(&alice.key()),
            vec![(ga.lease, board_ref("org-a", "b1"))]
        );
        assert!(s.leases_held_by(&subject_in("org-c", "nobody").key()).is_empty());
    }

    /// Deny by default, stated as a test: an access that confers nothing can
    /// never be granted a board, whatever the selector says.
    ///
    /// The outcome is now `NoCandidate`, not `Queued`, and that is more honest:
    /// an empty access matches no board in any state, so no release will ever
    /// satisfy this request and parking it in the queue only delayed the same
    /// refusal (silently, forever).
    #[test]
    fn empty_access_never_gets_a_board() {
        let mut s = sched();
        s.upsert_board(tagged_board_in("org-a", "b1", "nrf52"));
        let d = s.request_lease(
            subject_in("org-a", "ghost"),
            RequesterId::DETACHED,
            &Access::none(),
            req(by_id("b1"), 100, Priority::Ci),
            0,
        );
        assert_eq!(d, LeaseDecision::NoCandidate { reachable: 0 });
        assert_eq!(s.queue.len(), 0, "a hopeless request must not be queued");
    }
}
