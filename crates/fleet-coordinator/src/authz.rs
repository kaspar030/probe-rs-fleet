//! The authorization layer: the single place that answers "may this subject
//! act on this object?".
//!
//! Revision 1 shipped **no** authorization — authentication happened and
//! nothing consulted the result. Architecture revision 2 §6.5 defines the
//! minimal model implemented here:
//!
//! * **Deny by default.** Every request resolves to a
//!   [`Subject`] and is checked against the target object's org before
//!   anything else happens.
//! * **Two roles per org.** Membership alone is enough to add a node and to
//!   use the org's boards; `admin` additionally acts on other members' leases
//!   and reads the audit log.
//! * **Ownership, unconditionally.** A lease may be extended, released, or
//!   channel-opened only by its holder (or an org admin).
//!
//! * **Grants** (§6.5, this task). A subject that is *not* a member of a
//!   board's org may still reach it through a live, unexpired grant issued by
//!   that org. [`board_access`] resolves membership and grants into a single
//!   [`Access`] value, and every board decision is made against that — which
//!   is what keeps the tenancy fence in one place now that the scheduler's
//!   selector matching is org-blind.
//!
//! Errors are deliberately coarse. A cross-org object and a nonexistent one
//! must be indistinguishable to the caller, or the error message becomes an
//! org-enumeration oracle.

use fleet_core::access::Access;
use fleet_core::scheduler::Scheduler;
use fleet_proto::ids::{LeaseId, OrgId, Role, Subject, SubjectKey, SubjectKind};
use tracing::warn;

use crate::state::Db;

/// Why a request was refused.
///
/// Both variants render to the caller as one flat message (see
/// [`AuthzError::client_message`]): never leak whether an object exists in
/// another org.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthzError {
    /// The subject may not act on this object.
    #[error("not authorized")]
    Denied,
    /// The object does not exist (or is in another org — indistinguishable by
    /// design).
    #[error("not found")]
    NotFound,
}

impl AuthzError {
    /// The message sent back to the caller.
    ///
    /// For lease operations both variants collapse to "no such lease": a
    /// caller must not be able to tell "someone else's lease" from "no such
    /// lease", or it can enumerate other orgs' lease ids.
    #[must_use]
    pub fn lease_message() -> String {
        "no such lease".to_owned()
    }
}

/// Deny-by-default org check: the subject's org must equal the object's.
///
/// # Errors
///
/// [`AuthzError::Denied`] if the orgs differ.
pub fn same_org(subject: &Subject, org: &OrgId) -> Result<(), AuthzError> {
    if &subject.org == org {
        Ok(())
    } else {
        Err(AuthzError::Denied)
    }
}

/// Require that `subject` is a member of `org` with at least `min` role.
///
/// **Membership is defined for [`SubjectKind::User`] only** in this task: the
/// `member` table is keyed by `user_id` and references `user(id)`, so a
/// `Node` or `Workload` subject has no row and is denied *by construction*.
/// That is the intended outcome — workloads will get access through grants
/// (a separate task), not by being silently treated as members.
///
/// # Errors
///
/// [`AuthzError::Denied`] if the subject is in another org, is not a user, is
/// not a member, or holds a lesser role. A database failure is also reported as
/// `Denied` (fail closed).
pub async fn require_role(
    db: &Db,
    subject: &Subject,
    org: &OrgId,
    min: Role,
) -> Result<(), AuthzError> {
    same_org(subject, org)?;
    if subject.kind != SubjectKind::User {
        return Err(AuthzError::Denied);
    }
    // Fail closed: a DB error must never widen access.
    let role = db
        .role_of(org, &subject.id)
        .await
        .map_err(|_| AuthzError::Denied)?
        .ok_or(AuthzError::Denied)?;
    if role.satisfies(min) {
        Ok(())
    } else {
        Err(AuthzError::Denied)
    }
}

/// Whether `subject` is an admin of its own org.
pub async fn is_org_admin(db: &Db, subject: &Subject) -> bool {
    let org = subject.org.clone();
    require_role(db, subject, &org, Role::Admin).await.is_ok()
}

/// Resolve everything `subject` may reach, at `now`.
///
/// The single builder of an [`Access`], and therefore the single place a
/// cross-org board can become reachable. Two independent legs:
///
/// * **membership** — a `member` row in the subject's own org sets
///   `own_org`. Membership, not merely "the subject's `Subject.org`": a
///   revoked member keeps a valid session until it expires, and must stop
///   being able to lease.
/// * **grants** — live rows issued *to* this subject, from any org. Each is
///   re-parsed from its stored form; a row that will not parse is dropped
///   **closed** with a `warn!`, never widened into a match-anything.
///
/// A database failure yields an *empty* access rather than an error, which is
/// the fail-closed behaviour the rest of this module already uses: a DB blip
/// must never widen access.
pub async fn board_access(db: &Db, subject: &Subject, now: u64) -> Access {
    let mut access = Access::none();

    // Membership leg. Only users have membership rows (§6.1); a node or
    // workload subject is denied here by construction and reaches boards only
    // through the grant leg, which is the intended shape.
    if subject.kind == SubjectKind::User {
        match db.role_of(&subject.org, &subject.id).await {
            Ok(Some(_role)) => access.own_org = Some(subject.org.clone()),
            Ok(None) => {}
            Err(e) => warn!(error = %e, subject = %subject, "membership lookup failed; denying"),
        }
    }

    // Grant leg. Scoped by the authenticated subject key, which the caller
    // cannot forge — see `Db::grants_for_subject` for why this one query is
    // deliberately not org-scoped.
    let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);
    match db.grants_for_subject(&subject.key(), now_i64).await {
        Ok(rows) => {
            for row in rows {
                if let Some(scope) = row.to_scope() {
                    access.grants.push(scope);
                } else {
                    warn!(
                        grant = %row.id,
                        selector = %row.selector,
                        ops = %row.ops,
                        "dropping an unparseable grant row (fails closed)"
                    );
                }
            }
        }
        Err(e) => warn!(error = %e, subject = %subject, "grant lookup failed; denying"),
    }

    access
}

/// The lease-ownership rule of architecture §6.5: a lease may be acted on by
/// its holder, or by an admin of an org with a stake in it.
///
/// Returns the **holder's** [`SubjectKey`] — the caller's own when it is the
/// holder, the recorded holder's when an admin overrides — which is exactly
/// what [`Scheduler::extend_lease`] / [`Scheduler::release_lease`] require.
///
/// # Three ways in, since cross-org leases now exist
///
/// Under grants a lease's holder and its *board* can be in different orgs, so
/// "the lease's org" is ambiguous and the old `holder.org != subject.org`
/// short-circuit is actively wrong: it would strip a board's owner of control
/// over a lease running on their own hardware. The rule is therefore:
///
/// 1. the holder; or
/// 2. an admin of the **holder's** org (the original override); or
/// 3. an admin of the **board's** org — you can always reclaim your own
///    hardware from someone you shared it with.
///
/// Anyone else gets `NotFound`, so a stranger still cannot distinguish
/// "someone else's lease" from "no such lease".
///
/// # Errors
///
/// [`AuthzError::NotFound`] if no such lease is active or the caller has no
/// relationship to it, [`AuthzError::Denied`] if the caller is in a related org
/// but lacks the role. Callers must render both identically
/// ([`AuthzError::lease_message`]).
pub async fn require_lease_control(
    db: &Db,
    sched: &Scheduler,
    subject: &Subject,
    lease: LeaseId,
) -> Result<SubjectKey, AuthzError> {
    let holder = sched.lease_holder(lease).ok_or(AuthzError::NotFound)?.clone();
    if holder.key() == subject.key() {
        return Ok(holder.key());
    }

    let board_org = sched.lease_target(lease).map(|(board, _)| board.org.clone());
    let related = holder.org == subject.org || board_org.as_ref() == Some(&subject.org);
    if !related {
        // Neither the holder's org nor the hardware's: the lease is invisible,
        // not merely forbidden.
        return Err(AuthzError::NotFound);
    }
    if is_org_admin(db, subject).await {
        return Ok(holder.key());
    }
    Err(AuthzError::Denied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_core::policy::Policy;
    use fleet_proto::board::{Board, BoardState, PowerKind};
    use fleet_proto::ids::{AgentId, BoardName, BoardRef};
    use fleet_proto::lease::{Constraint, LeaseRequest, Priority};

    fn org(name: &str) -> OrgId {
        OrgId(name.to_owned())
    }

    fn user(org_name: &str, id: &str) -> Subject {
        Subject::new(org(org_name), SubjectKind::User, id)
    }

    fn board(org_name: &str, name: &str) -> Board {
        Board {
            id: BoardRef::new(org(org_name), AgentId("node-1".to_owned()), name),
            agent: AgentId("node-1".to_owned()),
            chip: "nRF52840_xxAA".to_owned(),
            tags: vec![],
            exclusive: true,
            power: PowerKind::None,
            state: BoardState::Idle,
        }
    }

    fn lease_req(name: &str) -> LeaseRequest {
        LeaseRequest {
            select: Constraint::Board(BoardName(name.to_owned())),
            duration_secs: 600,
            priority: Priority::Interactive,
        }
    }

    async fn db_with(members: &[(&str, &str, Role)]) -> Db {
        let db = Db::connect_in_memory().await.unwrap();
        for (org_name, id, role) in members {
            db.ensure_user_member(&org(org_name), id, *role).await.unwrap();
        }
        db
    }

    fn sched_with_lease(holder: &Subject) -> (Scheduler, LeaseId) {
        sched_with_lease_on(holder, &holder.org.0)
    }

    /// A scheduler where `holder` holds a lease on a board in `board_org` —
    /// which under grants need not be the holder's own org.
    fn sched_with_lease_on(holder: &Subject, board_org: &str) -> (Scheduler, LeaseId) {
        let mut s = Scheduler::new(Policy::default());
        let b = board(board_org, "b1");
        s.upsert_board(b.clone());
        // The scheduler only ever asks the access it is given; building one
        // that admits this board is exactly what `board_access` would do for a
        // member (same org) or a grantee (cross org).
        let access = if board_org == holder.org.0 {
            Access::own_org(holder.org.clone())
        } else {
            Access {
                own_org: Some(holder.org.clone()),
                grants: vec![fleet_core::access::GrantScope {
                    id: "g1".to_owned(),
                    org: org(board_org),
                    selector: Constraint::Board(BoardName("b1".to_owned())),
                    ops: vec![fleet_proto::token::AllowedOp::Attach],
                    expires: None,
                }],
            }
        };
        let fleet_core::scheduler::LeaseDecision::Granted(g) =
            s.request_lease(holder.clone(), &access, lease_req("b1"), 1000)
        else {
            panic!("expected grant");
        };
        (s, g.lease)
    }

    #[test]
    fn same_org_denies_cross_org() {
        assert!(same_org(&user("a", "alice"), &org("a")).is_ok());
        assert_eq!(
            same_org(&user("a", "alice"), &org("b")),
            Err(AuthzError::Denied)
        );
    }

    #[tokio::test]
    async fn require_role_denies_non_member_and_lesser_role() {
        let db = db_with(&[("a", "alice", Role::Member), ("a", "root", Role::Admin)]).await;
        assert!(require_role(&db, &user("a", "alice"), &org("a"), Role::Member)
            .await
            .is_ok());
        assert_eq!(
            require_role(&db, &user("a", "alice"), &org("a"), Role::Admin).await,
            Err(AuthzError::Denied),
            "a member is not an admin"
        );
        assert!(require_role(&db, &user("a", "root"), &org("a"), Role::Admin)
            .await
            .is_ok());
        assert_eq!(
            require_role(&db, &user("a", "mallory"), &org("a"), Role::Member).await,
            Err(AuthzError::Denied),
            "a non-member is denied"
        );
    }

    /// Membership is a user-only concept in this task; node and workload
    /// subjects must be denied by construction, not by accident.
    #[tokio::test]
    async fn non_user_subjects_are_denied_membership() {
        let db = db_with(&[("a", "ci", Role::Admin)]).await;
        for kind in [SubjectKind::Node, SubjectKind::Workload] {
            let s = Subject::new(org("a"), kind, "ci");
            assert_eq!(
                require_role(&db, &s, &org("a"), Role::Member).await,
                Err(AuthzError::Denied),
                "{kind} subjects have no membership"
            );
        }
    }

    #[tokio::test]
    async fn holder_controls_its_own_lease() {
        let alice = user("a", "alice");
        let db = db_with(&[("a", "alice", Role::Member)]).await;
        let (sched, lease) = sched_with_lease(&alice);
        assert_eq!(
            require_lease_control(&db, &sched, &alice, lease).await,
            Ok(alice.key())
        );
    }

    #[tokio::test]
    async fn other_member_cannot_control_someone_elses_lease() {
        let alice = user("a", "alice");
        let db = db_with(&[("a", "alice", Role::Member), ("a", "bob", Role::Member)]).await;
        let (sched, lease) = sched_with_lease(&alice);
        assert_eq!(
            require_lease_control(&db, &sched, &user("a", "bob"), lease).await,
            Err(AuthzError::Denied)
        );
    }

    #[tokio::test]
    async fn org_admin_may_override_and_gets_the_holders_key() {
        let alice = user("a", "alice");
        let db = db_with(&[("a", "alice", Role::Member), ("a", "root", Role::Admin)]).await;
        let (sched, lease) = sched_with_lease(&alice);
        assert_eq!(
            require_lease_control(&db, &sched, &user("a", "root"), lease).await,
            Ok(alice.key()),
            "the admin acts as the holder, not as itself"
        );
    }

    /// A cross-org caller must not be able to tell "someone else's lease" from
    /// "no such lease".
    #[tokio::test]
    async fn cross_org_lease_is_indistinguishable_from_unknown() {
        let alice = user("a", "alice");
        let db = db_with(&[("a", "alice", Role::Member), ("b", "root", Role::Admin)]).await;
        let (sched, lease) = sched_with_lease(&alice);
        let intruder = user("b", "root");
        assert_eq!(
            require_lease_control(&db, &sched, &intruder, lease).await,
            Err(AuthzError::NotFound)
        );
        assert_eq!(
            require_lease_control(&db, &sched, &intruder, LeaseId(9999)).await,
            Err(AuthzError::NotFound)
        );
    }

    /// Same id, different org: still someone else.
    #[tokio::test]
    async fn same_id_in_another_org_cannot_control_the_lease() {
        let alice_a = user("a", "alice");
        let db = db_with(&[("a", "alice", Role::Member), ("b", "alice", Role::Admin)]).await;
        let (sched, lease) = sched_with_lease(&alice_a);
        assert_eq!(
            require_lease_control(&db, &sched, &user("b", "alice"), lease).await,
            Err(AuthzError::NotFound)
        );
    }

    // -----------------------------------------------------------------------
    // Grants (architecture §6.5)
    // -----------------------------------------------------------------------

    /// Store one grant of `org`'s hardware to `to`.
    async fn seed_grant(
        db: &Db,
        org_name: &str,
        to: &Subject,
        selector: &str,
        ops: &[fleet_proto::token::AllowedOp],
        expires: Option<i64>,
    ) -> String {
        let id = crate::state::new_grant_id();
        db.ensure_org(&org(org_name), "team").await.unwrap();
        db.scoped(org(org_name))
            .insert_grant(&id, &to.key(), selector, ops, expires, Some("alice"), 100)
            .await
            .unwrap();
        id
    }

    #[tokio::test]
    async fn board_access_carries_membership_and_grants() {
        use fleet_proto::token::AllowedOp;

        let db = db_with(&[("a", "alice", Role::Admin), ("b", "bob", Role::Member)]).await;
        let bob = user("b", "bob");
        seed_grant(&db, "a", &bob, "tag=nrf52", &[AllowedOp::Attach], Some(5_000)).await;

        let access = board_access(&db, &bob, 1_000).await;
        assert_eq!(access.own_org, Some(org("b")), "membership leg");
        assert_eq!(access.grants.len(), 1, "grant leg");
        assert_eq!(access.grants[0].org, org("a"));
    }

    /// A grant to somebody else must never show up in this subject's access —
    /// the query is scoped by the authenticated subject key.
    #[tokio::test]
    async fn a_grant_to_another_subject_is_not_visible() {
        use fleet_proto::token::AllowedOp;

        let db = db_with(&[("a", "alice", Role::Admin), ("b", "bob", Role::Member)]).await;
        let bob = user("b", "bob");
        let mallory = user("b", "mallory");
        seed_grant(&db, "a", &bob, "tag=nrf52", &[AllowedOp::Attach], None).await;

        let access = board_access(&db, &mallory, 1_000).await;
        assert!(access.grants.is_empty());
    }

    /// Same id, different org, is a different subject here too.
    #[tokio::test]
    async fn a_grant_does_not_follow_an_id_across_orgs() {
        use fleet_proto::token::AllowedOp;

        let db = db_with(&[("b", "alice", Role::Member), ("c", "alice", Role::Member)]).await;
        seed_grant(&db, "a", &user("b", "alice"), "tag=nrf52", &[AllowedOp::Attach], None).await;

        assert_eq!(board_access(&db, &user("b", "alice"), 1_000).await.grants.len(), 1);
        assert!(board_access(&db, &user("c", "alice"), 1_000).await.grants.is_empty());
    }

    #[tokio::test]
    async fn an_expired_grant_is_filtered_out() {
        use fleet_proto::token::AllowedOp;

        let db = db_with(&[("b", "bob", Role::Member)]).await;
        let bob = user("b", "bob");
        seed_grant(&db, "a", &bob, "tag=nrf52", &[AllowedOp::Attach], Some(500)).await;

        assert_eq!(board_access(&db, &bob, 400).await.grants.len(), 1);
        assert!(board_access(&db, &bob, 600).await.grants.is_empty());
    }

    /// A corrupt row must be dropped closed, not widened into a match-anything
    /// — the difference between "this grant is broken" and "this grant covers
    /// the whole fleet".
    #[tokio::test]
    async fn an_unparseable_grant_row_is_dropped_closed() {
        let db = db_with(&[("b", "bob", Role::Member)]).await;
        let bob = user("b", "bob");
        db.ensure_org(&org("a"), "team").await.unwrap();

        for (selector, ops) in [("", "attach"), ("colour=red", "attach"), ("tag=nrf52", "")] {
            let id = crate::state::new_grant_id();
            sqlx::query(
                "INSERT INTO \"grant\" (id, org_id, subject, selector, ops, expires, created_by, created_at)
                 VALUES (?1, 'a', ?2, ?3, ?4, NULL, NULL, 0)",
            )
            .bind(&id)
            .bind(bob.key().to_string())
            .bind(selector)
            .bind(ops)
            .execute(db.pool_for_test())
            .await
            .unwrap();
        }

        let access = board_access(&db, &bob, 1_000).await;
        assert!(
            access.grants.is_empty(),
            "every unparseable row must be dropped, not widened"
        );
    }

    /// A non-member with no grant gets an empty access, which every handler
    /// treats as a flat refusal.
    #[tokio::test]
    async fn a_stranger_gets_an_empty_access() {
        let db = db_with(&[("a", "alice", Role::Member)]).await;
        assert!(board_access(&db, &user("a", "mallory"), 1_000).await.is_empty());
    }

    /// A node or workload subject has no membership row by construction (§6.1),
    /// so a grant is the *only* way it reaches a board — and it does work.
    #[tokio::test]
    async fn a_workload_subject_reaches_boards_only_through_a_grant() {
        use fleet_proto::token::AllowedOp;

        let db = db_with(&[("a", "alice", Role::Admin)]).await;
        let ci = Subject::new(org("b"), SubjectKind::Workload, "ci");
        assert!(board_access(&db, &ci, 1_000).await.is_empty());

        seed_grant(&db, "a", &ci, "tag=nrf52", &[AllowedOp::Flash, AllowedOp::Attach], None).await;
        let access = board_access(&db, &ci, 1_000).await;
        assert!(access.own_org.is_none(), "no membership, by construction");
        assert_eq!(access.grants.len(), 1);
    }

    /// §1.7: the board's org admin may control a lease a grantee is holding on
    /// their hardware. Without this, sharing a board would mean losing control
    /// of it until the lease lapses.
    #[tokio::test]
    async fn the_boards_org_admin_may_control_a_grantees_lease() {
        let bob = user("b", "bob");
        let db = db_with(&[
            ("a", "root", Role::Admin),
            ("a", "plain", Role::Member),
            ("b", "bob", Role::Member),
        ])
        .await;
        // bob (org b) holds a lease on org a's board, by grant.
        let (sched, lease) = sched_with_lease_on(&bob, "a");

        assert_eq!(
            require_lease_control(&db, &sched, &user("a", "root"), lease).await,
            Ok(bob.key()),
            "the hardware's owner can always reclaim it"
        );
        assert_eq!(
            require_lease_control(&db, &sched, &user("a", "plain"), lease).await,
            Err(AuthzError::Denied),
            "a plain member of the board's org still may not"
        );
        assert_eq!(
            require_lease_control(&db, &sched, &bob, lease).await,
            Ok(bob.key()),
            "the holder, obviously"
        );
    }

    /// The holder's own org admin keeps the override too, even when the
    /// hardware belongs to somebody else.
    #[tokio::test]
    async fn the_holders_org_admin_still_overrides_on_a_cross_org_lease() {
        let bob = user("b", "bob");
        let db = db_with(&[("b", "bob", Role::Member), ("b", "boss", Role::Admin)]).await;
        let (sched, lease) = sched_with_lease_on(&bob, "a");
        assert_eq!(
            require_lease_control(&db, &sched, &user("b", "boss"), lease).await,
            Ok(bob.key())
        );
    }

    /// An unrelated third org still sees nothing at all.
    #[tokio::test]
    async fn an_unrelated_org_cannot_see_a_cross_org_lease() {
        let bob = user("b", "bob");
        let db = db_with(&[("b", "bob", Role::Member), ("c", "root", Role::Admin)]).await;
        let (sched, lease) = sched_with_lease_on(&bob, "a");
        assert_eq!(
            require_lease_control(&db, &sched, &user("c", "root"), lease).await,
            Err(AuthzError::NotFound),
            "not found, not forbidden: no enumeration oracle"
        );
    }
}
