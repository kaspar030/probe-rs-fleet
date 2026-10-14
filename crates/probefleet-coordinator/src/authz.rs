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

use probefleet_core::access::Access;
use probefleet_core::scheduler::Scheduler;
use probefleet_proto::ids::{LeaseId, OrgId, SubjectKey, SubjectKind};
use tracing::warn;

use crate::state::Db;
use crate::subject::{FleetRole, Subject};

/// Why a request was refused.
///
/// Both variants render to the caller as one flat message: never leak whether
/// an object exists in another org.
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

/// Deny-by-default org check: the subject's acting org must equal the
/// object's.
///
/// # Errors
///
/// [`AuthzError::Denied`] if the orgs differ or the subject acts in none.
pub fn same_org(subject: &Subject, org: &OrgId) -> Result<(), AuthzError> {
    if subject.org() == Some(org) {
        Ok(())
    } else {
        Err(AuthzError::Denied)
    }
}

/// The subject's acting org, or `Denied`.
///
/// # Errors
///
/// [`AuthzError::Denied`] for a subject acting in no org (a workload).
pub fn acting_org(subject: &Subject) -> Result<&OrgId, AuthzError> {
    subject.org().ok_or(AuthzError::Denied)
}

/// Require that `subject` is a member of `org` with at least `min` role.
///
/// **Membership is defined for users only** (forgs memberships are keyed by
/// user): a node or workload subject is denied *by construction*. A CI
/// workload reaches boards through **per-repo grants** ([`board_access`]'s
/// grant leg), never by being silently treated as a member of anything.
///
/// Checked against the database on every call, not against the acting org
/// the connection was opened with: a revoked member keeps a live session
/// until it expires, and must stop being able to act.
///
/// # Errors
///
/// [`AuthzError::Denied`] if the subject acts in another org, is not a user,
/// is not a member, or holds a lesser role. A database failure is also
/// reported as `Denied` (fail closed).
pub async fn require_role(
    db: &Db,
    subject: &Subject,
    org: &OrgId,
    min: FleetRole,
) -> Result<(), AuthzError> {
    same_org(subject, org)?;
    let user = subject.user_id().ok_or(AuthzError::Denied)?;
    let role = db
        .role_of(org, user)
        .await
        .map_err(|_| AuthzError::Denied)?
        .ok_or(AuthzError::Denied)?;
    if role >= min {
        Ok(())
    } else {
        Err(AuthzError::Denied)
    }
}

/// Whether `subject` is an admin of `org` (a user, by membership; regardless
/// of the acting org).
pub async fn is_admin_of(db: &Db, subject: &Subject, org: &OrgId) -> bool {
    let Some(user) = subject.user_id() else {
        return false;
    };
    matches!(db.role_of(org, user).await, Ok(Some(FleetRole::Admin)))
}

/// Whether `subject` is an admin of its acting org.
pub async fn is_org_admin(db: &Db, subject: &Subject) -> bool {
    match subject.org() {
        Some(org) => is_admin_of(db, subject, org).await,
        None => false,
    }
}

/// Resolve everything `subject` may reach, at `now`.
///
/// The single builder of an [`Access`], and therefore the single place a
/// cross-org board can become reachable. Two independent legs:
///
/// * **membership** — every org the user is a member of (forgs
///   memberships). Membership, not merely the acting org: the ownership path
///   is "the board's org is one of mine". A node or workload has none.
/// * **grants** — live rows issued *to* this subject key, from any org. Each
///   is re-parsed from its stored form; a row that will not parse is dropped
///   **closed** with a `warn!`, never widened into a match-anything.
///
/// A database failure yields an *empty* leg rather than an error: a DB blip
/// must never widen access.
pub async fn board_access(db: &Db, subject: &Subject, now: u64) -> Access {
    access_of(db, subject.key(), now).await
}

/// [`board_access`] for a bare subject key (the revocation cascade).
pub async fn access_of(db: &Db, key: &SubjectKey, now: u64) -> Access {
    let mut access = Access::none();
    if key.kind() == SubjectKind::User {
        if let Some(user) = crate::subject::user_of(key) {
            match db.orgs_of_user(user).await {
                Ok(orgs) => access.member_of = orgs.into_iter().map(|(o, _)| o).collect(),
                Err(e) => warn!(error = %e, subject = %key, "membership lookup failed; denying"),
            }
        }
    }
    match db.grant_scopes_for(key, now).await {
        Ok(grants) => access.grants = grants,
        Err(e) => warn!(error = %e, subject = %key, "grant lookup failed; denying"),
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
/// # Three ways in
///
/// 1. the holder; or
/// 2. an admin of the **holder's** org (the holder's namespace for a node or
///    named workload; for a user holder, the caller's acting org when the
///    holder is a member of it); or
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
    let holder = sched
        .lease_holder(lease)
        .ok_or(AuthzError::NotFound)?
        .clone();
    if &holder == subject.key() {
        return Ok(holder);
    }
    let Some(acting) = subject.org() else {
        return Err(AuthzError::NotFound);
    };
    let board_org = sched
        .lease_target(lease)
        .map(|(board, _)| board.org.clone());
    let holder_in_acting = holder_org_is(db, &holder, acting).await;
    let related = holder_in_acting || board_org.as_ref() == Some(acting);
    if !related {
        // Neither the holder's org nor the hardware's: the lease is invisible,
        // not merely forbidden.
        return Err(AuthzError::NotFound);
    }
    if is_admin_of(db, subject, acting).await {
        return Ok(holder);
    }
    Err(AuthzError::Denied)
}

/// Whether `holder` belongs to `org`: its namespace for a node / named
/// workload, membership for a user.
async fn holder_org_is(db: &Db, holder: &SubjectKey, org: &OrgId) -> bool {
    if holder.ns() == Some(org.0.as_str()) {
        return true;
    }
    match crate::subject::user_of(holder) {
        Some(user) => matches!(db.role_of(org, user).await, Ok(Some(_))),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subject::testkit::{self, member};
    use probefleet_core::policy::Policy;
    use probefleet_proto::board::{Board, BoardState, PowerKind};
    use probefleet_proto::ids::{BoardName, BoardRef, NodeId};
    use probefleet_proto::lease::{Constraint, LeaseRequest, Priority};
    use probefleet_proto::token::AllowedOp;
    use FleetRole::{Admin, Member};

    fn node(org: &OrgId) -> NodeId {
        crate::state::node_id_for(org, "node-1")
    }

    fn board(org: &OrgId, name: &str) -> Board {
        Board {
            id: BoardRef::new(org.clone(), node(org), name),
            node: node(org),
            chip: "nRF52840_xxAA".to_owned(),
            model: None,
            tags: vec![],
            exclusive: true,
            power: PowerKind::None,
            state: BoardState::Idle,
        }
    }

    fn lease_req(name: &str) -> LeaseRequest {
        LeaseRequest {
            select: Constraint::Id(BoardName(name.to_owned())),
            duration_secs: 600,
            priority: Priority::Interactive,
        }
    }

    fn sched_with_lease(holder: &Subject) -> (Scheduler, LeaseId) {
        sched_with_lease_on(holder, holder.org().unwrap())
    }

    /// A scheduler where `holder` holds a lease on a board in `board_org` —
    /// which under grants need not be the holder's own org.
    fn sched_with_lease_on(holder: &Subject, board_org: &OrgId) -> (Scheduler, LeaseId) {
        let mut s = Scheduler::new(Policy::default());
        s.upsert_board(board(board_org, "b1"));
        let access = if Some(board_org) == holder.org() {
            Access::own_org(board_org.clone())
        } else {
            Access {
                member_of: holder.org().into_iter().cloned().collect(),
                grants: vec![probefleet_core::access::GrantScope {
                    id: "g1".to_owned(),
                    org: board_org.clone(),
                    selector: Constraint::Id(BoardName("b1".to_owned())),
                    ops: vec![AllowedOp::Attach],
                    expires: None,
                }],
            }
        };
        let probefleet_core::scheduler::LeaseDecision::Granted(g) = s.request_lease(
            holder.key().clone(),
            probefleet_core::scheduler::RequesterId::DETACHED,
            &access,
            lease_req("b1"),
            1000,
        ) else {
            panic!("expected grant");
        };
        (s, g.lease)
    }

    #[tokio::test]
    async fn same_org_denies_cross_org() {
        let db = testkit::db().await;
        let alice = member(&db, "a", "alice", Member).await;
        let b = testkit::org(&db, "b").await;
        assert!(same_org(&alice, alice.org().unwrap()).is_ok());
        assert_eq!(same_org(&alice, &b), Err(AuthzError::Denied));
    }

    #[tokio::test]
    async fn require_role_denies_non_member_and_lesser_role() {
        let db = testkit::db().await;
        let alice = member(&db, "a", "alice", Member).await;
        let root = member(&db, "a", "root", Admin).await;
        let a = alice.org().unwrap().clone();
        assert!(require_role(&db, &alice, &a, Member).await.is_ok());
        assert_eq!(
            require_role(&db, &alice, &a, Admin).await,
            Err(AuthzError::Denied),
            "a member is not an admin"
        );
        assert!(require_role(&db, &root, &a, Admin).await.is_ok());
        let mallory = Subject::user(testkit::user(&db, "mallory").await, a.clone());
        assert_eq!(
            require_role(&db, &mallory, &a, Member).await,
            Err(AuthzError::Denied),
            "a non-member claiming the org is denied"
        );
    }

    /// Everyone is always in an org: a fresh user administers their personal
    /// org.
    #[tokio::test]
    async fn a_user_administers_their_personal_org() {
        let db = testkit::db().await;
        let u = testkit::user(&db, "alice").await;
        let personal = db.personal_org(u).await.unwrap().unwrap();
        assert!(
            require_role(&db, &Subject::user(u, personal.clone()), &personal, Admin)
                .await
                .is_ok()
        );
        assert_eq!(
            db.org_name(&personal).await.unwrap().as_deref(),
            Some("alice")
        );
    }

    /// Membership is a user-only concept: node and workload subjects are denied
    /// even when claiming an org.
    #[tokio::test]
    async fn non_user_subjects_are_denied_membership() {
        let db = testkit::db().await;
        let a = testkit::org(&db, "a").await;
        let n = Subject::node(a.clone(), &node(&a)).unwrap();
        let w = Subject::new(
            SubjectKey::new(Some(&a.0), SubjectKind::Workload, "agent:ci").unwrap(),
            Some(a.clone()),
        );
        for s in [n, w] {
            assert_eq!(
                require_role(&db, &s, &a, Member).await,
                Err(AuthzError::Denied),
                "{s} has no membership"
            );
        }
    }

    #[tokio::test]
    async fn holder_controls_its_own_lease() {
        let db = testkit::db().await;
        let alice = member(&db, "a", "alice", Member).await;
        let (sched, lease) = sched_with_lease(&alice);
        assert_eq!(
            require_lease_control(&db, &sched, &alice, lease).await,
            Ok(alice.key().clone())
        );
    }

    #[tokio::test]
    async fn other_member_cannot_control_someone_elses_lease() {
        let db = testkit::db().await;
        let alice = member(&db, "a", "alice", Member).await;
        let bob = member(&db, "a", "bob", Member).await;
        let (sched, lease) = sched_with_lease(&alice);
        assert_eq!(
            require_lease_control(&db, &sched, &bob, lease).await,
            Err(AuthzError::Denied)
        );
    }

    #[tokio::test]
    async fn org_admin_may_override_and_gets_the_holders_key() {
        let db = testkit::db().await;
        let alice = member(&db, "a", "alice", Member).await;
        let root = member(&db, "a", "root", Admin).await;
        let (sched, lease) = sched_with_lease(&alice);
        assert_eq!(
            require_lease_control(&db, &sched, &root, lease).await,
            Ok(alice.key().clone()),
            "the admin acts as the holder, not as itself"
        );
    }

    /// A cross-org caller must not be able to tell "someone else's lease" from
    /// "no such lease".
    #[tokio::test]
    async fn cross_org_lease_is_indistinguishable_from_unknown() {
        let db = testkit::db().await;
        let alice = member(&db, "a", "alice", Member).await;
        let intruder = member(&db, "b", "root", Admin).await;
        let (sched, lease) = sched_with_lease(&alice);
        assert_eq!(
            require_lease_control(&db, &sched, &intruder, lease).await,
            Err(AuthzError::NotFound)
        );
        assert_eq!(
            require_lease_control(&db, &sched, &intruder, LeaseId(9999)).await,
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
        to: &SubjectKey,
        selector: &str,
        ops: &[AllowedOp],
        expires: Option<u64>,
    ) {
        let o = testkit::org(db, org_name).await;
        db.forgs()
            .scoped(crate::subject::ns_of(&o).unwrap())
            .insert_grant(
                &forgs_store::NewGrant {
                    subject: crate::subject::to_forgs(to).unwrap(),
                    selector: selector.to_owned(),
                    ops: crate::state::join_ops(ops),
                    expires,
                    created_by: None,
                },
                100,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn board_access_carries_membership_and_grants() {
        let db = testkit::db().await;
        member(&db, "a", "alice", Admin).await;
        let bob = member(&db, "b", "bob", Member).await;
        seed_grant(
            &db,
            "a",
            bob.key(),
            "tag=nrf52",
            &[AllowedOp::Attach],
            Some(5_000),
        )
        .await;

        let access = board_access(&db, &bob, 1_000).await;
        let personal = db
            .personal_org(bob.user_id().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(
            access.member_of.contains(bob.org().unwrap()),
            "membership leg"
        );
        assert!(
            access.member_of.contains(&personal),
            "every org, not just the acting one"
        );
        assert_eq!(access.grants.len(), 1, "grant leg");
        assert_eq!(access.grants[0].org, testkit::org(&db, "a").await);
    }

    /// A grant to somebody else must never show up in this subject's access.
    #[tokio::test]
    async fn a_grant_to_another_subject_is_not_visible() {
        let db = testkit::db().await;
        let bob = member(&db, "b", "bob", Member).await;
        let mallory = member(&db, "b", "mallory", Member).await;
        seed_grant(&db, "a", bob.key(), "tag=nrf52", &[AllowedOp::Attach], None).await;
        assert!(board_access(&db, &mallory, 1_000).await.grants.is_empty());
    }

    #[tokio::test]
    async fn an_expired_grant_is_filtered_out() {
        let db = testkit::db().await;
        let bob = member(&db, "b", "bob", Member).await;
        seed_grant(
            &db,
            "a",
            bob.key(),
            "tag=nrf52",
            &[AllowedOp::Attach],
            Some(500),
        )
        .await;
        assert_eq!(board_access(&db, &bob, 400).await.grants.len(), 1);
        assert!(board_access(&db, &bob, 600).await.grants.is_empty());
    }

    /// A corrupt row must be dropped closed, not widened into a match-anything.
    #[tokio::test]
    async fn an_unparseable_grant_row_is_dropped_closed() {
        let db = testkit::db().await;
        let bob = member(&db, "b", "bob", Member).await;
        let a = testkit::org(&db, "a").await;
        for (i, (selector, ops)) in [("", "attach"), ("colour=red", "attach"), ("tag=nrf52", "")]
            .into_iter()
            .enumerate()
        {
            sqlx::query(
                "INSERT INTO forgs_grant (id, ns_node_id, subject, selector, ops, expires, created_by, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, 0)",
            )
            .bind(forgs::GrantId::generate(u64::try_from(i).unwrap()).to_string())
            .bind(&a.0)
            .bind(bob.key().to_string())
            .bind(selector)
            .bind(ops)
            .execute(db.pool_for_test())
            .await
            .unwrap();
        }
        assert!(
            board_access(&db, &bob, 1_000).await.grants.is_empty(),
            "every unparseable row must be dropped, not widened"
        );
    }

    /// A node or workload subject has no membership, so a grant is the *only*
    /// way it reaches a board — and it does work.
    #[tokio::test]
    async fn a_workload_subject_reaches_boards_only_through_a_grant() {
        let db = testkit::db().await;
        let ci = Subject::new(
            forgs::subject::workload_subject_key("acme/fw")
                .to_string()
                .parse::<String>()
                .ok()
                .and_then(|s| SubjectKey::parse(&s))
                .unwrap(),
            None,
        );
        assert!(board_access(&db, &ci, 1_000).await.is_empty());
        seed_grant(
            &db,
            "a",
            ci.key(),
            "tag=nrf52",
            &[AllowedOp::Flash, AllowedOp::Attach],
            None,
        )
        .await;
        let access = board_access(&db, &ci, 1_000).await;
        assert!(
            access.member_of.is_empty(),
            "no membership, by construction"
        );
        assert_eq!(access.grants.len(), 1);
    }

    /// The board's org admin may control a lease a grantee is holding on their
    /// hardware.
    #[tokio::test]
    async fn the_boards_org_admin_may_control_a_grantees_lease() {
        let db = testkit::db().await;
        let root = member(&db, "a", "root", Admin).await;
        let plain = member(&db, "a", "plain", Member).await;
        let bob = member(&db, "b", "bob", Member).await;
        let (sched, lease) = sched_with_lease_on(&bob, root.org().unwrap());
        assert_eq!(
            require_lease_control(&db, &sched, &root, lease).await,
            Ok(bob.key().clone()),
            "the hardware's owner can always reclaim it"
        );
        assert_eq!(
            require_lease_control(&db, &sched, &plain, lease).await,
            Err(AuthzError::Denied),
            "a plain member of the board's org still may not"
        );
        assert_eq!(
            require_lease_control(&db, &sched, &bob, lease).await,
            Ok(bob.key().clone())
        );
    }

    /// The holder's own org admin keeps the override on a cross-org lease.
    #[tokio::test]
    async fn the_holders_org_admin_still_overrides_on_a_cross_org_lease() {
        let db = testkit::db().await;
        let bob = member(&db, "b", "bob", Member).await;
        let boss = member(&db, "b", "boss", Admin).await;
        let a = testkit::org(&db, "a").await;
        let (sched, lease) = sched_with_lease_on(&bob, &a);
        assert_eq!(
            require_lease_control(&db, &sched, &boss, lease).await,
            Ok(bob.key().clone())
        );
    }

    /// An unrelated third org still sees nothing at all.
    #[tokio::test]
    async fn an_unrelated_org_cannot_see_a_cross_org_lease() {
        let db = testkit::db().await;
        let bob = member(&db, "b", "bob", Member).await;
        let root = member(&db, "c", "root", Admin).await;
        let a = testkit::org(&db, "a").await;
        let (sched, lease) = sched_with_lease_on(&bob, &a);
        assert_eq!(
            require_lease_control(&db, &sched, &root, lease).await,
            Err(AuthzError::NotFound),
            "not found, not forbidden: no enumeration oracle"
        );
    }
}
