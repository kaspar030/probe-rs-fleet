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
//! Errors are deliberately coarse. A cross-org object and a nonexistent one
//! must be indistinguishable to the caller, or the error message becomes an
//! org-enumeration oracle.

use fleet_core::scheduler::Scheduler;
use fleet_proto::ids::{LeaseId, OrgId, Role, Subject, SubjectKey, SubjectKind};

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

/// The lease-ownership rule of architecture §6.5: a lease may be acted on by
/// its holder, or by an admin of the lease's org.
///
/// Returns the **holder's** [`SubjectKey`] — the caller's own when it is the
/// holder, the recorded holder's when an admin overrides — which is exactly
/// what [`Scheduler::extend_lease`] / [`Scheduler::release_lease`] require.
///
/// # Errors
///
/// [`AuthzError::NotFound`] if no such lease is active, [`AuthzError::Denied`]
/// if the caller neither holds it nor administers its org. Callers must render
/// both identically ([`AuthzError::lease_message`]).
pub async fn require_lease_control(
    db: &Db,
    sched: &Scheduler,
    subject: &Subject,
    lease: LeaseId,
) -> Result<SubjectKey, AuthzError> {
    let holder = sched.lease_holder(lease).ok_or(AuthzError::NotFound)?.clone();
    // Cross-org leases are invisible, not merely forbidden.
    if holder.org != subject.org {
        return Err(AuthzError::NotFound);
    }
    if holder.key() == subject.key() {
        return Ok(holder.key());
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
        let mut s = Scheduler::new(Policy::default());
        s.upsert_board(board(&holder.org.0, "b1"));
        let fleet_core::scheduler::LeaseDecision::Granted(g) =
            s.request_lease(holder.clone(), lease_req("b1"), 1000)
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
}
