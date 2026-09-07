//! The single `Subject` construction site.
//!
//! Task 3445 established the invariant that a `Subject` is built from wire input
//! in exactly one place, so every authorization check downstream consumes a
//! value whose provenance is known. Bearer auth replaced that function's *body*
//! (certificate CN → token lookup) without changing its shape, and these tests
//! pin the properties that make the replacement equivalent:
//!
//! * a session token resolves to a **user** subject in the session's org;
//! * a node token resolves to a **node** subject in the *node row's* org — never
//!   a configured default, which is what stops a token from being replayed into
//!   another tenant;
//! * an authenticated user with no `member` row is denied by construction. That
//!   last one is the trap: minting a session token without provisioning
//!   membership yields a credential that authenticates perfectly and then fails
//!   every authorization check, so `ctl list` fails closed on a valid token.

mod common;

use common::TestCoordinator;

use fleet_proto::ids::{OrgId, Role, Subject, SubjectKind};
use fleet_wire::{CoordToSidecar, SidecarToCoord};

/// Open a `/client` session and issue one operator request.
async fn operator_request(
    fleet: &TestCoordinator,
    token: &str,
    msg: SidecarToCoord,
) -> CoordToSidecar {
    let (tx, rx) = fleet
        .dial("/client", token)
        .await
        .expect("upgrade accepted");
    let session = fleet_sidecar::transport::CoordSession::start(Box::new(tx), Box::new(rx))
        .await
        .expect("handshake");
    session.request(msg).await.expect("reply")
}

/// A properly provisioned admin can exercise the operator surface. This is the
/// baseline the fail-closed cases below are measured against.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provisioned_admin_can_list_the_fleet() {
    let fleet = TestCoordinator::start().await;
    let token = fleet.seed_session("default", "alice", Role::Admin).await;

    match operator_request(&fleet, &token, SidecarToCoord::ListBoards).await {
        CoordToSidecar::BoardList(_) => {}
        other => panic!("expected BoardList, got {other:?}"),
    }
}

/// A `member` can use the fleet but not read the audit log — the role split from
/// §6.5, reached through a bearer token rather than a certificate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn role_is_honoured_for_a_token_authenticated_user() {
    let fleet = TestCoordinator::start().await;
    let member = fleet.seed_session("default", "bob", Role::Member).await;

    match operator_request(&fleet, &member, SidecarToCoord::ListBoards).await {
        CoordToSidecar::BoardList(_) => {}
        other => panic!("a member must be able to list boards, got {other:?}"),
    }

    match operator_request(
        &fleet,
        &member,
        SidecarToCoord::Logs {
            board: None,
            follow: false,
        },
    )
    .await
    {
        CoordToSidecar::Error { .. } => {}
        other => panic!("a member must not read the audit log, got {other:?}"),
    }
}

/// **The fail-closed trap.** A session row exists, so the token authenticates —
/// but there is no `member` row, so authorization denies everything. Minting a
/// session without provisioning membership must therefore be impossible in the
/// mint path; this test documents what happens when it is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_authenticated_non_member_is_denied() {
    let fleet = TestCoordinator::start().await;
    let org = OrgId("default".to_owned());

    // A user row without a membership row: authenticates, authorizes nothing.
    let token = fleet_auth::OpaqueToken::mint(fleet_auth::TokenKind::Session);
    let now = i64::try_from(fleet.coord.now()).unwrap();
    fleet
        .db()
        .ensure_user_member(&org, "carol", Role::Member)
        .await
        .unwrap();
    // Remove the membership, keeping the user.
    sqlx::query("DELETE FROM member WHERE user_id = 'carol'")
        .execute(fleet.db().pool_for_test())
        .await
        .unwrap();
    fleet
        .db()
        .insert_session(token.hash().as_str(), &org, "carol", now, now + 3_600)
        .await
        .unwrap();
    let token = token.to_secret_string();

    // The upgrade succeeds — the credential is valid.
    assert_eq!(fleet.upgrade_status("/client", Some(&token)).await, 101);

    // ... and every authorization check denies.
    match operator_request(&fleet, &token, SidecarToCoord::ListBoards).await {
        CoordToSidecar::Error { .. } => {}
        other => panic!("a non-member must be denied, got {other:?}"),
    }
}

/// The org a credential resolves into comes from **its own row**, never from
/// `config.default_org`.
///
/// Exercised through the wrong-kind rejection, because that is the one
/// authenticated path that audits unconditionally: a node token presented on the
/// operator plane matched a `node` row first, so an org *is* resolvable, and the
/// audit row must land in that node's org. If the construction site ever
/// defaulted the org instead, this row would appear under `default`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_credential_resolves_into_its_own_org_not_the_configured_default() {
    let fleet = TestCoordinator::start().await;
    assert_eq!(
        fleet.coord.config().default_org.0,
        "default",
        "the point of this test is that `acme` != the configured default"
    );

    let (node_token, node) = fleet.seed_node("acme", "rpi-1").await;
    assert_eq!(
        fleet.upgrade_status("/client", Some(&node_token)).await,
        403
    );

    let rows: Vec<(String, Option<String>, String)> =
        sqlx::query_as("SELECT org_id, subject, action FROM audit_log")
            .fetch_all(fleet.db().pool_for_test())
            .await
            .unwrap();
    assert!(
        rows.iter().any(|(org, subject, action)| org == "acme"
            && subject.as_deref() == Some(node.0.as_str())
            && action == "auth.wrong_kind"),
        "the rejection must be audited in the node row's org; got {rows:?}"
    );
    assert!(
        !rows.iter().any(|(org, _, _)| org == "default"),
        "nothing may be attributed to the configured default org; got {rows:?}"
    );
}

/// A session's subject key is `<org>/user:<id>` — the org from the session row,
/// the id from the user, and nothing the client asserted. (The deleted
/// `PROBE_RS_FLEET_SUBJECT_ID` used to let a client supply that id.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_subject_is_org_scoped_and_client_supplied_ids_are_gone() {
    let fleet = TestCoordinator::start().await;
    let token = fleet.seed_session("acme", "alice", Role::Admin).await;

    // The session works and is scoped to `acme`.
    match operator_request(&fleet, &token, SidecarToCoord::ListBoards).await {
        CoordToSidecar::BoardList(_) => {}
        other => panic!("expected BoardList, got {other:?}"),
    }

    let expected = Subject::new(OrgId("acme".to_owned()), SubjectKind::User, "alice");
    assert_eq!(expected.key().to_string(), "acme/user:alice");

    // The same login in another org is a different subject entirely.
    let other = Subject::new(OrgId("default".to_owned()), SubjectKind::User, "alice");
    assert_ne!(expected.key(), other.key());
}
