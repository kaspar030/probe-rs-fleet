//! Where a caller's `Subject` — and the org it acts in — comes from.
//!
//! `forgs_http::authenticate_request` is the only place a credential becomes
//! a subject; fleet adds the **acting org** (`http::acting_subject`). These
//! tests pin the properties that make that safe:
//!
//! * a user session acts in its **personal** org by default, or in the org a
//!   request names (`?org=<name>` or `?org=<id>` — both spellings work);
//! * membership is checked **per request**: naming an org the caller is not
//!   a member of, or one that does not exist, is the same `403` (no
//!   org-existence oracle), and a revoked membership stops working at once;
//! * the role is the one held in the *acting* org;
//! * a node token resolves into its **node row's** org and is refused on the
//!   operator plane; a workload acts in no org and may not ask for one;
//! * a grantee named by username resolves to the user's immutable id, and an
//!   unknown one is refused by name.

mod common;

use common::TestCoordinator;

use fleet_coordinator::FleetRole;
use fleet_proto::ids::SubjectKind;
use fleet_proto::token::AllowedOp;
use fleet_wire::{CoordToSidecar, SidecarToCoord};

/// Open a `/client` session at `path` and issue one operator request.
async fn operator_request(
    fleet: &TestCoordinator,
    path: &str,
    token: &str,
    msg: SidecarToCoord,
) -> CoordToSidecar {
    let (tx, rx) = fleet.dial(path, token).await.expect("upgrade accepted");
    let session = fleet_sidecar::transport::CoordSession::start(Box::new(tx), Box::new(rx))
        .await
        .expect("handshake");
    session.request(msg).await.expect("reply")
}

/// The board names a `ListBoards` at `path` returns.
async fn board_names(fleet: &TestCoordinator, path: &str, token: &str) -> Vec<String> {
    match operator_request(fleet, path, token, SidecarToCoord::ListBoards).await {
        CoordToSidecar::BoardList(list) => {
            let mut names: Vec<String> = list.into_iter().map(|b| b.board.name.clone()).collect();
            names.sort();
            names
        }
        other => panic!("expected BoardList, got {other:?}"),
    }
}

/// A member names its team org by **name** or by **id**; without `?org=` the
/// same session acts in its personal org. Board *visibility* spans every org
/// the user belongs to (`Access::member_of`), so the acting org is observed
/// where it matters: the org an admin action lands in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_selects_its_org_by_name_or_id_and_defaults_to_personal() {
    let fleet = TestCoordinator::start().await;
    let token = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let acme = fleet.org("acme").await;
    let personal = fleet.personal_org("alice").await;
    fleet.user("bob").await;
    fleet
        .seed_board(&acme, "rpi-1", "team-dk", &["nrf52"])
        .await;
    fleet
        .seed_board(&personal, "laptop", "own-dk", &["nrf52"])
        .await;

    // Both memberships' boards are visible whichever org is acting.
    for path in ["/client", "/client?org=acme"] {
        assert_eq!(
            board_names(&fleet, path, &token).await,
            ["own-dk", "team-dk"]
        );
    }
    // A stranger sees neither.
    let (mallory, _, _) = fleet.seed_user("mallory").await;
    assert!(board_names(&fleet, "/client", &mallory).await.is_empty());

    let grant = SidecarToCoord::GrantCreate {
        subject: "bob".to_owned(),
        selector: "tag=nrf52".to_owned(),
        ops: vec![AllowedOp::Attach],
        expires: Some(fleet.now() + 3_600),
    };
    for (path, expected) in [
        ("/client?org=acme".to_owned(), &acme),
        (format!("/client?org={}", acme.0), &acme),
        ("/client".to_owned(), &personal),
    ] {
        match operator_request(&fleet, &path, &token, grant.clone()).await {
            CoordToSidecar::GrantCreated(g) => assert_eq!(&g.org, expected, "{path}"),
            other => panic!("{path}: expected GrantCreated, got {other:?}"),
        }
    }

    // The same on the JSON API: `/api/v1/org` reports the acting org.
    for (query, expected) in [
        (String::new(), (&personal, "alice")),
        ("?org=acme".to_owned(), (&acme, "acme")),
        (format!("?org={}", acme.0), (&acme, "acme")),
    ] {
        let (status, body) = fleet
            .http_auth("GET", &format!("/api/v1/org{query}"), Some(&token), None)
            .await;
        assert_eq!(status, 200, "{query}: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["id"], expected.0 .0, "{query}: {body}");
        assert_eq!(v["name"], expected.1, "{query}: {body}");
    }
}

/// Naming an org one is not a member of, and naming one that does not exist,
/// are the **same** refusal — on `/client` and on `/api/v1`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_member_and_an_unknown_org_are_refused_identically() {
    let fleet = TestCoordinator::start().await;
    fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let (mallory, _, _) = fleet.seed_user("mallory").await;
    let acme = fleet.org("acme").await;
    let alice_personal = fleet.personal_org("alice").await;

    let orgs = [
        "acme".to_owned(),
        acme.0.clone(),
        "alice".to_owned(),
        alice_personal.0.clone(),
        "no-such-org".to_owned(),
        // A well-formed id that names nothing.
        "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_owned(),
    ];
    let mut bodies = Vec::new();
    for org in &orgs {
        assert_eq!(
            fleet
                .upgrade_status(&format!("/client?org={org}"), Some(&mallory))
                .await,
            403,
            "/client?org={org}"
        );
        let (status, body) = fleet
            .http_auth(
                "GET",
                &format!("/api/v1/org?org={org}"),
                Some(&mallory),
                None,
            )
            .await;
        assert_eq!(status, 403, "/api/v1/org?org={org}: {body}");
        bodies.push(body);
    }
    assert!(
        bodies.windows(2).all(|w| w[0] == w[1]),
        "the refusals must be byte-identical: {bodies:?}"
    );

    // Their own personal org works, so the refusals are about membership.
    assert_eq!(
        fleet
            .upgrade_status("/client?org=mallory", Some(&mallory))
            .await,
        101
    );
}

/// The role is the one held in the **acting** org: a member lists boards but
/// may not read that org's audit log, while in its personal org (where it is
/// admin) it may.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_role_is_the_one_held_in_the_acting_org() {
    let fleet = TestCoordinator::start().await;
    let bob = fleet.seed_session("acme", "bob", FleetRole::Member).await;
    let logs = || SidecarToCoord::Logs {
        board: None,
        follow: false,
    };

    board_names(&fleet, "/client?org=acme", &bob).await;
    match operator_request(&fleet, "/client?org=acme", &bob, logs()).await {
        CoordToSidecar::Error { .. } => {}
        other => panic!("a member must not read the audit log, got {other:?}"),
    }
    match operator_request(&fleet, "/client", &bob, logs()).await {
        CoordToSidecar::LogLines(_) => {}
        other => panic!("an admin of its personal org reads its log, got {other:?}"),
    }
}

/// **Membership is checked per request.** A session outlives a membership
/// revocation — and from then on authenticates perfectly and acts in that org
/// not at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_membership_stops_working_at_once() {
    let fleet = TestCoordinator::start().await;
    let token = fleet.seed_session("acme", "carol", FleetRole::Member).await;
    assert_eq!(
        fleet.upgrade_status("/client?org=acme", Some(&token)).await,
        101
    );

    let acme = fleet.org("acme").await;
    let carol = fleet.user("carol").await;
    let removed = fleet
        .db()
        .forgs()
        .scoped(fleet_coordinator::subject::ns_of(&acme).unwrap())
        .remove_member(&forgs::SubjectKey::user(carol))
        .await
        .unwrap();
    assert!(removed);

    // The credential is still valid ...
    assert_eq!(fleet.upgrade_status("/client", Some(&token)).await, 101);
    // ... but no longer acts in `acme`.
    assert_eq!(
        fleet.upgrade_status("/client?org=acme", Some(&token)).await,
        403
    );
}

/// A node token on the operator plane is a wrong-kind `403`, audited under
/// the node's own subject — whose namespace is the **node row's** org, never
/// the configured default.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_token_resolves_into_its_own_org_and_is_refused_on_client() {
    let fleet = TestCoordinator::start().await;
    let default = fleet.org(&fleet.coord.config().default_org.clone()).await;
    let acme = fleet.org("acme").await;
    assert_ne!(default, acme);

    let (node_token, node) = fleet.seed_node("acme", "rpi-1").await;
    assert_eq!(
        fleet.upgrade_status("/client", Some(&node_token)).await,
        403
    );
    assert_eq!(
        fleet
            .upgrade_status("/client?org=acme", Some(&node_token))
            .await,
        403
    );

    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT action, subject FROM forgs_audit WHERE action = 'auth.wrong_kind'")
            .fetch_all(fleet.db().pool_for_test())
            .await
            .unwrap();
    let expected = format!("{}/node:{}", acme.0, node.0);
    assert!(
        rows.iter()
            .any(|(_, s)| s.as_deref() == Some(expected.as_str())),
        "the rejection must be audited as {expected}; got {rows:?}"
    );
    assert!(
        !rows
            .iter()
            .any(|(_, s)| s.as_deref().is_some_and(|s| s.starts_with(&default.0))),
        "nothing may be attributed to the configured default org; got {rows:?}"
    );
}

/// A workload acts in **no** org: it reaches boards only through grants, and
/// asking for an org — even the one that granted it — is a `403`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_workload_acts_in_no_org_and_may_not_ask_for_one() {
    let fleet = TestCoordinator::start().await;
    fleet
        .seed_workload_grant("acme", "o/r", "tag=nrf52", &[AllowedOp::Attach], None)
        .await;
    let token = fleet.seed_workload_token("o/r", fleet.now() + 3_600).await;
    assert_eq!(fleet.upgrade_status("/client", Some(&token)).await, 101);
    assert_eq!(
        fleet.upgrade_status("/client?org=acme", Some(&token)).await,
        403
    );
}

/// A grantee named by **username** resolves to the user's immutable id
/// (`user:<ULID>`), and an unknown username is refused by name rather than
/// becoming a grant to a subject nobody can authenticate as.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grantee_username_resolves_to_the_immutable_user_id() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let bob = fleet.user("bob").await;
    let grant = |subject: &str| SidecarToCoord::GrantCreate {
        subject: subject.to_owned(),
        selector: "tag=nrf52".to_owned(),
        ops: vec![AllowedOp::Attach],
        expires: Some(fleet.now() + 3_600),
    };

    match operator_request(&fleet, "/client?org=acme", &alice, grant("bob")).await {
        CoordToSidecar::GrantCreated(g) => {
            assert_eq!(g.subject.kind(), SubjectKind::User);
            assert_eq!(g.subject.to_string(), format!("user:{bob}"));
            assert_eq!(g.subject_display.as_deref(), Some("bob"));
        }
        other => panic!("expected GrantCreated, got {other:?}"),
    }

    match operator_request(&fleet, "/client?org=acme", &alice, grant("nobody")).await {
        CoordToSidecar::Error { message } => {
            assert!(message.contains("no such user `nobody`"), "{message}");
        }
        other => panic!("an unknown username must be refused, got {other:?}"),
    }
}
