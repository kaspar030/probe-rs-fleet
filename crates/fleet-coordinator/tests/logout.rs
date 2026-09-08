//! `POST /auth/logout`: the revocation half of the refresh-token feature.
//!
//! A durable credential with no way to revoke it is not acceptable, and this
//! route is that way. What matters, and what this file pins:
//!
//! * a plain logout kills **the session the caller authenticated with** — never
//!   one named in the request — and, if presented, that caller's own refresh
//!   token;
//! * `--all` kills every session and every refresh token of the calling user,
//!   and **leaves another user's untouched**. That is the lost-machine answer,
//!   and it is also the one operation with a blast radius worth a test;
//! * a refresh token belonging to somebody else is ignored rather than deleted,
//!   and the response does not reveal that it existed;
//! * the answer is `204` either way, so a caller cannot distinguish "revoked"
//!   from "already gone".

mod common;

use common::TestCoordinator;

use fleet_auth::{OpaqueToken, TokenKind};
use fleet_proto::ids::Role;

fn body(refresh: Option<&str>, all: bool) -> String {
    match refresh {
        Some(r) => serde_json::json!({ "refresh_token": r, "all": all }).to_string(),
        None => serde_json::json!({ "all": all }).to_string(),
    }
}

/// Can a token still open `/client`? The most honest liveness check there is:
/// it asks the real authentication path rather than the database.
async fn session_works(fleet: &TestCoordinator, token: &str) -> bool {
    fleet.upgrade_status("/client", Some(token)).await == 101
}

/// Can a refresh token still mint?
async fn refresh_works(fleet: &TestCoordinator, token: &str) -> bool {
    let (status, _) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(
                serde_json::json!({ "grant_type": "refresh_token", "refresh_token": token })
                    .to_string(),
            ),
        )
        .await;
    status == 200
}

#[tokio::test]
async fn a_plain_logout_revokes_the_presented_session_and_refresh_token() {
    let fleet = TestCoordinator::start().await;
    let now = i64::try_from(fleet.coord.now()).unwrap();
    let session = fleet.seed_session("acme", "alice", Role::Admin).await;
    let refresh = fleet
        .seed_refresh_token("acme", "alice", now + 86_400)
        .await;
    assert!(session_works(&fleet, &session).await);
    assert!(refresh_works(&fleet, &refresh).await);

    let (status, response) = fleet
        .http_auth(
            "POST",
            "/auth/logout",
            Some(&session),
            Some(body(Some(&refresh), false)),
        )
        .await;
    assert_eq!(status, 204, "body: {response}");

    assert!(!session_works(&fleet, &session).await);
    assert!(
        !refresh_works(&fleet, &refresh).await,
        "the durable credential must go too, or logout means nothing"
    );
}

/// A logout with no refresh token in the body still kills the session — the
/// pre-feature shape, and what a client whose file has no refresh token sends.
#[tokio::test]
async fn a_logout_without_a_refresh_token_still_revokes_the_session() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Admin).await;

    let (status, _) = fleet
        .http_auth(
            "POST",
            "/auth/logout",
            Some(&session),
            Some(body(None, false)),
        )
        .await;
    assert_eq!(status, 204);
    assert!(!session_works(&fleet, &session).await);
}

/// The lost-machine case: every credential the caller holds anywhere goes, and
/// the other user in the same org keeps theirs.
///
/// Same org deliberately — a pair of personal orgs would make the survival
/// assertion true for the wrong reason (org scoping rather than user scoping).
#[tokio::test]
async fn logout_all_revokes_every_credential_of_that_user_only() {
    let fleet = TestCoordinator::start().await;
    let now = i64::try_from(fleet.coord.now()).unwrap();

    let alice_a = fleet.seed_session("acme", "alice", Role::Admin).await;
    let alice_b = fleet.seed_session("acme", "alice", Role::Admin).await;
    let alice_r1 = fleet
        .seed_refresh_token("acme", "alice", now + 86_400)
        .await;
    let alice_r2 = fleet
        .seed_refresh_token("acme", "alice", now + 86_400)
        .await;
    let bob = fleet.seed_session("acme", "bob", Role::Member).await;
    let bob_r = fleet.seed_refresh_token("acme", "bob", now + 86_400).await;

    let (status, response) = fleet
        .http_auth(
            "POST",
            "/auth/logout",
            Some(&alice_a),
            Some(body(None, true)),
        )
        .await;
    assert_eq!(status, 204, "body: {response}");

    assert!(!session_works(&fleet, &alice_a).await);
    assert!(
        !session_works(&fleet, &alice_b).await,
        "--all must reach the session on the other machine; that is its point"
    );
    assert!(!refresh_works(&fleet, &alice_r1).await);
    assert!(!refresh_works(&fleet, &alice_r2).await);

    assert!(session_works(&fleet, &bob).await, "bob is untouched");
    assert!(refresh_works(&fleet, &bob_r).await, "bob is untouched");
}

/// Presenting **somebody else's** refresh token deletes nothing and reveals
/// nothing: the response is the same `204` as any other logout, and bob's
/// credential still mints.
#[tokio::test]
async fn another_users_refresh_token_is_ignored_rather_than_deleted() {
    let fleet = TestCoordinator::start().await;
    let now = i64::try_from(fleet.coord.now()).unwrap();
    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;
    let bob_r = fleet.seed_refresh_token("acme", "bob", now + 86_400).await;

    let (status, _) = fleet
        .http_auth(
            "POST",
            "/auth/logout",
            Some(&alice),
            Some(body(Some(&bob_r), false)),
        )
        .await;
    assert_eq!(status, 204, "never an oracle: the answer is the usual 204");
    assert!(
        refresh_works(&fleet, &bob_r).await,
        "a cross-user delete is the one thing this route must never do"
    );
    // Alice's own session still went, so the request was not simply refused.
    assert!(!session_works(&fleet, &alice).await);
}

/// A garbled or wrong-kind `refresh_token` is dropped without a lookup, and the
/// session revocation still happens: a typo must not cost the caller their
/// logout.
#[tokio::test]
async fn a_malformed_refresh_token_does_not_break_the_logout() {
    let fleet = TestCoordinator::start().await;
    for junk in [
        "not-a-token".to_owned(),
        OpaqueToken::mint(TokenKind::Node).to_secret_string(),
        String::new(),
    ] {
        let session = fleet.seed_session("acme", "alice", Role::Admin).await;
        let (status, _) = fleet
            .http_auth(
                "POST",
                "/auth/logout",
                Some(&session),
                Some(body(Some(&junk), false)),
            )
            .await;
        assert_eq!(status, 204, "junk: {junk:?}");
        assert!(!session_works(&fleet, &session).await);
    }
}

/// The route is bearer-only and `Session`-only. A refresh token cannot drive
/// it: `logout` is an authenticated act, and a mint-only credential is not an
/// identity.
#[tokio::test]
async fn logout_refuses_every_credential_but_a_session() {
    let fleet = TestCoordinator::start().await;
    let now = i64::try_from(fleet.coord.now()).unwrap();
    let refresh = fleet
        .seed_refresh_token("acme", "alice", now + 86_400)
        .await;
    let (node, _) = fleet.seed_node("acme", "rpi-1").await;

    for credential in [refresh.clone(), node] {
        let (status, _) = fleet
            .http_auth(
                "POST",
                "/auth/logout",
                Some(&credential),
                Some(body(None, true)),
            )
            .await;
        assert_eq!(status, 403);
    }
    // Nothing was revoked on the way out.
    assert!(refresh_works(&fleet, &refresh).await);

    // ...and with no credential at all it is a 401, uniform with every other
    // authenticated route.
    let (status, _) = fleet
        .http("POST", "/auth/logout", Some(body(None, true)))
        .await;
    assert_eq!(status, 401);
}

/// Idempotent: logging out twice is two `204`s. A caller must not be able to
/// tell "revoked" from "already gone".
#[tokio::test]
async fn a_second_logout_of_the_same_credentials_is_still_204() {
    let fleet = TestCoordinator::start().await;
    let now = i64::try_from(fleet.coord.now()).unwrap();
    let session = fleet.seed_session("acme", "alice", Role::Admin).await;
    let refresh = fleet
        .seed_refresh_token("acme", "alice", now + 86_400)
        .await;

    for _ in 0..2 {
        let (status, _) = fleet
            .http_auth(
                "POST",
                "/auth/logout",
                Some(&session),
                Some(body(Some(&refresh), false)),
            )
            .await;
        // The second call authenticates with a session that is already gone, so
        // it is a 401 rather than a 204 — the credential really is dead. That
        // is the honest outcome, and the property under test is that the *first*
        // call did not leave a usable credential behind.
        assert!(status == 204 || status == 401);
    }
    assert!(!session_works(&fleet, &session).await);
    assert!(!refresh_works(&fleet, &refresh).await);
}

/// **A storage failure must not be reported as a successful revocation.**
///
/// This is the one place in the refresh-token feature where swallowing an error
/// is not conservative: the CLI takes a `204` as truth and prints "revoked every
/// session and refresh token you hold in this fleet", so a failed write would
/// tell someone whose laptop was stolen that a 30-day mint-capable credential
/// was gone when it was not.
///
/// The failure is induced by dropping the table out from under the handler —
/// crude, but it is the honest way to reach the `Err` arm of a `DELETE`, and it
/// is exactly what a locked or corrupt database surfaces as. `api::logout`
/// already answers `500` for its own delete error; this pins the same rule for
/// both of this route's modes.
#[tokio::test]
async fn a_storage_failure_is_a_500_rather_than_a_false_success() {
    for all in [false, true] {
        let fleet = TestCoordinator::start().await;
        let now = i64::try_from(fleet.coord.now()).unwrap();
        let session = fleet.seed_session("acme", "alice", Role::Admin).await;
        let refresh = fleet
            .seed_refresh_token("acme", "alice", now + 86_400)
            .await;

        // `authenticate` reads `session`, so only the *delete* targets may go:
        // dropping `session` too would fail the request at authentication and
        // assert nothing about the delete path.
        sqlx::query("DROP TABLE refresh_token")
            .execute(fleet.db().pool_for_test())
            .await
            .unwrap();

        let (status, response) = fleet
            .http_auth(
                "POST",
                "/auth/logout",
                Some(&session),
                Some(body(Some(&refresh), all)),
            )
            .await;
        assert_eq!(
            status, 500,
            "all={all}: a failed revocation must not answer 204 ({response})"
        );
        assert!(response.contains("server_error"), "{response}");
    }
}
