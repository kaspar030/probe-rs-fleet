//! Authentication and route-authorization over the `WebSocket` upgrade.
//!
//! This is the coverage that replaces "a cert not signed by the CA is rejected"
//! from the deleted mTLS tests. Under bearer auth the equivalent questions are:
//! is the credential present, well-formed, known, unexpired — and is it the
//! *right kind* for the route it was presented on.
//!
//! Credentials are verified by forgs (`forgs_http::authenticate_request`);
//! what fleet owns, and what this file pins, is each route's allowlist of
//! token kinds: `/agent` takes node tokens (`prfn1_`) only, `/client` takes
//! user sessions and workload tokens, `/delegate` takes neither (only a
//! capability token), and the browser's session cookie opens none of them.
//!
//! Two properties are asserted throughout:
//!
//! * **401 vs. 403 is about the route, not the credential.** An absent, garbled,
//!   unknown or expired credential is a 401. A perfectly valid credential of the
//!   wrong kind for the route is a 403: the caller's problem is the door, not
//!   the key.
//! * **No oracle.** The rejection bodies are identical whatever the reason;
//!   the moment they diverge an endpoint becomes a credential-enumeration tool.

mod common;

use common::TestCoordinator;

use forgs::TokenKind;
use probefleet_coordinator::FleetRole;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

/// A `POST /node/enroll` body.
fn enroll_body(key: &str, name: &str) -> String {
    serde_json::json!({ "auth_key": key, "node_name": name }).to_string()
}

#[tokio::test]
async fn no_credential_is_rejected_on_both_planes() {
    let fleet = TestCoordinator::start().await;
    assert_eq!(fleet.upgrade_status("/agent", None).await, 401);
    assert_eq!(fleet.upgrade_status("/client", None).await, 401);
}

#[tokio::test]
async fn garbage_credentials_are_rejected() {
    let fleet = TestCoordinator::start().await;
    for garbage in ["nonsense", "prfn1_not-base64!!", "prfs1_", "Bearer"] {
        assert_eq!(
            fleet.upgrade_status("/agent", Some(garbage)).await,
            401,
            "`{garbage}` must not authenticate"
        );
        assert_eq!(fleet.upgrade_status("/client", Some(garbage)).await, 401);
    }
}

/// A well-formed token that matches no row: the shape is right, the credential
/// is not.
#[tokio::test]
async fn a_well_formed_but_unknown_token_is_rejected() {
    let fleet = TestCoordinator::start().await;
    let format = fleet.auth().format();
    let orphan_node = format
        .mint(probefleet_coordinator::identity::node_token_kind(format))
        .to_secret_string();
    let orphan_session = format.mint(TokenKind::Session).to_secret_string();
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&orphan_node)).await,
        401
    );
    assert_eq!(
        fleet.upgrade_status("/client", Some(&orphan_session)).await,
        401
    );
}

/// Revocation is deleting the `node` row, so it must fail on the very next
/// connection.
#[tokio::test]
async fn a_revoked_node_cannot_reconnect() {
    let fleet = TestCoordinator::start().await;
    let (token, node) = fleet.seed_node("acme", "rpi-1").await;

    // It works before revocation ...
    assert_eq!(fleet.upgrade_status("/agent", Some(&token)).await, 101);

    // ... and revocation is deleting the row.
    fleet.db().delete_node(&node).await.unwrap();
    assert_eq!(fleet.upgrade_status("/agent", Some(&token)).await, 401);
}

#[tokio::test]
async fn an_expired_session_is_rejected() {
    let fleet = TestCoordinator::start().await;
    let expired = fleet.seed_expired_session("alice").await;
    assert_eq!(fleet.upgrade_status("/client", Some(&expired)).await, 401);

    // A live session for the same user still works, so the rejection is about
    // the expiry and not about the user.
    let live = fleet.session_for("alice").await;
    assert_eq!(fleet.upgrade_status("/client", Some(&live)).await, 101);
}

/// The wrong-kind-for-route case, in both directions. A node token is a valid
/// credential — it just does not open the operator plane, and a session token
/// does not open the node plane. 403, not 401: the credential is fine.
#[tokio::test]
async fn a_node_token_is_forbidden_on_the_client_plane() {
    let fleet = TestCoordinator::start().await;
    let (node_token, _) = fleet.seed_node("acme", "rpi-1").await;
    assert_eq!(
        fleet.upgrade_status("/client", Some(&node_token)).await,
        403,
        "a node token must not open the operator plane"
    );
    // ... while opening its own plane perfectly well.
    assert_eq!(fleet.upgrade_status("/agent", Some(&node_token)).await, 101);
}

#[tokio::test]
async fn a_session_token_is_forbidden_on_the_agent_plane() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&session)).await,
        403,
        "a user session token must not impersonate a node"
    );
    assert_eq!(fleet.upgrade_status("/client", Some(&session)).await, 101);
    assert_eq!(
        fleet
            .upgrade_status("/client?org=acme", Some(&session))
            .await,
        101
    );
}

/// A workload token opens `/client` (acting in no org) and nothing else.
#[tokio::test]
async fn a_workload_token_is_forbidden_on_the_agent_plane() {
    let fleet = TestCoordinator::start().await;
    let workload = fleet
        .seed_workload_token("octo/firmware", fleet.now() + 600)
        .await;
    assert_eq!(fleet.upgrade_status("/agent", Some(&workload)).await, 403);
    assert_eq!(fleet.upgrade_status("/client", Some(&workload)).await, 101);
    // A workload acts in no org; naming one is refused.
    assert_eq!(
        fleet
            .upgrade_status("/client?org=acme", Some(&workload))
            .await,
        403
    );
}

/// An API key is redeemed at `POST /node/enroll`; it is not a connection
/// credential. Presenting one on a `WebSocket` upgrade is a 403 even though the
/// key itself is perfectly valid.
#[tokio::test]
async fn an_api_key_cannot_open_a_connection() {
    let fleet = TestCoordinator::start().await;
    let key = fleet.seed_auth_key("acme", &[], true, None).await;
    assert_eq!(fleet.upgrade_status("/agent", Some(&key)).await, 403);
    assert_eq!(fleet.upgrade_status("/client", Some(&key)).await, 403);

    // ... and it is still redeemable afterwards: a rejected upgrade must not
    // consume a single-use key.
    let (status, body) = fleet
        .http("POST", "/node/enroll", Some(enroll_body(&key, "rpi-1")))
        .await;
    assert_eq!(status, 200, "body: {body}");
}

/// A refresh token is a connection credential **nowhere**, and neither it nor
/// a workload token may mint API keys at forgs' `POST /auth/keys` — minting a
/// key with a mint-only or CI credential would be a privilege escalation.
///
/// The refresh token seeded here is entirely valid — it mints a session on the
/// route that is allowed to — which is what makes the 403s meaningful.
#[tokio::test]
async fn refresh_and_workload_tokens_cannot_open_connections_or_mint_keys() {
    let fleet = TestCoordinator::start().await;
    let (_, personal, _) = fleet.seed_user("alice").await;
    let refresh = fleet.seed_refresh_token("alice").await;
    let workload = fleet
        .seed_workload_token("octo/firmware", fleet.now() + 600)
        .await;

    for route in ["/agent", "/client", "/delegate"] {
        let status = fleet.upgrade_status(route, Some(&refresh)).await;
        assert!(
            status == 403 || (route == "/delegate" && status == 401),
            "a refresh token must not open {route} (got {status})"
        );
    }

    for token in [&refresh, &workload] {
        let (status, body) = fleet
            .http_auth(
                "POST",
                "/auth/keys",
                Some(token),
                Some(serde_json::json!({ "action": "list", "namespace": personal.0 }).to_string()),
            )
            .await;
        assert_eq!(status, 403, "body: {body}");
    }

    // `/node/register/approve` too: approving an enrollment is a member act.
    let (status, _) = fleet
        .http_auth(
            "POST",
            "/node/register/approve",
            Some(&refresh),
            Some(
                serde_json::json!({ "user_code": "ABCD-1234", "decision": "inspect" }).to_string(),
            ),
        )
        .await;
    assert_eq!(status, 403);

    // ... and the refresh token is still redeemable afterwards.
    let (status, body) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(
                serde_json::json!({ "grant_type": "refresh_token", "refresh_token": refresh })
                    .to_string(),
            ),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
}

/// The browser's session cookie is accepted on `/api/v1/*` only. A page (or a
/// cross-site `WebSocket`, which carries cookies) must never drive the node,
/// operator or delegate planes with it: without a bearer the upgrade is
/// unauthenticated, 401.
#[tokio::test]
async fn a_session_cookie_opens_no_connection() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let (cookie, csrf) = fleet.browser_session(&session);

    for route in ["/agent", "/client", "/client?org=acme", "/delegate"] {
        assert_eq!(
            fleet
                .upgrade_status_with(route, None, &[("cookie", &cookie), ("x-fleet-csrf", &csrf)])
                .await,
            401,
            "a session cookie must not open {route}"
        );
    }
    // The same session as a bearer does open `/client`: the refusal is about
    // the carrier.
    assert_eq!(fleet.upgrade_status("/client", Some(&session)).await, 101);
}

/// Only the `Bearer` scheme counts. A `Basic` credential — or a bare token with
/// no scheme — is *absent*, not malformed, and gets the same uniform 401.
#[tokio::test]
async fn other_authorization_schemes_do_not_authenticate() {
    let fleet = TestCoordinator::start().await;
    let (node_token, _) = fleet.seed_node("acme", "rpi-1").await;

    let url = format!("{}/agent", fleet.base_url.replace("http://", "ws://"));

    for value in [format!("Basic {node_token}"), node_token.clone()] {
        let mut request = url.as_str().into_client_request().unwrap();
        request
            .headers_mut()
            .insert(http::header::AUTHORIZATION, value.parse().unwrap());
        match tokio_tungstenite::connect_async(request).await {
            Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => {
                assert_eq!(
                    resp.status().as_u16(),
                    401,
                    "`{value}` must not authenticate"
                );
            }
            Ok(_) => panic!("`{value}` must not authenticate"),
            Err(e) => panic!("unexpected dial failure: {e}"),
        }
    }
}

/// **No oracle.** Every 401 body is byte-identical, whatever the underlying
/// reason. If this test ever fails because someone made the errors "more
/// helpful", the endpoint has become a credential-enumeration tool: an attacker
/// can distinguish "this key never existed" from "this key expired", which
/// tells them whether they have found a real one. The helpful detail belongs
/// in the coordinator's log and in the client's own local error text.
#[tokio::test]
async fn rejection_bodies_are_uniform() {
    let fleet = TestCoordinator::start().await;
    let unknown = fleet
        .auth()
        .format()
        .mint(TokenKind::ApiKey)
        .to_secret_string();
    let expired = fleet
        .seed_auth_key("acme", &[], false, Some(fleet.now() - 1))
        .await;
    let spent = fleet.seed_auth_key("acme", &[], true, None).await;
    let (status, _) = fleet
        .http("POST", "/node/enroll", Some(enroll_body(&spent, "rpi-0")))
        .await;
    assert_eq!(status, 200);

    let enroll = futures_util::future::join_all(
        [
            unknown.as_str(),
            expired.as_str(),
            spent.as_str(),
            "garbage",
        ]
        .map(|key| fleet.http("POST", "/node/enroll", Some(enroll_body(key, "rpi-1")))),
    )
    .await;
    for (status, _) in &enroll {
        assert_eq!(*status, 401);
    }
    for (_, body) in &enroll[1..] {
        assert_eq!(
            body, &enroll[0].1,
            "enrollment rejections must not distinguish unknown / expired / spent / malformed"
        );
    }

    // The same on a session-authenticated fleet route.
    let unknown_session = fleet
        .auth()
        .format()
        .mint(TokenKind::Session)
        .to_secret_string();
    let expired_session = fleet.seed_expired_session("alice").await;
    let body = serde_json::json!({ "node_name": "rpi-2" }).to_string();
    let register = futures_util::future::join_all(
        [
            unknown_session.as_str(),
            expired_session.as_str(),
            "garbage",
        ]
        .map(|token| {
            fleet.http_auth(
                "POST",
                "/node/self-register",
                Some(token),
                Some(body.clone()),
            )
        }),
    )
    .await;
    for (status, _) in &register {
        assert_eq!(*status, 401);
    }
    for (_, b) in &register[1..] {
        assert_eq!(
            b, &register[0].1,
            "session rejections must not distinguish unknown / expired / malformed"
        );
    }
}
