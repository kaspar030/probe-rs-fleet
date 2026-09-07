//! Authentication and route-authorization over the `WebSocket` upgrade.
//!
//! This is the coverage that replaces "a cert not signed by the CA is rejected"
//! from the deleted mTLS tests. Under bearer auth the equivalent questions are:
//! is the credential present, well-formed, known, unexpired — and is it the
//! *right kind* for the route it was presented on.
//!
//! Two properties are asserted throughout:
//!
//! * **401 vs. 403 is about the route, not the credential.** An absent, garbled,
//!   unknown or expired credential is a 401. A perfectly valid credential of the
//!   wrong kind for the route is a 403: the caller's problem is the door, not
//!   the key.
//! * **No oracle.** The rejection bodies are identical whatever the reason;
//!   `ws_auth` asserts that too, because the moment they diverge the endpoint
//!   becomes a credential-enumeration tool.

mod common;

use common::TestCoordinator;

use fleet_auth::{OpaqueToken, TokenKind};
use fleet_proto::ids::Role;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;

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
/// is not. This is also the **revoked node** case — revocation is deleting the
/// `node` row — so it must fail on the very next connection.
#[tokio::test]
async fn a_well_formed_but_unknown_token_is_rejected() {
    let fleet = TestCoordinator::start().await;
    let orphan_node = OpaqueToken::mint(TokenKind::Node).to_secret_string();
    let orphan_session = OpaqueToken::mint(TokenKind::Session).to_secret_string();
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&orphan_node)).await,
        401
    );
    assert_eq!(
        fleet.upgrade_status("/client", Some(&orphan_session)).await,
        401
    );
}

#[tokio::test]
async fn a_revoked_node_cannot_reconnect() {
    let fleet = TestCoordinator::start().await;
    let (token, node) = fleet.seed_node("default", "rpi-1").await;

    // It works before revocation ...
    assert_eq!(fleet.upgrade_status("/agent", Some(&token)).await, 101);

    // ... and revocation is deleting the row.
    fleet.db().delete_node(&node).await.unwrap();
    assert_eq!(fleet.upgrade_status("/agent", Some(&token)).await, 401);
}

#[tokio::test]
async fn an_expired_session_is_rejected() {
    let fleet = TestCoordinator::start().await;
    let expired = fleet.seed_expired_session("default", "alice").await;
    assert_eq!(fleet.upgrade_status("/client", Some(&expired)).await, 401);

    // A live session for the same user still works, so the rejection is about
    // the expiry and not about the user.
    let live = fleet.seed_session("default", "alice", Role::Admin).await;
    assert_eq!(fleet.upgrade_status("/client", Some(&live)).await, 101);
}

/// The wrong-kind-for-route case, in both directions. A node token is a valid
/// credential — it just does not open the operator plane, and a session token
/// does not open the node plane. 403, not 401: the credential is fine.
#[tokio::test]
async fn a_node_token_is_forbidden_on_the_client_plane() {
    let fleet = TestCoordinator::start().await;
    let (node_token, _) = fleet.seed_node("default", "rpi-1").await;
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
    let session = fleet.seed_session("default", "alice", Role::Admin).await;
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&session)).await,
        403,
        "a user session token must not impersonate a node"
    );
    assert_eq!(fleet.upgrade_status("/client", Some(&session)).await, 101);
}

/// An auth key is redeemed at `POST /auth/token`; it is not a connection
/// credential. Presenting one on a `WebSocket` upgrade is a 403 even though the
/// key itself is perfectly valid.
#[tokio::test]
async fn an_auth_key_cannot_open_a_connection() {
    let fleet = TestCoordinator::start().await;
    let key = fleet.seed_auth_key("default", &[], true, None).await;
    assert_eq!(fleet.upgrade_status("/agent", Some(&key)).await, 403);
    assert_eq!(fleet.upgrade_status("/client", Some(&key)).await, 403);

    // ... and it is still redeemable afterwards: a rejected upgrade must not
    // consume it.
    let body = serde_json::json!({
        "grant_type": "auth_key",
        "auth_key": key,
        "node_name": "rpi-1",
    })
    .to_string();
    let (status, _) = fleet.http("POST", "/auth/token", Some(body)).await;
    assert_eq!(status, 200);
}

/// Only the `Bearer` scheme counts. A `Basic` credential — or a bare token with
/// no scheme — is *absent*, not malformed, and gets the same uniform 401.
#[tokio::test]
async fn other_authorization_schemes_do_not_authenticate() {
    let fleet = TestCoordinator::start().await;
    let (node_token, _) = fleet.seed_node("default", "rpi-1").await;

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
/// can distinguish "this token never existed" from "this token expired", which
/// tells them whether they have found a real account. The helpful detail belongs
/// in the coordinator's audit log and in the client's own local error text.
#[tokio::test]
async fn rejection_bodies_are_uniform() {
    let fleet = TestCoordinator::start().await;
    let unknown = OpaqueToken::mint(TokenKind::Session).to_secret_string();
    let expired = fleet.seed_expired_session("default", "alice").await;

    let bodies = futures_util::future::join_all([
        fleet.http("POST", "/auth/token", Some(refresh_body(&unknown))),
        fleet.http("POST", "/auth/token", Some(refresh_body(&expired))),
        fleet.http("POST", "/auth/token", Some(refresh_body("garbage"))),
    ])
    .await;

    for (status, _) in &bodies {
        assert_eq!(*status, 401);
    }
    let first = &bodies[0].1;
    for (_, body) in &bodies[1..] {
        assert_eq!(
            body, first,
            "rejection bodies must not distinguish unknown / expired / malformed"
        );
    }
}

fn refresh_body(token: &str) -> String {
    serde_json::json!({ "grant_type": "refresh", "session_token": token }).to_string()
}
