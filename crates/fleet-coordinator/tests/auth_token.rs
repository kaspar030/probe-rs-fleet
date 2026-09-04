//! `POST /auth/token`: the JSON credential-exchange endpoint.
//!
//! This is the one HTTP (non-`WebSocket`) surface a node touches, and the only
//! place an auth key is redeemable. The properties that matter:
//!
//! * a valid key mints a node token **and** creates the `node` row, in the key's
//!   org;
//! * the minted token then authenticates a real `/agent` upgrade — the exchange
//!   is not merely returning a plausible-looking string;
//! * single-use means single use, and expiry is enforced;
//! * a session token can be refreshed, and refreshing retires the old one.

mod common;

use common::TestCoordinator;

use fleet_auth::api::TokenResponse;
use fleet_auth::{OpaqueToken, TokenKind};
use fleet_proto::ids::{AgentId, Role};

fn auth_key_body(key: &str, node_name: &str, tags: &[&str]) -> String {
    serde_json::json!({
        "grant_type": "auth_key",
        "auth_key": key,
        "node_name": node_name,
        "tags": tags,
    })
    .to_string()
}

fn refresh_body(token: &str) -> String {
    serde_json::json!({ "grant_type": "refresh", "session_token": token }).to_string()
}

#[tokio::test]
async fn a_valid_auth_key_mints_a_working_node_token() {
    let fleet = TestCoordinator::start().await;
    let key = fleet
        .seed_auth_key("acme", &["rack-1".to_owned()], true, None)
        .await;

    let (status, body) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(auth_key_body(&key, "rpi-lab-1", &["nrf52"])),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    let resp: TokenResponse = serde_json::from_str(&body).unwrap();

    assert_eq!(resp.org, "acme");
    assert!(resp.token.starts_with("prfn1_"), "expected a node token");
    let node_id = resp.node_id.clone().expect("node_id returned");

    // The capability-token public key must come back: without it the node
    // cannot verify the per-lease tokens the coordinator later mints for it.
    let pubkey = resp
        .coordinator_token_pubkey
        .clone()
        .expect("token pubkey returned");
    assert_eq!(pubkey, fleet.coord.token_pubkey_hex());

    // The node row exists, in the *key's* org, with the union of the key's tags
    // and the node's.
    let (node, org, _) = fleet
        .db()
        .node_by_token_hash(OpaqueToken::parse(&resp.token).unwrap().hash().as_str())
        .await
        .unwrap()
        .expect("node row created");
    assert_eq!(node, AgentId(node_id));
    assert_eq!(org.0, "acme");

    // ... and the minted token authenticates a real upgrade. This is the step
    // that makes the exchange meaningful rather than decorative.
    assert_eq!(fleet.upgrade_status("/agent", Some(&resp.token)).await, 101);
}

#[tokio::test]
async fn a_single_use_key_is_consumed_exactly_once() {
    let fleet = TestCoordinator::start().await;
    let key = fleet.seed_auth_key("default", &[], true, None).await;

    let (status, _) = fleet
        .http("POST", "/auth/token", Some(auth_key_body(&key, "a", &[])))
        .await;
    assert_eq!(status, 200);

    let (status, _) = fleet
        .http("POST", "/auth/token", Some(auth_key_body(&key, "b", &[])))
        .await;
    assert_eq!(status, 401, "a single-use key must not be redeemable twice");
}

#[tokio::test]
async fn a_multi_use_key_enrolls_a_rack() {
    let fleet = TestCoordinator::start().await;
    let key = fleet.seed_auth_key("default", &[], false, None).await;

    for name in ["rpi-1", "rpi-2", "rpi-3"] {
        let (status, body) = fleet
            .http("POST", "/auth/token", Some(auth_key_body(&key, name, &[])))
            .await;
        assert_eq!(status, 200, "{name}: {body}");
    }
}

#[tokio::test]
async fn an_expired_key_is_refused() {
    let fleet = TestCoordinator::start().await;
    let past = i64::try_from(fleet.coord.now()).unwrap() - 1;
    let key = fleet.seed_auth_key("default", &[], true, Some(past)).await;

    let (status, _) = fleet
        .http("POST", "/auth/token", Some(auth_key_body(&key, "a", &[])))
        .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn an_unknown_or_wrong_kind_key_is_refused() {
    let fleet = TestCoordinator::start().await;

    let orphan = OpaqueToken::mint(TokenKind::AuthKey).to_secret_string();
    let (status, _) = fleet
        .http("POST", "/auth/token", Some(auth_key_body(&orphan, "a", &[])))
        .await;
    assert_eq!(status, 401);

    // A session token where an auth key is expected.
    let session = fleet.seed_session("default", "alice", Role::Admin).await;
    let (status, _) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(auth_key_body(&session, "a", &[])),
        )
        .await;
    assert_eq!(status, 401);
}

/// Re-running `agent init` on the same machine must re-enroll it, not litter the
/// org with a second row for one physical Pi — and the old token must stop
/// working, since it is now a credential nobody holds.
#[tokio::test]
async fn re_enrolling_the_same_node_replaces_its_token() {
    let fleet = TestCoordinator::start().await;
    let key = fleet.seed_auth_key("default", &[], false, None).await;

    let (_, body) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(auth_key_body(&key, "rpi-1", &[])),
        )
        .await;
    let first: TokenResponse = serde_json::from_str(&body).unwrap();

    let (_, body) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(auth_key_body(&key, "rpi-1", &[])),
        )
        .await;
    let second: TokenResponse = serde_json::from_str(&body).unwrap();

    assert_eq!(first.node_id, second.node_id, "same machine, same node id");
    assert_ne!(first.token, second.token);
    assert_eq!(fleet.upgrade_status("/agent", Some(&second.token)).await, 101);
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&first.token)).await,
        401,
        "the superseded token must stop working"
    );
}

#[tokio::test]
async fn a_session_can_be_refreshed_and_the_old_token_is_retired() {
    let fleet = TestCoordinator::start().await;
    let old = fleet.seed_session("default", "alice", Role::Admin).await;

    let (status, body) = fleet
        .http("POST", "/auth/token", Some(refresh_body(&old)))
        .await;
    assert_eq!(status, 200, "body: {body}");
    let resp: TokenResponse = serde_json::from_str(&body).unwrap();
    assert!(resp.token.starts_with("prfs1_"));
    assert!(resp.expires.is_some());
    assert_eq!(resp.org, "default");

    assert_eq!(fleet.upgrade_status("/client", Some(&resp.token)).await, 101);
    // Refresh replaces: a stolen old token has a strictly bounded life even if
    // the theft is never noticed.
    assert_eq!(fleet.upgrade_status("/client", Some(&old)).await, 401);
}

#[tokio::test]
async fn a_node_token_cannot_be_refreshed_as_a_session() {
    let fleet = TestCoordinator::start().await;
    let (node_token, _) = fleet.seed_node("default", "rpi-1").await;
    let (status, _) = fleet
        .http("POST", "/auth/token", Some(refresh_body(&node_token)))
        .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn malformed_requests_are_bad_requests_not_credentials() {
    let fleet = TestCoordinator::start().await;

    // An unknown grant type is a client mistake, not a credential failure.
    let body = serde_json::json!({ "grant_type": "password", "username": "root" }).to_string();
    let (status, _) = fleet.http("POST", "/auth/token", Some(body)).await;
    assert!(
        (400..500).contains(&status) && status != 401,
        "unknown grant type should be a 4xx client error, got {status}"
    );

    // A missing node name cannot name a row.
    let key = fleet.seed_auth_key("default", &[], true, None).await;
    let (status, _) = fleet
        .http("POST", "/auth/token", Some(auth_key_body(&key, "  ", &[])))
        .await;
    assert_eq!(status, 400);
}
