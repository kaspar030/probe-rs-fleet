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

/// Re-running `agent up --auth-key` on the same machine must re-enroll it, not litter the
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

// ---------------------------------------------------------------------------
// Session-based self-registration (`probe-rs-fleet share`, architecture §4.2)
// ---------------------------------------------------------------------------

fn self_register_body(session: &str, node_name: &str, adopt: Option<&str>) -> String {
    let mut body = serde_json::json!({
        "grant_type": "self_register",
        "session_token": session,
        "node_name": node_name,
        "tags": [],
    });
    if let Some(adopt) = adopt {
        body["adopt"] = serde_json::Value::String(adopt.to_owned());
    }
    body.to_string()
}

/// The `share` path end to end: a session token registers the machine as a node
/// in the caller's own org, and — the step that makes the exchange meaningful
/// rather than decorative — the minted node token authenticates a real `/agent`
/// upgrade.
///
/// Also asserts the two properties that make the laptop case work: the node is
/// **owned by the user** (so "my laptop's boards" is expressible and revoking
/// the user cascades), and its adoption policy defaults to `auto` (so plugging
/// in a probe is enough).
#[tokio::test]
async fn a_session_self_registers_a_working_node_owned_by_the_caller() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;

    let (status, body) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(self_register_body(&session, "alice-laptop", None)),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    let resp: TokenResponse = serde_json::from_str(&body).unwrap();

    assert_eq!(resp.org, "acme");
    assert!(resp.token.starts_with("prfn1_"), "expected a node token");
    assert_eq!(
        resp.coordinator_token_pubkey.as_deref(),
        Some(fleet.coord.token_pubkey_hex().as_str()),
        "without the pubkey the node cannot verify per-lease tokens"
    );
    let node_id = resp.node_id.clone().expect("node_id returned");

    // The node token works on the agent plane...
    assert_eq!(fleet.upgrade_status("/agent", Some(&resp.token)).await, 101);
    // ...and only there: the two credentials stay distinct, which is what stops
    // a compromised laptop-as-node from being a compromised account.
    assert_eq!(fleet.upgrade_status("/client", Some(&resp.token)).await, 403);
    assert_ne!(resp.token, session);

    let node = AgentId(node_id);
    assert_eq!(
        fleet.db().node_org_and_policy(&node).await.unwrap(),
        Some((
            fleet_proto::ids::OrgId("acme".to_owned()),
            fleet_proto::AdoptPolicy::Auto
        )),
        "a node created by `share` defaults to auto-adoption"
    );
    assert_eq!(
        fleet.db().node_owner(&node).await.unwrap().as_deref(),
        Some("alice"),
        "the node must be owned by the user who shared it"
    );
}

/// An explicit `--adopt declared` must be honoured: `auto` is only the default.
#[tokio::test]
async fn an_explicit_adopt_policy_is_recorded() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;

    let (status, body) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(self_register_body(&session, "lab-pi", Some("declared"))),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    let resp: TokenResponse = serde_json::from_str(&body).unwrap();
    let node = AgentId(resp.node_id.unwrap());

    assert_eq!(
        fleet.db().node_org_and_policy(&node).await.unwrap().unwrap().1,
        fleet_proto::AdoptPolicy::Declared
    );
}

/// A typo'd policy is a 400, never a silent default. `adopt = "delcared"`
/// quietly meaning `auto` would share probes the operator did not mean to.
#[tokio::test]
async fn an_unrecognised_adopt_policy_is_refused() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;

    for bad in ["delcared", "manual", "AUTO", ""] {
        let (status, _) = fleet
            .http(
                "POST",
                "/auth/token",
                Some(self_register_body(&session, "pi", Some(bad))),
            )
            .await;
        assert_eq!(status, 400, "adopt={bad:?} must be refused");
    }
}

/// Self-registration is self-*approving*, not un-authorized: membership is
/// still required. `authz::require_role` denies a non-member everywhere else,
/// so a node created for one would be an orphan its "owner" could never use.
#[tokio::test]
async fn a_non_member_with_a_valid_session_is_refused() {
    let fleet = TestCoordinator::start().await;
    // A real user with a real session — but in an org they are not a member of.
    // This is the shape of a revoked membership, not a forged token.
    fleet.seed_session("other", "stranger", Role::Member).await;
    let acme = fleet_proto::ids::OrgId("acme".to_owned());
    fleet.db().ensure_org(&acme, "team").await.unwrap();
    let token = OpaqueToken::mint(TokenKind::Session);
    let now = i64::try_from(fleet.coord.now()).unwrap();
    fleet
        .db()
        .insert_session(token.hash().as_str(), &acme, "stranger", now, now + 3_600)
        .await
        .unwrap();
    let session = token.to_secret_string();

    let (status, _) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(self_register_body(&session, "trespasser", None)),
        )
        .await;
    assert_eq!(status, 403);

    // Nothing was created.
    assert!(fleet
        .db()
        .org_of_node(&AgentId("acme/trespasser".to_owned()))
        .await
        .unwrap()
        .is_none());
}

/// A node token where a session is expected. A node re-registering *itself* as
/// a node would be a privilege escalation shaped like a typo.
#[tokio::test]
async fn a_node_token_cannot_self_register() {
    let fleet = TestCoordinator::start().await;
    let (node_token, _) = fleet.seed_node("default", "rpi-1").await;

    let (status, _) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(self_register_body(&node_token, "rpi-2", None)),
        )
        .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn self_registration_needs_a_node_name() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;
    let (status, _) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(self_register_body(&session, "   ", None)),
        )
        .await;
    assert_eq!(status, 400);
}

/// Re-running `share` on the same machine re-enrolls it rather than littering
/// the org with a second row for one physical laptop, and the superseded token
/// stops working since it is now a credential nobody holds.
#[tokio::test]
async fn re_sharing_the_same_machine_converges() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;

    let (_, body) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(self_register_body(&session, "laptop", None)),
        )
        .await;
    let first: TokenResponse = serde_json::from_str(&body).unwrap();

    let (_, body) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(self_register_body(&session, "laptop", Some("declared"))),
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
    // The policy converged on the latest registration rather than keeping a
    // stale one nobody can see.
    assert_eq!(
        fleet
            .db()
            .node_org_and_policy(&AgentId(second.node_id.unwrap()))
            .await
            .unwrap()
            .unwrap()
            .1,
        fleet_proto::AdoptPolicy::Declared
    );
}

/// A machine first enrolled from an image and later shared by its owner must
/// converge: it gains an owner and the `auto` policy, rather than silently
/// keeping the lab defaults.
#[tokio::test]
async fn an_auth_key_node_later_shared_converges_on_the_share_defaults() {
    let fleet = TestCoordinator::start().await;
    let key = fleet.seed_auth_key("acme", &[], false, None).await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;

    let (_, body) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(auth_key_body(&key, "laptop", &[])),
        )
        .await;
    let enrolled: TokenResponse = serde_json::from_str(&body).unwrap();
    let node = AgentId(enrolled.node_id.clone().unwrap());
    assert_eq!(
        fleet.db().node_org_and_policy(&node).await.unwrap().unwrap().1,
        fleet_proto::AdoptPolicy::Declared,
        "an auth-key node is a lab node by default"
    );
    assert!(fleet.db().node_owner(&node).await.unwrap().is_none());

    let (status, body) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(self_register_body(&session, "laptop", None)),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");

    assert_eq!(
        fleet.db().node_org_and_policy(&node).await.unwrap().unwrap().1,
        fleet_proto::AdoptPolicy::Auto
    );
    assert_eq!(
        fleet.db().node_owner(&node).await.unwrap().as_deref(),
        Some("alice")
    );
}
