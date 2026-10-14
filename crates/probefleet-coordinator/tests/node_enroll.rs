//! Node enrollment over plain HTTP: `POST /node/enroll` (redeem a `node`
//! API key) and `POST /node/self-register` (a session registers its own
//! machine — `probefleet share`).
//!
//! These replaced the old `/auth/token` grants `auth_key` and
//! `self_register`; forgs now owns `/auth/token` and its session/refresh
//! mechanics are covered by forgs' own tests. The properties that matter here:
//!
//! * a valid key mints a node token **and** creates the `node` row, in the key's
//!   org, with the key's tags;
//! * the minted token then authenticates a real `/agent` upgrade — enrollment
//!   is not merely returning a plausible-looking string;
//! * single-use means single use, expiry is enforced, and a key of the wrong
//!   purpose is refused **without being burnt**;
//! * self-registration needs membership of the target org, records the user as
//!   owner, and never accepts a node token as the caller.

mod common;

use common::TestCoordinator;

use forgs::TokenKind;
use probefleet_coordinator::FleetRole;
use probefleet_proto::auth_api::NodeTokenResponse;
use probefleet_proto::ids::NodeId;

fn enroll_body(key: &str, node_name: &str) -> String {
    serde_json::json!({ "auth_key": key, "node_name": node_name }).to_string()
}

async fn enroll(fleet: &TestCoordinator, key: &str, name: &str) -> (u16, String) {
    fleet
        .http("POST", "/node/enroll", Some(enroll_body(key, name)))
        .await
}

fn self_register_body(node_name: &str, adopt: Option<&str>, org: Option<&str>) -> String {
    let mut body = serde_json::json!({ "node_name": node_name, "tags": [] });
    if let Some(adopt) = adopt {
        body["adopt"] = serde_json::Value::String(adopt.to_owned());
    }
    if let Some(org) = org {
        body["org"] = serde_json::Value::String(org.to_owned());
    }
    body.to_string()
}

async fn self_register(
    fleet: &TestCoordinator,
    bearer: &str,
    node_name: &str,
    adopt: Option<&str>,
    org: Option<&str>,
) -> (u16, String) {
    fleet
        .http_auth(
            "POST",
            "/node/self-register",
            Some(bearer),
            Some(self_register_body(node_name, adopt, org)),
        )
        .await
}

fn parse(body: &str) -> NodeTokenResponse {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("{e}: {body}"))
}

async fn policy(fleet: &TestCoordinator, node: &NodeId) -> probefleet_proto::AdoptPolicy {
    fleet
        .db()
        .node_org_and_policy(node)
        .await
        .unwrap()
        .unwrap()
        .1
}

// ---------------------------------------------------------------------------
// POST /node/enroll
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_valid_node_key_mints_a_working_node_token() {
    let fleet = TestCoordinator::start().await;
    let acme = fleet.org("acme").await;
    let key = fleet
        .seed_auth_key("acme", &["rack-1".to_owned()], true, None)
        .await;

    let (status, body) = enroll(&fleet, &key, "rpi-lab-1").await;
    assert_eq!(status, 200, "body: {body}");
    let resp = parse(&body);

    assert_eq!(resp.org, acme.0);
    assert_eq!(resp.org_name.as_deref(), Some("acme"));
    assert!(resp.token.starts_with("prfn1_"), "expected a node token");

    // The capability-token public key must come back: without it the node
    // cannot verify the per-lease tokens the coordinator later mints for it.
    assert_eq!(
        resp.coordinator_token_pubkey,
        fleet.coord.token_pubkey_hex()
    );

    // The node row exists, in the *key's* org, carrying the key's tags.
    let hash = fleet.auth().format().parse(&resp.token).unwrap().hash();
    let (node, org, _) = fleet
        .db()
        .node_by_token_hash(hash.as_str())
        .await
        .unwrap()
        .expect("node row created");
    assert_eq!(node, NodeId(resp.node_id.clone()));
    assert_eq!(org, acme);
    let row = fleet
        .db()
        .scoped(acme.clone())
        .node_by_name("rpi-lab-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.tags, vec!["rack-1".to_owned()]);
    assert!(
        row.owner_user_id.is_none(),
        "a key-enrolled node has no owner"
    );
    assert_eq!(row.adopt, probefleet_proto::AdoptPolicy::Declared);

    // ... and the minted token authenticates a real upgrade. This is the step
    // that makes the exchange meaningful rather than decorative.
    assert_eq!(fleet.upgrade_status("/agent", Some(&resp.token)).await, 101);
}

#[tokio::test]
async fn a_single_use_key_is_consumed_exactly_once() {
    let fleet = TestCoordinator::start().await;
    let key = fleet.seed_auth_key("acme", &[], true, None).await;

    assert_eq!(enroll(&fleet, &key, "a").await.0, 200);
    assert_eq!(
        enroll(&fleet, &key, "b").await.0,
        401,
        "a single-use key must not be redeemable twice"
    );
}

#[tokio::test]
async fn a_multi_use_key_enrolls_a_rack() {
    let fleet = TestCoordinator::start().await;
    let key = fleet.seed_auth_key("acme", &[], false, None).await;

    for name in ["rpi-1", "rpi-2", "rpi-3"] {
        let (status, body) = enroll(&fleet, &key, name).await;
        assert_eq!(status, 200, "{name}: {body}");
        let token = parse(&body).token;
        assert_eq!(fleet.upgrade_status("/agent", Some(&token)).await, 101);
    }
}

#[tokio::test]
async fn an_expired_key_is_refused() {
    let fleet = TestCoordinator::start().await;
    let key = fleet
        .seed_auth_key("acme", &[], true, Some(fleet.now() - 1))
        .await;
    assert_eq!(enroll(&fleet, &key, "a").await.0, 401);
}

#[tokio::test]
async fn an_unknown_or_wrong_kind_credential_is_refused() {
    let fleet = TestCoordinator::start().await;

    let orphan = fleet
        .auth()
        .format()
        .mint(TokenKind::ApiKey)
        .to_secret_string();
    assert_eq!(enroll(&fleet, &orphan, "a").await.0, 401);

    // A session token, or a node token, where an API key is expected.
    let session = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    assert_eq!(enroll(&fleet, &session, "a").await.0, 401);
    let (node_token, _) = fleet.seed_node("acme", "rpi-0").await;
    assert_eq!(enroll(&fleet, &node_token, "a").await.0, 401);
}

/// A `ci` key is a perfectly valid API key of the wrong purpose. It must not
/// enroll a node — and the refusal must come **before** the consume, so a
/// mistyped redemption does not burn a single-use key for its real purpose.
#[tokio::test]
async fn a_ci_key_cannot_enroll_a_node_and_is_not_burnt() {
    let fleet = TestCoordinator::start().await;
    let ci = fleet
        .seed_ci_auth_key("acme", &["nrf52".to_owned()], None)
        .await;

    let (status, body) = enroll(&fleet, &ci, "rpi-1").await;
    assert_eq!(status, 403, "body: {body}");
    assert!(fleet
        .db()
        .scoped(fleet.org("acme").await)
        .node_by_name("rpi-1")
        .await
        .unwrap()
        .is_none());

    // Still redeemable for what it is: a workload token.
    let (status, body) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(serde_json::json!({ "grant_type": "api_key", "api_key": ci }).to_string()),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
}

/// Re-running `node up --auth-key` on the same machine must re-enroll it, not
/// litter the org with a second row for one physical Pi — and the old token
/// must stop working, since it is now a credential nobody holds.
#[tokio::test]
async fn re_enrolling_the_same_node_replaces_its_token() {
    let fleet = TestCoordinator::start().await;
    let key = fleet.seed_auth_key("acme", &[], false, None).await;

    let first = parse(&enroll(&fleet, &key, "rpi-1").await.1);
    let second = parse(&enroll(&fleet, &key, "rpi-1").await.1);

    assert_eq!(first.node_id, second.node_id, "same machine, same node id");
    assert_ne!(first.token, second.token);
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&second.token)).await,
        101
    );
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&first.token)).await,
        401,
        "the superseded token must stop working"
    );
}

#[tokio::test]
async fn malformed_enrollments_are_bad_requests_not_credentials() {
    let fleet = TestCoordinator::start().await;
    let key = fleet.seed_auth_key("acme", &[], true, None).await;

    // A missing node name cannot name a row ...
    assert_eq!(enroll(&fleet, &key, "  ").await.0, 400);
    // ... and the 400 did not burn the key.
    assert_eq!(enroll(&fleet, &key, "rpi-1").await.0, 200);

    // A body that is not the request shape at all is a client error.
    let (status, _) = fleet
        .http(
            "POST",
            "/node/enroll",
            Some(r#"{"grant_type":"password"}"#.into()),
        )
        .await;
    assert!(
        (400..500).contains(&status) && status != 401,
        "a malformed body should be a 4xx client error, got {status}"
    );
}

// ---------------------------------------------------------------------------
// POST /node/self-register (`probefleet share`, architecture §4.2)
// ---------------------------------------------------------------------------

/// The `share` path end to end: a session registers the machine as a node in
/// an org the caller is a member of, and the minted node token authenticates
/// a real `/agent` upgrade.
///
/// Also asserts the two properties that make the laptop case work: the node is
/// **owned by the user** (so "my laptop's boards" is expressible and revoking
/// the user cascades), and its adoption policy defaults to `auto`.
#[tokio::test]
async fn a_session_self_registers_a_working_node_owned_by_the_caller() {
    let fleet = TestCoordinator::start().await;
    let (acme, alice) = fleet.member("acme", "alice", FleetRole::Member).await;
    let session = fleet.session_for("alice").await;

    let (status, body) = self_register(&fleet, &session, "alice-laptop", None, Some("acme")).await;
    assert_eq!(status, 200, "body: {body}");
    let resp = parse(&body);

    assert_eq!(resp.org, acme.0);
    assert!(resp.token.starts_with("prfn1_"), "expected a node token");
    assert_eq!(
        resp.coordinator_token_pubkey,
        fleet.coord.token_pubkey_hex(),
        "without the pubkey the node cannot verify per-lease tokens"
    );

    // The node token works on the node plane...
    assert_eq!(fleet.upgrade_status("/agent", Some(&resp.token)).await, 101);
    // ...and only there: the two credentials stay distinct, which is what stops
    // a compromised laptop-as-node from being a compromised account.
    assert_eq!(
        fleet.upgrade_status("/client", Some(&resp.token)).await,
        403
    );
    assert_ne!(resp.token, session);

    let node = NodeId(resp.node_id);
    assert_eq!(
        fleet.db().node_org_and_policy(&node).await.unwrap(),
        Some((acme, probefleet_proto::AdoptPolicy::Auto)),
        "a node created by `share` defaults to auto-adoption"
    );
    assert_eq!(
        fleet.db().node_owner(&node).await.unwrap(),
        Some(alice.to_string()),
        "the node must be owned by the user who shared it"
    );
}

/// Without an `org`, the node lands in the caller's personal org.
#[tokio::test]
async fn self_registration_defaults_to_the_personal_org() {
    let fleet = TestCoordinator::start().await;
    let (session, personal, _) = fleet.seed_user("alice").await;

    let (status, body) = self_register(&fleet, &session, "laptop", None, None).await;
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(parse(&body).org, personal.0);
}

/// An explicit `--adopt declared` must be honoured: `auto` is only the default.
#[tokio::test]
async fn an_explicit_adopt_policy_is_recorded() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;

    let (status, body) =
        self_register(&fleet, &session, "lab-pi", Some("declared"), Some("acme")).await;
    assert_eq!(status, 200, "body: {body}");
    let node = NodeId(parse(&body).node_id);
    assert_eq!(
        policy(&fleet, &node).await,
        probefleet_proto::AdoptPolicy::Declared
    );
}

/// A typo'd policy is a 400, never a silent default. `adopt = "delcared"`
/// quietly meaning `auto` would share probes the operator did not mean to.
#[tokio::test]
async fn an_unrecognised_adopt_policy_is_refused() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;

    for bad in ["delcared", "manual", "AUTO", ""] {
        let (status, _) = self_register(&fleet, &session, "pi", Some(bad), Some("acme")).await;
        assert_eq!(status, 400, "adopt={bad:?} must be refused");
    }
}

/// Self-registration is self-*approving*, not un-authorized: membership is
/// still required. A real user with a real session naming an org they are not
/// a member of — the shape of a revoked membership, not a forged token — is
/// refused, and so is naming an org that does not exist (the same 403, so the
/// route is no org-existence oracle).
#[tokio::test]
async fn a_non_member_with_a_valid_session_is_refused() {
    let fleet = TestCoordinator::start().await;
    let acme = fleet.org("acme").await;
    let session = fleet
        .seed_session("other", "stranger", FleetRole::Admin)
        .await;

    for org in ["acme", acme.0.as_str(), "no-such-org"] {
        let (status, _) = self_register(&fleet, &session, "trespasser", None, Some(org)).await;
        assert_eq!(status, 403, "org={org}");
    }

    // Nothing was created.
    assert!(fleet
        .db()
        .org_of_node(&probefleet_coordinator::node_id_for(&acme, "trespasser"))
        .await
        .unwrap()
        .is_none());
}

/// A node token where a session is expected. A node re-registering *itself* as
/// a node would be a privilege escalation shaped like a typo. So are the other
/// non-session kinds.
#[tokio::test]
async fn a_node_token_cannot_self_register() {
    let fleet = TestCoordinator::start().await;
    let (node_token, _) = fleet.seed_node("acme", "rpi-1").await;
    let (status, _) = self_register(&fleet, &node_token, "rpi-2", None, Some("acme")).await;
    assert_eq!(status, 403);

    fleet.seed_user("alice").await;
    let refresh = fleet.seed_refresh_token("alice").await;
    let workload = fleet
        .seed_workload_token("octo/firmware", fleet.now() + 600)
        .await;
    for token in [&refresh, &workload] {
        let (status, _) = self_register(&fleet, token, "rpi-3", None, None).await;
        assert_eq!(status, 403);
    }
}

#[tokio::test]
async fn self_registration_needs_a_node_name() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let (status, _) = self_register(&fleet, &session, "   ", None, Some("acme")).await;
    assert_eq!(status, 400);
}

/// Re-running `share` on the same machine re-enrolls it rather than littering
/// the org with a second row for one physical laptop, and the superseded token
/// stops working since it is now a credential nobody holds.
#[tokio::test]
async fn re_sharing_the_same_machine_converges() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;

    let first = parse(
        &self_register(&fleet, &session, "laptop", None, Some("acme"))
            .await
            .1,
    );
    let second = parse(
        &self_register(&fleet, &session, "laptop", Some("declared"), Some("acme"))
            .await
            .1,
    );

    assert_eq!(first.node_id, second.node_id, "same machine, same node id");
    assert_ne!(first.token, second.token);
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&second.token)).await,
        101
    );
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&first.token)).await,
        401,
        "the superseded token must stop working"
    );
    // The policy converged on the latest registration rather than keeping a
    // stale one nobody can see.
    assert_eq!(
        policy(&fleet, &NodeId(second.node_id)).await,
        probefleet_proto::AdoptPolicy::Declared
    );
}

/// A machine first enrolled from an image and later shared by its owner must
/// converge: it gains an owner and the `auto` policy, rather than silently
/// keeping the lab defaults.
#[tokio::test]
async fn a_key_enrolled_node_later_shared_converges_on_the_share_defaults() {
    let fleet = TestCoordinator::start().await;
    let key = fleet.seed_auth_key("acme", &[], false, None).await;
    let (_, alice) = fleet.member("acme", "alice", FleetRole::Member).await;
    let session = fleet.session_for("alice").await;

    let enrolled = parse(&enroll(&fleet, &key, "laptop").await.1);
    let node = NodeId(enrolled.node_id);
    assert_eq!(
        policy(&fleet, &node).await,
        probefleet_proto::AdoptPolicy::Declared,
        "a key-enrolled node is a lab node by default"
    );
    assert!(fleet.db().node_owner(&node).await.unwrap().is_none());

    let (status, body) = self_register(&fleet, &session, "laptop", None, Some("acme")).await;
    assert_eq!(status, 200, "body: {body}");

    assert_eq!(
        policy(&fleet, &node).await,
        probefleet_proto::AdoptPolicy::Auto
    );
    assert_eq!(
        fleet.db().node_owner(&node).await.unwrap(),
        Some(alice.to_string())
    );
}
