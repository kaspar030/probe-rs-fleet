//! `POST /auth/keys` with fleet's purposes: minting, listing and revoking API
//! keys with a user session, over the authenticated API.
//!
//! The route and its generic rules are forgs' (tested in `forgs-http`); what
//! is fleet's is the **purpose policy** (`FleetPurposes`) and what a minted key
//! redeems into. This is the hosted customer's path (architecture §6.4): a
//! member who has logged in — and who has no shell on the coordinator host —
//! mints the key that enrolls a headless lab node or a CI runner:
//!
//! * a `node` key (payload `{"tags":[..]}`) redeems at `POST /node/enroll`
//!   into the **key's** org, stamping its tags, and nowhere else;
//! * a `ci` key (payload `{"tags":[..],"ops":[..]}`, tags required) redeems at
//!   `/auth/token` into a workload whose grant is bounded by its tags;
//! * bad payloads, an unknown purpose and a `subject_name` on a `node` key are
//!   `400`; a non-member (or unknown org) is the same audited `403`;
//! * API-minted keys must expire, and within a cap;
//! * the listing is hash-only; revocation is creator-or-admin and a revoked
//!   key stops redeeming.

mod common;

use common::TestCoordinator;

use fleet_coordinator::FleetRole;
use fleet_proto::auth_api::NodeTokenResponse;
use forgs::api::{ApiKeyCreated, ApiKeyList, ApiKeyRevoked};

/// A day, comfortably inside the cap.
const DAY: u64 = 86_400;

fn create_body(org: &str, purpose: &str, payload: &serde_json::Value, ttl_secs: u64) -> String {
    serde_json::json!({
        "action": "create",
        "namespace": org,
        "ttl_secs": ttl_secs,
        "purpose": purpose,
        "payload": payload,
    })
    .to_string()
}

fn node_body(org: &str, tags: &[&str]) -> String {
    create_body(org, "node", &serde_json::json!({ "tags": tags }), DAY)
}

fn list_body(org: &str) -> String {
    serde_json::json!({ "action": "list", "namespace": org }).to_string()
}

fn revoke_body(org: &str, prefix: &str) -> String {
    serde_json::json!({ "action": "revoke", "namespace": org, "prefix": prefix }).to_string()
}

fn enroll_body(key: &str, node_name: &str) -> String {
    serde_json::json!({ "auth_key": key, "node_name": node_name }).to_string()
}

/// Mint over the API, asserting success.
async fn mint(fleet: &TestCoordinator, session: &str, body: String) -> ApiKeyCreated {
    let (status, response) = fleet
        .http_auth("POST", "/auth/keys", Some(session), Some(body))
        .await;
    assert_eq!(status, 200, "{response}");
    serde_json::from_str(&response).unwrap()
}

/// The org's keys, via the route itself (as `session`).
async fn list(fleet: &TestCoordinator, session: &str, org: &str) -> ApiKeyList {
    let (status, body) = fleet
        .http_auth("POST", "/auth/keys", Some(session), Some(list_body(org)))
        .await;
    assert_eq!(status, 200, "{body}");
    serde_json::from_str(&body).unwrap()
}

/// The whole point: a logged-in member mints a `node` key and it enrolls a
/// node in the key's org with the key's tags — whatever the configured
/// default org is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_mints_a_node_key_that_enrolls_into_the_keys_org() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let acme = fleet.org("acme").await;

    let created = mint(
        &fleet,
        &session,
        node_body("acme", &["nrf52", "lab", "lab"]),
    )
    .await;
    assert!(created.key.starts_with("prfk1_"), "got {}", created.key);
    assert_eq!(created.namespace, acme.0);
    assert!(created.single_use);
    assert_eq!(created.purpose, "node");
    // Canonicalised by fleet's purpose hook: sorted, deduplicated.
    assert_eq!(
        created.payload,
        Some(serde_json::json!({ "tags": ["lab", "nrf52"] }))
    );
    assert!(created.expires > fleet.now(), "API-minted keys must expire");

    // Naming the org by id works the same.
    mint(&fleet, &session, node_body(&acme.0, &[])).await;

    let (status, body) = fleet
        .http(
            "POST",
            "/node/enroll",
            Some(enroll_body(&created.key, "rpi-lab-1")),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let resp: NodeTokenResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(resp.org, acme.0);
    assert_eq!(resp.org_name.as_deref(), Some("acme"));
    assert!(resp.token.starts_with("prfn1_"));
    assert_eq!(
        resp.node_id,
        fleet_coordinator::node_id_for(&acme, "rpi-lab-1").0
    );

    // ... and the key's tags reached the node row.
    let (tags,): (String,) = sqlx::query_as("SELECT tags FROM node WHERE id = ?1")
        .bind(&resp.node_id)
        .fetch_one(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert!(
        tags.contains("lab") && tags.contains("nrf52"),
        "got {tags:?}"
    );

    // Single use: a second redemption enrolls nothing.
    let (status, _) = fleet
        .http(
            "POST",
            "/node/enroll",
            Some(enroll_body(&created.key, "rpi-lab-2")),
        )
        .await;
    assert_eq!(status, 401);
}

/// A `ci` key redeems into a workload (never a node), and the grant its
/// redemption synthesises is bounded by the key's tags and ops.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ci_key_redeems_into_a_workload_bounded_by_its_tags() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let acme = fleet.org("acme").await;

    let created = mint(
        &fleet,
        &session,
        create_body(
            "acme",
            "ci",
            &serde_json::json!({ "tags": ["nrf52"], "ops": ["flash", "attach"] }),
            DAY,
        ),
    )
    .await;
    assert_eq!(created.purpose, "ci");
    assert!(created.single_use);

    // A ci key is not an enrollment credential — and the refusal does not
    // burn it.
    let (status, _) = fleet
        .http(
            "POST",
            "/node/enroll",
            Some(enroll_body(&created.key, "rpi-1")),
        )
        .await;
    assert_eq!(status, 403);

    let (status, body) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(
                serde_json::json!({ "grant_type": "api_key", "api_key": created.key }).to_string(),
            ),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let token = serde_json::from_str::<serde_json::Value>(&body).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(token.starts_with("prfw1_"), "{token}");

    let (selector, ops): (String, String) =
        sqlx::query_as("SELECT selector, ops FROM forgs_grant WHERE ns_node_id = ?1")
            .bind(&acme.0)
            .fetch_one(fleet.db().pool_for_test())
            .await
            .unwrap();
    assert_eq!(selector, "tag=nrf52");
    assert!(ops.contains("flash") && ops.contains("attach"), "{ops}");
    assert!(!ops.contains("power_cycle"), "{ops}");

    // The workload acts in no org (it reaches boards only via the grant).
    assert_eq!(fleet.upgrade_status("/client", Some(&token)).await, 101);
}

/// Every payload fleet's purpose policy refuses is a `400`, and nothing is
/// stored along the way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_payloads_and_unknown_purposes_are_refused() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Admin).await;

    for (label, purpose, payload) in [
        (
            "an unknown purpose",
            "admin",
            serde_json::json!({ "tags": ["x"] }),
        ),
        ("an empty purpose", "", serde_json::json!({})),
        (
            "a tagless ci key (a grant over the whole org)",
            "ci",
            serde_json::json!({}),
        ),
        (
            "a ci key with empty tags",
            "ci",
            serde_json::json!({ "tags": [] }),
        ),
        (
            "an unknown op",
            "ci",
            serde_json::json!({ "tags": ["x"], "ops": ["teleport"] }),
        ),
        (
            "a wildcard tag",
            "node",
            serde_json::json!({ "tags": ["*"] }),
        ),
        ("an empty tag", "node", serde_json::json!({ "tags": [""] })),
        (
            "ops on a node key",
            "node",
            serde_json::json!({ "tags": ["x"], "ops": ["flash"] }),
        ),
        (
            "tags that are not a list",
            "node",
            serde_json::json!({ "tags": "x" }),
        ),
        (
            "an unknown field",
            "node",
            serde_json::json!({ "tags": [], "adopt": "auto" }),
        ),
        (
            "a payload that is not an object",
            "node",
            serde_json::json!(["x"]),
        ),
    ] {
        let (status, body) = fleet
            .http_auth(
                "POST",
                "/auth/keys",
                Some(&session),
                Some(create_body("acme", purpose, &payload, DAY)),
            )
            .await;
        assert_eq!(status, 400, "{label}: {body}");
    }
    assert!(list(&fleet, &session, "acme").await.keys.is_empty());
}

/// `subject_name` (a stable identity surviving rotation) belongs on a `ci`
/// key only: on a `node` key it would be a stored no-op that looks effective.
/// On a `ci` key it is normalised, echoed and listed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subject_name_is_accepted_on_ci_keys_only() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Admin).await;

    let named = |purpose: &str, name: &str, payload: serde_json::Value| {
        serde_json::json!({
            "action": "create", "namespace": "acme", "ttl_secs": DAY,
            "purpose": purpose, "subject_name": name, "payload": payload,
        })
        .to_string()
    };

    for (label, body) in [
        (
            "a name on a node key",
            named("node", "builder", serde_json::json!({ "tags": [] })),
        ),
        (
            "a name with a colon",
            named("ci", "key:deadbeef", serde_json::json!({ "tags": ["x"] })),
        ),
        (
            "a name with a slash",
            named("ci", "owner/repo", serde_json::json!({ "tags": ["x"] })),
        ),
        (
            "an empty name",
            named("ci", "", serde_json::json!({ "tags": ["x"] })),
        ),
    ] {
        let (status, response) = fleet
            .http_auth("POST", "/auth/keys", Some(&session), Some(body))
            .await;
        assert_eq!(status, 400, "{label}: {response}");
    }
    assert!(list(&fleet, &session, "acme").await.keys.is_empty());

    let created = mint(
        &fleet,
        &session,
        named("ci", "Builder-1", serde_json::json!({ "tags": ["nrf52"] })),
    )
    .await;
    assert_eq!(created.subject_name.as_deref(), Some("builder-1"));
    let keys = list(&fleet, &session, "acme").await.keys;
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].subject_name.as_deref(), Some("builder-1"));

    // Absence has one spelling.
    let unnamed = mint(
        &fleet,
        &session,
        create_body("acme", "ci", &serde_json::json!({ "tags": ["nrf52"] }), DAY),
    )
    .await;
    assert_eq!(unnamed.subject_name, None);
}

/// A non-member naming an org, and anybody naming one that does not exist,
/// get the same `403`, audited; nothing is minted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_member_or_unknown_org_is_refused_and_audited() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let (mallory, _, _) = fleet.seed_user("mallory").await;
    let acme = fleet.org("acme").await;

    let mut bodies = Vec::new();
    for org in ["acme", acme.0.as_str(), "alice", "no-such-org"] {
        let (status, body) = fleet
            .http_auth(
                "POST",
                "/auth/keys",
                Some(&mallory),
                Some(node_body(org, &[])),
            )
            .await;
        assert_eq!(status, 403, "{org}: {body}");
        bodies.push(body);
        let (status, _) = fleet
            .http_auth("POST", "/auth/keys", Some(&mallory), Some(list_body(org)))
            .await;
        assert_eq!(status, 403, "list {org}");
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]), "{bodies:?}");
    assert!(
        fleet
            .forgs_audit_actions()
            .await
            .iter()
            .any(|a| a == "api_key.denied"),
        "the refusal must be audited"
    );
    assert!(list(&fleet, &alice, "acme").await.keys.is_empty());

    // A member mints in their personal org without naming anything special.
    mint(&fleet, &mallory, node_body("mallory", &[])).await;
}

/// The credential kind is part of the route: a node token or an API key is a
/// `403` (wrong door), no credential or a forged one a `401`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_session_token_opens_this_route() {
    let fleet = TestCoordinator::start().await;
    let (node_token, _) = fleet.seed_node("acme", "rpi-1").await;
    let key = fleet.seed_auth_key("acme", &[], true, None).await;
    let workload = fleet.seed_workload_token("o/r", fleet.now() + 600).await;

    for (label, bearer) in [
        ("node", &node_token),
        ("api key", &key),
        ("workload", &workload),
    ] {
        let (status, _) = fleet
            .http_auth(
                "POST",
                "/auth/keys",
                Some(bearer),
                Some(node_body("acme", &[])),
            )
            .await;
        assert_eq!(status, 403, "a {label} token must not mint keys");
    }
    for bearer in [None, Some("prfs1_garbage")] {
        let (status, _) = fleet
            .http_auth("POST", "/auth/keys", bearer, Some(node_body("acme", &[])))
            .await;
        assert_eq!(status, 401, "bearer: {bearer:?}");
    }
}

/// A member-minted key must expire, and within the cap. A forever-key is an
/// operator's informed choice from a shell, not a hosted member's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_zero_or_over_cap_ttl_is_refused() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let cap = fleet.auth().ttl().api_key_max;

    for ttl in [0, cap + 1] {
        let (status, body) = fleet
            .http_auth(
                "POST",
                "/auth/keys",
                Some(&session),
                Some(create_body("acme", "node", &serde_json::json!({}), ttl)),
            )
            .await;
        assert_eq!(status, 400, "ttl {ttl}: {body}");
    }

    let before = fleet.now();
    let created = mint(
        &fleet,
        &session,
        create_body("acme", "node", &serde_json::json!({}), cap),
    )
    .await;
    assert!(created.expires >= before + cap);
}

/// The listing is hash-only and org-scoped, and records who minted each key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listing_returns_hashes_only_and_never_another_org() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let bob = fleet.seed_session("other", "bob", FleetRole::Member).await;
    let alice_id = fleet.user("alice").await;

    let mine = mint(&fleet, &alice, node_body("acme", &["lab"])).await;
    let theirs = mint(&fleet, &bob, node_body("other", &[])).await;

    let (status, body) = fleet
        .http_auth("POST", "/auth/keys", Some(&alice), Some(list_body("acme")))
        .await;
    assert_eq!(status, 200, "{body}");
    assert!(
        !body.contains(&mine.key) && !body.contains(&theirs.key),
        "a listing must never carry a secret: {body}"
    );
    let list: ApiKeyList = serde_json::from_str(&body).unwrap();
    assert_eq!(list.keys.len(), 1);
    assert_eq!(list.keys[0].key_hash, mine.key_hash);
    assert_eq!(list.keys[0].created_by, Some(alice_id.to_string()));
    assert_eq!(
        list.keys[0].payload,
        Some(serde_json::json!({ "tags": ["lab"] }))
    );
    assert!(list.keys[0].consumed_at.is_none());
}

/// Revocation is creator-or-admin, and a revoked key stops enrolling.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_is_creator_or_admin_and_the_key_stops_redeeming() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let bob = fleet.seed_session("acme", "bob", FleetRole::Member).await;
    let root = fleet.seed_session("acme", "root", FleetRole::Admin).await;

    let alices = mint(&fleet, &alice, node_body("acme", &[])).await;
    let prefix = &alices.key_hash[..16];

    let (status, _) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&bob),
            Some(revoke_body("acme", prefix)),
        )
        .await;
    assert_eq!(status, 403, "a fellow member is not the key's owner");
    assert_eq!(list(&fleet, &alice, "acme").await.keys.len(), 1);

    let (status, body) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&alice),
            Some(revoke_body("acme", prefix)),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let revoked: ApiKeyRevoked = serde_json::from_str(&body).unwrap();
    assert_eq!(revoked.revoked, vec![alices.key_hash.clone()]);

    let (status, _) = fleet
        .http(
            "POST",
            "/node/enroll",
            Some(enroll_body(&alices.key, "rpi-1")),
        )
        .await;
    assert_eq!(status, 401, "a revoked key must not enroll anything");

    // An admin revokes a shell-minted key, whose `created_by` is NULL.
    let shell_key = fleet.seed_auth_key("acme", &[], true, None).await;
    let hash = fleet.auth().format().parse(&shell_key).unwrap().hash();
    let (status, body) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&root),
            Some(revoke_body("acme", &hash.as_str()[..16])),
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // A cross-org prefix is indistinguishable from an unknown one.
    let bobs_other = fleet.seed_session("other", "bob", FleetRole::Member).await;
    let theirs = mint(&fleet, &bobs_other, node_body("other", &[])).await;
    for prefix in ["deadbeefdeadbeef", &theirs.key_hash[..16]] {
        let (status, body) = fleet
            .http_auth(
                "POST",
                "/auth/keys",
                Some(&root),
                Some(revoke_body("acme", prefix)),
            )
            .await;
        assert_eq!(status, 404, "{prefix}: {body}");
    }
    // A short prefix cannot address a key on purpose.
    let (status, _) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&root),
            Some(revoke_body("acme", "abc")),
        )
        .await;
    assert_eq!(status, 400);
}

/// `POST /api/v1/auth-keys` is a flat encoding of the same mint (the browser
/// UI's): tags + ops + purpose, validated by the same hook, landing in the
/// acting org (`?org=`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_browser_api_mints_the_same_keys_in_the_acting_org() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let acme = fleet.org("acme").await;
    let personal = fleet.personal_org("alice").await;

    let (status, body) = fleet
        .http_auth(
            "POST",
            "/api/v1/auth-keys?org=acme",
            Some(&session),
            Some(serde_json::json!({ "tags": ["nrf52"], "ttl_secs": DAY }).to_string()),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let created: ApiKeyCreated = serde_json::from_str(&body).unwrap();
    assert_eq!(created.namespace, acme.0);
    assert_eq!(created.purpose, "node");

    // No `?org=`: the personal org.
    let (status, body) = fleet
        .http_auth(
            "POST",
            "/api/v1/auth-keys",
            Some(&session),
            Some(
                serde_json::json!({ "tags": ["x"], "ttl_secs": DAY, "purpose": "ci",
                                    "ops": ["flash"] })
                .to_string(),
            ),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let created: ApiKeyCreated = serde_json::from_str(&body).unwrap();
    assert_eq!(created.namespace, personal.0);

    // The same refusals as `/auth/keys`.
    for body in [
        serde_json::json!({ "ttl_secs": DAY, "purpose": "ci" }),
        serde_json::json!({ "ttl_secs": DAY, "purpose": "admin" }),
        serde_json::json!({ "ttl_secs": DAY, "ops": ["flash"] }),
        serde_json::json!({ "ttl_secs": 0 }),
    ] {
        let (status, response) = fleet
            .http_auth(
                "POST",
                "/api/v1/auth-keys?org=acme",
                Some(&session),
                Some(body.to_string()),
            )
            .await;
        assert_eq!(status, 400, "{body}: {response}");
    }
    let (status, _) = fleet
        .http_auth(
            "POST",
            "/api/v1/auth-keys?org=other",
            Some(&session),
            Some(serde_json::json!({ "ttl_secs": DAY }).to_string()),
        )
        .await;
    assert_eq!(status, 403);

    let (status, body) = fleet
        .http_auth("GET", "/api/v1/auth-keys?org=acme", Some(&session), None)
        .await;
    assert_eq!(status, 200, "{body}");
    let list: ApiKeyList = serde_json::from_str(&body).unwrap();
    assert_eq!(list.keys.len(), 1);
}
