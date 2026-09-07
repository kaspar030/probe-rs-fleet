//! `POST /auth/keys`: minting, listing and revoking auth keys with a `[user]`
//! session, over the authenticated API.
//!
//! This is the hosted customer's path (architecture §6.4): a member who has
//! logged in — and who has no shell on the coordinator host — can still mint the
//! key that enrolls a headless lab node. The properties that matter:
//!
//! * a member's session mints a key, and the key really redeems at
//!   `/auth/token`, into the **caller's** org and nowhere else;
//! * `created_by` records the human, which is what makes creator-revocation
//!   possible;
//! * membership is required, the credential kind is enforced, and both refusals
//!   are the coordinator's usual coarse ones;
//! * API-minted keys must expire, and within a cap;
//! * revocation is creator-or-admin, and a prefix that could match everything is
//!   refused before it deletes anything.

mod common;

use common::TestCoordinator;

use fleet_auth::api::{AuthKeyCreated, AuthKeyList, AuthKeyRevoked, TokenResponse};
use fleet_proto::ids::{OrgId, Role};

/// A day, comfortably inside the cap.
const DAY: u64 = 86_400;

fn create_body(tags: &[&str], ttl_secs: u64, multi_use: bool) -> String {
    serde_json::json!({
        "action": "create",
        "tags": tags,
        "ttl_secs": ttl_secs,
        "multi_use": multi_use,
    })
    .to_string()
}

fn list_body() -> String {
    serde_json::json!({ "action": "list" }).to_string()
}

fn revoke_body(prefix: &str) -> String {
    serde_json::json!({ "action": "revoke", "prefix": prefix }).to_string()
}

fn redeem_body(key: &str, node_name: &str) -> String {
    serde_json::json!({
        "grant_type": "auth_key",
        "auth_key": key,
        "node_name": node_name,
        "tags": [],
    })
    .to_string()
}

/// Mint a key over the API, asserting success, and return the parsed response.
async fn create_key(fleet: &TestCoordinator, session: &str, tags: &[&str]) -> AuthKeyCreated {
    let (status, body) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(session),
            Some(create_body(tags, DAY, false)),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    serde_json::from_str(&body).unwrap()
}

/// The whole point of the task: a logged-in member mints a key and it works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_mints_a_key_that_enrolls_a_node_in_their_own_org() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;

    let created = create_key(&fleet, &session, &["lab", "nrf52"]).await;
    assert!(created.key.starts_with("prffk1_"), "got {}", created.key);
    assert_eq!(created.org, "acme");
    assert!(created.single_use);
    assert_eq!(created.tags, vec!["lab".to_owned(), "nrf52".to_owned()]);
    assert!(created.expires.is_some(), "API-minted keys must expire");

    // The key redeems, and the node lands in the caller's org — not in the
    // coordinator's configured default.
    let (status, body) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(redeem_body(&created.key, "rpi-lab-1")),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    let resp: TokenResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(resp.org, "acme");
    assert!(resp.token.starts_with("prfn1_"));

    // ... and the key's tags reached the node row.
    let node_id = resp.node_id.clone().unwrap();
    let (tags,): (String,) = sqlx::query_as("SELECT tags FROM node WHERE id = ?1")
        .bind(&node_id)
        .fetch_one(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert!(
        tags.contains("lab") && tags.contains("nrf52"),
        "got {tags:?}"
    );
}

/// `created_by` is populated on this path — the column `coordinator auth-key`
/// leaves `NULL`. Revocation authorization is built on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_minted_key_records_the_user_who_minted_it() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;
    let created = create_key(&fleet, &session, &[]).await;

    let keys = fleet
        .db()
        .list_auth_keys(&OrgId("acme".to_owned()))
        .await
        .unwrap();
    let row = keys
        .iter()
        .find(|k| k.key_hash == created.key_hash)
        .expect("the minted key is in the org's listing");
    assert_eq!(row.created_by.as_deref(), Some("alice"));

    // The audit log records the human's authority, not the key's.
    let rows: Vec<(String, Option<String>, String)> =
        sqlx::query_as("SELECT org_id, subject, action FROM audit_log")
            .fetch_all(fleet.db().pool_for_test())
            .await
            .unwrap();
    assert!(
        rows.iter().any(|(org, subject, action)| org == "acme"
            && subject.as_deref() == Some("alice")
            && action == "auth_key.mint"),
        "got {rows:?}"
    );
}

/// A session whose `member` row is gone still authenticates and must still be
/// refused: minting an enrollment credential is acting in the org.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_member_with_a_valid_session_is_refused_and_audited() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "mallory", Role::Member).await;
    sqlx::query("DELETE FROM member WHERE user_id = ?1")
        .bind("mallory")
        .execute(fleet.db().pool_for_test())
        .await
        .unwrap();

    let (status, body) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&session),
            Some(create_body(&[], DAY, false)),
        )
        .await;
    assert_eq!(status, 403, "body: {body}");

    let rows: Vec<(String, Option<String>, String)> =
        sqlx::query_as("SELECT org_id, subject, action FROM audit_log")
            .fetch_all(fleet.db().pool_for_test())
            .await
            .unwrap();
    assert!(
        rows.iter().any(|(org, subject, action)| org == "acme"
            && subject.as_deref() == Some("mallory")
            && action == "auth_key.denied"),
        "got {rows:?}"
    );
    assert_eq!(
        fleet
            .db()
            .list_auth_keys(&OrgId("acme".to_owned()))
            .await
            .unwrap()
            .len(),
        0,
        "nothing was minted"
    );
}

/// The credential kind is part of the route: a node token is a 403 (the caller's
/// problem is the door), no credential at all a 401.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_session_token_opens_this_route() {
    let fleet = TestCoordinator::start().await;
    let (node_token, _) = fleet.seed_node("acme", "rpi-1").await;

    let (status, _) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&node_token),
            Some(create_body(&[], DAY, false)),
        )
        .await;
    assert_eq!(status, 403, "a node token must not mint auth keys");

    for bearer in [None, Some("prfs1_garbage")] {
        let (status, _) = fleet
            .http_auth(
                "POST",
                "/auth/keys",
                bearer,
                Some(create_body(&[], DAY, false)),
            )
            .await;
        assert_eq!(status, 401, "bearer: {bearer:?}");
    }

    // An auth key is redeemed, never presented: it cannot mint its successor.
    let key = fleet.seed_auth_key("acme", &[], true, None).await;
    let (status, _) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&key),
            Some(create_body(&[], DAY, false)),
        )
        .await;
    assert_eq!(status, 403, "an auth key must not mint auth keys");
}

/// A member-minted key must expire, and within the documented cap. A forever-key
/// is an operator's informed choice from a shell, not a hosted member's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_zero_or_over_cap_ttl_is_refused() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;

    for ttl in [0, 31 * DAY] {
        let (status, body) = fleet
            .http_auth(
                "POST",
                "/auth/keys",
                Some(&session),
                Some(create_body(&[], ttl, false)),
            )
            .await;
        assert_eq!(status, 400, "ttl {ttl}: {body}");
    }

    // The cap itself is allowed, and a normal TTL is honoured to the second.
    let before = i64::try_from(fleet.coord.now()).unwrap();
    let (status, body) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&session),
            Some(create_body(&[], 30 * DAY, false)),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    let created: AuthKeyCreated = serde_json::from_str(&body).unwrap();
    let expires = created.expires.unwrap();
    assert!(
        expires >= before + i64::try_from(30 * DAY).unwrap(),
        "expiry {expires} must honour the requested TTL"
    );
}

/// The listing is hash-only and org-scoped: it is safe to print, and it is not
/// a window into another tenant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listing_returns_hashes_only_and_never_another_org() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    let bob = fleet.seed_session("other", "bob", Role::Member).await;

    let mine = create_key(&fleet, &alice, &["lab"]).await;
    let theirs = create_key(&fleet, &bob, &[]).await;

    let (status, body) = fleet
        .http_auth("POST", "/auth/keys", Some(&alice), Some(list_body()))
        .await;
    assert_eq!(status, 200, "body: {body}");
    assert!(
        !body.contains(&mine.key) && !body.contains(&theirs.key),
        "a listing must never carry a secret: {body}"
    );
    let list: AuthKeyList = serde_json::from_str(&body).unwrap();
    assert_eq!(list.org, "acme");
    assert_eq!(list.keys.len(), 1);
    assert_eq!(list.keys[0].key_hash, mine.key_hash);
    assert_eq!(list.keys[0].created_by.as_deref(), Some("alice"));
    assert_eq!(list.keys[0].tags, vec!["lab".to_owned()]);
    assert!(list.keys[0].consumed_at.is_none());
}

/// Creator-revocation, and the consequence that matters: the key stops working.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_creator_revokes_their_own_key_and_it_stops_redeeming() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;
    let created = create_key(&fleet, &session, &[]).await;

    let (status, body) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&session),
            Some(revoke_body(&created.key_hash[..16])),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    let revoked: AuthKeyRevoked = serde_json::from_str(&body).unwrap();
    assert_eq!(revoked.revoked, vec![created.key_hash.clone()]);

    let (status, _) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(redeem_body(&created.key, "rpi-lab-1")),
        )
        .await;
    assert_eq!(status, 401, "a revoked key must not enroll anything");
}

/// Revocation follows the lease-ownership rule (§6.5): another member is
/// refused, an org admin is not — including for a key they did not mint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_is_creator_or_admin() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    let bob = fleet.seed_session("acme", "bob", Role::Member).await;
    let root = fleet.seed_session("acme", "root", Role::Admin).await;

    let alices = create_key(&fleet, &alice, &[]).await;

    let (status, _) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&bob),
            Some(revoke_body(&alices.key_hash[..16])),
        )
        .await;
    assert_eq!(status, 403, "a fellow member is not the key's owner");
    assert_eq!(
        fleet
            .db()
            .list_auth_keys(&OrgId("acme".to_owned()))
            .await
            .unwrap()
            .len(),
        1,
        "a refused revocation deletes nothing"
    );

    let (status, body) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&root),
            Some(revoke_body(&alices.key_hash[..16])),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");

    // ... and an admin can also revoke a shell-minted key, whose `created_by`
    // is NULL and which would otherwise be unrevokable from here.
    let shell_key = fleet.seed_auth_key("acme", &[], true, None).await;
    let hash = fleet_auth::OpaqueToken::parse(&shell_key).unwrap().hash();
    let (status, body) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&root),
            Some(revoke_body(&hash.as_str()[..16])),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
}

/// A prefix that cannot address one key on purpose is refused *before* the
/// delete: `delete_auth_keys_by_prefix("")` is `LIKE '%'`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_short_empty_or_non_hex_prefix_deletes_nothing() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;
    create_key(&fleet, &session, &[]).await;
    create_key(&fleet, &session, &[]).await;

    for prefix in ["", "   ", "abc", "zzzzzzzzzz", "aaaa-bbbb"] {
        let (status, body) = fleet
            .http_auth(
                "POST",
                "/auth/keys",
                Some(&session),
                Some(revoke_body(prefix)),
            )
            .await;
        assert_eq!(status, 400, "prefix {prefix:?}: {body}");
    }
    assert_eq!(
        fleet
            .db()
            .list_auth_keys(&OrgId("acme".to_owned()))
            .await
            .unwrap()
            .len(),
        2,
        "the org's keys survived every malformed prefix"
    );
}

/// An unknown prefix is a 404, and a cross-org one is indistinguishable from it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_or_cross_org_prefix_is_not_found() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    let bob = fleet.seed_session("other", "bob", Role::Member).await;
    let theirs = create_key(&fleet, &bob, &[]).await;

    for prefix in ["deadbeefdeadbeef", &theirs.key_hash[..16]] {
        let (status, body) = fleet
            .http_auth(
                "POST",
                "/auth/keys",
                Some(&alice),
                Some(revoke_body(prefix)),
            )
            .await;
        assert_eq!(status, 404, "prefix {prefix}: {body}");
    }
    // The other org's key is untouched.
    assert_eq!(
        fleet
            .db()
            .list_auth_keys(&OrgId("other".to_owned()))
            .await
            .unwrap()
            .len(),
        1
    );
}

/// An ambiguous prefix is refused rather than resolved to the first match, and
/// deletes nothing. The body stays coarse — the CLI says "be more specific".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ambiguous_prefix_is_a_conflict_and_deletes_nothing() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;

    // Two rows sharing a prefix, seeded directly so the collision is certain.
    let org = OrgId("acme".to_owned());
    for hash in ["abcd0000ffff1111", "abcd0000ffff2222"] {
        fleet
            .db()
            .insert_auth_key(&org, hash, &[], true, Some(9_999_999_999), Some("alice"), 1)
            .await
            .unwrap();
    }

    let (status, body) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&session),
            Some(revoke_body("abcd0000")),
        )
        .await;
    assert_eq!(status, 409, "body: {body}");
    assert_eq!(body, r#"{"error":"ambiguous_prefix"}"#);
    assert_eq!(
        fleet.db().list_auth_keys(&org).await.unwrap().len(),
        2,
        "an ambiguous revocation deletes nothing"
    );
}

// ---------------------------------------------------------------------------
// Named identities (`--as <name>`), architecture §6.7
// ---------------------------------------------------------------------------

/// A `subject_name` is echoed on create and carried into the listing.
///
/// The echo is not decoration: `/auth/keys` does not `deny_unknown_fields`, so
/// an older coordinator would ignore the field and mint an *unnamed* key while
/// returning `200`. The CLI compares what it asked for against this echo, so
/// the field being present and correct is a contract, not a convenience.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subject_name_is_echoed_on_create_and_listed() {
    let fleet = TestCoordinator::start().await;
    let (alice, _org, _id) = fleet.seed_github_user(1, "alice", Role::Admin).await;

    let (status, body) = fleet
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&alice),
            Some(
                serde_json::json!({
                    "action": "create",
                    "tags": ["nrf52"],
                    "ttl_secs": DAY,
                    "purpose": "ci",
                    // Mixed case on the way in: the identity is normalised, so
                    // a rotation months later can be typed either way.
                    "subject_name": "Builder-1",
                })
                .to_string(),
            ),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    let created: AuthKeyCreated = serde_json::from_str(&body).unwrap();
    assert_eq!(created.subject_name.as_deref(), Some("builder-1"));
    assert_eq!(created.purpose, "ci");

    let (status, body) = fleet
        .http_auth("POST", "/auth/keys", Some(&alice), Some(list_body()))
        .await;
    assert_eq!(status, 200, "body: {body}");
    let list: AuthKeyList = serde_json::from_str(&body).unwrap();
    assert_eq!(list.keys.len(), 1);
    assert_eq!(list.keys[0].subject_name.as_deref(), Some("builder-1"));
}

/// The refusals, all `400`: a name on a `node` key (which confers no subject
/// for one to attach to), a name that breaks the charset or length rule, and —
/// the one a UI author would otherwise discover the hard way — `purpose:
/// "node"`, which is **CLI-only sugar and not a wire value**.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_identity_name_or_purpose_is_refused() {
    let fleet = TestCoordinator::start().await;
    let (alice, _org, _id) = fleet.seed_github_user(1, "alice", Role::Admin).await;

    for (label, request) in [
        (
            "a name on a node key",
            serde_json::json!({"action": "create", "ttl_secs": DAY,
                               "purpose": "node", "subject_name": "builder"}),
        ),
        (
            "a name with no purpose at all (i.e. node)",
            serde_json::json!({"action": "create", "ttl_secs": DAY,
                               "subject_name": "builder"}),
        ),
        (
            "a name containing a colon, which would spell the `key:<hash>` form",
            serde_json::json!({"action": "create", "tags": ["nrf52"], "ttl_secs": DAY,
                               "purpose": "ci", "subject_name": "key:deadbeef"}),
        ),
        (
            "a name containing a slash, which would look like a repo subject",
            serde_json::json!({"action": "create", "tags": ["nrf52"], "ttl_secs": DAY,
                               "purpose": "ci", "subject_name": "owner/repo"}),
        ),
        (
            "an empty name",
            serde_json::json!({"action": "create", "tags": ["nrf52"], "ttl_secs": DAY,
                               "purpose": "ci", "subject_name": ""}),
        ),
        (
            "a name starting with a dash",
            serde_json::json!({"action": "create", "tags": ["nrf52"], "ttl_secs": DAY,
                               "purpose": "ci", "subject_name": "-builder"}),
        ),
        (
            "an over-length name",
            serde_json::json!({"action": "create", "tags": ["nrf52"], "ttl_secs": DAY,
                               "purpose": "ci", "subject_name": "x".repeat(65)}),
        ),
        (
            "`node` is CLI sugar, not a wire purpose",
            serde_json::json!({"action": "create", "tags": ["nrf52"], "ttl_secs": DAY,
                               "purpose": "node", "subject_name": "builder"}),
        ),
    ] {
        let (status, body) = fleet
            .http_auth(
                "POST",
                "/auth/keys",
                Some(&alice),
                Some(request.to_string()),
            )
            .await;
        assert_eq!(status, 400, "{label}: {body}");
    }

    // Nothing was minted along the way.
    let (status, body) = fleet
        .http_auth("POST", "/auth/keys", Some(&alice), Some(list_body()))
        .await;
    assert_eq!(status, 200, "body: {body}");
    let list: AuthKeyList = serde_json::from_str(&body).unwrap();
    assert!(list.keys.is_empty(), "a refused mint must store nothing");
}

/// Absence has one spelling: a key minted without `subject_name` reads back as
/// absent, not as an empty string, so nothing downstream can synthesise the
/// nameless identity `<org>/workload:agent:`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_minted_without_a_name_has_no_identity() {
    let fleet = TestCoordinator::start().await;
    let (alice, _org, _id) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let created = create_key(&fleet, &alice, &["nrf52"]).await;
    assert_eq!(created.subject_name, None);

    let (status, body) = fleet
        .http_auth("POST", "/auth/keys", Some(&alice), Some(list_body()))
        .await;
    assert_eq!(status, 200, "body: {body}");
    let list: AuthKeyList = serde_json::from_str(&body).unwrap();
    assert_eq!(list.keys[0].subject_name, None);
}
