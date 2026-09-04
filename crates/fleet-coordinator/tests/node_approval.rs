//! Interactive node approval end to end (architecture §4.2 rung 3, §6.4).
//!
//! The ceremony: a headless machine posts to `/node/register/start`, prints the
//! short code it gets back, and polls. A logged-in member runs the approval
//! route. The next poll mints a node token.
//!
//! What these tests are actually for, in rough order of how badly it would hurt
//! to get them wrong:
//!
//! * the minted token **authenticates on `/agent`** — proof it is a credential,
//!   not a plausible-looking string;
//! * redemption is **single-use**, approval **single-binding**, and denial
//!   permanent, whatever races;
//! * approval cannot silently take over an existing node in the approver's org;
//! * `GET /node/approve` reflects nothing;
//! * a serve path with no `ConnectInfo` degrades to `source_ip = null` rather
//!   than 500ing (every harness here is such a path, deliberately).

mod common;

use common::TestCoordinator;

use fleet_auth::api::{NodeApprovalResponse, NodeRegisterStartResponse, TokenResponse};
use fleet_auth::{OpaqueToken, TokenKind};
use fleet_proto::ids::{OrgId, Role};

fn start_body(node_name: &str, tags: &[&str], adopt: Option<&str>) -> String {
    let mut body = serde_json::json!({
        "node_name": node_name,
        "tags": tags,
    });
    if let Some(adopt) = adopt {
        body["adopt"] = serde_json::json!(adopt);
    }
    body.to_string()
}

fn poll_body(device_secret: &str) -> String {
    serde_json::json!({ "device_secret": device_secret }).to_string()
}

fn decision_body(code: &str, decision: &str, replace: bool) -> String {
    serde_json::json!({
        "user_code": code,
        "decision": decision,
        "replace": replace,
    })
    .to_string()
}

/// Begin a registration, asserting success.
async fn start(fleet: &TestCoordinator, node_name: &str) -> NodeRegisterStartResponse {
    let (status, body) = fleet
        .http(
            "POST",
            "/node/register/start",
            Some(start_body(node_name, &["lab"], None)),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    serde_json::from_str(&body).unwrap()
}

/// Send a decision, returning `(status, body)` for the caller to judge.
async fn decide(
    fleet: &TestCoordinator,
    session: &str,
    code: &str,
    decision: &str,
    replace: bool,
) -> (u16, String) {
    fleet
        .http_auth(
            "POST",
            "/node/register/approve",
            Some(session),
            Some(decision_body(code, decision, replace)),
        )
        .await
}

/// The whole ceremony, and the assertion that matters most: the token works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_approves_a_headless_machine_into_their_own_org() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;

    let grant = start(&fleet, "rpi-lab-3").await;
    assert!(grant.device_secret.starts_with("prfnd1_"));
    assert_eq!(grant.user_code.len(), 9, "hyphenated: {}", grant.user_code);
    assert!(grant.verification_uri.ends_with("/node/approve"));
    // Deliberately no code in the URL: the page must never reflect one.
    assert!(!grant
        .verification_uri
        .contains(&grant.user_code.replace('-', "")));

    // Before approval, the machine is told to keep waiting — and told exactly
    // that, because this describes its *own* registration.
    let (status, body) = fleet
        .http(
            "POST",
            "/node/register/poll",
            Some(poll_body(&grant.device_secret)),
        )
        .await;
    assert_eq!(status, 401);
    assert!(body.contains("authorization_pending"), "body: {body}");

    // Inspect first, as the CLI always does.
    let (status, body) = decide(&fleet, &session, &grant.user_code, "inspect", false).await;
    assert_eq!(status, 200, "body: {body}");
    let seen: NodeApprovalResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(seen.node_name, "rpi-lab-3");
    assert_eq!(seen.tags, vec!["lab".to_owned()]);
    assert_eq!(seen.adopt, "auto", "a live human approving means `auto`");
    assert_eq!(seen.state, "pending");
    assert!(seen.collides_with.is_none());
    // Inspecting changes nothing.
    let (status, _) = fleet
        .http(
            "POST",
            "/node/register/poll",
            Some(poll_body(&grant.device_secret)),
        )
        .await;
    assert_eq!(status, 401);

    let (status, body) = decide(&fleet, &session, &grant.user_code, "approve", false).await;
    assert_eq!(status, 200, "body: {body}");
    let approved: NodeApprovalResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(approved.state, "approved");
    assert_eq!(approved.org.as_deref(), Some("acme"));

    let (status, body) = fleet
        .http(
            "POST",
            "/node/register/poll",
            Some(poll_body(&grant.device_secret)),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    let minted: TokenResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(minted.org, "acme", "the approver's org, not a default");
    assert!(minted.token.starts_with("prfn1_"));
    assert!(minted.coordinator_token_pubkey.is_some());
    let node_id = minted.node_id.clone().unwrap();
    assert_eq!(node_id, "acme/rpi-lab-3");

    // The credential is real: it authenticates a `/agent` upgrade.
    let (tx, rx) = fleet
        .dial("/agent", &minted.token)
        .await
        .expect("the approved node's token must authenticate on /agent");
    drop((tx, rx));

    // The node row looks exactly like `share`'s: owned by the human whose
    // authority created it, in their org, with the requested policy and tags.
    let (org, owner, adopt, tags): (String, Option<String>, String, String) =
        sqlx::query_as("SELECT org_id, owner_user_id, adopt_policy, tags FROM node WHERE id = ?1")
            .bind(&node_id)
            .fetch_one(fleet.db().pool_for_test())
            .await
            .unwrap();
    assert_eq!(org, "acme");
    assert_eq!(owner.as_deref(), Some("alice"), "owned by the approver");
    assert_eq!(adopt, "auto");
    assert_eq!(tags, "lab");

    // Audited under the approving org, with the human as the subject.
    let rows: Vec<(String, Option<String>, String)> =
        sqlx::query_as("SELECT org_id, subject, action FROM audit_log")
            .fetch_all(fleet.db().pool_for_test())
            .await
            .unwrap();
    for action in [
        "node.approve.inspect",
        "node.approve",
        "node.approve_register",
    ] {
        assert!(
            rows.iter().any(|(org, subject, a)| org == "acme"
                && subject.as_deref() == Some("alice")
                && a == action),
            "missing {action} in {rows:?}"
        );
    }
}

/// Redemption is single-use and approval single-binding: the two properties
/// that make the ceremony safe under concurrency.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_and_redemption_each_happen_at_most_once() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    let bob = fleet.seed_session("other", "bob", Role::Member).await;

    let grant = start(&fleet, "rpi").await;
    let (status, _) = decide(&fleet, &alice, &grant.user_code, "approve", false).await;
    assert_eq!(status, 200);

    // A second approval, from another org, binds nothing: the machine cannot be
    // pulled into two tenants.
    let (status, body) = decide(&fleet, &bob, &grant.user_code, "approve", false).await;
    assert_eq!(status, 404, "body: {body}");
    assert!(body.contains("invalid_grant"), "body: {body}");

    let (status, body) = fleet
        .http(
            "POST",
            "/node/register/poll",
            Some(poll_body(&grant.device_secret)),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    let minted: TokenResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(minted.org, "acme");

    // A second poll mints nothing.
    let (status, body) = fleet
        .http(
            "POST",
            "/node/register/poll",
            Some(poll_body(&grant.device_secret)),
        )
        .await;
    assert_eq!(status, 401, "body: {body}");
    assert!(body.contains("invalid_grant"), "body: {body}");
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM node")
        .fetch_one(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert_eq!(count, 1, "exactly one node was created");
}

/// Denial is final, and the waiting machine is told so rather than left to time
/// out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_denied_registration_is_told_so_and_stays_dead() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;
    let grant = start(&fleet, "rpi").await;

    let (status, body) = decide(&fleet, &session, &grant.user_code, "deny", false).await;
    assert_eq!(status, 200, "body: {body}");
    let denied: NodeApprovalResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(denied.state, "denied");

    let (status, body) = fleet
        .http(
            "POST",
            "/node/register/poll",
            Some(poll_body(&grant.device_secret)),
        )
        .await;
    assert_eq!(status, 401);
    assert!(body.contains("access_denied"), "body: {body}");

    // And it cannot be resurrected by approving afterwards.
    let (status, _) = decide(&fleet, &session, &grant.user_code, "approve", false).await;
    assert_eq!(status, 404);
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM node")
        .fetch_one(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert_eq!(count, 0);
}

/// The takeover guard, enforced **server-side**: the requesting machine chose
/// its own name before any org existed, so approving it must not silently
/// re-credential a node the approver's org is already running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_refuses_to_take_over_an_existing_node_without_replace() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;
    let (existing_token, _) = fleet.seed_node("acme", "rpi-lab-3").await;

    let grant = start(&fleet, "rpi-lab-3").await;

    // Inspect names the collision, which is what the CLI shouts about.
    let (status, body) = decide(&fleet, &session, &grant.user_code, "inspect", false).await;
    assert_eq!(status, 200, "body: {body}");
    let seen: NodeApprovalResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(seen.collides_with.as_deref(), Some("acme/rpi-lab-3"));

    // Approving without `--replace` is refused with a named code, before any
    // state change: the running machine keeps its token.
    let (status, body) = decide(&fleet, &session, &grant.user_code, "approve", false).await;
    assert_eq!(status, 409, "body: {body}");
    assert!(body.contains("node_name_taken"), "body: {body}");
    let (tx, rx) = fleet
        .dial("/agent", &existing_token)
        .await
        .expect("the running node keeps working after a refused takeover");
    drop((tx, rx));

    // With `--replace` it goes through, and the old credential dies — which is
    // exactly why it needs the flag.
    let (status, body) = decide(&fleet, &session, &grant.user_code, "approve", true).await;
    assert_eq!(status, 200, "body: {body}");
    let (status, body) = fleet
        .http(
            "POST",
            "/node/register/poll",
            Some(poll_body(&grant.device_secret)),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&existing_token)).await,
        401,
        "the replaced node's token must stop working"
    );
}

/// Membership is required, and so is the right *kind* of credential.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approving_needs_a_member_session_and_nothing_else() {
    let fleet = TestCoordinator::start().await;
    // A valid session whose user is not a member of the org it names.
    let stranger = {
        let org = OrgId("acme".to_owned());
        fleet.db().ensure_org(&org, "personal").await.unwrap();
        fleet
            .db()
            .ensure_user_member(&OrgId("elsewhere".to_owned()), "mallory", Role::Member)
            .await
            .unwrap();
        let token = OpaqueToken::mint(TokenKind::Session);
        let now = i64::try_from(fleet.coord.now()).unwrap();
        fleet
            .db()
            .insert_session(token.hash().as_str(), &org, "mallory", now, now + 3_600)
            .await
            .unwrap();
        token.to_secret_string()
    };
    let (node_token, _) = fleet.seed_node("acme", "some-node").await;
    let grant = start(&fleet, "rpi").await;

    // Non-member: 403, audited.
    let (status, body) = decide(&fleet, &stranger, &grant.user_code, "approve", false).await;
    assert_eq!(status, 403, "body: {body}");

    // A node token is the wrong kind for this route: 403, not 401 — the
    // caller's problem is the door it knocked on.
    let (status, _) = decide(&fleet, &node_token, &grant.user_code, "approve", false).await;
    assert_eq!(status, 403);

    // The device secret is not a connection credential either.
    let (status, _) = decide(
        &fleet,
        &grant.device_secret,
        &grant.user_code,
        "approve",
        false,
    )
    .await;
    assert_eq!(status, 403);

    // No credential at all: 401.
    let (status, _) = fleet
        .http(
            "POST",
            "/node/register/approve",
            Some(decision_body(&grant.user_code, "approve", false)),
        )
        .await;
    assert_eq!(status, 401);

    // Through all of that, nothing was approved.
    let (status, body) = fleet
        .http(
            "POST",
            "/node/register/poll",
            Some(poll_body(&grant.device_secret)),
        )
        .await;
    assert_eq!(status, 401);
    assert!(body.contains("authorization_pending"), "body: {body}");
}

/// Unknown, malformed and already-decided codes are one uniform answer: a
/// caller learns nothing about which it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_and_malformed_codes_are_indistinguishable() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;

    for code in ["ZZZZ9999", "nonsense", "", "ABCD-123"] {
        let (status, body) = decide(&fleet, &session, code, "approve", false).await;
        assert_eq!(status, 404, "{code}: {body}");
        assert!(body.contains("invalid_grant"), "{code}: {body}");
    }
}

/// One code, several spellings: what the human reads off a screen and types
/// must work, including the Crockford confusables.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_code_is_accepted_however_a_human_spells_it() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;
    let grant = start(&fleet, "rpi").await;
    let canonical = grant.user_code.replace('-', "");

    // Lower case and no hyphen both resolve to the same pending row.
    for spelling in [canonical.to_lowercase(), grant.user_code.to_lowercase()] {
        let (status, body) = decide(&fleet, &session, &spelling, "inspect", false).await;
        assert_eq!(status, 200, "{spelling}: {body}");
    }

    // ... and so do the confusables, when the code contains one.
    let confusable: String = canonical
        .chars()
        .map(|c| match c {
            '1' => 'l',
            '0' => 'O',
            other => other,
        })
        .collect();
    let (status, body) = decide(&fleet, &session, &confusable, "inspect", false).await;
    assert_eq!(status, 200, "{confusable}: {body}");
}

/// The informational page: unauthenticated, stateless, and **reflecting
/// nothing**. The moment it echoes input it is an injection surface.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_approval_page_is_static_and_reflects_nothing() {
    let fleet = TestCoordinator::start().await;

    let (status, plain) = fleet.http("GET", "/node/approve", None).await;
    assert_eq!(status, 200);
    assert!(plain.contains("probe-rs-fleet node approve"), "{plain}");
    assert!(plain.contains("cannot see it from here"), "{plain}");

    for query in [
        "?code=ABCD-1234",
        // Percent-encoded, because a raw `<` is not a legal URI character and
        // would fail in the client rather than reaching the handler.
        "?x=%3Cscript%3Ealert(1)%3C/script%3E",
        "?code=ABCD-1234&other=1",
    ] {
        let (status, body) = fleet
            .http("GET", &format!("/node/approve{query}"), None)
            .await;
        assert_eq!(status, 200);
        assert_eq!(body, plain, "the page must be byte-identical for {query}");
    }
}

/// Attacker-controlled strings are refused at the door, because they end up in
/// a human's terminal (and inside the node id).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_names_and_tags_are_refused_at_registration() {
    let fleet = TestCoordinator::start().await;

    for name in [
        "",
        "  ",
        "evil/../../etc",
        "\x1b[2J\x1b[Hevil",
        "with space",
        "a\nb",
        &"x".repeat(65),
    ] {
        let (status, body) = fleet
            .http(
                "POST",
                "/node/register/start",
                Some(start_body(name, &[], None)),
            )
            .await;
        assert_eq!(status, 400, "{name:?} was accepted: {body}");
    }

    // Tags get the same treatment, and there is a ceiling on how many.
    for tags in [
        vec!["\x1b[2J"],
        vec!["two words"],
        vec![""],
        (0..17).map(|_| "t").collect(),
    ] {
        let (status, body) = fleet
            .http(
                "POST",
                "/node/register/start",
                Some(start_body("rpi", &tags, None)),
            )
            .await;
        assert_eq!(status, 400, "{tags:?} was accepted: {body}");
    }

    // An unrecognised adoption policy is a 400, never a silent default.
    let (status, _) = fleet
        .http(
            "POST",
            "/node/register/start",
            Some(start_body("rpi", &[], Some("delcared"))),
        )
        .await;
    assert_eq!(status, 400);

    // Nothing hostile was written.
    assert_eq!(
        fleet.db().live_pending_node_count(0).await.unwrap(),
        0,
        "a refused registration must not leave a row"
    );
}

/// The cap on unauthenticated growth, and its honest cost: at the ceiling,
/// legitimate machines are refused too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pending_table_is_bounded() {
    let fleet = TestCoordinator::start_with(|c| c.max_pending_nodes = 2).await;

    for i in 0..2 {
        let (status, body) = fleet
            .http(
                "POST",
                "/node/register/start",
                Some(start_body(&format!("rpi-{i}"), &[], None)),
            )
            .await;
        assert_eq!(status, 200, "body: {body}");
    }
    let (status, body) = fleet
        .http(
            "POST",
            "/node/register/start",
            Some(start_body("rpi-2", &[], None)),
        )
        .await;
    assert_eq!(status, 503, "body: {body}");
    assert!(body.contains("too_many_pending"), "body: {body}");
}

/// A registration that outlives its TTL cannot be approved or redeemed, and the
/// waiting machine is told which it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_registration_is_refused_at_both_ends() {
    let fleet = TestCoordinator::start_with(|c| c.pending_node_ttl_secs = 1).await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;
    let grant = start(&fleet, "rpi").await;

    // Age the row rather than the clock: the coordinator uses the system clock
    // here and this is the honest way to reach the boundary.
    sqlx::query("UPDATE pending_node SET expires = 1")
        .execute(fleet.db().pool_for_test())
        .await
        .unwrap();

    let (status, body) = fleet
        .http(
            "POST",
            "/node/register/poll",
            Some(poll_body(&grant.device_secret)),
        )
        .await;
    assert_eq!(status, 401);
    assert!(body.contains("expired_token"), "body: {body}");

    let (status, body) = decide(&fleet, &session, &grant.user_code, "approve", false).await;
    assert_eq!(status, 404, "body: {body}");
}

/// A poll credential of the wrong kind, or one nobody issued, is one answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bogus_device_secret_is_one_uniform_rejection() {
    let fleet = TestCoordinator::start().await;
    let session_token = fleet.seed_session("acme", "alice", Role::Member).await;

    for secret in [
        "garbage".to_owned(),
        session_token,
        OpaqueToken::mint(TokenKind::Node).to_secret_string(),
    ] {
        let (status, body) = fleet
            .http("POST", "/node/register/poll", Some(poll_body(&secret)))
            .await;
        assert_eq!(status, 401, "body: {body}");
        assert!(body.contains("invalid_grant"), "body: {body}");
    }

    // A well-formed device secret nobody issued: the row is unknown, which is
    // indistinguishable from expired by design.
    let unissued = OpaqueToken::mint(TokenKind::NodeDevice).to_secret_string();
    let (status, body) = fleet
        .http("POST", "/node/register/poll", Some(poll_body(&unissued)))
        .await;
    assert_eq!(status, 401, "body: {body}");
}

/// The degraded `ConnectInfo` path, asserted rather than assumed: this harness
/// serves with a plain `axum::serve`, so the extension is absent. It must
/// record `source_ip = null`, not 500.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_serve_path_without_connect_info_records_no_source_ip() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;

    let grant = start(&fleet, "rpi").await;
    let (status, body) = decide(&fleet, &session, &grant.user_code, "inspect", false).await;
    assert_eq!(status, 200, "body: {body}");
    let seen: NodeApprovalResponse = serde_json::from_str(&body).unwrap();
    assert!(
        seen.source_ip.is_none(),
        "expected a degraded null, got {:?}",
        seen.source_ip
    );
}

/// The sweep is hygiene, and it is what returns capacity under the cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sweep_reclaims_spent_and_expired_registrations() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", Role::Member).await;

    let denied = start(&fleet, "rpi-denied").await;
    let expired = start(&fleet, "rpi-expired").await;
    let live = start(&fleet, "rpi-live").await;
    let (status, _) = decide(&fleet, &session, &denied.user_code, "deny", false).await;
    assert_eq!(status, 200);
    sqlx::query("UPDATE pending_node SET expires = 1 WHERE node_name = 'rpi-expired'")
        .execute(fleet.db().pool_for_test())
        .await
        .unwrap();

    fleet_coordinator::sweep::sweep_once(&fleet.coord).await;

    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM pending_node")
        .fetch_one(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert_eq!(count, 1, "only the live registration survives");
    let (status, body) = fleet
        .http(
            "POST",
            "/node/register/poll",
            Some(poll_body(&live.device_secret)),
        )
        .await;
    assert_eq!(status, 401);
    assert!(body.contains("authorization_pending"), "body: {body}");
    // The expired one is gone, so its poll now reads as unknown/expired rather
    // than as anything the caller can act on differently.
    let (status, _) = fleet
        .http(
            "POST",
            "/node/register/poll",
            Some(poll_body(&expired.device_secret)),
        )
        .await;
    assert_eq!(status, 401);
}
