//! Interactive node approval end to end (architecture §4.2 rung 3, §6.4).
//!
//! The ceremony: a headless machine posts to `/node/register/start`, prints the
//! short code it gets back, and polls. A logged-in member runs the approval
//! route, naming the org the machine joins (`org`, default their personal
//! org). The next poll mints a node token.
//!
//! forgs owns the user-code / device-secret machine (a pending row with a JSON
//! payload); fleet's `FleetNodeApprovals` hook decides who may approve and
//! mints the node token, and `decide_pending_node` holds the takeover guard.
//! These tests drive the whole stack over HTTP.
//!
//! What these tests are actually for, in rough order of how badly it would hurt
//! to get them wrong:
//!
//! * the minted token **authenticates on `/agent`** — proof it is a credential,
//!   not a plausible-looking string — and lands in the **chosen** org;
//! * approving into an org needs **membership** of that org (a non-member or
//!   unknown org is one `403`);
//! * redemption is **single-use**, approval **single-binding**, and denial
//!   permanent, whatever races;
//! * approval cannot silently take over an existing node in the target org;
//! * the browser surface (`POST /api/v1/nodes/pending/{code}`) is the same
//!   ceremony behind cookie + CSRF, and the CLI route never accepts a cookie;
//! * `GET /node/approve` reflects nothing;
//! * the recorded source address is the socket peer, never `X-Forwarded-For`.

mod common;

use common::TestCoordinator;

use forgs::TokenKind;
use probefleet_coordinator::FleetRole;
use probefleet_proto::auth_api::{
    NodeApprovalResponse, NodeRegisterStartResponse, NodeTokenResponse,
};

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

fn decision_body(code: &str, decision: &str, replace: bool, org: Option<&str>) -> String {
    let mut body = serde_json::json!({
        "user_code": code,
        "decision": decision,
        "replace": replace,
    });
    if let Some(org) = org {
        body["org"] = serde_json::json!(org);
    }
    body.to_string()
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

/// Poll once, returning `(status, body)`.
async fn poll(fleet: &TestCoordinator, device_secret: &str) -> (u16, String) {
    fleet
        .http(
            "POST",
            "/node/register/poll",
            Some(poll_body(device_secret)),
        )
        .await
}

/// Send a decision on the CLI route into `org` (`None`: the approver's
/// personal org), returning `(status, body)` for the caller to judge.
async fn decide(
    fleet: &TestCoordinator,
    session: &str,
    code: &str,
    decision: &str,
    replace: bool,
    org: Option<&str>,
) -> (u16, String) {
    fleet
        .http_auth(
            "POST",
            "/node/register/approve",
            Some(session),
            Some(decision_body(code, decision, replace, org)),
        )
        .await
}

/// Rows in forgs' pending-approval table.
async fn pending_rows(fleet: &TestCoordinator) -> i64 {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM forgs_pending_device")
        .fetch_one(fleet.db().pool_for_test())
        .await
        .unwrap();
    count
}

/// Rows in fleet's node table.
async fn node_rows(fleet: &TestCoordinator) -> i64 {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM node")
        .fetch_one(fleet.db().pool_for_test())
        .await
        .unwrap();
    count
}

/// The whole ceremony, and the assertion that matters most: the token works,
/// in the org the approver chose.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_approves_a_headless_machine_into_a_chosen_org() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let acme = fleet.org("acme").await;
    let alice = fleet.user("alice").await;

    let grant = start(&fleet, "rpi-lab-3").await;
    assert!(grant.device_secret.starts_with("prfd1_"));
    assert_eq!(grant.user_code.len(), 9, "hyphenated: {}", grant.user_code);
    assert!(grant.verification_uri.ends_with("/node/approve"));
    // Deliberately no code in the URL: the page must never reflect one.
    assert!(!grant
        .verification_uri
        .contains(&grant.user_code.replace('-', "")));

    // Before approval, the machine is told to keep waiting — and told exactly
    // that, because this describes its *own* registration.
    let (status, body) = poll(&fleet, &grant.device_secret).await;
    assert_eq!(status, 401);
    assert!(body.contains("authorization_pending"), "body: {body}");

    // Inspect first, as the CLI always does.
    let (status, body) = decide(
        &fleet,
        &session,
        &grant.user_code,
        "inspect",
        false,
        Some("acme"),
    )
    .await;
    assert_eq!(status, 200, "body: {body}");
    let seen: NodeApprovalResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(seen.node_name, "rpi-lab-3");
    assert_eq!(seen.tags, vec!["lab".to_owned()]);
    assert_eq!(seen.adopt, "auto", "a live human approving means `auto`");
    assert_eq!(seen.state, "pending");
    assert!(seen.collides_with.is_none());
    // Inspecting changes nothing. (Polling again inside the interval is also
    // told to slow down — still not a credential.)
    let (status, body) = poll(&fleet, &grant.device_secret).await;
    assert_eq!(status, 401);
    assert!(body.contains("slow_down"), "body: {body}");

    let (status, body) = decide(
        &fleet,
        &session,
        &grant.user_code,
        "approve",
        false,
        Some("acme"),
    )
    .await;
    assert_eq!(status, 200, "body: {body}");
    let approved: NodeApprovalResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(approved.state, "approved");
    assert_eq!(approved.org.as_deref(), Some(acme.0.as_str()));

    let (status, body) = poll(&fleet, &grant.device_secret).await;
    assert_eq!(status, 200, "body: {body}");
    let minted: NodeTokenResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(minted.org, acme.0, "the chosen org, not a default");
    assert_eq!(minted.org_name.as_deref(), Some("acme"));
    assert!(minted.token.starts_with("prfn1_"));
    assert!(!minted.coordinator_token_pubkey.is_empty());
    let node_id = minted.node_id.clone();
    assert_eq!(
        node_id,
        probefleet_coordinator::node_id_for(&acme, "rpi-lab-3").0
    );

    // The credential is real: it authenticates a `/agent` upgrade.
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&minted.token)).await,
        101,
        "the approved node's token must authenticate on /agent"
    );

    // The node row looks exactly like `share`'s: owned by the human whose
    // authority created it, in the chosen org, with the requested policy and
    // tags.
    let (org, owner, adopt, tags): (String, Option<String>, String, String) = sqlx::query_as(
        "SELECT ns_node_id, owner_user_id, adopt_policy, tags FROM node WHERE id = ?1",
    )
    .bind(&node_id)
    .fetch_one(fleet.db().pool_for_test())
    .await
    .unwrap();
    assert_eq!(org, acme.0);
    assert_eq!(owner, Some(alice.to_string()), "owned by the approver");
    assert_eq!(adopt, "auto");
    assert_eq!(tags, "lab");

    // Audited under the approving org, with the human as the subject.
    let alice_key = format!("user:{alice}");
    let rows = fleet.audit_rows().await;
    for action in [
        "node.approve.inspect",
        "node.approve",
        "node.approve_register",
    ] {
        assert!(
            rows.iter().any(|(org, subject, a)| *org == acme.0
                && subject.as_deref() == Some(alice_key.as_str())
                && a == action),
            "missing {action} in {rows:?}"
        );
    }
    // forgs' own record of the decision.
    assert!(fleet
        .forgs_audit_actions()
        .await
        .contains(&"device.approve".to_owned()));
}

/// With no `org` the approval binds into the approver's **personal** org, and
/// the org can also be named by id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_default_target_is_the_personal_org_and_ids_work_too() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let personal = fleet.personal_org("alice").await;
    let acme = fleet.org("acme").await;

    let grant = start(&fleet, "rpi-home").await;
    let (status, body) = decide(&fleet, &session, &grant.user_code, "approve", false, None).await;
    assert_eq!(status, 200, "body: {body}");
    let (status, body) = poll(&fleet, &grant.device_secret).await;
    assert_eq!(status, 200, "body: {body}");
    let minted: NodeTokenResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(minted.org, personal.0, "no `org` means the personal org");
    assert_ne!(minted.org, acme.0);
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&minted.token)).await,
        101
    );

    let grant = start(&fleet, "rpi-lab").await;
    let (status, body) = decide(
        &fleet,
        &session,
        &grant.user_code,
        "approve",
        false,
        Some(&acme.0),
    )
    .await;
    assert_eq!(status, 200, "body: {body}");
    let (status, body) = poll(&fleet, &grant.device_secret).await;
    assert_eq!(status, 200, "body: {body}");
    let minted: NodeTokenResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(minted.org, acme.0, "an org named by id");
}

/// Redemption is single-use and approval single-binding: the two properties
/// that make the ceremony safe under concurrency.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_and_redemption_each_happen_at_most_once() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let bob = fleet.seed_session("other", "bob", FleetRole::Member).await;
    let acme = fleet.org("acme").await;

    let grant = start(&fleet, "rpi").await;
    let (status, _) = decide(
        &fleet,
        &alice,
        &grant.user_code,
        "approve",
        false,
        Some("acme"),
    )
    .await;
    assert_eq!(status, 200);

    // A second approval, into another org, binds nothing: the machine cannot
    // be pulled into two tenants.
    let (status, body) = decide(
        &fleet,
        &bob,
        &grant.user_code,
        "approve",
        false,
        Some("other"),
    )
    .await;
    assert_eq!(status, 404, "body: {body}");
    assert!(body.contains("invalid_grant"), "body: {body}");

    let (status, body) = poll(&fleet, &grant.device_secret).await;
    assert_eq!(status, 200, "body: {body}");
    let minted: NodeTokenResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(minted.org, acme.0);

    // A second poll mints nothing.
    let (status, body) = poll(&fleet, &grant.device_secret).await;
    assert_eq!(status, 401, "body: {body}");
    assert!(body.contains("invalid_grant"), "body: {body}");
    assert_eq!(node_rows(&fleet).await, 1, "exactly one node was created");
}

/// Denial is final, and the waiting machine is told so rather than left to time
/// out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_denied_registration_is_told_so_and_stays_dead() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let grant = start(&fleet, "rpi").await;

    let (status, body) = decide(
        &fleet,
        &session,
        &grant.user_code,
        "deny",
        false,
        Some("acme"),
    )
    .await;
    assert_eq!(status, 200, "body: {body}");
    let denied: NodeApprovalResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(denied.state, "denied");

    let (status, body) = poll(&fleet, &grant.device_secret).await;
    assert_eq!(status, 401);
    assert!(body.contains("access_denied"), "body: {body}");

    // And it cannot be resurrected by approving afterwards.
    let (status, _) = decide(
        &fleet,
        &session,
        &grant.user_code,
        "approve",
        false,
        Some("acme"),
    )
    .await;
    assert_eq!(status, 404);
    assert_eq!(node_rows(&fleet).await, 0);
}

/// The takeover guard, enforced **server-side**: the requesting machine chose
/// its own name before any org existed, so approving it must not silently
/// re-credential a node the target org is already running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_refuses_to_take_over_an_existing_node_without_replace() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let (existing_token, existing_id) = fleet.seed_node("acme", "rpi-lab-3").await;

    let grant = start(&fleet, "rpi-lab-3").await;

    // Inspect names the collision, which is what the CLI shouts about.
    let (status, body) = decide(
        &fleet,
        &session,
        &grant.user_code,
        "inspect",
        false,
        Some("acme"),
    )
    .await;
    assert_eq!(status, 200, "body: {body}");
    let seen: NodeApprovalResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(seen.collides_with.as_deref(), Some(existing_id.0.as_str()));

    // The same name in a different org (here: the personal one) is no
    // collision: the guard is per org.
    let (status, body) = decide(&fleet, &session, &grant.user_code, "inspect", false, None).await;
    assert_eq!(status, 200, "body: {body}");
    let seen: NodeApprovalResponse = serde_json::from_str(&body).unwrap();
    assert!(seen.collides_with.is_none(), "{seen:?}");

    // Approving without `--replace` is refused with a named code, before any
    // state change: the running machine keeps its token.
    let (status, body) = decide(
        &fleet,
        &session,
        &grant.user_code,
        "approve",
        false,
        Some("acme"),
    )
    .await;
    assert_eq!(status, 409, "body: {body}");
    assert!(body.contains("node_name_taken"), "body: {body}");
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&existing_token)).await,
        101,
        "the running node keeps working after a refused takeover"
    );
    let (status, body) = poll(&fleet, &grant.device_secret).await;
    assert_eq!(status, 401);
    assert!(body.contains("authorization_pending"), "body: {body}");

    // With `--replace` it goes through, and the old credential dies — which is
    // exactly why it needs the flag.
    let (status, body) = decide(
        &fleet,
        &session,
        &grant.user_code,
        "approve",
        true,
        Some("acme"),
    )
    .await;
    assert_eq!(status, 200, "body: {body}");
    let (status, body) = poll(&fleet, &grant.device_secret).await;
    assert_eq!(status, 200, "body: {body}");
    let minted: NodeTokenResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(minted.node_id, existing_id.0);
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&existing_token)).await,
        401,
        "the replaced node's token must stop working"
    );
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&minted.token)).await,
        101
    );
}

/// Membership of the **target** org is required, and so is the right *kind*
/// of credential.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approving_needs_membership_of_the_target_org_and_a_session() {
    let fleet = TestCoordinator::start().await;
    fleet.org("acme").await;
    // A valid session whose user is a member of their personal org only.
    let (stranger, _, _) = fleet.seed_user("mallory").await;
    let (node_token, _) = fleet.seed_node("acme", "some-node").await;
    let grant = start(&fleet, "rpi").await;

    // Non-member of an existing org, and an org that does not exist: one 403
    // (the route is no org-existence oracle), audited.
    for org in ["acme", "no-such-org"] {
        for decision in ["inspect", "approve"] {
            let (status, body) = decide(
                &fleet,
                &stranger,
                &grant.user_code,
                decision,
                false,
                Some(org),
            )
            .await;
            assert_eq!(status, 403, "{org} {decision}: {body}");
        }
    }
    assert!(fleet
        .forgs_audit_actions()
        .await
        .contains(&"node.approve.denied".to_owned()));

    // A node token is the wrong kind for this route: 403, not 401 — the
    // caller's problem is the door it knocked on.
    let (status, _) = decide(
        &fleet,
        &node_token,
        &grant.user_code,
        "approve",
        false,
        None,
    )
    .await;
    assert_eq!(status, 403);

    // The device secret is not a connection credential either.
    let (status, _) = decide(
        &fleet,
        &grant.device_secret,
        &grant.user_code,
        "approve",
        false,
        None,
    )
    .await;
    assert_eq!(status, 403);

    // No credential at all: 401.
    let (status, _) = fleet
        .http(
            "POST",
            "/node/register/approve",
            Some(decision_body(&grant.user_code, "approve", false, None)),
        )
        .await;
    assert_eq!(status, 401);

    // Through all of that, nothing was approved.
    let (status, body) = poll(&fleet, &grant.device_secret).await;
    assert_eq!(status, 401);
    assert!(body.contains("authorization_pending"), "body: {body}");
}

/// Unknown, malformed and already-decided codes are one uniform answer: a
/// caller learns nothing about which it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_and_malformed_codes_are_indistinguishable() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;

    for code in ["ZZZZ9999", "nonsense", "", "ABCD-123"] {
        let (status, body) = decide(&fleet, &session, code, "approve", false, Some("acme")).await;
        assert_eq!(status, 404, "{code}: {body}");
        assert!(body.contains("invalid_grant"), "{code}: {body}");
    }
}

/// One code, several spellings: what the human reads off a screen and types
/// must work, including the Crockford confusables.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_code_is_accepted_however_a_human_spells_it() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let grant = start(&fleet, "rpi").await;
    let canonical = grant.user_code.replace('-', "");

    // Lower case and no hyphen both resolve to the same pending row.
    for spelling in [canonical.to_lowercase(), grant.user_code.to_lowercase()] {
        let (status, body) = decide(&fleet, &session, &spelling, "inspect", false, None).await;
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
    let (status, body) = decide(&fleet, &session, &confusable, "inspect", false, None).await;
    assert_eq!(status, 200, "{confusable}: {body}");
}

/// The org an approval would bind the machine into must be on the **inspect**
/// response, not just the outcome.
///
/// The regression this guards: the pending row has no org until an approval
/// binds it, so a `describe` that reported the row's org would omit the very
/// thing the screen asks the human to decide. The org is the **request's**
/// target org, whoever inspects.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_inspection_names_the_org_the_machine_would_join() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let bob = fleet.seed_session("other", "bob", FleetRole::Member).await;
    let acme = fleet.org("acme").await;
    let other = fleet.org("other").await;
    let alice_personal = fleet.personal_org("alice").await;
    let grant = start(&fleet, "rpi").await;

    // Before any decision, the response already names the target org.
    let (status, body) = decide(
        &fleet,
        &alice,
        &grant.user_code,
        "inspect",
        false,
        Some("acme"),
    )
    .await;
    assert_eq!(status, 200, "body: {body}");
    let seen: NodeApprovalResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(seen.state, "pending");
    assert_eq!(
        seen.org.as_deref(),
        Some(acme.0.as_str()),
        "inspect must say which org the machine would join"
    );

    // With no `org`, it names the personal org the approval would bind into.
    let (status, body) = decide(&fleet, &alice, &grant.user_code, "inspect", false, None).await;
    assert_eq!(status, 200, "body: {body}");
    let seen: NodeApprovalResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(seen.org.as_deref(), Some(alice_personal.0.as_str()));

    // It is the *request's* org, not a property of the row: a member of
    // another org inspecting the same code is told about theirs.
    let (status, body) = decide(
        &fleet,
        &bob,
        &grant.user_code,
        "inspect",
        false,
        Some("other"),
    )
    .await;
    assert_eq!(status, 200, "body: {body}");
    let seen: NodeApprovalResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(seen.org.as_deref(), Some(other.0.as_str()));

    // Denial reports it too, so the outcome line can name the org that refused.
    let (status, body) = decide(
        &fleet,
        &alice,
        &grant.user_code,
        "deny",
        false,
        Some("acme"),
    )
    .await;
    assert_eq!(status, 200, "body: {body}");
    let denied: NodeApprovalResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(denied.org.as_deref(), Some(acme.0.as_str()));
}

/// The browser surface onto the same ceremony: `POST
/// /api/v1/nodes/pending/{code}?org=` with the session cookie **and** the CSRF
/// header. Without the header nothing happens; the CLI route never accepts
/// the cookie at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_browser_api_approves_behind_cookie_and_csrf() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let acme = fleet.org("acme").await;
    let (cookie, csrf) = fleet.browser_session(&session);
    let grant = start(&fleet, "rpi-web").await;
    let path = format!("/api/v1/nodes/pending/{}?org=acme", grant.user_code);
    let approve = serde_json::json!({ "decision": "approve" }).to_string();

    // Cookie without the CSRF header: refused, nothing bound.
    let (status, _, body) = fleet
        .http_full("POST", &path, &[("cookie", &cookie)], Some(approve.clone()))
        .await;
    assert_eq!(status, 403, "body: {body}");
    // A wrong CSRF value is no better.
    let (status, _, body) = fleet
        .http_full(
            "POST",
            &path,
            &[("cookie", &cookie), ("x-fleet-csrf", "not-the-token")],
            Some(approve.clone()),
        )
        .await;
    assert_eq!(status, 403, "body: {body}");
    // The CLI route is header-bearer only: a browser cookie is no credential
    // there, CSRF header or not.
    let (status, _, body) = fleet
        .http_full(
            "POST",
            "/node/register/approve",
            &[("cookie", &cookie), ("x-fleet-csrf", &csrf)],
            Some(decision_body(
                &grant.user_code,
                "approve",
                false,
                Some("acme"),
            )),
        )
        .await;
    assert_eq!(status, 401, "body: {body}");
    let (status, body) = poll(&fleet, &grant.device_secret).await;
    assert_eq!(status, 401);
    assert!(body.contains("authorization_pending"), "body: {body}");

    let headers = [("cookie", cookie.as_str()), ("x-fleet-csrf", csrf.as_str())];

    // A non-member org is the same 403 here as on the CLI route.
    fleet.org("elsewhere").await;
    let (status, _, body) = fleet
        .http_full(
            "POST",
            &format!("/api/v1/nodes/pending/{}?org=elsewhere", grant.user_code),
            &headers,
            Some(approve.clone()),
        )
        .await;
    assert_eq!(status, 403, "body: {body}");

    // Inspect carries the verbatim phishing warning and the target org.
    let (status, _, body) = fleet
        .http_full(
            "POST",
            &path,
            &headers,
            Some(serde_json::json!({ "decision": "inspect" }).to_string()),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    let seen: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(seen["org"], acme.0.as_str());
    assert_eq!(seen["node_name"], "rpi-web");
    assert!(
        seen["warning"]
            .as_str()
            .is_some_and(|w| w.contains("cannot see it from here")),
        "{seen}"
    );

    // Approve, then the machine's poll yields a working token in acme.
    let (status, _, body) = fleet
        .http_full("POST", &path, &headers, Some(approve))
        .await;
    assert_eq!(status, 200, "body: {body}");
    let (status, body) = poll(&fleet, &grant.device_secret).await;
    assert_eq!(status, 200, "body: {body}");
    let minted: NodeTokenResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(minted.org, acme.0);
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&minted.token)).await,
        101
    );
}

/// The informational page: unauthenticated, stateless, and **reflecting
/// nothing**. The moment it echoes input it is an injection surface.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_approval_page_is_static_and_reflects_nothing() {
    let fleet = TestCoordinator::start().await;

    let (status, plain) = fleet.http("GET", "/node/approve", None).await;
    assert_eq!(status, 200);
    assert!(plain.contains("probefleet node approve"), "{plain}");
    assert!(plain.contains("cannot see it from here"), "{plain}");
    // A static link into the web UI, for the human who would rather click
    // than install the CLI. Still no form, still no query parameter read.
    assert!(plain.contains("/ui/approve"), "{plain}");

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
        pending_rows(&fleet).await,
        0,
        "a refused registration must not leave a row"
    );
}

/// The cap on unauthenticated growth (`max_pending_nodes`), and its honest
/// cost: at the ceiling, legitimate machines are refused too. forgs answers
/// `503 temporarily_unavailable` (the CLI treats it like the old
/// `too_many_pending`).
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
    assert!(body.contains("temporarily_unavailable"), "body: {body}");
    assert_eq!(pending_rows(&fleet).await, 2);
}

/// A registration that outlives its TTL cannot be approved or redeemed, and the
/// waiting machine is told which it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_registration_is_refused_at_both_ends() {
    let fleet = TestCoordinator::start_with(|c| c.pending_node_ttl_secs = 1).await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let grant = start(&fleet, "rpi").await;

    // Age the row rather than the clock: the coordinator uses the system clock
    // here and this is the honest way to reach the boundary.
    sqlx::query("UPDATE forgs_pending_device SET expires = 1")
        .execute(fleet.db().pool_for_test())
        .await
        .unwrap();

    let (status, body) = poll(&fleet, &grant.device_secret).await;
    assert_eq!(status, 401);
    assert!(body.contains("expired_token"), "body: {body}");

    let (status, body) = decide(
        &fleet,
        &session,
        &grant.user_code,
        "approve",
        false,
        Some("acme"),
    )
    .await;
    assert_eq!(status, 404, "body: {body}");
    assert_eq!(node_rows(&fleet).await, 0);
}

/// A poll credential of the wrong kind, or one nobody issued, is one answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bogus_device_secret_is_one_uniform_rejection() {
    let fleet = TestCoordinator::start().await;
    let session_token = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let format = fleet.auth().format();
    let node_token = format
        .mint(probefleet_coordinator::identity::node_token_kind(format))
        .to_secret_string();

    for secret in ["garbage".to_owned(), session_token, node_token] {
        let (status, body) = poll(&fleet, &secret).await;
        assert_eq!(status, 401, "body: {body}");
        assert!(body.contains("invalid_grant"), "body: {body}");
    }

    // A well-formed device secret nobody issued. Reported as `expired_token`,
    // not `invalid_grant`: after a sweep an unissued secret and one whose row
    // aged out are indistinguishable, so they are answered uniformly.
    let unissued = format.mint(TokenKind::DeviceSecret).to_secret_string();
    let (status, body) = poll(&fleet, &unissued).await;
    assert_eq!(status, 401, "body: {body}");
    assert!(body.contains("expired_token"), "body: {body}");
}

/// The source address shown to an approver is **advisory** and comes from the
/// socket peer, never from a caller-supplied `X-Forwarded-For`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_source_ip_is_the_peer_and_forwarded_headers_are_ignored() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;

    let (status, _, body) = fleet
        .http_full(
            "POST",
            "/node/register/start",
            &[("x-forwarded-for", "203.0.113.7")],
            Some(start_body("rpi", &[], None)),
        )
        .await;
    assert_eq!(status, 200, "body: {body}");
    let grant: NodeRegisterStartResponse = serde_json::from_str(&body).unwrap();

    let (status, body) = decide(&fleet, &session, &grant.user_code, "inspect", false, None).await;
    assert_eq!(status, 200, "body: {body}");
    let seen: NodeApprovalResponse = serde_json::from_str(&body).unwrap();
    assert_eq!(seen.source_ip.as_deref(), Some("127.0.0.1"));
}

/// The sweep is hygiene, and it is what returns capacity under the cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sweep_reclaims_spent_and_expired_registrations() {
    let fleet = TestCoordinator::start().await;
    let session = fleet.seed_session("acme", "alice", FleetRole::Member).await;

    let denied = start(&fleet, "rpi-denied").await;
    let expired = start(&fleet, "rpi-expired").await;
    let live = start(&fleet, "rpi-live").await;
    let (status, _) = decide(&fleet, &session, &denied.user_code, "deny", false, None).await;
    assert_eq!(status, 200);
    sqlx::query("UPDATE forgs_pending_device SET expires = 1 WHERE payload LIKE '%rpi-expired%'")
        .execute(fleet.db().pool_for_test())
        .await
        .unwrap();

    probefleet_coordinator::sweep::sweep_once(&fleet.coord).await;

    assert_eq!(
        pending_rows(&fleet).await,
        1,
        "only the live registration survives"
    );
    let (status, body) = poll(&fleet, &live.device_secret).await;
    assert_eq!(status, 401);
    assert!(body.contains("authorization_pending"), "body: {body}");
    // The expired one is gone, so its poll now reads as unknown/expired rather
    // than as anything the caller can act on differently.
    let (status, body) = poll(&fleet, &expired.device_secret).await;
    assert_eq!(status, 401);
    assert!(body.contains("expired_token"), "body: {body}");
}
