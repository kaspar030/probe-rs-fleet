//! Board actions and lease release over `/api/v1` (`docs/web-ui.md` §3, phase
//! 1c / doc phase 4).
//!
//! Two verbs, both of which reach *hardware* rather than a table, so the
//! coverage is shaped by what a mistake would hand somebody:
//!
//! * **power-cycle is the one `AllowedOp` the coordinator enforces.** The agent
//!   enforces `attach` and `gdb` at channel open, and nothing enforces `flash` /
//!   `erase` / `reset` at all — but a power-cycle command carries no capability
//!   token for the agent to check, so if this handler does not refuse a grantee
//!   without `AllowedOp::PowerCycle`, nothing does. Asserting on the status code
//!   alone would not show that: the assertions here are against the **command
//!   the agent received**, or against its absence;
//! * **lease release is holder-or-admin**, where "admin" means the *board org's*
//!   admin reclaiming their own hardware from someone they shared it with. A
//!   stranger must get the answer they would get for a lease that never existed,
//!   or lease ids become enumerable across tenants;
//! * **CSRF** on both, for a cookie-authenticated caller, and **cross-tenancy**,
//!   where "not yours" and "does not exist" must be one answer.

mod common;

use common::{AgentStub, TestCoordinator};

use fleet_proto::ids::{LeaseId, OrgId, Role};
use fleet_proto::token::AllowedOp;

/// Every mutating route this file covers, as `(method, path)`.
const MUTATING: [(&str, &str); 2] = [
    ("POST", "/api/v1/boards/power-cycle"),
    ("DELETE", "/api/v1/leases/1"),
];

fn parse(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}"))
}

/// Call a route as a **browser** would: session cookie plus the CSRF header the
/// server itself derives.
async fn as_browser(
    fleet: &TestCoordinator,
    method: &str,
    path: &str,
    token: &str,
    body: Option<&str>,
) -> (u16, String) {
    let (cookie, csrf) = fleet.browser_session(token);
    let (status, _, body) = fleet
        .http_full(
            method,
            path,
            &[("cookie", &cookie), ("x-fleet-csrf", &csrf)],
            body.map(str::to_owned),
        )
        .await;
    (status, body)
}

/// Every audit action recorded, as `(org, subject, action)`.
async fn audit_rows(fleet: &TestCoordinator) -> Vec<(String, Option<String>, String)> {
    sqlx::query_as("SELECT org_id, subject, action FROM audit_log ORDER BY id")
        .fetch_all(fleet.db().pool_for_test())
        .await
        .unwrap()
}

fn power_cycle_body(board: &str) -> String {
    serde_json::json!({ "board": board }).to_string()
}

/// Take a lease on `board_name` through the real wire surface, so the
/// scheduler, the `leases` table and the audit log all agree it exists.
async fn take_lease(
    session: &fleet_sidecar::transport::CoordSession,
    board_name: &str,
) -> LeaseId {
    use fleet_proto::ids::BoardName;
    use fleet_proto::lease::{Constraint, LeaseRequest, Priority};
    use fleet_wire::{CoordToSidecar, SidecarToCoord};

    match session
        .request(SidecarToCoord::Lease(LeaseRequest {
            select: Constraint::Board(BoardName(board_name.to_owned())),
            duration_secs: 600,
            priority: Priority::Interactive,
        }))
        .await
        .unwrap()
    {
        CoordToSidecar::Lease(g) => g.lease,
        other => panic!("expected a lease, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Authentication and CSRF: properties of the surface
// ---------------------------------------------------------------------------

/// Unauthenticated is refused on every route here, with the same flat body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_route_refuses_an_unauthenticated_caller() {
    let fleet = TestCoordinator::start().await;
    for (method, path) in MUTATING {
        let (status, body) = fleet
            .http(method, path, Some(power_cycle_body("dk-3")))
            .await;
        assert_eq!(status, 401, "{method} {path}: {body}");
        assert!(body.contains("unauthorized"), "{method} {path}: {body}");
    }
}

/// **CSRF.** A cookie-authenticated mutation with no `X-Fleet-Csrf` header — or
/// with a wrong one — is refused, while the *same* credential in an
/// `Authorization` header goes through without one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cookie_authenticated_mutation_needs_the_csrf_header() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;
    let (cookie, csrf) = fleet.browser_session(&alice);

    for (method, path) in MUTATING {
        let (status, _, body) = fleet
            .http_full(
                method,
                path,
                &[("cookie", &cookie)],
                Some(power_cycle_body("dk-3")),
            )
            .await;
        assert_eq!(status, 403, "{method} {path} without CSRF: {body}");
        assert!(body.contains("forbidden"), "{method} {path}: {body}");

        // A plausible but wrong one: the value is an HMAC, so guessing is the
        // attack this refuses.
        let wrong = "0".repeat(csrf.len());
        let (status, _, body) = fleet
            .http_full(
                method,
                path,
                &[("cookie", &cookie), ("x-fleet-csrf", &wrong)],
                Some(power_cycle_body("dk-3")),
            )
            .await;
        assert_eq!(status, 403, "{method} {path} with a wrong CSRF: {body}");
    }

    // The bearer half: no CSRF header, and the answer is about the *request*
    // (no such board / no such lease) rather than about the credential.
    for (method, path) in MUTATING {
        let (status, _, body) = fleet
            .http_full(
                method,
                path,
                &[("authorization", &format!("Bearer {alice}"))],
                Some(power_cycle_body("dk-3")),
            )
            .await;
        assert_ne!(status, 403, "{method} {path} demanded CSRF of a bearer: {body}");
    }
}

// ---------------------------------------------------------------------------
// Power-cycle
// ---------------------------------------------------------------------------

/// The happy path, asserted against the **command the agent received** rather
/// than against a status code: a handler that answered `200` and sent nothing
/// would leave an operator staring at a board that did not reboot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_owner_power_cycles_a_board_and_the_agent_is_commanded() {
    let fleet = TestCoordinator::start().await;
    let org = OrgId("acme".to_owned());
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    let board = fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    let mut agent = AgentStub::attach(&fleet, &board.node).await;

    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/boards/power-cycle",
        &alice,
        Some(&power_cycle_body("dk-3")),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    // The node-local name comes back, which is how a caller who sent a bare
    // name learns which board was cycled.
    assert_eq!(parse(&body)["board"], "dk-3");
    assert_eq!(agent.expect_power_cycle().await.0, "dk-3");

    // Audited exactly as the CLI path audits it: same action, same board.
    let rows = audit_rows(&fleet).await;
    assert!(
        rows.iter()
            .any(|(o, _, a)| o == "acme" && a == "board.power-cycle"),
        "{rows:?}"
    );
}

/// **A grantee without `AllowedOp::PowerCycle` is refused** — the coordinator's
/// one op check, and the whole reason this endpoint cannot be a thin passthrough.
///
/// The grantee can *see* the board (they can lease it, `attach` to it and flash
/// it), so resolution succeeds and only the op check stands between them and
/// somebody else's power switch. The agent receiving nothing is the assertion
/// that matters: a `403` with a command already sent would be the worst of both.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grantee_without_the_power_cycle_op_is_refused() {
    let fleet = TestCoordinator::start().await;
    let (alice_token, alice_org, _alice) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let (bob_token, _bob_org, _bob) = fleet.seed_github_user(2, "bob", Role::Member).await;
    let board = fleet
        .seed_board(&alice_org, "rpi-1", "dk-3", &["nrf52"])
        .await;
    let mut agent = AgentStub::attach(&fleet, &board.node).await;

    // Bob may attach and flash, but not cut the power.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &alice_token,
        Some(
            &serde_json::json!({
                "subject": "bob",
                "selector": "tag=nrf52",
                "ops": ["attach"],
                "expires": fleet.coord.now() + 3_600,
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/boards/power-cycle",
        &bob_token,
        Some(&power_cycle_body("dk-3")),
    )
    .await;
    assert_eq!(status, 403, "a grantee without the op must be refused: {body}");
    assert!(body.contains("forbidden"), "{body}");
    assert!(
        agent.is_idle(),
        "a refused power-cycle must not reach the agent at all"
    );

    // The same grantee *with* the op succeeds, so the refusal above is the op
    // check rather than the grant being broken.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &alice_token,
        Some(
            &serde_json::json!({
                "subject": "bob",
                "selector": "tag=nrf52",
                "ops": ["power-cycle"],
                "expires": fleet.coord.now() + 3_600,
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/boards/power-cycle",
        &bob_token,
        Some(&power_cycle_body("dk-3")),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(agent.expect_power_cycle().await.0, "dk-3");
}

/// A board in another tenant is **"no such board"**, not "forbidden": the
/// distinction would answer a question about another org's inventory in the one
/// case where the caller guessed right.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cross_org_board_is_no_such_board() {
    let fleet = TestCoordinator::start().await;
    let acme = OrgId("acme".to_owned());
    let other = OrgId("other".to_owned());
    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;
    fleet.seed_board(&acme, "rpi-1", "mine", &["nrf52"]).await;
    let theirs = fleet.seed_board(&other, "rpi-9", "theirs", &["nrf52"]).await;
    let mut agent = AgentStub::attach(&fleet, &theirs.node).await;

    let (cross_status, cross_body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/boards/power-cycle",
        &alice,
        Some(&power_cycle_body("theirs")),
    )
    .await;
    let (absent_status, absent_body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/boards/power-cycle",
        &alice,
        Some(&power_cycle_body("no-such-board")),
    )
    .await;
    assert_eq!(cross_status, 404, "{cross_body}");
    assert_eq!(
        (cross_status, cross_body.as_str()),
        (absent_status, absent_body.as_str()),
        "another org's board must be indistinguishable from an absent one"
    );
    assert!(
        agent.is_idle(),
        "the other org's agent must not have been commanded"
    );
}

/// A caller with no access at all is refused, and a malformed body is a `400`
/// rather than a `500` or a silent no-op.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn power_cycle_rejects_a_non_member_and_a_malformed_body() {
    let fleet = TestCoordinator::start().await;
    let org = OrgId("acme".to_owned());
    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;

    // A session whose membership was revoked has an empty `Access`.
    let carol = fleet.seed_session("acme", "carol", Role::Member).await;
    sqlx::query("DELETE FROM member WHERE user_id = 'carol'")
        .execute(fleet.db().pool_for_test())
        .await
        .unwrap();
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/boards/power-cycle",
        &carol,
        Some(&power_cycle_body("dk-3")),
    )
    .await;
    assert_eq!(status, 403, "{body}");

    for bad in [
        String::new(),
        "not json".to_owned(),
        serde_json::json!({}).to_string(),
        serde_json::json!({ "board": "" }).to_string(),
        // `deny_unknown_fields`: a caller who misspells a field learns it.
        serde_json::json!({ "board": "dk-3", "force": true }).to_string(),
    ] {
        let (status, body) = as_browser(
            &fleet,
            "POST",
            "/api/v1/boards/power-cycle",
            &alice,
            Some(&bad),
        )
        .await;
        assert_eq!(status, 400, "{bad}: {body}");
        assert!(body.contains("invalid_request"), "{bad}: {body}");
    }
}

// ---------------------------------------------------------------------------
// Lease release
// ---------------------------------------------------------------------------

/// The holder releases their own lease, and the release is **real**: the
/// scheduler forgets it and the row is closed with a reason, exactly as the wire
/// verb does it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_holder_releases_their_own_lease() {
    let fleet = TestCoordinator::start().await;
    let org = OrgId("acme".to_owned());
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    let session = fleet.client_session(&alice).await;
    let lease = take_lease(&session, "dk-3").await;

    let (status, body) = as_browser(
        &fleet,
        "DELETE",
        &format!("/api/v1/leases/{}", lease.0),
        &alice,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body)["lease"], serde_json::json!(lease.0));

    assert!(
        fleet
            .coord
            .scheduler()
            .lock()
            .await
            .lease_holder(lease)
            .is_none(),
        "the lease survived the release in the scheduler"
    );
    let closed: Vec<(Option<i64>, Option<String>)> =
        sqlx::query_as("SELECT closed_at, close_reason FROM leases")
            .fetch_all(fleet.db().pool_for_test())
            .await
            .unwrap();
    assert_eq!(closed.len(), 1);
    assert!(closed[0].0.is_some(), "the lease row is still open: {closed:?}");
    assert_eq!(closed[0].1.as_deref(), Some("released"));

    // The same `lease.release` row the wire path writes.
    let rows = audit_rows(&fleet).await;
    assert!(
        rows.iter().any(|(o, _, a)| o == "acme" && a == "lease.release"),
        "{rows:?}"
    );

    // Releasing it again is the same not-found-shaped answer.
    let (status, body) = as_browser(
        &fleet,
        "DELETE",
        &format!("/api/v1/leases/{}", lease.0),
        &alice,
        None,
    )
    .await;
    assert_eq!(status, 404, "{body}");
}

/// **A stranger gets the not-found answer**, byte-identical to the one for a
/// lease that does not exist. Distinguishing them would let anyone probe which
/// lease ids are live, and across orgs it would enumerate other tenants' leases.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stranger_gets_the_answer_for_a_lease_that_does_not_exist() {
    let fleet = TestCoordinator::start().await;
    let org = OrgId("acme".to_owned());
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    let session = fleet.client_session(&alice).await;
    let lease = take_lease(&session, "dk-3").await;

    // A member of a *different* org — not a member of alice's, so not an admin
    // of the board's org either.
    let mallory = fleet.seed_session("evil", "mallory", Role::Admin).await;
    let (real_status, real_body) = as_browser(
        &fleet,
        "DELETE",
        &format!("/api/v1/leases/{}", lease.0),
        &mallory,
        None,
    )
    .await;
    let (fake_status, fake_body) = as_browser(
        &fleet,
        "DELETE",
        &format!("/api/v1/leases/{}", lease.0 + 9_999),
        &mallory,
        None,
    )
    .await;
    assert_eq!(real_status, 404, "{real_body}");
    assert_eq!(
        (real_status, real_body.as_str()),
        (fake_status, fake_body.as_str()),
        "someone else's lease must be indistinguishable from an absent one"
    );

    // And it really is still held.
    assert!(
        fleet
            .coord
            .scheduler()
            .lock()
            .await
            .lease_holder(lease)
            .is_some(),
        "a refused release must have no effect at all"
    );
}

/// **The board org's admin reclaims their own hardware** from a grantee in
/// another org — the case `require_lease_control` exists for, and the one a
/// naive "holder only" rule would get wrong.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_board_orgs_admin_reclaims_a_cross_org_lease() {
    let fleet = TestCoordinator::start().await;
    let (alice_token, alice_org, _alice) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let (bob_token, _bob_org, _bob) = fleet.seed_github_user(2, "bob", Role::Member).await;
    fleet
        .seed_board(&alice_org, "rpi-1", "dk-3", &["nrf52"])
        .await;
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &alice_token,
        Some(
            &serde_json::json!({
                "subject": "bob",
                "selector": "tag=nrf52",
                "ops": ["attach"],
                "expires": fleet.coord.now() + 3_600,
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    let bob = fleet.client_session(&bob_token).await;
    let lease = take_lease(&bob, "dk-3").await;

    let (status, body) = as_browser(
        &fleet,
        "DELETE",
        &format!("/api/v1/leases/{}", lease.0),
        &alice_token,
        None,
    )
    .await;
    assert_eq!(
        status, 200,
        "the board org's admin must be able to reclaim their hardware: {body}"
    );
    assert!(
        fleet
            .coord
            .scheduler()
            .lock()
            .await
            .lease_holder(lease)
            .is_none(),
        "the reclaimed lease survived in the scheduler"
    );
}

/// A non-numeric lease id is a `400`, not a `404`: it is a malformed request
/// rather than an answer about whether a lease exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_lease_id_is_a_bad_request() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;

    for bad in ["abc", "-1", "1.5", "18446744073709551616"] {
        let (status, body) = as_browser(
            &fleet,
            "DELETE",
            &format!("/api/v1/leases/{bad}"),
            &alice,
            None,
        )
        .await;
        assert_eq!(status, 400, "{bad}: {body}");
        assert!(body.contains("invalid_request"), "{bad}: {body}");
    }
}

/// **No capability token in any board-action response.** `docs/web-ui.md` §5
/// asks for this as a test over the response types; here it is on the two
/// routes that sit closest to one, since a lease is exactly the thing a
/// `LeaseGrant::token` belongs to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_board_action_response_carries_a_capability_token() {
    let fleet = TestCoordinator::start().await;
    let org = OrgId("acme".to_owned());
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    let board = fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    let _agent = AgentStub::attach(&fleet, &board.node).await;
    let session = fleet.client_session(&alice).await;
    let lease = take_lease(&session, "dk-3").await;

    let (_, cycled) = as_browser(
        &fleet,
        "POST",
        "/api/v1/boards/power-cycle",
        &alice,
        Some(&power_cycle_body("dk-3")),
    )
    .await;
    let (_, released) = as_browser(
        &fleet,
        "DELETE",
        &format!("/api/v1/leases/{}", lease.0),
        &alice,
        None,
    )
    .await;

    for body in [&cycled, &released] {
        for prefix in ["prfs1_", "prfn1_", "prffk1_", "prfnd1_", "prfw1_"] {
            assert!(!body.contains(prefix), "{body} carried a `{prefix}`");
        }
        // A capability token is a hex blob; the response shapes here are two
        // small objects, so any long hex run would be one.
        assert!(
            !body.contains("token"),
            "a board-action response named a token: {body}"
        );
        assert!(!body.contains(&alice), "the caller's own token came back");
    }
}

/// Ops the coordinator does *not* enforce stay unenforced, and the contract
/// says so rather than leaving the frontend to guess.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_limits_endpoint_reports_where_each_op_is_enforced() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    let (status, body) = as_browser(&fleet, "GET", "/api/v1/grants/limits", &alice, None).await;
    assert_eq!(status, 200, "{body}");
    let limits = parse(&body);
    let ops = limits["ops"].as_array().unwrap();
    assert_eq!(ops.len(), AllowedOp::all().len());

    let by_label = |label: &str| -> serde_json::Value {
        ops.iter()
            .find(|o| o["op"] == label)
            .unwrap_or_else(|| panic!("{label} missing from {body}"))
            .clone()
    };
    assert_eq!(by_label("power-cycle")["enforced_by"], "coordinator");
    assert_eq!(by_label("attach")["enforced_by"], "agent");
    assert_eq!(by_label("gdb")["enforced_by"], "agent");
    for label in ["flash", "erase", "reset"] {
        assert_eq!(
            by_label(label)["enforced_by"],
            "nobody",
            "{label} is recorded intent, not enforcement"
        );
        assert_eq!(
            by_label(label)["implies_attach"],
            true,
            "{label} travels in a data channel, so it implies attach"
        );
    }
    assert_eq!(by_label("power-cycle")["implies_attach"], false);
}
