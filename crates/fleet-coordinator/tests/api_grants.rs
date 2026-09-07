//! Grants and auth keys over `/api/v1` (`docs/web-ui.md` §3, phase 1c / doc
//! phase 3).
//!
//! These are the outward-pointing verbs: a grant hands *this* org's hardware to
//! somebody who is not in it, and an auth key mints a long-lived bearer secret.
//! `docs/web-ui.md` §6 put them last for that reason, and the coverage here is
//! shaped by what a mistake would hand somebody rather than by what is easy to
//! assert:
//!
//! * **the member/admin split**, which diverges between the two surfaces on
//!   purpose — grant *create* is admin-only while grant *list* is member-only,
//!   and auth-key mint is member. That divergence gets its own test, because a
//!   handler that "tidied" it would be handing an org's boards outward on a
//!   plain member's authority;
//! * **creator-or-admin revocation** for both, including the `created_by = NULL`
//!   row that only an admin can reach;
//! * **the cascade**, because revocation must be *real*: revoking a grant tears
//!   down the grantee's live lease through the whole release path, and revoking
//!   a `ci` auth key takes the grant its redemption synthesised with it. An
//!   assertion that the row vanished would pass against an implementation that
//!   leaves a runner relaying bytes until the lease TTL expires;
//! * **the selector and expiry bounds**, which the frontend has to constrain
//!   inputs against and which therefore have to be enforced identically here;
//! * **CSRF**, **cross-tenancy**, and **the no-capability-token rule**, whose
//!   one deliberate exception (`AuthKeyCreated.key`) the test knows by name.

mod common;

use common::TestCoordinator;

use fleet_proto::ids::{OrgId, Role};
use fleet_proto::token::AllowedOp;

/// Every mutating route this file covers, as `(method, path)`.
const MUTATING: [(&str, &str); 4] = [
    ("POST", "/api/v1/grants"),
    ("DELETE", "/api/v1/grants/abcdef0123456789"),
    ("POST", "/api/v1/auth-keys"),
    ("DELETE", "/api/v1/auth-keys/abcdef0123456789"),
];

/// Every read route, for the unauthenticated sweep.
const READ_ROUTES: [&str; 3] = [
    "/api/v1/grants",
    "/api/v1/grants/limits",
    "/api/v1/auth-keys",
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

/// A well-formed grant body, one hour out.
fn grant_body(fleet: &TestCoordinator, subject: &str, selector: &str, ops: &[&str]) -> String {
    serde_json::json!({
        "subject": subject,
        "selector": selector,
        "ops": ops,
        "expires": fleet.coord.now() + 3_600,
    })
    .to_string()
}

/// A well-formed auth-key body.
fn auth_key_body(tags: &[&str], ttl_secs: u64) -> String {
    serde_json::json!({ "tags": tags, "ttl_secs": ttl_secs }).to_string()
}

/// Take a lease on `board_name` through the real wire surface.
async fn take_lease(
    session: &fleet_sidecar::transport::CoordSession,
    board_name: &str,
) -> fleet_proto::ids::LeaseId {
    use fleet_proto::ids::BoardName;
    use fleet_proto::lease::{Constraint, LeaseRequest, Priority};
    use fleet_wire::{CoordToSidecar, SidecarToCoord};

    match session
        .request(SidecarToCoord::Lease(LeaseRequest {
            select: Constraint::Id(BoardName(board_name.to_owned())),
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

/// Unauthenticated is refused on every route, with the same flat body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_route_refuses_an_unauthenticated_caller() {
    let fleet = TestCoordinator::start().await;
    for path in READ_ROUTES {
        let (status, body) = fleet.http("GET", path, None).await;
        assert_eq!(status, 401, "{path}: {body}");
        assert!(body.contains("unauthorized"), "{path}: {body}");
    }
    for (method, path) in MUTATING {
        let (status, body) = fleet.http(method, path, Some("{}".into())).await;
        assert_eq!(status, 401, "{method} {path}: {body}");
        assert!(body.contains("unauthorized"), "{method} {path}: {body}");
    }
}

/// **CSRF.** Every mutating route refuses a cookie-authenticated call without a
/// valid `X-Fleet-Csrf` header, and the *same* credential in an `Authorization`
/// header needs none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_mutating_route_needs_the_csrf_header_when_cookie_authenticated() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;
    let (cookie, csrf) = fleet.browser_session(&alice);

    for (method, path) in MUTATING {
        let (status, _, body) = fleet
            .http_full(method, path, &[("cookie", &cookie)], Some("{}".into()))
            .await;
        assert_eq!(status, 403, "{method} {path} without CSRF: {body}");
        assert!(body.contains("forbidden"), "{method} {path}: {body}");

        let wrong = "0".repeat(csrf.len());
        let (status, _, body) = fleet
            .http_full(
                method,
                path,
                &[("cookie", &cookie), ("x-fleet-csrf", &wrong)],
                Some("{}".into()),
            )
            .await;
        assert_eq!(status, 403, "{method} {path} with a wrong CSRF: {body}");

        // The bearer half needs no header, and answers about the *request*.
        let (status, _, body) = fleet
            .http_full(
                method,
                path,
                &[("authorization", &format!("Bearer {alice}"))],
                Some("{}".into()),
            )
            .await;
        assert_ne!(
            status, 403,
            "{method} {path} demanded CSRF of a bearer: {body}"
        );
    }
}

// ---------------------------------------------------------------------------
// Grants: the member/admin split
// ---------------------------------------------------------------------------

/// **Create is admin, list is member** — and that divergence is deliberate.
///
/// An auth key cannot exceed the caller's own org (it enrolls a node *into*
/// it), so membership suffices there; a grant points outward, handing the org's
/// hardware to somebody who is not in it at all. A plain member who could create
/// one could give the fleet away.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grant_create_is_admin_only_while_grant_list_is_member() {
    let fleet = TestCoordinator::start().await;
    let (admin, org, _admin_id) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let (bob_token, _bob_org, _bob) = fleet.seed_github_user(2, "bob", Role::Member).await;
    // A plain member of alice's org.
    fleet
        .db()
        .ensure_user_member(&org, "member-user", Role::Member)
        .await
        .unwrap();
    let member = {
        let token = fleet_auth::OpaqueToken::mint(fleet_auth::TokenKind::Session);
        let now = i64::try_from(fleet.coord.now()).unwrap();
        fleet
            .db()
            .insert_session(token.hash().as_str(), &org, "member-user", now, now + 3_600)
            .await
            .unwrap();
        token.to_secret_string()
    };

    // The member may list...
    let (status, body) = as_browser(&fleet, "GET", "/api/v1/grants", &member, None).await;
    assert_eq!(status, 200, "a member must be able to list grants: {body}");
    assert_eq!(parse(&body).as_array().unwrap().len(), 0);

    // ... but not create.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &member,
        Some(&grant_body(&fleet, "bob", "tag=nrf52", &["attach"])),
    )
    .await;
    assert_eq!(status, 403, "a member must not create a grant: {body}");
    assert!(body.contains("forbidden"), "{body}");

    // The admin can.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &admin,
        Some(&grant_body(&fleet, "bob", "tag=nrf52", &["attach"])),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let created = parse(&body);
    // Resolved to the immutable id, never the login — §6.4's rename/reuse
    // takeover is otherwise a hole.
    assert_eq!(created["subject"]["id"], "gh-2");
    assert_eq!(created["created_by"], "gh-1");

    // And a non-member of the org sees nothing of it.
    let (status, body) = as_browser(&fleet, "GET", "/api/v1/grants", &bob_token, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        parse(&body).as_array().unwrap().len(),
        0,
        "bob's own org has issued no grants: {body}"
    );
}

/// A session whose membership was revoked is refused everywhere, exactly as an
/// absent one is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_membership_is_refused_like_an_absent_one() {
    let fleet = TestCoordinator::start().await;
    let carol = fleet.seed_session("acme", "carol", Role::Admin).await;
    sqlx::query("DELETE FROM member WHERE user_id = 'carol'")
        .execute(fleet.db().pool_for_test())
        .await
        .unwrap();

    for path in READ_ROUTES {
        let (status, body) = as_browser(&fleet, "GET", path, &carol, None).await;
        assert_eq!(status, 403, "{path}: {body}");
        assert!(body.contains("forbidden"), "{path}: {body}");
    }
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/auth-keys",
        &carol,
        Some(&auth_key_body(&[], 3_600)),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    // The refusal is the *shared* `auth_key.denied` row the CLI route writes,
    // not a second, differently-spelled opinion.
    let rows = audit_rows(&fleet).await;
    assert!(
        rows.iter().any(|(_, _, a)| a == "auth_key.denied"),
        "{rows:?}"
    );
}

// ---------------------------------------------------------------------------
// Grants: the bounds the frontend has to constrain inputs against
// ---------------------------------------------------------------------------

/// **Both expiry bounds, and the absence of one.** An unbounded grant is
/// refused, one expiring in the past is refused, and one beyond
/// `MAX_GRANT_TTL_SECS` is refused — and the endpoint *reports* both bounds, so
/// #3540's date picker constrains itself from the contract instead of from a
/// hardcoded `365` that goes stale silently.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grants_expiry_is_required_and_bounded_on_both_ends() {
    let fleet = TestCoordinator::start().await;
    let (alice, _org, _id) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    fleet.seed_github_user(2, "bob", Role::Member).await;
    let now = fleet.coord.now();

    let with_expiry = |expires: Option<u64>| {
        let mut body = serde_json::json!({
            "subject": "bob",
            "selector": "tag=nrf52",
            "ops": ["attach"],
        });
        if let Some(expires) = expires {
            body["expires"] = serde_json::json!(expires);
        } else {
            body["expires"] = serde_json::Value::Null;
        }
        body.to_string()
    };

    for (label, expires) in [
        ("unbounded", None),
        ("in the past", Some(now - 1)),
        ("exactly now", Some(now)),
        (
            "beyond the cap",
            Some(now + fleet_coordinator::core::Coordinator::MAX_GRANT_TTL_SECS + 60),
        ),
    ] {
        let (status, body) = as_browser(
            &fleet,
            "POST",
            "/api/v1/grants",
            &alice,
            Some(&with_expiry(expires)),
        )
        .await;
        assert_eq!(status, 400, "an expiry {label} must be refused: {body}");
        assert!(body.contains("invalid_request"), "{label}: {body}");
    }

    // Exactly at the cap is accepted, so the bound is the one reported.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &alice,
        Some(&with_expiry(Some(
            fleet.coord.now() + fleet_coordinator::core::Coordinator::MAX_GRANT_TTL_SECS,
        ))),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // The contract the frontend reads, rather than duplicates.
    let (status, body) = as_browser(&fleet, "GET", "/api/v1/grants/limits", &alice, None).await;
    assert_eq!(status, 200, "{body}");
    let limits = parse(&body);
    assert_eq!(
        limits["max_ttl_secs"],
        serde_json::json!(fleet_coordinator::core::Coordinator::MAX_GRANT_TTL_SECS),
    );
    assert_eq!(limits["expires_optional"], false);
    // The *server's* now, not the browser's: the difference is exactly what
    // turns "one minute from now" into a 400.
    let reported = limits["now"].as_u64().unwrap();
    assert!(
        reported.abs_diff(fleet.coord.now()) < 5,
        "the reported now ({reported}) must be the coordinator's clock"
    );
    assert_eq!(limits["min_revoke_prefix"], serde_json::json!(8));
    assert_eq!(limits["auth_key_max_ttl_secs"], serde_json::json!(30 * 24 * 3600));
}

/// **The selector round-trips to its canonical form**, and an empty one is
/// refused — an empty tag set matches every board in the org.
///
/// The canonicalisation is the load-bearing half: what is stored is what
/// `Constraint`'s `Display` produces, so a grant's meaning never depends on
/// which surface wrote it. The UI must send the same string a CLI would.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_selector_is_canonicalised_and_an_empty_one_is_refused() {
    let fleet = TestCoordinator::start().await;
    let (alice, org, _id) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    fleet.seed_github_user(2, "bob", Role::Member).await;

    // A bare term is a tag, and whitespace is normalised
    // away: the stored form is the parser's, not the caller's.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &alice,
        Some(&grant_body(&fleet, "bob", "  nrf52  ", &["attach"])),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body)["selector"], "tag=nrf52");

    // And the *stored* row agrees, not merely the response.
    let stored = fleet.db().scoped(org).list_grants().await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].selector, "tag=nrf52");

    for empty in ["", "   ", "&&", " && "] {
        let (status, body) = as_browser(
            &fleet,
            "POST",
            "/api/v1/grants",
            &alice,
            Some(&grant_body(&fleet, "bob", empty, &["attach"])),
        )
        .await;
        assert_eq!(status, 400, "an empty selector ({empty:?}) must be refused: {body}");
    }

    // A wildcard-looking selector is refused too, and for a different reason:
    // there is deliberately no match-everything selector, so `*` parsed into a
    // tag no board carries and the caller got a contention message for a typo.
    for wildcard in ["*", ".*", "tag=*"] {
        let (status, body) = as_browser(
            &fleet,
            "POST",
            "/api/v1/grants",
            &alice,
            Some(&grant_body(&fleet, "bob", wildcard, &["attach"])),
        )
        .await;
        assert_eq!(
            status, 400,
            "a wildcard selector ({wildcard:?}) must be refused: {body}"
        );
        assert_eq!(parse(&body)["error"], "invalid_request", "{body}");
    }
}

/// **An empty op set is refused, and a data-plane op implies `attach`** in the
/// stored row — `normalize_ops`' whole point, since a token with `flash` but no
/// `attach` cannot open a data channel and so cannot flash either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ops_are_normalised_and_an_empty_set_is_refused() {
    let fleet = TestCoordinator::start().await;
    let (alice, org, _id) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    fleet.seed_github_user(2, "bob", Role::Member).await;

    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &alice,
        Some(&grant_body(&fleet, "bob", "tag=nrf52", &[])),
    )
    .await;
    assert_eq!(status, 400, "an empty op set must be refused: {body}");

    // An unrecognised label is a 400 rather than a silently dropped op.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &alice,
        Some(&grant_body(&fleet, "bob", "tag=nrf52", &["teleport"])),
    )
    .await;
    assert_eq!(status, 400, "{body}");

    // `flash` alone implies `attach`, in the response *and* in the row.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &alice,
        Some(&grant_body(&fleet, "bob", "tag=nrf52", &["flash"])),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let ops = parse(&body)["ops"].as_array().unwrap().clone();
    assert!(ops.contains(&serde_json::json!("attach")), "{body}");
    assert!(ops.contains(&serde_json::json!("flash")), "{body}");

    let stored = fleet.db().scoped(org).list_grants().await.unwrap();
    assert_eq!(stored.len(), 1);
    let stored_ops = stored[0].parsed_ops();
    assert!(
        stored_ops.contains(&AllowedOp::Attach),
        "the stored row must carry the implied attach: {stored_ops:?}"
    );
}

/// An unknown grantee is a `400` with no row written: a grant to a user who has
/// never logged in would be an artefact nobody could use or explain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_grantee_is_refused() {
    let fleet = TestCoordinator::start().await;
    let (alice, org, _id) = fleet.seed_github_user(1, "alice", Role::Admin).await;

    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &alice,
        Some(&grant_body(&fleet, "nobody-here", "tag=nrf52", &["attach"])),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(fleet.db().scoped(org).list_grants().await.unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Grants: revocation, and its cascade
// ---------------------------------------------------------------------------

/// **Creator-or-admin**, including the `created_by = NULL` row only an admin can
/// revoke — the same shape as auth keys with no recorded creator, and the reason
/// a shell-created grant is not stranded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grant_is_revocable_by_its_creator_or_an_admin_only() {
    let fleet = TestCoordinator::start().await;
    let (alice, org, alice_id) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    fleet.seed_github_user(2, "bob", Role::Member).await;
    // A second *member* of alice's org, who created nothing.
    fleet
        .db()
        .ensure_user_member(&org, "dave", Role::Member)
        .await
        .unwrap();
    let dave = {
        let token = fleet_auth::OpaqueToken::mint(fleet_auth::TokenKind::Session);
        let now = i64::try_from(fleet.coord.now()).unwrap();
        fleet
            .db()
            .insert_session(token.hash().as_str(), &org, "dave", now, now + 3_600)
            .await
            .unwrap();
        token.to_secret_string()
    };

    // Alice's own grant.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &alice,
        Some(&grant_body(&fleet, "bob", "tag=nrf52", &["attach"])),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let mine = parse(&body)["id"].as_str().unwrap().to_owned();
    assert_eq!(parse(&body)["created_by"], alice_id);

    // A row with no recorded creator, as a shell would leave.
    let orphan = fleet
        .seed_workload_grant(&org.0, "acme/runner", "tag=stm32", &[AllowedOp::Attach], None)
        .await;

    // Dave — a member, neither creator nor admin — may revoke neither.
    for id in [&mine, &orphan] {
        let (status, body) = as_browser(
            &fleet,
            "DELETE",
            &format!("/api/v1/grants/{}", &id[..12]),
            &dave,
            None,
        )
        .await;
        assert_eq!(status, 403, "{id}: {body}");
        assert!(body.contains("forbidden"), "{body}");
    }
    // Refused revocations are on the record.
    let rows = audit_rows(&fleet).await;
    assert_eq!(
        rows.iter()
            .filter(|(_, _, a)| a == "grant.revoke.denied")
            .count(),
        2,
        "{rows:?}"
    );

    // Alice, the admin, revokes both — including the creatorless one.
    for id in [&mine, &orphan] {
        let (status, body) = as_browser(
            &fleet,
            "DELETE",
            &format!("/api/v1/grants/{}", &id[..12]),
            &alice,
            None,
        )
        .await;
        assert_eq!(status, 200, "{id}: {body}");
        assert_eq!(parse(&body)["revoked"], serde_json::json!([id]));
    }
    assert!(fleet.db().scoped(org).list_grants().await.unwrap().is_empty());
}

/// A too-short or non-hex prefix is refused: `delete_grants_by_prefix("")` is
/// `LIKE '%'`, i.e. every grant in the org.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_short_or_non_hex_grant_prefix_is_refused() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;

    for bad in ["abc", "nothexbutlong", "ci-", "ci-abc"] {
        let (status, body) = as_browser(
            &fleet,
            "DELETE",
            &format!("/api/v1/grants/{bad}"),
            &alice,
            None,
        )
        .await;
        assert_eq!(status, 400, "{bad}: {body}");
        assert!(body.contains("invalid_request"), "{bad}: {body}");
    }
    // A well-formed prefix matching nothing is a 404, not a 400.
    let (status, body) = as_browser(
        &fleet,
        "DELETE",
        "/api/v1/grants/abcdef0123456789",
        &alice,
        None,
    )
    .await;
    assert_eq!(status, 404, "{body}");
}

/// **Revocation is real.** Revoking a grant tears down the grantee's live lease
/// on a now-unreachable board through the whole release path, rather than
/// unlinking a row and leaving them relaying bytes until the TTL ran out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_a_grant_tears_down_the_grantees_live_lease() {
    let fleet = TestCoordinator::start().await;
    let (alice, alice_org, _id) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let (bob_token, _bob_org, _bob) = fleet.seed_github_user(2, "bob", Role::Member).await;
    fleet
        .seed_board(&alice_org, "rpi-1", "dk-3", &["nrf52"])
        .await;

    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &alice,
        Some(&grant_body(&fleet, "bob", "tag=nrf52", &["attach"])),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let id = parse(&body)["id"].as_str().unwrap().to_owned();

    let bob = fleet.client_session(&bob_token).await;
    let lease = take_lease(&bob, "dk-3").await;
    assert!(
        fleet
            .coord
            .scheduler()
            .lock()
            .await
            .lease_holder(lease)
            .is_some(),
        "the lease must be live before the revoke"
    );

    let (status, body) = as_browser(
        &fleet,
        "DELETE",
        &format!("/api/v1/grants/{}", &id[..12]),
        &alice,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // Gone from the **scheduler**, not merely from the `grant` table.
    assert!(
        fleet
            .coord
            .scheduler()
            .lock()
            .await
            .lease_holder(lease)
            .is_none(),
        "the revoked grantee kept its lease"
    );
    // And the close is persisted, the way every other release is.
    let closed: Vec<(Option<i64>,)> = sqlx::query_as("SELECT closed_at FROM leases")
        .fetch_all(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert_eq!(closed.len(), 1);
    assert!(closed[0].0.is_some(), "the lease row is still open");

    let rows = audit_rows(&fleet).await;
    for action in ["grant.create", "grant.revoke"] {
        assert!(rows.iter().any(|(_, _, a)| a == action), "{rows:?}");
    }
}

// ---------------------------------------------------------------------------
// Auth keys
// ---------------------------------------------------------------------------

/// The happy path: a **member** mints, the secret comes back exactly once, and
/// the listing carries only hashes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_mints_a_key_and_the_listing_is_hash_only() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;

    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/auth-keys",
        &alice,
        Some(&auth_key_body(&["lab"], 3_600)),
    )
    .await;
    assert_eq!(status, 200, "a member must be able to mint: {body}");
    let created = parse(&body);
    let secret = created["key"].as_str().unwrap().to_owned();
    assert!(secret.starts_with("prffk1_"), "{body}");
    let hash = created["key_hash"].as_str().unwrap().to_owned();
    assert_eq!(created["purpose"], "node");
    assert_eq!(created["tags"], serde_json::json!(["lab"]));

    // The listing names the hash and never the secret — it is stored nowhere.
    let (status, body) = as_browser(&fleet, "GET", "/api/v1/auth-keys", &alice, None).await;
    assert_eq!(status, 200, "{body}");
    assert!(!body.contains(&secret), "the listing leaked the secret: {body}");
    assert!(body.contains(&hash), "{body}");
    let listed = parse(&body);
    assert_eq!(listed["keys"].as_array().unwrap().len(), 1);
    assert_eq!(listed["keys"][0]["created_by"], "alice");

    // And it works: the key enrolls a node, which is the whole point.
    let (status, body) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(
                serde_json::json!({
                    "grant_type": "auth_key",
                    "auth_key": secret,
                    "node_name": "rpi-lab-1",
                })
                .to_string(),
            ),
        )
        .await;
    assert_eq!(status, 200, "the minted key must enroll a node: {body}");
}

/// The validation is `POST /auth/keys`'s, because it is the same function:
/// `ttl_secs = 0` is a `400`, the TTL is capped, an unrecognised `purpose` is a
/// `400`, a `ci` key with no tags is a `400`, and the tags must pass
/// `valid_tags` (charset, `MAX_TAGS`, `MAX_TAG_LEN`).
///
/// Forking any of these would be worse than it looks. The tagless-`ci` rule is
/// the one that stops a key from synthesising a grant over the whole fleet: an
/// empty tag set is an empty selector, which matches every board in the org.
/// The `valid_tags` rule is what makes "validated at mint" imply "parses at
/// redemption": a CI key's tags become a *selector* when it is redeemed, and a
/// tag like `*` is refused by the selector grammar (there is no wildcard), so
/// without this gate a mint-time typo would only surface as a failed
/// redemption. It also imposes `MAX_TAGS`/`MAX_TAG_LEN` on this path for the
/// first time — a deliberate widening to a path that had escaped the shared
/// rule node registration and the node `PATCH` already apply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_key_validation_is_the_shared_validation() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;

    let cases = [
        ("a forever key", serde_json::json!({ "tags": [], "ttl_secs": 0 })),
        (
            "beyond the 30-day cap",
            serde_json::json!({ "tags": [], "ttl_secs": 31 * 24 * 3600 }),
        ),
        (
            "an unrecognised purpose",
            serde_json::json!({ "tags": [], "ttl_secs": 3600, "purpose": "nde" }),
        ),
        (
            "a tagless ci key",
            serde_json::json!({ "tags": [], "ttl_secs": 3600, "purpose": "ci" }),
        ),
        (
            "an unrecognised op",
            serde_json::json!({
                "tags": ["nrf52"], "ttl_secs": 3600, "purpose": "ci", "ops": ["teleport"]
            }),
        ),
        (
            "a wildcard tag",
            serde_json::json!({ "tags": ["*"], "ttl_secs": 3600, "purpose": "ci" }),
        ),
        (
            "an unknown field",
            serde_json::json!({ "tags": [], "ttl_secs": 3600, "single_use": true }),
        ),
    ];
    for (label, body) in cases {
        let (status, response) = as_browser(
            &fleet,
            "POST",
            "/api/v1/auth-keys",
            &alice,
            Some(&body.to_string()),
        )
        .await;
        assert_eq!(status, 400, "{label} must be refused: {response}");
        assert!(response.contains("invalid_request"), "{label}: {response}");
    }

    // Exactly at the cap is accepted, so the bound is the one reported.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/auth-keys",
        &alice,
        Some(&auth_key_body(&[], 30 * 24 * 3600)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
}

/// **Creator-or-admin**, including the `created_by = NULL` row that only an
/// admin can revoke — the shell-minted key which would otherwise be unrevokable
/// from a browser at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_auth_key_is_revocable_by_its_creator_or_an_admin_only() {
    let fleet = TestCoordinator::start().await;
    let org = OrgId("acme".to_owned());
    let admin = fleet.seed_session("acme", "root", Role::Admin).await;
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    let bob = fleet.seed_session("acme", "bob", Role::Member).await;

    // Alice's own key.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/auth-keys",
        &alice,
        Some(&auth_key_body(&[], 3_600)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let alices = parse(&body)["key_hash"].as_str().unwrap().to_owned();

    // A shell-minted key: `created_by` is NULL.
    let orphan_secret = fleet.seed_auth_key(&org.0, &[], true, None).await;
    let orphan = fleet_auth::OpaqueToken::parse(&orphan_secret)
        .unwrap()
        .hash()
        .as_str()
        .to_owned();

    // Bob, a member who created neither, may revoke neither.
    for hash in [&alices, &orphan] {
        let (status, body) = as_browser(
            &fleet,
            "DELETE",
            &format!("/api/v1/auth-keys/{}", &hash[..16]),
            &bob,
            None,
        )
        .await;
        assert_eq!(status, 403, "{hash}: {body}");
    }
    let rows = audit_rows(&fleet).await;
    assert_eq!(
        rows.iter()
            .filter(|(_, _, a)| a == "auth_key.revoke.denied")
            .count(),
        2,
        "{rows:?}"
    );

    // Alice revokes her own...
    let (status, body) = as_browser(
        &fleet,
        "DELETE",
        &format!("/api/v1/auth-keys/{}", &alices[..16]),
        &alice,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body)["revoked"], serde_json::json!([alices]));

    // ... but not the creatorless one; only the admin can.
    let (status, body) = as_browser(
        &fleet,
        "DELETE",
        &format!("/api/v1/auth-keys/{}", &orphan[..16]),
        &alice,
        None,
    )
    .await;
    assert_eq!(status, 403, "{body}");
    let (status, body) = as_browser(
        &fleet,
        "DELETE",
        &format!("/api/v1/auth-keys/{}", &orphan[..16]),
        &admin,
        None,
    )
    .await;
    assert_eq!(status, 200, "an admin must reach a creatorless key: {body}");

    // A short or non-hex prefix is refused: an empty one is `LIKE '%'`.
    for bad in ["abc", "nothexbutlong"] {
        let (status, body) = as_browser(
            &fleet,
            "DELETE",
            &format!("/api/v1/auth-keys/{bad}"),
            &admin,
            None,
        )
        .await;
        assert_eq!(status, 400, "{bad}: {body}");
    }
}

/// **Revoking a `ci` key takes its synthesised grant — and the live lease — with
/// it**, because `revoke_auth_key` is called unchanged and it owns that cascade.
///
/// This is the auth-key half of "revocation is real". An implementation that
/// reimplemented the delete would pass every other test here and leave a runner
/// on a board whose key the operator believes is dead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_a_ci_key_cascades_into_its_grant_and_lease() {
    let fleet = TestCoordinator::start().await;
    let org = OrgId("acme".to_owned());
    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;

    // Mint through the browser API, so the key under test is one this surface
    // created.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/auth-keys",
        &alice,
        Some(
            &serde_json::json!({
                "tags": ["nrf52"], "ttl_secs": 86_400, "multi_use": true, "purpose": "ci"
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let created = parse(&body);
    let secret = created["key"].as_str().unwrap().to_owned();
    let hash = created["key_hash"].as_str().unwrap().to_owned();

    // Redeem it: a workload token, and the grant its redemption synthesises.
    let (status, body) = fleet
        .http(
            "POST",
            "/auth/token",
            Some(
                serde_json::json!({ "grant_type": "workload_key", "auth_key": secret }).to_string(),
            ),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let workload = parse(&body)["token"].as_str().unwrap().to_owned();
    let grants = fleet.db().scoped(org.clone()).list_grants().await.unwrap();
    assert_eq!(grants.len(), 1, "one key, one grant");
    assert!(grants[0].id.starts_with("ci-"), "{}", grants[0].id);

    // The runner takes a lease.
    let ci = fleet.client_session(&workload).await;
    let lease = take_lease(&ci, "dk-3").await;

    // Revoke the key through the browser API.
    let (status, body) = as_browser(
        &fleet,
        "DELETE",
        &format!("/api/v1/auth-keys/{}", &hash[..16]),
        &alice,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");

    assert!(
        fleet
            .coord
            .scheduler()
            .lock()
            .await
            .lease_holder(lease)
            .is_none(),
        "revoking a CI key must release what it was holding, not wait out the TTL"
    );
    assert!(
        fleet.db().scoped(org).list_grants().await.unwrap().is_empty(),
        "the synthesised grant survived the key"
    );
}

// ---------------------------------------------------------------------------
// Cross-tenancy, and the no-capability-token rule
// ---------------------------------------------------------------------------

/// **Org A can list, create against, revoke and see nothing of org B.**
///
/// The listings are org-scoped by `OrgDb`, and the revocations must answer
/// exactly as they would for an object that does not exist — a `403` for "not
/// yours" and a `404` for "no such thing" would make the API an org-enumeration
/// oracle (`docs/web-ui.md` §4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_orgs_session_touches_nothing_of_another() {
    let fleet = TestCoordinator::start().await;
    let (alice, alice_org, _a) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    let (mallory, mallory_org, _m) = fleet.seed_github_user(2, "mallory", Role::Admin).await;
    fleet.seed_github_user(3, "bob", Role::Member).await;

    // Alice's org has a grant and a key; mallory's has neither.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &alice,
        Some(&grant_body(&fleet, "bob", "tag=nrf52", &["attach"])),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let grant_id = parse(&body)["id"].as_str().unwrap().to_owned();
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/auth-keys",
        &alice,
        Some(&auth_key_body(&[], 3_600)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let key_hash = parse(&body)["key_hash"].as_str().unwrap().to_owned();

    // Mallory sees neither.
    let (status, body) = as_browser(&fleet, "GET", "/api/v1/grants", &mallory, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body).as_array().unwrap().len(), 0, "{body}");
    let (status, body) = as_browser(&fleet, "GET", "/api/v1/auth-keys", &mallory, None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body)["keys"].as_array().unwrap().len(), 0, "{body}");
    assert_eq!(parse(&body)["org"], mallory_org.0);

    // And cannot revoke either, indistinguishably from an absent object.
    let (real_status, real_body) = as_browser(
        &fleet,
        "DELETE",
        &format!("/api/v1/grants/{}", &grant_id[..12]),
        &mallory,
        None,
    )
    .await;
    let (fake_status, fake_body) = as_browser(
        &fleet,
        "DELETE",
        "/api/v1/grants/ffffffffffff",
        &mallory,
        None,
    )
    .await;
    assert_eq!(
        (real_status, real_body.as_str()),
        (fake_status, fake_body.as_str()),
        "another org's grant must be indistinguishable from an absent one"
    );
    let (real_status, real_body) = as_browser(
        &fleet,
        "DELETE",
        &format!("/api/v1/auth-keys/{}", &key_hash[..16]),
        &mallory,
        None,
    )
    .await;
    let (fake_status, fake_body) = as_browser(
        &fleet,
        "DELETE",
        "/api/v1/auth-keys/ffffffffffffffff",
        &mallory,
        None,
    )
    .await;
    assert_eq!(
        (real_status, real_body.as_str()),
        (fake_status, fake_body.as_str()),
        "another org's auth key must be indistinguishable from an absent one"
    );

    // Nothing of alice's moved.
    assert_eq!(
        fleet
            .db()
            .scoped(alice_org)
            .list_grants()
            .await
            .unwrap()
            .len(),
        1
    );

    // A grant *created* by mallory lands in mallory's org, never alice's: the
    // org comes from the session, never from the request.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &mallory,
        Some(&grant_body(&fleet, "bob", "tag=nrf52", &["attach"])),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body)["org"], mallory_org.0);
}

/// **The no-capability-token test `docs/web-ui.md` §5 and D4 ask for by name**,
/// broad enough to fail if a future endpoint adds one.
///
/// It sweeps every `/api/v1` route this phase reaches for a credential prefix
/// and for the hex shape a `LeaseGrant::token` / `ChannelOpened::token` /
/// `/delegate` bearer would take. The **one** deliberate exception is
/// `POST /api/v1/auth-keys`' `key` field, which is checked by *name* rather than
/// by prefix class: an auth key is an org-scoped, expiring, revocable enrollment
/// credential, not an offline-verifiable capability over a leased board (D4).
/// Anything else carrying a secret fails here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_response_body_carries_a_capability_token() {
    let fleet = TestCoordinator::start().await;
    let (alice, org, _id) = fleet.seed_github_user(1, "alice", Role::Admin).await;
    fleet.seed_github_user(2, "bob", Role::Member).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    // A live lease, so the one artefact that *has* a capability token exists
    // while the sweep runs.
    let session = fleet.client_session(&alice).await;
    let lease = take_lease(&session, "dk-3").await;

    // Mint the two objects, then sweep everything.
    let (_, created_grant) = as_browser(
        &fleet,
        "POST",
        "/api/v1/grants",
        &alice,
        Some(&grant_body(&fleet, "bob", "tag=nrf52", &["attach"])),
    )
    .await;
    let (_, created_key) = as_browser(
        &fleet,
        "POST",
        "/api/v1/auth-keys",
        &alice,
        Some(&auth_key_body(&[], 3_600)),
    )
    .await;
    let minted_key = parse(&created_key)["key"].as_str().unwrap().to_owned();

    let mut bodies: Vec<(String, String)> = vec![
        ("POST /api/v1/grants".to_owned(), created_grant),
        (
            format!("DELETE /api/v1/leases/{}", lease.0),
            as_browser(
                &fleet,
                "DELETE",
                &format!("/api/v1/leases/{}", lease.0),
                &alice,
                None,
            )
            .await
            .1,
        ),
    ];
    for path in [
        "/api/v1/grants",
        "/api/v1/grants/limits",
        "/api/v1/auth-keys",
        "/api/v1/boards",
        "/api/v1/leases",
        "/api/v1/nodes",
        "/api/v1/session",
        "/api/v1/org",
        "/api/v1/org/members",
        "/api/v1/audit",
    ] {
        let (_, body) = as_browser(&fleet, "GET", path, &alice, None).await;
        bodies.push((format!("GET {path}"), body));
    }

    for (route, body) in &bodies {
        for prefix in ["prfs1_", "prfn1_", "prffk1_", "prfnd1_", "prfw1_"] {
            assert!(
                !body.contains(prefix),
                "{route} returned a `{prefix}` credential: {body}"
            );
        }
        assert!(
            !body.contains(&alice),
            "{route} echoed the caller's own session token"
        );
        assert!(
            !body.contains(&minted_key),
            "{route} echoed a minted auth key: {body}"
        );
        // A capability token is a long hex blob. Nothing on this surface has a
        // legitimate reason to carry one; a field literally named `token` is
        // the shape a future endpoint would add.
        assert!(
            !contains_long_hex_run(body),
            "{route} carried something shaped like a capability token: {body}"
        );
    }

    // The one deliberate exception, and only there: `AuthKeyCreated.key`.
    let key_fields = parse(&created_key);
    assert!(
        key_fields["key"].as_str().unwrap().starts_with("prffk1_"),
        "the auth-key panel's shown-once secret must still be present"
    );
    // ... and it is the *only* field of that body carrying it.
    for (name, value) in key_fields.as_object().unwrap() {
        if name == "key" {
            continue;
        }
        assert!(
            !value.to_string().contains("prffk1_"),
            "{name} carried the secret too: {created_key}"
        );
    }
}

/// A hex run long enough to be a signed capability token rather than an id.
///
/// Grant ids are 32 hex characters and key hashes are 64, so the bar is set
/// above both: a `SignedToken`'s wire form is a signature plus a payload, so it
/// is far longer than either. This is deliberately a *shape* check — the point
/// is to fail for a token a future endpoint adds, whatever it is called.
fn contains_long_hex_run(body: &str) -> bool {
    let mut run = 0usize;
    for b in body.bytes() {
        if b.is_ascii_hexdigit() {
            run += 1;
            if run > 96 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Audit parity with the CLI path
// ---------------------------------------------------------------------------

/// **Every mutating endpoint emits the audit entries the CLI path does** —
/// same action, same subject, same detail.
///
/// This is the assertion that catches a handler which reimplemented a verb
/// instead of calling its core: the row would still be there, spelled slightly
/// differently, and an audit log with two spellings of one ceremony is one
/// nobody can query. The comparison is against rows the **wire** surface writes
/// for the identical operation, not against strings copied out of the source.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_browser_path_audits_exactly_as_the_wire_path_does() {
    use fleet_wire::{CoordToSidecar, SidecarToCoord};

    /// `(action, detail)` for every audit row, in order.
    async fn detailed_rows(fleet: &TestCoordinator) -> Vec<(String, Option<String>)> {
        sqlx::query_as("SELECT action, detail FROM audit_log ORDER BY id")
            .fetch_all(fleet.db().pool_for_test())
            .await
            .unwrap()
    }

    // --- the wire path, as the CLI drives it ------------------------------
    let wire = TestCoordinator::start().await;
    let (alice_w, org_w, _id) = wire.seed_github_user(1, "alice", Role::Admin).await;
    wire.seed_github_user(2, "bob", Role::Member).await;
    let expires = wire.coord.now() + 3_600;
    let session = wire.client_session(&alice_w).await;
    let wire_id = match session
        .request(SidecarToCoord::GrantCreate {
            subject: "bob".to_owned(),
            selector: "tag=nrf52".to_owned(),
            ops: vec![AllowedOp::Attach],
            expires: Some(expires),
        })
        .await
        .unwrap()
    {
        CoordToSidecar::GrantCreated(g) => g.id,
        other => panic!("expected GrantCreated, got {other:?}"),
    };
    match session
        .request(SidecarToCoord::GrantRevoke {
            id: wire_id[..12].to_owned(),
        })
        .await
        .unwrap()
    {
        CoordToSidecar::GrantRevoked { ids } => assert_eq!(ids.len(), 1),
        other => panic!("expected GrantRevoked, got {other:?}"),
    }
    let wire_rows = detailed_rows(&wire).await;

    // --- the browser path, doing exactly the same thing -------------------
    let browser = TestCoordinator::start().await;
    let (alice_b, org_b, _id) = browser.seed_github_user(1, "alice", Role::Admin).await;
    browser.seed_github_user(2, "bob", Role::Member).await;
    assert_eq!(org_w, org_b, "the two fixtures must produce the same org");
    let (status, body) = as_browser(
        &browser,
        "POST",
        "/api/v1/grants",
        &alice_b,
        Some(
            &serde_json::json!({
                "subject": "bob",
                "selector": "tag=nrf52",
                "ops": ["attach"],
                "expires": browser.coord.now() + 3_600,
            })
            .to_string(),
        ),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let browser_id = parse(&body)["id"].as_str().unwrap().to_owned();
    let (status, body) = as_browser(
        &browser,
        "DELETE",
        &format!("/api/v1/grants/{}", &browser_id[..12]),
        &alice_b,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let browser_rows = detailed_rows(&browser).await;

    // The grant id is random per run, so it is normalised out; everything else
    // — the action names, the subject rendering, the op list, the selector —
    // must match byte for byte.
    let normalise = |rows: Vec<(String, Option<String>)>, id: &str| -> Vec<(String, Option<String>)> {
        rows.into_iter()
            .map(|(a, d)| (a, d.map(|d| d.replace(id, "<id>"))))
            .collect()
    };
    let wire_rows = normalise(wire_rows, &wire_id);
    // Guard against the comparison passing because both sides logged nothing:
    // the two verbs write one row each, and `grant.revoke` is the one a
    // reimplementation would most plausibly drop.
    assert!(
        wire_rows.iter().any(|(a, _)| a == "grant.create")
            && wire_rows.iter().any(|(a, _)| a == "grant.revoke"),
        "the wire baseline is empty, so the comparison proves nothing: {wire_rows:?}"
    );
    assert_eq!(
        normalise(browser_rows, &browser_id),
        wire_rows,
        "the browser path must leave the same audit trail as the CLI's"
    );
}

/// Auth-key mint and revoke leave the rows `POST /auth/keys` leaves, for the
/// same reason: one credential, one ceremony, one spelling in the log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_key_verbs_audit_exactly_as_the_json_route_does() {
    /// `(action, detail)` for every audit row, in order.
    async fn detailed_rows(fleet: &TestCoordinator) -> Vec<(String, Option<String>)> {
        sqlx::query_as("SELECT action, detail FROM audit_log ORDER BY id")
            .fetch_all(fleet.db().pool_for_test())
            .await
            .unwrap()
    }

    // --- `POST /auth/keys`, as the CLI drives it --------------------------
    let cli = TestCoordinator::start().await;
    let alice_c = cli.seed_session("acme", "alice", Role::Member).await;
    let (status, body) = cli
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&alice_c),
            Some(
                serde_json::json!({ "action": "create", "tags": ["lab"], "ttl_secs": 3600 })
                    .to_string(),
            ),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let cli_hash = parse(&body)["key_hash"].as_str().unwrap().to_owned();
    let (status, body) = cli
        .http_auth(
            "POST",
            "/auth/keys",
            Some(&alice_c),
            Some(
                serde_json::json!({ "action": "revoke", "prefix": &cli_hash[..16] }).to_string(),
            ),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let cli_rows = detailed_rows(&cli).await;

    // --- `/api/v1/auth-keys`, doing the same thing ------------------------
    let web = TestCoordinator::start().await;
    let alice_w = web.seed_session("acme", "alice", Role::Member).await;
    let (status, body) = as_browser(
        &web,
        "POST",
        "/api/v1/auth-keys",
        &alice_w,
        Some(&auth_key_body(&["lab"], 3_600)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let web_hash = parse(&body)["key_hash"].as_str().unwrap().to_owned();
    let (status, body) = as_browser(
        &web,
        "DELETE",
        &format!("/api/v1/auth-keys/{}", &web_hash[..16]),
        &alice_w,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let web_rows = detailed_rows(&web).await;

    let normalise = |rows: Vec<(String, Option<String>)>, hash: &str| -> Vec<(String, Option<String>)> {
        rows.into_iter()
            .map(|(a, d)| (a, d.map(|d| d.replace(hash, "<hash>"))))
            .collect()
    };
    let cli_rows = normalise(cli_rows, &cli_hash);
    assert!(
        cli_rows.iter().any(|(a, _)| a == "auth_key.mint")
            && cli_rows.iter().any(|(a, _)| a == "auth_key.revoke"),
        "the CLI baseline is empty, so the comparison proves nothing: {cli_rows:?}"
    );
    assert_eq!(
        normalise(web_rows, &web_hash),
        cli_rows,
        "the browser path must leave the same auth-key audit trail"
    );
}
