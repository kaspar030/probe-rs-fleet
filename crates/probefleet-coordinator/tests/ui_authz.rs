//! Hiding a button is UX; the server does not care that it was hidden.
//!
//! `docs/web-ui.md` §4 and the task's "no new authorization logic in the
//! frontend" both reduce to one claim: **every action the UI hides from a
//! caller is refused server-side for that caller, over the exact carrier the UI
//! uses.** The per-endpoint matrix already lives in `api_grants.rs` /
//! `api_readonly.rs` / `api_nodes.rs`; this file asserts the frontend-relevant
//! claim in one place, so a reviewer of the UI has one file to read.
//!
//! The carrier matters and is not incidental: these calls go over the session
//! **cookie plus `X-Fleet-Csrf`**, which is what `web/api.mjs` sends. A test
//! that used `Authorization: Bearer` would exercise a path the browser never
//! takes and would skip the CSRF gate entirely.
//!
//! What is deliberately *not* here: any assertion about the frontend's own
//! rendering. Whether a member's devices page shows a Release button is a
//! question for `web-tests/pages.test.mjs`; whether pressing it would work is
//! this file's, and the answer must be no regardless of what the page drew.

mod common;

use common::TestCoordinator;

use probefleet_coordinator::FleetRole;
use probefleet_proto::adopt::AdoptPolicy;

/// Call a route the way the UI does: session cookie + CSRF header.
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

/// Every action the access page hides from a member is refused for a member.
///
/// The page renders "creating a grant is admin-only" instead of the form, and
/// hides the audit nav for a non-admin. Neither is a control.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_is_refused_every_admin_action_the_ui_hides() {
    let fleet = TestCoordinator::start().await;
    // Both in **one** org: the question is what a member of an org may do in
    // it, not what a stranger may do to it. A pair of personal orgs would make
    // every refusal below true for the wrong reason.
    fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let bob = fleet.seed_session("acme", "bob", FleetRole::Member).await;

    // Grant creation: admin-only, because a grant points *outward*.
    let body = serde_json::json!({
        "subject": "alice",
        "selector": "tag=nrf52",
        "ops": ["attach"],
        "expires": fleet.coord.now() + 3_600,
    })
    .to_string();
    let (status, response) =
        as_browser(&fleet, "POST", "/api/v1/grants?org=acme", &bob, Some(&body)).await;
    assert_eq!(status, 403, "a member created a grant: {response}");
    assert!(response.contains("forbidden"), "{response}");

    // The audit log: admin-only. The UI renders "your role cannot read the
    // audit log"; the server is what makes that true.
    let (status, response) = as_browser(&fleet, "GET", "/api/v1/audit?org=acme", &bob, None).await;
    assert_eq!(status, 403, "a member read the audit log: {response}");
}

/// A member may not touch a node they do not own, whatever the page drew.
///
/// The nodes page shows Edit/Revoke only for `owner == me` or an admin; the
/// rule itself is `Coordinator::update_node_core`'s, and it holds for a caller
/// who never saw the page.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_cannot_mutate_a_node_it_does_not_own() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let bob = fleet.seed_session("acme", "bob", FleetRole::Member).await;
    // Owned by alice, in the org bob is a member of — so the refusal below is
    // about ownership, not about tenancy (which `api_nodes.rs` covers).
    fleet
        .seed_owned_node("acme", "rpi-1", "alice", AdoptPolicy::Declared)
        .await;

    let (status, response) = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/rpi-1?org=acme",
        &bob,
        Some(r#"{"tags":["mine-now"]}"#),
    )
    .await;
    assert_eq!(status, 403, "a non-owner retagged a node: {response}");

    let (status, response) =
        as_browser(&fleet, "DELETE", "/api/v1/nodes/rpi-1?org=acme", &bob, None).await;
    assert_eq!(status, 403, "a non-owner revoked a node: {response}");

    // And a rename is refused for the *owner* too — the nodes page offers
    // tags and adopt only, and says why, because the server 400s a `name`.
    let (status, response) = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/rpi-1?org=acme",
        &alice,
        Some(r#"{"name":"rpi-2"}"#),
    )
    .await;
    assert_eq!(status, 400, "a rename was accepted: {response}");
    assert!(response.contains("invalid_request"), "{response}");
}

/// A stranger cannot release somebody else's lease, and gets the answer a
/// nonexistent lease would produce.
///
/// The devices page shows Release for the holder or an org admin. A member who
/// is neither gets `404` — deliberately *not* `403`, or the API would be an
/// oracle for which lease ids are live.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stranger_cannot_release_a_lease_and_learns_nothing_from_trying() {
    let fleet = TestCoordinator::start().await;
    let org = fleet.org("acme").await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let bob = fleet.seed_session("acme", "bob", FleetRole::Member).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;

    // Alice takes a lease through the real sidecar path.
    let session = fleet.client_session_in(&alice, "acme").await;
    let lease = {
        use probefleet_proto::ids::BoardName;
        use probefleet_proto::lease::{Constraint, LeaseRequest, Priority};
        use probefleet_wire::{CoordToSidecar, SidecarToCoord};
        match session
            .request(SidecarToCoord::Lease(LeaseRequest {
                select: Constraint::Id(BoardName("dk-3".to_owned())),
                duration_secs: 600,
                priority: Priority::Interactive,
            }))
            .await
            .unwrap()
        {
            CoordToSidecar::Lease(g) => g.lease,
            other => panic!("expected a lease, got {other:?}"),
        }
    };

    let (status, held) = as_browser(
        &fleet,
        "DELETE",
        &format!("/api/v1/leases/{}?org=acme", lease.0),
        &bob,
        None,
    )
    .await;
    assert_eq!(status, 404, "a stranger released a lease: {held}");

    // Byte-identical to the answer for a lease that never existed: that is
    // what stops the endpoint enumerating live leases across tenants.
    let (absent_status, absent) = as_browser(
        &fleet,
        "DELETE",
        "/api/v1/leases/999999?org=acme",
        &bob,
        None,
    )
    .await;
    assert_eq!(absent_status, status);
    assert_eq!(absent, held);
}

/// Power-cycling a board in another org is a `404`, exactly as an absent one
/// is — the devices page simply never lists it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_board_in_another_org_is_indistinguishable_from_one_that_does_not_exist() {
    let fleet = TestCoordinator::start().await;
    let other = fleet.org("other").await;
    let secret = fleet
        .seed_board(&other, "rpi-9", "secret-dk", &["nrf52"])
        .await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;

    let (cross, cross_body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/boards/power-cycle?org=acme",
        &alice,
        Some(&serde_json::json!({ "board": secret.to_string() }).to_string()),
    )
    .await;
    let (absent, absent_body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/boards/power-cycle?org=acme",
        &alice,
        Some(r#"{"board":"no-such-board"}"#),
    )
    .await;
    assert_eq!(cross, 404, "{cross_body}");
    assert_eq!(cross, absent);
    assert_eq!(cross_body, absent_body);
}

/// The UI's carrier is refused without its CSRF header, on every action the
/// pages perform.
///
/// This is the property that makes "the UI is same-origin by construction"
/// true: `web/api.mjs` attaches `X-Fleet-Csrf` to every non-GET, and a request
/// that arrived without it did not come from the UI.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_action_the_ui_performs_needs_the_csrf_header() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    fleet
        .seed_owned_node("acme", "rpi-1", "alice", AdoptPolicy::Declared)
        .await;
    let (cookie, _csrf) = fleet.browser_session(&alice);

    for (method, path, body) in [
        ("POST", "/api/v1/boards/power-cycle", r#"{"board":"dk-3"}"#),
        ("DELETE", "/api/v1/leases/1", "{}"),
        ("PATCH", "/api/v1/nodes/rpi-1", r#"{"tags":[]}"#),
        ("DELETE", "/api/v1/nodes/rpi-1", "{}"),
        ("POST", "/api/v1/nodes/rpi-1/move", r#"{"to_org":"x"}"#),
        (
            "POST",
            "/api/v1/nodes/pending/ABCD-1234",
            r#"{"decision":"inspect"}"#,
        ),
        ("POST", "/api/v1/grants", "{}"),
        ("DELETE", "/api/v1/grants/abcdef0123456789", "{}"),
        ("POST", "/api/v1/auth-keys", r#"{"ttl_secs":3600}"#),
        ("DELETE", "/api/v1/auth-keys/abcdef0123456789", "{}"),
        ("POST", "/api/v1/session/logout", "{}"),
    ] {
        let (status, _, response) = fleet
            .http_full(method, path, &[("cookie", &cookie)], Some(body.to_owned()))
            .await;
        assert_eq!(status, 403, "{method} {path} without CSRF: {response}");
        assert!(
            response.contains("forbidden"),
            "{method} {path}: {response}"
        );
    }
}

/// The `/api/v1` surface is the one place a **cookie** is an accepted
/// credential, so it needs its own version of "a refresh token opens nothing":
/// a `prfr1_` must be refused there over both carriers.
///
/// This closes the last of the five `allowed` lists. `api::api_auth` names
/// `[TokenKind::Session]` and must keep naming exactly that.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refresh_token_reaches_no_api_route_over_either_carrier() {
    let fleet = TestCoordinator::start().await;
    // A genuinely valid refresh token: it mints sessions on `/auth/token`, so
    // the refusals below are about the route rather than a dead credential.
    let refresh = fleet.seed_refresh_token("alice").await;

    for path in ["/api/v1/session", "/api/v1/org", "/api/v1/nodes"] {
        // As a bearer.
        let (status, body) = fleet.http_auth("GET", path, Some(&refresh), None).await;
        assert_eq!(
            status, 403,
            "GET {path} with a bearer refresh token: {body}"
        );

        // As the session cookie, the carrier the browser uses. `browser_session`
        // is not usable here (it derives a CSRF token for a session), so the
        // cookie is built directly — which is the point: an attacker would do
        // exactly this.
        let (status, _, body) = fleet
            .http_full(
                "GET",
                path,
                &[("cookie", &format!("prfs_session={refresh}"))],
                None,
            )
            .await;
        assert_eq!(
            status, 403,
            "GET {path} with a cookie refresh token: {body}"
        );
    }
}

/// The `/<org>/<page>` URLs are no existence oracle.
///
/// The page routes are static: the shell for an org the caller is not in, for
/// an org that does not exist and for one they are in are byte-identical, with
/// or without a session cookie. Membership is decided by the API the shell
/// then calls, `GET /api/v1/session?org=<path>` — which answers `org: null` to
/// a non-member and to a nonexistent org alike (by path *or* by id, the legacy
/// `/ui/<page>?org=<id>` rewrite's input), and data calls refuse both with the
/// same 403. A member resolves the same org by path and by id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_page_urls_leak_no_org_existence() {
    let fleet = TestCoordinator::start().await;
    fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let alice = fleet.session_for("alice").await;
    let (bob, _, _) = fleet.seed_user("bob").await;
    let acme = fleet.org("acme").await;
    let (cookie, csrf) = fleet.browser_session(&bob);
    let carrier = [("cookie", cookie.as_str()), ("x-fleet-csrf", csrf.as_str())];

    // The shell: identical for a real org bob is not in, a nonexistent one,
    // his own, and with no cookie at all.
    let (_, _, reference) = fleet.http_full("GET", "/", &[], None).await;
    for org in ["acme", "no-such-org", "bob", acme.0.as_str()] {
        let path = format!("/{org}/devices");
        for headers in [&carrier[..], &[]] {
            let (status, response_headers, body) =
                fleet.http_full("GET", &path, headers, None).await;
            assert_eq!(status, 200, "{path}");
            assert_eq!(body, reference, "{path} must be byte-identical to /");
            assert!(
                !response_headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case("set-cookie")),
                "{path}"
            );
        }
    }

    // The session API: `org: null` for every org bob cannot act in, by path
    // or id, and byte-identical answers.
    let mut sessions = Vec::new();
    for org in [
        "acme",
        "no-such-org",
        acme.0.as_str(),
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ] {
        let path = format!("/api/v1/session?org={org}");
        let (status, body) = as_browser(&fleet, "GET", &path, &bob, None).await;
        assert_eq!(status, 200, "{path}: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["org"].is_null(), "{path}: {body}");
        sessions.push(v);
    }
    assert!(sessions.windows(2).all(|w| w[0] == w[1]), "{sessions:?}");

    // A data call: the same 403, byte for byte.
    let mut refusals = Vec::new();
    for org in ["acme", "no-such-org"] {
        let path = format!("/api/v1/boards?org={org}");
        let (status, body) = as_browser(&fleet, "GET", &path, &bob, None).await;
        assert_eq!(status, 403, "{path}: {body}");
        refusals.push(body);
    }
    assert_eq!(refusals[0], refusals[1]);

    // A member: path and id are the same org, and the session names it by
    // path — which is what the client puts in the URL.
    for org in ["acme", acme.0.as_str()] {
        let path = format!("/api/v1/session?org={org}");
        let (status, body) = as_browser(&fleet, "GET", &path, &alice, None).await;
        assert_eq!(status, 200, "{path}: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["org"]["id"], acme.0, "{path}: {body}");
        assert_eq!(v["org"]["name"], "acme", "{path}: {body}");
    }
}
