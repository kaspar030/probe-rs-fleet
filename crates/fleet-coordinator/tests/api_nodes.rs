//! Node management and pending-node approval over `/api/v1` (`docs/web-ui.md`
//! §3, phase 1b).
//!
//! These are the first genuinely mutating browser endpoints, so the coverage is
//! shaped by what a mistake would cost rather than by what is easy to assert:
//!
//! * **the owner-or-admin policy**, including its deliberate sharp edge — a
//!   node with `owner_user_id = NULL` (auth-key or shell enrollment) is
//!   **admin-only**, and a plain member cannot reach it by the owner path;
//! * **the cascade**, because `DELETE` is a revocation and not a tidy-up: a
//!   node holding a live lease must leave the *scheduler*, not merely the
//!   `node` table. Asserting the row vanished would pass against an
//!   implementation that leaves a machine relaying bytes until its lease TTL
//!   expires;
//! * **CSRF**, on every mutating route, for a cookie-authenticated caller;
//! * **cross-tenancy**, where the required answer is that org B's node is
//!   indistinguishable from one that does not exist — a `404` for "no such
//!   node" and a `403` for "not yours" would make the API an org-enumeration
//!   oracle (`docs/web-ui.md` §4);
//! * **the audit trail**, which must match the CLI path's rather than being a
//!   second, differently-spelled opinion.

mod common;

use common::TestCoordinator;

use fleet_auth::api::NodeRegisterStartResponse;
use fleet_proto::adopt::AdoptPolicy;
use fleet_proto::ids::{OrgId, Role};

/// Every mutating route this phase adds, as `(method, path)`.
const MUTATING: [(&str, &str); 3] = [
    ("PATCH", "/api/v1/nodes/rpi-1"),
    ("DELETE", "/api/v1/nodes/rpi-1"),
    ("POST", "/api/v1/nodes/pending/ABCD-1234"),
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

/// Call a route with an `Authorization: Bearer`, which needs no CSRF header:
/// the credential is not ambient.
async fn as_bearer(
    fleet: &TestCoordinator,
    method: &str,
    path: &str,
    token: &str,
    body: Option<&str>,
) -> (u16, String) {
    let (status, _, body) = fleet
        .http_full(
            method,
            path,
            &[("authorization", &format!("Bearer {token}"))],
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

/// Begin a node registration, returning its start response.
async fn start_registration(fleet: &TestCoordinator, node_name: &str) -> NodeRegisterStartResponse {
    let (status, body) = fleet
        .http(
            "POST",
            "/node/register/start",
            Some(serde_json::json!({ "node_name": node_name, "tags": ["lab"] }).to_string()),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    serde_json::from_str(&body).unwrap()
}

fn decision(decision: &str, replace: bool) -> String {
    serde_json::json!({ "decision": decision, "replace": replace }).to_string()
}

// ---------------------------------------------------------------------------
// Authentication and CSRF: properties of the surface
// ---------------------------------------------------------------------------

/// Unauthenticated is refused on every mutating route, with the same flat body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_mutating_route_refuses_an_unauthenticated_caller() {
    let fleet = TestCoordinator::start().await;
    for (method, path) in MUTATING {
        let (status, body) = fleet.http(method, path, Some("{}".into())).await;
        assert_eq!(status, 401, "{method} {path}: {body}");
        assert!(body.contains("unauthorized"), "{method} {path}: {body}");
    }
}

/// **CSRF.** A cookie-authenticated mutating call with no `X-Fleet-Csrf` header
/// — or with the wrong one — is refused, while the *same* credential in an
/// `Authorization` header goes through without one.
///
/// That asymmetry is the whole design: the cookie is ambient (a browser
/// attaches it to any request to this origin, including one another site
/// caused), the header is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cookie_authenticated_mutation_needs_the_csrf_header() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;
    fleet
        .seed_owned_node("acme", "rpi-1", "alice", AdoptPolicy::Declared)
        .await;
    let (cookie, csrf) = fleet.browser_session(&alice);

    for (method, path) in MUTATING {
        // No header at all.
        let (status, _, body) = fleet
            .http_full(method, path, &[("cookie", &cookie)], Some("{}".into()))
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
                Some("{}".into()),
            )
            .await;
        assert_eq!(status, 403, "{method} {path} with a wrong CSRF: {body}");
    }

    // And the same credential in a header needs none: `PATCH` succeeds, which
    // proves the 403s above were the CSRF check and not the route being closed.
    let (status, body) = as_bearer(
        &fleet,
        "PATCH",
        "/api/v1/nodes/rpi-1",
        &alice,
        Some(r#"{"tags":["lab"]}"#),
    )
    .await;
    assert_eq!(status, 200, "{body}");
}

// ---------------------------------------------------------------------------
// PATCH
// ---------------------------------------------------------------------------

/// The happy path, plus the two things a `PATCH` must *not* do: rename, and
/// clear a field the caller did not mention.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_owner_may_patch_tags_and_adopt_but_never_the_name() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    fleet
        .seed_owned_node("acme", "rpi-1", "alice", AdoptPolicy::Declared)
        .await;

    // Tags only: `adopt` is untouched, because an absent key means "leave it".
    let (status, body) = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/rpi-1",
        &alice,
        Some(r#"{"tags":["lab","nrf52"]}"#),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let node = parse(&body);
    assert_eq!(node["tags"], serde_json::json!(["lab", "nrf52"]));
    assert_eq!(node["adopt"], "declared");
    assert_eq!(node["name"], "rpi-1");
    assert_eq!(node["owner"], "alice");

    // Adopt only: the tags survive.
    let (status, body) = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/rpi-1",
        &alice,
        Some(r#"{"adopt":"auto"}"#),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let node = parse(&body);
    assert_eq!(node["adopt"], "auto");
    assert_eq!(node["tags"], serde_json::json!(["lab", "nrf52"]));

    // An empty tag list *does* clear them: `Some(vec![])` and `None` are
    // different requests, which is why the field is an `Option`.
    let (status, body) = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/rpi-1",
        &alice,
        Some(r#"{"tags":[]}"#),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body)["tags"], serde_json::json!([]));

    // A `name` field is a 400, **not** a silent no-op: the node id is
    // `{org}/{name}` and renaming would have to cascade through `board`,
    // `leases.node_id` and every live `BoardRef` in the scheduler. Refusing is
    // the v1 answer, and an operator must learn that it was refused.
    let (status, body) = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/rpi-1",
        &alice,
        Some(r#"{"name":"rpi-2"}"#),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("invalid_request"), "{body}");
    // Even alongside a field that *is* accepted: the whole request is refused.
    let (status, body) = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/rpi-1",
        &alice,
        Some(r#"{"name":"rpi-2","tags":["x"]}"#),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    let (_, body) = as_browser(&fleet, "PATCH", "/api/v1/nodes/rpi-1", &alice, Some("{}")).await;
    assert_eq!(
        parse(&body)["tags"],
        serde_json::json!([]),
        "no partial write"
    );

    // The row itself never moved.
    let names: Vec<(String,)> = sqlx::query_as("SELECT name FROM node WHERE org_id = 'acme'")
        .fetch_all(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert_eq!(names, vec![("rpi-1".to_owned(),)]);
}

/// `tags` and `adopt` are validated with the **existing** validators, so the
/// charset claim `docs/web-ui.md` §5 makes about rendered text holds here too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn patch_validates_tags_and_adopt_the_way_enrollment_does() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    fleet
        .seed_owned_node("acme", "rpi-1", "alice", AdoptPolicy::Declared)
        .await;

    for bad in [
        // An ANSI escape, which is what could repaint an approval warning or a
        // terminal listing.
        r#"{"tags":["\u001b[2Jgotcha"]}"#,
        // A slash, which is meaningful inside ids.
        r#"{"tags":["a/b"]}"#,
        // Empty, over-long, and too many.
        r#"{"tags":[""]}"#,
        r#"{"tags":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}"#,
        r#"{"tags":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q"]}"#,
        // A typo'd policy is a 400, never a silent default — the failure mode
        // would be sharing probes nobody meant to share.
        r#"{"adopt":"delcared"}"#,
        r#"{"adopt":""}"#,
        // Not an object at all.
        r#"["tags"]"#,
        r#"{"tags":"lab"}"#,
        // An unknown field, including the near-miss of the one field that is
        // refused by name: a misspelling must not be a silent success while the
        // correct spelling is a 400.
        r#"{"nmae":"rpi-2"}"#,
        r#"{"tags":["lab"],"owner":"mallory"}"#,
    ] {
        let (status, body) =
            as_browser(&fleet, "PATCH", "/api/v1/nodes/rpi-1", &alice, Some(bad)).await;
        assert_eq!(status, 400, "{bad} was accepted: {body}");
    }

    // Nothing was written by any of them.
    let (tags, adopt): (String, String) =
        sqlx::query_as("SELECT tags, adopt_policy FROM node WHERE id = 'acme/rpi-1'")
            .fetch_one(fleet.db().pool_for_test())
            .await
            .unwrap();
    assert_eq!(tags, "");
    assert_eq!(adopt, "declared");
}

/// **The owner-or-admin policy, from every side.**
///
/// A member who is neither owner nor admin is refused; an admin may act on
/// somebody else's node; and a node with `owner_user_id = NULL` is admin-only
/// — the sharp edge, deliberate and asserted rather than left to be
/// rediscovered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_mutation_is_owner_or_admin_and_a_null_owner_is_admin_only() {
    let fleet = TestCoordinator::start().await;
    let admin = fleet.seed_session("acme", "root", Role::Admin).await;
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    let bob = fleet.seed_session("acme", "bob", Role::Member).await;

    fleet
        .seed_owned_node("acme", "alices-pi", "alice", AdoptPolicy::Declared)
        .await;
    // The auth-key / shell shape: no owning human by construction.
    fleet.seed_node("acme", "unowned-pi").await;

    // Bob is a member of the org, and that is not enough.
    let (status, body) = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/alices-pi",
        &bob,
        Some(r#"{"tags":["mine-now"]}"#),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("forbidden"), "{body}");
    let (status, body) = as_browser(&fleet, "DELETE", "/api/v1/nodes/alices-pi", &bob, None).await;
    assert_eq!(status, 403, "{body}");

    // The owner may.
    let (status, body) = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/alices-pi",
        &alice,
        Some(r#"{"tags":["lab"]}"#),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // An admin may, on somebody else's node.
    let (status, body) = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/alices-pi",
        &admin,
        Some(r#"{"adopt":"auto"}"#),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // `owner_user_id = NULL` is **admin-only**: it does not mean "everybody
    // owns it". A plain member's owner-path attempt fails.
    for member in [&alice, &bob] {
        let (status, body) = as_browser(
            &fleet,
            "PATCH",
            "/api/v1/nodes/unowned-pi",
            member,
            Some(r#"{"tags":["x"]}"#),
        )
        .await;
        assert_eq!(status, 403, "a NULL owner must not be everybody's: {body}");
        let (status, body) =
            as_browser(&fleet, "DELETE", "/api/v1/nodes/unowned-pi", member, None).await;
        assert_eq!(status, 403, "{body}");
    }
    // ... while the admin can still administer it, or it would be unreachable.
    let (status, body) = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/unowned-pi",
        &admin,
        Some(r#"{"tags":["x"]}"#),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // The refusals are on the record, under the same shape `grant.revoke.denied`
    // uses: a refused mutation is still an event worth auditing.
    let rows = audit_rows(&fleet).await;
    assert!(
        rows.iter().any(|(org, subject, action)| org == "acme"
            && subject.as_deref() == Some("acme/user:bob")
            && action == "node.update.denied"),
        "{rows:?}"
    );
    assert!(
        rows.iter()
            .any(|(_, _, action)| action == "node.delete.denied"),
        "{rows:?}"
    );
}

/// A non-member of the org gets the flat refusal, and learns nothing about
/// which node names exist: membership is checked before the lookup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_member_cannot_probe_which_nodes_exist() {
    let fleet = TestCoordinator::start().await;
    let carol = fleet.seed_session("acme", "carol", Role::Member).await;
    fleet
        .seed_owned_node("acme", "rpi-1", "carol", AdoptPolicy::Declared)
        .await;
    sqlx::query("DELETE FROM member WHERE user_id = 'carol'")
        .execute(fleet.db().pool_for_test())
        .await
        .unwrap();

    let (present, body_present) = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/rpi-1",
        &carol,
        Some(r#"{"tags":["x"]}"#),
    )
    .await;
    let (absent, body_absent) = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/no-such-node",
        &carol,
        Some(r#"{"tags":["x"]}"#),
    )
    .await;
    assert_eq!(present, 403, "{body_present}");
    assert_eq!(
        (present, body_present),
        (absent, body_absent),
        "an existing node and an absent one must answer identically"
    );
}

// ---------------------------------------------------------------------------
// DELETE — the cascade
// ---------------------------------------------------------------------------

/// Take a lease on `board_name` through the real wire surface, so the
/// scheduler, the `leases` table and the audit log all agree it exists.
///
/// Factored out of the delete tests because seeding a lease by hand would not
/// exercise the path whose teardown is under test.
async fn take_lease(
    session: &fleet_sidecar::transport::CoordSession,
    board_name: &str,
) -> fleet_proto::ids::LeaseId {
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

/// **`DELETE` is a revocation.** A node holding a live lease loses it through
/// the whole release path, and the assertion is against the *scheduler*, not
/// merely the row: an implementation that deletes the row alone leaves the
/// machine relaying bytes until the lease TTL expires while the operator
/// believes it is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_a_node_tears_down_its_live_leases_and_boards() {
    use fleet_wire::WireRx as _;

    let fleet = TestCoordinator::start().await;
    let org = OrgId("acme".to_owned());
    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;
    let board = fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    // A real node credential for the same row, so the connection below is a
    // genuine authenticated `/agent` upgrade rather than a stub handle.
    // `seed_node` re-registers `acme/rpi-1` (`register_node` is an upsert on
    // the id), which is what a machine reconnecting after enrollment does.
    let (node_token, _) = fleet.seed_node("acme", "rpi-1").await;
    // The node has to be *owned* by the caller for the owner path; neither
    // `ensure_node` nor `register_node` records an owner.
    sqlx::query("UPDATE node SET owner_user_id = 'alice', name = 'rpi-1' WHERE id = 'acme/rpi-1'")
        .execute(fleet.db().pool_for_test())
        .await
        .unwrap();

    let session = fleet.client_session(&alice).await;
    let lease = take_lease(&session, "dk-3").await;
    assert!(
        fleet
            .coord
            .scheduler()
            .lock()
            .await
            .lease_holder(lease)
            .is_some(),
        "the lease must be live before the delete"
    );
    // ... and a **real** `/agent` connection to drop. Deliberately not an
    // `AgentStub`: a stub is a bare `mpsc` handle with nobody serving the far
    // end, so it can only ever show that the registry entry went away — which
    // is exactly the weaker claim that let the connection-close bug hide here.
    let (node_tx, mut node_rx) = fleet.dial("/agent", &node_token).await.unwrap();
    // Wait for the server to register the connection before deleting, or the
    // test races the upgrade and passes for the wrong reason.
    loop {
        if fleet.coord.agents().get(&board.node).await.is_some() {
            break;
        }
        tokio::task::yield_now().await;
    }

    let (status, body) = as_browser(&fleet, "DELETE", "/api/v1/nodes/rpi-1", &alice, None).await;
    assert_eq!(status, 204, "{body}");
    assert!(body.is_empty(), "204 carries no body: {body}");

    // The lease is gone from the **scheduler**, not merely from the table.
    {
        let sched = fleet.coord.scheduler().lock().await;
        assert!(
            sched.lease_holder(lease).is_none(),
            "the lease survived the delete in the scheduler"
        );
        assert!(
            sched.board(&board).is_none(),
            "the board survived the delete in the scheduler"
        );
    }
    // The close is persisted with a reason, the way every other release is.
    let closed: Vec<(Option<i64>, Option<String>)> =
        sqlx::query_as("SELECT closed_at, close_reason FROM leases")
            .fetch_all(fleet.db().pool_for_test())
            .await
            .unwrap();
    assert_eq!(closed.len(), 1);
    assert!(
        closed[0].0.is_some(),
        "the lease row is still open: {closed:?}"
    );

    // The connection is really gone, not merely unrouted. The node's socket
    // must close: an operator who deleted a node expects the machine off the
    // fleet, and `AgentRegistry::remove` alone cannot deliver that (the
    // connection task holds its own sender clone, so the registry's is only a
    // clone). This is the assertion that fails against a bare `remove`.
    assert!(
        fleet.coord.agents().get(&board.node).await.is_none(),
        "the node kept its registry entry"
    );
    let closed_within = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match node_rx.recv().await {
                Ok(fleet_wire::WireEvent::Closed) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(
        closed_within.is_ok(),
        "the deleted node's control-plane connection stayed open"
    );
    drop(node_tx);

    // The rows are gone — node **and** the boards that reference it, which is
    // the cascade `Db::delete_node` alone cannot do under enforced foreign keys.
    let nodes: Vec<(String,)> = sqlx::query_as("SELECT id FROM node")
        .fetch_all(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert!(nodes.is_empty(), "{nodes:?}");
    let boards: Vec<(String,)> = sqlx::query_as("SELECT name FROM board")
        .fetch_all(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert!(boards.is_empty(), "{boards:?}");

    // Audited: the lease teardown writes the same `lease.revoke` the grant
    // cascade does, and the deletion its own row.
    let rows = audit_rows(&fleet).await;
    for action in ["lease.revoke", "node.delete"] {
        assert!(
            rows.iter().any(|(_, _, a)| a == action),
            "missing {action} in {rows:?}"
        );
    }
}

/// A **queued waiter** must not be promoted onto a board that is about to
/// vanish and then left holding an open `leases` row nobody will ever close.
///
/// The shared release path (`tear_down_lease`) promotes the next waiter onto
/// each board it frees, *and persists that promotion*, so a single teardown
/// pass followed by `remove_board` would strand exactly such a row — open in
/// the table, absent from the scheduler, invisible to the sweep. Pinned here
/// because it is a one-line implementation difference with a silent failure
/// mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_waiter_promoted_during_the_teardown_is_not_stranded() {
    use fleet_proto::ids::BoardName;
    use fleet_proto::lease::{Constraint, LeaseRequest, Priority};
    use fleet_wire::{CoordToSidecar, SidecarToCoord};

    let fleet = TestCoordinator::start().await;
    let org = OrgId("acme".to_owned());
    let admin = fleet.seed_session("acme", "root", Role::Admin).await;
    // Plain `seed_session` users, so their subject org **is** `acme` and the
    // board is reachable by ordinary membership. A personal-org user
    // (`seed_github_user`) would be in `gh-N` and reach nothing here.
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    let bob = fleet.seed_session("acme", "bob", Role::Member).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    sqlx::query("UPDATE node SET name = 'rpi-1' WHERE id = 'acme/rpi-1'")
        .execute(fleet.db().pool_for_test())
        .await
        .unwrap();

    let want = || {
        SidecarToCoord::Lease(LeaseRequest {
            select: Constraint::Board(BoardName("dk-3".to_owned())),
            duration_secs: 600,
            priority: Priority::Interactive,
        })
    };
    // Alice holds it; bob queues behind her.
    let alice_session = fleet.client_session(&alice).await;
    match alice_session.request(want()).await.unwrap() {
        CoordToSidecar::Lease(_) => {}
        other => panic!("expected a lease, got {other:?}"),
    }
    let bob_session = fleet.client_session(&bob).await;
    match bob_session.request(want()).await.unwrap() {
        CoordToSidecar::Queued { .. } => {}
        other => panic!("expected bob to queue, got {other:?}"),
    }

    let (status, body) = as_browser(&fleet, "DELETE", "/api/v1/nodes/rpi-1", &admin, None).await;
    assert_eq!(status, 204, "{body}");

    // Every lease row is closed. A row still open here is one whose holder was
    // promoted onto a board that no longer exists.
    let open: Vec<(i64,)> = sqlx::query_as("SELECT lease FROM leases WHERE closed_at IS NULL")
        .fetch_all(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert!(open.is_empty(), "a promoted waiter was stranded: {open:?}");
    // ... and the scheduler holds no lease at all.
    assert_eq!(
        fleet.coord.scheduler().lock().await.boards().count(),
        0,
        "the board survived the delete"
    );
}

/// `DELETE` on a node with boards but no lease still succeeds — the plain
/// cascade, which a bare `DELETE FROM node` would fail outright under
/// `PRAGMA foreign_keys = ON`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_a_node_with_boards_succeeds_and_the_boards_leave_the_scheduler() {
    let fleet = TestCoordinator::start().await;
    let org = OrgId("acme".to_owned());
    let admin = fleet.seed_session("acme", "root", Role::Admin).await;
    let board = fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    let other = fleet.seed_board(&org, "rpi-2", "dk-9", &[]).await;
    sqlx::query("UPDATE node SET name = 'rpi-1' WHERE id = 'acme/rpi-1'")
        .execute(fleet.db().pool_for_test())
        .await
        .unwrap();

    let (status, body) = as_browser(&fleet, "DELETE", "/api/v1/nodes/rpi-1", &admin, None).await;
    assert_eq!(status, 204, "{body}");

    {
        let sched = fleet.coord.scheduler().lock().await;
        assert!(
            sched.board(&board).is_none(),
            "the deleted node's board stayed"
        );
        assert!(
            sched.board(&other).is_some(),
            "another node's board must be untouched"
        );
    }
    let boards: Vec<(String,)> = sqlx::query_as("SELECT node_id FROM board")
        .fetch_all(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert_eq!(boards, vec![("acme/rpi-2".to_owned(),)]);

    // Deleting it again is a 404, not a 500: the row is genuinely gone.
    let (status, body) = as_browser(&fleet, "DELETE", "/api/v1/nodes/rpi-1", &admin, None).await;
    assert_eq!(status, 404, "{body}");
    assert!(body.contains("not_found"), "{body}");
}

/// A deleted node's token stops working on the very next connection, which is
/// what makes `DELETE` a revocation rather than a listing change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deleted_nodes_token_no_longer_authenticates() {
    let fleet = TestCoordinator::start().await;
    let admin = fleet.seed_session("acme", "root", Role::Admin).await;
    let (token, _node) = fleet.seed_node("acme", "rpi-1").await;
    assert_eq!(fleet.upgrade_status("/agent", Some(&token)).await, 101);

    let (status, body) = as_browser(&fleet, "DELETE", "/api/v1/nodes/rpi-1", &admin, None).await;
    assert_eq!(status, 204, "{body}");
    assert_eq!(fleet.upgrade_status("/agent", Some(&token)).await, 401);
}

// ---------------------------------------------------------------------------
// Pending approval
// ---------------------------------------------------------------------------

/// The §4.2 commitment cashed in: a cookie-authenticated approval calls exactly
/// the CLI's handler, produces the same audit rows, and mints a token the node
/// can use.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_member_can_inspect_and_approve_a_pending_node_from_the_browser() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    let grant = start_registration(&fleet, "rpi-lab-3").await;
    let path = format!("/api/v1/nodes/pending/{}", grant.user_code);

    // Inspect: describes the machine, changes nothing, and carries the
    // phishing warning the form must render verbatim.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        &path,
        &alice,
        Some(&decision("inspect", false)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let seen = parse(&body);
    assert_eq!(seen["node_name"], "rpi-lab-3");
    assert_eq!(seen["tags"], serde_json::json!(["lab"]));
    assert_eq!(seen["state"], "pending");
    assert_eq!(seen["org"], "acme", "the approver's org, on inspect too");
    // The RFC 8628 §5.4 mitigation, carried by the response so a frontend that
    // forgets it shows an empty box rather than silently dropping it.
    let warning = seen["warning"].as_str().unwrap_or_default();
    assert!(
        warning.contains("cannot see it from here")
            && warning.contains("ONLY if you started this enrollment"),
        "the approval warning must be carried verbatim: {body}"
    );

    // Approve, then the machine's own poll mints a token.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        &path,
        &alice,
        Some(&decision("approve", false)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body)["state"], "approved");

    let (status, body) = fleet
        .http(
            "POST",
            "/node/register/poll",
            Some(serde_json::json!({ "device_secret": grant.device_secret }).to_string()),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let minted = parse(&body);
    assert_eq!(minted["org"], "acme");
    assert_eq!(minted["node_id"], "acme/rpi-lab-3");
    let token = minted["token"].as_str().unwrap();
    assert_eq!(
        fleet.upgrade_status("/agent", Some(token)).await,
        101,
        "the browser-approved node's token must authenticate"
    );

    // The same audit rows the CLI route writes, under the approver's org.
    let rows = audit_rows(&fleet).await;
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

/// Denial is permanent, and it too goes through the shared handler.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn denying_from_the_browser_burns_the_code() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    let grant = start_registration(&fleet, "rpi-lab-3").await;
    let path = format!("/api/v1/nodes/pending/{}", grant.user_code);

    let (status, body) = as_browser(
        &fleet,
        "POST",
        &path,
        &alice,
        Some(&decision("deny", false)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body)["state"], "denied");

    // The machine never gets a token, and a second decision cannot revive it.
    let (status, body) = fleet
        .http(
            "POST",
            "/node/register/poll",
            Some(serde_json::json!({ "device_secret": grant.device_secret }).to_string()),
        )
        .await;
    assert_ne!(status, 200, "a denied registration must not mint: {body}");
    let (status, body) = as_browser(
        &fleet,
        "POST",
        &path,
        &alice,
        Some(&decision("approve", false)),
    )
    .await;
    assert_eq!(status, 404, "{body}");
}

/// Membership is required to approve, and the refusal writes the *same*
/// `node.approve.denied` row the CLI route writes — one ceremony, one audit
/// action, whichever surface performed it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_requires_membership_and_audits_the_refusal_once() {
    let fleet = TestCoordinator::start().await;
    let carol = fleet.seed_session("acme", "carol", Role::Member).await;
    sqlx::query("DELETE FROM member WHERE user_id = 'carol'")
        .execute(fleet.db().pool_for_test())
        .await
        .unwrap();
    let grant = start_registration(&fleet, "rpi-lab-3").await;
    let path = format!("/api/v1/nodes/pending/{}", grant.user_code);

    let (status, body) = as_browser(
        &fleet,
        "POST",
        &path,
        &carol,
        Some(&decision("inspect", false)),
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("forbidden"), "{body}");

    let rows = audit_rows(&fleet).await;
    assert_eq!(
        rows.iter()
            .filter(|(_, _, action)| action == "node.approve.denied")
            .count(),
        1,
        "exactly one refusal row, spelled the CLI's way: {rows:?}"
    );
}

/// A malformed or unknown code is one flat answer, whatever it actually was:
/// the browser must not become a code oracle either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_code_is_indistinguishable_from_a_malformed_one() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;

    let mut answers = Vec::new();
    for code in ["ABCD-1234", "abcd1234", "%20", "not-a-code"] {
        answers.push(
            as_browser(
                &fleet,
                "POST",
                &format!("/api/v1/nodes/pending/{code}"),
                &alice,
                Some(&decision("inspect", false)),
            )
            .await,
        );
    }
    for answer in &answers {
        assert_eq!(answer.0, 404, "{answer:?}");
        assert_eq!(answer, &answers[0], "the answers must not differ");
    }

    // A body that is not a decision is a 400, not a 500.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/nodes/pending/ABCD-1234",
        &alice,
        Some(r#"{"decision":"obliterate"}"#),
    )
    .await;
    assert_eq!(status, 400, "{body}");
}

// ---------------------------------------------------------------------------
// Cross-tenancy
// ---------------------------------------------------------------------------

/// **Org A cannot `PATCH`, `DELETE` or approve into org B**, and a cross-org
/// node answers exactly as an absent one.
///
/// The REST instinct — `404` for "no such node", `403` for "not yours" — is
/// explicitly wrong here (`docs/web-ui.md` §4): it turns the API into an
/// org-enumeration oracle for anyone with a session anywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_orgs_session_cannot_touch_anothers_nodes() {
    let fleet = TestCoordinator::start().await;
    let mallory = fleet.seed_session("globex", "mallory", Role::Admin).await;
    // The `alice` user row must exist before a node can reference it as owner.
    fleet.seed_session("acme", "alice", Role::Admin).await;
    fleet
        .seed_owned_node("acme", "acme-pi", "alice", AdoptPolicy::Declared)
        .await;
    // Mallory's own org has a node too, so the refusals below cannot be
    // explained by her having no reach at all.
    fleet
        .seed_owned_node("globex", "globex-pi", "mallory", AdoptPolicy::Declared)
        .await;

    let cross = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/acme-pi",
        &mallory,
        Some(r#"{"tags":["pwned"]}"#),
    )
    .await;
    let absent = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/no-such-node",
        &mallory,
        Some(r#"{"tags":["pwned"]}"#),
    )
    .await;
    assert_eq!(cross.0, 404, "{cross:?}");
    assert_eq!(
        cross, absent,
        "a cross-org node must be indistinguishable from an absent one"
    );

    let cross = as_browser(&fleet, "DELETE", "/api/v1/nodes/acme-pi", &mallory, None).await;
    let absent = as_browser(
        &fleet,
        "DELETE",
        "/api/v1/nodes/no-such-node",
        &mallory,
        None,
    )
    .await;
    assert_eq!(cross.0, 404, "{cross:?}");
    assert_eq!(cross, absent);

    // Nothing was written, and nothing leaked into the answer.
    let (tags,): (String,) = sqlx::query_as("SELECT tags FROM node WHERE id = 'acme/acme-pi'")
        .fetch_one(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert_eq!(tags, "");
    assert!(!cross.1.contains("acme"), "{cross:?}");

    // Her own node still works, in her own org: the refusals above are about
    // tenancy, not about her.
    let (status, body) = as_browser(
        &fleet,
        "PATCH",
        "/api/v1/nodes/globex-pi",
        &mallory,
        Some(r#"{"tags":["ok"]}"#),
    )
    .await;
    assert_eq!(status, 200, "{body}");

    // Approval binds into the *approver's* org — which is §6.4's accepted
    // cross-tenant enumeration risk, unchanged and not worsened here. What must
    // hold is that it lands in globex and never touches acme's inventory.
    let grant = start_registration(&fleet, "victim-pi").await;
    let (status, body) = as_browser(
        &fleet,
        "POST",
        &format!("/api/v1/nodes/pending/{}", grant.user_code),
        &mallory,
        Some(&decision("approve", false)),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    // The node row materialises when the machine redeems, so poll before
    // asking which org it landed in.
    let (status, body) = fleet
        .http(
            "POST",
            "/node/register/poll",
            Some(serde_json::json!({ "device_secret": grant.device_secret }).to_string()),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let (org,): (String,) = sqlx::query_as("SELECT org_id FROM node WHERE name = 'victim-pi'")
        .fetch_one(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert_eq!(
        org, "globex",
        "an approval binds into the approver's org only"
    );
    let acme: Vec<(String,)> = sqlx::query_as("SELECT name FROM node WHERE org_id = 'acme'")
        .fetch_all(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert_eq!(acme, vec![("acme-pi".to_owned(),)]);
}

/// No response body from any of these routes carries a credential, which is the
/// property `docs/web-ui.md` §5 asks to be enforced by test rather than by
/// review vigilance — extended here to the routes this phase added.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_mutating_response_carries_a_credential() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;
    fleet
        .seed_owned_node("acme", "rpi-1", "alice", AdoptPolicy::Declared)
        .await;
    let grant = start_registration(&fleet, "rpi-2").await;

    let mut bodies = Vec::new();
    bodies.push(
        as_browser(
            &fleet,
            "PATCH",
            "/api/v1/nodes/rpi-1",
            &alice,
            Some(r#"{"tags":["lab"]}"#),
        )
        .await
        .1,
    );
    bodies.push(
        as_browser(
            &fleet,
            "POST",
            &format!("/api/v1/nodes/pending/{}", grant.user_code),
            &alice,
            Some(&decision("inspect", false)),
        )
        .await
        .1,
    );
    bodies.push(
        as_browser(
            &fleet,
            "POST",
            &format!("/api/v1/nodes/pending/{}", grant.user_code),
            &alice,
            Some(&decision("approve", false)),
        )
        .await
        .1,
    );
    bodies.push(
        as_browser(&fleet, "DELETE", "/api/v1/nodes/rpi-1", &alice, None)
            .await
            .1,
    );

    for body in &bodies {
        for prefix in ["prfs1_", "prfn1_", "prffk1_", "prfnd1_", "prfw1_"] {
            assert!(
                !body.contains(prefix),
                "a `{prefix}` credential leaked: {body}"
            );
        }
        assert!(
            !body.contains(&alice),
            "the caller's own token was echoed: {body}"
        );
        assert!(
            !body.contains(&grant.device_secret),
            "the enrolling machine's device secret leaked: {body}"
        );
    }
}
