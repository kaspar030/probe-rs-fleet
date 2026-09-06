//! The read-only `/api/v1` surface (`docs/web-ui.md` §3, phase 1a).
//!
//! Per endpoint: unauthenticated is rejected; a wrong-org subject is rejected
//! **exactly as an absent object would be**; the member/admin split holds; and
//! the happy path returns what the CLI's equivalent verb returns.
//!
//! Two properties are asserted once for the whole surface rather than per
//! route, because they are properties *of* the surface:
//!
//! * **cross-tenancy** — org A's session sees nothing of org B through any
//!   route, and gets the response an absent object would produce;
//! * **no capability token ever reaches the browser** — no response body
//!   contains a `prfs1_` / `prfn1_` / `prffk1_` prefix or a hex capability
//!   token. `docs/web-ui.md` §5 asks for exactly this, "enforced by a test over
//!   the API response types, not by review vigilance".

mod common;

use common::TestCoordinator;
use fleet_proto::ids::{OrgId, Role};

/// Every read-only route, for the assertions that hold across all of them.
const READ_ROUTES: [&str; 6] = [
    "/api/v1/session",
    "/api/v1/org",
    "/api/v1/org/members",
    "/api/v1/nodes",
    "/api/v1/boards",
    "/api/v1/leases",
];

/// `GET` a route as the holder of `token`, via the session cookie.
async fn get_as(fleet: &TestCoordinator, path: &str, token: &str) -> (u16, String) {
    let (status, _, body) = fleet
        .http_full(
            "GET",
            path,
            &[("cookie", &format!("prfs_session={token}"))],
            None,
        )
        .await;
    (status, body)
}

fn parse(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}"))
}

/// Every route refuses an unauthenticated caller, with the same flat body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_route_refuses_an_unauthenticated_caller() {
    let fleet = TestCoordinator::start().await;
    for path in READ_ROUTES.iter().chain(["/api/v1/audit"].iter()) {
        let (status, body) = fleet.http("GET", path, None).await;
        assert_eq!(status, 401, "{path}: {body}");
        assert!(body.contains("unauthorized"), "{path}: {body}");
    }
    // The one mutating route too.
    let (status, body) = fleet
        .http("POST", "/api/v1/session/logout", Some("{}".into()))
        .await;
    assert_eq!(status, 401, "{body}");
}

/// An expired session is refused everywhere, and indistinguishably from an
/// unknown one: `fleet_auth::authenticate` decides what "expired" means and
/// there is no second opinion on this surface.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_session_is_refused_like_an_unknown_one() {
    let fleet = TestCoordinator::start().await;
    let expired = fleet.seed_expired_session("acme", "alice").await;
    for path in READ_ROUTES {
        let (status, body) = get_as(&fleet, path, &expired).await;
        assert_eq!(status, 401, "{path}: {body}");
        assert!(body.contains("unauthorized"), "{path}: {body}");
    }
}

/// `GET /api/v1/session` answers for **any** session, including one whose
/// membership was revoked: a UI that cannot learn "you are in no org" has
/// nothing to render but a blank 403.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_answers_even_without_membership() {
    let fleet = TestCoordinator::start().await;
    let (token, org, user_id) = fleet.seed_github_user(7, "kaspar", Role::Member).await;

    let (status, body) = get_as(&fleet, "/api/v1/session", &token).await;
    assert_eq!(status, 200, "{body}");
    let me = parse(&body);
    assert_eq!(me["user"], user_id);
    assert_eq!(me["login"], "kaspar");
    assert_eq!(me["org"], org.0);
    // First login makes you the admin of your own personal org (§6.1), and
    // `ensure_user_member` does not downgrade an existing row — so the role
    // here is `admin` whatever the seed asked for.
    assert_eq!(me["role"], "admin");
    assert!(me["expires"].is_number());

    // Revoke the membership; the session still resolves, with no role.
    sqlx::query("DELETE FROM member WHERE org_id = ?1 AND user_id = ?2")
        .bind(org.0.as_str())
        .bind(user_id.as_str())
        .execute(fleet.db().pool_for_test())
        .await
        .unwrap();

    let (status, body) = get_as(&fleet, "/api/v1/session", &token).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body)["role"], "none");

    // But everything that needs membership is now closed.
    for path in ["/api/v1/org", "/api/v1/org/members", "/api/v1/nodes"] {
        let (status, body) = get_as(&fleet, path, &token).await;
        assert_eq!(status, 403, "{path}: {body}");
    }
}

/// `GET /api/v1/org` and `/api/v1/org/members` are member-gated, and the
/// listing is the org's own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_and_members_are_member_gated_and_org_scoped() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;
    let bob = fleet.seed_session("acme", "bob", Role::Member).await;
    let _mallory = fleet.seed_session("other", "mallory", Role::Admin).await;

    let (status, body) = get_as(&fleet, "/api/v1/org", &alice).await;
    assert_eq!(status, 200, "{body}");
    let org = parse(&body);
    assert_eq!(org["id"], "acme");
    assert_eq!(org["role"], "admin");

    let (status, body) = get_as(&fleet, "/api/v1/org/members", &alice).await;
    assert_eq!(status, 200, "{body}");
    let members = parse(&body);
    let ids: Vec<&str> = members
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["user_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["alice", "bob"]);
    assert!(!body.contains("mallory"), "another org's member leaked: {body}");
    // A member with no GitHub identity has no login to show, and it is not
    // defaulted to the id.
    assert!(members[0]["login"].is_null(), "{body}");

    // A plain member sees the same thing: membership suffices for both.
    let bob_view = get_as(&fleet, "/api/v1/org/members", &bob).await;
    assert_eq!(bob_view.0, 200);
    assert_eq!(parse(&bob_view.1), members);
}

/// `GET /api/v1/nodes` is the new surface: a machine with no boards is still a
/// node, which `ctl list` cannot say.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nodes_lists_machines_including_ones_offering_nothing() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    let org = OrgId("acme".to_owned());
    // Registered before the board, so the row carries a node-local `name`.
    // `OrgDb::ensure_node` — the inventory-report path `seed_board` uses —
    // writes the *full* node id into `name`, which this listing faithfully
    // reports; see `OrgDb::list_nodes`. Registering first is what a real node
    // does, and it takes the `ON CONFLICT` branch that leaves `name` alone.
    fleet.seed_node("acme", "rpi-1").await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    // A second node with no boards at all.
    fleet.seed_node("acme", "rpi-2").await;

    let (status, body) = get_as(&fleet, "/api/v1/nodes", &alice).await;
    assert_eq!(status, 200, "{body}");
    let nodes = parse(&body);
    let rows = nodes.as_array().unwrap();
    assert_eq!(rows.len(), 2, "{body}");

    let by_name = |name: &str| {
        rows.iter()
            .find(|n| n["name"] == name)
            .unwrap_or_else(|| panic!("no node {name} in {body}"))
    };
    assert_eq!(by_name("rpi-1")["boards"], serde_json::json!(["dk-3"]));
    assert_eq!(by_name("rpi-2")["boards"], serde_json::json!([]));
    // Neither is connected: the flag comes from the live registry, and these
    // rows were seeded straight into the database.
    assert_eq!(by_name("rpi-1")["online"], false);
    assert!(by_name("rpi-1")["adopt"].is_string());
}

/// `GET /api/v1/boards` and `/api/v1/leases` need a non-empty `Access` — the
/// same fence `ctl list` and `ctl who` use, because they call the same cores.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boards_and_leases_need_access_and_render_the_same_inventory() {
    let fleet = TestCoordinator::start().await;
    let org = OrgId("acme".to_owned());
    let alice = fleet.seed_session("acme", "alice", Role::Member).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;

    let (status, body) = get_as(&fleet, "/api/v1/boards", &alice).await;
    assert_eq!(status, 200, "{body}");
    let boards = parse(&body);
    assert_eq!(boards.as_array().unwrap().len(), 1, "{body}");
    let board = &boards[0];
    // A BoardRef is four segments, so the flattened key is what a body field
    // would carry; the parts stay available for display.
    assert_eq!(board["board"]["key"], "acme/acme/rpi-1/dk-3");
    assert_eq!(board["board"]["name"], "dk-3");
    assert_eq!(board["board"]["node"], "acme/rpi-1");
    assert_eq!(board["availability"], "available");
    assert_eq!(board["power"], "none");
    assert!(board["holder"].is_null());

    let (status, body) = get_as(&fleet, "/api/v1/leases", &alice).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body).as_array().unwrap().len(), 0, "{body}");

    // A subject with no membership anywhere and no grant reaches no board, and
    // that is the flat refusal, not an empty list: an empty list would say
    // "your org has no boards", which is a different fact.
    let nobody = fleet.seed_session("acme", "carol", Role::Member).await;
    sqlx::query("DELETE FROM member WHERE user_id = 'carol'")
        .execute(fleet.db().pool_for_test())
        .await
        .unwrap();
    for path in ["/api/v1/boards", "/api/v1/leases"] {
        let (status, body) = get_as(&fleet, path, &nobody).await;
        assert_eq!(status, 403, "{path}: {body}");
        assert!(body.contains("forbidden"), "{path}: {body}");
    }
}

/// `GET /api/v1/audit` is **admin-only**, with two independent fences: the role
/// check inside `logs_core`, and `OrgDb` scoping on the rows themselves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audit_is_admin_only_and_filters_by_board() {
    let fleet = TestCoordinator::start().await;
    let org = OrgId("acme".to_owned());
    let admin = fleet.seed_session("acme", "alice", Role::Admin).await;
    let member = fleet.seed_session("acme", "bob", Role::Member).await;

    fleet
        .db()
        .scoped(org.clone())
        .append_audit(&fleet_coordinator::state::AuditEntry {
            ts: 100,
            subject: Some("acme/user:alice"),
            action: "board.power-cycle",
            node: Some("acme/rpi-1"),
            board: Some("dk-3"),
            lease: None,
            detail: Some("operator request"),
        })
        .await
        .unwrap();
    fleet
        .db()
        .scoped(org)
        .append_audit(&fleet_coordinator::state::AuditEntry {
            ts: 101,
            subject: Some("acme/user:alice"),
            action: "grant.create",
            node: None,
            board: Some("other-board"),
            lease: None,
            detail: None,
        })
        .await
        .unwrap();

    let (status, body) = get_as(&fleet, "/api/v1/audit", &member).await;
    assert_eq!(status, 403, "a member must not read the audit log: {body}");

    let (status, body) = get_as(&fleet, "/api/v1/audit", &admin).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body).as_array().unwrap().len(), 2, "{body}");

    let (status, body) = get_as(&fleet, "/api/v1/audit?board=dk-3", &admin).await;
    assert_eq!(status, 200, "{body}");
    let lines = parse(&body);
    assert_eq!(lines.as_array().unwrap().len(), 1, "{body}");
    assert_eq!(lines[0]["action"], "board.power-cycle");
    assert_eq!(lines[0]["board"], "dk-3");

    // A board nobody logged against is an empty list, not an error: the filter
    // is over this org's own rows either way.
    let (status, body) = get_as(&fleet, "/api/v1/audit?board=absent", &admin).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body).as_array().unwrap().len(), 0, "{body}");
}

/// **Cross-tenancy.** Org A's session must see nothing of org B through any
/// route, and must get the response an absent object would produce — a
/// different answer for "exists but not yours" would make the API an
/// org-enumeration oracle (`docs/web-ui.md` §4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_orgs_session_sees_nothing_of_another() {
    let fleet = TestCoordinator::start().await;
    let org_a = OrgId("acme".to_owned());
    let org_b = OrgId("globex".to_owned());

    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;
    let _mallory = fleet.seed_session("globex", "mallory", Role::Admin).await;

    // Org B has a node, a board and an audit row; org A has nothing at all.
    fleet.seed_board(&org_b, "rpi-b", "dk-b", &["nrf52"]).await;
    fleet
        .db()
        .scoped(org_b.clone())
        .append_audit(&fleet_coordinator::state::AuditEntry {
            ts: 100,
            subject: Some("globex/user:mallory"),
            action: "board.power-cycle",
            node: Some("globex/rpi-b"),
            board: Some("dk-b"),
            lease: None,
            detail: Some("secret"),
        })
        .await
        .unwrap();
    // Org A needs one board of its own, or `boards`/`leases` would refuse for
    // the *empty-Access* reason and prove nothing about scoping.
    fleet.seed_board(&org_a, "rpi-a", "dk-a", &[]).await;

    for path in [
        "/api/v1/nodes",
        "/api/v1/boards",
        "/api/v1/leases",
        "/api/v1/org/members",
        "/api/v1/audit",
    ] {
        let (status, body) = get_as(&fleet, path, &alice).await;
        assert_eq!(status, 200, "{path}: {body}");
        for leak in ["globex", "rpi-b", "dk-b", "mallory", "secret"] {
            assert!(!body.contains(leak), "{path} leaked `{leak}`: {body}");
        }
    }

    // Naming org B's board explicitly gets the same answer an absent board
    // does: an empty list, not a 403 and not a 404.
    let (status, body) = get_as(&fleet, "/api/v1/audit?board=dk-b", &alice).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body).as_array().unwrap().len(), 0, "{body}");
    let (_, absent) = get_as(&fleet, "/api/v1/audit?board=no-such-board", &alice).await;
    assert_eq!(
        body, absent,
        "a cross-org board must be indistinguishable from an absent one"
    );
}

/// **No capability token, and no bearer of any kind, in any response body.**
/// `docs/web-ui.md` §5 asks for this as a test over the response types rather
/// than as review vigilance, because the cost of getting it wrong is an XSS
/// that walks away with a credential which can power-cycle hardware.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_response_body_carries_a_credential() {
    let fleet = TestCoordinator::start().await;
    let org = OrgId("acme".to_owned());
    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    // Seed the credentials whose *hashes* live in tables this surface reads
    // near, so a handler that widened a query would show up here.
    let _node_token = fleet.seed_node("acme", "rpi-2").await;
    let _auth_key = fleet.seed_auth_key("acme", &[], true, None).await;

    for path in READ_ROUTES.iter().chain(["/api/v1/audit"].iter()) {
        let (status, body) = get_as(&fleet, path, &alice).await;
        assert_eq!(status, 200, "{path}: {body}");
        for prefix in ["prfs1_", "prfn1_", "prffk1_", "prfnd1_", "prfw1_"] {
            assert!(
                !body.contains(prefix),
                "{path} returned a `{prefix}` credential: {body}"
            );
        }
        // The session token the caller itself authenticated with must not come
        // back either: `GET /api/v1/session` is where that would be tempting.
        assert!(!body.contains(&alice), "{path} echoed the caller's token");
    }
}

/// A node token and a workload token are valid credentials, and neither has
/// any business on the browser API. Saying so explicitly beats relying on the
/// absence of a membership row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_session_token_reaches_the_browser_api() {
    let fleet = TestCoordinator::start().await;
    let (node_token, _id) = fleet.seed_node("acme", "rpi-1").await;
    let workload = fleet.seed_workload_token("acme/repo", i64::MAX).await;

    for token in [node_token, workload] {
        for path in READ_ROUTES {
            let (status, _, body) = fleet
                .http_full(
                    "GET",
                    path,
                    &[("authorization", &format!("Bearer {token}"))],
                    None,
                )
                .await;
            assert_eq!(status, 403, "{path} accepted a non-session token: {body}");
        }
    }
}

/// Both carriers resolve the same credential to the same caller, which is the
/// claim `docs/web-ui.md` D1 makes about the cookie: "a second carrier of the
/// same credential, not a second credential kind".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_cookie_and_the_header_answer_identically() {
    let fleet = TestCoordinator::start().await;
    let org = OrgId("acme".to_owned());
    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;

    for path in READ_ROUTES {
        let (cookie_status, cookie_body) = get_as(&fleet, path, &alice).await;
        let (header_status, _, header_body) = fleet
            .http_full(
                "GET",
                path,
                &[("authorization", &format!("Bearer {alice}"))],
                None,
            )
            .await;
        assert_eq!(cookie_status, header_status, "{path}");
        assert_eq!(cookie_body, header_body, "{path}");
    }
}
