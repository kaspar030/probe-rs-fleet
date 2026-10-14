//! The read-only `/api/v1` surface (`docs/web-ui.md` §3, phase 1a).
//!
//! Per endpoint: unauthenticated is rejected; a wrong-org subject is rejected
//! **exactly as an absent object would be**; the member/admin split holds; and
//! the happy path returns what the CLI's equivalent verb returns.
//!
//! A session is not bound to an org: every request acts in the caller's
//! personal org unless it names another with `?org=<name-or-id>`, and
//! membership there is checked per request. Naming an org the caller is not a
//! member of — or one that does not exist — is the same flat `403`.
//!
//! Two properties are asserted once for the whole surface rather than per
//! route, because they are properties *of* the surface:
//!
//! * **cross-tenancy** — org A's session sees nothing of org B through any
//!   route, and gets the response an absent object would produce;
//! * **no credential ever reaches the browser** — no response body contains a
//!   token prefix (`prfs1_` / `prfr1_` / `prfk1_` / `prfw1_` / `prfd1_` /
//!   `prfn1_`). `docs/web-ui.md` §5 asks for exactly this, "enforced by a test
//!   over the API response types, not by review vigilance".

mod common;

use common::TestCoordinator;
use probefleet_coordinator::FleetRole;

/// Every read-only route, for the assertions that hold across all of them.
const READ_ROUTES: [&str; 6] = [
    "/api/v1/session",
    "/api/v1/org",
    "/api/v1/org/members",
    "/api/v1/nodes",
    "/api/v1/boards",
    "/api/v1/leases",
];

/// Every token prefix the coordinator's format can mint.
const TOKEN_PREFIXES: [&str; 6] = ["prfs1_", "prfr1_", "prfk1_", "prfw1_", "prfd1_", "prfn1_"];

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

/// `path` with `?org=<org>` (or `&org=`) appended.
fn in_org(path: &str, org: &str) -> String {
    let sep = if path.contains('?') { '&' } else { '?' };
    format!("{path}{sep}org={org}")
}

fn parse(body: &str) -> serde_json::Value {
    serde_json::from_str(body).unwrap_or_else(|e| panic!("not JSON ({e}): {body}"))
}

/// Remove `user` from `org` through forgs' store.
async fn remove_member(
    fleet: &TestCoordinator,
    org: &probefleet_proto::ids::OrgId,
    user: forgs::UserId,
) {
    let ns = probefleet_coordinator::subject::ns_of(org).unwrap();
    assert!(fleet
        .db()
        .forgs()
        .scoped(ns)
        .remove_member(&forgs::SubjectKey::user(user))
        .await
        .unwrap());
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
/// unknown one: forgs' `authenticate_request` decides what "expired" means
/// and there is no second opinion on this surface.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_session_is_refused_like_an_unknown_one() {
    let fleet = TestCoordinator::start().await;
    let expired = fleet.seed_expired_session("alice").await;
    let unknown = fleet
        .auth()
        .format()
        .mint(forgs::TokenKind::Session)
        .to_secret_string();
    for path in READ_ROUTES {
        let (status, body) = get_as(&fleet, path, &expired).await;
        assert_eq!(status, 401, "{path}: {body}");
        assert!(body.contains("unauthorized"), "{path}: {body}");
        assert_eq!(
            get_as(&fleet, path, &unknown).await,
            (status, body),
            "{path}"
        );
    }
}

/// `GET /api/v1/session` answers for **any** session, including one whose
/// membership was revoked: a UI that cannot learn "you are in no org" has
/// nothing to render but a blank 403.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_answers_even_without_membership() {
    let fleet = TestCoordinator::start().await;
    let (token, org, user_id) = fleet.seed_user("kaspar").await;

    let (status, body) = get_as(&fleet, "/api/v1/session", &token).await;
    assert_eq!(status, 200, "{body}");
    let me = parse(&body);
    assert_eq!(me["user_id"], user_id.to_string());
    assert_eq!(me["username"], "kaspar");
    // Signup makes you the admin of your own personal org, which is where a
    // request that names no org acts.
    assert_eq!(me["org"]["id"], org.0);
    assert_eq!(me["org"]["role"], "admin");
    assert_eq!(me["memberships"].as_array().unwrap().len(), 1, "{body}");
    assert!(me["expires"].is_number());

    // Revoke the membership; the session still resolves, with no org.
    remove_member(&fleet, &org, user_id).await;

    let (status, body) = get_as(&fleet, "/api/v1/session", &token).await;
    assert_eq!(status, 200, "{body}");
    let me = parse(&body);
    assert!(me["org"].is_null(), "{body}");
    assert_eq!(me["memberships"], serde_json::json!([]), "{body}");

    // But everything that needs membership is now closed.
    for path in ["/api/v1/org", "/api/v1/org/members", "/api/v1/nodes"] {
        let (status, body) = get_as(&fleet, path, &token).await;
        assert_eq!(status, 403, "{path}: {body}");
    }
}

/// `GET /api/v1/org` and `/api/v1/org/members` are member-gated, and the
/// listing is the org's own. Naming an org one is not a member of, or one
/// that does not exist, is the same `403`: the routes are not an
/// org-existence oracle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_and_members_are_member_gated_and_org_scoped() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let bob = fleet.seed_session("acme", "bob", FleetRole::Member).await;
    let _mallory = fleet
        .seed_session("other", "mallory", FleetRole::Admin)
        .await;
    let acme = fleet.org("acme").await;
    let alice_id = fleet.user("alice").await;
    let bob_id = fleet.user("bob").await;

    let (status, body) = get_as(&fleet, "/api/v1/org?org=acme", &alice).await;
    assert_eq!(status, 200, "{body}");
    let org = parse(&body);
    assert_eq!(org["id"], acme.0);
    assert_eq!(org["name"], "acme");
    assert_eq!(org["role"], "admin");

    // The id names the same org as the name does.
    let (_, by_id) = get_as(&fleet, &format!("/api/v1/org?org={}", acme.0), &alice).await;
    assert_eq!(parse(&by_id), org);

    // With no `?org=`, the personal org.
    let (status, body) = get_as(&fleet, "/api/v1/org", &alice).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body)["id"], fleet.personal_org("alice").await.0);

    let (status, body) = get_as(&fleet, "/api/v1/org/members?org=acme", &alice).await;
    assert_eq!(status, 200, "{body}");
    let members = parse(&body);
    let mut ids: Vec<&str> = members
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["user_id"].as_str().unwrap())
        .collect();
    ids.sort_unstable();
    let mut expected = [alice_id.to_string(), bob_id.to_string()];
    expected.sort_unstable();
    assert_eq!(ids, expected);
    assert!(
        !body.contains("mallory"),
        "another org's member leaked: {body}"
    );
    let alice_row = members
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["user_id"] == alice_id.to_string())
        .unwrap();
    assert_eq!(alice_row["username"], "alice");
    assert_eq!(alice_row["role"], "admin");

    // A plain member sees the same thing: membership suffices for both.
    let bob_view = get_as(&fleet, "/api/v1/org/members?org=acme", &bob).await;
    assert_eq!(bob_view.0, 200);
    assert_eq!(parse(&bob_view.1), members);

    // A non-member org and an absent one: one answer.
    for path in ["/api/v1/org", "/api/v1/org/members"] {
        let other = get_as(&fleet, &in_org(path, "other"), &alice).await;
        let absent = get_as(&fleet, &in_org(path, "no-such-org"), &alice).await;
        assert_eq!(other.0, 403, "{path}: {}", other.1);
        assert_eq!(other, absent, "{path}");
    }
}

/// `GET /api/v1/nodes` is the new surface: a machine with no boards is still a
/// node, which `ctl list` cannot say.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nodes_lists_machines_including_ones_offering_nothing() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    let org = fleet.org("acme").await;
    // `seed_node` registers before `seed_board` reports, as a real node does.
    fleet.seed_node("acme", "rpi-1").await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    // A second node with no boards at all.
    fleet.seed_node("acme", "rpi-2").await;

    let (status, body) = get_as(&fleet, "/api/v1/nodes?org=acme", &alice).await;
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

    // The personal org has none of them.
    let (status, body) = get_as(&fleet, "/api/v1/nodes", &alice).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body), serde_json::json!([]));
}

/// `GET /api/v1/boards` and `/api/v1/leases` need a non-empty `Access` — the
/// same fence `ctl list` and `ctl who` use, because they call the same cores.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boards_and_leases_need_access_and_render_the_same_inventory() {
    let fleet = TestCoordinator::start().await;
    let org = fleet.org("acme").await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Member).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;

    let (status, body) = get_as(&fleet, "/api/v1/boards?org=acme", &alice).await;
    assert_eq!(status, 200, "{body}");
    let boards = parse(&body);
    assert_eq!(boards.as_array().unwrap().len(), 1, "{body}");
    let board = &boards[0];
    // A BoardRef is four segments, so the flattened key is what a body field
    // would carry; the parts stay available for display.
    assert_eq!(board["board"]["key"], format!("{0}/{0}/rpi-1/dk-3", org.0));
    assert_eq!(board["board"]["name"], "dk-3");
    assert_eq!(board["board"]["node"], format!("{}/rpi-1", org.0));
    assert_eq!(board["availability"], "available");
    assert_eq!(board["power"], "none");
    assert!(board["holder"].is_null());

    let (status, body) = get_as(&fleet, "/api/v1/leases?org=acme", &alice).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body).as_array().unwrap().len(), 0, "{body}");

    // A subject with no membership anywhere and no grant reaches no board, and
    // that is the flat refusal, not an empty list: an empty list would say
    // "your org has no boards", which is a different fact.
    let (nobody, personal, carol) = fleet.seed_user("carol").await;
    remove_member(&fleet, &personal, carol).await;
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
    let org = fleet.org("acme").await;
    let admin = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let member = fleet.seed_session("acme", "bob", FleetRole::Member).await;
    let alice_key =
        probefleet_coordinator::subject::user_key(fleet.user("alice").await).to_string();
    let node = format!("{}/rpi-1", org.0);

    fleet
        .db()
        .scoped(org.clone())
        .append_audit(&probefleet_coordinator::state::AuditEntry {
            ts: 100,
            subject: Some(&alice_key),
            action: "board.power-cycle",
            node: Some(&node),
            board: Some("dk-3"),
            lease: None,
            detail: Some("operator request"),
        })
        .await
        .unwrap();
    fleet
        .db()
        .scoped(org.clone())
        .append_audit(&probefleet_coordinator::state::AuditEntry {
            ts: 101,
            subject: Some(&alice_key),
            action: "lease.release",
            node: None,
            board: Some("other-board"),
            lease: None,
            detail: None,
        })
        .await
        .unwrap();
    // The rows are scoped by the org's forgs namespace id.
    let rows = fleet.audit_rows().await;
    assert!(rows.iter().all(|(ns, _, _)| *ns == org.0), "{rows:?}");

    let (status, body) = get_as(&fleet, "/api/v1/audit?org=acme", &member).await;
    assert_eq!(status, 403, "a member must not read the audit log: {body}");

    let (status, body) = get_as(&fleet, "/api/v1/audit?org=acme", &admin).await;
    assert_eq!(status, 200, "{body}");
    let lines = parse(&body);
    let actions: Vec<&str> = lines
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"board.power-cycle"), "{body}");
    assert!(actions.contains(&"lease.release"), "{body}");

    let (status, body) = get_as(&fleet, "/api/v1/audit?org=acme&board=dk-3", &admin).await;
    assert_eq!(status, 200, "{body}");
    let lines = parse(&body);
    assert_eq!(lines.as_array().unwrap().len(), 1, "{body}");
    assert_eq!(lines[0]["action"], "board.power-cycle");
    assert_eq!(lines[0]["board"], "dk-3");

    // A board nobody logged against is an empty list, not an error: the filter
    // is over this org's own rows either way.
    let (status, body) = get_as(&fleet, "/api/v1/audit?org=acme&board=absent", &admin).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body).as_array().unwrap().len(), 0, "{body}");
}

/// A malformed query string must be an ordinary answer, not a dropped
/// connection.
///
/// The query is parsed **before** the endpoint's admin check runs, so a
/// decoder that panicked would be reachable by any authenticated session — and
/// `http`'s scanner passes high bytes through, so `%€` really does arrive here.
/// The unit tests pin the decoder; this pins that the route survives the real
/// path, which is the part a reader of either alone would have to assume.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_query_is_answered_not_a_dropped_connection() {
    let fleet = TestCoordinator::start().await;
    // Both act in their personal orgs (no `?org=` survives these queries):
    // alice is admin there; bob is only a member of acme's…
    let (admin, _, _) = fleet.seed_user("alice").await;
    let (member, personal, bob) = fleet.seed_user("bob").await;
    // …and demoted in his own, so the role fence is what answers.
    fleet
        .db()
        .set_member(&personal, bob, FleetRole::Member, fleet.now())
        .await
        .unwrap();

    for query in [
        "?board=%\u{20ac}x", // `%` before a multi-byte char: the panic case
        "?%\u{20ac}x=1",     // the same shape in a key, which is decoded too
        "?board=%",
        "?board=%4",
        "?board=%zz",
        "?board=%ff", // decodes to invalid UTF-8, repaired not refused
        "?board=",
        "?",
    ] {
        let (status, body) = get_as(&fleet, &format!("/api/v1/audit{query}"), &admin).await;
        assert_eq!(status, 200, "{query}: {body}");

        // And a non-admin still gets the role refusal rather than a panic:
        // the parse happens first, so this is the case that would have been
        // reachable without any privilege at all.
        let (status, body) = get_as(&fleet, &format!("/api/v1/audit{query}"), &member).await;
        assert_eq!(status, 403, "{query}: {body}");
    }
    // A malformed `org` is the flat refusal, not a panic either.
    for query in ["?org=%\u{20ac}x", "?org=%", "?org=%ff", "?org="] {
        let (status, body) = get_as(&fleet, &format!("/api/v1/org{query}"), &admin).await;
        assert!(status == 200 || status == 403, "{query}: {status} {body}");
    }
}

/// **Cross-tenancy.** Org A's session must see nothing of org B through any
/// route, and must get the response an absent object would produce — a
/// different answer for "exists but not yours" would make the API an
/// org-enumeration oracle (`docs/web-ui.md` §4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_orgs_session_sees_nothing_of_another() {
    let fleet = TestCoordinator::start().await;
    let org_a = fleet.org("acme").await;
    let org_b = fleet.org("globex").await;

    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let _mallory = fleet
        .seed_session("globex", "mallory", FleetRole::Admin)
        .await;
    let mallory_key =
        probefleet_coordinator::subject::user_key(fleet.user("mallory").await).to_string();
    let node_b = format!("{}/rpi-b", org_b.0);

    // Org B has a node, a board and an audit row; org A has nothing at all.
    fleet.seed_board(&org_b, "rpi-b", "dk-b", &["nrf52"]).await;
    fleet
        .db()
        .scoped(org_b.clone())
        .append_audit(&probefleet_coordinator::state::AuditEntry {
            ts: 100,
            subject: Some(&mallory_key),
            action: "board.power-cycle",
            node: Some(&node_b),
            board: Some("dk-b"),
            lease: None,
            detail: Some("secret"),
        })
        .await
        .unwrap();
    // Org A needs one board of its own, or `boards`/`leases` would refuse for
    // the *empty-Access* reason and prove nothing about scoping.
    fleet.seed_board(&org_a, "rpi-a", "dk-a", &[]).await;

    let mallory_id = fleet.user("mallory").await.to_string();
    for path in [
        "/api/v1/nodes",
        "/api/v1/boards",
        "/api/v1/leases",
        "/api/v1/org/members",
        "/api/v1/audit",
    ] {
        let (status, body) = get_as(&fleet, &in_org(path, "acme"), &alice).await;
        assert_eq!(status, 200, "{path}: {body}");
        for leak in [
            "globex",
            "rpi-b",
            "dk-b",
            "mallory",
            "secret",
            org_b.0.as_str(),
            mallory_id.as_str(),
        ] {
            assert!(!body.contains(leak), "{path} leaked `{leak}`: {body}");
        }
    }

    // Naming org B's board explicitly gets the same answer an absent board
    // does: an empty list, not a 403 and not a 404.
    let (status, body) = get_as(&fleet, "/api/v1/audit?org=acme&board=dk-b", &alice).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(parse(&body).as_array().unwrap().len(), 0, "{body}");
    let (_, absent) = get_as(&fleet, "/api/v1/audit?org=acme&board=no-such-board", &alice).await;
    assert_eq!(
        body, absent,
        "a cross-org board must be indistinguishable from an absent one"
    );

    // Naming org B itself (by name or id) is the flat refusal an unknown org
    // gets, on every route.
    for path in READ_ROUTES.iter().skip(1).chain(["/api/v1/audit"].iter()) {
        let by_name = get_as(&fleet, &in_org(path, "globex"), &alice).await;
        let by_id = get_as(&fleet, &in_org(path, &org_b.0), &alice).await;
        let absent = get_as(&fleet, &in_org(path, "no-such-org"), &alice).await;
        assert_eq!(by_name.0, 403, "{path}: {}", by_name.1);
        assert_eq!(by_name, absent, "{path}");
        assert_eq!(by_id, absent, "{path}");
    }
}

/// **No capability token, and no bearer of any kind, in any response body.**
/// `docs/web-ui.md` §5 asks for this as a test over the response types rather
/// than as review vigilance, because the cost of getting it wrong is an XSS
/// that walks away with a credential which can power-cycle hardware.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_response_body_carries_a_credential() {
    let fleet = TestCoordinator::start().await;
    let org = fleet.org("acme").await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;
    // Seed the credentials whose *hashes* live in tables this surface reads
    // near, so a handler that widened a query would show up here.
    let (node_token, _) = fleet.seed_node("acme", "rpi-2").await;
    let auth_key = fleet.seed_auth_key("acme", &[], true, None).await;
    let ci_key = fleet
        .seed_ci_auth_key("acme", &["nrf52".into()], None)
        .await;
    let refresh = fleet.seed_refresh_token("alice").await;
    let secrets = [alice.clone(), node_token, auth_key, ci_key, refresh];

    for route in READ_ROUTES.iter().chain(["/api/v1/audit"].iter()) {
        for path in [route.to_string(), in_org(route, "acme")] {
            let (status, body) = get_as(&fleet, &path, &alice).await;
            assert_eq!(status, 200, "{path}: {body}");
            for prefix in TOKEN_PREFIXES {
                assert!(
                    !body.contains(prefix),
                    "{path} returned a `{prefix}` credential: {body}"
                );
            }
            // Nor any seeded secret, whole: `GET /api/v1/session` is where
            // echoing the caller's own would be tempting.
            for secret in &secrets {
                assert!(!body.contains(secret.as_str()), "{path} echoed a secret");
            }
        }
    }
}

/// A node token and a workload token are valid credentials, and neither has
/// any business on the browser API. Saying so explicitly beats relying on the
/// absence of a membership row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_session_token_reaches_the_browser_api() {
    let fleet = TestCoordinator::start().await;
    let (node_token, _id) = fleet.seed_node("acme", "rpi-1").await;
    let workload = fleet
        .seed_workload_token("acme/repo", fleet.now() + 3600)
        .await;
    let refresh = fleet.seed_refresh_token("alice").await;
    let api_key = fleet.seed_auth_key("acme", &[], false, None).await;

    for token in [node_token, workload, refresh, api_key] {
        for path in READ_ROUTES {
            let (status, _, body) = fleet
                .http_full(
                    "GET",
                    path,
                    &[("authorization", &format!("Bearer {token}"))],
                    None,
                )
                .await;
            assert!(
                status == 401 || status == 403,
                "{path} accepted a non-session token: {status} {body}"
            );
        }
    }
}

/// Both carriers resolve the same credential to the same caller, which is the
/// claim `docs/web-ui.md` D1 makes about the cookie: "a second carrier of the
/// same credential, not a second credential kind".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_cookie_and_the_header_answer_identically() {
    let fleet = TestCoordinator::start().await;
    let org = fleet.org("acme").await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    fleet.seed_board(&org, "rpi-1", "dk-3", &["nrf52"]).await;

    for route in READ_ROUTES {
        for path in [route.to_owned(), in_org(route, "acme")] {
            let (cookie_status, cookie_body) = get_as(&fleet, &path, &alice).await;
            let (header_status, _, header_body) = fleet
                .http_full(
                    "GET",
                    &path,
                    &[("authorization", &format!("Bearer {alice}"))],
                    None,
                )
                .await;
            assert_eq!(cookie_status, header_status, "{path}");
            assert_eq!(cookie_body, header_body, "{path}");
        }
    }
}
