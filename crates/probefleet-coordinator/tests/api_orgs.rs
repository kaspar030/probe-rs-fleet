//! Self-service team orgs and membership over `/api/v1` (`docs/web-ui.md`
//! "Orgs and membership"):
//!
//! * `POST /api/v1/orgs` — any logged-in user creates a team org and becomes
//!   its admin, subject to `allow_org_creation` / `max_orgs_per_user`; the
//!   name must be canonical and free (no org, user or tombstone holds it);
//!   audited as `org.create`;
//! * `POST /api/v1/org/members` / `DELETE /api/v1/org/members/{username}` —
//!   admin-only add / re-role / remove, through forgs' `members::{set,
//!   remove}`, with the last-admin guard; a member may list, not mutate; a
//!   non-member's `?org=` is refused before anything is touched;
//! * every one of them needs the CSRF header when cookie-authenticated.

mod common;

use common::TestCoordinator;

use probefleet_coordinator::FleetRole;

/// Call a route as a browser would: session cookie plus the CSRF header.
async fn as_browser(
    fleet: &TestCoordinator,
    method: &str,
    path: &str,
    token: &str,
    body: Option<serde_json::Value>,
) -> (u16, String) {
    let (cookie, csrf) = fleet.browser_session(token);
    let (status, _, body) = fleet
        .http_full(
            method,
            path,
            &[("cookie", &cookie), ("x-fleet-csrf", &csrf)],
            body.map(|b| b.to_string()),
        )
        .await;
    (status, body)
}

async fn create(fleet: &TestCoordinator, token: &str, name: &str) -> (u16, serde_json::Value) {
    let (status, body) = as_browser(
        fleet,
        "POST",
        "/api/v1/orgs",
        token,
        Some(serde_json::json!({ "name": name })),
    )
    .await;
    (status, serde_json::from_str(&body).unwrap_or_default())
}

async fn set_member(
    fleet: &TestCoordinator,
    token: &str,
    org: &str,
    username: &str,
    role: &str,
) -> (u16, String) {
    as_browser(
        fleet,
        "POST",
        &format!("/api/v1/org/members?org={org}"),
        token,
        Some(serde_json::json!({ "username": username, "role": role })),
    )
    .await
}

async fn remove_member(
    fleet: &TestCoordinator,
    token: &str,
    org: &str,
    username: &str,
) -> (u16, String) {
    as_browser(
        fleet,
        "DELETE",
        &format!("/api/v1/org/members/{username}?org={org}"),
        token,
        None,
    )
    .await
}

/// `(username, role)` pairs of `org`, as `token` sees them.
async fn members(fleet: &TestCoordinator, token: &str, org: &str) -> Vec<(String, String)> {
    let (status, body) = as_browser(
        fleet,
        "GET",
        &format!("/api/v1/org/members?org={org}"),
        token,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let rows: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    let mut out: Vec<(String, String)> = rows
        .iter()
        .map(|r| {
            (
                r["username"].as_str().unwrap().to_owned(),
                r["role"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    out.sort();
    out
}

fn error_code(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body).unwrap()["error"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

async fn session_json(fleet: &TestCoordinator, token: &str) -> serde_json::Value {
    let (status, body) = as_browser(fleet, "GET", "/api/v1/session", token, None).await;
    assert_eq!(status, 200, "{body}");
    serde_json::from_str(&body).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_user_creates_an_org_and_becomes_its_admin() {
    let fleet = TestCoordinator::start().await;
    let (alice, _, alice_id) = fleet.seed_user("alice").await;

    assert_eq!(session_json(&fleet, &alice).await["can_create_orgs"], true);

    let (status, created) = create(&fleet, &alice, "acme").await;
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["name"], "acme");
    assert_eq!(created["role"], "admin");
    let id = created["id"].as_str().unwrap().to_owned();

    let org = fleet.db().resolve_org("acme").await.unwrap().unwrap();
    assert_eq!(org.0, id);
    assert_eq!(
        fleet.db().role_of(&org, alice_id).await.unwrap(),
        Some(FleetRole::Admin)
    );

    // The membership shows up in the session, by name and role.
    let session = session_json(&fleet, &alice).await;
    let memberships = session["memberships"].as_array().unwrap();
    assert!(
        memberships
            .iter()
            .any(|m| m["id"] == id.as_str() && m["name"] == "acme" && m["role"] == "admin"),
        "{session}"
    );

    // Audited in the new org, visible to its admin.
    assert!(fleet
        .forgs_audit_actions()
        .await
        .contains(&"org.create".to_owned()));
    let (status, audit) = as_browser(&fleet, "GET", "/api/v1/audit?org=acme", &alice, None).await;
    assert_eq!(status, 200, "{audit}");
    assert!(audit.contains("org.create"), "{audit}");

    assert_eq!(
        members(&fleet, &alice, "acme").await,
        vec![("alice".into(), "admin".into())]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_org_names_are_invalid_name() {
    let fleet = TestCoordinator::start().await;
    let (alice, _, _) = fleet.seed_user("alice").await;
    for bad in [
        "Acme",
        "a/b",
        "-x",
        "x-",
        "a--b",
        "api",
        "",
        "   ",
        "with space",
        "ünï",
    ] {
        let (status, body) = create(&fleet, &alice, bad).await;
        assert_eq!(status, 400, "{bad:?}: {body}");
        assert_eq!(body["error"], "invalid_name", "{bad:?}");
    }
    // A malformed body is a plain invalid_request.
    let (status, body) = as_browser(
        &fleet,
        "POST",
        "/api/v1/orgs",
        &alice,
        Some(serde_json::json!({ "nmae": "acme" })),
    )
    .await;
    assert_eq!(
        (status, error_code(&body).as_str()),
        (400, "invalid_request")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn colliding_names_are_name_taken() {
    let fleet = TestCoordinator::start().await;
    let (alice, _, _) = fleet.seed_user("alice").await;
    fleet.user("bob").await;
    fleet.org("existing").await;
    assert_eq!(create(&fleet, &alice, "acme").await.0, 201);
    // Another org, a username (personal orgs share the root), the default
    // org, and the caller's own name.
    for taken in ["acme", "existing", "bob", "alice", "default"] {
        let (status, body) = create(&fleet, &alice, taken).await;
        assert_eq!(status, 409, "{taken}: {body}");
        assert_eq!(body["error"], "name_taken", "{taken}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creation_can_be_disabled() {
    let fleet = TestCoordinator::start_with(|c| c.allow_org_creation = false).await;
    let (alice, _, _) = fleet.seed_user("alice").await;
    assert_eq!(session_json(&fleet, &alice).await["can_create_orgs"], false);
    let (status, body) = create(&fleet, &alice, "acme").await;
    assert_eq!(
        (status, body["error"].as_str()),
        (403, Some("org_creation_disabled"))
    );
    assert!(fleet.db().resolve_org("acme").await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_per_user_cap_applies() {
    let fleet = TestCoordinator::start_with(|c| c.max_orgs_per_user = 2).await;
    let (alice, _, _) = fleet.seed_user("alice").await;
    let (bob, _, _) = fleet.seed_user("bob").await;
    // Memberships elsewhere and the personal org do not count.
    fleet.member("other", "alice", FleetRole::Admin).await;
    assert_eq!(create(&fleet, &alice, "one").await.0, 201);
    assert_eq!(session_json(&fleet, &alice).await["can_create_orgs"], true);
    assert_eq!(create(&fleet, &alice, "two").await.0, 201);
    assert_eq!(session_json(&fleet, &alice).await["can_create_orgs"], false);
    let (status, body) = create(&fleet, &alice, "three").await;
    assert_eq!(
        (status, body["error"].as_str()),
        (403, Some("org_limit_reached"))
    );
    // The cap is per user.
    assert_eq!(create(&fleet, &bob, "three").await.0, 201);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutations_need_the_csrf_header() {
    let fleet = TestCoordinator::start().await;
    let (alice, _, _) = fleet.seed_user("alice").await;
    fleet.user("bob").await;
    assert_eq!(create(&fleet, &alice, "acme").await.0, 201);
    let (cookie, _) = fleet.browser_session(&alice);
    for (method, path, body) in [
        ("POST", "/api/v1/orgs", r#"{"name":"beta"}"#),
        (
            "POST",
            "/api/v1/org/members?org=acme",
            r#"{"username":"bob","role":"member"}"#,
        ),
        ("DELETE", "/api/v1/org/members/alice?org=acme", ""),
        ("POST", "/api/v1/org/rename?org=acme", r#"{"name":"acme2"}"#),
        ("DELETE", "/api/v1/org?org=acme", ""),
        ("POST", "/api/v1/org/delete?org=acme", ""),
    ] {
        let (status, _, response) = fleet
            .http_full(method, path, &[("cookie", &cookie)], Some(body.to_owned()))
            .await;
        assert_eq!(status, 403, "{method} {path}: {response}");
    }
    assert!(fleet.db().resolve_org("beta").await.unwrap().is_none());
    assert!(fleet.db().resolve_org("acme2").await.unwrap().is_none());
    assert_eq!(members(&fleet, &alice, "acme").await.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admins_add_re_role_and_remove_members() {
    let fleet = TestCoordinator::start().await;
    let (alice, _, _) = fleet.seed_user("alice").await;
    let (bob, _, _) = fleet.seed_user("bob").await;
    fleet.user("dave").await;
    assert_eq!(create(&fleet, &alice, "acme").await.0, 201);

    let (status, body) = set_member(&fleet, &alice, "acme", "bob", "member").await;
    assert_eq!(status, 204, "{body}");
    // bob may now list …
    assert_eq!(
        members(&fleet, &bob, "acme").await,
        vec![
            ("alice".into(), "admin".into()),
            ("bob".into(), "member".into())
        ]
    );
    // … but not mutate.
    let (status, body) = set_member(&fleet, &bob, "acme", "dave", "member").await;
    assert_eq!((status, error_code(&body).as_str()), (403, "forbidden"));
    let (status, body) = remove_member(&fleet, &bob, "acme", "alice").await;
    assert_eq!((status, error_code(&body).as_str()), (403, "forbidden"));
    let (status, _) = set_member(&fleet, &bob, "acme", "bob", "admin").await;
    assert_eq!(status, 403, "a member cannot promote themselves");

    // Promote bob, then demote alice: there is still an admin.
    assert_eq!(
        set_member(&fleet, &alice, "acme", "bob", "admin").await.0,
        204
    );
    assert_eq!(
        set_member(&fleet, &alice, "acme", "alice", "member")
            .await
            .0,
        204
    );
    assert_eq!(
        members(&fleet, &bob, "acme").await,
        vec![
            ("alice".into(), "member".into()),
            ("bob".into(), "admin".into())
        ]
    );
    // alice is no longer an admin.
    let (status, _) = remove_member(&fleet, &alice, "acme", "bob").await;
    assert_eq!(status, 403);
    // bob removes alice.
    assert_eq!(remove_member(&fleet, &bob, "acme", "alice").await.0, 204);
    assert_eq!(
        members(&fleet, &bob, "acme").await,
        vec![("bob".into(), "admin".into())]
    );
    // alice has lost the org entirely.
    let (status, _) = as_browser(&fleet, "GET", "/api/v1/org/members?org=acme", &alice, None).await;
    assert_eq!(status, 403);

    let actions = fleet.forgs_audit_actions().await;
    assert!(actions.contains(&"member.set".to_owned()), "{actions:?}");
    assert!(actions.contains(&"member.remove".to_owned()), "{actions:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_last_admin_cannot_be_removed_or_demoted() {
    let fleet = TestCoordinator::start().await;
    let (alice, _, _) = fleet.seed_user("alice").await;
    fleet.user("bob").await;
    assert_eq!(create(&fleet, &alice, "acme").await.0, 201);
    assert_eq!(
        set_member(&fleet, &alice, "acme", "bob", "member").await.0,
        204
    );

    let (status, body) = set_member(&fleet, &alice, "acme", "alice", "member").await;
    assert_eq!((status, error_code(&body).as_str()), (409, "last_admin"));
    let (status, body) = remove_member(&fleet, &alice, "acme", "alice").await;
    assert_eq!((status, error_code(&body).as_str()), (409, "last_admin"));
    assert_eq!(
        members(&fleet, &alice, "acme").await,
        vec![
            ("alice".into(), "admin".into()),
            ("bob".into(), "member".into())
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_users_bad_roles_and_cross_org_calls_are_refused() {
    let fleet = TestCoordinator::start().await;
    let (alice, _, _) = fleet.seed_user("alice").await;
    let (carol, _, _) = fleet.seed_user("carol").await;
    fleet.user("bob").await;
    assert_eq!(create(&fleet, &alice, "acme").await.0, 201);
    assert_eq!(create(&fleet, &carol, "other").await.0, 201);

    // Unknown user: 404 (usernames are public handles).
    let (status, body) = set_member(&fleet, &alice, "acme", "nobody", "member").await;
    assert_eq!((status, error_code(&body).as_str()), (404, "not_found"));
    // Removing a non-member: 404.
    let (status, _) = remove_member(&fleet, &alice, "acme", "bob").await;
    assert_eq!(status, 404);
    // A role outside the ladder: 400, before forgs.
    let (status, body) = set_member(&fleet, &alice, "acme", "bob", "owner").await;
    assert_eq!(
        (status, error_code(&body).as_str()),
        (400, "invalid_request")
    );

    // carol, an admin elsewhere, cannot touch acme's membership, nor list it.
    let (status, _) = set_member(&fleet, &carol, "acme", "carol", "admin").await;
    assert_eq!(status, 403);
    let (status, _) = remove_member(&fleet, &carol, "acme", "alice").await;
    assert_eq!(status, 403);
    let (status, _) = as_browser(&fleet, "GET", "/api/v1/org/members?org=acme", &carol, None).await;
    assert_eq!(status, 403);
    assert_eq!(
        members(&fleet, &alice, "acme").await,
        vec![("alice".into(), "admin".into())]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bearer_session_can_create_without_csrf() {
    // The CLI's path: a bearer is not ambient, so no CSRF header is needed.
    let fleet = TestCoordinator::start().await;
    let (alice, _, _) = fleet.seed_user("alice").await;
    let (status, body) = fleet
        .http_auth(
            "POST",
            "/api/v1/orgs",
            Some(&alice),
            Some(r#"{"name":"acme"}"#.to_owned()),
        )
        .await;
    assert_eq!(status, 201, "{body}");
}

async fn rename(fleet: &TestCoordinator, token: &str, org: &str, name: &str) -> (u16, String) {
    as_browser(
        fleet,
        "POST",
        &format!("/api/v1/org/rename?org={org}"),
        token,
        Some(serde_json::json!({ "name": name })),
    )
    .await
}

async fn delete_org(fleet: &TestCoordinator, token: &str, org: &str) -> (u16, String) {
    as_browser(
        fleet,
        "DELETE",
        &format!("/api/v1/org?org={org}"),
        token,
        None,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admins_rename_team_orgs() {
    let fleet = TestCoordinator::start().await;
    let (alice, _, _) = fleet.seed_user("alice").await;
    let (bob, _, _) = fleet.seed_user("bob").await;
    let (status, created) = create(&fleet, &alice, "acme").await;
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(
        set_member(&fleet, &alice, "acme", "bob", "member").await.0,
        204
    );
    fleet.org("other").await;

    // A member may not.
    let (status, body) = rename(&fleet, &bob, "acme", "acme2").await;
    assert_eq!((status, error_code(&body).as_str()), (403, "forbidden"));
    // Name refusals as for create.
    let (status, body) = rename(&fleet, &alice, "acme", "Acme2").await;
    assert_eq!((status, error_code(&body).as_str()), (400, "invalid_name"));
    for taken in ["other", "bob", "default"] {
        let (status, body) = rename(&fleet, &alice, "acme", taken).await;
        assert_eq!(
            (status, error_code(&body).as_str()),
            (409, "name_taken"),
            "{taken}"
        );
    }

    let (status, body) = rename(&fleet, &alice, "acme", "acme2").await;
    assert_eq!(status, 200, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(view["id"], id.as_str());
    assert_eq!(view["name"], "acme2");
    assert_eq!(view["personal"], false);

    let (status, body) = as_browser(&fleet, "GET", "/api/v1/org?org=acme2", &alice, None).await;
    assert_eq!(status, 200, "{body}");
    let view: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(view["name"], "acme2");
    assert_eq!(view["personal"], false);
    // The old name is tombstoned.
    let (status, body) = create(&fleet, &alice, "acme").await;
    assert_eq!((status, body["error"].as_str()), (409, Some("name_taken")));
    // Audited, with where it came from.
    let (status, audit) = as_browser(&fleet, "GET", "/api/v1/audit?org=acme2", &alice, None).await;
    assert_eq!(status, 200, "{audit}");
    assert!(
        audit.contains("org.rename") && audit.contains("from acme"),
        "{audit}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn personal_orgs_cannot_be_renamed_or_deleted() {
    let fleet = TestCoordinator::start().await;
    let (alice, _, _) = fleet.seed_user("alice").await;
    let (status, body) = rename(&fleet, &alice, "alice", "alice2").await;
    assert_eq!((status, error_code(&body).as_str()), (409, "personal_org"));
    let (status, body) = delete_org(&fleet, &alice, "alice").await;
    assert_eq!((status, error_code(&body).as_str()), (409, "personal_org"));
    assert!(fleet.db().resolve_org("alice").await.unwrap().is_some());

    // The flag the UI hides the controls on.
    let session = session_json(&fleet, &alice).await;
    assert_eq!(session["org"]["personal"], true, "{session}");
    assert_eq!(session["memberships"][0]["personal"], true, "{session}");
    let (status, body) = as_browser(&fleet, "GET", "/api/v1/org", &alice, None).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(r#""personal":true"#), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admins_delete_empty_team_orgs() {
    let fleet = TestCoordinator::start().await;
    let (alice, _, _) = fleet.seed_user("alice").await;
    let (bob, _, _) = fleet.seed_user("bob").await;
    assert_eq!(create(&fleet, &alice, "acme").await.0, 201);
    assert_eq!(
        set_member(&fleet, &alice, "acme", "bob", "member").await.0,
        204
    );
    let session = session_json(&fleet, &alice).await;
    assert!(
        session["memberships"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["name"] == "acme" && m["personal"] == false),
        "{session}"
    );

    let (status, body) = delete_org(&fleet, &bob, "acme").await;
    assert_eq!((status, error_code(&body).as_str()), (403, "forbidden"));

    let (status, body) = delete_org(&fleet, &alice, "acme").await;
    assert_eq!(status, 204, "{body}");
    assert!(fleet.db().resolve_org("acme").await.unwrap().is_none());
    let (status, _) = as_browser(&fleet, "GET", "/api/v1/org?org=acme", &alice, None).await;
    assert_eq!(status, 403);
    // The name is released for good.
    let (status, body) = create(&fleet, &alice, "acme").await;
    assert_eq!((status, body["error"].as_str()), (409, Some("name_taken")));
    assert!(fleet
        .forgs_audit_actions()
        .await
        .contains(&"org.delete".to_owned()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn orgs_with_hardware_or_grants_are_not_deleted() {
    let fleet = TestCoordinator::start().await;
    let (alice, _, _) = fleet.seed_user("alice").await;
    assert_eq!(create(&fleet, &alice, "acme").await.0, 201);
    let org = fleet.db().resolve_org("acme").await.unwrap().unwrap();
    fleet.seed_node_in(&org, "rpi-1").await;

    let (status, body) = delete_org(&fleet, &alice, "acme").await;
    assert_eq!((status, error_code(&body).as_str()), (409, "org_not_empty"));
    assert!(fleet.db().resolve_org("acme").await.unwrap().is_some());

    // Remove the node; its audit history alone does not block the delete.
    let (status, body) = as_browser(
        &fleet,
        "DELETE",
        "/api/v1/nodes/rpi-1?org=acme",
        &alice,
        None,
    )
    .await;
    assert!(status == 200 || status == 204, "{status}: {body}");

    // A live grant does.
    fleet
        .seed_workload_grant(
            "acme",
            "octo/repo",
            "tag=nrf52",
            &[probefleet_proto::token::AllowedOp::Attach],
            None,
        )
        .await;
    let (status, body) = delete_org(&fleet, &alice, "acme").await;
    assert_eq!((status, error_code(&body).as_str()), (409, "org_not_empty"));

    let ns = probefleet_coordinator::subject::ns_of(&org).unwrap();
    let scoped = fleet.db().forgs().scoped(ns);
    for g in scoped.list_grants().await.unwrap() {
        scoped.delete_grant(g.id).await.unwrap();
    }
    let (status, body) = delete_org(&fleet, &alice, "acme").await;
    assert_eq!(status, 204, "{body}");
    assert!(fleet.db().resolve_org("acme").await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_per_user_cap_is_hard_under_concurrency() {
    let fleet = TestCoordinator::start_with(|c| c.max_orgs_per_user = 2).await;
    let (alice, _, _) = fleet.seed_user("alice").await;
    let names = ["c1", "c2", "c3", "c4", "c5"];
    let results =
        futures_util::future::join_all(names.iter().map(|n| create(&fleet, &alice, n))).await;
    let created = results.iter().filter(|(s, _)| *s == 201).count();
    assert_eq!(created, 2, "{results:?}");
    for (status, body) in results.iter().filter(|(s, _)| *s != 201) {
        assert_eq!(
            (*status, body["error"].as_str()),
            (403, Some("org_limit_reached")),
            "{results:?}"
        );
    }
}
