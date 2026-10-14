//! The browser session cookie's blast-radius fence (`docs/web-ui.md` D1).
//!
//! The login flow itself — provider redirects, `state` binding, the callback,
//! cookie attributes, signup, the device flow, logout and refresh mechanics —
//! is forgs' and is tested in `forgs-http`'s own suite. What stays here is
//! what *fleet* promises about the credential once a browser holds it:
//!
//! * the cookie is the *same* credential the header carries, and is accepted
//!   **only under `/api/v1`** (fleet's `cookie_api_prefix`) — never on the
//!   control-plane `WebSocket`s and never on forgs' header-only JSON routes;
//! * a cookie-authenticated mutating `/api/v1` call needs `X-Fleet-Csrf`,
//!   derived the way the server derives it; a bearer call needs none;
//! * a garbage cookie is simply "no credential", and an explicit bearer wins
//!   over an ambient cookie;
//! * `/auth/providers` lists exactly the configured login providers.

mod common;

use std::sync::Arc;

use serde_json::json;

use common::TestCoordinator;
use probefleet_coordinator::FleetRole;

/// Pull one `Set-Cookie` value by cookie name.
fn set_cookie<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
    headers
        .iter()
        .filter(|(k, _)| k == "set-cookie")
        .map(|(_, v)| v.as_str())
        .find(|v| v.starts_with(&format!("{name}=")))
}

/// Live session rows.
async fn live_sessions(fleet: &TestCoordinator) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM forgs_session")
        .fetch_one(fleet.db().pool_for_test())
        .await
        .unwrap()
}

/// **The blast-radius fence.** Cookie authentication is accepted under
/// `/api/v1` and nowhere else — one assertion per route that keeps requiring
/// an explicit bearer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cookie_is_refused_everywhere_outside_the_api() {
    let fleet = TestCoordinator::start().await;
    let token = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let cookie = format!("prfs_session={token}");

    // The same credential *does* work on the API, so what follows is about the
    // route and not about the token.
    let (status, _, body) = fleet
        .http_full("GET", "/api/v1/session", &[("cookie", &cookie)], None)
        .await;
    assert_eq!(status, 200, "{body}");

    // A browser must never drive a control-plane WebSocket by ambient
    // authority. The upgrade fails at authentication, before the handshake —
    // also when the request names an org the cookie's holder belongs to.
    for path in ["/agent", "/client", "/client?org=acme", "/delegate"] {
        let status = fleet
            .upgrade_status_with(path, None, &[("cookie", &cookie)])
            .await;
        assert!(
            status == 401 || status == 403,
            "{path} accepted a cookie: {status}"
        );
    }
    // ...while the same token as a bearer does open `/client`.
    assert_eq!(
        fleet.upgrade_status("/client?org=acme", Some(&token)).await,
        101
    );

    // forgs' JSON surface the CLI uses is header-only (forgs `routes.rs`):
    // `/auth/keys`, `/auth/logout`, `/auth/members`, `/auth/rename`.
    for (path, body) in [
        (
            "/auth/keys",
            json!({ "action": "list", "namespace": "acme" }),
        ),
        (
            "/auth/members",
            json!({ "action": "list", "namespace": "acme" }),
        ),
        (
            "/auth/rename",
            json!({ "kind": "user", "new_username": "mallory" }),
        ),
        ("/auth/logout", json!({ "all": true })),
    ] {
        let (status, _, response) = fleet
            .http_full("POST", path, &[("cookie", &cookie)], Some(body.to_string()))
            .await;
        assert_eq!(status, 401, "{path} accepted a cookie: {response}");
    }

    // `/auth/token`'s grants carry their credential **in the body** by design,
    // so the assertion is that an empty one plus a valid cookie authenticates
    // nothing.
    let (status, _, body) = fleet
        .http_full(
            "POST",
            "/auth/token",
            &[("cookie", &cookie)],
            Some(json!({ "grant_type": "refresh", "session_token": "" }).to_string()),
        )
        .await;
    assert!(
        status == 400 || status == 401,
        "/auth/token accepted a cookie: {status} {body}"
    );

    // Nothing was revoked or renamed on the way out.
    assert_eq!(live_sessions(&fleet).await, 1);
    let (status, _, body) = fleet
        .http_full("GET", "/api/v1/session", &[("cookie", &cookie)], None)
        .await;
    assert_eq!(status, 200, "a refused call must change nothing");
    let me: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(me["username"], "alice");
}

/// CSRF on a mutating `/api/v1` route: absent header, wrong header, right
/// header — and the session is gone only in the last case.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cookie_mutation_requires_the_csrf_header() {
    let fleet = TestCoordinator::start().await;
    let token = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let (cookie, csrf) = fleet.browser_session(&token);
    assert_eq!(live_sessions(&fleet).await, 1);

    // No header at all.
    let (status, _, body) = fleet
        .http_full(
            "POST",
            "/api/v1/session/logout",
            &[("cookie", &cookie)],
            Some("{}".into()),
        )
        .await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(
        live_sessions(&fleet).await,
        1,
        "a refused logout must change nothing"
    );

    // A header, but the wrong value.
    let (status, _, _) = fleet
        .http_full(
            "POST",
            "/api/v1/session/logout",
            &[
                ("cookie", &cookie),
                ("x-fleet-csrf", &"0".repeat(csrf.len())),
            ],
            Some("{}".into()),
        )
        .await;
    assert_eq!(status, 403);
    assert_eq!(live_sessions(&fleet).await, 1);

    // The right value, derived the way the server derives it.
    let (status, headers, body) = fleet
        .http_full(
            "POST",
            "/api/v1/session/logout",
            &[("cookie", &cookie), ("x-fleet-csrf", &csrf)],
            Some("{}".into()),
        )
        .await;
    assert_eq!(status, 204, "{body}");
    assert_eq!(
        live_sessions(&fleet).await,
        0,
        "the session row must be gone"
    );

    // Both cookies are cleared: leaving the CSRF cookie behind would leave a
    // value derived from a credential that no longer exists.
    let cleared = set_cookie(&headers, "prfs_session").expect("a cleared session cookie");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    let cleared = set_cookie(&headers, "prfs_csrf").expect("a cleared csrf cookie");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");

    // And the credential really is dead.
    let (status, _, _) = fleet
        .http_full("GET", "/api/v1/session", &[("cookie", &cookie)], None)
        .await;
    assert_eq!(status, 401);
}

/// A **bearer**-authenticated `/api/v1` call needs no CSRF header: the
/// credential is not ambient, so there is nothing for another origin to forge
/// with. Easy to lose by checking the carrier the route *allows* rather than
/// the one the credential *arrived in*.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bearer_call_needs_no_csrf_header() {
    let fleet = TestCoordinator::start().await;
    let token = fleet.seed_session("acme", "alice", FleetRole::Admin).await;

    let (status, _, body) = fleet
        .http_full(
            "POST",
            "/api/v1/session/logout",
            &[("authorization", &format!("Bearer {token}"))],
            Some("{}".into()),
        )
        .await;
    assert_eq!(status, 204, "{body}");
    assert_eq!(live_sessions(&fleet).await, 0);
}

/// A garbage cookie jar must be indistinguishable from an empty one: "no
/// credential", never a 500 and never a different code path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mangled_cookie_is_simply_unauthenticated() {
    let fleet = TestCoordinator::start().await;
    let forged = fleet
        .auth()
        .format()
        .mint(forgs::TokenKind::Session)
        .to_secret_string();
    for raw in [
        "prfs_session".to_owned(),
        "prfs_session=".to_owned(),
        "prfs_session=not a token".to_owned(),
        "garbage".to_owned(),
        "prfs_session=prfs1_nonsense".to_owned(),
        // Well-formed, but no such session.
        format!("prfs_session={forged}"),
    ] {
        let (status, _, body) = fleet
            .http_full("GET", "/api/v1/session", &[("cookie", &raw)], None)
            .await;
        assert_eq!(status, 401, "{raw}: {body}");
        assert!(body.contains("unauthorized"), "{raw}: {body}");
    }
}

/// An explicit bearer wins over a cookie, so a page that opts into a header
/// never has an ambient credential silently substituted for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_explicit_bearer_wins_over_a_cookie() {
    let fleet = TestCoordinator::start().await;
    let alice = fleet.seed_session("acme", "alice", FleetRole::Admin).await;
    let bob = fleet.seed_session("acme", "bob", FleetRole::Member).await;

    let (status, _, body) = fleet
        .http_full(
            "GET",
            "/api/v1/session",
            &[
                ("cookie", &format!("prfs_session={bob}")),
                ("authorization", &format!("Bearer {alice}")),
            ],
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let me: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(me["username"], "alice");
}

/// `/auth/providers` is what the login page renders from: exactly the
/// configured providers — possibly none, which is a supported deployment
/// (sessions minted by `coordinator user-token` only).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_providers_route_lists_what_is_configured() {
    let fleet = TestCoordinator::start().await;
    let (status, body) = fleet.http("GET", "/auth/providers", None).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["providers"], json!([]));

    let github = forgs_idp::GithubProvider::new(forgs_idp::github::GithubConfig::new(
        "client-id",
        "client-secret",
    ))
    .unwrap();
    let config = probefleet_coordinator::config::CoordinatorConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        sqlite_path: ":memory:".into(),
        signing_key: probefleet_coordinator::config::SigningKeySource::Seed(common::SEED),
        csrf_secret: Some(common::CSRF_SECRET.to_vec()),
        ..Default::default()
    };
    let fleet = TestCoordinator::start_config(config, vec![Arc::new(github)]).await;
    let (status, body) = fleet.http("GET", "/auth/providers", None).await;
    assert_eq!(status, 200, "{body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["providers"], json!(["github"]));
}
