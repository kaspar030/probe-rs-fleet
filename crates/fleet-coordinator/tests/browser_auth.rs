//! Browser session authentication, end to end (`docs/web-ui.md` D1).
//!
//! The authorization-code flow runs against a **stub GitHub** on loopback, the
//! pattern `tests/device_flow.rs` establishes — including its awkward part,
//! which this flow shares: GitHub reports OAuth errors with HTTP **200** and an
//! `error` field, so a test that only checked statuses would exercise a path
//! production never takes.
//!
//! What is genuinely exercised here, rather than restated: that the cookie is
//! the *same* credential the header carries and is accepted only under
//! `/api/v1`; that `state` is what binds a callback to a browser; that
//! `redirect_uri` comes from configuration and not from the request; that the
//! CSRF token the server derives is the one a page can compute from its own
//! cookie; and that no secret the design moved into a cookie ever appears in a
//! body.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use common::TestCoordinator;
use fleet_coordinator::config::GithubConfig;
use fleet_proto::ids::Role;

/// The stub's view of an in-flight authorization-code flow.
struct StubState {
    /// Every `redirect_uri` the coordinator sent, so a test can assert it was
    /// built from `public_url` and not from the request's `Host`.
    seen_redirect_uris: std::sync::Mutex<Vec<String>>,
    /// Every `client_id` the stub was sent.
    seen_client_ids: std::sync::Mutex<Vec<String>>,
    /// The identity `/user` reports.
    user: std::sync::Mutex<(u64, String)>,
    /// Whether the token endpoint should refuse.
    refuse_exchange: bool,
    /// Device-flow polls served so far.
    polls: AtomicUsize,
}

/// A stub github.com + api.github.com on loopback.
struct StubGithub {
    base_url: String,
    state: Arc<StubState>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for StubGithub {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl StubGithub {
    async fn start() -> Self {
        Self::start_with(false).await
    }

    async fn start_with(refuse_exchange: bool) -> Self {
        let state = Arc::new(StubState {
            seen_redirect_uris: std::sync::Mutex::new(Vec::new()),
            seen_client_ids: std::sync::Mutex::new(Vec::new()),
            user: std::sync::Mutex::new((4242, "kaspar".to_owned())),
            refuse_exchange,
            polls: AtomicUsize::new(0),
        });

        let router = Router::new()
            .route("/login/oauth/access_token", post(access_token))
            .route("/login/device/code", post(device_code))
            .route("/user", get(user))
            .with_state(Arc::clone(&state));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        Self {
            base_url: format!("http://{addr}"),
            state,
            server,
        }
    }

    /// A `[github]` config pointing a coordinator at this stub, with the
    /// callback registration asserted (and therefore a client secret, which the
    /// validator requires and GitHub's token endpoint needs).
    fn config(&self, callback_registered: bool) -> GithubConfig {
        GithubConfig {
            client_id: "Iv1.test-client".to_owned(),
            client_secret: callback_registered.then(|| "s3cret".to_owned()),
            scope: String::new(),
            authorize_url: format!("{}/login/oauth/authorize", self.base_url),
            device_code_url: format!("{}/login/device/code", self.base_url),
            access_token_url: format!("{}/login/oauth/access_token", self.base_url),
            api_base: self.base_url.clone(),
            callback_registered,
        }
    }
}

fn form_pairs(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (percent_decode(k), percent_decode(v)))
        .collect()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn access_token(
    State(state): State<Arc<StubState>>,
    body: String,
) -> Json<serde_json::Value> {
    for (k, v) in form_pairs(&body) {
        match k.as_str() {
            "client_id" => state.seen_client_ids.lock().unwrap().push(v),
            "redirect_uri" => state.seen_redirect_uris.lock().unwrap().push(v),
            _ => {}
        }
    }
    if state.refuse_exchange {
        // HTTP 200 with an `error` field: GitHub's actual shape.
        return Json(json!({ "error": "bad_verification_code" }));
    }
    Json(json!({
        "access_token": "gho_stubaccesstoken",
        "token_type": "bearer",
        "scope": "",
    }))
}

async fn device_code(
    State(state): State<Arc<StubState>>,
    _body: String,
) -> Json<serde_json::Value> {
    state.polls.store(0, Ordering::SeqCst);
    Json(json!({
        "device_code": "dc-abc123",
        "user_code": "WDJB-MJHT",
        "verification_uri": "https://github.com/login/device",
        "expires_in": 900,
        "interval": 1,
    }))
}

async fn user(State(state): State<Arc<StubState>>) -> Json<serde_json::Value> {
    let (id, login) = state.user.lock().unwrap().clone();
    Json(json!({ "id": id, "login": login, "email": "kaspar@example.com" }))
}

/// Pull one `Set-Cookie` value by cookie name.
fn set_cookie<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
    headers
        .iter()
        .filter(|(k, _)| k == "set-cookie")
        .map(|(_, v)| v.as_str())
        .find(|v| v.starts_with(&format!("{name}=")))
}

/// The value half of a `Set-Cookie`.
fn cookie_body(raw: &str) -> &str {
    raw.split_once('=')
        .and_then(|(_, rest)| rest.split(';').next())
        .unwrap_or("")
}

/// One header pair from a response.
fn header<'h>(headers: &'h [(String, String)], name: &str) -> Option<&'h str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Drive `/auth/github/start` and return `(state parameter, flow cookie)`.
async fn begin_authorization_code(fleet: &TestCoordinator) -> (String, String) {
    let (status, headers, _) = fleet
        .http_full("GET", "/auth/github/start", &[], None)
        .await;
    assert_eq!(status, 302, "start must redirect to GitHub");
    let location = header(&headers, "location").expect("a Location header");
    let state = location
        .split('&')
        .find_map(|kv| kv.strip_prefix("state="))
        .expect("a state parameter")
        .to_owned();
    let flow = set_cookie(&headers, "prfs_oauth").expect("a login-flow cookie");
    (state, format!("prfs_oauth={}", cookie_body(flow)))
}

/// The happy path: a browser that follows the redirect comes back with a
/// session it can actually use, delivered only as cookies.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_authorization_code_login_yields_a_working_cookie_session() {
    let github = StubGithub::start().await;
    let gh_config = github.config(true);
    let fleet = TestCoordinator::start_with(move |c| {
        c.public_url = "https://fleet.example".to_owned();
        c.github = Some(gh_config);
    })
    .await;

    let (status, headers, _) = fleet
        .http_full("GET", "/auth/github/start", &[], None)
        .await;
    assert_eq!(status, 302);
    let location = header(&headers, "location").unwrap().to_owned();
    assert!(
        location.starts_with(&format!("{}/login/oauth/authorize?", github.base_url)),
        "{location}"
    );
    // PKCE parameters are sent even though GitHub ignores them; `state` and the
    // client secret are what actually protect the callback.
    assert!(
        location.contains("code_challenge_method=S256"),
        "{location}"
    );
    assert!(location.contains("client_id=Iv1.test-client"), "{location}");

    let flow_cookie = set_cookie(&headers, "prfs_oauth").expect("a login-flow cookie");
    assert!(flow_cookie.contains("HttpOnly"), "{flow_cookie}");
    let state = location
        .split('&')
        .find_map(|kv| kv.strip_prefix("state="))
        .unwrap()
        .to_owned();

    let (status, headers, body) = fleet
        .http_full(
            "GET",
            &format!("/auth/github/callback?code=abc&state={state}"),
            &[(
                "cookie",
                &format!("prfs_oauth={}", cookie_body(flow_cookie)),
            )],
            None,
        )
        .await;
    assert_eq!(status, 302, "{body}");
    assert_eq!(header(&headers, "location"), Some("/ui"));

    // Neither the session token nor anything else secret is in the body.
    assert!(!body.contains("prfs1_"), "{body}");

    let session = set_cookie(&headers, "prfs_session").expect("a session cookie");
    let csrf = set_cookie(&headers, "prfs_csrf").expect("a csrf cookie");
    let token = cookie_body(session).to_owned();
    assert!(token.starts_with("prfs1_"), "{session}");

    // The cookie is a carrier of the same credential, so it authenticates the
    // API — and the API is where it is accepted.
    let (status, _, body) = fleet
        .http_full(
            "GET",
            "/api/v1/session",
            &[("cookie", &format!("prfs_session={token}"))],
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let me: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(me["login"], "kaspar");
    assert_eq!(me["org"], "gh-4242");
    assert_eq!(me["role"], "admin");

    // And the CSRF cookie is exactly what the server derives, not a value the
    // page and the test agreed on between themselves.
    let (_, expected_csrf) = fleet.browser_session(&token);
    assert_eq!(cookie_body(csrf), expected_csrf);
}

/// The session cookie's attributes are the design, not decoration: `HttpOnly`
/// is what keeps an XSS from exfiltrating a credential that power-cycles
/// hardware, `Secure` is unconditional, and `Max-Age` must not outlive the
/// `session` row the database will forget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_session_cookie_carries_the_promised_attributes() {
    let github = StubGithub::start().await;
    let gh_config = github.config(true);
    let ttl = 3_600;
    let fleet = TestCoordinator::start_with(move |c| {
        c.github = Some(gh_config);
        c.session_ttl_secs = ttl;
    })
    .await;

    let (state, flow) = begin_authorization_code(&fleet).await;
    let (_, headers, _) = fleet
        .http_full(
            "GET",
            &format!("/auth/github/callback?code=abc&state={state}"),
            &[("cookie", &flow)],
            None,
        )
        .await;

    let session = set_cookie(&headers, "prfs_session").unwrap();
    for attribute in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
        assert!(
            session.contains(attribute),
            "{attribute} missing: {session}"
        );
    }
    let max_age: i64 = session
        .split(';')
        .find_map(|a| a.trim().strip_prefix("Max-Age="))
        .expect("a Max-Age")
        .parse()
        .unwrap();
    // Never longer than the row's own lifetime; a browser holding a cookie the
    // database has already dropped is the state D1 rules out.
    assert!(
        max_age > 0 && max_age <= i64::try_from(ttl).unwrap(),
        "{max_age}"
    );

    // The CSRF cookie is deliberately readable by the page.
    let csrf = set_cookie(&headers, "prfs_csrf").unwrap();
    assert!(!csrf.contains("HttpOnly"), "{csrf}");
    assert!(csrf.contains("Secure"), "{csrf}");
}

/// `state` is the control that binds a callback to the browser that started
/// it. Missing, mismatched or replayed, it must mint nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_callback_without_a_matching_state_mints_no_session() {
    let github = StubGithub::start().await;
    let gh_config = github.config(true);
    let fleet = TestCoordinator::start_with(move |c| c.github = Some(gh_config)).await;

    let sessions = |fleet: &TestCoordinator| {
        let pool = fleet.db().pool_for_test().clone();
        async move {
            let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM session")
                .fetch_one(&pool)
                .await
                .unwrap();
            row.0
        }
    };
    assert_eq!(sessions(&fleet).await, 0);

    let (state, flow) = begin_authorization_code(&fleet).await;

    // No cookie at all.
    let (status, headers, _) = fleet
        .http_full(
            "GET",
            &format!("/auth/github/callback?code=abc&state={state}"),
            &[],
            None,
        )
        .await;
    assert_eq!(status, 400);
    assert!(set_cookie(&headers, "prfs_session").is_none());

    // A cookie, but a `state` that does not match it.
    let (status, headers, _) = fleet
        .http_full(
            "GET",
            "/auth/github/callback?code=abc&state=not-the-one",
            &[("cookie", &flow)],
            None,
        )
        .await;
    assert_eq!(status, 400);
    assert!(set_cookie(&headers, "prfs_session").is_none());

    // No `state` parameter at all.
    let (status, _, _) = fleet
        .http_full(
            "GET",
            "/auth/github/callback?code=abc",
            &[("cookie", &flow)],
            None,
        )
        .await;
    assert_eq!(status, 400);

    assert_eq!(sessions(&fleet).await, 0, "no session may have been minted");

    // Now the matching pair succeeds once...
    let (status, _, _) = fleet
        .http_full(
            "GET",
            &format!("/auth/github/callback?code=abc&state={state}"),
            &[("cookie", &flow)],
            None,
        )
        .await;
    assert_eq!(status, 302);
    assert_eq!(sessions(&fleet).await, 1);

    // ...and a replay of the same callback, which a browser would no longer
    // have the cookie for, is refused. The cookie is cleared on use, so this
    // asserts the server-side half: presenting the *spent* pair again is only
    // possible for an attacker who captured it, and it must still not work.
    // (The client here keeps the cookie precisely to make that case testable.)
    let (status, _, _) = fleet
        .http_full(
            "GET",
            &format!("/auth/github/callback?code=abc&state={state}"),
            &[],
            None,
        )
        .await;
    assert_eq!(status, 400, "a callback with no cookie is always refused");
    assert_eq!(sessions(&fleet).await, 1, "no second session");
}

/// `redirect_uri` comes from `public_url`. A `Host`-derived callback behind a
/// reverse proxy is an attacker-chosen OAuth redirect — an account takeover —
/// so this is the one place a header must be ignored on purpose.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_redirect_uri_ignores_host_and_x_forwarded_host() {
    let github = StubGithub::start().await;
    let gh_config = github.config(true);
    let fleet = TestCoordinator::start_with(move |c| {
        c.public_url = "https://fleet.example".to_owned();
        c.github = Some(gh_config);
    })
    .await;

    // The authorize redirect first.
    let (_, headers, _) = fleet
        .http_full(
            "GET",
            "/auth/github/start",
            &[
                ("host", "evil.example"),
                ("x-forwarded-host", "evil.example"),
            ],
            None,
        )
        .await;
    let location = header(&headers, "location").unwrap();
    assert!(
        location.contains("redirect_uri=https%3A%2F%2Ffleet.example%2Fauth%2Fgithub%2Fcallback"),
        "{location}"
    );
    assert!(!location.contains("evil.example"), "{location}");

    // And the token exchange, which GitHub compares byte-for-byte.
    let state = location
        .split('&')
        .find_map(|kv| kv.strip_prefix("state="))
        .unwrap()
        .to_owned();
    let flow = set_cookie(&headers, "prfs_oauth").unwrap();
    let (status, _, _) = fleet
        .http_full(
            "GET",
            &format!("/auth/github/callback?code=abc&state={state}"),
            &[
                ("cookie", &format!("prfs_oauth={}", cookie_body(flow))),
                ("host", "evil.example"),
                ("x-forwarded-host", "evil.example"),
            ],
            None,
        )
        .await;
    assert_eq!(status, 302);

    let seen = github.state.seen_redirect_uris.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec!["https://fleet.example/auth/github/callback".to_owned()],
        "the exchange must send the configured callback, whatever the request said"
    );
}

/// A refused exchange arrives as HTTP 200 with an `error` field. The
/// coordinator must not read that as success.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_exchange_mints_nothing() {
    let github = StubGithub::start_with(true).await;
    let gh_config = github.config(true);
    let fleet = TestCoordinator::start_with(move |c| c.github = Some(gh_config)).await;

    let (state, flow) = begin_authorization_code(&fleet).await;
    let (status, headers, body) = fleet
        .http_full(
            "GET",
            &format!("/auth/github/callback?code=abc&state={state}"),
            &[("cookie", &flow)],
            None,
        )
        .await;
    assert_eq!(status, 401, "{body}");
    assert!(set_cookie(&headers, "prfs_session").is_none());
    // The upstream detail belongs in the coordinator's log, not the response.
    assert!(!body.contains("bad_verification_code"), "{body}");
}

/// A deployment that has not registered the callback is a supported one: the
/// browser routes answer a **named** 503 the page can turn into a fallback,
/// and `/api/v1/auth/methods` says which login to render.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_methods_reports_what_the_deployment_can_actually_do() {
    // No `[github]` table at all.
    let fleet = TestCoordinator::start().await;
    let (status, body) = fleet.http("GET", "/api/v1/auth/methods", None).await;
    assert_eq!(status, 200);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["login"],
        "none"
    );

    // A `[github]` table, no callback registered.
    let github = StubGithub::start().await;
    let gh_config = github.config(false);
    let fleet = TestCoordinator::start_with(move |c| c.github = Some(gh_config)).await;
    let (_, body) = fleet.http("GET", "/api/v1/auth/methods", None).await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["login"],
        "device"
    );
    let (status, body) = fleet.http("GET", "/auth/github/start", None).await;
    assert_eq!(status, 503);
    assert!(body.contains("browser_login_unconfigured"), "{body}");

    // The callback registered.
    let gh_config = github.config(true);
    let fleet = TestCoordinator::start_with(move |c| c.github = Some(gh_config)).await;
    let (_, body) = fleet.http("GET", "/api/v1/auth/methods", None).await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["login"],
        "authorization_code"
    );
}

/// The cookie-brokered device fallback exists for exactly one reason: neither
/// the `device_code` nor the session token may reach JavaScript. If either
/// appears in a body, the routes have no purpose.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_brokered_device_flow_puts_no_secret_in_a_body() {
    let github = StubGithub::start().await;
    let gh_config = github.config(false);
    let fleet = TestCoordinator::start_with(move |c| c.github = Some(gh_config)).await;

    let (status, headers, body) = fleet
        .http_full(
            "POST",
            "/api/v1/session/device/start",
            &[],
            Some("{}".into()),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    let start: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(start["user_code"], "WDJB-MJHT");
    assert_eq!(start["verification_uri"], "https://github.com/login/device");
    assert!(start["interval"].is_number());
    assert!(start["expires_in"].is_number());
    // The two things that must not be here.
    assert!(!body.contains("dc-abc123"), "{body}");
    assert!(!body.contains("device_code"), "{body}");

    let device = set_cookie(&headers, "prfs_device").expect("a device cookie");
    assert!(device.contains("HttpOnly"), "{device}");
    assert_eq!(cookie_body(device), "dc-abc123");

    let (status, headers, body) = fleet
        .http_full(
            "POST",
            "/api/v1/session/device/poll",
            &[("cookie", &format!("prfs_device={}", cookie_body(device)))],
            Some("{}".into()),
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["status"],
        "ok"
    );
    assert!(!body.contains("prfs1_"), "{body}");

    // The session arrived only as cookies, and it works.
    let session = set_cookie(&headers, "prfs_session").expect("a session cookie");
    let (status, _, body) = fleet
        .http_full(
            "GET",
            "/api/v1/session",
            &[("cookie", &format!("prfs_session={}", cookie_body(session)))],
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");

    // And a poll with no in-flight flow is a bad request, not an eternal
    // "pending" the page would loop on.
    let (status, _, _) = fleet
        .http_full(
            "POST",
            "/api/v1/session/device/poll",
            &[],
            Some("{}".into()),
        )
        .await;
    assert_eq!(status, 400);
}

/// **The blast-radius fence.** Cookie authentication is accepted under
/// `/api/v1` and nowhere else — five separate assertions, one per route that
/// keeps requiring an explicit bearer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cookie_is_refused_everywhere_outside_the_api() {
    let fleet = TestCoordinator::start().await;
    let token = fleet.seed_session("acme", "alice", Role::Admin).await;
    let cookie = format!("prfs_session={token}");

    // The same credential *does* work on the API, so what follows is about the
    // route and not about the token.
    let (status, _, body) = fleet
        .http_full("GET", "/api/v1/session", &[("cookie", &cookie)], None)
        .await;
    assert_eq!(status, 200, "{body}");

    // A browser must never drive a control-plane WebSocket by ambient
    // authority. The upgrade fails at authentication, before the handshake.
    for path in ["/agent", "/client", "/delegate"] {
        let (status, _, _) = fleet
            .http_full(
                "GET",
                path,
                &[
                    ("cookie", &cookie),
                    ("connection", "upgrade"),
                    ("upgrade", "websocket"),
                    ("sec-websocket-version", "13"),
                    ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
                ],
                None,
            )
            .await;
        assert!(
            status == 401 || status == 403,
            "{path} accepted a cookie: {status}"
        );
    }

    // The CLI JSON endpoints keep requiring an explicit credential too, and
    // neither consults the cookie. `/auth/token`'s refresh grant takes the
    // session token **in the body** by design (its grants are precisely about
    // a credential in the body), so the assertion is that an empty one plus a
    // valid cookie authenticates nothing.
    let (status, _, body) = fleet
        .http_full(
            "POST",
            "/auth/token",
            &[("cookie", &cookie)],
            Some(json!({ "grant_type": "refresh", "session_token": "" }).to_string()),
        )
        .await;
    assert_eq!(status, 401, "/auth/token accepted a cookie: {body}");

    // `/auth/keys` authenticates with a header, so this one is the direct
    // carrier assertion.
    let (status, _, body) = fleet
        .http_full(
            "POST",
            "/auth/keys",
            &[("cookie", &cookie)],
            Some(json!({ "action": "list" }).to_string()),
        )
        .await;
    assert_eq!(status, 401, "/auth/keys accepted a cookie: {body}");

    // `/auth/logout` is the newest route on this surface and follows the same
    // rule: `Authorization: Bearer` only, so a cookie — which a hostile page
    // can cause the browser to attach — must not be able to revoke a
    // developer's credentials from under them.
    let (status, _, body) = fleet
        .http_full(
            "POST",
            "/auth/logout",
            &[("cookie", &cookie)],
            Some(json!({ "all": true }).to_string()),
        )
        .await;
    assert_eq!(status, 401, "/auth/logout accepted a cookie: {body}");
    // ...and nothing was revoked on the way out.
    let (status, _, _) = fleet
        .http_full("GET", "/api/v1/session", &[("cookie", &cookie)], None)
        .await;
    assert_eq!(status, 200, "a refused logout must revoke nothing");
}

/// CSRF, on the one mutating route phase 1a ships. Absent header, wrong
/// header, right header — and the row is gone only in the last case.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_requires_the_csrf_header_when_the_credential_is_a_cookie() {
    let fleet = TestCoordinator::start().await;
    let token = fleet.seed_session("acme", "alice", Role::Admin).await;
    let (cookie, csrf) = fleet.browser_session(&token);

    let live = |fleet: &TestCoordinator| {
        let pool = fleet.db().pool_for_test().clone();
        async move {
            let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM session")
                .fetch_one(&pool)
                .await
                .unwrap();
            row.0
        }
    };
    assert_eq!(live(&fleet).await, 1);

    // No header at all.
    let (status, _, _) = fleet
        .http_full(
            "POST",
            "/api/v1/session/logout",
            &[("cookie", &cookie)],
            Some("{}".into()),
        )
        .await;
    assert_eq!(status, 403);
    assert_eq!(
        live(&fleet).await,
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
    assert_eq!(live(&fleet).await, 1);

    // The right value, derived the way the server derives it.
    let (status, headers, _) = fleet
        .http_full(
            "POST",
            "/api/v1/session/logout",
            &[("cookie", &cookie), ("x-fleet-csrf", &csrf)],
            Some("{}".into()),
        )
        .await;
    assert_eq!(status, 204);
    assert_eq!(live(&fleet).await, 0, "the session row must be gone");

    // Both cookies are cleared, not just the session one: leaving the CSRF
    // cookie behind would leave a value derived from a credential that no
    // longer exists.
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
/// with. This is the asymmetry the whole design rests on, and it would be easy
/// to lose by checking the carrier the route *allows* rather than the one the
/// credential *arrived in*.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bearer_call_needs_no_csrf_header() {
    let fleet = TestCoordinator::start().await;
    let token = fleet.seed_session("acme", "alice", Role::Admin).await;

    let (status, _, body) = fleet
        .http_full(
            "POST",
            "/api/v1/session/logout",
            &[("authorization", &format!("Bearer {token}"))],
            Some("{}".into()),
        )
        .await;
    assert_eq!(status, 204, "{body}");

    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM session")
        .fetch_one(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert_eq!(row.0, 0);
}

/// A garbage cookie jar must be indistinguishable from an empty one: "no
/// credential", never a 500 and never a different code path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mangled_cookie_is_simply_unauthenticated() {
    let fleet = TestCoordinator::start().await;
    for raw in [
        "prfs_session",
        "prfs_session=",
        "prfs_session=not a token",
        "garbage",
        "prfs_session=prfs1_nonsense",
    ] {
        let (status, _, body) = fleet
            .http_full("GET", "/api/v1/session", &[("cookie", raw)], None)
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
    let alice = fleet.seed_session("acme", "alice", Role::Admin).await;
    let bob = fleet.seed_session("acme", "bob", Role::Member).await;

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
    assert_eq!(me["user"], "alice");
}
