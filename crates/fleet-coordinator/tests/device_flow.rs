//! The GitHub device flow, end to end, against a **stub GitHub** on loopback.
//!
//! The real thing needs an OAuth app registration, which no test can create. So
//! the coordinator's three GitHub endpoints are configurable (that is the only
//! reason they are), and these tests point them at an axum stub that answers
//! exactly what github.com answers — including the awkward parts: device-flow
//! errors arrive as HTTP **200** with an `error` field, and `/user` returns the
//! identity as a JSON *number*.
//!
//! What is genuinely exercised: the coordinator's brokering, the identity
//! provisioning (personal org on first login, reuse on the second), the poll
//! state relay, and — the point — that the session token which comes out
//! authenticates a real `/client` upgrade.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use common::TestCoordinator;
use fleet_coordinator::config::GithubConfig;

/// What the stub should answer the next `/login/oauth/access_token` poll with.
#[derive(Debug, Clone)]
enum PollScript {
    /// `authorization_pending` for the first N polls, then a grant.
    PendingThenGrant { pending: usize },
    /// Always answer with this OAuth error code.
    AlwaysError(&'static str),
}

/// State shared with the stub's handlers.
struct StubState {
    script: PollScript,
    polls: AtomicUsize,
    /// The identity `/user` reports. Mutable so a test can rename the login
    /// while keeping the id, which is the rename-takeover case.
    user: std::sync::Mutex<(u64, String)>,
    /// Every `client_id` the stub was sent, so a test can assert the
    /// coordinator forwards its configured app rather than something invented.
    seen_client_ids: std::sync::Mutex<Vec<String>>,
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
    async fn start(script: PollScript) -> Self {
        let state = Arc::new(StubState {
            script,
            polls: AtomicUsize::new(0),
            user: std::sync::Mutex::new((4242, "kaspar".to_owned())),
            seen_client_ids: std::sync::Mutex::new(Vec::new()),
        });

        let router = Router::new()
            .route("/login/device/code", post(device_code))
            .route("/login/oauth/access_token", post(access_token))
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

    /// The `[github]` config pointing a coordinator at this stub.
    fn config(&self) -> GithubConfig {
        GithubConfig {
            client_id: "Iv1.test-client".to_owned(),
            client_secret: None,
            scope: String::new(),
            device_code_url: format!("{}/login/device/code", self.base_url),
            access_token_url: format!("{}/login/oauth/access_token", self.base_url),
            api_base: self.base_url.clone(),
            authorize_url: format!("{}/login/oauth/authorize", self.base_url),
            callback_registered: false,
        }
    }
}

/// Parse an `application/x-www-form-urlencoded` body into pairs.
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

async fn device_code(State(state): State<Arc<StubState>>, body: String) -> Json<serde_json::Value> {
    for (k, v) in form_pairs(&body) {
        if k == "client_id" {
            state.seen_client_ids.lock().unwrap().push(v);
        }
    }
    Json(json!({
        "device_code": "dc-abc123",
        "user_code": "WDJB-MJHT",
        "verification_uri": "https://github.com/login/device",
        "expires_in": 900,
        "interval": 1,
    }))
}

async fn access_token(
    State(state): State<Arc<StubState>>,
    body: String,
) -> Json<serde_json::Value> {
    let pairs = form_pairs(&body);
    for (k, v) in &pairs {
        if k == "client_id" {
            state.seen_client_ids.lock().unwrap().push(v.clone());
        }
    }
    // The device code must come back verbatim: the coordinator holds no state
    // between /start and /poll, so this is the whole continuity of the flow.
    assert!(
        pairs
            .iter()
            .any(|(k, v)| k == "device_code" && v == "dc-abc123"),
        "the coordinator must relay the device code it was given, got {pairs:?}"
    );

    let n = state.polls.fetch_add(1, Ordering::SeqCst);
    // GitHub answers device-flow errors with HTTP 200 and an `error` field, so
    // the stub must too, or the test would exercise a path production never
    // takes.
    match &state.script {
        PollScript::PendingThenGrant { pending } if n < *pending => {
            Json(json!({ "error": "authorization_pending" }))
        }
        PollScript::PendingThenGrant { .. } => Json(json!({
            "access_token": "gho_stubaccesstoken",
            "token_type": "bearer",
            "scope": "",
        })),
        PollScript::AlwaysError(code) => Json(json!({ "error": code, "interval": 7 })),
    }
}

async fn user(State(state): State<Arc<StubState>>) -> Json<serde_json::Value> {
    let (id, login) = state.user.lock().unwrap().clone();
    // `id` is a JSON number, as GitHub sends it. Identity keys off this, never
    // off `login`.
    Json(json!({ "id": id, "login": login, "email": "kaspar@example.com" }))
}

/// Begin a flow and return the device code.
async fn start_flow(fleet: &TestCoordinator) -> String {
    let (_, body) = fleet
        .http("POST", "/auth/device/start", Some("{}".to_owned()))
        .await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    v["device_code"].as_str().unwrap().to_owned()
}

/// Poll until the coordinator returns something other than `authorization_pending`.
async fn poll_until_settled(fleet: &TestCoordinator, device_code: &str) -> (u16, String) {
    for _ in 0..20 {
        let (status, body) = fleet
            .http(
                "POST",
                "/auth/device/poll",
                Some(json!({ "device_code": device_code }).to_string()),
            )
            .await;
        if !body.contains("authorization_pending") {
            return (status, body);
        }
    }
    panic!("the device flow never settled");
}

/// The whole point: a device flow that completes yields a session token which
/// authenticates a real `/client` upgrade. Anything short of that is a token
/// that parses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_device_flow_yields_a_working_session_token() {
    let github = StubGithub::start(PollScript::PendingThenGrant { pending: 2 }).await;
    let gh_config = github.config();
    let fleet = TestCoordinator::start_with(move |c| c.github = Some(gh_config)).await;

    let (status, body) = fleet
        .http("POST", "/auth/device/start", Some("{}".to_owned()))
        .await;
    assert_eq!(status, 200, "{body}");
    let start: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(start["user_code"], "WDJB-MJHT");
    assert_eq!(start["verification_uri"], "https://github.com/login/device");

    let device_code = start["device_code"].as_str().unwrap();
    // The first polls are pending — the human has not typed the code yet.
    let (status, body) = fleet
        .http(
            "POST",
            "/auth/device/poll",
            Some(json!({ "device_code": device_code }).to_string()),
        )
        .await;
    assert_eq!(status, 401);
    assert!(body.contains("authorization_pending"), "{body}");

    let (status, body) = poll_until_settled(&fleet, device_code).await;
    assert_eq!(status, 200, "{body}");
    let granted: serde_json::Value = serde_json::from_str(&body).unwrap();
    let token = granted["token"].as_str().unwrap().to_owned();
    assert!(token.starts_with("prfs1_"));
    assert_eq!(granted["login"], "kaspar");
    // The org is keyed off the immutable numeric id, not the login.
    assert_eq!(granted["org"], "gh-4242");
    assert!(granted["expires"].is_number());

    // The coordinator forwarded *its* configured client id, not one the CLI
    // could have chosen: that is what keeps the OAuth app server-side.
    let seen = github.state.seen_client_ids.lock().unwrap().clone();
    assert!(!seen.is_empty());
    assert!(seen.iter().all(|id| id == "Iv1.test-client"), "{seen:?}");

    // The session token opens the operator plane.
    let (tx, rx) = fleet
        .dial("/client", &token)
        .await
        .expect("the device-flow session token must authenticate on /client");
    drop((tx, rx));
}

/// First login creates the user *and* a personal org with the user as admin;
/// the second reuses both. Everyone is always in an org — yours is an org of
/// one — and there is no user-owned/org-owned branch anywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_login_creates_a_personal_org_and_the_second_reuses_it() {
    let github = StubGithub::start(PollScript::PendingThenGrant { pending: 0 }).await;
    let gh_config = github.config();
    let fleet = TestCoordinator::start_with(move |c| c.github = Some(gh_config)).await;

    let dc = start_flow(&fleet).await;
    let (status, body) = poll_until_settled(&fleet, &dc).await;
    assert_eq!(status, 200, "{body}");
    let first: serde_json::Value = serde_json::from_str(&body).unwrap();

    // The user is an admin of its personal org: without the membership row the
    // token would authenticate and then authorize nothing.
    let org = fleet_proto::ids::OrgId(first["org"].as_str().unwrap().to_owned());
    assert_eq!(
        fleet.db().role_of(&org, "gh-4242").await.unwrap(),
        Some(fleet_proto::ids::Role::Admin)
    );

    // Rename the GitHub login between logins. The id is what identifies, so the
    // second login must land in the *same* org.
    github.state.user.lock().unwrap().1 = "kaspar-renamed".to_owned();

    let dc = start_flow(&fleet).await;
    let (status, body) = poll_until_settled(&fleet, &dc).await;
    assert_eq!(status, 200, "{body}");
    let second: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(second["org"], first["org"]);
    assert_eq!(second["login"], "kaspar-renamed");
    assert_ne!(
        second["token"], first["token"],
        "each login mints its own token"
    );

    let orgs: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM org WHERE id LIKE 'gh-%'")
        .fetch_one(fleet.db().pool_for_test())
        .await
        .unwrap();
    assert_eq!(orgs.0, 1, "the second login must not create a second org");
}

/// GitHub's poll states are relayed verbatim, because they describe the
/// caller's *own* device code rather than answering a question about somebody
/// else's credential — so there is no oracle to protect here, and a CLI that
/// cannot tell `slow_down` from `access_denied` cannot behave correctly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poll_states_are_relayed_with_their_own_codes() {
    for (github_code, expected_status) in [
        ("slow_down", 429),
        ("expired_token", 401),
        ("access_denied", 401),
    ] {
        let github = StubGithub::start(PollScript::AlwaysError(github_code)).await;
        let gh_config = github.config();
        let fleet = TestCoordinator::start_with(move |c| c.github = Some(gh_config)).await;

        let (_, body) = fleet
            .http("POST", "/auth/device/start", Some("{}".to_owned()))
            .await;
        let start: serde_json::Value = serde_json::from_str(&body).unwrap();
        let dc = start["device_code"].as_str().unwrap();

        let (status, body) = fleet
            .http(
                "POST",
                "/auth/device/poll",
                Some(json!({ "device_code": dc }).to_string()),
            )
            .await;
        assert_eq!(status, expected_status, "{github_code}: {body}");
        assert!(body.contains(github_code), "{github_code}: {body}");
    }
}

/// An OAuth error GitHub does not document as a device-flow state collapses to
/// `invalid_grant`: that one *would* be an oracle, and the detail belongs in the
/// coordinator's log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unexpected_oauth_error_collapses_to_invalid_grant() {
    let github = StubGithub::start(PollScript::AlwaysError("incorrect_client_credentials")).await;
    let gh_config = github.config();
    let fleet = TestCoordinator::start_with(move |c| c.github = Some(gh_config)).await;

    let (_, body) = fleet
        .http("POST", "/auth/device/start", Some("{}".to_owned()))
        .await;
    let start: serde_json::Value = serde_json::from_str(&body).unwrap();
    let dc = start["device_code"].as_str().unwrap();

    let (status, body) = fleet
        .http(
            "POST",
            "/auth/device/poll",
            Some(json!({ "device_code": dc }).to_string()),
        )
        .await;
    assert_eq!(status, 401);
    assert!(body.contains("invalid_grant"), "{body}");
    assert!(
        !body.contains("incorrect_client_credentials"),
        "the upstream detail must not reach the caller: {body}"
    );
}

/// A coordinator with no `[github]` table is a supported deployment (air-gapped,
/// or development), so the routes answer a **named** 503 rather than a 404 or
/// silence. The name is what lets the CLI say "ask the operator, or use
/// `coordinator user-token`" instead of "not found".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unconfigured_coordinator_says_so_by_name() {
    let fleet = TestCoordinator::start().await;

    let (status, body) = fleet
        .http("POST", "/auth/device/start", Some("{}".to_owned()))
        .await;
    assert_eq!(status, 503);
    assert!(body.contains("device_flow_unconfigured"), "{body}");

    let (status, body) = fleet
        .http(
            "POST",
            "/auth/device/poll",
            Some(json!({ "device_code": "whatever" }).to_string()),
        )
        .await;
    assert_eq!(status, 503);
    assert!(body.contains("device_flow_unconfigured"), "{body}");
}

/// The brokering is stateless — there is no `device_flow` table — so an empty
/// device code has to be rejected on shape alone rather than by lookup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_device_code_is_a_bad_request() {
    let github = StubGithub::start(PollScript::PendingThenGrant { pending: 0 }).await;
    let gh_config = github.config();
    let fleet = TestCoordinator::start_with(move |c| c.github = Some(gh_config)).await;

    let (status, _) = fleet
        .http(
            "POST",
            "/auth/device/poll",
            Some(json!({ "device_code": "   " }).to_string()),
        )
        .await;
    assert_eq!(status, 400);
}
