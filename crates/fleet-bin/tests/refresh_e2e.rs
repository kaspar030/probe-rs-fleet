//! Refresh tokens end to end, against a live coordinator.
//!
//! Two properties no unit test can reach, both from the task that added the
//! feature:
//!
//! * **the sidecar path** — the reported bug. A workstation whose `[user]`
//!   session has expired but whose refresh token has not must resolve to a
//!   *working* token through `roles::sidecar::resolve_client_config`, and the
//!   file on disk must be updated. Before this feature that machine got a bare
//!   `401 Unauthorized` through laze every 12 hours no matter how heavily it
//!   was used.
//! * **`logout --all` really revokes** — the durable credential's whole
//!   justification. After it, neither the session nor the refresh token works
//!   against the real coordinator.
//!
//! The new-client-against-old-coordinator degradation is asserted in
//! `fleet_config`'s unit tests instead, against a stub that answers the
//! unknown `grant_type` with a `422`. It has to be: no coordinator in this tree
//! still refuses that grant, so a live one cannot express the case.
//!
//! # Why these tests own `XDG_CONFIG_HOME`
//!
//! `ensure_fresh_session` persists through `update_named` →
//! `paths::fleet_config_path`, which resolves the XDG path and ignores any
//! `--config-dir`. The other e2e files sidestep that by keeping their sessions
//! far from expiry; this one is *about* renewal, so it must repoint
//! `XDG_CONFIG_HOME` instead. That makes the file process-global state, so
//! every test here is `#[serial]`-by-mutex on the lock below and each takes the
//! whole environment for its duration.

// Every test below repoints `XDG_CONFIG_HOME` under `ENV_LOCK` and then awaits.
// What the guard protects is the *process environment* for the whole test body,
// so holding it across the await is the requirement, not an oversight; an
// async-aware mutex would not change it. Each test is its own `#[tokio::test]`
// runtime. This mirrors `fleet_config`'s tests, which carry the same note.
#![allow(clippy::await_holding_lock)]

use std::sync::{Arc, Mutex, PoisonError};

use fleet_auth::{OpaqueToken, TokenKind};
use fleet_coordinator::auth::Ed25519Signer;
use fleet_coordinator::clock::SystemClock;
use fleet_coordinator::config::{CoordinatorConfig, SigningKeySource};
use fleet_coordinator::core::Coordinator;
use fleet_coordinator::state::Db;
use fleet_core::policy::Policy;
use fleet_core::scheduler::Scheduler;
use fleet_proto::ids::{OrgId, Role};

const SEED: [u8; 32] = [31u8; 32];

/// Serialises the `XDG_CONFIG_HOME` writes. These tests all compile into one
/// binary and run multithreaded, so a shared lock is the only thing that keeps
/// them from reading each other's fleet files.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// A live coordinator serving its real router on loopback.
struct Fleet {
    coord: Arc<Coordinator>,
    base_url: String,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Fleet {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn start_fleet() -> Fleet {
    let config = CoordinatorConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        sqlite_path: ":memory:".into(),
        signing_key: SigningKeySource::Seed(SEED),
        ..CoordinatorConfig::default()
    };
    let db = Db::connect_in_memory().await.unwrap();
    let coord = Arc::new(Coordinator::new(
        config,
        Scheduler::new(Policy::default()),
        db,
        Ed25519Signer::from_seed(&SEED),
        Arc::new(SystemClock),
    ));

    let router = fleet_coordinator::http::router(Arc::clone(&coord));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    Fleet {
        coord,
        base_url: format!("http://{addr}"),
        server,
    }
}

/// Seed a user with an **already expired** session and a live refresh token:
/// the exact state of the workstation in the reported failure.
async fn seed_expired_with_refresh(fleet: &Fleet, login: &str) -> (String, String) {
    let org = OrgId("default".to_owned());
    let db = fleet.coord.db();
    db.ensure_user_member(&org, login, Role::Admin)
        .await
        .unwrap();
    let now = i64::try_from(fleet.coord.now()).unwrap();

    let session = OpaqueToken::mint(TokenKind::Session);
    db.insert_session(session.hash().as_str(), &org, login, now - 86_400, now - 60)
        .await
        .unwrap();

    let refresh = OpaqueToken::mint(TokenKind::Refresh);
    db.insert_refresh_token(
        refresh.hash().as_str(),
        &org,
        login,
        now,
        now + 30 * 24 * 3600,
    )
    .await
    .unwrap();

    (session.to_secret_string(), refresh.to_secret_string())
}

/// Does this token open `/client`? The honest liveness check: it goes through
/// the coordinator's real authentication path.
async fn token_works(fleet: &Fleet, token: &str) -> bool {
    fleet_wire::client::dial(fleet_wire::client::DialOpts {
        url: fleet.base_url.clone(),
        path: "/client",
        bearer: token.to_owned(),
        pin: None,
    })
    .await
    .is_ok()
}

/// Write a fleet file at the XDG path the renewal code will re-read and patch.
fn write_fleet_file(base_url: &str, session: &str, refresh: Option<&str>, expires: Option<u64>) {
    let path = fleet_bin::paths::fleet_config_path("default").unwrap();
    fleet_bin::fleet_config::update(&path, |f| {
        base_url.clone_into(&mut f.url);
        f.user = Some(fleet_bin::fleet_config::UserSection {
            session_token: session.to_owned(),
            org: "default".to_owned(),
            login: Some("kaspar".to_owned()),
            expires,
            refresh_token: refresh.map(ToOwned::to_owned),
        });
    })
    .unwrap();
}

/// **The reported bug.** An expired `[user]` session plus a valid refresh token
/// resolves, through the shim's own credential path, to a token that actually
/// opens `/client` — and the renewed session is written back to disk, so the
/// next invocation in the same build does no round trip at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sidecar_renews_an_expired_user_session_and_persists_it() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let tmp = tempfile::tempdir().unwrap();
    let prev = std::env::var_os("XDG_CONFIG_HOME");
    // SAFETY of correctness (not memory): guarded by ENV_LOCK above.
    std::env::set_var("XDG_CONFIG_HOME", tmp.path());
    // ...and the shim skips its refresh entirely when this is set, which would
    // make the test pass for the wrong reason.
    let prev_token = std::env::var_os("PROBE_RS_FLEET_TOKEN");
    std::env::remove_var("PROBE_RS_FLEET_TOKEN");

    let fleet = start_fleet().await;
    let (expired, refresh) = seed_expired_with_refresh(&fleet, "kaspar").await;
    let now = fleet.coord.now();
    write_fleet_file(
        &fleet.base_url,
        &expired,
        Some(&refresh),
        Some(now.saturating_sub(60)),
    );

    // Precondition: the stored session really is dead. Without this the
    // assertion below could pass on a session that never needed renewing.
    assert!(
        !token_works(&fleet, &expired).await,
        "the stored session must already be expired"
    );

    let (url, token, _pin) = fleet_bin::roles::sidecar::resolve_client_config_for_test("default")
        .await
        .expect("the shim must resolve a credential from the fleet file");
    assert_eq!(url, fleet.base_url);
    assert_ne!(token, expired, "the shim must not hand back a dead token");
    assert!(
        token_works(&fleet, &token).await,
        "this is the reported bug: the shim's token must actually work"
    );

    // Persisted, so the next `probe-rs` in the build reuses it.
    let path = fleet_bin::paths::fleet_config_path("default").unwrap();
    let user = fleet_bin::fleet_config::load(&path).unwrap().user.unwrap();
    assert_eq!(user.session_token, token);
    assert!(user.expires.is_some_and(|e| e > now));
    assert_eq!(
        user.refresh_token.as_deref(),
        Some(refresh.as_str()),
        "redemption is non-rotating: the durable credential must survive"
    );

    // SAFETY of correctness (not memory): guarded by ENV_LOCK above.
    match prev {
        Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
        None => std::env::remove_var("XDG_CONFIG_HOME"),
    }
    if let Some(v) = prev_token {
        std::env::set_var("PROBE_RS_FLEET_TOKEN", v);
    }
}

/// Today's shape, unchanged: an expired session with **no** refresh token gets
/// the shim nothing better than what it had, and — crucially — does not stall.
///
/// The shim runs once per `probe-rs` invocation, so a doomed 30-second refresh
/// here would turn a clear 401 into a multi-minute build slowdown. The elapsed
/// assertion is the one that would catch that.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_without_a_refresh_token_behaves_exactly_as_before() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let tmp = tempfile::tempdir().unwrap();
    let prev = std::env::var_os("XDG_CONFIG_HOME");
    // SAFETY of correctness (not memory): guarded by ENV_LOCK above.
    std::env::set_var("XDG_CONFIG_HOME", tmp.path());
    let prev_token = std::env::var_os("PROBE_RS_FLEET_TOKEN");
    std::env::remove_var("PROBE_RS_FLEET_TOKEN");

    let fleet = start_fleet().await;
    let (expired, _refresh) = seed_expired_with_refresh(&fleet, "kaspar").await;
    let now = fleet.coord.now();
    write_fleet_file(
        &fleet.base_url,
        &expired,
        None,
        Some(now.saturating_sub(60)),
    );

    let started = std::time::Instant::now();
    let (_url, token, _pin) = fleet_bin::roles::sidecar::resolve_client_config_for_test("default")
        .await
        .expect("a fleet file with a [user] table still resolves");
    // The stored token, warned about and handed on: a shim that refuses to
    // start is worse than one that produces a clear auth failure.
    assert_eq!(token, expired);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the shim must not stall on a refresh the coordinator would refuse"
    );

    // SAFETY of correctness (not memory): guarded by ENV_LOCK above.
    match prev {
        Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
        None => std::env::remove_var("XDG_CONFIG_HOME"),
    }
    if let Some(v) = prev_token {
        std::env::set_var("PROBE_RS_FLEET_TOKEN", v);
    }
}

/// `logout --all` through the real CLI verb: after it, neither credential
/// works against the coordinator, and the local file no longer holds either.
///
/// This is the whole justification for issuing a 30-day durable credential, so
/// it is asserted end to end rather than at the route.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_all_revokes_both_credentials_end_to_end() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let tmp = tempfile::tempdir().unwrap();
    let prev = std::env::var_os("XDG_CONFIG_HOME");
    // SAFETY of correctness (not memory): guarded by ENV_LOCK above.
    std::env::set_var("XDG_CONFIG_HOME", tmp.path());

    let fleet = start_fleet().await;
    let org = OrgId("default".to_owned());
    fleet
        .coord
        .db()
        .ensure_user_member(&org, "kaspar", Role::Admin)
        .await
        .unwrap();
    let now = i64::try_from(fleet.coord.now()).unwrap();

    let session = OpaqueToken::mint(TokenKind::Session);
    fleet
        .coord
        .db()
        .insert_session(session.hash().as_str(), &org, "kaspar", now, now + 3_600)
        .await
        .unwrap();
    let refresh = OpaqueToken::mint(TokenKind::Refresh);
    fleet
        .coord
        .db()
        .insert_refresh_token(refresh.hash().as_str(), &org, "kaspar", now, now + 86_400)
        .await
        .unwrap();
    let session = session.to_secret_string();
    let refresh = refresh.to_secret_string();

    write_fleet_file(
        &fleet.base_url,
        &session,
        Some(&refresh),
        Some(u64::try_from(now + 3_600).unwrap()),
    );
    assert!(token_works(&fleet, &session).await);

    let path = fleet_bin::paths::fleet_config_path("default").unwrap();
    fleet_bin::roles::logout::run(fleet_bin::cli::LogoutArgs {
        all: true,
        fleet: "default".to_owned(),
        // The XDG path deliberately, so the verb and the renewal code agree on
        // one file — the same reason `agent_login_e2e` passes `None`.
        config_dir: None,
    })
    .await
    .expect("logout --all");

    assert!(
        !token_works(&fleet, &session).await,
        "the session must be dead server-side, not merely forgotten locally"
    );
    let (status, _) = redeem(&fleet, &refresh).await;
    assert_eq!(
        status, 401,
        "the durable credential must be revoked, or logout means nothing"
    );
    assert!(
        fleet_bin::fleet_config::load(&path).unwrap().user.is_none(),
        "[user] must be cleared locally too"
    );

    // SAFETY of correctness (not memory): guarded by ENV_LOCK above.
    match prev {
        Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
        None => std::env::remove_var("XDG_CONFIG_HOME"),
    }
}

/// Can this refresh token still mint? Driven through the *client helper*
/// rather than a hand-rolled request, so the test exercises the same code path
/// `ensure_fresh_session` does.
async fn redeem(fleet: &Fleet, refresh: &str) -> (u16, String) {
    match fleet_auth::http_client::redeem_refresh_token(&fleet.base_url, None, refresh).await {
        Ok(response) => (200, response.token),
        Err(fleet_auth::http_client::ClientError::Rejected { status, code }) => (status, code),
        Err(e) => panic!("unexpected transport failure: {e}"),
    }
}
