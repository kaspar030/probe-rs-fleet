//! `probe-rs-fleet agent login` end to end, through the CLI's own code paths.
//!
//! The story this task exists for: a persistent sandbox with concurrent users
//! is handed a `--purpose agent --as <name> --multi-use` key once, and from
//! then on holds a **self-renewing** fleet session — no cron job, no hourly
//! `eval "$(probe-rs-fleet ci login …)"`, and no per-process wrapper.
//!
//! Modelled on `auth_key_e2e.rs` + `ci_e2e.rs`: an in-process coordinator on
//! loopback, driving the role functions rather than a subprocess. Everything
//! but the human is real — the redemption, the grant upsert, the token mint.
//!
//! # Why this file sets `XDG_CONFIG_HOME`, unlike `auth_key_e2e.rs`
//!
//! The *refresh* half of this feature is unreachable from a unit test with a
//! `--config-dir`. `fleet_config::ensure_fresh_agent_session` persists through
//! `update_named` and re-reads through `load_named_opt`, both of which resolve
//! the **XDG** path and ignore `--config-dir` — the pre-existing wart
//! `auth_key_e2e.rs`'s header documents and deliberately stays outside of. The
//! only honest way to exercise the refresh is to point XDG at a tempdir, which
//! is process-global state, which is why every test here takes this file's own
//! `ENV_LOCK`. That lock is per-binary: `fleet_bin::test_support::ENV_LOCK` is
//! `pub(crate)`, so an integration test cannot reach it.
//!
//! The guard is held across `await` points on purpose: what it protects is the
//! process environment for the whole test body. Each test is its own
//! `#[tokio::test]` runtime, so there is no task to starve.
#![allow(clippy::await_holding_lock)]

use std::sync::{Arc, Mutex};

use fleet_auth::{OpaqueToken, TokenKind};
use fleet_bin::cli::{AgentLoginArgs, LoginArgs};
use fleet_coordinator::auth::Ed25519Signer;
use fleet_coordinator::clock::SystemClock;
use fleet_coordinator::config::{CoordinatorConfig, SigningKeySource};
use fleet_coordinator::core::Coordinator;
use fleet_coordinator::state::Db;
use fleet_core::policy::Policy;
use fleet_core::scheduler::Scheduler;
use fleet_proto::ids::{OrgId, Role};

const SEED: [u8; 32] = [31u8; 32];

/// Serialises the tests in this file, which all repoint `XDG_CONFIG_HOME`.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Take [`ENV_LOCK`], ignoring poisoning.
///
/// A panicking test poisons the lock; the *next* test would then fail for a
/// reason that has nothing to do with it, turning one failure into a cascade
/// and hiding the real one.
fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `XDG_CONFIG_HOME` pointed at a tempdir for the duration of a test.
struct XdgHome {
    _dir: tempfile::TempDir,
    fleet_file: std::path::PathBuf,
    previous: Option<std::ffi::OsString>,
}

impl XdgHome {
    fn set() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("XDG_CONFIG_HOME");
        // SAFETY of correctness (not memory): callers hold ENV_LOCK.
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        // Resolved here, while the override is in force: this is the path the
        // role functions and `update_named` will reach for, and computing it
        // once is what makes the tests below assert against *that* file rather
        // than one they constructed themselves.
        let fleet_file = fleet_bin::paths::fleet_config_path("default").unwrap();
        Self {
            _dir: dir,
            fleet_file,
            previous,
        }
    }

    /// Where `paths::fleet_config_path("default")` resolves to while this guard
    /// is alive.
    fn fleet_file(&self) -> &std::path::Path {
        &self.fleet_file
    }
}

impl Drop for XdgHome {
    fn drop(&mut self) {
        // SAFETY of correctness (not memory): callers hold ENV_LOCK.
        match self.previous.take() {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
    }
}

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

/// Mint a session token with its membership, as `coordinator user-token` does.
///
/// An hour of life: comfortably outside `REFRESH_SKEW_SECS`, so the `[user]`
/// half of the file is never itself refreshed by anything here.
async fn mint_user_token(fleet: &Fleet, login: &str) -> String {
    let org = OrgId("default".to_owned());
    fleet
        .coord
        .db()
        .ensure_user_member(&org, login, Role::Member)
        .await
        .unwrap();
    let token = OpaqueToken::mint(TokenKind::Session);
    let now = i64::try_from(fleet.coord.now()).unwrap();
    fleet
        .coord
        .db()
        .insert_session(token.hash().as_str(), &org, login, now, now + 3_600)
        .await
        .unwrap();
    token.to_secret_string()
}

/// Mint an `--purpose agent --as <name>` auth key directly in the coordinator's
/// database, as `auth-key create` does over the API.
async fn mint_agent_key(fleet: &Fleet, name: &str, single_use: bool) -> String {
    let org = OrgId("default".to_owned());
    let now = i64::try_from(fleet.coord.now()).unwrap();
    let key = OpaqueToken::mint(TokenKind::AuthKey);
    fleet
        .coord
        .db()
        .insert_auth_key_with_purpose(
            &org,
            key.hash().as_str(),
            &["nrf52".to_owned()],
            single_use,
            Some(now + 86_400),
            None,
            now,
            // `agent` is CLI sugar; the database holds `ci`.
            "ci",
            &[],
            Some(name),
        )
        .await
        .unwrap();
    key.to_secret_string()
}

fn agent_login_args(fleet: &Fleet, key: &str, name: Option<&str>) -> AgentLoginArgs {
    AgentLoginArgs {
        fleet_url: Some(fleet.base_url.clone()),
        server_cert_sha256: None,
        auth_key: key.to_owned(),
        subject_name: name.map(ToOwned::to_owned),
    }
}

/// The whole feature, in order: log in, `agent login`, then age the session out
/// and watch it renew itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_login_writes_a_session_that_renews_itself() {
    let _guard = lock_env();
    let xdg = XdgHome::set();
    let fleet = start_fleet().await;

    // The sandbox's operator is a logged-in human on this same machine: the
    // `[user]` table must survive, since that is the read-modify-write rule the
    // whole file format rests on.
    let session = mint_user_token(&fleet, "alice").await;
    fleet_bin::roles::login::run(LoginArgs {
        fleet_url: Some(fleet.base_url.clone()),
        server_cert_sha256: None,
        token: Some(session.clone()),
        no_browser: true,
        fleet: "default".to_owned(),
        // The XDG path, deliberately: `ensure_fresh_agent_session` writes there
        // and nowhere else, so the two halves must agree on one file.
        config_dir: None,
    })
    .await
    .expect("login --token");

    let key = mint_agent_key(&fleet, "desk-bot", false).await;
    fleet_bin::roles::agent_login::run(
        agent_login_args(&fleet, &key, Some("desk-bot")),
        "default",
        None,
    )
    .await
    .expect("agent login");

    let path = xdg.fleet_file();
    let file = fleet_bin::fleet_config::load(path).unwrap();
    let agent = file.agent.clone().expect("[agent] was written");
    assert!(
        agent.workload_token.starts_with("prfw1_"),
        "a real workload token, not a plausible-looking string: {}",
        &agent.workload_token[..8.min(agent.workload_token.len())]
    );
    assert_eq!(agent.auth_key, key, "the durable credential is stored");
    assert_eq!(agent.name.as_deref(), Some("desk-bot"));
    assert!(agent.expires > 0, "expiry is required, not optional");
    assert_eq!(
        file.user.as_ref().unwrap().session_token,
        session,
        "[user] must survive an agent login"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the durable key is 0600");
    }

    // The redemption synthesised the identity's grant, which is what makes the
    // sandbox's access ordinary and revocable.
    let grants = fleet
        .coord
        .db()
        .scoped(OrgId("default".to_owned()))
        .list_grants()
        .await
        .unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].subject, "default/workload:agent:desk-bot");

    // --- the renewal ---------------------------------------------------
    //
    // Age the stored session past its expiry, exactly as an hour of wall clock
    // would, and ask for a usable token.
    let stale = fleet_bin::fleet_config::update(path, |f| {
        f.agent.as_mut().unwrap().expires = 1;
    })
    .unwrap();
    let before = stale.agent.as_ref().unwrap().workload_token.clone();

    let refreshed = fleet_bin::fleet_config::ensure_fresh_agent_session("default", &stale)
        .await
        .expect("the stored auth key re-mints a session with no human involved");
    assert_ne!(
        refreshed, before,
        "a genuinely new token, not the stale one"
    );
    assert!(refreshed.starts_with("prfw1_"));

    // ...and it was persisted, so the next process in the sandbox reuses it
    // instead of minting its own.
    let after = fleet_bin::fleet_config::load(path).unwrap();
    let after_agent = after.agent.as_ref().unwrap();
    assert_eq!(after_agent.workload_token, refreshed);
    assert!(after_agent.expires > 1, "the new expiry was written too");
    assert_eq!(after_agent.auth_key, key, "the key is not disturbed");
    assert_eq!(
        after.user.as_ref().unwrap().session_token,
        session,
        "[user] survives a refresh too"
    );
}

/// The concurrency case at the file seam: a peer process in the same sandbox
/// refreshed while our snapshot was in memory, so we take its token and redeem
/// nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_process_refresh_is_shared_rather_than_duplicated() {
    let _guard = lock_env();
    let xdg = XdgHome::set();
    let fleet = start_fleet().await;

    let key = mint_agent_key(&fleet, "desk-bot", false).await;
    fleet_bin::roles::agent_login::run(
        agent_login_args(&fleet, &key, Some("desk-bot")),
        "default",
        None,
    )
    .await
    .expect("agent login");
    let path = xdg.fleet_file();

    // Our snapshot: the session this process loaded, now expired.
    let mut snapshot = fleet_bin::fleet_config::load(path).unwrap();
    snapshot.agent.as_mut().unwrap().expires = 1;

    // Meanwhile a peer redeemed and wrote a fresh token to the shared file.
    let peer = fleet_bin::fleet_config::ensure_fresh_agent_session("default", &snapshot)
        .await
        .expect("the peer's refresh");

    // We now ask with our *stale* snapshot. The pre-redemption re-read must
    // hand back the peer's token rather than minting a third one.
    let ours = fleet_bin::fleet_config::ensure_fresh_agent_session("default", &snapshot)
        .await
        .expect("the peer's token is reused");
    assert_eq!(ours, peer, "concurrent processes share one session");

    // Token equality *is* the "minted nothing" assertion: a workload token is
    // random, so a second redemption could not have produced this value. The
    // file agrees, which is what the next process in the sandbox will read.
    //
    // (The coordinator-side count is deliberately not asserted: `Db` exposes no
    // way to count `workload_token` rows, and reaching into its pool to add one
    // would test the schema rather than this behaviour.)
    let after = fleet_bin::fleet_config::load(path).unwrap();
    assert_eq!(after.agent.as_ref().unwrap().workload_token, peer);
}

/// A single-use key cannot back a persistent session, and saying so beats
/// half-working until the second process starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_single_use_key_is_refused_and_writes_nothing() {
    let _guard = lock_env();
    let xdg = XdgHome::set();
    let fleet = start_fleet().await;

    let key = mint_agent_key(&fleet, "desk-bot", true).await;
    let err = fleet_bin::roles::agent_login::run(
        agent_login_args(&fleet, &key, Some("desk-bot")),
        "default",
        None,
    )
    .await
    .expect_err("a single-use key must be refused");

    let text = format!("{err:#}");
    assert!(text.contains("single-use"), "got: {text}");
    assert!(text.contains("PROCESS"), "got: {text}");
    assert!(text.contains("--multi-use"), "got: {text}");
    assert!(text.contains("spent"), "got: {text}");

    // Nothing half-written: no `[agent]` table, and on a machine with no
    // previous login, no file at all.
    let path = xdg.fleet_file();
    let agent = fleet_bin::fleet_config::load(path)
        .ok()
        .and_then(|f| f.agent);
    assert!(agent.is_none(), "a refused login writes no [agent] table");
}

/// A key that is not an auth key at all is refused locally, before any request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_kind_of_credential_never_reaches_the_coordinator() {
    let _guard = lock_env();
    let xdg = XdgHome::set();
    let fleet = start_fleet().await;

    let session = mint_user_token(&fleet, "alice").await;
    let err = fleet_bin::roles::agent_login::run(
        agent_login_args(&fleet, &session, None),
        "default",
        None,
    )
    .await
    .expect_err("a session token is not an auth key");
    assert!(format!("{err:#}").contains("prffk1_"), "got: {err:#}");
    assert!(!xdg.fleet_file().exists());
}
