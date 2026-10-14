//! `probefleet agent login` end to end, through the CLI's own code paths.
//!
//! The story this task exists for: a persistent sandbox with concurrent users
//! is handed a `--purpose agent --as <name> --multi-use` key once, and from
//! then on holds a **self-renewing** fleet session — no cron job, no hourly
//! `eval "$(probefleet ci login …)"`, and no per-process wrapper.
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
//! `ENV_LOCK`. That lock is per-binary: `probefleet::test_support::ENV_LOCK` is
//! `pub(crate)`, so an integration test cannot reach it.
//!
//! The guard is held across `await` points on purpose: what it protects is the
//! process environment for the whole test body. Each test is its own
//! `#[tokio::test]` runtime, so there is no task to starve.
#![allow(clippy::await_holding_lock)]

mod common;

use std::sync::Mutex;

use common::{start_fleet, Fleet};
use probefleet::cli::{AgentLoginArgs, LoginArgs};
use probefleet_coordinator::FleetRole;

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
        let fleet_file = probefleet::paths::fleet_config_path("default").unwrap();
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

/// A session token for `login`, a member of the default org, as
/// `coordinator user-token` mints it. forgs' default lifetime is comfortably
/// outside `REFRESH_SKEW_SECS`, so the `[user]` half of the file is never
/// itself refreshed by anything here.
async fn mint_user_token(fleet: &Fleet, login: &str) -> String {
    fleet.session(login, FleetRole::Member).await
}

/// Mint an `--purpose agent --as <name>` auth key directly in the coordinator's
/// database, as `auth-key create` does over the API.
async fn mint_agent_key(fleet: &Fleet, name: &str, single_use: bool) -> String {
    fleet
        .api_key(
            common::DEFAULT_ORG,
            // `agent` is CLI sugar; the database holds `ci`.
            "ci",
            serde_json::json!({ "tags": ["nrf52"], "ops": [] }),
            single_use,
            Some(name),
        )
        .await
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
    let fleet = start_fleet(SEED).await;

    // The sandbox's operator is a logged-in human on this same machine: the
    // `[user]` table must survive, since that is the read-modify-write rule the
    // whole file format rests on.
    let session = mint_user_token(&fleet, "alice").await;
    probefleet::roles::login::run(LoginArgs {
        fleet_url: Some(fleet.base_url.clone()),
        server_cert_sha256: None,
        token: Some(session.clone()),
        refresh_token: None,
        no_browser: true,
        org: Some(common::DEFAULT_ORG.to_owned()),
        fleet: "default".to_owned(),
        // The XDG path, deliberately: `ensure_fresh_agent_session` writes there
        // and nowhere else, so the two halves must agree on one file.
        config_dir: None,
    })
    .await
    .expect("login --token");

    let key = mint_agent_key(&fleet, "desk-bot", false).await;
    probefleet::roles::agent_login::run(
        agent_login_args(&fleet, &key, Some("desk-bot")),
        "default",
        None,
    )
    .await
    .expect("agent login");

    let path = xdg.fleet_file();
    let file = probefleet::fleet_config::load(path).unwrap();
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
    let ns = probefleet_coordinator::subject::ns_of(&fleet.default_org().await).unwrap();
    let grants = fleet
        .coord
        .db()
        .forgs()
        .scoped(ns)
        .list_grants()
        .await
        .unwrap();
    assert_eq!(grants.len(), 1);
    assert!(
        grants[0].subject.ends_with("workload:agent:desk-bot"),
        "{}",
        grants[0].subject
    );

    // --- the renewal ---------------------------------------------------
    //
    // Age the stored session past its expiry, exactly as an hour of wall clock
    // would, and ask for a usable token.
    let stale = probefleet::fleet_config::update(path, |f| {
        f.agent.as_mut().unwrap().expires = 1;
    })
    .unwrap();
    let before = stale.agent.as_ref().unwrap().workload_token.clone();

    let refreshed = probefleet::fleet_config::ensure_fresh_agent_session("default", &stale)
        .await
        .expect("the stored auth key re-mints a session with no human involved");
    assert_ne!(
        refreshed, before,
        "a genuinely new token, not the stale one"
    );
    assert!(refreshed.starts_with("prfw1_"));

    // ...and it was persisted, so the next process in the sandbox reuses it
    // instead of minting its own.
    let after = probefleet::fleet_config::load(path).unwrap();
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
    let fleet = start_fleet(SEED).await;

    let key = mint_agent_key(&fleet, "desk-bot", false).await;
    probefleet::roles::agent_login::run(
        agent_login_args(&fleet, &key, Some("desk-bot")),
        "default",
        None,
    )
    .await
    .expect("agent login");
    let path = xdg.fleet_file();

    // Our snapshot: the session this process loaded, now expired.
    let mut snapshot = probefleet::fleet_config::load(path).unwrap();
    snapshot.agent.as_mut().unwrap().expires = 1;

    // Meanwhile a peer redeemed and wrote a fresh token to the shared file.
    let peer = probefleet::fleet_config::ensure_fresh_agent_session("default", &snapshot)
        .await
        .expect("the peer's refresh");

    // We now ask with our *stale* snapshot. The pre-redemption re-read must
    // hand back the peer's token rather than minting a third one.
    let ours = probefleet::fleet_config::ensure_fresh_agent_session("default", &snapshot)
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
    let after = probefleet::fleet_config::load(path).unwrap();
    assert_eq!(after.agent.as_ref().unwrap().workload_token, peer);
}

/// A single-use key cannot back a persistent session, and saying so beats
/// half-working until the second process starts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_single_use_key_is_refused_and_writes_nothing() {
    let _guard = lock_env();
    let xdg = XdgHome::set();
    let fleet = start_fleet(SEED).await;

    let key = mint_agent_key(&fleet, "desk-bot", true).await;
    let err = probefleet::roles::agent_login::run(
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
    let agent = probefleet::fleet_config::load(path)
        .ok()
        .and_then(|f| f.agent);
    assert!(agent.is_none(), "a refused login writes no [agent] table");
}

/// A key that is not an auth key at all is refused locally, before any request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_kind_of_credential_never_reaches_the_coordinator() {
    let _guard = lock_env();
    let xdg = XdgHome::set();
    let fleet = start_fleet(SEED).await;

    let session = mint_user_token(&fleet, "alice").await;
    let err = probefleet::roles::agent_login::run(
        agent_login_args(&fleet, &session, None),
        "default",
        None,
    )
    .await
    .expect_err("a session token is not an auth key");
    assert!(format!("{err:#}").contains("prfk1_"), "got: {err:#}");
    assert!(!xdg.fleet_file().exists());
}
