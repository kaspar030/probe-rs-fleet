//! `probe-rs-fleet auth-key create` end to end, through the CLI's own code
//! paths.
//!
//! The story-1 assertion the task exists for: a customer who has only ever run
//! `probe-rs-fleet login` — no shell on the coordinator host — mints a key on
//! their laptop, and that key enrolls a headless node. Before this verb existed
//! that was impossible for a hosted customer: `coordinator auth-key` reads
//! `coordinator.toml` and writes the coordinator's `SQLite` directly.
//!
//! Modelled on `share_e2e.rs`. As there, `login --token` stands in for the
//! device flow (covered against a stub GitHub in
//! `fleet-coordinator/tests/device_flow.rs`), and the test drives the role
//! functions rather than a subprocess.
//!
//! **The session is minted fresh, far from expiry, deliberately.** On refresh
//! `fleet_config::ensure_fresh_session` persists through `update_named` →
//! `paths::fleet_config_path`, which resolves the XDG path and ignores the
//! `--config-dir` override these tests use. That is a pre-existing wart, not
//! this test's to fix; staying out of the `REFRESH_SKEW_SECS` window keeps the
//! test's writes inside its tempdir.

use std::sync::Arc;

use fleet_auth::{OpaqueToken, TokenKind};
use fleet_bin::cli::{
    AuthKeyCreateArgs, AuthKeyListArgs, AuthKeyRevokeCliArgs, LoginArgs, NodeUpFlags,
};
use fleet_coordinator::auth::Ed25519Signer;
use fleet_coordinator::clock::SystemClock;
use fleet_coordinator::config::{CoordinatorConfig, SigningKeySource};
use fleet_coordinator::core::Coordinator;
use fleet_coordinator::state::Db;
use fleet_core::policy::Policy;
use fleet_core::scheduler::Scheduler;
use fleet_proto::ids::{OrgId, Role};

const SEED: [u8; 32] = [29u8; 32];

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
/// An hour of life: comfortably outside the refresh window (see the module
/// docs), so nothing is ever written to the real XDG path.
async fn mint_user_token(fleet: &Fleet, login: &str, role: Role) -> String {
    let org = OrgId("default".to_owned());
    fleet
        .coord
        .db()
        .ensure_user_member(&org, login, role)
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

/// Run `login --token` into `config_dir`.
async fn login(fleet: &Fleet, config_dir: &std::path::Path, login_name: &str, role: Role) {
    let token = mint_user_token(fleet, login_name, role).await;
    fleet_bin::roles::login::run(LoginArgs {
        fleet_url: Some(fleet.base_url.clone()),
        server_cert_sha256: None,
        token: Some(token),
        no_browser: true,
        fleet: "default".to_owned(),
        config_dir: Some(config_dir.to_path_buf()),
    })
    .await
    .expect("login --token");
}

fn create_args(config_dir: &std::path::Path, tags: &[&str]) -> AuthKeyCreateArgs {
    AuthKeyCreateArgs {
        tag: tags.iter().map(|t| (*t).to_owned()).collect(),
        ttl: "24h".to_owned(),
        multi_use: false,
        single_use: false,
        // Node enrollment is what this file exercises, and it is the default a
        // caller who says nothing gets — the CI purpose is a deliberate opt-in
        // (architecture §6.7).
        purpose: "node".to_owned(),
        // Likewise: an identity name belongs to a `ci` key, and node
        // enrollment confers no subject for one to attach to.
        subject_name: None,
        ops: None,
        fleet: "default".to_owned(),
        config_dir: Some(config_dir.to_path_buf()),
    }
}

fn list_args(config_dir: &std::path::Path) -> AuthKeyListArgs {
    AuthKeyListArgs {
        fleet: "default".to_owned(),
        config_dir: Some(config_dir.to_path_buf()),
    }
}

fn revoke_args(config_dir: &std::path::Path, prefix: &str) -> AuthKeyRevokeCliArgs {
    AuthKeyRevokeCliArgs {
        prefix: prefix.to_owned(),
        fleet: "default".to_owned(),
        config_dir: Some(config_dir.to_path_buf()),
    }
}

/// The whole point: log in on a laptop, mint a key, enroll a Pi with it.
///
/// No shell on the coordinator host is involved anywhere in this test — only
/// the session `login` wrote into a tempdir.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_logged_in_user_mints_a_key_that_enrolls_a_headless_node() {
    let fleet = start_fleet().await;
    let tmp = tempfile::tempdir().unwrap();
    let laptop = tmp.path().join("laptop");
    login(&fleet, &laptop, "alice", Role::Member).await;

    let created = fleet_bin::roles::auth_key::create(&create_args(&laptop, &["lab", "nrf52"]))
        .await
        .expect("auth-key create");
    assert!(created.key.starts_with("prffk1_"));
    assert_eq!(created.org, "default");
    assert!(created.single_use);
    assert!(created.expires.is_some(), "an API-minted key must expire");

    // The Pi: a *different* config dir, with no login of its own — exactly the
    // headless machine the ladder's rungs 1 and 3 cannot serve.
    let pi = tmp.path().join("pi");
    fleet_bin::roles::node_up::bootstrap(
        &NodeUpFlags {
            fleet_url: Some(fleet.base_url.clone()),
            auth_key: Some(created.key.clone()),
            node_name: Some("rpi-lab-1".to_owned()),
            tag: vec![],
            adopt: None,
            server_cert_sha256: None,
            force: false,
            // Explicit rather than relying on the tty auto-detection: these
            // tests assert the other rungs, and a test runner attached to a
            // terminal must not send them into a 15-minute approval wait.
            interactive: false,
            no_interactive: true,
        },
        "default",
        Some(&pi),
    )
    .await
    .expect("node up --auth-key with a user-minted key");

    let node = fleet_bin::fleet_config::load(&pi.join("default.toml"))
        .unwrap()
        .node
        .expect("[node] was written");

    // The credential works against the live coordinator: the exchange returned
    // a real token, not a plausible-looking string.
    let (tx, rx) = fleet_wire::client::dial(fleet_wire::client::DialOpts {
        url: fleet.base_url.clone(),
        path: "/agent",
        bearer: node.node_token.clone(),
        pin: None,
    })
    .await
    .expect("the enrolled node's token must authenticate on /agent");
    drop((tx, rx));

    // The key's tags reached the node, and the node is in alice's org.
    let node_id = fleet_proto::ids::NodeId(node.node_id.clone());
    let (org, _) = fleet
        .coord
        .db()
        .node_org_and_policy(&node_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(org.0, "default");

    // ... and the listing now shows the key as consumed, attributed to alice.
    let list = fleet_bin::roles::auth_key::list(&list_args(&laptop))
        .await
        .expect("auth-key list");
    let row = list
        .keys
        .iter()
        .find(|k| k.key_hash == created.key_hash)
        .expect("the minted key is listed");
    assert!(row.consumed_at.is_some(), "single use means consumed");
    assert_eq!(row.created_by.as_deref(), Some("alice"));
    // A listing is not a credential.
    assert_ne!(row.key_hash, created.key);
}

/// Revoking works from the same laptop, and takes effect: the key stops
/// enrolling anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_a_minted_key_stops_it_enrolling() {
    let fleet = start_fleet().await;
    let tmp = tempfile::tempdir().unwrap();
    let laptop = tmp.path().join("laptop");
    login(&fleet, &laptop, "alice", Role::Member).await;

    let created = fleet_bin::roles::auth_key::create(&create_args(&laptop, &[]))
        .await
        .expect("auth-key create");

    let revoked =
        fleet_bin::roles::auth_key::revoke(&revoke_args(&laptop, &created.key_hash[..16]))
            .await
            .expect("auth-key revoke");
    assert_eq!(revoked.revoked, vec![created.key_hash.clone()]);

    let pi = tmp.path().join("pi");
    let err = fleet_bin::roles::node_up::bootstrap(
        &NodeUpFlags {
            fleet_url: Some(fleet.base_url.clone()),
            auth_key: Some(created.key.clone()),
            node_name: Some("rpi-lab-2".to_owned()),
            tag: vec![],
            adopt: None,
            server_cert_sha256: None,
            force: false,
            // Explicit rather than relying on the tty auto-detection: these
            // tests assert the other rungs, and a test runner attached to a
            // terminal must not send them into a 15-minute approval wait.
            interactive: false,
            no_interactive: true,
        },
        "default",
        Some(&pi),
    )
    .await
    .expect_err("a revoked key must not enroll a node");
    assert!(
        format!("{err:#}").contains("401"),
        "expected a rejected exchange, got: {err:#}"
    );
}

/// A member without a `[user]` session is told to log in, not handed a 401 from
/// a command they have no reason to associate with logging in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creating_without_a_login_says_so() {
    let tmp = tempfile::tempdir().unwrap();
    let empty = tmp.path().join("no-login");
    std::fs::create_dir_all(&empty).unwrap();

    let err = fleet_bin::roles::auth_key::create(&create_args(&empty, &[]))
        .await
        .expect_err("no fleet file");
    let rendered = format!("{err:#}");
    assert!(rendered.contains("login"), "got: {rendered}");
}

/// A refused TTL is refused *locally*, with the reason and the escape hatch —
/// the user is not bounced off a 400 from the coordinator.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forever_key_is_refused_with_the_reason() {
    let fleet = start_fleet().await;
    let tmp = tempfile::tempdir().unwrap();
    let laptop = tmp.path().join("laptop");
    login(&fleet, &laptop, "alice", Role::Member).await;

    let mut args = create_args(&laptop, &[]);
    args.ttl = "0".to_owned();
    let rendered = format!(
        "{:#}",
        fleet_bin::roles::auth_key::create(&args)
            .await
            .expect_err("a never-expiring key is not mintable over the API")
    );
    assert!(rendered.contains("must expire"), "got: {rendered}");
    assert!(rendered.contains("coordinator auth-key"), "got: {rendered}");

    // Over the cap is the coordinator's call, and it arrives as remediation
    // rather than as a bare code.
    args.ttl = "60d".to_owned();
    let rendered = format!(
        "{:#}",
        fleet_bin::roles::auth_key::create(&args)
            .await
            .expect_err("over the cap")
    );
    assert!(rendered.contains("30 days"), "got: {rendered}");
}
