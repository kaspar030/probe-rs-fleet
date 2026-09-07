//! `probe-rs-fleet share` end to end, through the CLI's own code paths.
//!
//! The story-2 payoff, asserted rather than assumed: on a machine that has
//! logged in, one command makes it a node — no token, no coordinator shell, no
//! out-of-band step — and the credential it writes **works against a live
//! coordinator** rather than merely being a file that parses.
//!
//! Modelled on `bearer_e2e.rs`, which does the same for the auth-key path. As
//! there, `login --token` stands in for the device flow: the flow itself is
//! covered against a stub GitHub in `fleet-coordinator/tests/device_flow.rs`,
//! and these tests are about what the CLI writes and whether it works.

use std::sync::Arc;

use fleet_auth::{OpaqueToken, TokenKind};
use fleet_bin::cli::{AdoptArg, LoginArgs, NodeUpFlags, ShareArgs};
use fleet_coordinator::auth::Ed25519Signer;
use fleet_coordinator::clock::SystemClock;
use fleet_coordinator::config::{CoordinatorConfig, SigningKeySource};
use fleet_coordinator::core::Coordinator;
use fleet_coordinator::state::Db;
use fleet_core::policy::Policy;
use fleet_core::scheduler::Scheduler;
use fleet_proto::ids::{NodeId, OrgId, Role};
use fleet_proto::AdoptPolicy;

const SEED: [u8; 32] = [23u8; 32];

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

/// Mint a session token the way `coordinator user-token` does — including the
/// membership, without which the token authenticates and then authorizes
/// nothing (and `share` would be refused with a 403).
async fn mint_user_token(fleet: &Fleet, org: &str, login: &str) -> String {
    let org = OrgId(org.to_owned());
    fleet
        .coord
        .db()
        .ensure_user_member(&org, login, Role::Admin)
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

/// Run `login --token` into `config_dir`, returning the session token written.
async fn login(fleet: &Fleet, config_dir: &std::path::Path, login_name: &str) -> String {
    let token = mint_user_token(fleet, "default", login_name).await;
    fleet_bin::roles::login::run(LoginArgs {
        fleet_url: Some(fleet.base_url.clone()),
        server_cert_sha256: None,
        token: Some(token.clone()),
        no_browser: true,
        fleet: "default".to_owned(),
        config_dir: Some(config_dir.to_path_buf()),
    })
    .await
    .expect("login --token");
    token
}

fn share_args(config_dir: &std::path::Path, node_name: &str) -> ShareArgs {
    ShareArgs {
        fleet: "default".to_owned(),
        node_name: Some(node_name.to_owned()),
        tag: vec![],
        adopt: None,
        force: false,
        config_dir: Some(config_dir.to_path_buf()),
    }
}

/// The whole point: `login` then `share`, and the machine is a node.
///
/// One fleet file, **both** tables, two distinct tokens, and the node token
/// actually authenticates on `/agent`. The node is owned by the user and its
/// adoption policy is `auto`, so the next thing that happens — plugging in a
/// probe — needs no further steps.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn login_then_share_yields_a_working_node_owned_by_the_user() {
    let fleet = start_fleet().await;
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("fleets");
    let session = login(&fleet, &config_dir, "alice").await;

    fleet_bin::roles::share::run(share_args(&config_dir, "alice-laptop"))
        .await
        .expect("share");

    let config_path = config_dir.join("default.toml");
    let file = fleet_bin::fleet_config::load(&config_path).unwrap();

    // Both tables, and the [user] one is byte-for-byte what login wrote.
    let user = file.user.clone().expect("[user] survived share");
    let node = file.node.clone().expect("[node] was written");
    assert_eq!(user.session_token, session);
    assert_ne!(user.session_token, node.node_token);
    assert!(node.node_token.starts_with("prfn1_"));
    assert_eq!(node.coordinator_token_pubkey.len(), 64);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&config_path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "the fleet file holds two bearer credentials and must be 0600"
        );
    }

    // Node-local settings are scaffolded, with the policy `share` chose written
    // out where the operator can read it.
    let node_toml = config_dir.join("node").join("node.toml");
    assert!(config_dir.join("node").join("boards.toml").exists());
    let settings = fleet_bin::roles::node_run::load_node_settings(&node_toml).unwrap();
    assert_eq!(settings.adopt, Some(AdoptPolicy::Auto));

    // ... and, the point of the whole test, the token actually connects.
    let (tx, rx) = fleet_wire::client::dial(fleet_wire::client::DialOpts {
        url: file.url.clone(),
        path: "/agent",
        bearer: node.node_token.clone(),
        pin: None,
    })
    .await
    .expect("the shared node's token must authenticate on /agent");
    drop((tx, rx));

    // The coordinator's row records the owner and the policy: "my laptop's
    // boards" is expressible, and auto-adoption is on.
    let node_id = NodeId(node.node_id.clone());
    assert_eq!(
        fleet
            .coord
            .db()
            .node_owner(&node_id)
            .await
            .unwrap()
            .as_deref(),
        Some("alice")
    );
    assert_eq!(
        fleet
            .coord
            .db()
            .node_org_and_policy(&node_id)
            .await
            .unwrap()
            .unwrap()
            .1,
        AdoptPolicy::Auto
    );
}

/// `--adopt declared` is honoured: `auto` is the default, not the only choice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn share_honours_an_explicit_adopt_policy() {
    let fleet = start_fleet().await;
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("fleets");
    login(&fleet, &config_dir, "alice").await;

    let mut args = share_args(&config_dir, "lab-laptop");
    args.adopt = Some(AdoptArg::Declared);
    fleet_bin::roles::share::run(args).await.expect("share");

    let file = fleet_bin::fleet_config::load(&config_dir.join("default.toml")).unwrap();
    let node_id = NodeId(file.node.unwrap().node_id);
    assert_eq!(
        fleet
            .coord
            .db()
            .node_org_and_policy(&node_id)
            .await
            .unwrap()
            .unwrap()
            .1,
        AdoptPolicy::Declared
    );

    let settings =
        fleet_bin::roles::node_run::load_node_settings(&config_dir.join("node").join("node.toml"))
            .unwrap();
    assert_eq!(settings.adopt, Some(AdoptPolicy::Declared));
}

/// `share` without a login must say so, naming `login` — not fail with an
/// opaque 401 from a command the user has no reason to associate with logging
/// in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn share_without_a_login_names_the_remedy() {
    let _fleet = start_fleet().await;
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("fleets");

    let err = fleet_bin::roles::share::run(share_args(&config_dir, "laptop"))
        .await
        .expect_err("share with no [user] must fail");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("login"),
        "the error must name `login`: {rendered}"
    );
    assert!(
        !config_dir.join("default.toml").exists(),
        "no config may be written when there is nothing to share with"
    );
}

/// Re-sharing is a deliberate act: the old node token stops working, and on a
/// machine somebody depends on that is not something to do by accident.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sharing_twice_without_force_is_refused() {
    let fleet = start_fleet().await;
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("fleets");
    login(&fleet, &config_dir, "alice").await;

    fleet_bin::roles::share::run(share_args(&config_dir, "laptop"))
        .await
        .expect("first share");
    let first = fleet_bin::fleet_config::load(&config_dir.join("default.toml"))
        .unwrap()
        .node
        .unwrap()
        .node_token;

    let err = fleet_bin::roles::share::run(share_args(&config_dir, "laptop"))
        .await
        .expect_err("a second share must be refused");
    assert!(format!("{err:#}").contains("--force"));

    // And the working credential is untouched.
    let after = fleet_bin::fleet_config::load(&config_dir.join("default.toml"))
        .unwrap()
        .node
        .unwrap()
        .node_token;
    assert_eq!(after, first);

    // With --force it goes through, and the old token is retired.
    let mut forced = share_args(&config_dir, "laptop");
    forced.force = true;
    // The operator has annotated a board in the meantime — stable id, chip
    // name, the things auto-adoption cannot infer. Re-sharing must not eat it:
    // `--force` replaces the *credential*, and `share --force` is the
    // documented way to re-share a machine, so this is exactly when the file
    // would be lost.
    let boards_path = config_dir.join("node").join("boards.toml");
    let mine = "[[board]]\nid = \"my-dk\"\nserial = \"ZZZ\"\nchip = \"nRF52840_xxAA\"\n";
    std::fs::write(&boards_path, mine).unwrap();

    fleet_bin::roles::share::run(forced)
        .await
        .expect("share --force");

    assert_eq!(
        std::fs::read_to_string(&boards_path).unwrap(),
        mine,
        "re-sharing must not destroy a hand-written board inventory"
    );

    let fresh = fleet_bin::fleet_config::load(&config_dir.join("default.toml"))
        .unwrap()
        .node
        .unwrap()
        .node_token;
    assert_ne!(fresh, first);
    assert!(fleet_wire::client::dial(fleet_wire::client::DialOpts {
        url: fleet.base_url.clone(),
        path: "/agent",
        bearer: first,
        pin: None,
    })
    .await
    .is_err());
}

/// `node up` on a laptop that has logged in takes the same path `share` does,
/// with no flags at all. This is §4.2's ladder rung 2, and the two verbs must
/// not drift: the same node row, the same policy, the same scaffolding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_up_self_registers_from_an_existing_session() {
    let fleet = start_fleet().await;
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("fleets");
    login(&fleet, &config_dir, "alice").await;

    fleet_bin::roles::node_up::bootstrap(
        &NodeUpFlags {
            fleet_url: None,
            auth_key: None,
            node_name: Some("laptop".to_owned()),
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
        Some(&config_dir),
    )
    .await
    .expect("node up with a session and no flags");

    let file = fleet_bin::fleet_config::load(&config_dir.join("default.toml")).unwrap();
    let node = file.node.expect("[node] written");
    assert!(file.user.is_some(), "[user] must survive");
    let node_id = NodeId(node.node_id);
    assert_eq!(
        fleet
            .coord
            .db()
            .node_owner(&node_id)
            .await
            .unwrap()
            .as_deref(),
        Some("alice")
    );
    assert_eq!(
        fleet
            .coord
            .db()
            .node_org_and_policy(&node_id)
            .await
            .unwrap()
            .unwrap()
            .1,
        AdoptPolicy::Auto,
        "the session path defaults to auto, exactly as `share` does"
    );
}

/// Rung 1 of the ladder: an existing `[node]` credential is reused, not
/// replaced. Re-registering a working node for no reason would invalidate the
/// token it is currently connected with.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_up_reuses_an_existing_node_credential() {
    let fleet = start_fleet().await;
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("fleets");
    login(&fleet, &config_dir, "alice").await;
    fleet_bin::roles::share::run(share_args(&config_dir, "laptop"))
        .await
        .expect("share");
    let before = fleet_bin::fleet_config::load(&config_dir.join("default.toml"))
        .unwrap()
        .node
        .unwrap()
        .node_token;

    fleet_bin::roles::node_up::bootstrap(
        &NodeUpFlags {
            fleet_url: None,
            auth_key: None,
            node_name: None,
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
        Some(&config_dir),
    )
    .await
    .expect("node up on an already-enrolled node");

    let after = fleet_bin::fleet_config::load(&config_dir.join("default.toml"))
        .unwrap()
        .node
        .unwrap()
        .node_token;
    assert_eq!(after, before, "a working credential must not be replaced");
}

/// Rung 5: nothing to work with, and no terminal to run the interactive rung
/// on. `node up` must name every way out — login, interactive approval, and an
/// auth key — rather than doing nothing quietly on a machine someone is waiting
/// on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_up_with_no_credential_at_all_explains_itself() {
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("fleets");

    let err = fleet_bin::roles::node_up::bootstrap(
        &NodeUpFlags {
            fleet_url: None,
            auth_key: None,
            node_name: None,
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
        Some(&config_dir),
    )
    .await
    .expect_err("no credential and no way to get one");
    let rendered = format!("{err:#}");
    assert!(rendered.contains("--auth-key"), "got: {rendered}");
    assert!(rendered.contains("login"), "got: {rendered}");
    // A key is mintable without a shell on the coordinator (task 3454), so the
    // remediation must point at the command that mints one.
    assert!(rendered.contains("auth-key create"), "got: {rendered}");
    // ... and the interactive rung exists now, so it is offered, together with
    // why it was skipped here.
    assert!(rendered.contains("--interactive"), "got: {rendered}");
    assert!(
        rendered.contains("Interactive approval was disabled"),
        "got: {rendered}"
    );
}

/// An explicit `--auth-key` beats a session that merely happens to be present:
/// passing it is a deliberate act, and a provisioning script run on a laptop
/// should enroll the node it was told to.
///
/// Documented as a deliberate deviation from §4.2's listed ordering.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_explicit_auth_key_beats_an_incidental_session() {
    let fleet = start_fleet().await;
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("fleets");
    login(&fleet, &config_dir, "alice").await;

    let org = OrgId("default".to_owned());
    let key = OpaqueToken::mint(TokenKind::AuthKey);
    let now = i64::try_from(fleet.coord.now()).unwrap();
    fleet
        .coord
        .db()
        .insert_auth_key(&org, key.hash().as_str(), &[], true, None, None, now)
        .await
        .unwrap();

    fleet_bin::roles::node_up::bootstrap(
        &NodeUpFlags {
            fleet_url: Some(fleet.base_url.clone()),
            auth_key: Some(key.to_secret_string()),
            node_name: Some("ci-runner".to_owned()),
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
        Some(&config_dir),
    )
    .await
    .expect("node up --auth-key");

    let file = fleet_bin::fleet_config::load(&config_dir.join("default.toml")).unwrap();
    let node_id = NodeId(file.node.unwrap().node_id);
    // The auth-key path leaves the node unowned and `declared` — which is how
    // you can tell which rung ran.
    assert!(fleet
        .coord
        .db()
        .node_owner(&node_id)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        fleet
            .coord
            .db()
            .node_org_and_policy(&node_id)
            .await
            .unwrap()
            .unwrap()
            .1,
        AdoptPolicy::Declared
    );
}
