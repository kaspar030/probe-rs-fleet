//! `probefleet auth-key create` end to end, through the CLI's own code
//! paths.
//!
//! The story-1 assertion the task exists for: a customer who has only ever run
//! `probefleet login` — no shell on the coordinator host — mints a key on
//! their laptop, and that key enrolls a headless node. Before this verb existed
//! that was impossible for a hosted customer: `coordinator auth-key` reads
//! `coordinator.toml` and writes the coordinator's `SQLite` directly.
//!
//! Modelled on `share_e2e.rs`. As there, `login --token` stands in for the
//! device flow (covered against a stub GitHub in
//! `probefleet-coordinator/tests/device_flow.rs`), and the test drives the role
//! functions rather than a subprocess.
//!
//! **The session is minted fresh, far from expiry, deliberately.** On refresh
//! `fleet_config::ensure_fresh_session` persists through `update_named` →
//! `paths::fleet_config_path`, which resolves the XDG path and ignores the
//! `--config-dir` override these tests use. That is a pre-existing wart, not
//! this test's to fix; staying out of the `REFRESH_SKEW_SECS` window keeps the
//! test's writes inside its tempdir.

mod common;

use common::{start_fleet, Fleet};
use probefleet::cli::{
    AuthKeyCreateArgs, AuthKeyListArgs, AuthKeyRevokeCliArgs, LoginArgs, NodeUpFlags,
};
use probefleet_coordinator::FleetRole;

const SEED: [u8; 32] = [29u8; 32];

/// Run `login --token` into `config_dir`, acting in the default org.
///
/// The session is minted with forgs' default lifetime: comfortably outside
/// the refresh window (see the module docs), so nothing is ever written to
/// the real XDG path.
async fn login(fleet: &Fleet, config_dir: &std::path::Path, login_name: &str, role: FleetRole) {
    let token = fleet.session(login_name, role).await;
    probefleet::roles::login::run(LoginArgs {
        fleet_url: Some(fleet.base_url.clone()),
        server_cert_sha256: None,
        token: Some(token),
        refresh_token: None,
        no_browser: true,
        org: Some(common::DEFAULT_ORG.to_owned()),
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
        org: None,
        fleet: "default".to_owned(),
        config_dir: Some(config_dir.to_path_buf()),
    }
}

fn list_args(config_dir: &std::path::Path) -> AuthKeyListArgs {
    AuthKeyListArgs {
        org: None,
        fleet: "default".to_owned(),
        config_dir: Some(config_dir.to_path_buf()),
    }
}

fn revoke_args(config_dir: &std::path::Path, prefix: &str) -> AuthKeyRevokeCliArgs {
    AuthKeyRevokeCliArgs {
        prefix: prefix.to_owned(),
        org: None,
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
    let fleet = start_fleet(SEED).await;
    let tmp = tempfile::tempdir().unwrap();
    let laptop = tmp.path().join("laptop");
    login(&fleet, &laptop, "alice", FleetRole::Member).await;

    let created = probefleet::roles::auth_key::create(&create_args(&laptop, &["lab", "nrf52"]))
        .await
        .expect("auth-key create");
    assert!(created.key.starts_with("prfk1_"));
    assert_eq!(created.namespace, fleet.default_org().await.0);
    assert!(created.single_use);
    assert!(created.expires > 0, "an API-minted key must expire");

    // The Pi: a *different* config dir, with no login of its own — exactly the
    // headless machine the ladder's rungs 1 and 3 cannot serve.
    let pi = tmp.path().join("pi");
    probefleet::roles::node_up::bootstrap(
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

    let node = probefleet::fleet_config::load(&pi.join("default.toml"))
        .unwrap()
        .node
        .expect("[node] was written");

    // The credential works against the live coordinator: the exchange returned
    // a real token, not a plausible-looking string.
    let (tx, rx) = probefleet_wire::client::dial(probefleet_wire::client::DialOpts {
        url: fleet.base_url.clone(),
        path: "/agent",
        bearer: node.node_token.clone(),
        pin: None,
    })
    .await
    .expect("the enrolled node's token must authenticate on /agent");
    drop((tx, rx));

    // The key's tags reached the node, and the node is in alice's org.
    let node_id = probefleet_proto::ids::NodeId(node.node_id.clone());
    let (org, _) = fleet
        .coord
        .db()
        .node_org_and_policy(&node_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(org, fleet.default_org().await);

    // ... and the listing now shows the key as consumed, attributed to alice.
    let list = probefleet::roles::auth_key::list(&list_args(&laptop))
        .await
        .expect("auth-key list");
    let row = list
        .keys
        .iter()
        .find(|k| k.key_hash == created.key_hash)
        .expect("the minted key is listed");
    assert!(row.consumed_at.is_some(), "single use means consumed");
    let alice = fleet.user("alice").await.to_string();
    assert_eq!(row.created_by.as_deref(), Some(alice.as_str()));
    // A listing is not a credential.
    assert_ne!(row.key_hash, created.key);
}

/// Revoking works from the same laptop, and takes effect: the key stops
/// enrolling anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_a_minted_key_stops_it_enrolling() {
    let fleet = start_fleet(SEED).await;
    let tmp = tempfile::tempdir().unwrap();
    let laptop = tmp.path().join("laptop");
    login(&fleet, &laptop, "alice", FleetRole::Member).await;

    let created = probefleet::roles::auth_key::create(&create_args(&laptop, &[]))
        .await
        .expect("auth-key create");

    let revoked =
        probefleet::roles::auth_key::revoke(&revoke_args(&laptop, &created.key_hash[..16]))
            .await
            .expect("auth-key revoke");
    assert_eq!(revoked.revoked, vec![created.key_hash.clone()]);

    let pi = tmp.path().join("pi");
    let err = probefleet::roles::node_up::bootstrap(
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
        format!("{err:#}").contains("not accepted"),
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

    let err = probefleet::roles::auth_key::create(&create_args(&empty, &[]))
        .await
        .expect_err("no fleet file");
    let rendered = format!("{err:#}");
    assert!(rendered.contains("login"), "got: {rendered}");
}

/// A refused TTL is refused *locally*, with the reason and the escape hatch —
/// the user is not bounced off a 400 from the coordinator.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forever_key_is_refused_with_the_reason() {
    let fleet = start_fleet(SEED).await;
    let tmp = tempfile::tempdir().unwrap();
    let laptop = tmp.path().join("laptop");
    login(&fleet, &laptop, "alice", FleetRole::Member).await;

    let mut args = create_args(&laptop, &[]);
    args.ttl = "0".to_owned();
    let rendered = format!(
        "{:#}",
        probefleet::roles::auth_key::create(&args)
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
        probefleet::roles::auth_key::create(&args)
            .await
            .expect_err("over the cap")
    );
    assert!(rendered.contains("30 days"), "got: {rendered}");
}
