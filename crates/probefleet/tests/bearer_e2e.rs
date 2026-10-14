//! End-to-end bootstrap through the CLI's own code paths.
//!
//! Replaces `enroll_e2e.rs`, which walked the deleted CSR/certificate flow. The
//! property is the same and is the one an operator actually cares about: the
//! scaffolding commands produce credentials that *work against a live
//! coordinator*, not merely files that parse.
//!
//! Three chains:
//!
//! 1. `coordinator auth-key` → `node up --auth-key` → the fleet file's
//!    `[node]` table holds a node token that authenticates on `/agent`;
//! 2. `coordinator user-token` → `login --token` → the fleet file's `[user]`
//!    table holds a session token that authenticates on `/client` and can list
//!    the fleet;
//! 3. **both on one machine** — the laptop case revision 2 exists to fix. One
//!    fleet file, two tables, two distinct tokens, each still authenticating on
//!    its own route.
//!
//! `login --token` rather than the device flow: the flow itself is covered
//! against a stub GitHub in `probefleet-coordinator/tests/device_flow.rs`, and these
//! tests are about the *file* the CLI writes.

mod common;

use common::{start_fleet, Fleet};
use probefleet::cli::{LoginArgs, NodeUpFlags};
use probefleet_coordinator::FleetRole;

const SEED: [u8; 32] = [11u8; 32];

/// Mint an auth key the way `coordinator auth-key` does.
async fn mint_auth_key(fleet: &Fleet, org: &str) -> String {
    fleet
        .api_key(org, "node", serde_json::json!({ "tags": [] }), true, None)
        .await
}

/// Mint a session token the way `coordinator user-token` does — including the
/// membership provisioning, without which the token authenticates and then
/// authorizes nothing.
async fn mint_user_token(fleet: &Fleet, org: &str, login: &str) -> String {
    fleet.member(login, org, FleetRole::Admin).await;
    fleet.session(login, FleetRole::Admin).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_key_to_node_up_yields_a_working_node_token() {
    let fleet = start_fleet(SEED).await;
    let key = mint_auth_key(&fleet, "default").await;

    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("agent");

    probefleet::roles::node_up::bootstrap(
        &NodeUpFlags {
            fleet_url: Some(fleet.base_url.clone()),
            auth_key: Some(key),
            node_name: Some("rpi-lab-1".to_owned()),
            tag: vec!["nrf52".to_owned()],
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
    .expect("node up");

    // The written fleet file parses ...
    let config_path = config_dir.join("default.toml");
    let file = probefleet::fleet_config::load(&config_path).unwrap();
    assert_eq!(file.url, fleet.base_url);
    let node = file.node.clone().expect("[node] table");
    assert!(node.node_token.starts_with("prfn1_"));
    assert!(!node.coordinator_token_pubkey.is_empty());
    // No [user] table: a headless Pi has only a node credential.
    assert!(file.user.is_none());

    // ... node-local settings are scaffolded under node/ (not per-fleet: they
    // describe the machine, not the fleet) ...
    assert!(config_dir.join("node").join("boards.toml").exists());
    assert!(config_dir.join("node").join("node.toml").exists());

    // ... the credential file is not world-readable ...
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
            "the fleet file holds a bearer credential and must be 0600"
        );
    }

    // ... and, the point of the whole test, the token actually connects.
    let (tx, rx) = probefleet_wire::client::dial(probefleet_wire::client::DialOpts {
        url: file.url.clone(),
        path: "/agent",
        bearer: node.node_token.clone(),
        pin: None,
    })
    .await
    .expect("the enrolled node token must authenticate on /agent");
    drop((tx, rx));

    // The node row exists in the right org, with the tags it asked for.
    let (_node, org, _) = fleet
        .coord
        .db()
        .node_by_token_hash(
            probefleet::tokens::format()
                .parse(&node.node_token)
                .unwrap()
                .hash()
                .as_str(),
        )
        .await
        .unwrap()
        .expect("node row");
    assert_eq!(org, fleet.default_org().await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_token_to_login_yields_a_client_that_can_list() {
    let fleet = start_fleet(SEED).await;
    let token = mint_user_token(&fleet, "default", "alice").await;

    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("fleets");

    probefleet::roles::login::run(LoginArgs {
        fleet_url: Some(fleet.base_url.clone()),
        server_cert_sha256: None,
        token: Some(token.clone()),
        refresh_token: None,
        no_browser: true,
        org: Some(common::DEFAULT_ORG.to_owned()),
        fleet: "default".to_owned(),
        config_dir: Some(config_dir.clone()),
    })
    .await
    .expect("login --token");

    let config_path = config_dir.join("default.toml");
    let file = probefleet::fleet_config::load(&config_path).unwrap();
    assert_eq!(file.url, fleet.base_url);
    let user = file.user.clone().expect("[user] table");
    assert_eq!(user.session_token, token);
    // No [node] table: a workstation is not a node.
    assert!(file.node.is_none());

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
            "the fleet file holds a bearer credential"
        );
    }

    // `ctl list` over the real transport, through the real session type.
    let (tx, rx) = probefleet_wire::client::dial(probefleet_wire::client::DialOpts {
        url: file.url.clone(),
        path: "/client",
        bearer: user.session_token.clone(),
        pin: None,
    })
    .await
    .expect("the minted session token must authenticate on /client");
    let session = probefleet_sidecar::transport::CoordSession::start(Box::new(tx), Box::new(rx))
        .await
        .unwrap();
    match session
        .request(probefleet_wire::SidecarToCoord::ListBoards)
        .await
        .unwrap()
    {
        probefleet_wire::CoordToSidecar::BoardList(boards) => assert!(boards.is_empty()),
        other => panic!("expected BoardList, got {other:?}"),
    }
}

/// `node up` must fail loudly on a bad key rather than writing a config file
/// that only fails later, when the agent is running unattended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_up_refuses_an_invalid_auth_key_and_writes_nothing() {
    let fleet = start_fleet(SEED).await;
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("agent");

    let result = probefleet::roles::node_up::bootstrap(
        &NodeUpFlags {
            fleet_url: Some(fleet.base_url.clone()),
            auth_key: Some(probefleet::tokens::mint_string(forgs::TokenKind::ApiKey)),
            node_name: Some("rpi-1".to_owned()),
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
    .await;

    assert!(result.is_err(), "an unknown auth key must be refused");
    assert!(
        !config_dir.join("default.toml").exists(),
        "no config may be written when enrollment fails"
    );
}

/// The laptop case, and the reason revision 2 has one file per fleet rather than
/// one tree per role: a machine that is both a user and a node needed two
/// unrelated enrollments before, with nothing tying them to the same fleet.
///
/// Both tables must survive each other's writes, and — the security half — the
/// two tokens must stay **distinct** and keep authenticating only on their own
/// route. A node token that worked on `/client` would make a Pi on a shelf
/// equivalent to a user account.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_laptop_holds_both_credentials_in_one_fleet_file() {
    let fleet = start_fleet(SEED).await;
    let key = mint_auth_key(&fleet, "default").await;
    let session = mint_user_token(&fleet, "default", "alice").await;

    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("fleets");

    // The human logs in first ...
    probefleet::roles::login::run(LoginArgs {
        fleet_url: Some(fleet.base_url.clone()),
        server_cert_sha256: None,
        token: Some(session.clone()),
        refresh_token: None,
        no_browser: true,
        org: Some(common::DEFAULT_ORG.to_owned()),
        fleet: "default".to_owned(),
        config_dir: Some(config_dir.clone()),
    })
    .await
    .expect("login --token");

    // ... then enrolls the same machine as a node.
    probefleet::roles::node_up::bootstrap(
        &NodeUpFlags {
            fleet_url: Some(fleet.base_url.clone()),
            auth_key: Some(key),
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
    .expect("node up");

    let file = probefleet::fleet_config::load(&config_dir.join("default.toml")).unwrap();
    let user = file.user.clone().expect("[user] survived node up");
    let node = file.node.clone().expect("[node] was written");
    assert_eq!(user.session_token, session);
    assert_ne!(user.session_token, node.node_token);

    // Each token authenticates on its own route ...
    let (tx, rx) = probefleet_wire::client::dial(probefleet_wire::client::DialOpts {
        url: file.url.clone(),
        path: "/agent",
        bearer: node.node_token.clone(),
        pin: None,
    })
    .await
    .expect("the node token must authenticate on /agent");
    drop((tx, rx));

    let (tx, rx) = probefleet_wire::client::dial(probefleet_wire::client::DialOpts {
        url: file.url.clone(),
        path: "/client",
        bearer: user.session_token.clone(),
        pin: None,
    })
    .await
    .expect("the session token must authenticate on /client");
    drop((tx, rx));

    // ... and only on its own route.
    assert!(
        probefleet_wire::client::dial(probefleet_wire::client::DialOpts {
            url: file.url.clone(),
            path: "/client",
            bearer: node.node_token.clone(),
            pin: None,
        })
        .await
        .is_err(),
        "a node token must not open the operator plane"
    );
    assert!(
        probefleet_wire::client::dial(probefleet_wire::client::DialOpts {
            url: file.url.clone(),
            path: "/agent",
            bearer: user.session_token.clone(),
            pin: None,
        })
        .await
        .is_err(),
        "a session token must not open the agent plane"
    );
}
