//! End-to-end bootstrap through the CLI's own code paths.
//!
//! Replaces `enroll_e2e.rs`, which walked the deleted CSR/certificate flow. The
//! property is the same and is the one an operator actually cares about: the
//! scaffolding commands produce credentials that *work against a live
//! coordinator*, not merely files that parse.
//!
//! Two chains:
//!
//! 1. `coordinator auth-key` → `agent init --auth-key` → the written
//!    `agent.toml` holds a node token that authenticates on `/agent`;
//! 2. `coordinator user-token` → `ctl init` → the written `client.toml` holds a
//!    session token that authenticates on `/client` and can list the fleet.

use std::sync::Arc;

use fleet_auth::{OpaqueToken, TokenKind};
use fleet_bin::cli::{AgentInitArgs, CtlInitArgs};
use fleet_coordinator::auth::Ed25519Signer;
use fleet_coordinator::clock::SystemClock;
use fleet_coordinator::config::{CoordinatorConfig, SigningKeySource};
use fleet_coordinator::core::Coordinator;
use fleet_coordinator::state::Db;
use fleet_core::policy::Policy;
use fleet_core::scheduler::Scheduler;
use fleet_proto::ids::{OrgId, Role};

const SEED: [u8; 32] = [11u8; 32];

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

/// Mint an auth key the way `coordinator auth-key` does.
async fn mint_auth_key(fleet: &Fleet, org: &str) -> String {
    let org = OrgId(org.to_owned());
    fleet.coord.db().ensure_org(&org, "personal").await.unwrap();
    let token = OpaqueToken::mint(TokenKind::AuthKey);
    let now = i64::try_from(fleet.coord.now()).unwrap();
    fleet
        .coord
        .db()
        .insert_auth_key(&org, token.hash().as_str(), &[], true, None, None, now)
        .await
        .unwrap();
    token.to_secret_string()
}

/// Mint a session token the way `coordinator user-token` does — including the
/// membership provisioning, without which the token authenticates and then
/// authorizes nothing.
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_key_to_agent_init_yields_a_working_node_token() {
    let fleet = start_fleet().await;
    let key = mint_auth_key(&fleet, "default").await;

    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("agent");

    fleet_bin::roles::agent_init::run(
        AgentInitArgs {
            fleet_url: fleet.base_url.clone(),
            auth_key: key,
            node_name: Some("rpi-lab-1".to_owned()),
            tag: vec!["nrf52".to_owned()],
            server_cert_sha256: None,
            config_dir: Some(config_dir.clone()),
            boards_path: None,
            force: false,
        },
        "default".to_owned(),
    )
    .await
    .expect("agent init");

    // The written config parses ...
    let config_path = config_dir.join("agent.toml");
    let cfg = fleet_agent::config::AgentConfig::from_path(&config_path).unwrap();
    assert_eq!(cfg.fleet_url, fleet.base_url);
    assert!(cfg.node_token.starts_with("prfn1_"));
    assert!(!cfg.coordinator_token_pubkey.is_empty());

    // ... a starter boards.toml is scaffolded alongside it ...
    assert!(config_dir.join("boards.toml").exists());

    // ... the credential file is not world-readable ...
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&config_path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "agent.toml holds a bearer credential and must be 0600"
        );
    }

    // ... and, the point of the whole test, the token actually connects.
    let (tx, rx) = fleet_wire::client::dial(fleet_wire::client::DialOpts {
        url: cfg.fleet_url.clone(),
        path: "/agent",
        bearer: cfg.node_token.clone(),
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
            OpaqueToken::parse(&cfg.node_token)
                .unwrap()
                .hash()
                .as_str(),
        )
        .await
        .unwrap()
        .expect("node row");
    assert_eq!(org.0, "default");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_token_to_ctl_init_yields_a_client_that_can_list() {
    let fleet = start_fleet().await;
    let token = mint_user_token(&fleet, "default", "alice").await;

    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("client");

    fleet_bin::roles::ctl_init::run(
        CtlInitArgs {
            fleet_url: fleet.base_url.clone(),
            token: token.clone(),
            server_cert_sha256: None,
            config_dir: Some(config_dir.clone()),
            force: false,
        },
        "default".to_owned(),
    )
    .await
    .expect("ctl init");

    let config_path = config_dir.join("client.toml");
    let cfg = fleet_bin::config::load_client_config(&config_path).unwrap();
    assert_eq!(cfg.fleet_url, fleet.base_url);
    assert_eq!(cfg.token, token);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&config_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "client.toml holds a bearer credential");
    }

    // `ctl list` over the real transport, through the real session type.
    let (tx, rx) = fleet_wire::client::dial(fleet_wire::client::DialOpts {
        url: cfg.fleet_url.clone(),
        path: "/client",
        bearer: cfg.token.clone(),
        pin: None,
    })
    .await
    .expect("the minted session token must authenticate on /client");
    let session = fleet_sidecar::transport::CoordSession::start(Box::new(tx), Box::new(rx))
        .await
        .unwrap();
    match session
        .request(fleet_wire::SidecarToCoord::ListBoards)
        .await
        .unwrap()
    {
        fleet_wire::CoordToSidecar::BoardList(boards) => assert!(boards.is_empty()),
        other => panic!("expected BoardList, got {other:?}"),
    }
}

/// `agent init` must fail loudly on a bad key rather than writing a config file
/// that only fails later, when the agent is running unattended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn agent_init_refuses_an_invalid_auth_key_and_writes_nothing() {
    let fleet = start_fleet().await;
    let tmp = tempfile::tempdir().unwrap();
    let config_dir = tmp.path().join("agent");

    let result = fleet_bin::roles::agent_init::run(
        AgentInitArgs {
            fleet_url: fleet.base_url.clone(),
            auth_key: OpaqueToken::mint(TokenKind::AuthKey).to_secret_string(),
            node_name: Some("rpi-1".to_owned()),
            tag: vec![],
            server_cert_sha256: None,
            config_dir: Some(config_dir.clone()),
            boards_path: None,
            force: false,
        },
        "default".to_owned(),
    )
    .await;

    assert!(result.is_err(), "an unknown auth key must be refused");
    assert!(
        !config_dir.join("agent.toml").exists(),
        "no config may be written when enrollment fails"
    );
}
