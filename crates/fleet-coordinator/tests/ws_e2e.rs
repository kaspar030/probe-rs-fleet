//! The replacement acceptance gate: a byte travels the whole path over a real
//! `WebSocket`.
//!
//! `wire_e2e.rs` proves the same property over in-memory pipes, which isolates
//! the relay from the transport. This test does it over the transport that
//! actually ships: a real axum router on a real socket, a real
//! `tokio-tungstenite` agent client and sidecar client, both presenting bearer
//! tokens seeded into the database. Nothing between the two ends is stubbed.

mod common;

use std::sync::Arc;

use common::TestCoordinator;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use fleet_agent::{Agent, ProbeRsBackend, Session, SpliceIo};
use fleet_proto::ids::{BoardName, BoardRef, OrgId, Role};
use fleet_proto::lease::{Constraint, LeaseRequest, Priority};

/// A backend whose `probe-rs serve` session echoes every byte back.
struct EchoBackend;

struct EchoSession {
    board: String,
    io: tokio::sync::Mutex<Option<tokio::io::DuplexStream>>,
}

#[async_trait::async_trait]
impl Session for EchoSession {
    fn board(&self) -> &str {
        &self.board
    }
    async fn take_io(&self) -> Option<Box<dyn SpliceIo>> {
        self.io
            .lock()
            .await
            .take()
            .map(|s| Box::new(s) as Box<dyn SpliceIo>)
    }
    async fn kill(&self) -> Result<(), String> {
        Ok(())
    }
    async fn wait(&self) -> fleet_agent::probers::SessionExit {
        fleet_agent::probers::SessionExit::Killed
    }
}

#[async_trait::async_trait]
impl ProbeRsBackend for EchoBackend {
    async fn open(
        &self,
        board: &fleet_agent::config::BoardSpec,
        _serve_token: &str,
    ) -> Result<Box<dyn Session>, String> {
        let (agent_side, mut peer) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match peer.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if peer.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        let _ = peer.flush().await;
                    }
                }
            }
        });
        Ok(Box::new(EchoSession {
            board: board.id.clone(),
            io: tokio::sync::Mutex::new(Some(agent_side)),
        }))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn agent_config(
    node_id: &str,
    fleet_url: &str,
    node_token: &str,
    token_pubkey: &[u8; 32],
) -> fleet_agent::config::AgentConfig {
    fleet_agent::config::AgentConfig {
        agent_id: node_id.to_owned(),
        fleet_url: fleet_url.to_owned(),
        node_token: node_token.to_owned(),
        previous_node_token: None,
        server_cert_sha256: None,
        coordinator_token_pubkey: hex_encode(token_pubkey),
        boards_path: std::path::PathBuf::from("/boards.toml"),
        heartbeat_secs: 30,
        // Long enough that these transport tests never tick discovery.
        discovery_secs: 3_600,
        adopt: fleet_proto::AdoptPolicy::Declared,
        erase_on_release: false,
    }
}

fn boards() -> fleet_agent::config::BoardsConfig {
    fleet_agent::config::BoardsConfig::from_str(
        r#"
[[board]]
id = "nrf52840-dk-1"
serial = "001050257890"
chip = "nRF52840_xxAA"
tags = ["nrf52"]
[board.power]
kind = "none"
"#,
    )
    .unwrap()
}

#[tokio::test]
async fn healthz_is_reachable_without_a_credential() {
    let fleet = TestCoordinator::start().await;
    let (status, body) = fleet.http("GET", "/healthz", None).await;
    assert_eq!(status, 200);
    assert_eq!(body, "ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn sidecar_to_agent_round_trip_over_a_real_websocket() {
    let fleet = TestCoordinator::start().await;
    let token_pubkey = fleet.coord.signer().public_key_bytes();

    // --- The node: a real WS client presenting its node token on /agent ---
    let (node_token, node_id) = fleet.seed_node("default", "rpi-lab-1").await;
    let mut config = agent_config(&node_id.0, &fleet.base_url, &node_token, &token_pubkey);
    let agent = Arc::new(Agent::new(config.clone(), boards(), Arc::new(EchoBackend)).unwrap());
    agent.seed_inventory_from_boards().await;

    let (agent_tx, agent_rx) = fleet.dial("/agent", &node_token).await.unwrap();
    {
        let agent = Arc::clone(&agent);
        tokio::spawn(async move {
            // A node that never persists its rotated token: these tests are
            // about the wire, and the storage half is covered in fleet-bin.
            let store: Arc<dyn fleet_agent::config::NodeTokenStore> =
                Arc::new(fleet_agent::config::NullTokenStore);
            let _ = fleet_agent::connection::serve_connection(
                &agent,
                &mut config,
                &store,
                Box::new(agent_tx),
                Box::new(agent_rx),
            )
            .await;
        });
    }

    // The agent registers and reports inventory; the board becomes leasable.
    let board_name = BoardName("nrf52840-dk-1".to_owned());
    let board_id = BoardRef::new(
        OrgId("default".to_owned()),
        node_id.clone(),
        "nrf52840-dk-1",
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        {
            let sched = fleet.coord.scheduler().lock().await;
            if sched.board(&board_id).is_some() {
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "board never registered over the WebSocket"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    // --- The user: a real WS client presenting a session token on /client ---
    let session_token = fleet.seed_session("default", "dev", Role::Admin).await;
    let (sc_tx, sc_rx) = fleet.dial("/client", &session_token).await.unwrap();
    let session = fleet_sidecar::transport::CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
        .await
        .unwrap();

    let grant = session
        .lease(&LeaseRequest {
            select: Constraint::Board(board_name.clone()),
            duration_secs: 600,
            priority: Priority::Interactive,
        })
        .await
        .unwrap();
    assert_eq!(grant.board, board_id);
    assert_eq!(grant.agent, node_id);

    let channel = session
        .open_channel(grant.lease, fleet_proto::ChannelKind::Data)
        .await
        .unwrap();

    // The byte-opaque path: client -> sidecar -> coordinator -> agent -> echo
    // backend -> and all the way back.
    let (mut client, client_peer) = tokio::io::duplex(4096);
    {
        let session = &session;
        let splice = fleet_sidecar::transport::splice_client(session, channel, client_peer);
        let exchange = async {
            client.write_all(b"$AttachRequest#").await.unwrap();
            client.flush().await.unwrap();
            let mut buf = vec![0u8; 15];
            client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"$AttachRequest#");
        };
        tokio::pin!(splice);
        tokio::pin!(exchange);
        tokio::select! {
            _ = &mut splice => panic!("splice ended before the exchange completed"),
            () = &mut exchange => {}
        }
    }

    // The operator surface sees the same fleet: the board is leased.
    let reply = session
        .request(fleet_wire::SidecarToCoord::ListBoards)
        .await
        .unwrap();
    match reply {
        fleet_wire::CoordToSidecar::BoardList(boards) => {
            let b = boards.iter().find(|b| b.board == board_id).unwrap();
            assert_eq!(
                b.availability,
                fleet_proto::admin::BoardAvailability::Leased
            );
        }
        other => panic!("expected BoardList, got {other:?}"),
    }
}

/// The org a node lands in comes from its `node` row, not from
/// `config.default_org`. Without this, a token minted in one tenant could report
/// inventory into another's fleet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_nodes_org_comes_from_its_row_not_the_config_default() {
    // The coordinator's default org is `default`; the node belongs to `acme`.
    let fleet = TestCoordinator::start().await;
    let token_pubkey = fleet.coord.signer().public_key_bytes();
    assert_eq!(fleet.coord.config().default_org.0, "default");

    let (node_token, node_id) = fleet.seed_node("acme", "rpi-1").await;
    let mut config = agent_config(&node_id.0, &fleet.base_url, &node_token, &token_pubkey);
    let agent = Arc::new(Agent::new(config.clone(), boards(), Arc::new(EchoBackend)).unwrap());
    agent.seed_inventory_from_boards().await;

    let (tx, rx) = fleet.dial("/agent", &node_token).await.unwrap();
    tokio::spawn(async move {
        let store: Arc<dyn fleet_agent::config::NodeTokenStore> =
            Arc::new(fleet_agent::config::NullTokenStore);
        let _ = fleet_agent::connection::serve_connection(
            &agent,
            &mut config,
            &store,
            Box::new(tx),
            Box::new(rx),
        )
        .await;
    });

    let acme_board = BoardRef::new(OrgId("acme".to_owned()), node_id.clone(), "nrf52840-dk-1");
    let default_board = BoardRef::new(
        OrgId("default".to_owned()),
        node_id.clone(),
        "nrf52840-dk-1",
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        {
            let sched = fleet.coord.scheduler().lock().await;
            if sched.board(&acme_board).is_some() {
                assert!(
                    sched.board(&default_board).is_none(),
                    "the board must not also appear in the coordinator's default org"
                );
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "board never registered in the node's own org"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}
