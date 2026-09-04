//! End-to-end "live wire" integration test.
//!
//! This wires a real agent dial-out connection and a real sidecar relay client
//! to the coordinator's genuine `handle_agent` / `handle_sidecar` pumps over
//! in-memory wire pairs (no HTTP, no TLS), and proves a byte travels
//! sidecar -> coordinator -> agent -> backend -> back.
//!
//! `ws_e2e.rs` is the same property over a *real* `WebSocket` against a real
//! router; this one keeps the pumps testable without an HTTP layer, so a
//! failure here localises to the relay rather than to the transport.
//!
//! The hardware end-to-end (real Pi + nRF52840) is the separate ST-D gate.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use fleet_agent::{Agent, ProbeRsBackend, Session, SpliceIo};
use fleet_coordinator::auth::Ed25519Signer;
use fleet_coordinator::clock::SystemClock;
use fleet_coordinator::config::{CoordinatorConfig, SigningKeySource};
use fleet_coordinator::core::Coordinator;
use fleet_coordinator::state::Db;
use fleet_core::policy::Policy;
use fleet_core::scheduler::Scheduler;
use fleet_proto::ids::{AgentId, BoardName, BoardRef, OrgId, Role, Subject, SubjectKind};
use fleet_proto::lease::{Constraint, LeaseRequest, Priority};
use fleet_wire::{CoordToSidecar, SidecarToCoord};

const SEED: [u8; 32] = [7u8; 32];

/// A backend whose `probe-rs serve` session is an in-memory duplex that echoes
/// every byte back (a stand-in for a real probe-rs server's request/response).
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
        // Echo task: bounce every byte the agent writes back to it.
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

fn coordinator_config() -> CoordinatorConfig {
    CoordinatorConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        sqlite_path: ":memory:".into(),
        signing_key: SigningKeySource::Seed(SEED),
        default_org: OrgId("default".to_owned()),
        ..CoordinatorConfig::default()
    }
}

fn agent_config(token_pubkey: &[u8; 32]) -> fleet_agent::config::AgentConfig {
    fleet_agent::config::AgentConfig {
        agent_id: "agent-a".to_owned(),
        fleet_url: "https://coordinator.example:7000".to_owned(),
        node_token: "prfn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn sidecar_to_agent_data_plane_round_trip() {
    // --- Coordinator ---
    let signer = Ed25519Signer::from_seed(&SEED);
    let token_pubkey = signer.public_key_bytes();
    let sched = Scheduler::new(Policy::default());
    let db = Db::connect_in_memory().await.unwrap();
    // The membership `coordinator user-token` provisions when it mints a
    // session: without it, `authz::require_role` denies a perfectly valid token.
    db.ensure_user_member(&OrgId("default".to_owned()), "dev", Role::Admin)
        .await
        .unwrap();
    // The node row resolves this agent's reports to an org: since task 3448
    // there is no `default_org` fallback, so a report from a node with no row
    // is dropped rather than filed into the configured tenant.
    db.scoped(OrgId("default".to_owned()))
        .ensure_node(&AgentId("agent-a".to_owned()), 1_000)
        .await
        .unwrap();
    let dev = Subject::new(OrgId("default".to_owned()), SubjectKind::User, "dev");
    let coord = Arc::new(Coordinator::new(
        coordinator_config(),
        sched,
        db,
        signer,
        Arc::new(SystemClock),
    ));

    // --- Agent dial-out over duplex A ---
    let agent = Arc::new(Agent::new(agent_config(&token_pubkey), boards(), Arc::new(EchoBackend)).unwrap());
    agent.seed_inventory_from_boards().await;

    let (coord_tx, coord_rx, agent_tx, agent_rx) = fleet_wire::mock::pair();
    {
        let coord = Arc::clone(&coord);
        tokio::spawn(async move {
            let _ = fleet_coordinator::server::handle_agent_for_test(
                coord,
                Box::new(coord_tx),
                Box::new(coord_rx),
                AgentId("agent-a".to_owned()),
            )
            .await;
        });
    }
    {
        let agent = Arc::clone(&agent);
        let mut config = agent_config(&token_pubkey);
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

    // Wait for the agent's inventory to populate the scheduler.
    // The coordinator keys the board by (org, node, name); the sidecar asks for
    // it by node-local name.
    let board_name = BoardName("nrf52840-dk-1".to_owned());
    let board_id = BoardRef::new(
        OrgId("default".to_owned()),
        AgentId("agent-a".to_owned()),
        "nrf52840-dk-1",
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        {
            let sched = coord.scheduler().lock().await;
            if sched.board(&board_id).is_some() {
                break;
            }
        }
        assert!(std::time::Instant::now() < deadline, "board never registered");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    // --- Sidecar relay client over duplex B ---
    let (coord_tx, coord_rx, sc_tx, sc_rx) = fleet_wire::mock::pair();
    {
        let coord = Arc::clone(&coord);
        let dev = dev.clone();
        tokio::spawn(async move {
            let _ = fleet_coordinator::server::handle_sidecar_for_test(
                coord,
                Box::new(coord_tx),
                Box::new(coord_rx),
                dev.clone(),
            )
            .await;
        });
    }
    let session = fleet_sidecar::transport::CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
        .await
        .unwrap();

    // Lease the board.
    let grant = session
        .lease(&LeaseRequest {
            select: Constraint::Board(board_name.clone()),
            duration_secs: 600,
            priority: Priority::Interactive,
        })
        .await
        .unwrap();
    assert_eq!(grant.board, board_id);
    assert_eq!(grant.agent, AgentId("agent-a".to_owned()));

    // Open a data relay channel.
    let channel = session
        .open_channel(grant.lease, fleet_proto::ChannelKind::Data)
        .await
        .unwrap();

    // A local "probe-rs client" duplex; the splice copies bytes to the relay,
    // the agent forwards them to the echo backend, and they come back.
    let (mut client, client_peer) = tokio::io::duplex(4096);
    {
        // The splice borrows the session for the connection's lifetime.
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
        // Drive both; the exchange completes the round trip, then we stop.
        tokio::select! {
            _ = &mut splice => panic!("splice ended before exchange completed"),
            () = &mut exchange => {}
        }
    }

    // The board shows up as leased in the operator inventory.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<CoordToSidecar>(8);
    coord
        .handle_sidecar_message(&dev, SidecarToCoord::ListBoards, &tx)
        .await
        .unwrap();
    match rx.recv().await.unwrap() {
        CoordToSidecar::BoardList(boards) => {
            let b = boards.iter().find(|b| b.board == board_id).unwrap();
            assert_eq!(
                b.availability,
                fleet_proto::admin::BoardAvailability::Leased
            );
        }
        other => panic!("expected BoardList, got {other:?}"),
    }
}
