//! End-to-end serial passthrough over the real coordinator pumps.
//!
//! A real agent (`serve_connection`) and a real client (`CoordSession`) are
//! wired to the coordinator's `handle_agent` / `handle_sidecar` over
//! in-memory wire pairs. The board's "USB tty" is the slave end of a pty
//! pair; the test holds the master as the device side.
//!
//! Proves: the holder opens a `ChannelKind::Serial` channel, bytes flow both
//! ways, a `Configure` reaches the device's termios, a non-holder is refused,
//! and releasing the lease closes the channel and the tty fd.

use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use probefleet_agent::serial::{MapOpener, StaticSerialLister, UsbTty};
use probefleet_agent::{Agent, ProbeRsBackend, Session};
use probefleet_coordinator::auth::Ed25519Signer;
use probefleet_coordinator::clock::SystemClock;
use probefleet_coordinator::config::{CoordinatorConfig, SigningKeySource};
use probefleet_coordinator::core::Coordinator;
use probefleet_coordinator::state::Db;
use probefleet_coordinator::subject::Subject;
use probefleet_coordinator::FleetRole;
use probefleet_core::policy::Policy;
use probefleet_core::scheduler::Scheduler;
use probefleet_proto::ids::{BoardName, BoardRef, NodeId, OrgId};
use probefleet_proto::lease::{Constraint, LeaseRequest, Priority};
use probefleet_proto::serial::{self as wire, LineSettings, SerialEvent, SerialRequest};
use probefleet_proto::{ChannelKind, DataFrame};
use probefleet_sidecar::transport::CoordSession;
use probefleet_wire::CoordToSidecar;
use serialport::SerialPort as _;

const SEED: [u8; 32] = [7u8; 32];

/// No probe-rs serve is needed for a serial channel.
struct NoBackend;

#[async_trait::async_trait]
impl ProbeRsBackend for NoBackend {
    async fn open(
        &self,
        _board: &probefleet_agent::config::BoardSpec,
        _serve_token: &str,
    ) -> Result<Box<dyn Session>, String> {
        Err("no serve in this test".to_owned())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn agent_config(node: &NodeId, token_pubkey: &[u8; 32]) -> probefleet_agent::config::AgentConfig {
    probefleet_agent::config::AgentConfig {
        node_id: node.0.clone(),
        fleet_url: "https://coordinator.example:7000".to_owned(),
        node_token: "prfn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        previous_node_token: None,
        server_cert_sha256: None,
        coordinator_token_pubkey: hex_encode(token_pubkey),
        boards_path: std::path::PathBuf::from("/boards.toml"),
        heartbeat_secs: 30,
        discovery_secs: 3_600,
        adopt: probefleet_proto::AdoptPolicy::Declared,
        erase_on_release: false,
    }
}

fn boards() -> probefleet_agent::config::BoardsConfig {
    probefleet_agent::config::BoardsConfig::from_str(
        r#"
[[board]]
id = "dk-1"
serial = "001050257890"
chip = "nRF52840_xxAA"
[board.power]
kind = "none"
"#,
    )
    .unwrap()
}

const TTY_PATH: &str = "/dev/serial/by-id/usb-SEGGER_J-Link_001050257890-if02";

async fn connect_client(coord: &Arc<Coordinator>, who: &Subject) -> CoordSession {
    let (coord_tx, coord_rx, sc_tx, sc_rx) = probefleet_wire::mock::pair();
    let coord = Arc::clone(coord);
    let who = who.clone();
    tokio::spawn(async move {
        let _ = probefleet_coordinator::server::handle_sidecar_for_test(
            coord,
            Box::new(coord_tx),
            Box::new(coord_rx),
            who,
        )
        .await;
    });
    CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
        .await
        .unwrap()
}

async fn send(session: &CoordSession, channel: probefleet_proto::ChannelId, req: &SerialRequest) {
    session
        .send_frame(DataFrame {
            channel,
            bytes: wire::encode(req),
        })
        .await
        .unwrap();
}

async fn next_event(rx: &mut tokio::sync::mpsc::Receiver<DataFrame>) -> SerialEvent {
    let frame = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("event in time")
        .expect("sink open");
    wire::decode(&frame.bytes).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)]
async fn holder_relays_serial_non_holder_is_denied_release_closes() {
    // --- Coordinator, with a holder (admin) and a plain member ---
    let signer = Ed25519Signer::from_seed(&SEED);
    let token_pubkey = signer.public_key_bytes();
    let db = Db::connect_in_memory().await.unwrap();
    let now = probefleet_coordinator::now_epoch_secs();
    let org: OrgId = db.ensure_org_named("default", now).await.unwrap();
    let (holder_user, _) = db
        .forgs()
        .create_local_user("dev", None, now)
        .await
        .unwrap();
    db.set_member(&org, holder_user, FleetRole::Admin, now)
        .await
        .unwrap();
    let (other_user, _) = db
        .forgs()
        .create_local_user("eve", None, now)
        .await
        .unwrap();
    db.set_member(&org, other_user, FleetRole::Member, now)
        .await
        .unwrap();
    let node_id = probefleet_coordinator::node_id_for(&org, "node-a");
    db.scoped(org.clone())
        .ensure_node(&node_id, 1_000)
        .await
        .unwrap();
    let holder = Subject::user(holder_user, org.clone());
    let other = Subject::user(other_user, org.clone());
    let coord = Arc::new(Coordinator::new(
        CoordinatorConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            sqlite_path: ":memory:".into(),
            signing_key: SigningKeySource::Seed(SEED),
            csrf_secret: Some([9u8; 32].to_vec()),
            ..CoordinatorConfig::default()
        },
        Scheduler::new(Policy::default()),
        db,
        signer,
        Arc::new(SystemClock),
    ));

    // --- Node: the board's tty is a pty slave; we keep the master ---
    let (mut device, slave) = serialport::TTYPort::pair().unwrap();
    let opener = MapOpener::default();
    opener.insert(TTY_PATH, Box::new(slave));
    let lister = StaticSerialLister::default();
    lister.0.lock().unwrap().push(UsbTty {
        tty: "ttyACM0".to_owned(),
        path: TTY_PATH.into(),
        vid: 0x1366,
        pid: 0x1015,
        usb_serial: Some("001050257890".to_owned()),
        usb_device_path: "/sys/devices/usb1/1-1".into(),
        interface: Some(2),
    });
    let node = Arc::new(
        Agent::new(
            agent_config(&node_id, &token_pubkey),
            boards(),
            Arc::new(NoBackend),
        )
        .unwrap()
        .with_serial_lister(Arc::new(lister))
        .with_serial_opener(Arc::new(opener)),
    );
    node.seed_inventory_from_boards().await;
    {
        let (coord_tx, coord_rx, agent_tx, agent_rx) = probefleet_wire::mock::pair();
        let c = Arc::clone(&coord);
        let n = node_id.clone();
        tokio::spawn(async move {
            let _ = probefleet_coordinator::server::handle_agent_for_test(
                c,
                Box::new(coord_tx),
                Box::new(coord_rx),
                n,
            )
            .await;
        });
        let node = Arc::clone(&node);
        let mut config = agent_config(&node_id, &token_pubkey);
        tokio::spawn(async move {
            let store: Arc<dyn probefleet_agent::config::NodeTokenStore> =
                Arc::new(probefleet_agent::config::NullTokenStore);
            let _ = probefleet_agent::connection::serve_connection(
                &node,
                &mut config,
                &store,
                Box::new(agent_tx),
                Box::new(agent_rx),
            )
            .await;
        });
    }
    let board_id = BoardRef::new(org.clone(), node_id.clone(), "dk-1");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while coord.scheduler().lock().await.board(&board_id).is_none() {
        assert!(
            std::time::Instant::now() < deadline,
            "board never registered"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // The port is reported all the way to the board list.
    let session = connect_client(&coord, &holder).await;
    match session
        .request(probefleet_wire::SidecarToCoord::ListBoards)
        .await
        .unwrap()
    {
        CoordToSidecar::BoardList(boards) => {
            let b = boards.iter().find(|b| b.board == board_id).unwrap();
            assert_eq!(b.serial_ports.len(), 1);
            assert_eq!(b.serial_ports[0].name, "if2");
        }
        other => panic!("expected BoardList, got {other:?}"),
    }

    // --- Holder leases and opens a serial channel ---
    let grant = session
        .lease(
            &LeaseRequest {
                select: Constraint::Id(BoardName("dk-1".to_owned())),
                duration_secs: 600,
                priority: Priority::Interactive,
            },
            Duration::ZERO,
        )
        .await
        .unwrap();

    // A non-holder (same org, plain member) cannot open a channel on it.
    let intruder = connect_client(&coord, &other).await;
    let denied = intruder
        .open_channel(grant.lease, ChannelKind::Serial)
        .await;
    assert!(
        matches!(
            denied,
            Err(probefleet_sidecar::transport::TransportError::Declined(_))
        ),
        "{denied:?}"
    );

    let channel = session
        .open_channel(grant.lease, ChannelKind::Serial)
        .await
        .unwrap()
        .channel;
    let mut rx = session.attach_data(channel).await;
    send(
        &session,
        channel,
        &SerialRequest::Open {
            port: Some("if2".to_owned()),
            settings: LineSettings::default(),
        },
    )
    .await;
    match next_event(&mut rx).await {
        SerialEvent::Opened { port, settings } => {
            assert_eq!(port, "if2");
            assert_eq!(settings, LineSettings::default());
        }
        other => panic!("expected Opened, got {other:?}"),
    }

    // device → client
    device.write_all(b"boot ok\r\n").unwrap();
    let mut got = Vec::new();
    while got.len() < 9 {
        match next_event(&mut rx).await {
            SerialEvent::Data(b) => got.extend(b),
            other => panic!("expected data, got {other:?}"),
        }
    }
    assert_eq!(got, b"boot ok\r\n");

    // client → device, then a baud change.
    send(&session, channel, &SerialRequest::Data(b"help\n".to_vec())).await;
    send(
        &session,
        channel,
        &SerialRequest::Configure(LineSettings {
            baud: 57_600,
            ..LineSettings::default()
        }),
    )
    .await;
    let mut device = tokio::task::spawn_blocking(move || {
        device.set_timeout(Duration::from_secs(5)).unwrap();
        let mut buf = [0u8; 5];
        device.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"help\n");
        device
    })
    .await
    .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        // On Linux the master's termios is the slave's.
        if device.baud_rate().unwrap() == 57_600 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "Configure never applied"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // --- Release closes the channel and the tty fd ---
    session.release(grant.lease).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while node.serial_session_count().await != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "serial session survived release"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The node's fd to the "tty" is gone: the master reads a hangup.
    let hung_up = tokio::task::spawn_blocking(move || {
        device.set_timeout(Duration::from_millis(200)).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut buf = [0u8; 16];
        loop {
            match device.read(&mut buf) {
                Ok(0) => return true,
                Err(e) if e.kind() != std::io::ErrorKind::TimedOut => return true,
                _ if std::time::Instant::now() > deadline => return false,
                _ => {}
            }
        }
    })
    .await
    .unwrap();
    assert!(hung_up, "the tty fd must be closed on release");
}
