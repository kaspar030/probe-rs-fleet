//! `WebSocket` keepalive.
//!
//! Keepalive stopped being a nicety in revision 2. The hosted deployment puts an
//! HTTPS reverse proxy in front of the coordinator, and a proxy reaps idle
//! `WebSocket`s on a timeout nobody here controls. A lab node's connection is
//! idle almost all the time, so without ping/pong the fleet's control plane
//! would evaporate every few minutes and the agent's reconnect backoff would
//! become the primary mechanism rather than the fallback.
//!
//! The two properties worth pinning:
//!
//! * an idle connection that answers pings **survives** past the ping interval;
//! * a peer that stops answering is **dropped** rather than held open forever,
//!   because a half-open connection is worse than no connection: the coordinator
//!   would keep routing leases to a node that is not there.

mod common;

use common::TestCoordinator;

use fleet_proto::agent_api::AgentReport;
use fleet_wire::{AgentToCoord, WireEvent, WireRx, WireTx};

/// An idle connection stays up: the coordinator pings, tungstenite answers
/// automatically, and nothing is dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_connection_survives_several_ping_intervals() {
    let fleet = TestCoordinator::start_with(|c| {
        c.ping_interval_secs = 1;
        c.pong_timeout_secs = 10;
    })
    .await;
    let (token, node) = fleet.seed_node("default", "rpi-1").await;

    let (mut tx, mut rx) = fleet.dial("/agent", &token).await.unwrap();

    // Register, then go completely silent at the application level.
    fleet_wire::send(
        &mut tx,
        &AgentToCoord::Report(AgentReport::Register {
            agent: node.clone(),
            protocol_version: fleet_proto::PROTOCOL_VERSION,
        }),
    )
    .await
    .unwrap();

    // Drive the receiver so tungstenite processes (and auto-answers) the
    // coordinator's pings, exactly as the agent's read loop does.
    let pump = tokio::spawn(async move {
        let mut pings_seen = 0u32;
        loop {
            match rx.recv().await {
                Ok(WireEvent::Closed) | Err(_) => return (false, pings_seen),
                Ok(_) => pings_seen += 1,
            }
        }
    });

    // Well past several ping intervals.
    tokio::time::sleep(std::time::Duration::from_millis(3_500)).await;

    // Still registered: the coordinator has not reaped us.
    assert!(
        fleet.coord.agents().get(&node).await.is_some(),
        "an idle connection that answers pings must not be dropped"
    );
    pump.abort();
}

/// A peer that stops answering is dropped. Simulated by a client that never
/// reads, so it never processes a ping and therefore never pongs — the same
/// observable behaviour as a node whose network went away without a FIN.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_never_pongs_is_eventually_dropped() {
    let fleet = TestCoordinator::start_with(|c| {
        c.ping_interval_secs = 1;
        // Just above the ping interval, so the timeout is reachable in a test.
        c.pong_timeout_secs = 2;
    })
    .await;
    let (token, node) = fleet.seed_node("default", "rpi-1").await;

    let (mut tx, rx) = fleet.dial("/agent", &token).await.unwrap();
    fleet_wire::send(
        &mut tx,
        &AgentToCoord::Report(AgentReport::Register {
            agent: node.clone(),
            protocol_version: fleet_proto::PROTOCOL_VERSION,
        }),
    )
    .await
    .unwrap();

    // Wait for the registration to land, then stop reading entirely: the
    // receive half is parked, so pings are never answered.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while fleet.coord.agents().get(&node).await.is_none() {
        assert!(std::time::Instant::now() < deadline, "never registered");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let _parked = rx;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if fleet.coord.agents().get(&node).await.is_none() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "a silent peer must be dropped once the liveness deadline passes; \
             otherwise the coordinator keeps routing leases to a node that is gone"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Application traffic counts as liveness too: a node that is busy relaying
/// bytes must not be reaped merely because its pongs are queued behind them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_traffic_counts_as_liveness() {
    let fleet = TestCoordinator::start_with(|c| {
        c.ping_interval_secs = 1;
        c.pong_timeout_secs = 2;
    })
    .await;
    let (token, node) = fleet.seed_node("default", "rpi-1").await;

    let (mut tx, mut rx) = fleet.dial("/agent", &token).await.unwrap();
    let pump = tokio::spawn(async move { while rx.recv().await.is_ok() {} });

    // Heartbeat faster than the pong timeout for a few rounds.
    for _ in 0..8 {
        fleet_wire::send(
            &mut tx,
            &AgentToCoord::Report(AgentReport::Heartbeat { uptime_secs: 1 }),
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    }

    assert!(
        fleet.coord.agents().get(&node).await.is_some(),
        "a connection carrying traffic must not be reaped"
    );
    pump.abort();
}

/// The client's own ping reaches the server and comes back as a pong: the
/// keepalive is bidirectional, which matters because the proxy's idle timer
/// looks at traffic in both directions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_ping_is_answered() {
    let fleet = TestCoordinator::start().await;
    let (token, _node) = fleet.seed_node("default", "rpi-1").await;

    let (mut tx, mut rx) = fleet.dial("/agent", &token).await.unwrap();
    tx.send_ping().await.unwrap();

    let saw_pong = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match rx.recv().await.unwrap() {
                WireEvent::Pong => return true,
                WireEvent::Closed => return false,
                WireEvent::Binary(_) => {}
            }
        }
    })
    .await
    .expect("timed out waiting for a pong");
    assert!(saw_pong, "the server must answer a client ping");
}
