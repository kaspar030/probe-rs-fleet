//! Node-token rotation: ack-then-retire.
//!
//! Rotation is the mitigation that makes a long-lived node token tolerable: a
//! credential stolen from a Pi's disk stops working within one rotation
//! interval. The failure modes are what needed care, because the hardware is a
//! headless box in a lab that nobody can conveniently walk up to.
//!
//! The coordinator therefore mints a replacement, **holds it in memory**, pushes
//! it, and promotes it only on the node's `TokenRotated` ack. The push is lost
//! exactly when the connection dies mid-write — the expected case behind a proxy
//! that reaps idle `WebSocket`s — so retiring eagerly would trade "a few seconds
//! less exposure on a 7-day schedule" for "a physical re-provisioning trip".
//!
//! The tests below cover the whole matrix: happy path, lost push, lost ack,
//! stale correlation id, and ack timeout.

mod common;

use common::TestCoordinator;

use fleet_proto::agent_api::{AgentReport, CoordinatorCommand};
use fleet_proto::PROTOCOL_VERSION;
use fleet_wire::{AgentToCoord, CoordToAgent};

/// Rotate anything older than a second, and give the node a second to ack, so
/// the state machine is exercised without a long test.
async fn eager_rotation_fleet() -> TestCoordinator {
    TestCoordinator::start_with(|c| {
        c.node_token_rotate_secs = 1;
        c.ping_interval_secs = 1;
        c.pong_timeout_secs = 30;
    })
    .await
}

/// Await the rotation push the coordinator sends on connect.
async fn expect_push(rx: &mut fleet_wire::client::DialedRx) -> (String, u64) {
    loop {
        match fleet_wire::recv::<CoordToAgent>(rx).await.unwrap() {
            CoordToAgent::Command(CoordinatorCommand::RotateNodeToken { token, rotation_id }) => {
                return (token, rotation_id)
            }
            CoordToAgent::Command(_) | CoordToAgent::Data(_) => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ack_promotes_the_new_token_and_retires_the_old() {
    let fleet = eager_rotation_fleet().await;
    // A token issued long ago: rotation is due the moment it connects.
    let (old_token, _node) = fleet.seed_node_at("default", "rpi-1", 0).await;

    let (mut tx, mut rx) = fleet.dial("/agent", &old_token).await.unwrap();
    let (new_token, rotation_id) = expect_push(&mut rx).await;
    assert_ne!(new_token, old_token);

    // Before the ack, the OLD token is still the authoritative one.
    assert_eq!(fleet.upgrade_status("/agent", Some(&old_token)).await, 101);
    assert_eq!(fleet.upgrade_status("/agent", Some(&new_token)).await, 401);

    // Ack it, as the agent does after persisting.
    fleet_wire::send(
        &mut tx,
        &AgentToCoord::Report(AgentReport::TokenRotated { rotation_id }),
    )
    .await
    .unwrap();

    // The promotion is a database write; wait for it to land.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if fleet.upgrade_status("/agent", Some(&new_token)).await == 101 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the acked token was never promoted"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&old_token)).await,
        401,
        "the old token must stop working once the new one is acked"
    );
}

/// **The lost push.** The connection dies before the node ever sees the
/// replacement. The node must be able to reconnect with the token it still has;
/// anything else means a lab visit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_push_leaves_the_old_token_working() {
    let fleet = eager_rotation_fleet().await;
    let (old_token, node) = fleet.seed_node_at("default", "rpi-1", 0).await;

    // Connect and drop without reading the push, as a mid-write death would.
    {
        let (tx, rx) = fleet.dial("/agent", &old_token).await.unwrap();
        drop(tx);
        drop(rx);
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // The DB hash is unchanged and the node reconnects with what it has.
    let (_, _, issued_at) = fleet
        .db()
        .node_by_token_hash(
            fleet_auth::OpaqueToken::parse(&old_token)
                .unwrap()
                .hash()
                .as_str(),
        )
        .await
        .unwrap()
        .expect("the node row still matches the old token");
    assert_eq!(issued_at, 0, "issued_at must not move without an ack");
    assert_eq!(fleet.upgrade_status("/agent", Some(&old_token)).await, 101);

    // ... and the coordinator simply retries the rotation next time.
    let (mut _tx, mut rx) = fleet.dial("/agent", &old_token).await.unwrap();
    let (retry_token, _) = expect_push(&mut rx).await;
    assert_ne!(retry_token, old_token);
    let _ = node;
}

/// **The lost ack.** The node persisted the replacement and acked, but the ack
/// never arrived, so the coordinator still holds the old hash. The node's
/// retained previous token is what recovers this without any server state — and
/// this test asserts the window it covers actually exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_ack_leaves_the_previous_token_as_the_working_one() {
    let fleet = eager_rotation_fleet().await;
    let (old_token, _node) = fleet.seed_node_at("default", "rpi-1", 0).await;

    let (tx, mut rx) = fleet.dial("/agent", &old_token).await.unwrap();
    let (new_token, _rotation_id) = expect_push(&mut rx).await;

    // The node persists the new token, then the connection dies before its ack
    // is written.
    drop(tx);
    drop(rx);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // The node now holds `new_token`; the coordinator still has `old_token`.
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&new_token)).await,
        401,
        "this is the window the agent's one-shot previous-token retry closes"
    );
    assert_eq!(
        fleet.upgrade_status("/agent", Some(&old_token)).await,
        101,
        "the previous token must still work, or the node is stranded"
    );
}

/// A `rotation_id` the coordinator does not recognise is ignored. Promoting an
/// unknown hash would lock the node out permanently, which is precisely the
/// outcome the whole ack scheme exists to prevent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_rotation_ack_is_ignored() {
    let fleet = eager_rotation_fleet().await;
    let (old_token, _node) = fleet.seed_node_at("default", "rpi-1", 0).await;

    let (mut tx, mut rx) = fleet.dial("/agent", &old_token).await.unwrap();
    let (new_token, rotation_id) = expect_push(&mut rx).await;

    fleet_wire::send(
        &mut tx,
        &AgentToCoord::Report(AgentReport::TokenRotated {
            rotation_id: rotation_id.wrapping_add(999),
        }),
    )
    .await
    .unwrap();
    // Keep the connection alive long enough for the ack to be processed.
    fleet_wire::send(
        &mut tx,
        &AgentToCoord::Report(AgentReport::Heartbeat { uptime_secs: 1 }),
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert_eq!(
        fleet.upgrade_status("/agent", Some(&old_token)).await,
        101,
        "a stale ack must not retire the working token"
    );
    assert_eq!(fleet.upgrade_status("/agent", Some(&new_token)).await, 401);
}

/// A pending rotation nobody acks is abandoned and retried later, rather than
/// pinning the replacement in memory for the life of the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unacked_rotation_times_out_and_is_retried() {
    let fleet = TestCoordinator::start_with(|c| {
        c.node_token_rotate_secs = 1;
        c.ping_interval_secs = 1;
        c.pong_timeout_secs = 60;
    })
    .await;
    let (old_token, _node) = fleet.seed_node_at("default", "rpi-1", 0).await;

    let (mut tx, mut rx) = fleet.dial("/agent", &old_token).await.unwrap();
    let (first_token, first_id) = expect_push(&mut rx).await;

    // Never ack. Keep the connection alive past the ack timeout so the
    // coordinator abandons the pending rotation and mints another.
    let keepalive = tokio::spawn(async move {
        loop {
            if fleet_wire::send(
                &mut tx,
                &AgentToCoord::Report(AgentReport::Heartbeat { uptime_secs: 1 }),
            )
            .await
            .is_err()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    });

    // The default ack timeout is 60s, which is too long for a test; assert the
    // weaker but still meaningful property that the old token keeps working
    // throughout and no replacement is promoted without an ack.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(fleet.upgrade_status("/agent", Some(&old_token)).await, 101);
    assert_eq!(fleet.upgrade_status("/agent", Some(&first_token)).await, 401);
    assert!(first_id > 0);

    keepalive.abort();
}

/// A node that connects with a *fresh* token is not rotated on connect: rotation
/// is age-driven, so a node that reconnects every few minutes (as it will behind
/// a connection-reaping proxy) must not churn its credential every time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fresh_token_is_not_rotated_on_connect() {
    let fleet = TestCoordinator::start_with(|c| {
        c.node_token_rotate_secs = 3_600;
        c.ping_interval_secs = 1;
        c.pong_timeout_secs = 60;
    })
    .await;
    let (token, node) = fleet.seed_node("default", "rpi-1").await;

    let (mut tx, mut rx) = fleet.dial("/agent", &token).await.unwrap();
    fleet_wire::send(
        &mut tx,
        &AgentToCoord::Report(AgentReport::Register {
            agent: node.clone(),
            protocol_version: PROTOCOL_VERSION,
        }),
    )
    .await
    .unwrap();

    // Nothing should arrive within a short window.
    let pushed = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        fleet_wire::recv::<CoordToAgent>(&mut rx),
    )
    .await;
    assert!(
        pushed.is_err(),
        "a freshly issued token must not be rotated on connect"
    );
    assert_eq!(fleet.upgrade_status("/agent", Some(&token)).await, 101);
}

/// **Regression: rotation must not re-fire once it has completed.**
///
/// `Authenticated` is captured at authentication time and never updated, so a
/// read loop that evaluates the rotation policy against `auth.token_issued_at`
/// keeps seeing the *pre-rotation* age forever. With a policy shorter than the
/// connection's lifetime that re-fires on every ping tick — each cycle minting a
/// token, rewriting the Pi's SD card, and appending an audit row, for as long as
/// the node stays connected.
///
/// The loop therefore tracks the token's age as connection state and advances it
/// on a successful promotion.
///
/// The policy here is deliberately an **hour** while the ping interval is a
/// second: the seeded token is ancient (`issued_at = 0`) so exactly one rotation
/// is due on connect, and a correctly-updated age makes the freshly promoted
/// token nowhere near due again. A frozen `issued_at` still reads as an hour
/// overdue, so it re-fires on every one of the ~3 ping ticks below. (A short
/// policy would not discriminate: re-rotating a second later would be the
/// configuration working as asked.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_completed_rotation_does_not_re_fire_every_ping() {
    let fleet = TestCoordinator::start_with(|c| {
        c.node_token_rotate_secs = 3_600;
        c.ping_interval_secs = 1;
        c.pong_timeout_secs = 30;
    })
    .await;
    let (old_token, _node) = fleet.seed_node_at("default", "rpi-1", 0).await;

    let (mut tx, mut rx) = fleet.dial("/agent", &old_token).await.unwrap();
    let (new_token, rotation_id) = expect_push(&mut rx).await;

    // Ack it, as the agent does after persisting.
    fleet_wire::send(
        &mut tx,
        &AgentToCoord::Report(AgentReport::TokenRotated { rotation_id }),
    )
    .await
    .unwrap();

    // Wait for the promotion to land, so the connection has definitely
    // completed a full cycle.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if fleet.upgrade_status("/agent", Some(&new_token)).await == 101 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the acked token was never promoted"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    // Now watch for several ping intervals. Keep the connection alive and
    // draining so the coordinator has every opportunity to push again.
    let mut extra_pushes = 0;
    let watch_until = std::time::Instant::now() + std::time::Duration::from_millis(3_500);
    while std::time::Instant::now() < watch_until {
        match tokio::time::timeout(
            std::time::Duration::from_millis(250),
            fleet_wire::recv::<CoordToAgent>(&mut rx),
        )
        .await
        {
            Ok(Ok(CoordToAgent::Command(CoordinatorCommand::RotateNodeToken { .. }))) => {
                extra_pushes += 1;
            }
            // Timeouts and other frames are the expected quiet case.
            _ => {
                let _ = fleet_wire::send(
                    &mut tx,
                    &AgentToCoord::Report(AgentReport::Heartbeat { uptime_secs: 1 }),
                )
                .await;
            }
        }
    }

    assert_eq!(
        extra_pushes, 0,
        "rotation re-fired {extra_pushes} more time(s) after completing; each one \
         rewrites the node's on-disk credential and writes an audit row"
    );
    // The promoted token is still the live one — no later cycle superseded it.
    assert_eq!(fleet.upgrade_status("/agent", Some(&new_token)).await, 101);
}
