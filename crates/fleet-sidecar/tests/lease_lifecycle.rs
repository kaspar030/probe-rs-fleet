//! The sidecar's fleet-path lease lifecycle, driven against a mock coordinator
//! peer: what TTL is requested, that a shutdown signal releases the lease, and
//! that a long session is kept alive by heartbeats.
//!
//! Regression cover for task 3595, where the sidecar leased a hardcoded 3600s
//! and released only on the happy path — so a Ctrl-C'd or killed invocation sat
//! on an exclusive board for a full hour.
//!
//! Since task 3620 the release is conditional: a lease shared across
//! invocations by the lease store is deliberately kept. These tests pass
//! `Disposition::Release` explicitly so the release assertions keep meaning what
//! they always meant, plus one sibling case pinning the `Keep` arm.
//! `tests/lease_reuse.rs` covers the sharing itself.
//!
//! Everything runs over `fleet_wire::mock::pair`: no coordinator, no TLS, no
//! probe-rs binary. `hold_and_run` takes its shutdown future as a parameter
//! precisely so this file can fire "a signal" without raising a real one at the
//! test process.

use std::sync::Arc;
use std::time::Duration;

use fleet_proto::ids::{BoardName, BoardRef, NodeId, OrgId, Subject, SubjectKind};
use fleet_proto::lease::{Constraint, LeaseGrant, LeaseRequest, Priority};
use fleet_proto::{LeaseId, PROTOCOL_VERSION};
use fleet_sidecar::lease_store::Disposition;
use fleet_sidecar::transport::CoordSession;
use fleet_wire::{CoordToSidecar, SidecarToCoord, WireRx, WireTx};
use tokio::sync::{mpsc, Mutex};

/// The grant every peer in this file hands out.
fn grant(expires: u64) -> LeaseGrant {
    LeaseGrant {
        lease: LeaseId(1),
        board: BoardRef::new(OrgId("default".to_owned()), NodeId("a".to_owned()), "b1"),
        node: NodeId("a".to_owned()),
        holder: Subject::new(OrgId("default".to_owned()), SubjectKind::User, "p"),
        expires,
        token: vec![0xab],
    }
}

fn lease_request() -> LeaseRequest {
    LeaseRequest {
        select: Constraint::Id(BoardName("b1".to_owned())),
        // What `run_fleet` sends: the operator's policy default.
        duration_secs: 0,
        priority: Priority::Interactive,
    }
}

/// Answer the Hello with a Welcome.
async fn handshake(tx: &mut impl WireTx, rx: &mut impl WireRx) {
    match fleet_wire::recv::<SidecarToCoord>(rx).await.unwrap() {
        SidecarToCoord::Hello { .. } => {}
        other => panic!("expected Hello, got {other:?}"),
    }
    fleet_wire::send(
        tx,
        &CoordToSidecar::Welcome {
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .await
    .unwrap();
}

/// The lease request the fleet path sends carries **no** hardcoded duration:
/// `duration_secs: 0` defers to the coordinator's `Policy::default_ttl_secs`,
/// which is the whole point of task 3595. A sidecar that picks its own TTL is
/// overriding the operator's policy with a constant nobody can configure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_lease_request_carries_no_hardcoded_duration() {
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        let req = match fleet_wire::recv::<SidecarToCoord>(&mut coord_rx)
            .await
            .unwrap()
        {
            SidecarToCoord::Lease(req) => req,
            other => panic!("expected Lease, got {other:?}"),
        };
        assert_ne!(
            req.duration_secs, 3600,
            "the hardcoded hour must not come back"
        );
        assert_eq!(
            req.duration_secs, 0,
            "0 means the coordinator's policy default"
        );
        assert_eq!(req.priority, Priority::Interactive);
        fleet_wire::send(&mut coord_tx, &CoordToSidecar::Lease(grant(9_999)))
            .await
            .unwrap();
    });

    let session = CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
        .await
        .unwrap();
    session
        .lease(&lease_request(), Duration::ZERO)
        .await
        .unwrap();
    peer.await.unwrap();
}

/// Ctrl-C (or SIGTERM) during a fleet invocation releases the lease before
/// exiting, and reports the conventional `128 + signum` exit code.
///
/// Before this, the release was reached only on the happy path: an aborted
/// `probe-rs run` left the board leased until the TTL expired.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shutdown_signal_releases_the_lease() {
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();
    let released = Arc::new(Mutex::new(false));
    let released_peer = Arc::clone(&released);

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        match fleet_wire::recv::<SidecarToCoord>(&mut coord_rx)
            .await
            .unwrap()
        {
            SidecarToCoord::Lease(_) => {}
            other => panic!("expected Lease, got {other:?}"),
        }
        fleet_wire::send(&mut coord_tx, &CoordToSidecar::Lease(grant(9_999)))
            .await
            .unwrap();
        // The only other frame we expect is the release.
        loop {
            match fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await {
                Ok(SidecarToCoord::Release { lease }) => {
                    assert_eq!(lease, LeaseId(1));
                    *released_peer.lock().await = true;
                    fleet_wire::send(&mut coord_tx, &CoordToSidecar::Released { lease })
                        .await
                        .unwrap();
                    break;
                }
                // A heartbeat may race in; ignore it.
                Ok(SidecarToCoord::Extend { lease }) => {
                    fleet_wire::send(
                        &mut coord_tx,
                        &CoordToSidecar::Extended {
                            lease,
                            expires: 19_999,
                        },
                    )
                    .await
                    .unwrap();
                }
                Ok(other) => panic!("unexpected frame {other:?}"),
                Err(_) => break,
            }
        }
    });

    let session = CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
        .await
        .unwrap();
    let granted = session
        .lease(&lease_request(), Duration::ZERO)
        .await
        .unwrap();

    // Work that never finishes — an `attach` session, say — plus a shutdown
    // future we fire by hand. `hold_and_run` must pick the shutdown arm,
    // release, and report 128 + SIGINT.
    let (fire_tx, mut fire_rx) = mpsc::channel::<i32>(1);
    let work = async {
        std::future::pending::<()>().await;
        unreachable!()
    };
    let shutdown = async move { fire_rx.recv().await.unwrap_or(2) };

    let held = fleet_sidecar::hold_and_run(
        &session,
        &granted,
        Disposition::Release,
        None,
        work,
        shutdown,
    );
    tokio::pin!(held);
    tokio::select! {
        code = &mut held => panic!("returned {code:?} before the signal"),
        () = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
    }
    fire_tx.send(2).await.unwrap();
    let code = held.await.unwrap();

    assert_eq!(code, 130, "SIGINT propagates as 128 + 2");
    assert!(
        *released.lock().await,
        "the coordinator must have seen a Release"
    );
    peer.await.unwrap();
}

/// A **shareable** lease survives the same shutdown: no `Release` is sent.
///
/// The mirror image of the test above, and the one invariant task 3620
/// deliberately reverses. Releasing a cached lease on every Ctrl-C would make
/// the cross-invocation cache miss every time — which is the whole feature — so
/// a `Keep` disposition holds the board for the next `probe-rs`. It still
/// returns `128 + signum`, and it still kills the child first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shutdown_signal_keeps_a_shareable_lease() {
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();
    let released = Arc::new(Mutex::new(false));
    let released_peer = Arc::clone(&released);

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        match fleet_wire::recv::<SidecarToCoord>(&mut coord_rx)
            .await
            .unwrap()
        {
            SidecarToCoord::Lease(_) => {}
            other => panic!("expected Lease, got {other:?}"),
        }
        fleet_wire::send(&mut coord_tx, &CoordToSidecar::Lease(grant(9_999)))
            .await
            .unwrap();
        while let Ok(msg) = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await {
            match msg {
                SidecarToCoord::Release { .. } => {
                    *released_peer.lock().await = true;
                    break;
                }
                // A heartbeat may race in; ignore it.
                SidecarToCoord::Extend { lease } => {
                    fleet_wire::send(
                        &mut coord_tx,
                        &CoordToSidecar::Extended {
                            lease,
                            expires: 19_999,
                        },
                    )
                    .await
                    .unwrap();
                }
                other => panic!("unexpected frame {other:?}"),
            }
        }
    });

    let session = CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
        .await
        .unwrap();
    let granted = session
        .lease(&lease_request(), Duration::ZERO)
        .await
        .unwrap();

    let (fire_tx, mut fire_rx) = mpsc::channel::<i32>(1);
    let work = async {
        std::future::pending::<()>().await;
        unreachable!()
    };
    let shutdown = async move { fire_rx.recv().await.unwrap_or(2) };

    let mut held = Box::pin(fleet_sidecar::hold_and_run(
        &session,
        &granted,
        Disposition::Keep,
        None,
        work,
        shutdown,
    ));
    tokio::select! {
        code = &mut held => panic!("returned {code:?} before the signal"),
        () = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
    }
    fire_tx.send(2).await.unwrap();
    let code = held.as_mut().await.unwrap();

    assert_eq!(code, 130, "SIGINT still propagates as 128 + 2");
    // Give any (wrongly) sent Release time to reach the peer before asserting.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        !*released.lock().await,
        "a shareable lease must survive Ctrl-C so the next invocation reuses it"
    );
    // Tearing the connection down is what ends the peer's read loop.
    drop(held);
    drop(session);
    peer.await.unwrap();
}

/// A session that outlives its TTL is heartbeat rather than swept.
///
/// With the hardcoded hour gone, a `attach` / `gdb` session routinely outlives
/// the policy default (900s). An expired lease is not benign — the coordinator's
/// sweep closes the relay channels and power-cycles the board — so the keepalive
/// is what makes the short TTL safe. Time is paused, so this asserts on the
/// heartbeat *sequence*, never on wall-clock.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn a_long_session_is_kept_alive() {
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();
    let (seen_tx, mut seen_rx) = mpsc::channel::<u64>(64);

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        match fleet_wire::recv::<SidecarToCoord>(&mut coord_rx)
            .await
            .unwrap()
        {
            SidecarToCoord::Lease(_) => {}
            other => panic!("expected Lease, got {other:?}"),
        }
        // A grant far in the future: `keepalive` derives its interval from the
        // remaining TTL against the *local* clock, and clamps it to 300s.
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 900;
        fleet_wire::send(&mut coord_tx, &CoordToSidecar::Lease(grant(expires)))
            .await
            .unwrap();

        let mut n = 0u64;
        while let Ok(msg) = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await {
            match msg {
                SidecarToCoord::Extend { lease } => {
                    n += 1;
                    fleet_wire::send(
                        &mut coord_tx,
                        &CoordToSidecar::Extended {
                            lease,
                            expires: expires + n * 900,
                        },
                    )
                    .await
                    .unwrap();
                    if seen_tx.send(n).await.is_err() {
                        break;
                    }
                }
                SidecarToCoord::Release { lease } => {
                    let _ =
                        fleet_wire::send(&mut coord_tx, &CoordToSidecar::Released { lease }).await;
                    break;
                }
                other => panic!("unexpected frame {other:?}"),
            }
        }
    });

    let session = CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
        .await
        .unwrap();
    let granted = session
        .lease(&lease_request(), Duration::ZERO)
        .await
        .unwrap();

    // Work that runs well past one heartbeat interval: a 900s TTL yields a
    // 300s interval, so this sees two renewals before finishing.
    let work = async {
        tokio::time::sleep(std::time::Duration::from_secs(700)).await;
        Ok(7)
    };
    let shutdown = std::future::pending::<i32>();
    let code = fleet_sidecar::hold_and_run(
        &session,
        &granted,
        Disposition::Release,
        None,
        work,
        shutdown,
    )
    .await
    .unwrap();

    assert_eq!(code, 7, "the work's exit code is propagated");
    let first = seen_rx.recv().await.expect("a first heartbeat");
    let second = seen_rx.recv().await.expect("a second heartbeat");
    assert_eq!(
        (first, second),
        (1, 2),
        "the session is heartbeat repeatedly"
    );
    peer.await.unwrap();
}

/// #384: a queued lease request **waits** for its turn instead of failing.
///
/// The headline behaviour: the peer replies `Queued`, then later pushes the
/// promotion `Lease` on the same connection, and `lease()` returns that grant.
/// Before this, a CI matrix wider than the fleet failed legs it should merely
/// have delayed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_queued_request_returns_the_grant_when_it_is_promoted() {
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        match fleet_wire::recv::<SidecarToCoord>(&mut coord_rx)
            .await
            .unwrap()
        {
            SidecarToCoord::Lease(_) => {}
            other => panic!("expected Lease, got {other:?}"),
        }
        fleet_wire::send(&mut coord_tx, &CoordToSidecar::Queued { position: 1 })
            .await
            .unwrap();
        // Some other traffic in the meantime must not abort the wait.
        fleet_wire::send(&mut coord_tx, &CoordToSidecar::BoardList(Vec::new()))
            .await
            .unwrap();
        fleet_wire::send(&mut coord_tx, &CoordToSidecar::Lease(grant(9_999)))
            .await
            .unwrap();
    });

    let session = CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
        .await
        .unwrap();
    let granted = session
        .lease(&lease_request(), Duration::from_secs(300))
        .await
        .expect("a queued request is promoted, not refused");
    assert_eq!(granted.lease, LeaseId(1));
    peer.await.unwrap();
}

/// The wait is bounded: a peer that queues us and then says nothing must not
/// park the invocation forever. Time is virtual (`start_paused`), so this
/// exercises the real 300s-shaped deadline without sleeping.
#[tokio::test(start_paused = true)]
async fn a_queued_request_gives_up_at_its_deadline() {
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        match fleet_wire::recv::<SidecarToCoord>(&mut coord_rx)
            .await
            .unwrap()
        {
            SidecarToCoord::Lease(_) => {}
            other => panic!("expected Lease, got {other:?}"),
        }
        fleet_wire::send(&mut coord_tx, &CoordToSidecar::Queued { position: 3 })
            .await
            .unwrap();
        // ...and then nothing at all. Hold the connection open so the failure
        // is the deadline, not a close.
        std::future::pending::<()>().await;
    });

    let session = CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
        .await
        .unwrap();
    let err = session
        .lease(&lease_request(), Duration::from_secs(300))
        .await
        .expect_err("the wait must be bounded");
    let msg = err.to_string();
    assert!(
        msg.contains("still queued at position 3") && msg.contains("300s"),
        "the failure must name the wait: {msg}"
    );
    peer.abort();
}

/// `queue_wait_secs: 0` is the escape hatch: fail fast on contention exactly as
/// the sidecar did before the wait existed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_zero_wait_fails_fast_on_contention() {
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        let _ = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx)
            .await
            .unwrap();
        fleet_wire::send(&mut coord_tx, &CoordToSidecar::Queued { position: 2 })
            .await
            .unwrap();
    });

    let session = CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
        .await
        .unwrap();
    let err = session
        .lease(&lease_request(), Duration::ZERO)
        .await
        .expect_err("zero wait means do not wait");
    assert!(err.to_string().contains("queued at position 2"), "{err}");
    peer.await.unwrap();
}

/// `NoCandidate` fails immediately and says what is actually wrong: waiting for
/// a board that does not exist can only ever time out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_candidate_fails_fast_with_a_useful_message() {
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        let _ = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx)
            .await
            .unwrap();
        fleet_wire::send(
            &mut coord_tx,
            &CoordToSidecar::NoCandidate {
                selector: "id=b9".to_owned(),
                reachable: 4,
            },
        )
        .await
        .unwrap();
    });

    let session = CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
        .await
        .unwrap();
    // A long wait, to prove the failure is the decision and not a timeout.
    let err = session
        .lease(&lease_request(), Duration::from_secs(300))
        .await
        .expect_err("no candidate must not wait");
    let msg = err.to_string();
    assert!(msg.contains("no board matches `id=b9`"), "{msg}");
    assert!(msg.contains("4 boards you can reach"), "{msg}");
    peer.await.unwrap();
}

/// `AtCap` likewise: the caller's own budget is the problem, and the message
/// names the knob rather than blaming the fleet.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn at_cap_fails_fast_and_blames_the_right_thing() {
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        let _ = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx)
            .await
            .unwrap();
        fleet_wire::send(&mut coord_tx, &CoordToSidecar::AtCap { held: 2, cap: 2 })
            .await
            .unwrap();
    });

    let session = CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
        .await
        .unwrap();
    let err = session
        .lease(&lease_request(), Duration::from_secs(300))
        .await
        .expect_err("at cap must not wait");
    let msg = err.to_string();
    assert!(msg.contains("you already hold 2 leases"), "{msg}");
    assert!(msg.contains("max_concurrent_per_subject = 2"), "{msg}");
    peer.await.unwrap();
}
