//! Cross-invocation lease sharing (task 3620), driven against a mock
//! coordinator peer.
//!
//! `tests/lease_lifecycle.rs` covers what happens *within* one invocation; this
//! file covers what survives *between* them: a second `probe-rs` under the same
//! selector reuses the first one's lease instead of re-leasing, and every way
//! that reuse can be wrong degrades to an ordinary fresh `Lease` rather than an
//! error the user has to understand.
//!
//! Everything runs over `fleet_wire::mock::pair` with the store rooted in a
//! `TempDir`: no coordinator, no TLS, no probe-rs binary, and no
//! `$XDG_RUNTIME_DIR` of the machine running the tests.

use std::sync::Arc;

use fleet_proto::ids::{BoardName, BoardRef, NodeId, OrgId, Subject, SubjectKind};
use fleet_proto::lease::{Constraint, LeaseGrant};
use fleet_proto::token::{AllowedOp, CapabilityToken, SignedToken, SIGNATURE_LEN};
use fleet_proto::{ChannelId, ChannelKind, LeaseId, PROTOCOL_VERSION};
use fleet_sidecar::lease_store::{Disposition, LeaseStore};
use fleet_sidecar::selector::FleetConfig;
use fleet_sidecar::transport::CoordSession;
use fleet_wire::{CoordToSidecar, SidecarToCoord, WireRx, WireTx};
use tokio::sync::Mutex;

const COORDINATOR: &str = "https://coord.example:4443";
const TOKEN: &str = "prfs1_bearer";

fn board(name: &str) -> BoardRef {
    BoardRef::new(
        OrgId("default".to_owned()),
        NodeId("node-a".to_owned()),
        name,
    )
}

fn grant_for(lease: u64, board_name: &str, expires: u64, kind: SubjectKind) -> LeaseGrant {
    LeaseGrant {
        lease: LeaseId(lease),
        board: board(board_name),
        node: NodeId("node-a".to_owned()),
        holder: Subject::new(OrgId("default".to_owned()), kind, "alice"),
        expires,
        // The delegation artefact. Nothing on the reuse path may hand this to a
        // probe-rs child; `a_cache_hit_still_takes_a_fresh_channel_token` pins
        // that.
        token: b"GRANT-TOKEN-NEVER-USE-ME".to_vec(),
    }
}

fn cfg() -> FleetConfig {
    FleetConfig {
        coordinator: COORDINATOR.to_owned(),
        token: TOKEN.to_owned(),
        select: Constraint::Id(BoardName("b1".to_owned())),
        server_cert_sha256: None,
        queue_wait_secs: 0,
    }
}

/// A channel token in the shape the coordinator mints: a postcard
/// [`CapabilityToken`] followed by a signature. The signature is never checked
/// on this path (the *node* verifies it), so dummy bytes are enough.
fn channel_token(lease: u64, board_name: &str) -> Vec<u8> {
    let token = CapabilityToken {
        lease: LeaseId(lease),
        board: board(board_name),
        allowed_ops: AllowedOp::all(),
        expires: 9_999_999,
    };
    SignedToken {
        token_bytes: token.serialize_for_signing().unwrap(),
        signature: [0u8; SIGNATURE_LEN],
    }
    .to_wire()
}

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

/// Two successive invocations under one selector share a single lease.
///
/// The peer panics if it ever sees a *second* `Lease`: that is the regression
/// this whole feature exists to remove. The second invocation must instead
/// revalidate with an `Extend` and come back with the same `LeaseId`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_invocations_under_one_selector_reuse_one_lease() {
    let dir = tempfile::tempdir().unwrap();
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();
    let leases = Arc::new(Mutex::new(0u32));
    let leases_peer = Arc::clone(&leases);

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        while let Ok(msg) = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await {
            match msg {
                SidecarToCoord::Lease(_) => {
                    let mut n = leases_peer.lock().await;
                    *n += 1;
                    assert_eq!(*n, 1, "the second invocation must not re-lease");
                    fleet_wire::send(
                        &mut coord_tx,
                        &CoordToSidecar::Lease(grant_for(1, "b1", 9_999, SubjectKind::User)),
                    )
                    .await
                    .unwrap();
                }
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

    // First invocation: a cold lease, recorded for the next one.
    let mut store = LeaseStore::open_at(dir.path()).expect("a usable store");
    let first = fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store), 1_000)
        .await
        .unwrap();
    assert!(!first.reused, "the first invocation leases cold");
    assert_eq!(first.disposition, Disposition::Keep);
    assert_eq!(first.grant.lease, LeaseId(1));
    // The invocation ends: the guard goes with it, the entry stays.
    drop(first);

    // Second invocation: a fresh process would open a fresh store.
    let mut store = LeaseStore::open_at(dir.path()).unwrap();
    let second = fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store), 1_000)
        .await
        .unwrap();
    assert!(second.reused, "the second invocation reuses the lease");
    assert_eq!(second.grant.lease, LeaseId(1));
    assert_eq!(
        second.grant.expires, 19_999,
        "the revalidating Extend's expiry is what we keep"
    );
    assert_eq!(*leases.lock().await, 1, "exactly one Lease was ever sent");

    drop(second);
    drop(session);
    peer.await.unwrap();
}

/// A stale entry — the coordinator expired or swept the lease while no sidecar
/// was running — degrades to a fresh `Lease`, never to an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lease_the_coordinator_refuses_degrades_to_a_fresh_lease() {
    let dir = tempfile::tempdir().unwrap();
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        let mut leases = 0u64;
        while let Ok(msg) = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await {
            match msg {
                SidecarToCoord::Lease(_) => {
                    leases += 1;
                    fleet_wire::send(
                        &mut coord_tx,
                        &CoordToSidecar::Lease(grant_for(leases, "b1", 9_999, SubjectKind::User)),
                    )
                    .await
                    .unwrap();
                }
                // The lease is gone: the coordinator says so with an Error,
                // which lands on the control channel rather than the extend
                // slot. Reusing `extend` here would have timed out instead and
                // left this frame to poison the next OpenChannel.
                SidecarToCoord::Extend { .. } => {
                    fleet_wire::send(
                        &mut coord_tx,
                        &CoordToSidecar::Error {
                            message: "no such lease".to_owned(),
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

    let mut store = LeaseStore::open_at(dir.path()).unwrap();
    let first = fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store), 1_000)
        .await
        .unwrap();
    assert_eq!(first.grant.lease, LeaseId(1));
    drop(first);

    let mut store = LeaseStore::open_at(dir.path()).unwrap();
    let second = fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store), 1_000)
        .await
        .expect("a stale hit must never surface as an error");
    assert!(!second.reused, "the refused lease was discarded");
    assert_eq!(second.grant.lease, LeaseId(2), "a fresh lease was taken");

    drop(second);
    drop(session);
    peer.await.unwrap();
}

/// An expired entry is discarded rather than used, without so much as a probe:
/// nothing is revalidated, the store simply does not hand it out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_entry_is_never_offered() {
    let dir = tempfile::tempdir().unwrap();
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        let mut leases = 0u64;
        while let Ok(msg) = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await {
            match msg {
                SidecarToCoord::Lease(_) => {
                    leases += 1;
                    fleet_wire::send(
                        &mut coord_tx,
                        &CoordToSidecar::Lease(grant_for(leases, "b1", 2_000, SubjectKind::User)),
                    )
                    .await
                    .unwrap();
                }
                SidecarToCoord::Extend { .. } => {
                    panic!("an expired entry must not even be probed")
                }
                other => panic!("unexpected frame {other:?}"),
            }
        }
    });

    let session = CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
        .await
        .unwrap();

    let mut store = LeaseStore::open_at(dir.path()).unwrap();
    let first = fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store), 1_000)
        .await
        .unwrap();
    assert_eq!(first.grant.lease, LeaseId(1));
    drop(first);

    // Well past the grant's 2_000s expiry.
    let mut store = LeaseStore::open_at(dir.path()).unwrap();
    let second = fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store), 5_000)
        .await
        .unwrap();
    assert!(!second.reused);
    assert_eq!(second.grant.lease, LeaseId(2));

    drop(second);
    drop(session);
    peer.await.unwrap();
}

/// A cache hit still takes a **fresh** per-channel credential.
///
/// The stored grant's token is the delegation artefact, not a data-plane
/// credential (architecture §6.5), and a reused one would be stale by
/// construction. Both credentials the child path uses — the capability token
/// the node verifies and the serve token `probe-rs serve` accepts — come from
/// `ChannelOpened`, on the hit path exactly as on the cold one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cache_hit_still_takes_a_fresh_channel_token() {
    let dir = tempfile::tempdir().unwrap();
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        while let Ok(msg) = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await {
            match msg {
                SidecarToCoord::Lease(_) => {
                    fleet_wire::send(
                        &mut coord_tx,
                        &CoordToSidecar::Lease(grant_for(1, "b1", 9_999, SubjectKind::User)),
                    )
                    .await
                    .unwrap();
                }
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
                SidecarToCoord::OpenChannel { lease, .. } => {
                    fleet_wire::send(
                        &mut coord_tx,
                        &CoordToSidecar::ChannelOpened {
                            channel: ChannelId(7),
                            token: channel_token(lease.0, "b1"),
                            serve_token: format!("serve-for-lease-{}", lease.0),
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

    let mut store = LeaseStore::open_at(dir.path()).unwrap();
    drop(
        fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store), 1_000)
            .await
            .unwrap(),
    );

    let mut store = LeaseStore::open_at(dir.path()).unwrap();
    let hit = fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store), 1_000)
        .await
        .unwrap();
    assert!(hit.reused);
    assert!(
        hit.grant.token.is_empty(),
        "a reconstructed grant carries no token at all"
    );

    let opened = fleet_sidecar::open_channel_verified(
        &session,
        hit.grant.lease,
        ChannelKind::Data,
        Some(&hit.grant.board),
    )
    .await
    .unwrap()
    .expect("the channel names the board we cached");
    assert_eq!(
        opened.token,
        channel_token(1, "b1"),
        "the capability token is the fresh per-channel one"
    );
    // And the data-plane credential is the lease-scoped serve token that came
    // back on this same `ChannelOpened` — never anything reconstructed locally.
    assert_eq!(opened.serve_token, "serve-for-lease-1");
    assert_ne!(
        opened.token,
        b"GRANT-TOKEN-NEVER-USE-ME".to_vec(),
        "never the stored grant's token"
    );

    drop(hit);
    drop(session);
    peer.await.unwrap();
}

/// A CI (`Workload`) lease is never cached: it is released at exit exactly as
/// before, so a finished job does not strand a board for a policy TTL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_workload_lease_is_not_shareable() {
    let dir = tempfile::tempdir().unwrap();
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        let mut leases = 0u64;
        while let Ok(msg) = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await {
            match msg {
                SidecarToCoord::Lease(_) => {
                    leases += 1;
                    fleet_wire::send(
                        &mut coord_tx,
                        &CoordToSidecar::Lease(grant_for(
                            leases,
                            "b1",
                            9_999,
                            SubjectKind::Workload,
                        )),
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

    let mut store = LeaseStore::open_at(dir.path()).unwrap();
    let first = fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store), 1_000)
        .await
        .unwrap();
    assert_eq!(
        first.disposition,
        Disposition::Release,
        "CI releases at exit"
    );
    drop(first);

    // Nothing was written, so the next invocation leases cold — with no Extend
    // in between (the peer would panic on one).
    let mut store = LeaseStore::open_at(dir.path()).unwrap();
    let second = fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store), 1_000)
        .await
        .unwrap();
    assert!(!second.reused);
    assert_eq!(second.grant.lease, LeaseId(2));

    drop(second);
    drop(session);
    peer.await.unwrap();
}

/// A *concurrent* invocation must not take the cached lease.
///
/// This is the interlock the cache would otherwise remove: today the second
/// invocation's `Lease` is answered `Queued` → "board contended", and neither
/// the coordinator nor the node caps sessions per board. Holding the first
/// invocation's use-lock makes the second one fall through to a fresh `Lease`,
/// which reproduces exactly that pre-existing behaviour.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_concurrent_invocation_does_not_take_the_cached_lease() {
    let dir = tempfile::tempdir().unwrap();
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        let mut leases = 0u64;
        while let Ok(msg) = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await {
            match msg {
                SidecarToCoord::Lease(_) => {
                    leases += 1;
                    if leases == 1 {
                        fleet_wire::send(
                            &mut coord_tx,
                            &CoordToSidecar::Lease(grant_for(1, "b1", 9_999, SubjectKind::User)),
                        )
                        .await
                        .unwrap();
                    } else {
                        // What the coordinator really says when the board is
                        // already held: the contention is reported, not hidden.
                        fleet_wire::send(&mut coord_tx, &CoordToSidecar::Queued { position: 0 })
                            .await
                            .unwrap();
                    }
                }
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

    let mut store = LeaseStore::open_at(dir.path()).unwrap();
    drop(
        fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store), 1_000)
            .await
            .unwrap(),
    );

    // Invocation A is still running and holds the record's use-lock.
    let mut store_a = LeaseStore::open_at(dir.path()).unwrap();
    let live = fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store_a), 1_000)
        .await
        .unwrap();
    assert!(live.reused);

    // Invocation B starts while A holds the board.
    let mut store_b = LeaseStore::open_at(dir.path()).unwrap();
    let err = fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store_b), 1_000)
        .await
        .expect_err("B must not silently share A's board");
    let rendered = err.to_string();
    assert!(
        rendered.contains("contended"),
        "B sees today's board-contention error, not a new one: {rendered}"
    );

    // Once A finishes, B's successor hits again.
    drop(live);
    let mut store_b = LeaseStore::open_at(dir.path()).unwrap();
    let after = fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store_b), 1_000)
        .await
        .unwrap();
    assert!(after.reused, "the slot is free again once A exits");

    drop(after);
    drop(session);
    peer.await.unwrap();
}

/// A concurrent invocation that lost the cache slot must not touch the store on
/// the way out — in *either* finishing order.
///
/// Regression test. `acquire_lease` returns `Disposition::Release` both when the
/// lease is unshareable *and* when another live invocation holds the slot, so
/// `run_fleet`'s epilogue used to key its `forget` on the disposition alone. If
/// B (the loser) finished after A, B deleted A's record: A's board stayed held
/// — `Keep` is deliberate — with nothing in the store naming it, so nothing
/// could reuse it and nothing released it until the policy TTL. Exactly the
/// stranding Guard A exists to prevent, via the concurrent path.
///
/// The A-then-B order is the one that breaks; B-then-A self-heals, because A's
/// `touch_expiry` still finds the entry in its in-memory records and `save`
/// merges it back. So this test finishes them A first, B second.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_losing_concurrent_invocation_never_deletes_the_winners_record() {
    let dir = tempfile::tempdir().unwrap();
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        let mut leases = 0u64;
        while let Ok(msg) = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await {
            match msg {
                // A selector matching several boards: B gets a *different*
                // board rather than being queued, which is what makes both
                // invocations run concurrently and the bug reachable.
                SidecarToCoord::Lease(_) => {
                    leases += 1;
                    let name = if leases == 1 { "b1" } else { "b2" };
                    fleet_wire::send(
                        &mut coord_tx,
                        &CoordToSidecar::Lease(grant_for(leases, name, 9_999, SubjectKind::User)),
                    )
                    .await
                    .unwrap();
                }
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

    // A leases b1 cold and records it; it owns the slot and keeps the lease.
    let mut store_a = LeaseStore::open_at(dir.path()).unwrap();
    let a = fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store_a), 1_000)
        .await
        .unwrap();
    assert_eq!(a.disposition, Disposition::Keep);
    assert!(a.owns_slot, "A took the slot");
    assert_eq!(a.grant.board.name, "b1");

    // B starts while A is live: the slot is taken, so B leases b2 cold and must
    // release at exit. Crucially it does **not** own the slot.
    let mut store_b = LeaseStore::open_at(dir.path()).unwrap();
    let b = fleet_sidecar::acquire_lease(&session, &cfg(), Some(&mut store_b), 1_000)
        .await
        .unwrap();
    assert_eq!(b.disposition, Disposition::Release);
    assert!(
        !b.owns_slot,
        "B lost the slot, so the record on disk is not B's to write"
    );
    assert_eq!(b.grant.board.name, "b2");

    // A finishes first: it owns the slot, so its epilogue persists the latest
    // expiry and keeps b1 for the next invocation.
    fleet_sidecar::release_slot(Some(&mut store_a), &cfg(), &a, 19_999, 1_000);
    drop(a);

    // B finishes second, through the *same* epilogue. This is the ordering that
    // used to delete A's record: B's disposition is `Release`, so an epilogue
    // keyed on the disposition alone would `forget` a slot B never owned.
    fleet_sidecar::release_slot(Some(&mut store_b), &cfg(), &b, 9_999, 1_000);
    drop(b);

    // A's record must still be there, and still reusable.
    let mut next = LeaseStore::open_at(dir.path()).unwrap();
    let (record, _guard) = next
        .get(COORDINATOR, TOKEN, &cfg().select, 1_000)
        .expect("A's kept lease must survive B's exit");
    assert_eq!(record.lease, LeaseId(1));
    assert_eq!(
        record.board.name, "b1",
        "the board A is still holding is the one the store names"
    );
    assert_eq!(
        record.expires, 19_999,
        "and it carries A's heartbeat expiry, not B's"
    );

    drop(session);
    peer.await.unwrap();
}

/// A channel token naming a **different** board forces a cold re-lease.
///
/// Lease ids restart at 1 on every coordinator boot and nothing on the wire
/// identifies a boot, so a persisted id can name a different live lease after a
/// restart — one the same subject legitimately holds, so even the `Extend`
/// revalidation succeeds. The channel token's `BoardRef` is what catches it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_channel_naming_another_board_is_refused() {
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        let mut closed = false;
        while let Ok(msg) = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await {
            match msg {
                SidecarToCoord::OpenChannel { .. } => {
                    // A post-restart lease id that now names somebody else's
                    // board entirely.
                    fleet_wire::send(
                        &mut coord_tx,
                        &CoordToSidecar::ChannelOpened {
                            channel: ChannelId(9),
                            token: channel_token(1, "some-other-board"),
                            serve_token: "serve-for-someone-else".to_owned(),
                        },
                    )
                    .await
                    .unwrap();
                }
                SidecarToCoord::CloseChannel { channel } => {
                    assert_eq!(channel, ChannelId(9), "the bad channel is handed back");
                    closed = true;
                    break;
                }
                other => panic!("unexpected frame {other:?}"),
            }
        }
        assert!(closed, "the mismatching channel must be closed");
    });

    let session = CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
        .await
        .unwrap();

    let opened = fleet_sidecar::open_channel_verified(
        &session,
        LeaseId(1),
        ChannelKind::Data,
        Some(&board("b1")),
    )
    .await
    .unwrap();
    assert!(
        opened.is_none(),
        "a channel on the wrong board is refused, not driven"
    );

    peer.await.unwrap();
}

/// With no store at all — the opt-out, or a non-unix build — nothing changes:
/// every invocation leases cold and releases at exit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_store_every_invocation_leases_afresh() {
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        let mut leases = 0u64;
        while let Ok(msg) = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await {
            match msg {
                SidecarToCoord::Lease(_) => {
                    leases += 1;
                    fleet_wire::send(
                        &mut coord_tx,
                        &CoordToSidecar::Lease(grant_for(leases, "b1", 9_999, SubjectKind::User)),
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

    for expected in 1..=2 {
        let acquired = fleet_sidecar::acquire_lease(&session, &cfg(), None, 1_000)
            .await
            .unwrap();
        assert!(!acquired.reused);
        assert_eq!(acquired.grant.lease, LeaseId(expected));
        assert_eq!(acquired.disposition, Disposition::Release);
    }

    drop(session);
    peer.await.unwrap();
}

/// **The channel-lifetime regression test.** An invocation *ending* closes its
/// channel, even when the lease is deliberately **kept** for the next one.
///
/// Driven through `run_on_channel` — the seam both planes share — rather than a
/// synthetic `CloseChannel`, because a synthetic one proves nothing: the bug is
/// precisely that no code path sent it. On the lease-cache-hit path
/// `hold_and_run` with `Disposition::Keep` sends no `Release`, and the node
/// reports `SessionClosed` only in reply to a `KillSession`, so before this the
/// node's `probe-rs serve` kept the first invocation's `ProbeLease` and the next
/// invocation's `attach` was refused (`ProbeInUse`; `errno 16` before serve was
/// reused at all).
///
/// The peer also asserts the close is *acknowledged*: the shim exits
/// immediately afterwards, so an unacknowledged write can lose the race with
/// process teardown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invocation_ending_closes_its_channel_with_the_lease_kept() {
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();
    let closed = Arc::new(Mutex::new(Vec::<ChannelId>::new()));
    let closed_peer = Arc::clone(&closed);

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        while let Ok(msg) = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await {
            match msg {
                SidecarToCoord::OpenChannel { lease, .. } => {
                    fleet_wire::send(
                        &mut coord_tx,
                        &CoordToSidecar::ChannelOpened {
                            channel: ChannelId(7),
                            token: channel_token(lease.0, "b1"),
                            serve_token: "serve-tok".to_owned(),
                        },
                    )
                    .await
                    .unwrap();
                }
                SidecarToCoord::CloseChannel { channel } => {
                    closed_peer.lock().await.push(channel);
                    // The coordinator's real `relay::close_channel` acks; the
                    // sidecar waits for exactly this frame.
                    fleet_wire::send(&mut coord_tx, &CoordToSidecar::ChannelClosed { channel })
                        .await
                        .unwrap();
                }
                // No `Release`: the lease is kept for the next invocation.
                other => panic!("unexpected frame {other:?}"),
            }
        }
    });

    let session = CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
        .await
        .unwrap();
    let opened = fleet_sidecar::open_channel_verified(&session, LeaseId(1), ChannelKind::Data, None)
        .await
        .unwrap()
        .expect("no expected board, so it always verifies");
    assert_eq!(opened.serve_token, "serve-tok");

    // One invocation's worth of work, returning as the probe-rs child would.
    let code = fleet_sidecar::run_on_channel(&session, opened.channel, async { Ok(0) })
        .await
        .unwrap();
    assert_eq!(code, 0);

    assert_eq!(
        *closed.lock().await,
        vec![ChannelId(7)],
        "the channel must be handed back when the invocation ends"
    );

    drop(session);
    peer.await.unwrap();
}

/// The close happens on the **failing** arm too: a probe-rs run that exits with
/// an error still owes the board's `serve` its probe back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_invocation_still_closes_its_channel() {
    let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();
    let closed = Arc::new(Mutex::new(false));
    let closed_peer = Arc::clone(&closed);

    let peer = tokio::spawn(async move {
        handshake(&mut coord_tx, &mut coord_rx).await;
        while let Ok(msg) = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await {
            match msg {
                SidecarToCoord::CloseChannel { channel } => {
                    *closed_peer.lock().await = true;
                    fleet_wire::send(&mut coord_tx, &CoordToSidecar::ChannelClosed { channel })
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
    let err = fleet_sidecar::run_on_channel(&session, ChannelId(7), async {
        Err(fleet_sidecar::transport::TransportError::Io("boom".to_owned()).into())
    })
    .await;
    assert!(err.is_err(), "the work's error must be propagated");
    assert!(*closed.lock().await, "and the channel still handed back");

    drop(session);
    peer.await.unwrap();
}
