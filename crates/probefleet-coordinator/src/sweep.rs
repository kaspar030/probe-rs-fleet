//! Background lease-expiry sweep.
//!
//! Periodically asks the pure scheduler to [`expire`](probefleet_core::scheduler::Scheduler::expire)
//! leases whose deadline has passed. For each freed lease the coordinator:
//! closes any relay channels on the board, instructs the owning node to clean
//! up (`ReleaseLease` → power-cycle, optional erase), persists the close, and
//! audits it. A waiter promoted onto a just-freed board is persisted **and
//! pushed** its grant on its own connection; if that connection has gone away
//! the promotion is undeliverable and the board is released again for the next
//! waiter. A *disconnected* sidecar no longer has a waiter to promote in the
//! first place — its queued requests are dropped when its connection closes
//! (architecture §6).
//!
//! **No authorization check happens here, deliberately**: the sweep is
//! system-initiated, not caller-initiated, so there is no subject to check.
//! That omission is not the same bug as the missing checks on the *request*
//! paths in [`crate::core`] — it is the absence of a caller. Every write it
//! makes still goes through the freed board's [`crate::state::OrgDb`], so a
//! sweep cannot cross a tenant boundary either.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::interval;
use tracing::{debug, warn};

use probefleet_core::scheduler::ExpireResult;
use probefleet_proto::node_api::CoordinatorCommand;

use crate::core::Coordinator;
use crate::relay;
use crate::state::AuditEntry;

/// Run the expiry sweep forever, ticking every `sweep_interval_secs`.
pub async fn run(coord: Arc<Coordinator>) {
    let period = Duration::from_secs(coord.config().sweep_interval_secs.max(1));
    let mut ticker = interval(period);
    loop {
        ticker.tick().await;
        sweep_once(&coord).await;
    }
}

/// Perform a single expiry sweep. Factored out for unit testing.
pub async fn sweep_once(coord: &Coordinator) {
    let now = coord.now();
    let result: ExpireResult = {
        let mut sched = coord.scheduler().lock().await;
        sched.expire(now)
    };

    let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);

    for freed in &result.freed {
        debug!(lease = ?freed.lease, board = %freed.board, "lease expired");

        // Close any open relay channels for the expired lease.
        for channel in coord.channels().channels_for_lease(freed.lease).await {
            let node = coord.nodes().get(&freed.node).await;
            relay::close_channel(coord.channels(), node.as_ref(), channel).await;
        }

        // Instruct the owning node to clean up the board.
        if let Some(node) = coord.nodes().get(&freed.node).await {
            let cmd = CoordinatorCommand::ReleaseLease {
                lease: freed.lease,
                board: freed.board.board_name(),
                erase: false,
            };
            if node.send_command(cmd).await.is_err() {
                warn!(node = %freed.node, "failed to send cleanup to node");
            }
        } else {
            debug!(node = %freed.node, "owning node offline; cleanup deferred");
        }

        // Persist + audit the close, scoped to the freed board's org.
        let scoped = coord.db().scoped(freed.board.org.clone());
        if let Err(e) = scoped.close_lease(freed.lease, now_i64, "expired").await {
            warn!(error = %e, "failed to persist lease close");
        }
        let _ = scoped
            .append_audit(&AuditEntry {
                ts: now_i64,
                subject: Some(&freed.holder.to_string()),
                action: "lease.expire",
                node: Some(freed.board.node.0.as_str()),
                board: Some(freed.board.name.as_str()),
                lease: Some(freed.lease),
                detail: None,
            })
            .await;
    }

    // Settle any promotions made during the sweep: persist, push the grant to
    // the promoted holder, and — if that holder is unreachable — release the
    // board again for the next waiter, rather than leaving it held by nobody.
    for promotion in result.granted {
        if let Err(e) = coord
            .settle_promotion(Some(promotion), Some("via expiry sweep"))
            .await
        {
            warn!(error = %e, "failed to settle a promoted lease");
        }
    }

    // Expired / spent credentials and pending approvals (sessions, refresh
    // tokens, workload tokens, API keys, signups, device and node
    // approvals) are forgs' rows. Expiry and single use are *enforced* at
    // verification time, so this is hygiene — but it is also what returns
    // capacity to `max_pending_nodes` after an abandoned or hostile burst of
    // unauthenticated `/node/register/start` calls.
    match coord.db().forgs().sweep(now).await {
        Ok(counts) => debug!(?counts, "expired credentials swept"),
        Err(e) => warn!(error = %e, "failed to sweep expired credentials"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Ed25519Signer;
    use crate::clock::Clock;
    use crate::config::{CoordinatorConfig, SigningKeySource};
    use crate::proto::{CoordToSidecar, SidecarToCoord};
    use crate::registry::{NodeHandle, NodeMessage};
    use crate::subject::testkit;
    use crate::subject::{FleetRole, Subject};
    use probefleet_core::policy::Policy;
    use probefleet_core::scheduler::{RequesterId, Scheduler};
    use probefleet_proto::board::{Board, BoardState, PowerKind};
    use probefleet_proto::ids::{BoardName, BoardRef, NodeId, OrgId};
    use probefleet_proto::lease::{Constraint, LeaseRequest, Priority};
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::mpsc;

    const SEED: [u8; 32] = [3u8; 32];

    struct TestClock(Arc<AtomicU64>);
    impl Clock for TestClock {
        fn now_secs(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn config() -> CoordinatorConfig {
        CoordinatorConfig {
            sqlite_path: ":memory:".into(),
            signing_key: SigningKeySource::Seed(SEED),
            ..CoordinatorConfig::default()
        }
    }

    /// The node id the coordinator would mint for one of this org's nodes.
    ///
    /// Built by the production constructor: the node registry, the board key
    /// and the `node` row must all agree on one id, and the only way to be
    /// sure a fixture agrees with production is to call what production calls.
    fn node(org: &OrgId) -> NodeId {
        crate::state::node_id_for(org, "node-a")
    }

    /// A coordinator with one board in org `acme`, and alice a member.
    async fn coord_with_board(time: Arc<AtomicU64>) -> (Coordinator, OrgId, Subject) {
        let db = testkit::db().await;
        let alice = testkit::member(&db, "acme", "alice", FleetRole::Member).await;
        let org = testkit::org(&db, "acme").await;
        let node = node(&org);
        let mut sched = Scheduler::new(Policy::default());
        sched.upsert_board(Board {
            id: BoardRef::new(org.clone(), node.clone(), "b1"),
            node: node.clone(),
            chip: "nRF52840_xxAA".to_owned(),
            model: None,
            tags: vec![],
            exclusive: true,
            power: PowerKind::None,
            state: BoardState::Idle,
            serial_ports: Vec::new(),
        });
        db.scoped(org.clone())
            .ensure_node(&node, 1000)
            .await
            .unwrap();
        let coord = Coordinator::new(
            config(),
            sched,
            db,
            Ed25519Signer::from_seed(&SEED),
            Arc::new(TestClock(time)),
        );
        (coord, org, alice)
    }

    #[tokio::test]
    async fn sweep_expires_lease_and_commands_agent_cleanup() {
        let time = Arc::new(AtomicU64::new(1000));
        let (coord, org, alice) = coord_with_board(time.clone()).await;

        // Register a node so cleanup is delivered.
        let (atx, mut arx) = mpsc::channel::<NodeMessage>(16);
        coord.nodes().insert(node(&org), NodeHandle::new(atx)).await;

        // alice grabs a short lease.
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        let req = LeaseRequest {
            select: Constraint::Id(BoardName("b1".to_owned())),
            duration_secs: 10,
            priority: Priority::Interactive,
        };
        coord
            .handle_sidecar_message(
                &alice,
                SidecarToCoord::Lease(req),
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        assert!(matches!(rx.recv().await.unwrap(), CoordToSidecar::Lease(_)));
        let scoped = coord.db().scoped(org.clone());
        assert_eq!(scoped.open_lease_count().await.unwrap(), 1);

        // No expiry yet.
        sweep_once(&coord).await;
        assert_eq!(scoped.open_lease_count().await.unwrap(), 1);

        // Advance past expiry and sweep.
        time.store(2000, Ordering::SeqCst);
        sweep_once(&coord).await;
        assert_eq!(scoped.open_lease_count().await.unwrap(), 0);

        // Node received a ReleaseLease cleanup command, addressed by the
        // node-local board name it knows.
        match arx.recv().await.unwrap() {
            NodeMessage::Command(CoordinatorCommand::ReleaseLease { board, .. }) => {
                assert_eq!(board, BoardName("b1".to_owned()));
            }
            other => panic!("expected ReleaseLease, got {other:?}"),
        }
    }

    /// The expiry path pushes a promotion too, not just the release path: a
    /// waiter whose turn comes round because the holder's TTL ran out is told
    /// so on its own connection.
    #[tokio::test]
    async fn sweep_pushes_a_promotion_to_the_waiting_sidecar() {
        let time = Arc::new(AtomicU64::new(1000));
        let (coord, org, alice) = coord_with_board(time.clone()).await;
        let bob = testkit::member(coord.db(), "acme", "bob", FleetRole::Member).await;

        let req = || LeaseRequest {
            select: Constraint::Id(BoardName("b1".to_owned())),
            duration_secs: 10,
            priority: Priority::Interactive,
        };

        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &alice,
                SidecarToCoord::Lease(req()),
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        assert!(matches!(rx.recv().await.unwrap(), CoordToSidecar::Lease(_)));

        let (bob_tx, mut bob_rx) = mpsc::channel::<CoordToSidecar>(16);
        let bob_id = coord.sidecars().mint();
        coord.sidecars().insert(bob_id, bob_tx.clone()).await;
        coord
            .handle_sidecar_message(&bob, SidecarToCoord::Lease(req()), &bob_tx, bob_id)
            .await
            .unwrap();
        assert!(matches!(
            bob_rx.recv().await.unwrap(),
            CoordToSidecar::Queued { .. }
        ));

        time.store(2000, Ordering::SeqCst);
        sweep_once(&coord).await;

        match bob_rx.recv().await.unwrap() {
            CoordToSidecar::Lease(g) => assert_eq!(&g.holder, bob.key()),
            other => panic!("expected a promotion push, got {other:?}"),
        }
        assert_eq!(
            coord.db().scoped(org).open_lease_count().await.unwrap(),
            1,
            "alice's expired lease is closed, bob's promotion is open"
        );
    }
}
