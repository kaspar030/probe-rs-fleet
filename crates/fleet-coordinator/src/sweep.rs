//! Background lease-expiry sweep.
//!
//! Periodically asks the pure scheduler to [`expire`](Scheduler::expire) leases
//! whose deadline has passed. For each freed lease the coordinator: closes any
//! relay channels on the board, instructs the owning agent to clean up
//! (`ReleaseLease` → power-cycle, optional erase), persists the close, and
//! audits it. Waiters promoted onto a just-freed board are persisted; notifying
//! a *disconnected* sidecar of its promotion is best-effort/deferred for v1 —
//! such a sidecar re-requests on reconnect (architecture §6).

use std::sync::Arc;
use std::time::Duration;

use tokio::time::interval;
use tracing::{debug, warn};

use fleet_core::scheduler::ExpireResult;
use fleet_proto::agent_api::CoordinatorCommand;

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
            let agent = coord.agents().get(&freed.agent).await;
            relay::close_channel(coord.channels(), agent.as_ref(), channel).await;
        }

        // Instruct the owning agent to clean up the board.
        if let Some(agent) = coord.agents().get(&freed.agent).await {
            let cmd = CoordinatorCommand::ReleaseLease {
                lease: freed.lease,
                board: freed.board.clone(),
                erase: false,
            };
            if agent.send_command(cmd).await.is_err() {
                warn!(agent = %freed.agent, "failed to send cleanup to agent");
            }
        } else {
            debug!(agent = %freed.agent, "owning agent offline; cleanup deferred");
        }

        // Persist + audit the close.
        if let Err(e) = coord
            .db()
            .close_lease(freed.lease, now_i64, "expired")
            .await
        {
            warn!(error = %e, "failed to persist lease close");
        }
        let _ = coord
            .db()
            .append_audit(&AuditEntry {
                ts: now_i64,
                principal: Some(freed.holder.0.as_str()),
                action: "lease.expire",
                board: Some(freed.board.0.as_str()),
                lease: Some(freed.lease),
                detail: None,
            })
            .await;
    }

    // Persist any promotions made during the sweep.
    for granted in &result.granted {
        if let Err(e) = coord
            .db()
            .record_lease(
                granted.lease,
                &granted.board,
                &granted.agent.0,
                &granted.holder,
                now_i64,
                i64::try_from(granted.expires).unwrap_or(i64::MAX),
            )
            .await
        {
            warn!(error = %e, "failed to persist promoted lease");
        }
        let _ = coord
            .db()
            .append_audit(&AuditEntry {
                ts: now_i64,
                principal: Some(granted.holder.0.as_str()),
                action: "lease.promote",
                board: Some(granted.board.0.as_str()),
                lease: Some(granted.lease),
                detail: Some("via expiry sweep"),
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Ed25519Signer;
    use crate::clock::Clock;
    use crate::config::{CoordinatorConfig, SigningKeySource};
    use crate::proto::{CoordToSidecar, SidecarToCoord};
    use crate::registry::{AgentHandle, AgentMessage};
    use fleet_core::policy::Policy;
    use fleet_core::scheduler::Scheduler;
    use fleet_proto::board::{Board, BoardState, PowerKind};
    use fleet_proto::ids::{AgentId, BoardId, Principal};
    use fleet_proto::lease::{Constraint, LeaseRequest, Priority};
    use std::collections::HashMap;
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
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tls_cert: "c".into(),
            tls_key: "k".into(),
            client_ca: "ca".into(),
            sqlite_path: ":memory:".into(),
            signing_key: SigningKeySource::Seed(SEED),
            policy: Policy::default(),
            pinned_agents: HashMap::new(),
            sweep_interval_secs: 1,
        }
    }

    async fn coord_with_board(time: Arc<AtomicU64>) -> Coordinator {
        let mut sched = Scheduler::new(Policy::default());
        sched.upsert_board(Board {
            id: BoardId("b1".to_owned()),
            agent: AgentId("agent-a".to_owned()),
            chip: "nRF52840_xxAA".to_owned(),
            tags: vec![],
            exclusive: true,
            power: PowerKind::None,
            state: BoardState::Idle,
        });
        let db = crate::state::Db::connect_in_memory().await.unwrap();
        Coordinator::new(
            config(),
            sched,
            db,
            Ed25519Signer::from_seed(&SEED),
            Arc::new(TestClock(time)),
        )
    }

    #[tokio::test]
    async fn sweep_expires_lease_and_commands_agent_cleanup() {
        let time = Arc::new(AtomicU64::new(1000));
        let coord = coord_with_board(time.clone()).await;

        // Register an agent so cleanup is delivered.
        let (atx, mut arx) = mpsc::channel::<AgentMessage>(16);
        coord
            .agents()
            .insert(AgentId("agent-a".to_owned()), AgentHandle::new(atx))
            .await;

        // alice grabs a short lease.
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        let req = LeaseRequest {
            select: Constraint::Board(BoardId("b1".to_owned())),
            duration_secs: 10,
            priority: Priority::Interactive,
        };
        coord
            .handle_sidecar_message(&Principal("alice".to_owned()), SidecarToCoord::Lease(req), &tx)
            .await
            .unwrap();
        assert!(matches!(rx.recv().await.unwrap(), CoordToSidecar::Lease(_)));
        assert_eq!(coord.db().open_lease_count().await.unwrap(), 1);

        // No expiry yet.
        sweep_once(&coord).await;
        assert_eq!(coord.db().open_lease_count().await.unwrap(), 1);

        // Advance past expiry and sweep.
        time.store(2000, Ordering::SeqCst);
        sweep_once(&coord).await;
        assert_eq!(coord.db().open_lease_count().await.unwrap(), 0);

        // Agent received a ReleaseLease cleanup command.
        match arx.recv().await.unwrap() {
            AgentMessage::Command(CoordinatorCommand::ReleaseLease { board, .. }) => {
                assert_eq!(board, BoardId("b1".to_owned()));
            }
            other => panic!("expected ReleaseLease, got {other:?}"),
        }
    }
}
