//! The transport-agnostic coordinator core.
//!
//! [`Coordinator`] ties together the shared state — the pure
//! [`fleet_core::scheduler::Scheduler`] (behind a short-held mutex), the
//! [`Db`], the [`AgentRegistry`]/[`ChannelTable`], the ed25519 token
//! [`Ed25519Signer`], and the clock — and implements the decision logic for
//! every control-plane message *without* any socket I/O. The [`crate::server`]
//! module is the thin I/O shell that reads frames off TLS streams and calls
//! into here; this split keeps the lease/relay/auth logic unit-testable over
//! in-memory channels.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use fleet_core::scheduler::{LeaseDecision, Scheduler};
use fleet_proto::agent_api::AgentReport;
use fleet_proto::board::{Board, BoardState};
use fleet_proto::ids::{AgentId, BoardId, LeaseId, Principal};
use fleet_proto::lease::LeaseRequest;

use crate::auth::{default_allowed_ops, Ed25519Signer};
use crate::clock::SharedClock;
use crate::config::CoordinatorConfig;
use crate::error::Result;
use crate::proto::{CoordToSidecar, SidecarToCoord};
use crate::registry::{AgentRegistry, ChannelTable};
use crate::relay;
use crate::state::{AuditEntry, Db};

/// The shared coordinator state and control-plane logic.
pub struct Coordinator {
    config: CoordinatorConfig,
    scheduler: Mutex<Scheduler>,
    db: Db,
    signer: Ed25519Signer,
    agents: AgentRegistry,
    channels: ChannelTable,
    clock: SharedClock,
}

impl Coordinator {
    /// Build a coordinator from its parts.
    #[must_use]
    pub fn new(
        config: CoordinatorConfig,
        scheduler: Scheduler,
        db: Db,
        signer: Ed25519Signer,
        clock: SharedClock,
    ) -> Self {
        Self {
            config,
            scheduler: Mutex::new(scheduler),
            db,
            signer,
            agents: AgentRegistry::new(),
            channels: ChannelTable::new(),
            clock,
        }
    }

    /// The static configuration.
    #[must_use]
    pub fn config(&self) -> &CoordinatorConfig {
        &self.config
    }

    /// The agent registry.
    #[must_use]
    pub fn agents(&self) -> &AgentRegistry {
        &self.agents
    }

    /// The relay channel table.
    #[must_use]
    pub fn channels(&self) -> &ChannelTable {
        &self.channels
    }

    /// The token signer.
    #[must_use]
    pub fn signer(&self) -> &Ed25519Signer {
        &self.signer
    }

    /// The persistent state handle.
    #[must_use]
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// The scheduler (locked).
    #[must_use]
    pub fn scheduler(&self) -> &Mutex<Scheduler> {
        &self.scheduler
    }

    /// The current time in epoch seconds.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.clock.now_secs()
    }

    fn now_i64(&self) -> i64 {
        i64::try_from(self.now()).unwrap_or(i64::MAX)
    }

    /// Handle one [`AgentReport`] from a connected agent.
    ///
    /// # Errors
    ///
    /// Returns a [`CoordinatorError`] only on a fatal DB error; routine report
    /// content is logged and tolerated.
    pub async fn handle_agent_report(
        &self,
        agent_id: &AgentId,
        report: AgentReport,
    ) -> Result<()> {
        match report {
            AgentReport::Register {
                agent,
                protocol_version,
            } => {
                debug!(%agent, protocol_version, "agent register");
                self.audit("agent.register", None, None, None, Some(&agent.0))
                    .await?;
            }
            AgentReport::Inventory(inv) => {
                // The agent's inventory is reconciled into the scheduler's board
                // set. We translate presence to a coarse board view; the agent
                // owns the authoritative board metadata via its boards.toml,
                // which arrives separately (future work) — for v1 we record
                // presence in the audit log and refresh `last_seen`.
                self.audit(
                    "agent.inventory",
                    None,
                    None,
                    None,
                    Some(&format!("{} boards", inv.boards.len())),
                )
                .await?;
            }
            AgentReport::Heartbeat { uptime_secs } => {
                debug!(%agent_id, uptime_secs, "heartbeat");
            }
            AgentReport::Fault { board, reason } => {
                warn!(%agent_id, %board, %reason, "board fault");
                self.fault_board(&board, &reason).await;
                self.audit("board.fault", None, Some(&board.0), None, Some(&reason))
                    .await?;
            }
            AgentReport::Log {
                level,
                board,
                message,
            } => {
                debug!(%agent_id, ?level, ?board, %message, "agent log");
                self.audit(
                    "agent.log",
                    None,
                    board.as_ref().map(|b| b.0.as_str()),
                    None,
                    Some(&message),
                )
                .await?;
            }
            AgentReport::PowerEvent { board, action } => {
                debug!(%agent_id, %board, ?action, "power event");
                self.audit(
                    "board.power",
                    None,
                    Some(&board.0),
                    None,
                    Some(&format!("{action:?}")),
                )
                .await?;
            }
            AgentReport::SessionClosed { channel, exit_code } => {
                debug!(%agent_id, ?channel, ?exit_code, "session closed");
                relay::close_channel(&self.channels, None, channel).await;
            }
        }
        Ok(())
    }

    /// Mark a board as faulted in the scheduler (best-effort).
    async fn fault_board(&self, board: &BoardId, reason: &str) {
        let mut sched = self.scheduler.lock().await;
        if let Some(existing) = sched.board(board).cloned() {
            let faulted = Board {
                state: BoardState::Faulted {
                    reason: reason.to_owned(),
                },
                ..existing
            };
            sched.upsert_board(faulted);
        }
    }

    /// Handle one [`SidecarToCoord`] message, replying via `tx`.
    ///
    /// # Errors
    ///
    /// Returns a [`CoordinatorError`] only on a fatal error (DB / token
    /// signing); request-level failures are reported back to the sidecar via
    /// [`CoordToSidecar::Error`] and return `Ok`.
    pub async fn handle_sidecar_message(
        &self,
        principal: &Principal,
        msg: SidecarToCoord,
        tx: &mpsc::Sender<CoordToSidecar>,
    ) -> Result<()> {
        match msg {
            SidecarToCoord::Hello { .. } => {
                // Hello after handshake is a protocol error but not fatal.
                let _ = tx
                    .send(CoordToSidecar::Error {
                        message: "unexpected Hello".to_owned(),
                    })
                    .await;
            }
            SidecarToCoord::Lease(req) => {
                let reply = self.request_lease(principal, req).await?;
                let _ = tx.send(reply).await;
            }
            SidecarToCoord::Extend { lease } => {
                let reply = self.extend_lease(principal, lease).await?;
                let _ = tx.send(reply).await;
            }
            SidecarToCoord::Release { lease } => {
                let reply = self.release_lease(principal, lease).await?;
                let _ = tx.send(reply).await;
            }
            SidecarToCoord::OpenChannel { lease, kind } => {
                let reply = self.open_channel(principal, lease, kind, tx.clone()).await?;
                if let Some(reply) = reply {
                    let _ = tx.send(reply).await;
                }
            }
            SidecarToCoord::Data(frame) => {
                self.relay_from_sidecar(frame).await;
            }
            SidecarToCoord::CloseChannel { channel } => {
                let route = self.channels.get(channel).await;
                let agent = match route {
                    Some(r) => self.agents.get(&r.agent).await,
                    None => None,
                };
                relay::close_channel(&self.channels, agent.as_ref(), channel).await;
            }
        }
        Ok(())
    }

    /// Process a lease request: ask the scheduler, mint + persist a grant.
    async fn request_lease(
        &self,
        principal: &Principal,
        req: LeaseRequest,
    ) -> Result<CoordToSidecar> {
        let now = self.now();
        let decision = {
            let mut sched = self.scheduler.lock().await;
            sched.request_lease(principal.clone(), req, now)
        };
        match decision {
            LeaseDecision::Granted(granted) => {
                let grant = self
                    .signer
                    .grant_to_wire(&granted, default_allowed_ops())?;
                self.db
                    .record_lease(
                        granted.lease,
                        &granted.board,
                        &granted.agent.0,
                        &granted.holder,
                        self.now_i64(),
                        i64::try_from(granted.expires).unwrap_or(i64::MAX),
                    )
                    .await?;
                self.audit(
                    "lease.grant",
                    Some(&principal.0),
                    Some(&granted.board.0),
                    Some(granted.lease),
                    None,
                )
                .await?;
                Ok(CoordToSidecar::Lease(grant))
            }
            LeaseDecision::Queued { position } => Ok(CoordToSidecar::Queued { position }),
        }
    }

    /// Extend a lease the principal holds.
    async fn extend_lease(
        &self,
        principal: &Principal,
        lease: LeaseId,
    ) -> Result<CoordToSidecar> {
        let now = self.now();
        let new_expires = {
            let mut sched = self.scheduler.lock().await;
            sched.extend_lease(lease, now)
        };
        match new_expires {
            Some(expires) => {
                self.db
                    .update_lease_expiry(lease, i64::try_from(expires).unwrap_or(i64::MAX))
                    .await?;
                self.audit(
                    "lease.extend",
                    Some(&principal.0),
                    None,
                    Some(lease),
                    None,
                )
                .await?;
                Ok(CoordToSidecar::Extended { lease, expires })
            }
            None => Ok(CoordToSidecar::Error {
                message: format!("lease {lease:?} not found"),
            }),
        }
    }

    /// Release a lease, tearing down its channels and persisting the close.
    async fn release_lease(
        &self,
        principal: &Principal,
        lease: LeaseId,
    ) -> Result<CoordToSidecar> {
        let now = self.now();
        // Close any relay channels for this lease first.
        self.teardown_lease_channels(lease).await;

        let promoted = {
            let mut sched = self.scheduler.lock().await;
            sched.release_lease(lease, now)
        };
        self.db.close_lease(lease, self.now_i64(), "released").await?;
        self.audit(
            "lease.release",
            Some(&principal.0),
            None,
            Some(lease),
            None,
        )
        .await?;

        // If a waiter was promoted onto the freed board, persist its grant. The
        // promoted holder is notified out-of-band when it next polls/re-requests
        // (v1 limitation: no push to a disconnected sidecar).
        if let Some(granted) = promoted {
            self.db
                .record_lease(
                    granted.lease,
                    &granted.board,
                    &granted.agent.0,
                    &granted.holder,
                    self.now_i64(),
                    i64::try_from(granted.expires).unwrap_or(i64::MAX),
                )
                .await?;
            self.audit(
                "lease.promote",
                Some(&granted.holder.0),
                Some(&granted.board.0),
                Some(granted.lease),
                None,
            )
            .await?;
        }

        Ok(CoordToSidecar::Released { lease })
    }

    /// Open a relay channel for a held lease.
    ///
    /// Returns `Some(reply)` to send to the sidecar, or `None` if the reply was
    /// already handled.
    async fn open_channel(
        &self,
        _principal: &Principal,
        lease: LeaseId,
        kind: fleet_proto::ChannelKind,
        sidecar_tx: mpsc::Sender<CoordToSidecar>,
    ) -> Result<Option<CoordToSidecar>> {
        // Find the board + agent for this lease from the scheduler's board set.
        let target = {
            let sched = self.scheduler.lock().await;
            let found = sched.boards().find_map(|b| match &b.state {
                BoardState::Leased { lease: l, .. } if *l == lease => {
                    Some((b.id.clone(), b.agent.clone()))
                }
                _ => None,
            });
            found
        };
        let Some((board, agent_id)) = target else {
            return Ok(Some(CoordToSidecar::Error {
                message: format!("no active lease {lease:?}"),
            }));
        };

        let Some(agent) = self.agents.get(&agent_id).await else {
            return Ok(Some(CoordToSidecar::Error {
                message: format!("agent {agent_id} not connected"),
            }));
        };

        // Mint a fresh capability token scoped to this lease/board.
        let now = self.now();
        let expires = {
            let sched = self.scheduler.lock().await;
            sched
                .board(&board)
                .and_then(|b| match &b.state {
                    BoardState::Leased { expires, .. } => Some(*expires),
                    _ => None,
                })
                .unwrap_or(now)
        };
        let token = fleet_proto::token::CapabilityToken {
            lease,
            board: board.clone(),
            allowed_ops: default_allowed_ops(),
            expires,
        };
        let wire = self.signer.sign_to_wire(&token)?;

        let channel = relay::open_channel(
            &self.channels,
            &agent,
            agent_id,
            sidecar_tx,
            relay::OpenRequest {
                lease,
                board: board.clone(),
                token: wire,
                kind,
            },
        )
        .await?;

        self.audit(
            "channel.open",
            None,
            Some(&board.0),
            Some(lease),
            Some(&format!("{channel:?}")),
        )
        .await?;
        Ok(Some(CoordToSidecar::ChannelOpened { channel }))
    }

    /// Forward a sidecar data frame to the owning agent.
    async fn relay_from_sidecar(&self, frame: fleet_proto::DataFrame) {
        let Some(route) = self.channels.get(frame.channel).await else {
            return;
        };
        let Some(agent) = self.agents.get(&route.agent).await else {
            return;
        };
        if let Err(e) = relay::forward_to_agent(&self.channels, &agent, frame).await {
            debug!(error = %e, "relay to agent failed");
        }
    }

    /// Forward an agent data frame to the owning sidecar.
    ///
    /// # Errors
    ///
    /// Returns a [`CoordinatorError`] if the sidecar's connection has closed.
    pub async fn relay_from_agent(&self, frame: fleet_proto::DataFrame) -> Result<bool> {
        relay::forward_to_sidecar(&self.channels, frame).await
    }

    /// Close all relay channels tied to a lease.
    async fn teardown_lease_channels(&self, lease: LeaseId) {
        for channel in self.channels.channels_for_lease(lease).await {
            let route = self.channels.get(channel).await;
            let agent = match route {
                Some(r) => self.agents.get(&r.agent).await,
                None => None,
            };
            relay::close_channel(&self.channels, agent.as_ref(), channel).await;
        }
    }

    /// Note a disconnecting sidecar principal.
    ///
    /// v1 deliberately does **not** force-release the principal's leases here:
    /// a lease outlives a single connection and expires via the sweep
    /// (architecture §6). Any relay channels the sidecar had open are torn down
    /// when its writer task drops and the agent reports `SessionClosed`.
    pub fn drop_sidecar(&self, principal: &Principal) {
        debug!(%principal, "sidecar disconnected");
    }

    /// Append an audit row at the current time.
    async fn audit(
        &self,
        action: &str,
        principal: Option<&str>,
        board: Option<&str>,
        lease: Option<LeaseId>,
        detail: Option<&str>,
    ) -> Result<()> {
        self.db
            .append_audit(&AuditEntry {
                ts: self.now_i64(),
                principal,
                action,
                board,
                lease,
                detail,
            })
            .await
    }
}

/// A shared, cheaply-cloneable coordinator handle.
pub type SharedCoordinator = Arc<Coordinator>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::Clock;
    use crate::config::SigningKeySource;
    use ed25519_dalek::{Verifier, VerifyingKey};
    use fleet_core::policy::Policy;
    use fleet_proto::board::PowerKind;
    use fleet_proto::ids::AgentId;
    use fleet_proto::lease::{Constraint, Priority};
    use fleet_proto::token::SignedToken;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};

    const TEST_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    struct TestClock(AtomicU64);
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
            signing_key: SigningKeySource::Seed(TEST_SEED),
            policy: Policy::default(),
            pinned_agents: HashMap::new(),
            sweep_interval_secs: 5,
        }
    }

    fn board(id: &str, agent: &str) -> Board {
        Board {
            id: BoardId(id.to_owned()),
            agent: AgentId(agent.to_owned()),
            chip: "nRF52840_xxAA".to_owned(),
            tags: vec!["nrf52".to_owned()],
            exclusive: true,
            power: PowerKind::None,
            state: BoardState::Idle,
        }
    }

    async fn coordinator(clock: Arc<TestClock>) -> Coordinator {
        let mut sched = Scheduler::new(Policy::default());
        sched.upsert_board(board("b1", "agent-a"));
        let db = Db::connect_in_memory().await.unwrap();
        let signer = Ed25519Signer::from_seed(&TEST_SEED);
        Coordinator::new(config(), sched, db, signer, clock)
    }

    fn lease_req(board: &str) -> LeaseRequest {
        LeaseRequest {
            select: Constraint::Board(BoardId(board.to_owned())),
            duration_secs: 600,
            priority: Priority::Interactive,
        }
    }

    /// Full lease lifecycle through the coordinator: request -> grant -> verify
    /// token -> extend -> release, with sqlite + audit side effects.
    #[tokio::test]
    async fn lease_lifecycle_through_coordinator() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock.clone()).await;
        let alice = Principal("alice".to_owned());
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);

        // Request -> Granted.
        coord
            .handle_sidecar_message(&alice, SidecarToCoord::Lease(lease_req("b1")), &tx)
            .await
            .unwrap();
        let grant = match rx.recv().await.unwrap() {
            CoordToSidecar::Lease(g) => g,
            other => panic!("expected Lease, got {other:?}"),
        };
        assert_eq!(grant.board, BoardId("b1".to_owned()));
        assert_eq!(grant.expires, 1000 + 600);

        // The minted token verifies under the agent's public key.
        let pubkey = coord.signer().public_key_bytes();
        let key = VerifyingKey::from_bytes(&pubkey).unwrap();
        let signed = SignedToken::from_wire(&grant.token).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&signed.signature);
        key.verify(&signed.token_bytes, &sig).unwrap();
        let claims = signed.decode_token().unwrap();
        assert_eq!(claims.lease, grant.lease);
        assert_eq!(claims.board, grant.board);

        // Lease persisted.
        assert_eq!(coord.db().open_lease_count().await.unwrap(), 1);

        // Extend.
        coord
            .handle_sidecar_message(
                &alice,
                SidecarToCoord::Extend { lease: grant.lease },
                &tx,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::Extended { lease, expires } => {
                assert_eq!(lease, grant.lease);
                // Interactive cap is 4h; extend = now + cap.
                assert_eq!(expires, 1000 + 4 * 60 * 60);
            }
            other => panic!("expected Extended, got {other:?}"),
        }

        // Release.
        coord
            .handle_sidecar_message(
                &alice,
                SidecarToCoord::Release { lease: grant.lease },
                &tx,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::Released { lease } => assert_eq!(lease, grant.lease),
            other => panic!("expected Released, got {other:?}"),
        }
        assert_eq!(coord.db().open_lease_count().await.unwrap(), 0);

        // Audit log recorded grant/extend/release at minimum.
        assert!(coord.db().audit_count().await.unwrap() >= 3);
    }

    #[tokio::test]
    async fn contended_request_is_queued() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);

        // alice grabs b1.
        coord
            .handle_sidecar_message(
                &Principal("alice".to_owned()),
                SidecarToCoord::Lease(lease_req("b1")),
                &tx,
            )
            .await
            .unwrap();
        assert!(matches!(rx.recv().await.unwrap(), CoordToSidecar::Lease(_)));

        // bob is queued.
        coord
            .handle_sidecar_message(
                &Principal("bob".to_owned()),
                SidecarToCoord::Lease(lease_req("b1")),
                &tx,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::Queued { position } => assert_eq!(position, 0),
            other => panic!("expected Queued, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn extend_unknown_lease_errors() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &Principal("alice".to_owned()),
                SidecarToCoord::Extend { lease: LeaseId(99) },
                &tx,
            )
            .await
            .unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            CoordToSidecar::Error { .. }
        ));
    }
}
