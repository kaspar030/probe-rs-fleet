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
//!
//! ## Authorization
//!
//! Every sidecar handler here is **deny by default** (architecture §6.5): it
//! resolves the caller's [`Subject`], checks it against the target object's org
//! (and, for a lease, against the lease's holder) via [`crate::authz`], and only
//! then acts. Errors are flattened so a cross-org object is indistinguishable
//! from a nonexistent one — otherwise the error text enumerates other tenants.
//!
//! The one place a [`BoardRef`] is minted from node input is
//! [`Coordinator::reconcile_inventory`], which attaches the org of the
//! authenticated node connection. Nodes report node-local [`BoardName`]s and
//! therefore cannot inject a board into another org.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use fleet_core::scheduler::{LeaseAuthError, LeaseDecision, Scheduler};
use fleet_proto::agent_api::AgentReport;
use fleet_proto::board::{Board, BoardState};
use fleet_proto::ids::{
    AgentId, BoardName, BoardRef, LeaseId, OrgId, Role, Subject, SubjectKey,
};
use fleet_proto::lease::LeaseRequest;

use crate::auth::{default_allowed_ops, Ed25519Signer};
use crate::authz::{self, AuthzError};
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

    /// The org a node's inventory and boards belong to.
    ///
    /// Resolved from the `node` table, falling back to the configured default
    /// org (single-user deployment, until bearer auth and `share` land). A node
    /// whose org cannot be resolved has its inventory **rejected**, never
    /// defaulted into someone else's tenant.
    async fn org_of_node(&self, node: &AgentId) -> Option<OrgId> {
        match self.db.org_of_node(node).await {
            Ok(Some(org)) => Some(org),
            Ok(None) => Some(self.config.default_org.clone()),
            Err(e) => {
                warn!(%node, error = %e, "failed to resolve node org");
                None
            }
        }
    }

    /// Handle one [`AgentReport`] from a connected agent.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::error::CoordinatorError`] only on a fatal DB error;
    /// routine report content is logged and tolerated.
    pub async fn handle_agent_report(
        &self,
        agent_id: &AgentId,
        report: AgentReport,
    ) -> Result<()> {
        let Some(org) = self.org_of_node(agent_id).await else {
            warn!(%agent_id, "dropping report from a node with no resolvable org");
            return Ok(());
        };
        match report {
            AgentReport::Register {
                agent,
                protocol_version,
            } => {
                debug!(%agent, protocol_version, "agent register");
                self.audit(
                    &org,
                    "agent.register",
                    None,
                    Some(&agent.0),
                    None,
                    None,
                    Some(&agent.0),
                )
                .await?;
            }
            AgentReport::Inventory(inv) => {
                // Reconcile the agent's inventory into the scheduler's board set
                // so the boards become leasable and `open_channel` can resolve
                // board -> owning agent. Each present (online) declared board is
                // upserted as a `Board` owned by this agent *within the node's
                // org*; the agent is authoritative for its board metadata via
                // `boards.toml`, but never for the org. The scheduler preserves
                // any live lease state on re-report (see
                // `Scheduler::upsert_board`).
                let online = self.reconcile_inventory(&org, agent_id, &inv).await;
                self.audit(
                    &org,
                    "agent.inventory",
                    None,
                    Some(&agent_id.0),
                    None,
                    None,
                    Some(&format!("{} boards ({online} online)", inv.boards.len())),
                )
                .await?;
            }
            AgentReport::Heartbeat { uptime_secs } => {
                debug!(%agent_id, uptime_secs, "heartbeat");
            }
            AgentReport::Fault { board, reason } => {
                warn!(%agent_id, %board, %reason, "board fault");
                let board_ref = BoardRef::new(org.clone(), agent_id.clone(), board.0.clone());
                self.fault_board(&board_ref, &reason).await;
                self.audit(
                    &org,
                    "board.fault",
                    None,
                    Some(&agent_id.0),
                    Some(&board.0),
                    None,
                    Some(&reason),
                )
                .await?;
            }
            AgentReport::Log {
                level,
                board,
                message,
            } => {
                debug!(%agent_id, ?level, ?board, %message, "agent log");
                self.audit(
                    &org,
                    "agent.log",
                    None,
                    Some(&agent_id.0),
                    board.as_ref().map(|b| b.0.as_str()),
                    None,
                    Some(&message),
                )
                .await?;
            }
            AgentReport::PowerEvent { board, action } => {
                debug!(%agent_id, %board, ?action, "power event");
                self.audit(
                    &org,
                    "board.power",
                    None,
                    Some(&agent_id.0),
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

    /// Reconcile an agent inventory snapshot into the scheduler's board set.
    ///
    /// Online declared boards are upserted (and persisted to the board table)
    /// as `Board`s owned by `agent_id` **in `org`**; offline boards are removed
    /// from the scheduler unless they currently hold a live lease. Returns the
    /// number of online boards.
    ///
    /// This is the only place a [`BoardRef`] is minted from node input: the
    /// node supplies a node-local [`BoardName`] and the coordinator attaches the
    /// org of the authenticated connection, so cross-org board injection is not
    /// expressible.
    async fn reconcile_inventory(
        &self,
        org: &OrgId,
        agent_id: &AgentId,
        inv: &fleet_proto::agent_api::ProbeInventory,
    ) -> usize {
        use fleet_proto::agent_api::BoardPresence;

        let now = self.now_i64();
        let scoped = self.db.scoped(org.clone());
        // Boards reference their node row, so the node must exist first —
        // otherwise every board insert below fails the foreign key.
        if let Err(e) = scoped.ensure_node(agent_id, now).await {
            warn!(node = %agent_id, error = %e, "failed to record node; skipping inventory");
            return 0;
        }

        let mut online = 0usize;
        let mut boards_to_record: Vec<Board> = Vec::new();
        {
            let mut sched = self.scheduler.lock().await;
            for status in &inv.boards {
                let board_ref =
                    BoardRef::new(org.clone(), agent_id.clone(), status.board.0.clone());
                if status.presence == BoardPresence::Online {
                    online += 1;
                    let board = Board {
                        id: board_ref,
                        agent: agent_id.clone(),
                        chip: status.chip.clone(),
                        tags: status.tags.clone(),
                        exclusive: status.exclusive,
                        power: status.power.clone(),
                        state: BoardState::Idle,
                    };
                    sched.upsert_board(board.clone());
                    boards_to_record.push(board);
                } else {
                    // An offline board is dropped from the scheduler unless it
                    // is currently leased (an in-flight lease is preserved).
                    let leased = matches!(
                        sched.board(&board_ref).map(|b| &b.state),
                        Some(BoardState::Leased { .. })
                    );
                    if !leased {
                        sched.remove_board(&board_ref);
                    }
                }
            }
        }
        // Persist the board rows (best-effort; a DB error is logged, not fatal
        // — the scheduler is the source of truth for leasing).
        for board in &boards_to_record {
            if let Err(e) = scoped.record_board(board, now).await {
                warn!(board = %board.id, error = %e, "failed to record board");
            }
        }
        online
    }

    /// Mark a board as faulted in the scheduler (best-effort).
    async fn fault_board(&self, board: &BoardRef, reason: &str) {
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
    /// Returns a [`crate::error::CoordinatorError`] only on a fatal error (DB /
    /// token signing); request-level failures — including every authorization
    /// refusal — are reported back to the sidecar via [`CoordToSidecar::Error`]
    /// and return `Ok`.
    pub async fn handle_sidecar_message(
        &self,
        subject: &Subject,
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
                let reply = self.request_lease(subject, req).await?;
                let _ = tx.send(reply).await;
            }
            SidecarToCoord::Extend { lease } => {
                let reply = self.extend_lease(subject, lease).await?;
                let _ = tx.send(reply).await;
            }
            SidecarToCoord::Release { lease } => {
                let reply = self.release_lease(subject, lease).await?;
                let _ = tx.send(reply).await;
            }
            SidecarToCoord::OpenChannel { lease, kind } => {
                let reply = self.open_channel(subject, lease, kind, tx.clone()).await?;
                if let Some(reply) = reply {
                    let _ = tx.send(reply).await;
                }
            }
            SidecarToCoord::Data(frame) => {
                self.relay_from_sidecar(frame).await;
            }
            SidecarToCoord::CloseChannel { channel } => {
                // Only the sidecar that owns the channel may close it: the
                // route records the authorising lease, so the same
                // holder-or-admin rule applies as everywhere else.
                let route = self.channels.get(channel).await;
                let Some(route) = route else {
                    return Ok(());
                };
                {
                    let sched = self.scheduler.lock().await;
                    if authz::require_lease_control(&self.db, &sched, subject, route.lease)
                        .await
                        .is_err()
                    {
                        let _ = tx
                            .send(CoordToSidecar::Error {
                                message: AuthzError::lease_message(),
                            })
                            .await;
                        return Ok(());
                    }
                }
                let agent = self.agents.get(&route.agent).await;
                relay::close_channel(&self.channels, agent.as_ref(), channel).await;
            }
            SidecarToCoord::ListBoards => {
                let reply = self.list_boards(subject).await;
                let _ = tx.send(reply).await;
            }
            SidecarToCoord::Who => {
                let reply = self.who(subject).await;
                let _ = tx.send(reply).await;
            }
            SidecarToCoord::Logs { board, follow } => {
                let reply = self.logs(subject, board.as_ref(), follow).await?;
                let _ = tx.send(reply).await;
            }
            SidecarToCoord::PowerCycle { board } => {
                let reply = self.operator_power_cycle(subject, &board).await?;
                let _ = tx.send(reply).await;
            }
        }
        Ok(())
    }

    /// The flat refusal reply. Never says *why*, and never says whether the
    /// object exists in another org.
    fn denied() -> CoordToSidecar {
        CoordToSidecar::Error {
            message: "not authorized".to_owned(),
        }
    }

    /// Resolve a node-local board name to a [`BoardRef`] **within the caller's
    /// org**.
    ///
    /// The request wire stays node-local (so `PROBE_RS_FLEET_BOARD=nrf52840-dk-3`
    /// keeps working); the coordinator is the only thing that turns a name into
    /// a fleet key, and it can only do so inside one org. An absent board and a
    /// board in another org are both `None`, deliberately indistinguishable.
    /// An ambiguous name (the same name on two of the org's nodes) is also
    /// refused rather than resolved arbitrarily.
    async fn resolve_board(&self, subject: &Subject, name: &BoardName) -> Option<BoardRef> {
        let sched = self.scheduler.lock().await;
        let mut matching = sched
            .boards()
            .filter(|b| b.id.org == subject.org && b.id.name == name.0)
            .map(|b| b.id.clone());
        let first = matching.next()?;
        if matching.next().is_some() {
            return None;
        }
        Some(first)
    }

    /// Build the operator board-inventory reply (`ctl list`), scoped to the
    /// caller's org.
    ///
    /// Membership is enough: "membership alone is enough to add a node and to
    /// use the org's boards" (§6.5).
    async fn list_boards(&self, subject: &Subject) -> CoordToSidecar {
        use fleet_proto::admin::{BoardAvailability, BoardSummary};
        let org = subject.org.clone();
        if authz::require_role(&self.db, subject, &org, Role::Member)
            .await
            .is_err()
        {
            return Self::denied();
        }
        let sched = self.scheduler.lock().await;
        let boards = sched
            .boards()
            .filter(|b| b.id.org == org)
            .map(|b| {
                let (availability, holder, lease, expires) = match &b.state {
                    BoardState::Idle => (BoardAvailability::Available, None, None, None),
                    BoardState::Leased { lease, by, expires } => (
                        BoardAvailability::Leased,
                        Some(by.clone()),
                        Some(*lease),
                        Some(*expires),
                    ),
                    BoardState::Faulted { .. } => (BoardAvailability::Faulted, None, None, None),
                    BoardState::Disabled => (BoardAvailability::Disabled, None, None, None),
                };
                BoardSummary {
                    board: b.id.clone(),
                    agent: b.agent.clone(),
                    chip: b.chip.clone(),
                    tags: b.tags.clone(),
                    exclusive: b.exclusive,
                    power: b.power.clone(),
                    availability,
                    holder,
                    lease,
                    expires,
                }
            })
            .collect();
        CoordToSidecar::BoardList(boards)
    }

    /// Build the operator lease-holder reply (`ctl who`), scoped to the
    /// caller's org.
    async fn who(&self, subject: &Subject) -> CoordToSidecar {
        use fleet_proto::admin::LeaseHolderSummary;
        let org = subject.org.clone();
        if authz::require_role(&self.db, subject, &org, Role::Member)
            .await
            .is_err()
        {
            return Self::denied();
        }
        let sched = self.scheduler.lock().await;
        let holders = sched
            .boards()
            .filter(|b| b.id.org == org)
            .filter_map(|b| match &b.state {
                BoardState::Leased { lease, by, expires } => Some(LeaseHolderSummary {
                    lease: *lease,
                    board: b.id.clone(),
                    holder: by.clone(),
                    expires: *expires,
                }),
                _ => None,
            })
            .collect();
        CoordToSidecar::LeaseTable(holders)
    }

    /// Build the operator logs reply (`ctl logs`).
    ///
    /// Two independent fences: the audit log is admin-only (§6.5), *and* the
    /// rows are read through the caller's [`crate::state::OrgDb`], so even a bug
    /// in the role check cannot surface another tenant's log.
    async fn logs(
        &self,
        subject: &Subject,
        board: Option<&BoardName>,
        _follow: bool,
    ) -> Result<CoordToSidecar> {
        let org = subject.org.clone();
        if authz::require_role(&self.db, subject, &org, Role::Admin)
            .await
            .is_err()
        {
            return Ok(Self::denied());
        }
        let board = board.map(|b| b.0.as_str());
        let lines = self.db.scoped(org).recent_audit(board, 200).await?;
        Ok(CoordToSidecar::LogLines(lines))
    }

    /// Operator power-cycle: command the owning agent to power-cycle the board.
    ///
    /// Scoped to the caller's org: a board in another org resolves to "no such
    /// board", exactly as an absent one does.
    async fn operator_power_cycle(
        &self,
        subject: &Subject,
        board: &BoardName,
    ) -> Result<CoordToSidecar> {
        let org = subject.org.clone();
        if authz::require_role(&self.db, subject, &org, Role::Member)
            .await
            .is_err()
        {
            return Ok(Self::denied());
        }
        let Some(board_ref) = self.resolve_board(subject, board).await else {
            return Ok(CoordToSidecar::Error {
                message: format!("no such board {board}"),
            });
        };
        // Belt and braces: the resolved board must live in the caller's org.
        if authz::same_org(subject, &board_ref.org).is_err() {
            return Ok(Self::denied());
        }
        let agent_id = board_ref.node.clone();
        let Some(agent) = self.agents.get(&agent_id).await else {
            return Ok(CoordToSidecar::Error {
                message: format!("agent {agent_id} for board {board} is not connected"),
            });
        };
        if agent
            .send_command(fleet_proto::CoordinatorCommand::PowerCycle {
                board: board.clone(),
            })
            .await
            .is_err()
        {
            return Ok(CoordToSidecar::Error {
                message: format!("agent {agent_id} connection closed"),
            });
        }
        self.audit(
            &org,
            "board.power-cycle",
            Some(&subject.key().to_string()),
            Some(&agent_id.0),
            Some(&board_ref.name),
            None,
            Some("operator request"),
        )
        .await?;
        Ok(CoordToSidecar::PowerCycled {
            board: board.clone(),
        })
    }

    /// Process a lease request: check membership, ask the scheduler, mint +
    /// persist a grant.
    async fn request_lease(
        &self,
        subject: &Subject,
        req: LeaseRequest,
    ) -> Result<CoordToSidecar> {
        let org = subject.org.clone();
        if authz::require_role(&self.db, subject, &org, Role::Member)
            .await
            .is_err()
        {
            return Ok(Self::denied());
        }
        let now = self.now();
        let decision = {
            let mut sched = self.scheduler.lock().await;
            sched.request_lease(subject.clone(), req, now)
        };
        match decision {
            LeaseDecision::Granted(granted) => {
                let grant = self
                    .signer
                    .grant_to_wire(&granted, default_allowed_ops())?;
                self.db
                    .scoped(org.clone())
                    .record_lease(
                        granted.lease,
                        &granted.board,
                        &granted.holder.key(),
                        self.now_i64(),
                        i64::try_from(granted.expires).unwrap_or(i64::MAX),
                    )
                    .await?;
                self.audit(
                    &org,
                    "lease.grant",
                    Some(&subject.key().to_string()),
                    Some(&granted.board.node.0),
                    Some(&granted.board.name),
                    Some(granted.lease),
                    None,
                )
                .await?;
                Ok(CoordToSidecar::Lease(grant))
            }
            LeaseDecision::Queued { position } => Ok(CoordToSidecar::Queued { position }),
        }
    }

    /// Extend a lease the subject holds (or, as an org admin, someone else's).
    async fn extend_lease(&self, subject: &Subject, lease: LeaseId) -> Result<CoordToSidecar> {
        let now = self.now();
        let outcome = {
            let mut sched = self.scheduler.lock().await;
            match authz::require_lease_control(&self.db, &sched, subject, lease).await {
                Ok(holder) => sched.extend_lease(lease, &holder, now).map(|e| (holder, e)),
                Err(_) => Err(LeaseAuthError::Unknown),
            }
        };
        match outcome {
            Ok((holder, expires)) => {
                self.db
                    .scoped(subject.org.clone())
                    .update_lease_expiry(lease, i64::try_from(expires).unwrap_or(i64::MAX))
                    .await?;
                self.audit(
                    &subject.org,
                    "lease.extend",
                    Some(&subject.key().to_string()),
                    None,
                    None,
                    Some(lease),
                    Self::override_detail(subject, &holder).as_deref(),
                )
                .await?;
                Ok(CoordToSidecar::Extended { lease, expires })
            }
            Err(_) => Ok(CoordToSidecar::Error {
                message: AuthzError::lease_message(),
            }),
        }
    }

    /// Release a lease, tearing down its channels and persisting the close.
    async fn release_lease(&self, subject: &Subject, lease: LeaseId) -> Result<CoordToSidecar> {
        let now = self.now();

        // Authorize *before* any teardown: a refused release must have no
        // observable effect at all.
        let holder = {
            let sched = self.scheduler.lock().await;
            match authz::require_lease_control(&self.db, &sched, subject, lease).await {
                Ok(holder) => holder,
                Err(_) => {
                    return Ok(CoordToSidecar::Error {
                        message: AuthzError::lease_message(),
                    })
                }
            }
        };

        // Close any relay channels for this lease first.
        self.teardown_lease_channels(lease).await;

        let promoted = {
            let mut sched = self.scheduler.lock().await;
            match sched.release_lease(lease, &holder, now) {
                Ok(promoted) => promoted,
                Err(_) => {
                    return Ok(CoordToSidecar::Error {
                        message: AuthzError::lease_message(),
                    })
                }
            }
        };
        let scoped = self.db.scoped(subject.org.clone());
        scoped.close_lease(lease, self.now_i64(), "released").await?;
        self.audit(
            &subject.org,
            "lease.release",
            Some(&subject.key().to_string()),
            None,
            None,
            Some(lease),
            Self::override_detail(subject, &holder).as_deref(),
        )
        .await?;

        // If a waiter was promoted onto the freed board, persist its grant. The
        // promoted holder is notified out-of-band when it next polls/re-requests
        // (v1 limitation: no push to a disconnected sidecar).
        if let Some(granted) = promoted {
            let promoted_org = granted.board.org.clone();
            self.db
                .scoped(promoted_org.clone())
                .record_lease(
                    granted.lease,
                    &granted.board,
                    &granted.holder.key(),
                    self.now_i64(),
                    i64::try_from(granted.expires).unwrap_or(i64::MAX),
                )
                .await?;
            self.audit(
                &promoted_org,
                "lease.promote",
                Some(&granted.holder.key().to_string()),
                Some(&granted.board.node.0),
                Some(&granted.board.name),
                Some(granted.lease),
                None,
            )
            .await?;
        }

        Ok(CoordToSidecar::Released { lease })
    }

    /// Audit detail noting an admin override, if the acting subject is not the
    /// holder.
    fn override_detail(subject: &Subject, holder: &SubjectKey) -> Option<String> {
        (subject.key() != *holder).then(|| format!("admin override; holder {holder}"))
    }

    /// Open a relay channel for a held lease.
    ///
    /// Revision 1's version of this handler took its principal argument
    /// **unused** and minted a full-ops capability token for whatever lease id
    /// it was handed — i.e. any authenticated client could get flash/debug
    /// access to any board in the fleet. The fix is the first statement below:
    /// nothing happens, and in particular **no token is minted**, until the
    /// caller is proven to hold the lease (or administer its org).
    ///
    /// Returns `Some(reply)` to send to the sidecar, or `None` if the reply was
    /// already handled.
    async fn open_channel(
        &self,
        subject: &Subject,
        lease: LeaseId,
        kind: fleet_proto::ChannelKind,
        sidecar_tx: mpsc::Sender<CoordToSidecar>,
    ) -> Result<Option<CoordToSidecar>> {
        let (holder, board, agent_id, expires) = {
            let sched = self.scheduler.lock().await;
            let Ok(holder) = authz::require_lease_control(&self.db, &sched, subject, lease).await
            else {
                return Ok(Some(CoordToSidecar::Error {
                    message: AuthzError::lease_message(),
                }));
            };
            let Some((board, agent_id)) = sched.lease_target(lease) else {
                return Ok(Some(CoordToSidecar::Error {
                    message: AuthzError::lease_message(),
                }));
            };
            let (board, agent_id) = (board.clone(), agent_id.clone());
            let expires = sched
                .board(&board)
                .and_then(|b| match &b.state {
                    BoardState::Leased { expires, .. } => Some(*expires),
                    _ => None,
                })
                .unwrap_or_else(|| self.now());
            (holder, board, agent_id, expires)
        };

        // Belt and braces: the board itself must be in the caller's org.
        if authz::same_org(subject, &board.org).is_err() {
            return Ok(Some(CoordToSidecar::Error {
                message: AuthzError::lease_message(),
            }));
        }

        let Some(agent) = self.agents.get(&agent_id).await else {
            return Ok(Some(CoordToSidecar::Error {
                message: format!("agent {agent_id} not connected"),
            }));
        };

        // Mint a fresh capability token scoped to this lease/board. Reached
        // only after the ownership check above.
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
            &board.org,
            "channel.open",
            Some(&subject.key().to_string()),
            Some(&board.node.0),
            Some(&board.name),
            Some(lease),
            Some(&format!(
                "{channel:?}{}",
                Self::override_detail(subject, &holder)
                    .map(|d| format!("; {d}"))
                    .unwrap_or_default()
            )),
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
    /// Returns a [`crate::error::CoordinatorError`] if the sidecar's connection
    /// has closed.
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

    /// Note a disconnecting sidecar subject.
    ///
    /// v1 deliberately does **not** force-release the subject's leases here:
    /// a lease outlives a single connection and expires via the sweep
    /// (architecture §6). Any relay channels the sidecar had open are torn down
    /// when its writer task drops and the agent reports `SessionClosed`.
    pub fn drop_sidecar(&self, subject: &Subject) {
        debug!(%subject, "sidecar disconnected");
    }

    /// Append an audit row at the current time, in `org`.
    ///
    /// Every audit row is written through an [`crate::state::OrgDb`], so it
    /// lands in exactly one tenant's log by construction.
    #[allow(clippy::too_many_arguments)]
    async fn audit(
        &self,
        org: &OrgId,
        action: &str,
        subject: Option<&str>,
        node: Option<&str>,
        board: Option<&str>,
        lease: Option<LeaseId>,
        detail: Option<&str>,
    ) -> Result<()> {
        self.db
            .scoped(org.clone())
            .append_audit(&AuditEntry {
                ts: self.now_i64(),
                subject,
                action,
                node,
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
    use crate::state::DEFAULT_ORG_ID;
    use ed25519_dalek::{Verifier, VerifyingKey};
    use fleet_core::policy::Policy;
    use fleet_proto::board::PowerKind;
    use fleet_proto::ids::{AgentId, SubjectKind};
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
            advertise_addr: None,
            tls_cert: "c".into(),
            tls_key: "k".into(),
            client_ca: "ca".into(),
            client_ca_key: "ca-key".into(),
            sqlite_path: ":memory:".into(),
            signing_key: SigningKeySource::Seed(TEST_SEED),
            policy: Policy::default(),
            pinned_agents: HashMap::new(),
            sweep_interval_secs: 5,
            default_org: OrgId(DEFAULT_ORG_ID.to_owned()),
        }
    }

    fn org(name: &str) -> OrgId {
        OrgId(name.to_owned())
    }

    fn user(org_name: &str, id: &str) -> Subject {
        Subject::new(org(org_name), SubjectKind::User, id)
    }

    fn board_ref(org_name: &str, agent: &str, name: &str) -> BoardRef {
        BoardRef::new(org(org_name), AgentId(agent.to_owned()), name)
    }

    fn board(org_name: &str, id: &str, agent: &str) -> Board {
        Board {
            id: board_ref(org_name, agent, id),
            agent: AgentId(agent.to_owned()),
            chip: "nRF52840_xxAA".to_owned(),
            tags: vec!["nrf52".to_owned()],
            exclusive: true,
            power: PowerKind::None,
            state: BoardState::Idle,
        }
    }

    /// A coordinator with one board in the default org and the given
    /// memberships already provisioned.
    async fn coordinator_with(
        clock: Arc<TestClock>,
        boards: &[Board],
        members: &[(&str, &str, Role)],
    ) -> Coordinator {
        let mut sched = Scheduler::new(Policy::default());
        for b in boards {
            sched.upsert_board(b.clone());
        }
        let db = Db::connect_in_memory().await.unwrap();
        for (org_name, id, role) in members {
            db.ensure_user_member(&org(org_name), id, *role)
                .await
                .unwrap();
            // Boards/leases reference their node row.
            for b in boards {
                if b.id.org.0 == *org_name {
                    db.scoped(org(org_name))
                        .ensure_node(&b.agent, 1000)
                        .await
                        .unwrap();
                }
            }
        }
        let signer = Ed25519Signer::from_seed(&TEST_SEED);
        Coordinator::new(config(), sched, db, signer, clock)
    }

    async fn coordinator(clock: Arc<TestClock>) -> Coordinator {
        coordinator_with(
            clock,
            &[board(DEFAULT_ORG_ID, "b1", "agent-a")],
            &[
                (DEFAULT_ORG_ID, "alice", Role::Member),
                (DEFAULT_ORG_ID, "bob", Role::Member),
                (DEFAULT_ORG_ID, "op", Role::Admin),
            ],
        )
        .await
    }

    fn lease_req(board: &str) -> LeaseRequest {
        LeaseRequest {
            select: Constraint::Board(BoardName(board.to_owned())),
            duration_secs: 600,
            priority: Priority::Interactive,
        }
    }

    /// Ask for a lease as `subject` and return the grant.
    async fn grant_lease(
        coord: &Coordinator,
        subject: &Subject,
        board: &str,
    ) -> fleet_proto::lease::LeaseGrant {
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(subject, SidecarToCoord::Lease(lease_req(board)), &tx)
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::Lease(g) => g,
            other => panic!("expected Lease, got {other:?}"),
        }
    }

    /// Full lease lifecycle through the coordinator: request -> grant -> verify
    /// token -> extend -> release, with sqlite + audit side effects.
    #[tokio::test]
    async fn lease_lifecycle_through_coordinator() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock.clone()).await;
        let alice = user(DEFAULT_ORG_ID, "alice");
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
        assert_eq!(grant.board, board_ref(DEFAULT_ORG_ID, "agent-a", "b1"));
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

        // Lease persisted, in the caller's org.
        let scoped = coord.db().scoped(org(DEFAULT_ORG_ID));
        assert_eq!(scoped.open_lease_count().await.unwrap(), 1);

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
        assert_eq!(scoped.open_lease_count().await.unwrap(), 0);

        // Audit log recorded grant/extend/release at minimum.
        assert!(scoped.audit_count().await.unwrap() >= 3);
    }

    #[tokio::test]
    async fn contended_request_is_queued() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);

        // alice grabs b1.
        coord
            .handle_sidecar_message(
                &user(DEFAULT_ORG_ID, "alice"),
                SidecarToCoord::Lease(lease_req("b1")),
                &tx,
            )
            .await
            .unwrap();
        assert!(matches!(rx.recv().await.unwrap(), CoordToSidecar::Lease(_)));

        // bob is queued.
        coord
            .handle_sidecar_message(
                &user(DEFAULT_ORG_ID, "bob"),
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
                &user(DEFAULT_ORG_ID, "alice"),
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

    /// **The bug this task exists to fix.** Revision 1's `open_channel` ignored
    /// its principal and minted a full-ops capability token for any lease id,
    /// so any authenticated client got flash/debug on any board. Assert not
    /// merely that an error comes back, but that **no token was minted** — i.e.
    /// the agent was never commanded to open a session.
    #[tokio::test]
    async fn other_subject_cannot_open_channel_and_no_token_is_minted() {
        use crate::registry::{AgentHandle, AgentMessage};

        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let (atx, mut arx) = mpsc::channel::<AgentMessage>(16);
        coord
            .agents()
            .insert(AgentId("agent-a".to_owned()), AgentHandle::new(atx))
            .await;

        let alice = user(DEFAULT_ORG_ID, "alice");
        let grant = grant_lease(&coord, &alice, "b1").await;

        // bob — a legitimate member of the same org, but not the holder.
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &user(DEFAULT_ORG_ID, "bob"),
                SidecarToCoord::OpenChannel {
                    lease: grant.lease,
                    kind: fleet_proto::ChannelKind::Data,
                },
                &tx,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::Error { message } => assert_eq!(message, "no such lease"),
            other => panic!("expected Error, got {other:?}"),
        }
        // No OpenSession reached the agent => no capability token exists.
        assert!(
            arx.try_recv().is_err(),
            "a refused open_channel must not mint or deliver a token"
        );
        assert!(coord.channels().is_empty().await);

        // The holder, by contrast, succeeds.
        coord
            .handle_sidecar_message(
                &alice,
                SidecarToCoord::OpenChannel {
                    lease: grant.lease,
                    kind: fleet_proto::ChannelKind::Data,
                },
                &tx,
            )
            .await
            .unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            CoordToSidecar::ChannelOpened { .. }
        ));
        assert!(matches!(
            arx.recv().await.unwrap(),
            AgentMessage::Command(fleet_proto::CoordinatorCommand::OpenSession { .. })
        ));
    }

    /// An org admin may open a channel on a member's lease (§6.5's "or an org
    /// admin"), and the audit line records the override.
    #[tokio::test]
    async fn org_admin_may_open_channel_on_members_lease() {
        use crate::registry::{AgentHandle, AgentMessage};

        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let (atx, mut arx) = mpsc::channel::<AgentMessage>(16);
        coord
            .agents()
            .insert(AgentId("agent-a".to_owned()), AgentHandle::new(atx))
            .await;

        let grant = grant_lease(&coord, &user(DEFAULT_ORG_ID, "alice"), "b1").await;
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &user(DEFAULT_ORG_ID, "op"),
                SidecarToCoord::OpenChannel {
                    lease: grant.lease,
                    kind: fleet_proto::ChannelKind::Data,
                },
                &tx,
            )
            .await
            .unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            CoordToSidecar::ChannelOpened { .. }
        ));
        assert!(matches!(
            arx.recv().await.unwrap(),
            AgentMessage::Command(fleet_proto::CoordinatorCommand::OpenSession { .. })
        ));
    }

    #[tokio::test]
    async fn other_subject_cannot_extend_or_release() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let alice = user(DEFAULT_ORG_ID, "alice");
        let grant = grant_lease(&coord, &alice, "b1").await;

        let bob = user(DEFAULT_ORG_ID, "bob");
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        for msg in [
            SidecarToCoord::Extend { lease: grant.lease },
            SidecarToCoord::Release { lease: grant.lease },
        ] {
            coord.handle_sidecar_message(&bob, msg, &tx).await.unwrap();
            match rx.recv().await.unwrap() {
                CoordToSidecar::Error { message } => assert_eq!(message, "no such lease"),
                other => panic!("expected Error, got {other:?}"),
            }
        }
        // The lease is untouched: still open, still alice's, still expiring at
        // its original time.
        assert_eq!(
            coord
                .db()
                .scoped(org(DEFAULT_ORG_ID))
                .open_lease_count()
                .await
                .unwrap(),
            1
        );
        let sched = coord.scheduler().lock().await;
        assert_eq!(sched.lease_holder(grant.lease), Some(&alice));
        let BoardState::Leased { expires, .. } = &sched
            .board(&board_ref(DEFAULT_ORG_ID, "agent-a", "b1"))
            .unwrap()
            .state
        else {
            panic!("still leased");
        };
        assert_eq!(*expires, 1000 + 600);
    }

    /// Cross-org: a subject in another org sees nothing and can do nothing,
    /// even with the same user id.
    #[tokio::test]
    async fn cross_org_subject_is_isolated() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[
                board("org-a", "b1", "node-a"),
                board("org-b", "b1", "node-b"),
            ],
            &[
                ("org-a", "alice", Role::Admin),
                ("org-b", "alice", Role::Admin),
            ],
        )
        .await;
        let alice_a = user("org-a", "alice");
        let alice_b = user("org-b", "alice");
        let grant = grant_lease(&coord, &alice_a, "b1").await;
        assert_eq!(grant.board.org, org("org-a"));

        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);

        // `ctl list` shows only org B's board to org B's alice.
        coord
            .handle_sidecar_message(&alice_b, SidecarToCoord::ListBoards, &tx)
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::BoardList(boards) => {
                assert_eq!(boards.len(), 1);
                assert_eq!(boards[0].board.org, org("org-b"));
            }
            other => panic!("expected BoardList, got {other:?}"),
        }

        // `ctl who` shows org A's lease to org A only.
        coord
            .handle_sidecar_message(&alice_b, SidecarToCoord::Who, &tx)
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::LeaseTable(rows) => assert!(rows.is_empty()),
            other => panic!("expected LeaseTable, got {other:?}"),
        }
        coord
            .handle_sidecar_message(&alice_a, SidecarToCoord::Who, &tx)
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::LeaseTable(rows) => assert_eq!(rows.len(), 1),
            other => panic!("expected LeaseTable, got {other:?}"),
        }

        // Lease verbs on the other org's lease are indistinguishable from
        // "no such lease".
        for msg in [
            SidecarToCoord::Extend { lease: grant.lease },
            SidecarToCoord::Release { lease: grant.lease },
            SidecarToCoord::OpenChannel {
                lease: grant.lease,
                kind: fleet_proto::ChannelKind::Data,
            },
        ] {
            coord
                .handle_sidecar_message(&alice_b, msg, &tx)
                .await
                .unwrap();
            match rx.recv().await.unwrap() {
                CoordToSidecar::Error { message } => assert_eq!(message, "no such lease"),
                other => panic!("expected Error, got {other:?}"),
            }
        }

        // org A's log is invisible to org B even though both are admins.
        coord
            .handle_sidecar_message(
                &alice_b,
                SidecarToCoord::Logs {
                    board: None,
                    follow: false,
                },
                &tx,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::LogLines(lines) => assert!(lines.is_empty()),
            other => panic!("expected LogLines, got {other:?}"),
        }
    }

    /// `ctl logs` is admin-only.
    #[tokio::test]
    async fn logs_require_admin() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);

        coord
            .handle_sidecar_message(
                &user(DEFAULT_ORG_ID, "alice"),
                SidecarToCoord::Logs {
                    board: None,
                    follow: false,
                },
                &tx,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::Error { message } => assert_eq!(message, "not authorized"),
            other => panic!("expected Error, got {other:?}"),
        }

        coord
            .handle_sidecar_message(
                &user(DEFAULT_ORG_ID, "op"),
                SidecarToCoord::Logs {
                    board: None,
                    follow: false,
                },
                &tx,
            )
            .await
            .unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            CoordToSidecar::LogLines(_)
        ));
    }

    /// A non-member (and, by construction, any non-user subject) gets nothing.
    #[tokio::test]
    async fn non_member_and_workload_subjects_are_denied() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);

        let strangers = [
            user(DEFAULT_ORG_ID, "mallory"),
            Subject::new(org(DEFAULT_ORG_ID), SubjectKind::Workload, "ci"),
            Subject::new(org(DEFAULT_ORG_ID), SubjectKind::Node, "rpi-1"),
        ];
        for s in strangers {
            for msg in [
                SidecarToCoord::ListBoards,
                SidecarToCoord::Who,
                SidecarToCoord::Lease(lease_req("b1")),
                SidecarToCoord::PowerCycle {
                    board: BoardName("b1".to_owned()),
                },
            ] {
                coord.handle_sidecar_message(&s, msg, &tx).await.unwrap();
                match rx.recv().await.unwrap() {
                    CoordToSidecar::Error { message } => assert_eq!(message, "not authorized"),
                    other => panic!("expected Error for {s}, got {other:?}"),
                }
            }
        }
    }

    /// Power-cycling another org's board is refused, and looks exactly like a
    /// board that does not exist.
    #[tokio::test]
    async fn cross_org_power_cycle_is_refused() {
        use crate::registry::{AgentHandle, AgentMessage};

        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[board("org-a", "b1", "node-a")],
            &[("org-a", "alice", Role::Member), ("org-b", "bob", Role::Admin)],
        )
        .await;
        let (atx, mut arx) = mpsc::channel::<AgentMessage>(16);
        coord
            .agents()
            .insert(AgentId("node-a".to_owned()), AgentHandle::new(atx))
            .await;

        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &user("org-b", "bob"),
                SidecarToCoord::PowerCycle {
                    board: BoardName("b1".to_owned()),
                },
                &tx,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::Error { message } => assert_eq!(message, "no such board b1"),
            other => panic!("expected Error, got {other:?}"),
        }
        assert!(
            arx.try_recv().is_err(),
            "no command may reach another org's node"
        );

        // The owning org's member may.
        coord
            .handle_sidecar_message(
                &user("org-a", "alice"),
                SidecarToCoord::PowerCycle {
                    board: BoardName("b1".to_owned()),
                },
                &tx,
            )
            .await
            .unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            CoordToSidecar::PowerCycled { .. }
        ));
        assert!(matches!(
            arx.recv().await.unwrap(),
            AgentMessage::Command(fleet_proto::CoordinatorCommand::PowerCycle { .. })
        ));
    }

    /// Inventory reconciliation: a registered agent's online board enters the
    /// scheduler (becomes leasable + appears in `list`), an offline board is
    /// dropped, and the board row is **actually persisted** — asserting on the
    /// warn-swallowed persistence path is exactly where a foreign-key bug would
    /// otherwise hide.
    #[tokio::test]
    async fn inventory_populates_scheduler_db_and_list() {
        use fleet_proto::agent_api::{BoardPresence, BoardStatus, ProbeInventory};
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        // Fresh coordinator with NO pre-seeded boards.
        let coord = coordinator_with(
            clock,
            &[],
            &[(DEFAULT_ORG_ID, "op", Role::Admin)],
        )
        .await;
        let agent_id = AgentId("agent-a".to_owned());

        let inv = ProbeInventory {
            boards: vec![
                BoardStatus {
                    board: BoardName("online-1".to_owned()),
                    serial: "S-ON".to_owned(),
                    presence: BoardPresence::Online,
                    chip: "nRF52840_xxAA".to_owned(),
                    tags: vec!["nrf52".to_owned()],
                    exclusive: true,
                    power: PowerKind::None,
                },
                BoardStatus {
                    board: BoardName("offline-1".to_owned()),
                    serial: "S-OFF".to_owned(),
                    presence: BoardPresence::Offline,
                    chip: "STM32F4".to_owned(),
                    tags: vec![],
                    exclusive: true,
                    power: PowerKind::None,
                },
            ],
            unknown: vec![],
        };
        coord
            .handle_agent_report(&agent_id, AgentReport::Inventory(inv))
            .await
            .unwrap();

        // The online board is in the scheduler, owned by the agent and keyed
        // into the default org; the offline one is not.
        {
            let sched = coord.scheduler().lock().await;
            let key = board_ref(DEFAULT_ORG_ID, "agent-a", "online-1");
            let board = sched.board(&key).unwrap();
            assert_eq!(board.agent, agent_id);
            assert_eq!(board.chip, "nRF52840_xxAA");
            assert!(sched
                .board(&board_ref(DEFAULT_ORG_ID, "agent-a", "offline-1"))
                .is_none());
        }

        // …and it reached the database, node row and all.
        let scoped = coord.db().scoped(org(DEFAULT_ORG_ID));
        assert!(
            scoped
                .has_board(&board_ref(DEFAULT_ORG_ID, "agent-a", "online-1"))
                .await
                .unwrap(),
            "the board row must be persisted, not silently dropped by a FK failure"
        );
        assert_eq!(
            coord.db().org_of_node(&agent_id).await.unwrap(),
            Some(org(DEFAULT_ORG_ID))
        );

        // `ctl list` (ListBoards) returns the online board as available.
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &user(DEFAULT_ORG_ID, "op"),
                SidecarToCoord::ListBoards,
                &tx,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::BoardList(boards) => {
                assert_eq!(boards.len(), 1);
                assert_eq!(
                    boards[0].board,
                    board_ref(DEFAULT_ORG_ID, "agent-a", "online-1")
                );
                assert_eq!(
                    boards[0].availability,
                    fleet_proto::admin::BoardAvailability::Available
                );
            }
            other => panic!("expected BoardList, got {other:?}"),
        }
    }
}
