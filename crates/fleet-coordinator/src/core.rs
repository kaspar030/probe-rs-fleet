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

use fleet_core::access::Access;
use fleet_core::scheduler::{LeaseAuthError, LeaseDecision, Scheduler};
use fleet_proto::adopt::AdoptPolicy;
use fleet_proto::agent_api::AgentReport;
use fleet_proto::board::{Board, BoardState};
use fleet_proto::ids::{
    AgentId, BoardName, BoardRef, LeaseId, OrgId, Role, Subject, SubjectKey,
};
use fleet_proto::lease::LeaseRequest;

use crate::auth::Ed25519Signer;
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

    /// Hex-encoded ed25519 public key of the capability-token signer.
    ///
    /// Handed to a node at enrollment so it can verify the capability tokens
    /// the coordinator later mints for its sessions.
    #[must_use]
    pub fn token_pubkey_hex(&self) -> String {
        let bytes = self.signer.public_key_bytes();
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
        }
        out
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

    /// The org a node's inventory and boards belong to, with its probe
    /// adoption policy.
    ///
    /// Resolved from the `node` table, and **only** from it: there is no
    /// fallback to `config.default_org` any more. A node connecting on
    /// `/agent` has already been authenticated against its `node` row, so a
    /// `None` here means the row vanished between authentication and the
    /// report (a revocation racing an inventory push). Defaulting that into
    /// the configured org silently lands a node in someone else's tenant the
    /// moment a second org exists, so the report is dropped instead — exactly
    /// as the `Err` arm does.
    async fn org_and_policy_of_node(&self, node: &AgentId) -> Option<(OrgId, AdoptPolicy)> {
        match self.db.node_org_and_policy(node).await {
            Ok(Some(found)) => Some(found),
            Ok(None) => {
                warn!(%node, "no node row for this connection; dropping report");
                None
            }
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
        let Some((org, adopt)) = self.org_and_policy_of_node(agent_id).await else {
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
                let online = self.reconcile_inventory(&org, agent_id, adopt, &inv).await;
                self.audit(
                    &org,
                    "agent.inventory",
                    None,
                    Some(&agent_id.0),
                    None,
                    None,
                    Some(&format!(
                        "{} boards ({online} online, adopt={adopt})",
                        inv.boards.len()
                    )),
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
            AgentReport::TokenRotated { rotation_id } => {
                // Handled by the connection task, which owns the pending
                // rotation; reaching `core` means the connection did not
                // recognise it, which is worth a trace but nothing more.
                debug!(%agent_id, rotation_id, "stray token-rotation ack");
            }
        }
        Ok(())
    }

    /// Reconcile an agent inventory snapshot into the scheduler's board set.
    ///
    /// Online boards are upserted (and persisted to the board table) as
    /// `Board`s owned by `agent_id` **in `org`**; offline boards are removed
    /// from the scheduler unless they currently hold a live lease. Returns the
    /// number of online boards.
    ///
    /// This is the only place a [`BoardRef`] is minted from node input: the
    /// node supplies a node-local [`BoardName`] and the coordinator attaches the
    /// org of the authenticated connection, so cross-org board injection is not
    /// expressible. That holds for an **adopted** board exactly as it does for
    /// a declared one — auto-adoption changes which probes become boards, never
    /// whose tenant they land in.
    ///
    /// `adopt` is the node's policy from its `node` row, which is the
    /// authoritative copy (the agent's `node.toml` setting only governs what it
    /// reports):
    ///
    /// * [`AdoptPolicy::Declared`] — a board the node flagged `adopted` is
    ///   dropped. The node should not have synthesised it, but the enforcement
    ///   point is here, so a node whose local config drifted (or which is
    ///   simply lying) cannot widen its own policy.
    /// * [`AdoptPolicy::Auto`] — adopted boards are scheduled like declared
    ///   ones. The synthesis itself lives on the agent, which is the only side
    ///   that can see a probe's identity.
    async fn reconcile_inventory(
        &self,
        org: &OrgId,
        agent_id: &AgentId,
        adopt: AdoptPolicy,
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
                // Enforcement, not decoration: a `declared` node that reports
                // an adopted board as *online* has drifted from (or is
                // contradicting) the policy its owner set, and the row here is
                // what decides.
                //
                // Scoped to online deliberately. An adopted board reported
                // **offline** is a tombstone — "this probe is gone, drop it" —
                // and must be honoured whatever the policy says, or a node
                // whose policy was flipped `auto` → `declared` would strand
                // every board it had adopted while it was `auto`. Removing a
                // board is never a tenancy risk; refusing to is the one that
                // leaves a phantom the scheduler will happily lease.
                if status.adopted
                    && adopt != AdoptPolicy::Auto
                    && status.presence == BoardPresence::Online
                {
                    warn!(
                        node = %agent_id,
                        board = %status.board,
                        "ignoring an adopted board from a node whose policy is `declared`"
                    );
                    continue;
                }
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

    /// Resolve a node-local board name to a [`BoardRef`] the caller may reach.
    ///
    /// The request wire stays node-local (so `PROBE_RS_FLEET_BOARD=nrf52840-dk-3`
    /// keeps working); the coordinator is the only thing that turns a name into
    /// a fleet key.
    ///
    /// # Own org wins, then granted orgs
    ///
    /// Once grants exist, two different boards can answer to `nrf52840-dk-3`:
    /// your own, and one somebody shared with you. Resolution is therefore
    /// **tiered** — candidates in the caller's own org first, and only if
    /// there are none, boards reachable by grant. A board acquired by grant can
    /// never shadow your own hardware for `ctl release` / `ctl power-cycle`,
    /// which is the failure a flat "report the ambiguity" rule would produce
    /// for a bare name with no way to disambiguate.
    ///
    /// The escape hatch is a **qualified name**: `<node>/<name>` or
    /// `<org>/<node>/<name>`, which reaches a granted board even when a
    /// same-named local one exists. It is purely resolver-side — [`BoardName`]
    /// stays an opaque wire string.
    ///
    /// Returns [`BoardLookup::NotFound`] for both an absent board and an
    /// unreachable one — deliberately indistinguishable. `Ambiguous` is
    /// reported only for a tie *within* the winning tier, where every candidate
    /// is already reachable by the caller so naming the nodes leaks nothing.
    async fn resolve_board(
        &self,
        access: &Access,
        name: &BoardName,
        now: u64,
    ) -> BoardLookup {
        // Split a qualified name. `a/b` is node/name, `a/b/c` is org/node/name.
        let parts: Vec<&str> = name.0.split('/').collect();
        let (want_org, want_node, want_name) = match parts.as_slice() {
            [name] => (None, None, *name),
            [node, name] => (None, Some(*node), *name),
            [org, node, name] => (Some(*org), Some(*node), *name),
            _ => return BoardLookup::NotFound,
        };

        let sched = self.scheduler.lock().await;
        let candidates: Vec<&fleet_proto::board::Board> = sched
            .boards()
            .filter(|b| b.id.name == want_name)
            .filter(|b| want_node.is_none_or(|n| b.id.node.0 == n))
            .filter(|b| want_org.is_none_or(|o| b.id.org.0 == o))
            .filter(|b| access.may_use(b, now))
            .collect();

        // Tier 1: the caller's own org. Tier 2: everything else they may reach.
        let own: Vec<&fleet_proto::board::Board> =
            candidates.iter().copied().filter(|b| access.owns(b)).collect();
        let tier = if own.is_empty() { &candidates } else { &own };

        match tier.len() {
            0 => BoardLookup::NotFound,
            1 => BoardLookup::Found(tier[0].id.clone()),
            _ => {
                let mut nodes: Vec<AgentId> = tier.iter().map(|b| b.id.node.clone()).collect();
                nodes.sort();
                BoardLookup::Ambiguous(nodes)
            }
        }
    }

    /// Build the operator board-inventory reply (`ctl list`).
    ///
    /// Shows the caller's own org's boards (membership is enough — "membership
    /// alone is enough to add a node and to use the org's boards", §6.5) plus
    /// every board a live grant covers. This is the **grantee-facing view**:
    /// there is deliberately no self-service "what am I granted?" verb, so
    /// `ctl list` is how a grantee discovers what it may use.
    ///
    /// Note a grantee therefore sees the *holder* of a granted board. That is
    /// necessary — "busy" is useless without "busy with whom" — and bounded:
    /// only boards already shared with them.
    async fn list_boards(&self, subject: &Subject) -> CoordToSidecar {
        use fleet_proto::admin::{BoardAvailability, BoardSummary};
        let now = self.now();
        let access = authz::board_access(&self.db, subject, now).await;
        if access.is_empty() {
            return Self::denied();
        }
        let sched = self.scheduler.lock().await;
        let boards = sched
            .boards()
            .filter(|b| access.may_use(b, now))
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

    /// Build the operator lease-holder reply (`ctl who`), over the boards the
    /// caller may reach — their own org's, plus any a live grant covers.
    async fn who(&self, subject: &Subject) -> CoordToSidecar {
        use fleet_proto::admin::LeaseHolderSummary;
        let now = self.now();
        let access = authz::board_access(&self.db, subject, now).await;
        if access.is_empty() {
            return Self::denied();
        }
        let sched = self.scheduler.lock().await;
        let holders = sched
            .boards()
            .filter(|b| access.may_use(b, now))
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
    /// Scoped by [`Access`]: an unreachable board resolves to "no such board",
    /// exactly as an absent one does. A *grantee* additionally needs the
    /// [`AllowedOp::PowerCycle`] op — this is the one op enforced here rather
    /// than by the agent, because the agent's power-cycle command carries no
    /// capability token to check.
    async fn operator_power_cycle(
        &self,
        subject: &Subject,
        board: &BoardName,
    ) -> Result<CoordToSidecar> {
        use fleet_proto::token::AllowedOp;

        let now = self.now();
        let access = authz::board_access(&self.db, subject, now).await;
        if access.is_empty() {
            return Ok(Self::denied());
        }
        let board_ref = match self.resolve_board(&access, board, now).await {
            BoardLookup::Found(b) => b,
            BoardLookup::NotFound => {
                return Ok(CoordToSidecar::Error {
                    message: format!("no such board {board}"),
                })
            }
            BoardLookup::Ambiguous(nodes) => {
                let nodes: Vec<&str> = nodes.iter().map(|n| n.0.as_str()).collect();
                return Ok(CoordToSidecar::Error {
                    message: format!(
                        "ambiguous board name {board}: present on nodes {}",
                        nodes.join(", ")
                    ),
                });
            }
        };
        // Re-check with the op: resolution proved the caller may *see* the
        // board, not that they may cut its power.
        let allowed = {
            let sched = self.scheduler.lock().await;
            sched
                .board(&board_ref)
                .is_some_and(|b| access.allows(b, AllowedOp::PowerCycle, now))
        };
        if !allowed {
            return Ok(Self::denied());
        }
        let org = board_ref.org.clone();
        let agent_id = board_ref.node.clone();
        let Some(agent) = self.agents.get(&agent_id).await else {
            return Ok(CoordToSidecar::Error {
                message: format!("agent {agent_id} for board {board} is not connected"),
            });
        };
        if agent
            .send_command(fleet_proto::CoordinatorCommand::PowerCycle {
                board: board_ref.board_name(),
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
            board: board_ref.board_name(),
        })
    }

    /// Process a lease request: resolve the caller's access, ask the scheduler,
    /// mint an **attenuated** token, and persist.
    ///
    /// Two things are subtly different from the pre-sharing version:
    ///
    /// * the gate is [`authz::board_access`], not `require_role(Member)` — a
    ///   subject with no membership but a live grant is a first-class caller
    ///   (CI workloads have no `member` row at all);
    /// * the minted capability token carries `access.effective_ops(board)`
    ///   rather than the full set, so a grantee's token says only what its
    ///   grant said.
    ///
    /// Bookkeeping follows the **board's** org, not the subject's: with
    /// cross-org leases the two differ, and a lease on org A's hardware belongs
    /// in org A's lease table and audit log.
    async fn request_lease(
        &self,
        subject: &Subject,
        req: LeaseRequest,
    ) -> Result<CoordToSidecar> {
        let now = self.now();
        let access = authz::board_access(&self.db, subject, now).await;
        if access.is_empty() {
            return Ok(Self::denied());
        }
        let decision = {
            let mut sched = self.scheduler.lock().await;
            sched.request_lease(subject.clone(), &access, req, now)
        };
        match decision {
            LeaseDecision::Granted(granted) => {
                // Recompute the ops for the board actually granted. The
                // request's selector may have matched several; only this one's
                // grant decides what the token may do.
                let (ops, via) = {
                    let sched = self.scheduler.lock().await;
                    match sched.board(&granted.board) {
                        Some(board) => (
                            access.effective_ops(board, now),
                            access
                                .matching_grant(board, now)
                                .map(|g| format!("via grant {}", g.id)),
                        ),
                        None => (Vec::new(), None),
                    }
                };
                let grant = self.signer.grant_to_wire(&granted, ops)?;
                let org = granted.board.org.clone();
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
                    via.as_deref(),
                )
                .await?;
                Ok(CoordToSidecar::Lease(grant))
            }
            LeaseDecision::Queued { position } => Ok(CoordToSidecar::Queued { position }),
        }
    }

    /// Extend a lease the subject holds (or, as an admin of the holder's or the
    /// board's org, someone else's).
    ///
    /// Bookkeeping goes to the **board's** org: with cross-org leases the
    /// holder's org is the wrong tenant to write into.
    async fn extend_lease(&self, subject: &Subject, lease: LeaseId) -> Result<CoordToSidecar> {
        let now = self.now();
        let outcome = {
            let mut sched = self.scheduler.lock().await;
            match authz::require_lease_control(&self.db, &sched, subject, lease).await {
                Ok(holder) => {
                    let board_org = sched.lease_target(lease).map(|(b, _)| b.org.clone());
                    sched
                        .extend_lease(lease, &holder, now)
                        .map(|e| (holder, board_org, e))
                }
                Err(_) => Err(LeaseAuthError::Unknown),
            }
        };
        match outcome {
            Ok((holder, board_org, expires)) => {
                let org = board_org.unwrap_or_else(|| subject.org.clone());
                self.db
                    .scoped(org.clone())
                    .update_lease_expiry(lease, i64::try_from(expires).unwrap_or(i64::MAX))
                    .await?;
                self.audit(
                    &org,
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

        match self
            .tear_down_lease(lease, &holder, "released", "lease.release", subject)
            .await?
        {
            true => Ok(CoordToSidecar::Released { lease }),
            false => Ok(CoordToSidecar::Error {
                message: AuthzError::lease_message(),
            }),
        }
    }

    /// The whole tail of releasing a lease: close its relay channels, release
    /// it in the scheduler, persist the close, audit it, and persist whatever
    /// waiter was promoted onto the freed board.
    ///
    /// Factored out so the **revocation cascade** goes through exactly this
    /// path rather than a reimplementation of it: forgetting `close_lease` or
    /// the promotion bookkeeping would leave the database claiming a lease is
    /// still open, or lose a promoted waiter's grant entirely. Two callers, one
    /// tail, no drift.
    ///
    /// Every write lands in the **board's** org, which under cross-org leases
    /// is not the holder's. Returns `false` if the scheduler refused (the lease
    /// vanished under us); the caller must already have authorized.
    async fn tear_down_lease(
        &self,
        lease: LeaseId,
        holder: &SubjectKey,
        close_reason: &str,
        audit_action: &str,
        acting: &Subject,
    ) -> Result<bool> {
        let now = self.now();

        // Close any relay channels for this lease first, so the data plane
        // stops immediately rather than when the sidecar next notices.
        self.teardown_lease_channels(lease).await;

        let (promoted, board_org) = {
            let mut sched = self.scheduler.lock().await;
            let board_org = sched.lease_target(lease).map(|(b, _)| b.org.clone());
            match sched.release_lease(lease, holder, now) {
                Ok(promoted) => (promoted, board_org),
                Err(_) => return Ok(false),
            }
        };
        let org = board_org.unwrap_or_else(|| acting.org.clone());

        self.db
            .scoped(org.clone())
            .close_lease(lease, self.now_i64(), close_reason)
            .await?;
        self.audit(
            &org,
            audit_action,
            Some(&acting.key().to_string()),
            None,
            None,
            Some(lease),
            Self::override_detail(acting, holder).as_deref(),
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

        Ok(true)
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

        // Belt and braces: the board itself must be reachable by whoever holds
        // the lease. Recomputed here, not cached at lease time, so a narrowed
        // or revoked grant bites on the very next channel open rather than at
        // the end of the lease's TTL.
        let holder_subject = {
            let sched = self.scheduler.lock().await;
            sched.lease_holder(lease).cloned()
        };
        let Some(holder_subject) = holder_subject else {
            return Ok(Some(CoordToSidecar::Error {
                message: AuthzError::lease_message(),
            }));
        };
        let now = self.now();
        let holder_access = authz::board_access(&self.db, &holder_subject, now).await;
        let ops = {
            let sched = self.scheduler.lock().await;
            match sched.board(&board) {
                Some(b) => holder_access.effective_ops(b, now),
                None => Vec::new(),
            }
        };
        if ops.is_empty() {
            // The holder's access to this board is gone (grant revoked, expired,
            // or narrowed to nothing). Refuse rather than mint an empty token:
            // reconnection must not survive revocation.
            return Ok(Some(CoordToSidecar::Error {
                message: AuthzError::lease_message(),
            }));
        }

        let Some(agent) = self.agents.get(&agent_id).await else {
            return Ok(Some(CoordToSidecar::Error {
                message: format!("agent {agent_id} not connected"),
            }));
        };

        // Mint a fresh capability token scoped to this lease/board, attenuated
        // to the holder's *current* effective ops. Reached only after the
        // ownership check above.
        let token = fleet_proto::token::CapabilityToken {
            lease,
            board: board.clone(),
            allowed_ops: ops,
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
                token: wire.clone(),
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
        // Return the *exact* bytes the agent got, so the sidecar can hand the
        // genuine probe-rs client a credential `probe-rs serve` will accept.
        // Re-minting on the sidecar side is what used to break after an
        // `extend_lease`.
        Ok(Some(CoordToSidecar::ChannelOpened {
            channel,
            token: wire,
        }))
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

/// The outcome of resolving a node-local board name inside one org.
///
/// `NotFound` covers both "no such board" and "a board in another org": the
/// caller must not be able to tell those apart, or the reply enumerates other
/// tenants. `Ambiguous` is safe to report in detail — every candidate is
/// already in the caller's own org.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BoardLookup {
    /// Exactly one board in the caller's org carries this name.
    Found(BoardRef),
    /// No such board in the caller's org.
    NotFound,
    /// Several of the caller's own nodes carry a board of this name.
    Ambiguous(Vec<AgentId>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::Clock;
    use crate::config::SigningKeySource;
    use crate::state::DEFAULT_ORG_ID;
    use ed25519_dalek::{Verifier, VerifyingKey};
    use fleet_core::policy::Policy;
    use fleet_proto::agent_api::BoardPresence;
    use fleet_proto::board::PowerKind;
    use fleet_proto::ids::{AgentId, SubjectKind};
    use fleet_proto::lease::{Constraint, Priority};
    use fleet_proto::token::SignedToken;
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
            sqlite_path: ":memory:".into(),
            signing_key: SigningKeySource::Seed(TEST_SEED),
            default_org: OrgId(crate::state::DEFAULT_ORG_ID.to_owned()),
            ..CoordinatorConfig::default()
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

    /// The token in `ChannelOpened` must be **exactly** the bytes the agent was
    /// sent in `OpenSession` — and, in particular, must survive an `extend`.
    ///
    /// Before `ChannelOpened` carried the token, the sidecar exported
    /// `LeaseGrant::token` as `PROBE_RS_REMOTE_TOKEN` and the two matched only
    /// by coincidence (same fields, deterministic ed25519). `extend_lease`
    /// rewrites the `BoardState::Leased { expires }` that `open_channel` reads,
    /// so this exact sequence produced a token `probe-rs serve` rejected with an
    /// opaque auth error. This test fails on the pre-fix tree.
    #[tokio::test]
    async fn channel_token_matches_the_agents_and_survives_an_extend() {
        use crate::registry::{AgentHandle, AgentMessage};

        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock.clone()).await;
        let (atx, mut arx) = mpsc::channel::<AgentMessage>(16);
        coord
            .agents()
            .insert(AgentId("agent-a".to_owned()), AgentHandle::new(atx))
            .await;

        let alice = user(DEFAULT_ORG_ID, "alice");
        let grant = grant_lease(&coord, &alice, "b1").await;
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);

        // Extend, which rewrites the lease expiry the channel mint reads.
        clock.0.store(1_200, Ordering::SeqCst);
        coord
            .handle_sidecar_message(
                &alice,
                SidecarToCoord::Extend {
                    lease: grant.lease,
                },
                &tx,
            )
            .await
            .unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            CoordToSidecar::Extended { .. }
        ));

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
        let CoordToSidecar::ChannelOpened { token: to_sidecar, .. } = rx.recv().await.unwrap()
        else {
            panic!("expected ChannelOpened");
        };
        let AgentMessage::Command(fleet_proto::CoordinatorCommand::OpenSession {
            token: to_agent,
            ..
        }) = arx.recv().await.unwrap()
        else {
            panic!("expected OpenSession");
        };

        assert_eq!(
            to_sidecar, to_agent,
            "the sidecar must get the very bytes the agent will check"
        );
        assert_ne!(
            to_sidecar, grant.token,
            "after an extend the lease grant's token is stale — using it is the bug"
        );
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

    /// B1 regression at the coordinator level: a chip constraint from another
    /// org must not be granted one of this org's boards, and **no lease row may
    /// land in either tenant's table**. Asserting on the DB matters because the
    /// scheduler and the persistence layer are scoped independently.
    #[tokio::test]
    async fn cross_org_chip_request_grants_nothing_and_persists_nothing() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        // Only org-A owns hardware; org-B has a member but no boards.
        let coord = coordinator_with(
            clock,
            &[board("org-a", "b1", "node-a")],
            &[("org-a", "alice", Role::Member), ("org-b", "mallory", Role::Admin)],
        )
        .await;

        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        let mallory = user("org-b", "mallory");
        coord
            .handle_sidecar_message(
                &mallory,
                SidecarToCoord::Lease(LeaseRequest {
                    select: Constraint::Chip("nRF52840_xxAA".to_owned()),
                    duration_secs: 600,
                    priority: Priority::Interactive,
                }),
                &tx,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::Queued { .. } => {}
            CoordToSidecar::Lease(g) => {
                panic!("cross-org lease granted on {} — tenancy breach", g.board)
            }
            other => panic!("expected Queued, got {other:?}"),
        }

        // Nothing persisted, in either tenant.
        assert_eq!(
            coord
                .db()
                .scoped(org("org-a"))
                .open_lease_count()
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            coord
                .db()
                .scoped(org("org-b"))
                .open_lease_count()
                .await
                .unwrap(),
            0
        );

        // org-A's board is untouched and still leasable by its own org.
        {
            let sched = coord.scheduler().lock().await;
            assert_eq!(
                sched.board(&board_ref("org-a", "node-a", "b1")).unwrap().state,
                BoardState::Idle
            );
        }
        let grant = grant_lease(&coord, &user("org-a", "alice"), "b1").await;
        assert_eq!(grant.board.org, org("org-a"));
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

    /// An ambiguous board name (two of the caller's *own* nodes carry it) is
    /// reported as ambiguous, not as "no such board" — naming the caller's own
    /// nodes leaks nothing, and the bare not-found reply would badly mislead.
    #[tokio::test]
    async fn ambiguous_board_name_is_reported_as_such() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[
                board("org-a", "dk", "node-1"),
                board("org-a", "dk", "node-2"),
            ],
            &[("org-a", "alice", Role::Member)],
        )
        .await;

        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &user("org-a", "alice"),
                SidecarToCoord::PowerCycle {
                    board: BoardName("dk".to_owned()),
                },
                &tx,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::Error { message } => {
                assert!(
                    message.starts_with("ambiguous board name dk"),
                    "got {message:?}"
                );
                assert!(message.contains("node-1") && message.contains("node-2"));
            }
            other => panic!("expected Error, got {other:?}"),
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
        use fleet_proto::agent_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        // Fresh coordinator with NO pre-seeded boards.
        let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", Role::Admin)]).await;
        let agent_id = AgentId("agent-a".to_owned());
        // The node row is what resolves the report's org: there is no default-org
        // fallback any more (see `org_and_policy_of_node`).
        coord
            .db()
            .scoped(org(DEFAULT_ORG_ID))
            .ensure_node(&agent_id, 1000)
            .await
            .unwrap();

        let inv = ProbeInventory {
            boards: vec![
                status("online-1", "S-ON", BoardPresence::Online, "nRF52840_xxAA", false),
                status("offline-1", "S-OFF", BoardPresence::Offline, "STM32F4", false),
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

    /// A [`BoardStatus`] for the inventory tests.
    fn status(
        name: &str,
        serial: &str,
        presence: BoardPresence,
        chip: &str,
        adopted: bool,
    ) -> fleet_proto::BoardStatus {
        fleet_proto::BoardStatus {
            board: BoardName(name.to_owned()),
            serial: serial.to_owned(),
            presence,
            chip: chip.to_owned(),
            tags: vec![],
            exclusive: true,
            power: PowerKind::None,
            adopted,
        }
    }

    /// The direct regression test for the deleted `default_org` fallback.
    ///
    /// A node with no row used to have its inventory silently filed under
    /// `config.default_org` — harmless with one org, a cross-tenant board
    /// injection the moment there are two. The report must now be dropped.
    #[tokio::test]
    async fn a_report_from_a_node_with_no_row_is_dropped_not_defaulted() {
        use fleet_proto::agent_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", Role::Admin)]).await;
        // Deliberately NOT calling `ensure_node`: this node is unknown.
        let ghost = AgentId("ghost".to_owned());

        let inv = ProbeInventory {
            boards: vec![status(
                "b1",
                "S1",
                BoardPresence::Online,
                "nRF52840_xxAA",
                false,
            )],
            unknown: vec![],
        };
        coord
            .handle_agent_report(&ghost, AgentReport::Inventory(inv))
            .await
            .unwrap();

        assert!(
            coord
                .scheduler()
                .lock()
                .await
                .board(&board_ref(DEFAULT_ORG_ID, "ghost", "b1"))
                .is_none(),
            "an unknown node's board must not land in the configured default org"
        );
        assert!(
            coord.db().org_of_node(&ghost).await.unwrap().is_none(),
            "the report must not have created a node row either"
        );
    }

    /// A node registered `auto` has its adopted boards scheduled like any
    /// other. This is the coordinator half of "plug in a probe and it is
    /// leasable".
    #[tokio::test]
    async fn an_auto_node_adopts_boards_a_declared_node_would_not() {
        use fleet_proto::agent_api::ProbeInventory;
        for (policy, expect_scheduled) in [(AdoptPolicy::Auto, true), (AdoptPolicy::Declared, false)]
        {
            let clock = Arc::new(TestClock(AtomicU64::new(1000)));
            let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", Role::Admin)]).await;
            let agent_id = AgentId("laptop".to_owned());
            coord
                .db()
                .register_node_full(
                    &org(DEFAULT_ORG_ID),
                    "laptop",
                    "hash",
                    &[],
                    Some("op"),
                    policy,
                    1000,
                )
                .await
                .unwrap();
            let node = AgentId(format!("{DEFAULT_ORG_ID}/laptop"));

            let inv = ProbeInventory {
                boards: vec![status(
                    "j-link-abc",
                    "ABC",
                    BoardPresence::Online,
                    "",
                    true,
                )],
                unknown: vec![],
            };
            coord
                .handle_agent_report(&node, AgentReport::Inventory(inv))
                .await
                .unwrap();

            let scheduled = coord
                .scheduler()
                .lock()
                .await
                .board(&board_ref(DEFAULT_ORG_ID, &node.0, "j-link-abc"))
                .is_some();
            assert_eq!(
                scheduled, expect_scheduled,
                "policy {policy} should {}have scheduled the adopted board",
                if expect_scheduled { "" } else { "not " }
            );
            let _ = agent_id;
        }
    }

    /// **The phantom-board regression.** An adopted board whose probe was
    /// unplugged arrives as an `Offline` status, and the coordinator must drop
    /// it from the scheduler.
    ///
    /// Without the agent's tombstone the board simply stopped appearing in the
    /// report, and nothing here prunes a board a report failed to mention: it
    /// stayed `Idle` forever, `ctl list` showed it, and a lease against it was
    /// *granted* and then failed at the agent with `UnknownBoard`. On a laptop,
    /// where probes are unplugged daily, that is the common case.
    #[tokio::test]
    async fn an_unplugged_adopted_board_leaves_the_scheduler() {
        use fleet_proto::agent_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", Role::Admin)]).await;
        coord
            .db()
            .register_node_full(
                &org(DEFAULT_ORG_ID),
                "laptop",
                "hash",
                &[],
                Some("op"),
                AdoptPolicy::Auto,
                1000,
            )
            .await
            .unwrap();
        let node = AgentId(format!("{DEFAULT_ORG_ID}/laptop"));
        let key = board_ref(DEFAULT_ORG_ID, &node.0, "j-link-zzz");

        // Plugged in.
        coord
            .handle_agent_report(
                &node,
                AgentReport::Inventory(ProbeInventory {
                    boards: vec![status("j-link-zzz", "ZZZ", BoardPresence::Online, "", true)],
                    unknown: vec![],
                }),
            )
            .await
            .unwrap();
        assert!(coord.scheduler().lock().await.board(&key).is_some());

        // Unplugged: the agent tombstones it.
        coord
            .handle_agent_report(
                &node,
                AgentReport::Inventory(ProbeInventory {
                    boards: vec![status("j-link-zzz", "ZZZ", BoardPresence::Offline, "", true)],
                    unknown: vec![],
                }),
            )
            .await
            .unwrap();
        assert!(
            coord.scheduler().lock().await.board(&key).is_none(),
            "an unplugged adopted board must not linger as a leasable phantom"
        );
    }

    /// The `declared`-policy guard must not swallow a **tombstone**. A node
    /// whose policy was flipped `auto` → `declared` still has to retire what it
    /// adopted while it was `auto`; refusing the offline report would strand
    /// exactly the phantom the tombstone exists to clear.
    ///
    /// Removing a board is never a tenancy risk, which is why the guard is
    /// scoped to `Online` rather than to `adopted`.
    #[tokio::test]
    async fn a_declared_node_still_honours_a_tombstone_for_a_previously_adopted_board() {
        use fleet_proto::agent_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", Role::Admin)]).await;
        let o = org(DEFAULT_ORG_ID);
        coord
            .db()
            .register_node_full(&o, "laptop", "hash", &[], Some("op"), AdoptPolicy::Auto, 1000)
            .await
            .unwrap();
        let node = AgentId(format!("{DEFAULT_ORG_ID}/laptop"));
        let key = board_ref(DEFAULT_ORG_ID, &node.0, "j-link-zzz");

        coord
            .handle_agent_report(
                &node,
                AgentReport::Inventory(ProbeInventory {
                    boards: vec![status("j-link-zzz", "ZZZ", BoardPresence::Online, "", true)],
                    unknown: vec![],
                }),
            )
            .await
            .unwrap();
        assert!(coord.scheduler().lock().await.board(&key).is_some());

        // The owner re-registers the node as `declared`.
        coord
            .db()
            .register_node_full(
                &o,
                "laptop",
                "hash",
                &[],
                Some("op"),
                AdoptPolicy::Declared,
                1001,
            )
            .await
            .unwrap();

        coord
            .handle_agent_report(
                &node,
                AgentReport::Inventory(ProbeInventory {
                    boards: vec![status("j-link-zzz", "ZZZ", BoardPresence::Offline, "", true)],
                    unknown: vec![],
                }),
            )
            .await
            .unwrap();
        assert!(
            coord.scheduler().lock().await.board(&key).is_none(),
            "a policy flip must not strand what auto-adoption scheduled"
        );
    }

    /// A declared board is unaffected by the policy: `declared` is the
    /// unchanged behaviour, not a lockdown.
    #[tokio::test]
    async fn a_declared_board_is_scheduled_under_either_policy() {
        use fleet_proto::agent_api::ProbeInventory;
        for policy in [AdoptPolicy::Auto, AdoptPolicy::Declared] {
            let clock = Arc::new(TestClock(AtomicU64::new(1000)));
            let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", Role::Admin)]).await;
            coord
                .db()
                .register_node_full(
                    &org(DEFAULT_ORG_ID),
                    "pi",
                    "hash",
                    &[],
                    None,
                    policy,
                    1000,
                )
                .await
                .unwrap();
            let node = AgentId(format!("{DEFAULT_ORG_ID}/pi"));

            let inv = ProbeInventory {
                boards: vec![status("b1", "S1", BoardPresence::Online, "chip", false)],
                unknown: vec![],
            };
            coord
                .handle_agent_report(&node, AgentReport::Inventory(inv))
                .await
                .unwrap();

            assert!(
                coord
                    .scheduler()
                    .lock()
                    .await
                    .board(&board_ref(DEFAULT_ORG_ID, &node.0, "b1"))
                    .is_some(),
                "a declared board must be scheduled under policy {policy}"
            );
        }
    }

    /// `ensure_node` runs on every inventory report, so if it touched
    /// `adopt_policy` on conflict it would silently reset a `share`-created
    /// node to `declared` the first time it connected — turning auto-adoption
    /// off for exactly the machines it exists for.
    #[tokio::test]
    async fn an_inventory_report_does_not_reset_the_adopt_policy() {
        use fleet_proto::agent_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", Role::Admin)]).await;
        coord
            .db()
            .register_node_full(
                &org(DEFAULT_ORG_ID),
                "laptop",
                "hash",
                &[],
                Some("op"),
                AdoptPolicy::Auto,
                1000,
            )
            .await
            .unwrap();
        let node = AgentId(format!("{DEFAULT_ORG_ID}/laptop"));

        for _ in 0..3 {
            coord
                .handle_agent_report(
                    &node,
                    AgentReport::Inventory(ProbeInventory {
                        boards: vec![],
                        unknown: vec![],
                    }),
                )
                .await
                .unwrap();
        }

        assert_eq!(
            coord.db().node_org_and_policy(&node).await.unwrap(),
            Some((org(DEFAULT_ORG_ID), AdoptPolicy::Auto))
        );
    }
}
