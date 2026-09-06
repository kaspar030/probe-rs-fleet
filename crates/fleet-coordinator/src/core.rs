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
    /// The GitHub Actions JWKS cache, built lazily from `config` on first use.
    ///
    /// Lazy, and behind a `OnceLock`, so [`Coordinator::new`]'s signature does
    /// not change: every test harness in the tree constructs one, and a fleet
    /// with no `[github_actions]` table must not pay for a cache it will never
    /// consult.
    jwks: std::sync::OnceLock<Arc<fleet_auth::oidc::JwksCache>>,
}

/// The transport-neutral failure of an operator verb.
///
/// Every operator verb exists twice: as a `*_core` method returning
/// `Result<T, OpError>`, and as a thin adapter that maps that onto the
/// postcard [`CoordToSidecar`] wire enum. A second surface (HTTP/JSON) maps
/// the *same* `OpError` onto status codes. That is the whole point: the wire
/// enum's failure channel is a flat `Error { message: String }`, and a JSON
/// handler that had to recover a status code from it would be string-matching
/// prose — prose that would then be frozen by the HTTP surface's tests and
/// could no longer be improved for `ctl`.
///
/// The rule that makes this hold: **the authorization checks live inside the
/// cores**, never in a handler. Both surfaces then get deny-by-default
/// (architecture §6.5) by construction, and adding a verb to one surface
/// cannot silently ship it without the other's checks. The failure mode this
/// design exists to prevent is a future handler reaching for [`crate::state::OrgDb`]
/// (or the scheduler) directly instead of calling a core: such a handler has
/// no authorization at all, and nothing in the type system would say so. If
/// you are writing a handler and find yourself touching the `Db`, stop and
/// add a core instead.
///
/// The variants are the *decision*, not its wording; each carries today's
/// operator-facing message where there is one, so the wire adapters reproduce
/// today's bytes exactly.
pub(crate) enum OpError {
    /// Refused. Deliberately says nothing about *why*, nor whether the object
    /// exists in another org — wire: [`Coordinator::denied`] (`"not
    /// authorized"`); HTTP: 403 `forbidden`.
    Denied,
    /// The named object does not exist, or is not reachable by this caller —
    /// the two are indistinguishable on purpose. Wire: `Error { message }`;
    /// HTTP: 404 `not_found`.
    NotFound(String),
    /// The request itself is malformed: a bad selector, an empty op set, a
    /// missing expiry. Wire: `Error { message }`; HTTP: 400 `invalid_request`.
    Invalid(String),
    /// The request is well-formed and permitted but cannot be satisfied in the
    /// current state — an ambiguous prefix, a disconnected agent. Wire:
    /// `Error { message }`; HTTP: 409.
    Conflict(String),
    /// A fault in the coordinator itself (database, token signing). Propagated
    /// by the adapters as `Err(..)` exactly as `?` did before; HTTP: 500
    /// `server_error`. Never rendered to the operator verbatim.
    Internal(crate::error::CoordinatorError),
}

impl OpError {
    /// Render this failure the way today's sidecar wire renders it.
    ///
    /// `Ok(reply)` is a request-level failure the operator sees as a
    /// [`CoordToSidecar::Error`]; `Err` is a fatal one, propagated exactly as
    /// the `?` in the pre-split methods did. Keeping the mapping in one place
    /// is what makes "the adapters emit today's bytes" checkable by reading
    /// one function instead of eight.
    fn into_wire(self) -> Result<CoordToSidecar> {
        match self {
            OpError::Denied => Ok(Coordinator::denied()),
            OpError::NotFound(message) | OpError::Invalid(message) | OpError::Conflict(message) => {
                Ok(CoordToSidecar::Error { message })
            }
            OpError::Internal(e) => Err(e),
        }
    }
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
            jwks: std::sync::OnceLock::new(),
        }
    }

    /// The GitHub Actions JWKS cache, or `None` when CI is unconfigured.
    ///
    /// Built on first use from `[github_actions]`. One cache per coordinator,
    /// so the rotation refetch and its rate limit are fleet-wide rather than
    /// per request — which is what makes the amplification bound real.
    #[must_use]
    pub fn jwks_cache(&self) -> Option<&Arc<fleet_auth::oidc::JwksCache>> {
        let gha = self.config.github_actions.as_ref()?;
        Some(self.jwks.get_or_init(|| {
            Arc::new(fleet_auth::oidc::JwksCache::new(
                gha.jwks_url.clone(),
                std::time::Duration::from_secs(gha.jwks_refresh_secs),
                std::time::Duration::from_secs(gha.jwks_min_refetch_secs),
            ))
        }))
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
            SidecarToCoord::GrantCreate {
                subject: grantee,
                selector,
                ops,
                expires,
            } => {
                let reply = self
                    .grant_create(subject, &grantee, &selector, ops, expires)
                    .await?;
                let _ = tx.send(reply).await;
            }
            SidecarToCoord::GrantList => {
                let reply = self.grant_list(subject).await?;
                let _ = tx.send(reply).await;
            }
            SidecarToCoord::GrantRevoke { id } => {
                let reply = self.grant_revoke(subject, &id).await?;
                let _ = tx.send(reply).await;
            }
            SidecarToCoord::Delegate {
                select,
                duration_secs,
                ops,
            } => {
                let reply = self.delegate(subject, select, duration_secs, ops).await?;
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
    /// The escape hatch is a **qualified name**, whose grammar lives on
    /// [`fleet_proto::ids::BoardRef::answers_to`] so this resolver and
    /// `ctl release`'s board lookup cannot disagree: the board name is the last
    /// slash-separated segment, and any prefix is matched against the node's
    /// short name, its full (org-namespaced) id, or `org/node-id` — the last
    /// being the `BoardRef`'s own `Display`, so a key copied out of `ctl list`
    /// works verbatim. Purely resolver-side: [`BoardName`] stays an opaque wire
    /// string.
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
        let sched = self.scheduler.lock().await;
        let candidates: Vec<&fleet_proto::board::Board> = sched
            .boards()
            .filter(|b| b.id.answers_to(&name.0))
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

    /// The operator board inventory (`ctl list`).
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
    ///
    /// # Errors
    ///
    /// [`OpError::Denied`] when the caller can reach no board at all.
    pub(crate) async fn list_boards_core(
        &self,
        subject: &Subject,
    ) -> std::result::Result<Vec<fleet_proto::admin::BoardSummary>, OpError> {
        use fleet_proto::admin::{BoardAvailability, BoardSummary};
        let now = self.now();
        let access = authz::board_access(&self.db, subject, now).await;
        if access.is_empty() {
            return Err(OpError::Denied);
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
        Ok(boards)
    }

    /// Wire adapter for [`Coordinator::list_boards_core`]: renders the board
    /// list, or the flat refusal, as a [`CoordToSidecar`].
    async fn list_boards(&self, subject: &Subject) -> CoordToSidecar {
        match self.list_boards_core(subject).await {
            Ok(boards) => CoordToSidecar::BoardList(boards),
            // Only `Denied` is reachable here — the core does no fallible I/O.
            // The remaining variants still have to go somewhere: this reply
            // has no error channel of its own (the signature predates the
            // core split and `handle_sidecar_message`'s call site must not
            // change), so they render as the flat refusal rather than panic.
            Err(e) => e.into_wire().unwrap_or_else(|_| Self::denied()),
        }
    }

    /// The org's membership, for the browser API.
    ///
    /// **New surface, no wire counterpart**, so there is no adapter: nothing on
    /// the postcard protocol lists members, and inventing a verb for it would
    /// mean shipping a `ctl members` nobody asked for. It is still a core
    /// rather than a handler-level query, because the rule the `OpError` doc
    /// records has no exceptions: a handler that reached for
    /// [`crate::state::OrgDb`] itself would have no authorization at all.
    ///
    /// Membership suffices — a member can already infer the roster from
    /// `grant list` and the audit log — and membership is **read-only** in v1
    /// (`docs/web-ui.md` D4), so there is deliberately no counterpart that
    /// writes.
    ///
    /// # Errors
    ///
    /// [`OpError::Denied`] for a non-member; [`OpError::Internal`] on a
    /// database failure.
    pub(crate) async fn list_members_core(
        &self,
        subject: &Subject,
    ) -> std::result::Result<Vec<crate::state::MemberRow>, OpError> {
        let org = subject.org.clone();
        if authz::require_role(&self.db, subject, &org, Role::Member)
            .await
            .is_err()
        {
            return Err(OpError::Denied);
        }
        self.db
            .scoped(org)
            .list_members()
            .await
            .map_err(OpError::Internal)
    }

    /// The org's machines, with live connection state.
    ///
    /// **New surface, no wire counterpart** — see [`Coordinator::list_members_core`]
    /// for why it is a core anyway. `ctl list` is board-shaped, so a machine
    /// that has plugged in no probes is invisible to it; a fleet UI has to be
    /// able to say "this Pi is enrolled and online but is offering nothing".
    ///
    /// `online` is composed here rather than stored: liveness is the
    /// [`crate::registry::AgentRegistry`]'s in-memory answer to "is the
    /// control-plane `WebSocket` up *right now*", and a database column
    /// tracking it would be wrong from the moment a process died. The cost is
    /// that the flag is per-coordinator-process, which is correct — there is
    /// one process, and a node is connected to it or is not.
    ///
    /// # Errors
    ///
    /// [`OpError::Denied`] for a non-member; [`OpError::Internal`] on a
    /// database failure, including an unrecognised stored `adopt_policy`.
    pub(crate) async fn list_nodes_core(
        &self,
        subject: &Subject,
    ) -> std::result::Result<Vec<NodeStatus>, OpError> {
        let org = subject.org.clone();
        if authz::require_role(&self.db, subject, &org, Role::Member)
            .await
            .is_err()
        {
            return Err(OpError::Denied);
        }
        let rows = self
            .db
            .scoped(org)
            .list_nodes()
            .await
            .map_err(OpError::Internal)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let online = self.agents.get(&row.id).await.is_some();
            out.push(NodeStatus { row, online });
        }
        Ok(out)
    }

    /// The operator lease-holder table (`ctl who`), over the boards the
    /// caller may reach — their own org's, plus any a live grant covers.
    ///
    /// # Errors
    ///
    /// [`OpError::Denied`] when the caller can reach no board at all.
    pub(crate) async fn who_core(
        &self,
        subject: &Subject,
    ) -> std::result::Result<Vec<fleet_proto::admin::LeaseHolderSummary>, OpError> {
        use fleet_proto::admin::LeaseHolderSummary;
        let now = self.now();
        let access = authz::board_access(&self.db, subject, now).await;
        if access.is_empty() {
            return Err(OpError::Denied);
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
        Ok(holders)
    }

    /// Wire adapter for [`Coordinator::who_core`]: renders the lease table, or
    /// the flat refusal, as a [`CoordToSidecar`].
    async fn who(&self, subject: &Subject) -> CoordToSidecar {
        match self.who_core(subject).await {
            Ok(holders) => CoordToSidecar::LeaseTable(holders),
            // As in `list_boards`: only `Denied` is reachable, and this reply
            // has no error channel to carry anything else.
            Err(e) => e.into_wire().unwrap_or_else(|_| Self::denied()),
        }
    }

    /// The operator audit-log view (`ctl logs`).
    ///
    /// Two independent fences: the audit log is admin-only (§6.5), *and* the
    /// rows are read through the caller's [`crate::state::OrgDb`], so even a bug
    /// in the role check cannot surface another tenant's log.
    ///
    /// The follow flag is a transport concern (the sidecar keeps the socket
    /// open), so it is not a parameter here: the core answers one snapshot.
    ///
    /// # Errors
    ///
    /// [`OpError::Denied`] for a non-admin; [`OpError::Internal`] on a database
    /// failure.
    pub(crate) async fn logs_core(
        &self,
        subject: &Subject,
        board: Option<&BoardName>,
    ) -> std::result::Result<Vec<fleet_proto::admin::LogLine>, OpError> {
        let org = subject.org.clone();
        if authz::require_role(&self.db, subject, &org, Role::Admin)
            .await
            .is_err()
        {
            return Err(OpError::Denied);
        }
        let board = board.map(|b| b.0.as_str());
        self.db
            .scoped(org)
            .recent_audit(board, 200)
            .await
            .map_err(OpError::Internal)
    }

    /// Wire adapter for [`Coordinator::logs_core`].
    ///
    /// # Errors
    ///
    /// Propagates a database failure; refusals become a [`CoordToSidecar`].
    async fn logs(
        &self,
        subject: &Subject,
        board: Option<&BoardName>,
        _follow: bool,
    ) -> Result<CoordToSidecar> {
        match self.logs_core(subject, board).await {
            Ok(lines) => Ok(CoordToSidecar::LogLines(lines)),
            Err(e) => e.into_wire(),
        }
    }

    /// Operator power-cycle: command the owning agent to power-cycle the board.
    ///
    /// Scoped by [`Access`]: an unreachable board resolves to "no such board",
    /// exactly as an absent one does. A *grantee* additionally needs the
    /// [`AllowedOp::PowerCycle`] op — this is the one op enforced here rather
    /// than by the agent, because the agent's power-cycle command carries no
    /// capability token to check.
    ///
    /// Returns the board's node-local name, as echoed back to the operator.
    ///
    /// # Errors
    ///
    /// [`OpError::Denied`] when the caller may not reach the board, or may see
    /// it but not cut its power; [`OpError::NotFound`] for an absent or
    /// unreachable board; [`OpError::Conflict`] for an ambiguous name and for
    /// an agent that is not connected; [`OpError::Internal`] on a database
    /// failure.
    pub(crate) async fn operator_power_cycle_core(
        &self,
        subject: &Subject,
        board: &BoardName,
    ) -> std::result::Result<BoardName, OpError> {
        use fleet_proto::token::AllowedOp;

        let now = self.now();
        let access = authz::board_access(&self.db, subject, now).await;
        if access.is_empty() {
            return Err(OpError::Denied);
        }
        let board_ref = match self.resolve_board(&access, board, now).await {
            BoardLookup::Found(b) => b,
            BoardLookup::NotFound => {
                return Err(OpError::NotFound(format!("no such board {board}")))
            }
            BoardLookup::Ambiguous(nodes) => {
                let nodes: Vec<&str> = nodes.iter().map(|n| n.0.as_str()).collect();
                return Err(OpError::Conflict(format!(
                    "ambiguous board name {board}: present on nodes {}",
                    nodes.join(", ")
                )));
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
            return Err(OpError::Denied);
        }
        let org = board_ref.org.clone();
        let agent_id = board_ref.node.clone();
        // Both agent-connection failures are `Conflict`, not `Internal` and not
        // `NotFound`: the request was well-formed and authorized, the fleet is
        // just momentarily unable to serve it. The enum has no "temporarily
        // unavailable" bucket, and `Conflict` is the one whose HTTP mapping
        // (409) tells the caller to retry rather than to re-authorize or to
        // stop asking for that board.
        let Some(agent) = self.agents.get(&agent_id).await else {
            return Err(OpError::Conflict(format!(
                "agent {agent_id} for board {board} is not connected"
            )));
        };
        if agent
            .send_command(fleet_proto::CoordinatorCommand::PowerCycle {
                board: board_ref.board_name(),
            })
            .await
            .is_err()
        {
            return Err(OpError::Conflict(format!(
                "agent {agent_id} connection closed"
            )));
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
        .await
        .map_err(OpError::Internal)?;
        Ok(board_ref.board_name())
    }

    /// Wire adapter for [`Coordinator::operator_power_cycle_core`].
    ///
    /// # Errors
    ///
    /// Propagates a database failure; refusals become a [`CoordToSidecar`].
    async fn operator_power_cycle(
        &self,
        subject: &Subject,
        board: &BoardName,
    ) -> Result<CoordToSidecar> {
        match self.operator_power_cycle_core(subject, board).await {
            Ok(board) => Ok(CoordToSidecar::PowerCycled { board }),
            Err(e) => e.into_wire(),
        }
    }

    /// Maximum lifetime of a grant created over the `/client` path.
    ///
    /// Mirrors the auth-key TTL cap of §6.4 and for the same reason: an
    /// unbounded grant of *somebody else's* hardware is exactly the artefact
    /// that outlives the reason it was created. A perpetual grant remains
    /// expressible from a shell against the database; it is not a hosted
    /// member's choice to make.
    pub const MAX_GRANT_TTL_SECS: u64 = 365 * 24 * 3600;

    /// Create a grant of this org's hardware to another subject.
    ///
    /// **Admin-gated**, deliberately diverging from `POST /auth/keys`, where
    /// membership suffices. The two verbs have different blast radii: an auth
    /// key cannot exceed the caller's own org (it enrolls a node *into* it),
    /// while a grant points outward, handing the org's hardware to somebody who
    /// is not in it at all. In a personal org you are the admin, so the
    /// single-user story is unchanged.
    ///
    /// The grantee is resolved **now**, to an immutable user id, and it is that
    /// which is stored — never the login. §6.4's rename/reuse takeover is
    /// otherwise a hole: `grant bob` must mean the account that is `bob` today,
    /// not whoever holds the name at evaluation time.
    ///
    /// # Errors
    ///
    /// [`OpError::Denied`] for a non-admin; [`OpError::Invalid`] for an
    /// unparseable selector, an empty op set, a missing or out-of-range expiry,
    /// or an unknown grantee; [`OpError::Internal`] on a database failure.
    pub(crate) async fn grant_create_core(
        &self,
        subject: &Subject,
        grantee: &str,
        selector: &str,
        ops: Vec<fleet_proto::token::AllowedOp>,
        expires: Option<u64>,
    ) -> std::result::Result<fleet_proto::GrantSummary, OpError> {
        use fleet_proto::lease::{parse_constraint, BareTerm};

        let org = subject.org.clone();
        if authz::require_role(&self.db, subject, &org, Role::Admin)
            .await
            .is_err()
        {
            return Err(OpError::Denied);
        }
        let now = self.now();

        // Canonicalise the selector: what is stored is what `Display` produces,
        // so a grant's meaning never depends on which CLI wrote it. An empty
        // expression is refused by the parser, which is what stops
        // `Tags([])` — a match-everything — from ever reaching the table.
        let selector = match parse_constraint(selector, BareTerm::Tag) {
            Ok(c) => c.to_string(),
            Err(e) => return Err(OpError::Invalid(format!("invalid selector: {e}"))),
        };

        let ops = fleet_proto::token::normalize_ops(ops);
        if ops.is_empty() {
            return Err(OpError::Invalid(
                "a grant must confer at least one operation".to_owned(),
            ));
        }

        // No perpetual grants over the API, and no absurd ones.
        let Some(expires) = expires else {
            return Err(OpError::Invalid(
                "a grant must expire; pass --until or --ttl".to_owned(),
            ));
        };
        if expires <= now || expires.saturating_sub(now) > Self::MAX_GRANT_TTL_SECS {
            return Err(OpError::Invalid(format!(
                "grant expiry must be in the future and within {} days",
                Self::MAX_GRANT_TTL_SECS / 86_400
            )));
        }

        let Some(key) = self
            .resolve_grantee(grantee)
            .await
            .map_err(OpError::Internal)?
        else {
            return Err(OpError::Invalid(format!(
                "no such user `{grantee}`; ask them to run `probe-rs-fleet login` first"
            )));
        };

        let id = crate::state::new_grant_id();
        self.db
            .scoped(org.clone())
            .insert_grant(
                &id,
                &key,
                &selector,
                &ops,
                Some(i64::try_from(expires).unwrap_or(i64::MAX)),
                Some(subject.id.as_str()),
                self.now_i64(),
            )
            .await
            .map_err(OpError::Internal)?;
        self.audit(
            &org,
            "grant.create",
            Some(&subject.key().to_string()),
            None,
            None,
            None,
            Some(&format!("grant {id} to {key}: {selector} ops=[{}]", {
                let labels: Vec<&str> = ops.iter().map(|o| o.as_str()).collect();
                labels.join(",")
            })),
        )
        .await
        .map_err(OpError::Internal)?;

        Ok(fleet_proto::GrantSummary {
            id,
            org,
            subject: key,
            selector,
            ops,
            expires: Some(expires),
            created_by: Some(subject.id.clone()),
            created_at: now,
        })
    }

    /// Wire adapter for [`Coordinator::grant_create_core`].
    ///
    /// # Errors
    ///
    /// Propagates a database failure; refusals become a [`CoordToSidecar`].
    async fn grant_create(
        &self,
        subject: &Subject,
        grantee: &str,
        selector: &str,
        ops: Vec<fleet_proto::token::AllowedOp>,
        expires: Option<u64>,
    ) -> Result<CoordToSidecar> {
        match self
            .grant_create_core(subject, grantee, selector, ops, expires)
            .await
        {
            Ok(summary) => Ok(CoordToSidecar::GrantCreated(summary)),
            Err(e) => e.into_wire(),
        }
    }

    /// Resolve a grantee spelling to a [`SubjectKey`].
    ///
    /// Four accepted forms, narrowing in precision:
    ///
    /// * `repo:<owner>/<name>` — a **CI repository** (architecture §6.7). It is
    ///   first so it can never be shadowed by the `SubjectKey::parse` branch,
    ///   and it is a distinct spelling rather than a bare `owner/name` because
    ///   granting hardware to a repo should not be something a typo produces;
    /// * a rendered `SubjectKey` (`gh-2/user:gh-2`) — unambiguous, and the way
    ///   to name a node subject;
    /// * a bare `gh-<id>` — a user's immutable id, personal org implied;
    /// * a GitHub login — looked up in the `user` table and immediately
    ///   resolved to the immutable id.
    ///
    /// The repo form is validated and lowercased by the **same** function the
    /// OIDC claim path uses (`fleet_proto::ids::normalise_repo`), so the two
    /// sides of the per-repo trust rule cannot disagree about spelling. Note
    /// that a grant names exactly one repo: `repository_owner` is never a
    /// grantee, so a fork or a new repo under the same owner matches nothing.
    async fn resolve_grantee(&self, spec: &str) -> Result<Option<SubjectKey>> {
        if let Some(repo) = spec.strip_prefix("repo:") {
            return Ok(fleet_proto::ids::normalise_repo(repo)
                .as_deref()
                .map(fleet_proto::ids::workload_subject_key));
        }
        if let Some(key) = SubjectKey::parse(spec) {
            return Ok(Some(key));
        }
        if let Some((user, org)) = self.db.user_by_login(spec).await? {
            return Ok(Some(SubjectKey {
                org,
                kind: fleet_proto::ids::SubjectKind::User,
                id: user,
            }));
        }
        // A bare `gh-<id>`: the user's id is also its personal org's id (§6.4).
        if spec.starts_with("gh-") {
            return Ok(Some(SubjectKey {
                org: OrgId(spec.to_owned()),
                kind: fleet_proto::ids::SubjectKind::User,
                id: spec.to_owned(),
            }));
        }
        Ok(None)
    }

    /// List this org's outbound grants.
    ///
    /// **Membership** suffices, unlike creation: this names only grants the org
    /// itself issued, which every member can already infer from `ctl list` /
    /// `ctl who`. Note there is deliberately no "what am I granted?" verb for
    /// the receiving side; `ctl list` is the grantee-facing view.
    ///
    /// # Errors
    ///
    /// [`OpError::Denied`] for a non-member; [`OpError::Internal`] on a database
    /// failure.
    pub(crate) async fn grant_list_core(
        &self,
        subject: &Subject,
    ) -> std::result::Result<Vec<fleet_proto::GrantSummary>, OpError> {
        let org = subject.org.clone();
        if authz::require_role(&self.db, subject, &org, Role::Member)
            .await
            .is_err()
        {
            return Err(OpError::Denied);
        }
        let rows = self
            .db
            .scoped(org.clone())
            .list_grants()
            .await
            .map_err(OpError::Internal)?;
        let grants = rows
            .into_iter()
            .map(|row| fleet_proto::GrantSummary {
                subject: row.parsed_subject().unwrap_or_else(|| SubjectKey {
                    org: row.org.clone(),
                    kind: fleet_proto::ids::SubjectKind::User,
                    id: row.subject.clone(),
                }),
                ops: row.parsed_ops(),
                id: row.id,
                org: row.org,
                selector: row.selector,
                expires: row.expires.map(|e| u64::try_from(e).unwrap_or(0)),
                created_by: row.created_by,
                created_at: u64::try_from(row.created_at).unwrap_or(0),
            })
            .collect();
        Ok(grants)
    }

    /// Wire adapter for [`Coordinator::grant_list_core`].
    ///
    /// # Errors
    ///
    /// Propagates a database failure; refusals become a [`CoordToSidecar`].
    async fn grant_list(&self, subject: &Subject) -> Result<CoordToSidecar> {
        match self.grant_list_core(subject).await {
            Ok(grants) => Ok(CoordToSidecar::Grants(grants)),
            Err(e) => e.into_wire(),
        }
    }

    /// Revoke a grant by id prefix, and make the revocation *real*.
    ///
    /// Authorization mirrors auth-key revocation (§6.4/§6.5): the grant's
    /// **creator** may revoke it, and an **org admin** may revoke any of the
    /// org's, including rows with no recorded creator which would otherwise be
    /// unrevokable from here.
    ///
    /// # The cascade is the point
    ///
    /// Deleting the row alone would leave the grantee holding whatever it had
    /// already leased, relaying bytes, until the lease's TTL ran out. So after
    /// the delete this recomputes the grantee's access and, for every lease it
    /// holds on a board it may no longer use, goes through the *whole* release
    /// path ([`Coordinator::tear_down_lease`]): channels down, lease closed and
    /// audited, any promoted waiter persisted. Queued requests are dropped too,
    /// since a [`fleet_core::access::Access`] snapshot cannot notice a
    /// revocation.
    ///
    /// One honest limit: a capability token already minted stays
    /// cryptographically valid until it expires. Tearing down the relay is what
    /// makes it useless — there is no path to the board without the
    /// coordinator. This is the same bound delegation has, and it is why lease
    /// TTLs are short.
    ///
    /// Returns the ids actually deleted (a prefix that matched one grant can
    /// still delete only that grant — the list is what the operator is shown).
    ///
    /// # Errors
    ///
    /// [`OpError::Denied`] for a non-member, and for a caller who is neither
    /// the grant's creator nor an org admin (the `grant.revoke.denied` audit row
    /// is written first, so a refused revoke is still on the record);
    /// [`OpError::Invalid`] for a prefix that is too short or not hex;
    /// [`OpError::NotFound`] when nothing matches; [`OpError::Conflict`] when
    /// more than one grant does; [`OpError::Internal`] on a database failure.
    pub(crate) async fn grant_revoke_core(
        &self,
        subject: &Subject,
        id_prefix: &str,
    ) -> std::result::Result<Vec<String>, OpError> {
        let org = subject.org.clone();
        // Membership first: a non-member must not be able to probe which
        // prefixes exist.
        if authz::require_role(&self.db, subject, &org, Role::Member)
            .await
            .is_err()
        {
            return Err(OpError::Denied);
        }

        let prefix = id_prefix.trim().to_ascii_lowercase();
        // Load-bearing, not hygiene: `delete_grants_by_prefix("")` is
        // `LIKE '%'`, i.e. every grant in the org. So a prefix must be long
        // enough to address a grant on purpose, and drawn from the alphabet
        // grant ids actually use.
        //
        // Two alphabets, because there are two kinds of id. A human-created
        // grant is 32 random hex characters. A grant synthesised by redeeming
        // a CI auth key (§6.7) is `ci-<29 hex>` — a reserved namespace no
        // random id can occupy, which is what keeps the two unambiguous. That
        // second shape has to be accepted here: `grant list` prints these ids,
        // and a listing whose ids its own revoke verb rejects is a dead end.
        // (`auth-key revoke` tears the row down too, as a side effect of
        // revoking the key; this is the direct route.)
        let body = prefix.strip_prefix("ci-").unwrap_or(&prefix);
        // Either way, at least 8 characters of *entropy*: the `ci-` marker
        // itself distinguishes nothing, so it does not count toward the floor.
        if body.len() < 8 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(OpError::Invalid(
                "grant id prefix must be at least 8 hex characters \
                 (or `ci-` followed by 8, for a CI key's grant)"
                    .to_owned(),
            ));
        }

        let scoped = self.db.scoped(org.clone());
        let all = scoped.list_grants().await.map_err(OpError::Internal)?;
        let matches: Vec<_> = all.iter().filter(|g| g.id.starts_with(&prefix)).collect();
        let target = match matches.len() {
            0 => return Err(OpError::NotFound(format!("no grant matching {prefix}"))),
            1 => matches[0],
            n => {
                return Err(OpError::Conflict(format!(
                    "{n} grants match {prefix}; use a longer prefix"
                )))
            }
        };

        let owned = target.created_by.as_deref() == Some(subject.id.as_str());
        if !owned && !authz::is_org_admin(&self.db, subject).await {
            self.audit(
                &org,
                "grant.revoke.denied",
                Some(&subject.key().to_string()),
                None,
                None,
                None,
                Some("neither the grant's creator nor an org admin"),
            )
            .await
            .map_err(OpError::Internal)?;
            return Err(OpError::Denied);
        }

        let grantee = target.parsed_subject();
        let deleted = scoped
            .delete_grants_by_prefix(&prefix)
            .await
            .map_err(OpError::Internal)?;
        let ids: Vec<String> = deleted.iter().map(|g| g.id.clone()).collect();
        self.audit(
            &org,
            "grant.revoke",
            Some(&subject.key().to_string()),
            None,
            None,
            None,
            Some(&format!("revoked {}", ids.join(","))),
        )
        .await
        .map_err(OpError::Internal)?;

        if let Some(grantee) = grantee {
            self.cascade_revocation(&grantee, &org)
                .await
                .map_err(OpError::Internal)?;
        }

        Ok(ids)
    }

    /// Wire adapter for [`Coordinator::grant_revoke_core`].
    ///
    /// # Errors
    ///
    /// Propagates a database failure; refusals become a [`CoordToSidecar`].
    async fn grant_revoke(&self, subject: &Subject, id_prefix: &str) -> Result<CoordToSidecar> {
        match self.grant_revoke_core(subject, id_prefix).await {
            Ok(ids) => Ok(CoordToSidecar::GrantRevoked { ids }),
            Err(e) => e.into_wire(),
        }
    }

    /// Revoke a **specific** grant by exact id, cascading as `grant revoke`
    /// does, without any of its authorization checks.
    ///
    /// The auth-key revocation path's hook (architecture §6.7): revoking a CI
    /// key must also tear down the grant its redemption synthesised, or the
    /// runner keeps its board until the lease TTL runs out and the operator is
    /// left believing the key is dead. Authorization already happened at
    /// `POST /auth/keys` — same rule, creator-or-admin — which is why this
    /// takes no `Subject`.
    ///
    /// Returns the ids actually deleted, so the caller can say whether
    /// anything cascaded. A key that was never redeemed has no grant, and that
    /// is an empty vector rather than an error.
    ///
    /// # Errors
    ///
    /// Returns a database or scheduler error from the release path.
    pub async fn revoke_grant_by_id(&self, org: &OrgId, id: &str) -> Result<Vec<String>> {
        let scoped = self.db.scoped(org.clone());
        let all = scoped.list_grants().await?;
        let Some(target) = all.iter().find(|g| g.id == id) else {
            return Ok(Vec::new());
        };
        let grantee = target.parsed_subject();
        // By exact id, via the prefix delete: the id *is* the whole prefix, so
        // this matches one row and reuses the one delete statement rather than
        // adding a second way to remove a grant.
        let deleted = scoped.delete_grants_by_prefix(id).await?;
        let ids: Vec<String> = deleted.iter().map(|g| g.id.clone()).collect();
        if let Some(grantee) = grantee {
            self.cascade_revocation(&grantee, org).await?;
        }
        Ok(ids)
    }

    /// After a grant is deleted, take back whatever it was still holding open.
    ///
    /// Recomputes `grantee`'s access from scratch and releases every lease it
    /// holds on a board in `org` that it may no longer use, through the shared
    /// release tail. It also pushes the fresh access into the grantee's queued
    /// requests, which the scheduler cannot invalidate itself (a waiter's
    /// access is a snapshot taken when the request was made).
    ///
    /// The queued half **refreshes rather than drops**: cancelling all of a
    /// subject's pending requests would silently kill ones for boards in their
    /// own org that this revocation has nothing to do with, and would also be
    /// wrong for a subject still covered by a second, overlapping grant.
    /// Refreshing lets `promote_one` decide per board, exactly.
    async fn cascade_revocation(&self, grantee: &SubjectKey, org: &OrgId) -> Result<()> {
        let now = self.now();
        // Rebuild the grantee's access. A `Subject` is needed for the lookup;
        // `groups` is advisory and excluded from identity, so an empty one is
        // faithful here.
        let as_subject = Subject::new(grantee.org.clone(), grantee.kind, grantee.id.clone());
        let access = authz::board_access(&self.db, &as_subject, now).await;

        let held = {
            let sched = self.scheduler.lock().await;
            sched.leases_held_by(grantee)
        };
        for (lease, board_ref) in held {
            if board_ref.org != *org {
                continue;
            }
            let still_ok = {
                let sched = self.scheduler.lock().await;
                sched
                    .board(&board_ref)
                    .is_some_and(|b| access.may_use(b, now))
            };
            if still_ok {
                continue;
            }
            warn!(
                %board_ref, ?lease, subject = %grantee,
                "revoking a lease the grantee may no longer hold"
            );
            self.tear_down_lease(lease, grantee, "revoked", "lease.revoke", &as_subject)
                .await?;
        }

        let refreshed = {
            let mut sched = self.scheduler.lock().await;
            sched.refresh_waiter_access(grantee, &access)
        };
        if refreshed > 0 {
            debug!(
                subject = %grantee, refreshed,
                "refreshed queued requests' access after revocation"
            );
        }
        Ok(())
    }

    /// `ctl delegate`: lease a board **as the caller** and hand back only the
    /// lease's capability token, for a sandboxed agent.
    ///
    /// Delegation is deliberately *not* a grant and creates **no principal**.
    /// The sandbox gets no fleet identity, no session token, cannot enumerate
    /// the fleet or request another board, and cannot outlive the lease.
    /// Revocation is releasing the lease. Mechanically this is exactly
    /// [`Coordinator::request_lease`] with the token attenuated further, to the
    /// intersection of what the caller may do and what they asked to hand over
    /// — you can never delegate more than you hold.
    ///
    /// # A CI workload may not delegate
    ///
    /// Every other `/client` verb is gated by `board_access` or `require_role`,
    /// and a workload passes exactly the ones it should: it may lease, extend,
    /// release, open channels and list; `Logs` and the grant verbs need a role
    /// it can never hold. `Delegate` is the one verb gated by `board_access`
    /// *alone*, so a workload would otherwise be able to mint a capability
    /// token for a lab board and hand it to something else. That is refused
    /// here rather than allowed by omission: nothing in the CI story needs it,
    /// v1 has no way for an operator to see that a CI job re-delegated their
    /// hardware, and allowing it later is a strictly smaller change than
    /// withdrawing it. The route allowlist is only a fence if the verbs behind
    /// the route have been walked — architecture §6.7 records the walk.
    async fn delegate(
        &self,
        subject: &Subject,
        select: fleet_proto::lease::Constraint,
        duration_secs: u64,
        ops: Vec<fleet_proto::token::AllowedOp>,
    ) -> Result<CoordToSidecar> {
        if subject.kind == fleet_proto::ids::SubjectKind::Workload {
            debug!(%subject, "refusing delegation by a CI workload");
            return Ok(CoordToSidecar::Error {
                message: "a CI workload may not delegate its lease".to_owned(),
            });
        }
        let ops = fleet_proto::token::normalize_ops(ops);
        if ops.is_empty() {
            return Ok(CoordToSidecar::Error {
                message: "a delegation must confer at least one operation".to_owned(),
            });
        }

        let now = self.now();
        let access = authz::board_access(&self.db, subject, now).await;
        if access.is_empty() {
            return Ok(Self::denied());
        }

        let req = LeaseRequest {
            select,
            duration_secs,
            priority: fleet_proto::lease::Priority::Interactive,
        };
        let decision = {
            let mut sched = self.scheduler.lock().await;
            sched.request_lease(subject.clone(), &access, req, now)
        };
        let granted = match decision {
            LeaseDecision::Granted(g) => g,
            // The caller decides what to do with a queue slip; `ctl delegate`
            // fails fast rather than blocking a sandbox handoff on it.
            LeaseDecision::Queued { position } => {
                return Ok(CoordToSidecar::Queued { position })
            }
        };

        // Never hand out more than the delegator holds.
        let effective: Vec<fleet_proto::token::AllowedOp> = {
            let sched = self.scheduler.lock().await;
            match sched.board(&granted.board) {
                Some(b) => {
                    let mine = access.effective_ops(b, now);
                    ops.iter().copied().filter(|o| mine.contains(o)).collect()
                }
                None => Vec::new(),
            }
        };
        if effective.is_empty() {
            // Undo the lease rather than hand back a token that does nothing.
            //
            // Through the **shared release tail**, not a bare
            // `Scheduler::release_lease`: there are awaits between the grant
            // above and this check, so a waiter can have queued in the window
            // and be promoted by the release. Dropping that promotion on the
            // floor would leave it live in memory with no `record_lease` row
            // and no `lease.promote` audit — precisely the drift factoring the
            // tail out exists to prevent.
            self.tear_down_lease(
                granted.lease,
                &subject.key(),
                "delegation refused",
                "lease.release",
                subject,
            )
            .await?;
            return Ok(CoordToSidecar::Error {
                message: "you do not hold any of the requested operations on that board".to_owned(),
            });
        }

        let grant = self.signer.grant_to_wire(&granted, effective.clone())?;
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
        let labels: Vec<&str> = effective.iter().map(|o| o.as_str()).collect();
        self.audit(
            &org,
            "lease.delegate",
            Some(&subject.key().to_string()),
            Some(&granted.board.node.0),
            Some(&granted.board.name),
            Some(granted.lease),
            Some(&format!("delegated ops=[{}]", labels.join(","))),
        )
        .await?;
        Ok(CoordToSidecar::Lease(grant))
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
        mut req: LeaseRequest,
    ) -> Result<CoordToSidecar> {
        let now = self.now();
        let access = authz::board_access(&self.db, subject, now).await;
        if access.is_empty() {
            return Ok(Self::denied());
        }
        // A CI workload is clamped to `Priority::Ci`, whatever it asked for.
        //
        // §6.6's fairness ordering is "interactive dev > nightly CI > soak", and
        // priority is a plain wire field: without this, a CI job could outbid a
        // human at a desk simply by setting it. This is not an edge case — the
        // sidecar sends `Priority::Interactive` unconditionally
        // (`fleet-sidecar/src/lib.rs`), so the clamp fires on *every* CI lease.
        //
        // `Policy::max_duration_ci` then applies to it, and extension inherits
        // the clamp for free: `Scheduler::extend_lease` re-derives the duration
        // from the **recorded** priority, so there is deliberately no second
        // guard in `extend_lease` — please do not add one.
        if subject.kind == fleet_proto::ids::SubjectKind::Workload
            && req.priority != fleet_proto::lease::Priority::Ci
        {
            debug!(
                %subject, requested = ?req.priority,
                "clamping a workload's lease request to CI priority"
            );
            req.priority = fleet_proto::lease::Priority::Ci;
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
    ///
    /// Returns the released lease id.
    ///
    /// # Errors
    ///
    /// [`OpError::NotFound`] carrying [`AuthzError::lease_message`] — *not*
    /// [`OpError::Denied`] — both when the caller may not control the lease and
    /// when the teardown finds nothing to close. This deliberately does not
    /// distinguish "someone else's lease" from "no such lease": telling them
    /// apart would let anyone probe which lease ids are live, and across orgs it
    /// would enumerate other tenants' leases. [`OpError::Internal`] on a
    /// database failure during teardown.
    pub(crate) async fn release_lease_core(
        &self,
        subject: &Subject,
        lease: LeaseId,
    ) -> std::result::Result<LeaseId, OpError> {
        // Authorize *before* any teardown: a refused release must have no
        // observable effect at all.
        let holder = {
            let sched = self.scheduler.lock().await;
            match authz::require_lease_control(&self.db, &sched, subject, lease).await {
                Ok(holder) => holder,
                Err(_) => return Err(OpError::NotFound(AuthzError::lease_message())),
            }
        };

        if self
            .tear_down_lease(lease, &holder, "released", "lease.release", subject)
            .await
            .map_err(OpError::Internal)?
        {
            Ok(lease)
        } else {
            // The lease vanished between the authorization check and the
            // teardown. Same message as the refusal above, for the same reason.
            Err(OpError::NotFound(AuthzError::lease_message()))
        }
    }

    /// Wire adapter for [`Coordinator::release_lease_core`].
    ///
    /// # Errors
    ///
    /// Propagates a database failure; refusals become a [`CoordToSidecar`].
    async fn release_lease(&self, subject: &Subject, lease: LeaseId) -> Result<CoordToSidecar> {
        match self.release_lease_core(subject, lease).await {
            Ok(lease) => Ok(CoordToSidecar::Released { lease }),
            Err(e) => e.into_wire(),
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

    /// Open a relay channel on behalf of a **delegated** connection.
    ///
    /// The caller has no [`Subject`] — that is the point of §6.5's delegation
    /// — so authorization comes entirely from the capability token, which the
    /// route already verified:
    ///
    /// 1. the lease it names must still be live and still target the board it
    ///    names (a token outlives neither);
    /// 2. the ops minted are `token.allowed_ops` ∩ the *holder's* current
    ///    effective ops, recomputed now — so revoking the delegator's grant
    ///    also narrows what the sandbox it handed a token to can do.
    ///
    /// The audit line lands in the **board's** org, which is known from the
    /// token, so there is no nullable-org audit problem on this path.
    pub(crate) async fn open_delegated_channel(
        &self,
        token: &fleet_proto::token::CapabilityToken,
        kind: fleet_proto::ChannelKind,
        sidecar_tx: mpsc::Sender<CoordToSidecar>,
    ) -> Result<CoordToSidecar> {
        let refused = || CoordToSidecar::Error {
            message: AuthzError::lease_message(),
        };

        let now = self.now();
        let (holder, board, agent_id, expires) = {
            let sched = self.scheduler.lock().await;
            let Some(holder) = sched.lease_holder(token.lease).cloned() else {
                return Ok(refused());
            };
            let Some((board, agent_id)) = sched.lease_target(token.lease) else {
                return Ok(refused());
            };
            let (board, agent_id) = (board.clone(), agent_id.clone());
            let expires = sched
                .board(&board)
                .and_then(|b| match &b.state {
                    BoardState::Leased { expires, .. } => Some(*expires),
                    _ => None,
                })
                .unwrap_or(now);
            (holder, board, agent_id, expires)
        };

        // The lease must still be on the board the token names. Boards can be
        // removed and lease ids reused across restarts; a token must not
        // silently follow.
        if board != token.board {
            return Ok(refused());
        }

        // Attenuate to the intersection: never more than the token says, and
        // never more than the delegator currently holds.
        let holder_access = authz::board_access(&self.db, &holder, now).await;
        let ops: Vec<fleet_proto::token::AllowedOp> = {
            let sched = self.scheduler.lock().await;
            match sched.board(&board) {
                Some(b) => {
                    let mine = holder_access.effective_ops(b, now);
                    token
                        .allowed_ops
                        .iter()
                        .copied()
                        .filter(|o| mine.contains(o))
                        .collect()
                }
                None => Vec::new(),
            }
        };
        if ops.is_empty() {
            return Ok(refused());
        }

        let Some(agent) = self.agents.get(&agent_id).await else {
            return Ok(CoordToSidecar::Error {
                message: format!("agent {agent_id} not connected"),
            });
        };

        let fresh = fleet_proto::token::CapabilityToken {
            lease: token.lease,
            board: board.clone(),
            allowed_ops: ops,
            expires,
        };
        let wire = self.signer.sign_to_wire(&fresh)?;

        let channel = relay::open_channel(
            &self.channels,
            &agent,
            agent_id,
            sidecar_tx,
            relay::OpenRequest {
                lease: token.lease,
                board: board.clone(),
                token: wire.clone(),
                kind,
            },
        )
        .await?;

        self.audit(
            &board.org,
            "delegate.channel.open",
            // No subject: a delegated connection is not a principal. The lease
            // and board identify it, and the lease names its holder.
            None,
            Some(&board.node.0),
            Some(&board.name),
            Some(token.lease),
            Some(&format!("{channel:?}; delegated by {}", holder.key())),
        )
        .await?;

        Ok(CoordToSidecar::ChannelOpened {
            channel,
            token: wire,
        })
    }

    /// Relay a data frame from a delegated connection, refusing any channel not
    /// belonging to the token's lease.
    pub(crate) async fn relay_delegated(&self, lease: LeaseId, frame: fleet_proto::DataFrame) {
        match self.channels.get(frame.channel).await {
            Some(route) if route.lease == lease => {}
            _ => return,
        }
        self.relay_from_sidecar(frame).await;
    }

    /// Close a channel from a delegated connection, refusing any channel not
    /// belonging to the token's lease.
    pub(crate) async fn close_delegated_channel(&self, lease: LeaseId, channel: fleet_proto::ChannelId) {
        let Some(route) = self.channels.get(channel).await else {
            return;
        };
        if route.lease != lease {
            return;
        }
        let agent = self.agents.get(&route.agent).await;
        relay::close_channel(&self.channels, agent.as_ref(), channel).await;
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

/// One row of [`Coordinator::list_nodes_core`]: a node row plus its live
/// connection state.
///
/// The two halves come from different places on purpose — the row from the
/// database, `online` from the in-memory registry — and are joined here rather
/// than in the handler, so both are answered under one authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NodeStatus {
    /// The persisted node row.
    pub row: crate::state::NodeRow,
    /// Whether the node holds its control-plane `WebSocket` right now.
    pub online: bool,
}

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

    /// A board's fleet key, with a **production-shaped** node id.
    ///
    /// `state.rs::node_id_for` namespaces node ids by org, so a real `AgentId`
    /// is `"{org}/{name}"` and a real `BoardRef` therefore has four
    /// slash-separated segments. This helper used to build bare ids
    /// (`"node-a"`), which is exactly why the qualified-name resolution tests
    /// below passed while the parse they exercised could not address a single
    /// production board. A fixture that cannot produce production-shaped data
    /// cannot fail on production-shaped bugs — so it produces it.
    fn board_ref(org_name: &str, agent: &str, name: &str) -> BoardRef {
        BoardRef::new(org(org_name), node_id(org_name, agent), name)
    }

    /// The org-namespaced node id `state.rs::node_id_for` would mint.
    fn node_id(org_name: &str, agent: &str) -> AgentId {
        AgentId(format!("{org_name}/{agent}"))
    }

    fn board(org_name: &str, id: &str, agent: &str) -> Board {
        Board {
            id: board_ref(org_name, agent, id),
            agent: node_id(org_name, agent),
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
            .insert(node_id(DEFAULT_ORG_ID, "agent-a"), AgentHandle::new(atx))
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
            .insert(node_id(DEFAULT_ORG_ID, "agent-a"), AgentHandle::new(atx))
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
            .insert(node_id(DEFAULT_ORG_ID, "agent-a"), AgentHandle::new(atx))
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

    /// `--repo owner/name` resolves to the reserved-namespace workload subject
    /// key, lowercased, and the branch is **first** so nothing can shadow it.
    ///
    /// This is the grant-creation half of the per-repo trust rule; the claim
    /// half is `oidc::verify`. Both go through `normalise_repo`, which is why
    /// they cannot disagree about spelling.
    #[tokio::test]
    async fn resolve_grantee_maps_repo_to_the_workload_namespace() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;

        let key = coord
            .resolve_grantee("repo:Ariel-OS/Ariel-OS")
            .await
            .unwrap()
            .expect("a repo spec must resolve");
        assert_eq!(key.to_string(), "gha/workload:ariel-os/ariel-os");
        assert_eq!(key.kind, SubjectKind::Workload);

        // Garbage after `repo:` resolves to nothing rather than to some
        // fallback subject: a grant to a subject nobody can authenticate as is
        // worse than a clear refusal.
        for bad in ["repo:", "repo:owner", "repo:a/b/c", "repo:own er/name"] {
            assert!(
                coord.resolve_grantee(bad).await.unwrap().is_none(),
                "{bad} must not resolve"
            );
        }

        // The other spellings still work, and a rendered workload key is not
        // mistaken for one of them.
        let key = coord
            .resolve_grantee("gha/workload:ariel-os/ariel-os")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(key.kind, SubjectKind::Workload);
        let key = coord.resolve_grantee("gh-7").await.unwrap().unwrap();
        assert_eq!(key.kind, SubjectKind::User);
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
            .insert(node_id("org-a", "node-a"), AgentHandle::new(atx))
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
        let agent_id = node_id(DEFAULT_ORG_ID, "agent-a");
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
                .board(&BoardRef::new(org(DEFAULT_ORG_ID), node.clone(), "j-link-abc"))
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
        let key = BoardRef::new(org(DEFAULT_ORG_ID), node.clone(), "j-link-zzz");

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
        let key = BoardRef::new(org(DEFAULT_ORG_ID), node.clone(), "j-link-zzz");

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
                    .board(&BoardRef::new(org(DEFAULT_ORG_ID), node.clone(), "b1"))
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

    // ---------------------------------------------------------------------
    // Board resolution under sharing (architecture §6.5)
    // ---------------------------------------------------------------------

    /// Build an access that owns `own_org` and holds one grant over
    /// `granted_org`'s `tag=nrf52` boards.
    fn shared_access(own_org: &str, granted_org: &str) -> Access {
        Access {
            own_org: Some(org(own_org)),
            grants: vec![fleet_core::access::GrantScope {
                id: "g1".to_owned(),
                org: org(granted_org),
                selector: Constraint::Tags(vec!["nrf52".to_owned()]),
                ops: vec![fleet_proto::token::AllowedOp::Attach],
                expires: None,
            }],
        }
    }

    /// Own-org wins on a name collision. Without the tiering, a board somebody
    /// shared with you could shadow your own hardware for `ctl release` — with
    /// no way to say which one you meant.
    #[tokio::test]
    async fn a_shared_board_never_shadows_your_own() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[board("org-b", "dk", "node-b"), board("org-a", "dk", "node-a")],
            &[("org-a", "alice", Role::Member), ("org-b", "bob", Role::Member)],
        )
        .await;

        let access = shared_access("org-b", "org-a");
        let found = coord
            .resolve_board(&access, &BoardName("dk".to_owned()), 1000)
            .await;
        assert_eq!(
            found,
            BoardLookup::Found(board_ref("org-b", "node-b", "dk")),
            "the caller's own board wins the bare name"
        );
    }

    /// ...and the qualified forms are the escape hatch that reaches the other
    /// one.
    #[tokio::test]
    async fn a_qualified_name_reaches_a_shared_board() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[board("org-b", "dk", "node-b"), board("org-a", "dk", "node-a")],
            &[("org-a", "alice", Role::Member), ("org-b", "bob", Role::Member)],
        )
        .await;
        let access = shared_access("org-b", "org-a");

        // Every qualified spelling, against a production-shaped node id
        // (`org-a/node-a`) — including the BoardRef's own Display, which is
        // what a user copies out of `ctl list`.
        for spelling in [
            "node-a/dk",
            "org-a/node-a/dk",
            "org-a/org-a/node-a/dk",
        ] {
            assert_eq!(
                coord
                    .resolve_board(&access, &BoardName(spelling.to_owned()), 1000)
                    .await,
                BoardLookup::Found(board_ref("org-a", "node-a", "dk")),
                "{spelling} should reach the shared board"
            );
        }
        // A qualified name for a board the caller may not reach is still just
        // "not found" — no enumeration oracle.
        assert_eq!(
            coord
                .resolve_board(&access, &BoardName("org-c/node-c/dk".to_owned()), 1000)
                .await,
            BoardLookup::NotFound
        );
    }

    /// Ambiguity is still reported, but only within the winning tier: two of
    /// your *own* nodes carrying one name is a real ambiguity you can fix.
    #[tokio::test]
    async fn ambiguity_within_the_winning_tier_is_still_reported() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[
                board("org-b", "dk", "node-1"),
                board("org-b", "dk", "node-2"),
                board("org-a", "dk", "node-a"),
            ],
            &[("org-a", "alice", Role::Member), ("org-b", "bob", Role::Member)],
        )
        .await;
        let access = shared_access("org-b", "org-a");
        match coord
            .resolve_board(&access, &BoardName("dk".to_owned()), 1000)
            .await
        {
            BoardLookup::Ambiguous(nodes) => {
                assert_eq!(
                    nodes,
                    vec![node_id("org-b", "node-1"), node_id("org-b", "node-2")],
                    "only the caller's own nodes are named"
                );
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    /// A board nothing in the access admits is invisible, exactly as an absent
    /// one is.
    #[tokio::test]
    async fn an_unreachable_board_resolves_to_not_found() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[board("org-a", "dk", "node-a")],
            &[("org-b", "bob", Role::Member)],
        )
        .await;
        assert_eq!(
            coord
                .resolve_board(&Access::own_org(org("org-b")), &BoardName("dk".to_owned()), 1000)
                .await,
            BoardLookup::NotFound
        );
    }

    // ---------------------------------------------------------------------
    // Revocation cascade
    // ---------------------------------------------------------------------

    /// Revoking a grant refreshes the grantee's *queued* requests too. A
    /// `Waiter` carries an `Access` snapshot, which by construction cannot
    /// notice a revocation, so without this the grantee would be promoted onto
    /// the board it just lost access to.
    ///
    /// Note the waiter is refreshed, not dropped — `fleet-core` pins the
    /// difference (a request for the grantee's *own* org must survive); this
    /// asserts the coordinator actually pushes the new access in.
    #[tokio::test]
    async fn revocation_refreshes_the_grantees_queued_requests() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[board("org-a", "dk", "node-a")],
            &[("org-a", "alice", Role::Admin), ("org-b", "bob", Role::Member)],
        )
        .await;
        let alice = user("org-a", "alice");
        let bob = user("org-b", "bob");

        // Alice holds the board; bob queues behind her by grant.
        let _ = grant_lease(&coord, &alice, "dk").await;
        let id = crate::state::new_grant_id();
        coord
            .db()
            .scoped(org("org-a"))
            .insert_grant(
                &id,
                &bob.key(),
                "tag=nrf52",
                &[fleet_proto::token::AllowedOp::Attach],
                None,
                Some("alice"),
                1000,
            )
            .await
            .unwrap();

        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &bob,
                SidecarToCoord::Lease(LeaseRequest {
                    select: Constraint::Tags(vec!["nrf52".to_owned()]),
                    duration_secs: 600,
                    priority: Priority::Interactive,
                }),
                &tx,
            )
            .await
            .unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            CoordToSidecar::Queued { .. }
        ));

        // Alice revokes, then releases the board.
        coord
            .handle_sidecar_message(
                &alice,
                SidecarToCoord::GrantRevoke { id: id[..8].to_owned() },
                &tx,
            )
            .await
            .unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            CoordToSidecar::GrantRevoked { .. }
        ));

        let promoted = {
            let mut sched = coord.scheduler().lock().await;
            let held = sched.leases_held_by(&alice.key());
            sched
                .release_lease(held[0].0, &alice.key(), 2000)
                .expect("holder may release")
        };
        assert!(
            promoted.is_none(),
            "a revoked grantee must not be promoted onto the board it lost"
        );
    }
}
