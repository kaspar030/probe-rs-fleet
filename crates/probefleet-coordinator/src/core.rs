//! The transport-agnostic coordinator core.
//!
//! [`Coordinator`] ties together the shared state — the pure
//! [`probefleet_core::scheduler::Scheduler`] (behind a short-held mutex), the
//! [`Db`], the [`NodeRegistry`]/[`ChannelTable`], the ed25519 token
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

use probefleet_core::access::Access;
use probefleet_core::scheduler::{
    LeaseAuthError, LeaseDecision, Promotion, RequesterId, Scheduler,
};
use probefleet_proto::adopt::AdoptPolicy;
use probefleet_proto::board::{Board, BoardState};
use probefleet_proto::ids::{BoardName, BoardRef, LeaseId, NodeId, OrgId, SubjectKey};

use crate::subject::{FleetRole, Subject};
use probefleet_proto::lease::LeaseRequest;
use probefleet_proto::node_api::NodeReport;

use crate::auth::Ed25519Signer;
use crate::authz::{self, AuthzError};
use crate::clock::SharedClock;
use crate::config::CoordinatorConfig;
use crate::error::{CoordinatorError, Result};
use crate::proto::{CoordToSidecar, SidecarToCoord};
use crate::registry::{ChannelTable, NodeRegistry, SidecarHandle, SidecarRegistry};
use crate::relay;
use crate::state::{AuditEntry, Db};
use forgs::schema::NameOrigin;
use forgs::UserId;

/// The shared coordinator state and control-plane logic.
pub struct Coordinator {
    config: CoordinatorConfig,
    scheduler: Mutex<Scheduler>,
    db: Db,
    signer: Ed25519Signer,
    nodes: NodeRegistry,
    /// Live sidecar/ctl connections, so a promotion can be pushed to the
    /// connection that queued for it.
    sidecars: SidecarRegistry,
    channels: ChannelTable,
    clock: SharedClock,
    /// forgs' auth surface: token format, store, hooks, providers.
    auth: forgs_http::AuthContext,
    /// How forgs' hooks reach back into this coordinator.
    link: crate::identity::CoordinatorLink,
}

/// What one [`Coordinator::reconcile_inventory`] pass did.
///
/// Two numbers rather than one because a deletion is the operator-visible half:
/// the audit detail is the only trace that a board row was retired, and
/// "5 boards, 3 removed" is the line that explains a dropped board count on the
/// Nodes page.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ReconcileOutcome {
    /// Boards reported present and admitted — i.e. now leasable.
    online: usize,
    /// `board` rows deleted because the node stopped declaring them.
    pruned: u64,
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
    /// current state — an ambiguous prefix, a disconnected node. Wire:
    /// `Error { message }`; HTTP: 409.
    Conflict(String),
    /// A fault in the coordinator itself (database, token signing). Propagated
    /// by the adapters as `Err(..)` exactly as `?` did before; HTTP: 500
    /// `server_error`. Never rendered to the operator verbatim.
    Internal(crate::error::CoordinatorError),
}

/// Why [`Coordinator::create_org_core`] refused. Each maps to its own
/// `/api/v1` code, because unlike the org-scoped verbs there is no
/// existence oracle to protect: the namespace is global and a taken name
/// is already observable at signup.
#[derive(Debug)]
pub(crate) enum OrgCreateError {
    /// `allow_org_creation = false`: 403 `org_creation_disabled`.
    Disabled,
    /// The caller already created `max_orgs_per_user` orgs: 403
    /// `org_limit_reached`.
    LimitReached,
    /// Not a canonical, user-choosable org name: 400 `invalid_name`.
    InvalidName,
    /// An org, a user or a tombstone holds the name: 409 `name_taken`.
    NameTaken,
    /// A coordinator fault: 500.
    Internal(crate::error::CoordinatorError),
}

/// Why [`Coordinator::rename_org_core`] / [`Coordinator::delete_org_core`]
/// refused. The caller is already a member of the org (the acting-org
/// resolution saw to that), so the specific codes reveal nothing new.
#[derive(Debug)]
pub(crate) enum OrgAdminError {
    /// Not an admin of the org: 403 `forbidden`.
    Denied,
    /// The org is a user's personal org: 409 `personal_org`.
    Personal,
    /// Not a canonical, user-choosable org name: 400 `invalid_name`.
    InvalidName,
    /// An org, a user or a tombstone holds the name: 409 `name_taken`.
    NameTaken,
    /// Nodes, boards, open leases or live grants still reference the org:
    /// 409 `org_not_empty`.
    NotEmpty,
    /// A coordinator fault: 500.
    Internal(crate::error::CoordinatorError),
}

/// Why [`Coordinator::move_node_core`] refused.
///
/// Distinct codes, unlike [`OpError`]: the caller is already an admin of
/// the source org and a member of the target before any of the specific
/// answers is given, so they reveal nothing the caller could not see.
#[derive(Debug)]
pub(crate) enum NodeMoveError {
    /// Not an admin of the source org, or not a member of the target (or
    /// the target does not exist — the same answer): 403 `forbidden`.
    Denied,
    /// The source org has no such node: 404 `not_found`.
    NotFound,
    /// Source and target are the same org: 400 `invalid_request`.
    SameOrg,
    /// The target org already has a node by that name: 409
    /// `node_name_taken`.
    NameTaken,
    /// This many of the node's boards are leased and `force` was not given:
    /// 409 `node_leased`.
    Leased(u32),
    /// A coordinator fault: 500.
    Internal(crate::error::CoordinatorError),
}

/// What [`Coordinator::move_node_core`] did.
#[derive(Debug)]
pub(crate) struct NodeMoveOutcome {
    /// The source org.
    pub from: OrgId,
    /// The target org.
    pub to: OrgId,
    /// The node's id before the move.
    pub old_id: NodeId,
    /// The moved node, as now stored in the target org.
    pub node: NodeStatus,
    /// Leases revoked by the move (with `force`, or by the post-commit
    /// sweep).
    pub revoked_leases: u32,
    /// Source-org grants that covered one of the node's live boards and no
    /// longer do. Unmodified: selectors never name an org or node.
    pub grants_lost: Vec<probefleet_proto::GrantSummary>,
    /// Target-org grants that now cover one of the node's boards.
    pub grants_gained: Vec<probefleet_proto::GrantSummary>,
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
    ///
    /// # Panics
    ///
    /// If the auth configuration derived from `config` is invalid (use
    /// [`Coordinator::with_providers`] to get an error instead).
    #[must_use]
    pub fn new(
        config: CoordinatorConfig,
        scheduler: Scheduler,
        db: Db,
        signer: Ed25519Signer,
        clock: SharedClock,
    ) -> Self {
        Self::with_providers(config, scheduler, db, signer, clock, Vec::new())
            .expect("the coordinator's auth configuration is valid")
    }

    /// [`Coordinator::new`] with login providers (built by
    /// [`crate::identity::build_providers`]).
    ///
    /// # Errors
    ///
    /// [`crate::CoordinatorError::AuthConfig`] for an unusable `public_url`,
    /// CSRF secret or provider name.
    pub fn with_providers(
        config: CoordinatorConfig,
        scheduler: Scheduler,
        db: Db,
        signer: Ed25519Signer,
        clock: SharedClock,
        providers: Vec<Arc<dyn forgs_idp::IdentityProvider>>,
    ) -> Result<Self> {
        let link: crate::identity::CoordinatorLink = Arc::default();
        let auth =
            crate::identity::build_context(&config, &db, Arc::clone(&clock), providers, &link)?;
        Ok(Self {
            config,
            scheduler: Mutex::new(scheduler),
            db,
            signer,
            nodes: NodeRegistry::new(),
            sidecars: SidecarRegistry::new(),
            channels: ChannelTable::new(),
            clock,
            auth,
            link,
        })
    }

    /// Point forgs' hooks at this (shared) coordinator. Idempotent;
    /// [`crate::http::router`] calls it, as does [`crate::build`].
    pub fn attach(self: &Arc<Self>) {
        let _ = self.link.set(Arc::downgrade(self));
    }

    /// forgs' auth context (the router state's `FromRef` target).
    #[must_use]
    pub fn auth(&self) -> &forgs_http::AuthContext {
        &self.auth
    }

    /// The static configuration.
    #[must_use]
    pub fn config(&self) -> &CoordinatorConfig {
        &self.config
    }

    /// The node registry.
    #[must_use]
    pub fn nodes(&self) -> &NodeRegistry {
        &self.nodes
    }

    /// The registry of live sidecar/ctl connections.
    #[must_use]
    pub fn sidecars(&self) -> &SidecarRegistry {
        &self.sidecars
    }

    /// The relay channel table.
    #[must_use]
    pub fn channels(&self) -> &ChannelTable {
        &self.channels
    }

    /// The lease-scoped `probe-rs serve` user token for `(lease, board)`.
    ///
    /// Derived from the signing seed rather than stored (see
    /// [`crate::auth::serve_token`]), so every channel open on one lease yields
    /// the same value with no per-lease state to expire or leak. Both mint
    /// paths — [`Coordinator::open_channel`] and
    /// [`Coordinator::open_delegated_channel`] — go through here, which is what
    /// makes a delegated sandbox land on the delegator's *existing* `serve`.
    fn serve_token(&self, lease: LeaseId, board: &BoardRef) -> String {
        let crate::config::SigningKeySource::Seed(seed) = self.config.signing_key;
        crate::auth::serve_token(&seed, lease, board)
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
    async fn org_and_policy_of_node(&self, node: &NodeId) -> Option<(OrgId, AdoptPolicy)> {
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

    /// Handle one [`NodeReport`] from a connected node.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::error::CoordinatorError`] only on a fatal DB error;
    /// routine report content is logged and tolerated.
    pub async fn handle_node_report(&self, node_id: &NodeId, report: NodeReport) -> Result<()> {
        let Some((org, adopt)) = self.org_and_policy_of_node(node_id).await else {
            warn!(%node_id, "dropping report from a node with no resolvable org");
            return Ok(());
        };
        match report {
            NodeReport::Register {
                node,
                protocol_version,
            } => {
                debug!(%node, protocol_version, "node register");
                self.audit(
                    &org,
                    "node.register",
                    None,
                    Some(&node.0),
                    None,
                    None,
                    Some(&node.0),
                )
                .await?;
            }
            NodeReport::Inventory(inv) => {
                // Reconcile the node's inventory into the scheduler's board set
                // so the boards become leasable and `open_channel` can resolve
                // board -> owning node. Each present (online) declared board is
                // upserted as a `Board` owned by this node *within the node's
                // org*; the node is authoritative for its board metadata via
                // `boards.toml`, but never for the org. The scheduler preserves
                // any live lease state on re-report (see
                // `Scheduler::upsert_board`).
                let ReconcileOutcome { online, pruned } =
                    self.reconcile_inventory(&org, node_id, adopt, &inv).await;
                self.audit(
                    &org,
                    "node.inventory",
                    None,
                    Some(&node_id.0),
                    None,
                    None,
                    Some(&format!(
                        "{} boards ({online} online, {pruned} removed, adopt={adopt})",
                        inv.boards.len()
                    )),
                )
                .await?;
            }
            NodeReport::Heartbeat { uptime_secs } => {
                debug!(%node_id, uptime_secs, "heartbeat");
            }
            NodeReport::Fault { board, reason } => {
                warn!(%node_id, %board, %reason, "board fault");
                let board_ref = BoardRef::new(org.clone(), node_id.clone(), board.0.clone());
                self.fault_board(&board_ref, &reason).await;
                self.audit(
                    &org,
                    "board.fault",
                    None,
                    Some(&node_id.0),
                    Some(&board.0),
                    None,
                    Some(&reason),
                )
                .await?;
            }
            NodeReport::Log {
                level,
                board,
                message,
            } => {
                debug!(%node_id, ?level, ?board, %message, "node log");
                self.audit(
                    &org,
                    "node.log",
                    None,
                    Some(&node_id.0),
                    board.as_ref().map(|b| b.0.as_str()),
                    None,
                    Some(&message),
                )
                .await?;
            }
            NodeReport::PowerEvent { board, action } => {
                debug!(%node_id, %board, ?action, "power event");
                self.audit(
                    &org,
                    "board.power",
                    None,
                    Some(&node_id.0),
                    Some(&board.0),
                    None,
                    Some(&format!("{action:?}")),
                )
                .await?;
            }
            NodeReport::SessionClosed { channel, exit_code } => {
                debug!(%node_id, ?channel, ?exit_code, "session closed");
                relay::close_channel(&self.channels, None, channel).await;
            }
            NodeReport::TokenRotated { rotation_id } => {
                // Handled by the connection task, which owns the pending
                // rotation; reaching `core` means the connection did not
                // recognise it, which is worth a trace but nothing more.
                debug!(%node_id, rotation_id, "stray token-rotation ack");
            }
        }
        Ok(())
    }

    /// Reconcile a node inventory snapshot into the scheduler's board set and
    /// the `board` table.
    ///
    /// A [`ProbeInventory`](probefleet_proto::node_api::ProbeInventory) is a full
    /// snapshot, never a delta, so this is a **set** operation: what the report
    /// omits is retired from both stores.
    ///
    /// # The two stores, and why they differ
    ///
    /// * **The scheduler is what can be leased right now.** A board is present
    ///   iff the latest report declares it, reports it `Online`, and policy
    ///   admits it. `Offline` → removed. Absent from the report → removed. A
    ///   live lease pins the board in either case.
    /// * **The `board` table is what the node currently declares.** A row
    ///   exists iff the latest report carries the board and this function
    ///   admits it: a *declared* board with any presence, or an *adopted* board
    ///   the policy admits **online**. A declared board reported `Offline`
    ///   keeps its row — a J-Link unplugged for an afternoon must not vanish
    ///   from the UI, and must not churn rows every `discovery_secs`. Absent
    ///   from the report → the declaration is gone → the row is deleted
    ///   ([`crate::state::OrgDb::prune_boards`]).
    ///
    /// The invariant: **the DB set is the scheduler set plus declared-but-
    /// offline boards, and nothing else.** "Nodes shows 3, Devices shows 2"
    /// is therefore a legitimate state (one declared board is unplugged), and
    /// after this it is the *only* way the two pages can differ.
    ///
    /// A renamed board is the case that motivates the prune: it is not reported
    /// offline, it simply stops appearing, so no tombstone ever arrives. Before
    /// the set difference it lingered in *both* stores — leaving a leasable
    /// phantom whose lease is granted, tokenised, and only refused at the last
    /// hop with `UnknownBoard`.
    ///
    /// Returns the number of online boards and the number of rows pruned.
    ///
    /// This is the only place a [`BoardRef`] is minted from node input: the
    /// node supplies a node-local [`BoardName`] and the coordinator attaches the
    /// org of the authenticated connection, so cross-org board injection is not
    /// expressible. That holds for an **adopted** board exactly as it does for
    /// a declared one — auto-adoption changes which probes become boards, never
    /// whose tenant they land in.
    ///
    /// `adopt` is the node's policy from its `node` row, which is the
    /// authoritative copy (the node's `node.toml` setting only governs what it
    /// reports):
    ///
    /// * [`AdoptPolicy::Declared`] — a board the node flagged `adopted` is
    ///   dropped. The node should not have synthesised it, but the enforcement
    ///   point is here, so a node whose local config drifted (or which is
    ///   simply lying) cannot widen its own policy.
    /// * [`AdoptPolicy::Auto`] — adopted boards are scheduled like declared
    ///   ones. The synthesis itself lives on the node, which is the only side
    ///   that can see a probe's identity.
    async fn reconcile_inventory(
        &self,
        org: &OrgId,
        node_id: &NodeId,
        adopt: AdoptPolicy,
        inv: &probefleet_proto::node_api::ProbeInventory,
    ) -> ReconcileOutcome {
        use probefleet_proto::node_api::BoardPresence;
        use std::collections::HashSet;

        let now = self.now_i64();
        let scoped = self.db.scoped(org.clone());
        // Boards reference their node row, so the node must exist first —
        // otherwise every board insert below fails the foreign key.
        if let Err(e) = scoped.ensure_node(node_id, now).await {
            warn!(node = %node_id, error = %e, "failed to record node; skipping inventory");
            // No prune in this path: without a node row we cannot tell an
            // unknown node from one whose write failed, and deleting its boards
            // on a transient DB error would be the worse answer.
            return ReconcileOutcome::default();
        }

        let mut online = 0usize;
        // Boards to persist, paired with the presence to record them under.
        let mut boards_to_record: Vec<(Board, BoardPresence)> = Vec::new();
        // The node-local names whose rows survive this report.
        let mut keep: HashSet<String> = HashSet::new();
        // Names pinned by a live lease: they survive the prune even when the
        // report stopped declaring them (see below).
        let mut leased_keep: Vec<String> = Vec::new();
        {
            let mut sched = self.scheduler.lock().await;
            for status in &inv.boards {
                // Which boards the coordinator is willing to know about at all.
                // One predicate for both stores, so the keep-set and the record
                // set cannot drift apart:
                //
                // * a *declared* board is admitted at any presence — offline
                //   just means "unplugged", and the declaration stands;
                // * an *adopted* board is admitted only when the node's policy
                //   is `auto` **and** it is online.
                //
                // Both halves of the adopted case matter. Refusing an adopted
                // board from a `declared` node is enforcement, not decoration:
                // a node whose local config drifted (or which is simply lying)
                // must not be able to widen its own policy, and the row here is
                // what decides. Refusing an adopted board reported *offline* is
                // the tombstone rule — "this probe is gone, drop it" — which
                // must be honoured whatever the policy says, or a node whose
                // policy was flipped `auto` → `declared` would strand every
                // board it had adopted while it was `auto`. Removing a board is
                // never a tenancy risk; refusing to is the one that leaves a
                // phantom the scheduler will happily lease.
                //
                // Since a non-admitted board is also absent from `keep`, any row
                // it left behind (from an earlier `auto` period, say) is pruned
                // below rather than lingering.
                let admitted = !status.adopted
                    || (adopt == AdoptPolicy::Auto && status.presence == BoardPresence::Online);
                if !admitted {
                    if status.presence == BoardPresence::Online {
                        warn!(
                            node = %node_id,
                            board = %status.board,
                            "ignoring an adopted board from a node whose policy is `declared`"
                        );
                    }
                    continue;
                }
                let board_ref = BoardRef::new(org.clone(), node_id.clone(), status.board.0.clone());
                keep.insert(status.board.0.clone());
                let board = Board {
                    id: board_ref.clone(),
                    node: node_id.clone(),
                    chip: status.chip.clone(),
                    model: status.model.clone(),
                    tags: status.tags.clone(),
                    exclusive: status.exclusive,
                    power: status.power.clone(),
                    state: BoardState::Idle,
                    serial_ports: status.serial_ports.clone(),
                };
                if status.presence == BoardPresence::Online {
                    online += 1;
                    sched.upsert_board(board.clone());
                } else {
                    // An offline board is dropped from the scheduler unless it
                    // is currently leased (an in-flight lease is preserved).
                    // Its row stays: it is still declared.
                    let leased = matches!(
                        sched.board(&board_ref).map(|b| &b.state),
                        Some(BoardState::Leased { .. })
                    );
                    if !leased {
                        sched.remove_board(&board_ref);
                    }
                }
                boards_to_record.push((board, status.presence));
            }

            // Boards this node no longer declares leave the scheduler. Decided
            // and applied under the same lock as the upserts above, so no lease
            // can be granted on a board between the decision and its removal —
            // the reasoning `delete_node_core` documents.
            //
            // A live lease pins the board: dropping it here would strand an open
            // `leases` row against a board nothing can release. Known hole,
            // accepted for v1: the stale board is only re-pruned by the *next*
            // inventory report, and `Node::discovery_pass` suppresses reports
            // whose inventory is unchanged — so a board renamed while leased
            // survives the lease's release until something else about the
            // inventory changes. Closing that needs a prune hooked into lease
            // release, which is a separate change.
            let stale: Vec<BoardRef> = sched
                .boards()
                .filter(|b| b.id.org == *org && b.id.node == *node_id)
                .filter(|b| !keep.contains(b.id.name.as_str()))
                .filter_map(|b| {
                    if matches!(b.state, BoardState::Leased { .. }) {
                        leased_keep.push(b.id.name.clone());
                        None
                    } else {
                        Some(b.id.clone())
                    }
                })
                .collect();
            for board_ref in &stale {
                debug!(board = %board_ref, "pruning a board the node no longer declares");
                sched.remove_board(board_ref);
            }
        }
        // Persist the board rows (best-effort; a DB error is logged, not fatal
        // — the scheduler is the source of truth for leasing).
        for (board, presence) in &boards_to_record {
            if let Err(e) = scoped.record_board(board, *presence, now).await {
                warn!(board = %board.id, error = %e, "failed to record board");
            }
        }
        // …and retire the rows of boards the node stopped declaring. A board
        // held by a live lease keeps its row for the same reason it keeps its
        // scheduler entry: the Nodes page must not contradict a lease that is
        // being actively used.
        let mut keep_names: Vec<String> = keep.into_iter().collect();
        keep_names.extend(leased_keep);
        let pruned = match scoped.prune_boards(node_id, &keep_names).await {
            Ok(n) => n,
            Err(e) => {
                warn!(node = %node_id, error = %e, "failed to prune stale board rows");
                0
            }
        };
        ReconcileOutcome { online, pruned }
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
    /// `requester` identifies the calling *connection*. It is what a queued
    /// lease request is tagged with, so the waiter can be dropped when this
    /// connection closes and a promotion can be pushed back down `tx`. Call
    /// paths that cannot create a waiter pass [`RequesterId::DETACHED`].
    ///
    /// # Errors
    ///
    /// Returns a [`crate::error::CoordinatorError`] only on a fatal error (DB /
    /// token signing); request-level failures — including every authorization
    /// refusal — are reported back to the sidecar via [`CoordToSidecar::Error`]
    /// and return `Ok`.
    // One arm per wire verb, so the length tracks the protocol's surface rather
    // than any complexity of its own; each arm delegates immediately.
    #[allow(clippy::too_many_lines)]
    pub async fn handle_sidecar_message(
        &self,
        subject: &Subject,
        msg: SidecarToCoord,
        tx: &mpsc::Sender<CoordToSidecar>,
        requester: RequesterId,
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
                let reply = self.request_lease(subject, req, requester).await?;
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
                let node = self.nodes.get(&route.node).await;
                relay::close_channel(&self.channels, node.as_ref(), channel).await;
            }
            SidecarToCoord::ListBoards => {
                let reply = self.list_boards(subject).await;
                let _ = tx.send(reply).await;
            }
            SidecarToCoord::ListNodes => {
                let reply = self.list_nodes(subject).await?;
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
    /// The request wire stays node-local (so `PROBEFLEET_ID=nrf52840-dk-3`
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
    /// [`probefleet_proto::ids::BoardRef::answers_to`] so this resolver and
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
    async fn resolve_board(&self, access: &Access, name: &BoardName, now: u64) -> BoardLookup {
        // An org **path** qualifier (`ariel-os/rpi-1/dk-3`) needs the orgs'
        // display names, which live in forgs; look them up (outside the
        // scheduler lock) only for a qualified name, and only for orgs the
        // caller may reach at all.
        let mut org_paths: std::collections::HashMap<OrgId, String> =
            std::collections::HashMap::new();
        if name.0.contains('/') {
            let mut orgs: Vec<OrgId> = access.member_of.clone();
            orgs.extend(access.grants.iter().map(|g| g.org.clone()));
            orgs.sort();
            orgs.dedup();
            for org in orgs {
                if let Ok(Some(path)) = self.db.org_name(&org).await {
                    org_paths.insert(org, path);
                }
            }
        }
        let sched = self.scheduler.lock().await;
        let candidates: Vec<&probefleet_proto::board::Board> = sched
            .boards()
            .filter(|b| {
                b.id.answers_to_in(&name.0, org_paths.get(&b.id.org).map(String::as_str))
            })
            .filter(|b| access.may_use(b, now))
            .collect();

        // Tier 1: the caller's own org. Tier 2: everything else they may reach.
        let own: Vec<&probefleet_proto::board::Board> = candidates
            .iter()
            .copied()
            .filter(|b| access.owns(b))
            .collect();
        let tier = if own.is_empty() { &candidates } else { &own };

        match tier.len() {
            0 => BoardLookup::NotFound,
            1 => BoardLookup::Found(tier[0].id.clone()),
            _ => {
                let mut nodes: Vec<NodeId> = tier.iter().map(|b| b.id.node.clone()).collect();
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
    ) -> std::result::Result<Vec<probefleet_proto::admin::BoardSummary>, OpError> {
        use probefleet_proto::admin::{BoardAvailability, BoardSummary};
        let now = self.now();
        let access = authz::board_access(&self.db, subject, now).await;
        if access.is_empty() {
            return Err(OpError::Denied);
        }
        let sched = self.scheduler.lock().await;
        let mut boards = sched
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
                    node: b.node.clone(),
                    chip: b.chip.clone(),
                    model: b.model.clone(),
                    tags: b.tags.clone(),
                    exclusive: b.exclusive,
                    power: b.power.clone(),
                    availability,
                    holder,
                    lease,
                    expires,
                    serial_ports: b.serial_ports.clone(),
                    org_name: None,
                    holder_display: None,
                }
            })
            .collect::<Vec<_>>();
        // The display lookups hit the database, so never under the scheduler
        // lock. They are best-effort (a miss renders the raw key), which keeps
        // this core infallible past the access check.
        drop(sched);
        let mut org_names: std::collections::HashMap<OrgId, Option<String>> =
            std::collections::HashMap::new();
        let mut displays: std::collections::HashMap<SubjectKey, Option<String>> =
            std::collections::HashMap::new();
        for b in &mut boards {
            if !org_names.contains_key(&b.board.org) {
                let name = self.db.org_name(&b.board.org).await.ok().flatten();
                org_names.insert(b.board.org.clone(), name);
            }
            b.org_name.clone_from(&org_names[&b.board.org]);
            if let Some(holder) = &b.holder {
                if !displays.contains_key(holder) {
                    let d = self.subject_display(holder).await;
                    displays.insert(holder.clone(), d);
                }
                b.holder_display.clone_from(&displays[holder]);
            }
        }
        Ok(boards)
    }

    /// Wire adapter for [`Coordinator::list_boards_core`]: renders the board
    /// list, or the flat refusal, as a [`CoordToSidecar`].
    async fn list_boards(&self, subject: &Subject) -> CoordToSidecar {
        match self.list_boards_core(subject).await {
            Ok(boards) => CoordToSidecar::BoardList(boards),
            // Only `Denied` is reachable here — the core's only I/O past the
            // access check is best-effort display lookups that cannot fail it.
            // The remaining variants still have to go somewhere: this reply
            // has no error channel of its own (the signature predates the
            // core split and `handle_sidecar_message`'s call site must not
            // change), so they render as the flat refusal rather than panic.
            Err(e) => e.into_wire().unwrap_or_else(|_| Self::denied()),
        }
    }

    /// Wire adapter for [`Coordinator::list_nodes_core`]: renders the org's
    /// machines as a [`CoordToSidecar::NodeList`] for `ctl nodes`.
    ///
    /// Adds **no** authorization of its own — it calls the same core the
    /// browser API's `GET /api/v1/nodes` calls, so the two surfaces cannot
    /// drift on who may see a node.
    ///
    /// Unlike [`Coordinator::list_boards`] this returns a `Result`: the core
    /// does fallible database I/O, and rendering an `OpError::Internal` as the
    /// flat "not authorized" refusal would misreport a DB fault as a
    /// permission problem.
    ///
    /// # Errors
    ///
    /// Propagates a database failure; refusals become a [`CoordToSidecar`].
    async fn list_nodes(&self, subject: &Subject) -> Result<CoordToSidecar> {
        match self.list_nodes_core(subject).await {
            Ok(nodes) => Ok(CoordToSidecar::NodeList(
                nodes.into_iter().map(node_summary).collect(),
            )),
            Err(e) => e.into_wire(),
        }
    }

    /// Whether `user` may create a team org over the API right now:
    /// `allow_org_creation` is on and they are under `max_orgs_per_user`.
    ///
    /// Advisory (it feeds `SessionView.can_create_orgs`); the cap itself is
    /// enforced inside the creating transaction by [`Self::create_org_core`].
    ///
    /// # Errors
    ///
    /// [`OrgCreateError::Disabled`], [`OrgCreateError::LimitReached`], or
    /// [`OrgCreateError::Internal`] on a database error.
    pub(crate) async fn org_creation_allowed(
        &self,
        user: UserId,
    ) -> std::result::Result<(), OrgCreateError> {
        self.org_creation_enabled()?;
        if let Some(cap) = self.org_cap() {
            let owned = self
                .db
                .count_orgs_owned_by(user)
                .await
                .map_err(OrgCreateError::Internal)?;
            if owned >= cap {
                return Err(OrgCreateError::LimitReached);
            }
        }
        Ok(())
    }

    /// `allow_org_creation`, as a refusal.
    fn org_creation_enabled(&self) -> std::result::Result<(), OrgCreateError> {
        if self.config.allow_org_creation {
            Ok(())
        } else {
            Err(OrgCreateError::Disabled)
        }
    }

    /// `max_orgs_per_user`, with `0` meaning no cap.
    fn org_cap(&self) -> Option<u64> {
        let cap = self.config.max_orgs_per_user;
        (cap > 0).then(|| u64::from(cap))
    }

    /// Canonicalise a user-supplied org name, refusing one that is not
    /// already canonical (`Acme` is refused rather than silently lowercased,
    /// so the display name and the path agree).
    fn canonical_org_name(&self, raw_name: &str) -> Option<String> {
        let name = raw_name.trim();
        let canonical = self
            .db
            .forgs()
            .schema()
            .canonical_name(crate::subject::ORG_KIND, name, NameOrigin::User)
            .ok()?;
        (canonical == name).then_some(canonical)
    }

    /// Create a team org named `raw_name` with `user` as its admin — the
    /// self-service path behind `POST /api/v1/orgs`.
    ///
    /// Policy first (`allow_org_creation`), then the name: it must already
    /// be canonical, and forgs' naming rules, reserved list and collision
    /// check (orgs, usernames, tombstones — they share the root) apply.
    /// Creation goes through [`forgs_http::members::create_namespace`]: the
    /// node, the admin membership and the `max_orgs_per_user` check are one
    /// transaction, so the cap is **hard** — concurrent creations cannot both
    /// pass at the limit. Audited as `org.create` in the new org, so it shows
    /// in its `GET /api/v1/audit`.
    ///
    /// # Errors
    ///
    /// See [`OrgCreateError`].
    pub(crate) async fn create_org_core(
        &self,
        user: UserId,
        raw_name: &str,
    ) -> std::result::Result<(OrgId, String), OrgCreateError> {
        self.org_creation_enabled()?;
        let canonical = self
            .canonical_org_name(raw_name)
            .ok_or(OrgCreateError::InvalidName)?;
        let now = self.now();
        let org = match forgs_http::members::create_namespace(
            self.auth(),
            user,
            None,
            crate::subject::ORG_KIND,
            &canonical,
            self.org_cap(),
        )
        .await
        {
            Ok(ns) => crate::subject::org_of(ns),
            Err(e) if e == forgs_http::ApiError::NAMESPACE_LIMIT => {
                return Err(OrgCreateError::LimitReached)
            }
            Err(e)
                if e == forgs_http::ApiError::USERNAME_INVALID
                    || e == forgs_http::ApiError::BadRequest =>
            {
                return Err(OrgCreateError::InvalidName)
            }
            Err(e) if e == forgs_http::ApiError::USERNAME_TAKEN => {
                return Err(OrgCreateError::NameTaken)
            }
            Err(e) => {
                return Err(OrgCreateError::Internal(CoordinatorError::State(format!(
                    "creating org `{canonical}`: {e}"
                ))))
            }
        };

        if let Some(ns) = crate::subject::ns_of(&org) {
            self.auth
                .audit()
                .record(
                    forgs_http::AuditEvent::new(now, "org.create")
                        .ns(ns)
                        .subject(&forgs::SubjectKey::user(user))
                        .target(canonical.clone()),
                )
                .await;
        }
        tracing::info!(org = %org, name = %canonical, user = %user, "team org created");
        Ok((org, canonical))
    }

    /// Require `user` to be an admin of a non-personal `org`.
    async fn require_team_org_admin(
        &self,
        org: &OrgId,
        user: UserId,
    ) -> std::result::Result<(), OrgAdminError> {
        match self.db.role_of(org, user).await {
            Ok(Some(FleetRole::Admin)) => {}
            Ok(_) => return Err(OrgAdminError::Denied),
            Err(e) => return Err(OrgAdminError::Internal(e)),
        }
        match self.db.is_personal_org(org).await {
            Ok(false) => Ok(()),
            Ok(true) => Err(OrgAdminError::Personal),
            Err(e) => Err(OrgAdminError::Internal(e)),
        }
    }

    /// Map a forgs namespace-admin error onto [`OrgAdminError`].
    fn org_admin_api_error(e: &forgs_http::ApiError, what: &str) -> OrgAdminError {
        use forgs_http::ApiError as E;
        if *e == E::USERNAME_INVALID || *e == E::BadRequest {
            OrgAdminError::InvalidName
        } else if *e == E::USERNAME_TAKEN {
            OrgAdminError::NameTaken
        } else if *e == E::CONFLICT {
            OrgAdminError::Personal
        } else if *e == E::NOT_EMPTY {
            OrgAdminError::NotEmpty
        } else if *e == E::Forbidden {
            OrgAdminError::Denied
        } else {
            OrgAdminError::Internal(CoordinatorError::State(format!("{what}: {e}")))
        }
    }

    /// Rename the acting team org to `raw_name` — `POST /api/v1/org/rename`.
    /// Admin only; a personal org follows its user's name and is refused.
    /// The name rules are those of [`Self::create_org_core`]; the old name is
    /// tombstoned by forgs. Audited as `org.rename` in the org.
    ///
    /// # Errors
    ///
    /// See [`OrgAdminError`].
    pub(crate) async fn rename_org_core(
        &self,
        subject: &Subject,
        user: UserId,
        raw_name: &str,
    ) -> std::result::Result<(OrgId, String), OrgAdminError> {
        let org = subject.org().cloned().ok_or(OrgAdminError::Denied)?;
        self.require_team_org_admin(&org, user).await?;
        let canonical = self
            .canonical_org_name(raw_name)
            .ok_or(OrgAdminError::InvalidName)?;
        let old = self
            .db
            .org_name(&org)
            .await
            .map_err(OrgAdminError::Internal)?
            .unwrap_or_default();
        forgs_http::members::rename_namespace(self.auth(), user, &org.0, &canonical)
            .await
            .map_err(|e| Self::org_admin_api_error(&e, "renaming an org"))?;
        if let Some(ns) = crate::subject::ns_of(&org) {
            self.auth
                .audit()
                .record(
                    forgs_http::AuditEvent::new(self.now(), "org.rename")
                        .ns(ns)
                        .subject(&forgs::SubjectKey::user(user))
                        .target(canonical.clone())
                        .detail(format!("from {old}")),
                )
                .await;
        }
        tracing::info!(org = %org, from = %old, to = %canonical, user = %user, "team org renamed");
        Ok((org, canonical))
    }

    /// Delete the acting team org — `DELETE /api/v1/org`. Admin only;
    /// personal orgs are refused.
    ///
    /// Refused with [`OrgAdminError::NotEmpty`] while the org has nodes,
    /// boards, open leases or unexpired grants. Otherwise its fleet history
    /// (closed leases, the fleet audit log) is purged — those rows would block
    /// the namespace delete forever — and the namespace is deleted through
    /// [`forgs_http::members::delete_namespace`], which tombstones the name
    /// and takes memberships and org-scoped API keys with it. The purge and
    /// the delete are two transactions: a node enrolled in between fails the
    /// delete (`not_empty`), losing only history. Audited as `org.delete` in
    /// the forgs audit log, which has no foreign key and so survives.
    ///
    /// # Errors
    ///
    /// See [`OrgAdminError`].
    pub(crate) async fn delete_org_core(
        &self,
        subject: &Subject,
        user: UserId,
    ) -> std::result::Result<String, OrgAdminError> {
        let org = subject.org().cloned().ok_or(OrgAdminError::Denied)?;
        let ns = crate::subject::ns_of(&org).ok_or(OrgAdminError::Denied)?;
        self.require_team_org_admin(&org, user).await?;
        let name = self
            .db
            .org_name(&org)
            .await
            .map_err(OrgAdminError::Internal)?
            .unwrap_or_else(|| org.0.clone());
        let now = self.now();
        let grants = self
            .db
            .forgs()
            .scoped(ns)
            .list_grants()
            .await
            .map_err(|e| OrgAdminError::Internal(e.into()))?;
        if grants.iter().any(|g| g.expires.is_none_or(|t| t > now)) {
            return Err(OrgAdminError::NotEmpty);
        }
        if !self
            .db
            .clear_org_history(&org)
            .await
            .map_err(OrgAdminError::Internal)?
        {
            return Err(OrgAdminError::NotEmpty);
        }
        forgs_http::members::delete_namespace(self.auth(), user, &org.0)
            .await
            .map_err(|e| Self::org_admin_api_error(&e, "deleting an org"))?;
        self.auth
            .audit()
            .record(
                forgs_http::AuditEvent::new(now, "org.delete")
                    .ns(ns)
                    .subject(&forgs::SubjectKey::user(user))
                    .target(name.clone()),
            )
            .await;
        tracing::info!(org = %org, name = %name, user = %user, "team org deleted");
        Ok(name)
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
    /// `grant list` and the audit log. Writes are admin-only and go through
    /// forgs' own `members::{set, remove}` (the functions `/auth/members`
    /// calls), which own the admin check and the last-admin guard.
    ///
    /// # Errors
    ///
    /// [`OpError::Denied`] for a non-member; [`OpError::Internal`] on a
    /// database failure.
    pub(crate) async fn list_members_core(
        &self,
        subject: &Subject,
    ) -> std::result::Result<Vec<crate::state::MemberRow>, OpError> {
        let Some(org) = subject.org().cloned() else {
            return Err(OpError::Denied);
        };
        if authz::require_role(&self.db, subject, &org, FleetRole::Member)
            .await
            .is_err()
        {
            return Err(OpError::Denied);
        }
        self.db.list_members(&org).await.map_err(OpError::Internal)
    }

    /// The org's machines, with live connection state.
    ///
    /// Shared by two surfaces with one authorization story: the browser API's
    /// `GET /api/v1/nodes` and the wire verb `SidecarToCoord::ListNodes`
    /// (`ctl nodes`), which reaches it through [`Coordinator::list_nodes`].
    /// Neither adds a check of its own.
    ///
    /// It is a core of its own — rather than part of `ctl list` — because
    /// `ctl list` is board-shaped, so a machine that has plugged in no probes
    /// is invisible to it; an operator (or a fleet UI) has to be able to say
    /// "this Pi is enrolled and online but is offering nothing", and to see the
    /// node tags a `tag=` selector will match.
    ///
    /// `online` is composed here rather than stored: liveness is the
    /// [`crate::registry::NodeRegistry`]'s in-memory answer to "is the
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
        let Some(org) = subject.org().cloned() else {
            return Err(OpError::Denied);
        };
        if authz::require_role(&self.db, subject, &org, FleetRole::Member)
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
            let online = self.nodes.get(&row.id).await.is_some();
            out.push(NodeStatus { row, online });
        }
        Ok(out)
    }

    /// Update one node's tags and/or adoption policy.
    ///
    /// **New surface, no wire counterpart** — there is no `ctl node edit`. The
    /// node is addressed by its node-local `name`, resolved inside the caller's
    /// own org: the id is `{org}/{name}` and so contains a slash, which cannot
    /// travel in a URL path segment (`docs/web-ui.md` §3).
    ///
    /// # The authorization is the one genuinely new policy
    ///
    /// **Owner ([`crate::state::NodeRow::owner_user_id`]), or org admin** —
    /// composed here from the row and [`authz::is_org_admin`] rather than
    /// added to `authz.rs`, because it is a rule about one table's column and
    /// not a new notion of access (`docs/web-ui.md` §7).
    ///
    /// Its sharp edge is deliberate: a node enrolled with an auth key or from a
    /// shell has `owner_user_id = NULL` and is therefore **admin-only**. The
    /// same shape as an auth key with no recorded creator, and the alternative
    /// — treating "nobody owns it" as "everybody owns it" — would let any
    /// member re-point a machine nobody claimed.
    ///
    /// # Rename is refused
    ///
    /// The caller cannot change `name`; see [`crate::state::OrgDb::update_node`]
    /// for why, and note that the handler rejects a `name` field outright
    /// rather than ignoring it — a silent no-op would leave an operator
    /// believing a rename had happened.
    ///
    /// Note also what is *not* here: nothing writes `adopt` from an inventory
    /// report. [`OrgDb::ensure_node`](crate::state::OrgDb::ensure_node)
    /// deliberately leaves the policy alone on every report, and this method
    /// does not create a second path that would undo that — it writes only
    /// what an authorized human asked for.
    ///
    /// # Errors
    ///
    /// [`OpError::Denied`] for a non-member, and for a member who is neither
    /// the node's owner nor an org admin (a `node.update.denied` audit row is
    /// written first, mirroring `grant.revoke.denied`); [`OpError::NotFound`]
    /// when this org has no node by that name — **the same answer** a node in
    /// another org produces, since [`crate::state::OrgDb`] cannot see one;
    /// [`OpError::Internal`] on a database failure.
    pub(crate) async fn update_node_core(
        &self,
        subject: &Subject,
        name: &str,
        tags: Option<&[String]>,
        adopt: Option<AdoptPolicy>,
    ) -> std::result::Result<NodeStatus, OpError> {
        let Some(org) = subject.org().cloned() else {
            return Err(OpError::Denied);
        };
        let row = self
            .authorize_node_mutation(subject, name, "node.update.denied")
            .await?;

        let updated = self
            .db
            .scoped(org.clone())
            .update_node(&row.name, tags, adopt)
            .await
            .map_err(OpError::Internal)?
            // It existed a moment ago; if it does not now, somebody deleted it
            // concurrently and "no such node" is the honest answer.
            .ok_or_else(|| OpError::NotFound(format!("no node named {name}")))?;

        let mut detail = Vec::new();
        if let Some(tags) = tags {
            detail.push(format!("tags={}", tags.join(",")));
        }
        if let Some(adopt) = adopt {
            detail.push(format!("adopt={}", adopt.as_str()));
        }
        self.audit(
            &org,
            "node.update",
            Some(&subject.key().to_string()),
            Some(&updated.id.0),
            None,
            None,
            (!detail.is_empty()).then(|| detail.join(" ")).as_deref(),
        )
        .await
        .map_err(OpError::Internal)?;

        let online = self.nodes.get(&updated.id).await.is_some();
        Ok(NodeStatus {
            row: updated,
            online,
        })
    }

    /// Delete a node: revoke its token, and make the revocation *real*.
    ///
    /// Same authorization as [`Coordinator::update_node_core`] — owner or org
    /// admin, `owner_user_id = NULL` meaning admin-only.
    ///
    /// # The cascade is the point
    ///
    /// Deleting the `node` row invalidates the node's token (architecture
    /// §4.2: revocation *is* deleting the row). But a token is not the only
    /// thing keeping a machine attached, so this goes, in order:
    ///
    /// 1. **live leases** on the node's boards are released through the whole
    ///    shared release path ([`Coordinator::tear_down_lease`]) — relay
    ///    channels closed, the lease closed and audited — exactly as the
    ///    grant-revocation cascade does, and *repeatedly*, because that path
    ///    promotes and persists a queued waiter onto each board it frees. Skip
    ///    this and the machine keeps relaying bytes until the lease TTL runs
    ///    out, while the operator believes it is gone;
    /// 2. the boards leave the **scheduler**, so nothing new can be leased onto
    ///    hardware that is no longer part of the fleet. The final "nothing is
    ///    leased" check and the removal happen under **one** lock acquisition:
    ///    a lease granted between a check and a later removal would be
    ///    persisted and then dropped from the scheduler, which is the same
    ///    stranded-row failure (1) guards against, reached by a different
    ///    route;
    /// 3. the `board` and `node` rows are deleted in one transaction
    ///    ([`crate::state::OrgDb::delete_node`]); the board rows *must* go
    ///    first, since `board.node_id` is an enforced foreign key;
    /// 4. the node is dropped from the [`crate::registry::NodeRegistry`] **and
    ///    its control-plane `WebSocket` is closed**
    ///    ([`crate::registry::NodeRegistry::remove_and_close`]). Both halves
    ///    are needed and neither implies the other: removing the entry only
    ///    makes the node unroutable, because
    ///    [`crate::server::handle_node`] keeps its own sender alive for the
    ///    life of the read loop and the registry therefore holds a *clone*. An
    ///    already-open socket would linger until it dropped of its own accord,
    ///    leaving an operator who deleted a node with the machine still
    ///    attached. The node's next reconnect then fails authentication,
    ///    because its row is gone.
    ///
    /// The database write sits at (3) rather than first on purpose: if it
    /// fails, the leases are already down (safe, if inconvenient — the machine
    /// is still enrolled and can be leased again), whereas deleting the row
    /// first and then failing would leave live leases against a node no
    /// authorization check can resolve any more.
    ///
    /// One honest limit, the same one grant revocation has: a capability token
    /// already minted stays cryptographically valid until it expires. Tearing
    /// down the relay is what makes it useless — there is no path to the board
    /// without the coordinator.
    ///
    /// Returns the deleted node's id.
    ///
    /// # Errors
    ///
    /// As [`Coordinator::update_node_core`], with `node.delete.denied` as the
    /// refusal audit action.
    pub(crate) async fn delete_node_core(
        &self,
        subject: &Subject,
        name: &str,
    ) -> std::result::Result<NodeId, OpError> {
        let Some(org) = subject.org().cloned() else {
            return Err(OpError::Denied);
        };
        let row = self
            .authorize_node_mutation(subject, name, "node.delete.denied")
            .await?;
        let node_id = row.id.clone();

        // (1) + (2): see `drain_node_boards`.
        let (removed, _) = self
            .drain_node_boards(
                &node_id,
                subject,
                "node deleted",
                "releasing a lease on a node being deleted",
            )
            .await
            .map_err(OpError::Internal)?;
        let board_refs: Vec<BoardRef> = removed.into_iter().map(|b| b.id).collect();

        // (3) The rows, board-first, in one transaction.
        let deleted = self
            .db
            .scoped(org.clone())
            .delete_node(&row.name)
            .await
            .map_err(OpError::Internal)?;
        if !deleted {
            return Err(OpError::NotFound(format!("no node named {name}")));
        }

        // (4) The live connection.
        self.nodes.remove_and_close(&node_id).await;

        self.audit(
            &org,
            "node.delete",
            Some(&subject.key().to_string()),
            Some(&node_id.0),
            None,
            None,
            Some(&format!("{} boards removed", board_refs.len())),
        )
        .await
        .map_err(OpError::Internal)?;
        Ok(node_id)
    }

    /// Move a node — and with it every board it hosts — from the caller's
    /// acting org to `to_org_raw` (an org path or id).
    ///
    /// # Authorization
    ///
    /// **Admin of the source org** (a move takes hardware out of it; a
    /// non-admin member gets a `node.move.denied` audit row) **and member of
    /// the target** (the same bar as approving a node into an org,
    /// [`crate::identity::APPROVE_ROLE`]). An unknown target and one the
    /// caller is not a member of give the same [`NodeMoveError::Denied`], so
    /// this is no oracle for which orgs exist.
    ///
    /// # What happens
    ///
    /// 1. leased boards refuse the move unless `force`; with `force` their
    ///    leases are revoked (`"node moved"`), and the boards leave the
    ///    scheduler ([`Coordinator::drain_node_boards`]);
    /// 2. the node and board rows are re-keyed in one transaction
    ///    ([`Db::move_node`]). The token hash stays on the row, so the agent's
    ///    existing token authenticates the moved node;
    /// 3. the live connection is closed: it captured the old org and id. The
    ///    agent reconnects by itself, re-reports its inventory, and the boards
    ///    re-enter the scheduler under the new org. Its stored node id stays
    ///    the old one until its next `node up`, which
    ///    [`crate::server`]'s `Register` check tolerates;
    /// 4. a final drain under the old id sweeps anything a report slipped in
    ///    before the commit — unconditionally, since those keys no longer
    ///    exist;
    /// 5. `node.move.out` / `node.move.in` audit rows in both orgs.
    ///
    /// Grants are not touched (selectors name neither org nor node); the
    /// outcome lists which source-org grants stop covering the boards and
    /// which target-org grants start to, computed over the boards that were
    /// live in the scheduler (an offline node's lists are empty).
    ///
    /// # Errors
    ///
    /// See [`NodeMoveError`].
    pub(crate) async fn move_node_core(
        &self,
        subject: &Subject,
        name: &str,
        to_org_raw: &str,
        force: bool,
    ) -> std::result::Result<NodeMoveOutcome, NodeMoveError> {
        let (from, to, row) = self.authorize_node_move(subject, name, to_org_raw).await?;
        let old_id = row.id.clone();

        if !force {
            let sched = self.scheduler.lock().await;
            let leased = sched
                .boards()
                .filter(|b| b.node == old_id && matches!(b.state, BoardState::Leased { .. }))
                .count();
            if leased > 0 {
                return Err(NodeMoveError::Leased(
                    u32::try_from(leased).unwrap_or(u32::MAX),
                ));
            }
        }
        let (removed, mut revoked) = self
            .drain_node_boards(
                &old_id,
                subject,
                "node moved",
                "releasing a lease on a node being moved",
            )
            .await
            .map_err(NodeMoveError::Internal)?;

        let new_id = match self.db.move_node(&from, &row.name, &to).await {
            Ok(crate::state::NodeMove::Moved(id)) => id,
            other => {
                // The boards already left the scheduler; drop the connection so
                // the node reconnects and re-reports them where it still is.
                self.nodes.remove_and_close(&old_id).await;
                return Err(match other {
                    Ok(crate::state::NodeMove::NameTaken) => NodeMoveError::NameTaken,
                    Ok(_) => NodeMoveError::NotFound,
                    Err(e) => NodeMoveError::Internal(e),
                });
            }
        };
        self.nodes.remove_and_close(&old_id).await;
        let (_, swept) = self
            .drain_node_boards(
                &old_id,
                subject,
                "node moved",
                "releasing a lease on a node being moved",
            )
            .await
            .map_err(NodeMoveError::Internal)?;
        revoked += swept;

        let (grants_lost, grants_gained) =
            self.move_grant_effects(&from, &to, &new_id, &removed).await;

        let from_name = self.org_label(&from).await;
        let to_name = self.org_label(&to).await;

        let actor = subject.key().to_string();
        self.audit(
            &from,
            "node.move.out",
            Some(&actor),
            Some(&old_id.0),
            None,
            None,
            Some(&format!(
                "to {to_name} as {new_id}; {} boards; {revoked} leases revoked",
                removed.len()
            )),
        )
        .await
        .map_err(NodeMoveError::Internal)?;
        self.audit(
            &to,
            "node.move.in",
            Some(&actor),
            Some(&new_id.0),
            None,
            None,
            Some(&format!("from {from_name} (was {old_id})")),
        )
        .await
        .map_err(NodeMoveError::Internal)?;

        let new_row = self
            .db
            .scoped(to.clone())
            .node_by_name(&row.name)
            .await
            .map_err(NodeMoveError::Internal)?
            .ok_or(NodeMoveError::NotFound)?;
        let online = self.nodes.get(&new_row.id).await.is_some();
        Ok(NodeMoveOutcome {
            from,
            to,
            old_id,
            node: NodeStatus {
                row: new_row,
                online,
            },
            revoked_leases: revoked,
            grants_lost,
            grants_gained,
        })
    }

    /// The checks of [`Coordinator::move_node_core`], in order: admin of the
    /// source (a member gets a `node.move.denied` row), the node exists,
    /// member of the target, not the same org, name free in the target.
    /// Returns the source, the target and the node row.
    async fn authorize_node_move(
        &self,
        subject: &Subject,
        name: &str,
        to_org_raw: &str,
    ) -> std::result::Result<(OrgId, OrgId, crate::state::NodeRow), NodeMoveError> {
        let Some(from) = subject.org().cloned() else {
            return Err(NodeMoveError::Denied);
        };
        let Some(user) = subject.user_id() else {
            return Err(NodeMoveError::Denied);
        };
        match self.db.role_of(&from, user).await {
            Ok(Some(FleetRole::Admin)) => {}
            Ok(Some(_)) => {
                self.audit(
                    &from,
                    "node.move.denied",
                    Some(&subject.key().to_string()),
                    None,
                    None,
                    None,
                    Some(&format!("{name}: not an org admin")),
                )
                .await
                .map_err(NodeMoveError::Internal)?;
                return Err(NodeMoveError::Denied);
            }
            Ok(None) => return Err(NodeMoveError::Denied),
            Err(e) => return Err(NodeMoveError::Internal(e)),
        }
        let row = self
            .db
            .scoped(from.clone())
            .node_by_name(name)
            .await
            .map_err(NodeMoveError::Internal)?
            .ok_or(NodeMoveError::NotFound)?;

        let to = self
            .db
            .resolve_org(to_org_raw)
            .await
            .map_err(NodeMoveError::Internal)?
            .ok_or(NodeMoveError::Denied)?;
        match self.db.role_of(&to, user).await {
            Ok(Some(role)) if role >= crate::identity::APPROVE_ROLE => {}
            Ok(_) => return Err(NodeMoveError::Denied),
            Err(e) => return Err(NodeMoveError::Internal(e)),
        }
        if to == from {
            return Err(NodeMoveError::SameOrg);
        }
        if self
            .db
            .node_id_in_org_by_name(&to, &row.name)
            .await
            .map_err(NodeMoveError::Internal)?
            .is_some()
        {
            return Err(NodeMoveError::NameTaken);
        }
        Ok((from, to, row))
    }

    /// An org's display name, else its id (for audit details).
    async fn org_label(&self, org: &OrgId) -> String {
        self.db
            .org_name(org)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| org.0.clone())
    }

    /// The grants a move takes `boards` out of (source org) and into
    /// (target org, the boards re-keyed under `new_id`). Best effort: a
    /// grant store failure yields empty lists rather than failing a move
    /// that has already committed.
    async fn move_grant_effects(
        &self,
        from: &OrgId,
        to: &OrgId,
        new_id: &NodeId,
        boards: &[Board],
    ) -> (
        Vec<probefleet_proto::GrantSummary>,
        Vec<probefleet_proto::GrantSummary>,
    ) {
        let now = self.now();
        let rekeyed: Vec<Board> = boards
            .iter()
            .map(|b| Board {
                id: BoardRef::new(to.clone(), new_id.clone(), b.id.name.clone()),
                node: new_id.clone(),
                ..b.clone()
            })
            .collect();
        let mut lost = Vec::new();
        let mut gained = Vec::new();
        for (org, set, out) in [(from, boards, &mut lost), (to, &rekeyed[..], &mut gained)] {
            let Some(ns) = crate::subject::ns_of(org) else {
                continue;
            };
            let Ok(rows) = self.db.forgs().scoped(ns).list_grants().await else {
                continue;
            };
            for row in rows {
                let covers = crate::state::grant_scope(&row)
                    .is_some_and(|g| g.is_live_at(now) && set.iter().any(|b| g.covers(b)));
                if covers {
                    out.push(self.grant_summary(row).await);
                }
            }
        }
        (lost, gained)
    }

    /// Revoke every live lease on `node_id`'s boards and remove the boards
    /// from the scheduler, returning the removed boards and the number of
    /// leases revoked.
    ///
    /// Shared by [`Coordinator::delete_node_core`] and
    /// [`Coordinator::move_node_core`]; the caller supplies the lease close
    /// reason (and a log line) so each keeps its own history.
    async fn drain_node_boards(
        &self,
        node_id: &NodeId,
        subject: &Subject,
        close_reason: &str,
        log_msg: &str,
    ) -> Result<(Vec<Board>, u32)> {
        let mut revoked = 0u32;
        // (1) + (2), interleaved on purpose: live leases go down through the
        // whole shared release path, then the boards leave the scheduler — and
        // the *last* teardown check and the `remove_board` calls happen under a
        // single lock.
        //
        // Looped, and that is not defensive coding. Two distinct routes produce
        // the same failure — an open `leases` row against a board the scheduler
        // no longer has, which nothing will ever close and whose holder
        // believes it has a lease:
        //
        // * `tear_down_lease` promotes a queued waiter onto the board it just
        //   freed **and persists the promotion**, so a single pass can leave a
        //   brand-new lease behind; and
        // * a lease request arriving between the check and `remove_board` is
        //   granted and persisted in that window.
        //
        // The second is why the exit is not "loop until empty, then take the
        // lock again": the guard has to be re-tested and acted on without ever
        // releasing the lock in between. Each iteration consumes at least one
        // waiter or grant, and `tear_down_lease` needs the lock itself, so the
        // teardown cannot happen inside the scope that removes the boards.
        let boards: Vec<Board> = loop {
            let held: Vec<(LeaseId, BoardRef, SubjectKey)> = {
                let mut sched = self.scheduler.lock().await;
                let held: Vec<_> = sched
                    .boards()
                    .filter(|b| b.node == *node_id)
                    .filter_map(|b| match &b.state {
                        BoardState::Leased { lease, by, .. } => {
                            Some((*lease, b.id.clone(), by.clone()))
                        }
                        _ => None,
                    })
                    .collect();
                if held.is_empty() {
                    // Nothing leased *and* still holding the lock: remove the
                    // boards now, before anything can be granted on them.
                    let refs: Vec<BoardRef> = sched
                        .boards()
                        .filter(|b| b.node == *node_id)
                        .map(|b| b.id.clone())
                        .collect();
                    let removed: Vec<Board> = refs
                        .iter()
                        .filter_map(|board_ref| sched.remove_board(board_ref))
                        .collect();
                    break removed;
                }
                held
            };
            for (lease, board_ref, holder) in held {
                warn!(%board_ref, ?lease, node = %node_id, "{log_msg}");
                if self
                    .tear_down_lease(lease, &holder, close_reason, "lease.revoke", subject)
                    .await?
                {
                    revoked += 1;
                }
            }
        };
        Ok((boards, revoked))
    }

    /// The owner-or-admin check shared by the two node-mutation cores.
    ///
    /// Returns the node row, so the caller does not re-read it and cannot
    /// accidentally act on a different one. Membership is checked first, for
    /// the same reason `grant_revoke_core` does: a non-member must not be able
    /// to probe which node names exist.
    ///
    /// A node in another org is invisible here — the lookup goes through
    /// [`crate::state::OrgDb`] — so "not yours" and "no such node" produce the
    /// same [`OpError::NotFound`]. The REST instinct to distinguish them turns
    /// this API into a cross-tenant existence oracle (`docs/web-ui.md` §4).
    async fn authorize_node_mutation(
        &self,
        subject: &Subject,
        name: &str,
        denied_action: &str,
    ) -> std::result::Result<crate::state::NodeRow, OpError> {
        let Some(org) = subject.org().cloned() else {
            return Err(OpError::Denied);
        };
        if authz::require_role(&self.db, subject, &org, FleetRole::Member)
            .await
            .is_err()
        {
            return Err(OpError::Denied);
        }
        let row = self
            .db
            .scoped(org.clone())
            .node_by_name(name)
            .await
            .map_err(OpError::Internal)?
            .ok_or_else(|| OpError::NotFound(format!("no node named {name}")))?;

        // `owner_user_id = NULL` is admin-only, not everyone-owns-it.
        let owned = row.owner_user_id.is_some() && row.owner_user_id == subject.user_id();
        if !owned && !authz::is_org_admin(&self.db, subject).await {
            self.audit(
                &org,
                denied_action,
                Some(&subject.key().to_string()),
                Some(&row.id.0),
                None,
                None,
                Some("neither the node's owner nor an org admin"),
            )
            .await
            .map_err(OpError::Internal)?;
            return Err(OpError::Denied);
        }
        Ok(row)
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
    ) -> std::result::Result<Vec<probefleet_proto::admin::LeaseHolderSummary>, OpError> {
        use probefleet_proto::admin::LeaseHolderSummary;
        let now = self.now();
        let access = authz::board_access(&self.db, subject, now).await;
        if access.is_empty() {
            return Err(OpError::Denied);
        }
        let sched = self.scheduler.lock().await;
        let mut holders = sched
            .boards()
            .filter(|b| access.may_use(b, now))
            .filter_map(|b| match &b.state {
                BoardState::Leased { lease, by, expires } => Some(LeaseHolderSummary {
                    lease: *lease,
                    board: b.id.clone(),
                    holder: by.clone(),
                    expires: *expires,
                    holder_display: None,
                }),
                _ => None,
            })
            .collect::<Vec<_>>();
        // Best-effort display lookups, outside the scheduler lock.
        drop(sched);
        let mut displays: std::collections::HashMap<SubjectKey, Option<String>> =
            std::collections::HashMap::new();
        for h in &mut holders {
            if !displays.contains_key(&h.holder) {
                let d = self.subject_display(&h.holder).await;
                displays.insert(h.holder.clone(), d);
            }
            h.holder_display.clone_from(&displays[&h.holder]);
        }
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
    ) -> std::result::Result<Vec<probefleet_proto::admin::LogLine>, OpError> {
        let Some(org) = subject.org().cloned() else {
            return Err(OpError::Denied);
        };
        if authz::require_role(&self.db, subject, &org, FleetRole::Admin)
            .await
            .is_err()
        {
            return Err(OpError::Denied);
        }
        let board_name = board.map(|b| b.0.as_str());
        let mut lines = self
            .db
            .scoped(org.clone())
            .recent_audit(board_name, 200)
            .await
            .map_err(OpError::Internal)?;
        // Identity events (keys, members, logins) live in forgs' audit table;
        // they concern no board, so they join only the unfiltered view.
        if board_name.is_none() {
            if let Some(ns) = crate::subject::ns_of(&org) {
                let rows = self
                    .db
                    .forgs()
                    .scoped(ns)
                    .recent_audit(200)
                    .await
                    .map_err(|e| OpError::Internal(e.into()))?;
                lines.extend(rows.into_iter().map(|r| probefleet_proto::admin::LogLine {
                    ts: i64::try_from(r.ts).unwrap_or(i64::MAX),
                    action: r.action,
                    board: None,
                    detail: {
                        let parts: Vec<String> = [r.subject, r.target, r.detail]
                            .into_iter()
                            .flatten()
                            .collect();
                        (!parts.is_empty()).then(|| parts.join(" "))
                    },
                }));
                // Newest first, as each source already is; stable on ties.
                lines.sort_by_key(|l| std::cmp::Reverse(l.ts));
                lines.truncate(200);
            }
        }
        Ok(lines)
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

    /// Operator power-cycle: command the owning node to power-cycle the board.
    ///
    /// Scoped by [`Access`]: an unreachable board resolves to "no such board",
    /// exactly as an absent one does. A *grantee* additionally needs the
    /// [`AllowedOp::PowerCycle`] op — this is the one op enforced here rather
    /// than by the node, because the node's power-cycle command carries no
    /// capability token to check.
    ///
    /// Returns the board's node-local name, as echoed back to the operator.
    ///
    /// # Errors
    ///
    /// [`OpError::Denied`] when the caller may not reach the board, or may see
    /// it but not cut its power; [`OpError::NotFound`] for an absent or
    /// unreachable board; [`OpError::Conflict`] for an ambiguous name and for
    /// a node that is not connected; [`OpError::Internal`] on a database
    /// failure.
    pub(crate) async fn operator_power_cycle_core(
        &self,
        subject: &Subject,
        board: &BoardName,
    ) -> std::result::Result<BoardName, OpError> {
        use probefleet_proto::token::AllowedOp;

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
        let node_id = board_ref.node.clone();
        // Both node-connection failures are `Conflict`, not `Internal` and not
        // `NotFound`: the request was well-formed and authorized, the fleet is
        // just momentarily unable to serve it. The enum has no "temporarily
        // unavailable" bucket, and `Conflict` is the one whose HTTP mapping
        // (409) tells the caller to retry rather than to re-authorize or to
        // stop asking for that board.
        let Some(node) = self.nodes.get(&node_id).await else {
            return Err(OpError::Conflict(format!(
                "node {node_id} for board {board} is not connected"
            )));
        };
        if node
            .send_command(probefleet_proto::CoordinatorCommand::PowerCycle {
                board: board_ref.board_name(),
            })
            .await
            .is_err()
        {
            return Err(OpError::Conflict(format!(
                "node {node_id} connection closed"
            )));
        }
        self.audit(
            &org,
            "board.power-cycle",
            Some(&subject.key().to_string()),
            Some(&node_id.0),
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
        ops: Vec<probefleet_proto::token::AllowedOp>,
        expires: Option<u64>,
    ) -> std::result::Result<probefleet_proto::GrantSummary, OpError> {
        use probefleet_proto::lease::parse_constraint;

        let Some(org) = subject.org().cloned() else {
            return Err(OpError::Denied);
        };
        if authz::require_role(&self.db, subject, &org, FleetRole::Admin)
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
        let selector = match parse_constraint(selector) {
            Ok(c) => c.to_string(),
            Err(e) => return Err(OpError::Invalid(format!("invalid selector: {e}"))),
        };

        let ops = probefleet_proto::token::normalize_ops(ops);
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
            return Err(OpError::Invalid(format!("no such user `{grantee}`")));
        };

        let ns = crate::subject::ns_of(&org).ok_or(OpError::Denied)?;
        let forgs_key = crate::subject::to_forgs(&key)
            .ok_or_else(|| OpError::Invalid(format!("`{grantee}` is not a grantable subject")))?;
        let id = self
            .db
            .forgs()
            .scoped(ns)
            .insert_grant(
                &forgs_store::NewGrant {
                    subject: forgs_key,
                    selector: selector.clone(),
                    ops: crate::state::join_ops(&ops),
                    expires: Some(expires),
                    created_by: subject.user_id(),
                },
                now,
            )
            .await
            .map_err(|e| OpError::Internal(e.into()))?
            .to_string();
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

        let org_name = self.db.org_name(&org).await.ok().flatten();
        let subject_display = self.subject_display(&key).await;
        Ok(probefleet_proto::GrantSummary {
            id,
            org,
            org_name,
            subject: key,
            subject_display,
            selector,
            ops,
            expires: Some(expires),
            created_by: subject.user_id().map(|u| u.to_string()),
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
        ops: Vec<probefleet_proto::token::AllowedOp>,
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
    /// Three accepted forms, narrowing in precision:
    ///
    /// * `repo:<owner>/<name>` — a **CI repository** (architecture §6.7),
    ///   first so it can never be shadowed by the key-parsing branch. Validated
    ///   and lowercased by the **same** function the OIDC claim path uses
    ///   (`forgs::subject::normalise_repo`), so the two sides of the per-repo
    ///   trust rule cannot disagree about spelling. A grant names exactly one
    ///   repo: the owner is never a grantee.
    /// * a rendered subject key (`user:01J…`, `<org>/node:…`,
    ///   `<org>/workload:agent:ci`) — unambiguous, and the way to name a node;
    /// * a **username** — resolved to the immutable user id **once**, here, so
    ///   the stored grant survives a rename and never follows a reused name.
    async fn resolve_grantee(&self, spec: &str) -> Result<Option<SubjectKey>> {
        let spec = spec.trim();
        if let Some(repo) = spec.strip_prefix("repo:") {
            return Ok(forgs::subject::normalise_repo(repo)
                .map(|r| forgs::subject::workload_subject_key(&r))
                .as_ref()
                .and_then(crate::subject::to_proto));
        }
        if let Some(key) = forgs::SubjectKey::parse_with(spec, &[crate::subject::NODE_KIND]) {
            return Ok(crate::subject::to_proto(&key));
        }
        if spec.contains([':', '/']) {
            return Ok(None);
        }
        match self.db.forgs().user_by_username(spec).await {
            Ok(Some(u)) => Ok(Some(crate::subject::user_key(u.id))),
            Ok(None) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// A human rendering of `key`: a user's username, else `None`.
    pub(crate) async fn subject_display(&self, key: &SubjectKey) -> Option<String> {
        let user = crate::subject::user_of(key)?;
        self.db
            .forgs()
            .user_by_id(user)
            .await
            .ok()
            .flatten()
            .map(|u| u.username)
    }

    /// A forgs grant row as the wire summary.
    async fn grant_summary(&self, row: forgs_store::GrantRow) -> probefleet_proto::GrantSummary {
        let org = crate::subject::org_of(row.ns);
        let subject = SubjectKey::parse(&row.subject).unwrap_or_else(|| {
            // An unparseable stored subject is still listed (so it can be
            // revoked), rendered verbatim as an opaque user id.
            SubjectKey::new(None, probefleet_proto::ids::SubjectKind::User, &row.subject)
                .unwrap_or_else(|| crate::subject::user_key(forgs::UserId::from_parts(0, 0)))
        });
        probefleet_proto::GrantSummary {
            id: row.id.to_string(),
            org_name: self.db.org_name(&org).await.ok().flatten(),
            org,
            subject_display: self.subject_display(&subject).await,
            subject,
            ops: crate::state::parsed_ops(&row.ops),
            selector: row.selector,
            expires: row.expires,
            created_by: row.created_by.map(|u| u.to_string()),
            created_at: row.created_at,
        }
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
    ) -> std::result::Result<Vec<probefleet_proto::GrantSummary>, OpError> {
        let Some(org) = subject.org().cloned() else {
            return Err(OpError::Denied);
        };
        if authz::require_role(&self.db, subject, &org, FleetRole::Member)
            .await
            .is_err()
        {
            return Err(OpError::Denied);
        }
        let ns = crate::subject::ns_of(&org).ok_or(OpError::Denied)?;
        let rows = self
            .db
            .forgs()
            .scoped(ns)
            .list_grants()
            .await
            .map_err(|e| OpError::Internal(e.into()))?;
        let mut grants = Vec::with_capacity(rows.len());
        for row in rows {
            grants.push(self.grant_summary(row).await);
        }
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
    /// since a [`probefleet_core::access::Access`] snapshot cannot notice a
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
        let Some(org) = subject.org().cloned() else {
            return Err(OpError::Denied);
        };
        // Membership first: a non-member must not be able to probe which
        // prefixes exist.
        if authz::require_role(&self.db, subject, &org, FleetRole::Member)
            .await
            .is_err()
        {
            return Err(OpError::Denied);
        }

        // Load-bearing, not hygiene: a prefix must be long enough to address
        // a grant on purpose, and drawn from the alphabet grant ids (ULIDs,
        // Crockford base32) actually use. forgs enforces the same floor.
        let prefix = id_prefix.trim().to_ascii_uppercase();
        if prefix.len() < 8
            || !prefix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b.is_ascii_uppercase() && !b"ILOU".contains(&b)))
        {
            return Err(OpError::Invalid(
                "grant id prefix must be at least 8 characters of the grant id".to_owned(),
            ));
        }

        let ns = crate::subject::ns_of(&org).ok_or(OpError::Denied)?;
        let scoped = self.db.forgs().scoped(ns);
        let all = scoped
            .list_grants()
            .await
            .map_err(|e| OpError::Internal(e.into()))?;
        let matches: Vec<_> = all
            .iter()
            .filter(|g| g.id.to_string().starts_with(&prefix))
            .collect();
        let target = match matches.len() {
            0 => return Err(OpError::NotFound(format!("no grant matching {prefix}"))),
            1 => matches[0],
            n => {
                return Err(OpError::Conflict(format!(
                    "{n} grants match {prefix}; use a longer prefix"
                )))
            }
        };

        let owned = target.created_by.is_some() && target.created_by == subject.user_id();
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

        let grantee = SubjectKey::parse(&target.subject);
        let deleted = scoped
            .delete_grant(target.id)
            .await
            .map_err(|e| OpError::Internal(e.into()))?;
        let ids: Vec<String> = deleted.iter().map(|g| g.id.to_string()).collect();
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
    pub(crate) async fn cascade_revocation(&self, grantee: &SubjectKey, org: &OrgId) -> Result<()> {
        let now = self.now();
        // Rebuild the grantee's access from scratch.
        let access = authz::access_of(&self.db, grantee, now).await;
        // The teardown is audited as acting in the hardware's org.
        let as_subject = Subject::new(grantee.clone(), Some(org.clone()));

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
    /// lease's capability token, for a sandboxed node.
    ///
    /// Delegation is deliberately *not* a grant and creates **no principal**.
    /// The sandbox gets no fleet identity, no session token, cannot enumerate
    /// the fleet or request another board, and cannot outlive the lease.
    /// Revocation is releasing the lease. Mechanically this is exactly
    /// [`Coordinator::request_lease`] with the token attenuated further, to the
    /// intersection of what the caller may do and what they asked to hand over
    /// — you can never delegate more than you hold — **minus the queueing**: it
    /// goes through [`probefleet_core::scheduler::Scheduler::try_lease`], so a
    /// contended board is reported and no waiter is left behind (#452).
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
        select: probefleet_proto::lease::Constraint,
        duration_secs: u64,
        ops: Vec<probefleet_proto::token::AllowedOp>,
    ) -> Result<CoordToSidecar> {
        if subject.kind() == probefleet_proto::ids::SubjectKind::Workload {
            debug!(%subject, "refusing delegation by a CI workload");
            return Ok(CoordToSidecar::Error {
                message: "a CI workload may not delegate its lease".to_owned(),
            });
        }
        let ops = probefleet_proto::token::normalize_ops(ops);
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

        let select_display = select.to_string();
        let req = LeaseRequest {
            select,
            duration_secs,
            priority: probefleet_proto::lease::Priority::Interactive,
        };
        let decision = {
            let mut sched = self.scheduler.lock().await;
            // `try_lease`, not `request_lease`: this verb must not leave a
            // waiter behind. It hands a token to a sandbox and returns, so a
            // queued request would stay eligible for promotion and a board
            // freed minutes later would be handed to a delegator that walked
            // away — held by nobody until TTL (#452). A separate entry point
            // rather than a flag, so the property is visible at the call site.
            sched.try_lease(subject.key().clone(), &access, req, now)
        };
        let granted = match decision {
            LeaseDecision::Granted(g) => g,
            // The caller decides what to do with a queue slip; `ctl delegate`
            // fails fast rather than blocking a sandbox handoff on it, and now
            // leaves nothing queued behind it.
            LeaseDecision::Queued { position } => return Ok(CoordToSidecar::Queued { position }),
            LeaseDecision::NoCandidate { reachable } => {
                return Ok(CoordToSidecar::NoCandidate {
                    selector: select_display,
                    reachable,
                })
            }
            LeaseDecision::AtCap { held, cap } => return Ok(CoordToSidecar::AtCap { held, cap }),
        };

        // Never hand out more than the delegator holds.
        let effective: Vec<probefleet_proto::token::AllowedOp> = {
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
                subject.key(),
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
                &granted.holder,
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
        requester: RequesterId,
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
        // (`probefleet-sidecar/src/lib.rs`), so the clamp fires on *every* CI lease.
        //
        // `Policy::max_duration_ci` then applies to it, and extension inherits
        // the clamp for free: `Scheduler::extend_lease` re-derives the renewal
        // from the **recorded** priority *and* the **recorded granted
        // duration** — both already carry the clamp, because the duration was
        // capped under the clamped priority at grant time. So a workload stays
        // clamped on every renewal and there is deliberately no second guard in
        // `extend_lease` — please do not add one.
        if subject.kind() == probefleet_proto::ids::SubjectKind::Workload
            && req.priority != probefleet_proto::lease::Priority::Ci
        {
            debug!(
                %subject, requested = ?req.priority,
                "clamping a workload's lease request to CI priority"
            );
            req.priority = probefleet_proto::lease::Priority::Ci;
        }
        let select_display = req.select.to_string();
        let decision = {
            let mut sched = self.scheduler.lock().await;
            sched.request_lease(subject.key().clone(), requester, &access, req, now)
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
                        &granted.holder,
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
            // Neither of these queued anything, and both say what is actually
            // wrong rather than blaming contention: a selector that matches
            // nothing can never be satisfied by waiting, and a cap is the
            // caller's own budget, not the fleet's state.
            LeaseDecision::NoCandidate { reachable } => Ok(CoordToSidecar::NoCandidate {
                selector: select_display,
                reachable,
            }),
            LeaseDecision::AtCap { held, cap } => Ok(CoordToSidecar::AtCap { held, cap }),
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
                // A live lease always has a board; the acting org is only a
                // fallback for the audit row.
                let Some(org) = board_org.or_else(|| subject.org().cloned()) else {
                    return Ok(CoordToSidecar::Extended { lease, expires });
                };
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
    /// it in the scheduler, persist the close, audit it, and settle whatever
    /// waiter was promoted onto the freed board (persist, notify, and — if the
    /// promoted holder is unreachable — pass the board on again).
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
        let Some(org) = board_org.or_else(|| acting.org().cloned()) else {
            return Ok(true);
        };

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

        // If a waiter was promoted onto the freed board, persist its grant and
        // push it to the holder — or, if the holder cannot be reached, hand the
        // board on to the next waiter. All of that is `settle_promotion`.
        self.settle_promotion(promoted, None).await?;

        Ok(true)
    }

    /// Audit detail noting an admin override, if the acting subject is not the
    /// holder.
    fn override_detail(subject: &Subject, holder: &SubjectKey) -> Option<String> {
        (subject.key() != holder).then(|| format!("admin override; holder {holder}"))
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
        kind: probefleet_proto::ChannelKind,
        sidecar_tx: mpsc::Sender<CoordToSidecar>,
    ) -> Result<Option<CoordToSidecar>> {
        let (holder, board, node_id, expires) = {
            let sched = self.scheduler.lock().await;
            let Ok(holder) = authz::require_lease_control(&self.db, &sched, subject, lease).await
            else {
                return Ok(Some(CoordToSidecar::Error {
                    message: AuthzError::lease_message(),
                }));
            };
            let Some((board, node_id)) = sched.lease_target(lease) else {
                return Ok(Some(CoordToSidecar::Error {
                    message: AuthzError::lease_message(),
                }));
            };
            let (board, node_id) = (board.clone(), node_id.clone());
            let expires = sched
                .board(&board)
                .and_then(|b| match &b.state {
                    BoardState::Leased { expires, .. } => Some(*expires),
                    _ => None,
                })
                .unwrap_or_else(|| self.now());
            (holder, board, node_id, expires)
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
        let holder_access = authz::access_of(&self.db, &holder_subject, now).await;
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

        let Some(node) = self.nodes.get(&node_id).await else {
            return Ok(Some(CoordToSidecar::Error {
                message: format!("node {node_id} not connected"),
            }));
        };

        // Mint a fresh capability token scoped to this lease/board, attenuated
        // to the holder's *current* effective ops. Reached only after the
        // ownership check above.
        let token = probefleet_proto::token::CapabilityToken {
            lease,
            board: board.clone(),
            allowed_ops: ops,
            expires,
        };
        let wire = self.signer.sign_to_wire(&token)?;
        // The serve user token is scoped to the **lease**, not this channel: the
        // node reuses one `probe-rs serve` process across the holder's many
        // invocations, and its Figment config is read once at startup.
        let serve = self.serve_token(lease, &board);

        let channel = relay::open_channel(
            &self.channels,
            &node,
            node_id,
            sidecar_tx,
            relay::OpenRequest {
                lease,
                board: board.clone(),
                token: wire.clone(),
                serve_token: serve.clone(),
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
        // Return the *exact* bytes the node got, so the sidecar can hand the
        // genuine probe-rs client credentials the node and `probe-rs serve`
        // will both accept. Re-minting on the sidecar side is what used to
        // break after an `extend_lease`.
        Ok(Some(CoordToSidecar::ChannelOpened {
            channel,
            token: wire,
            serve_token: serve,
        }))
    }

    /// Forward a sidecar data frame to the owning node.
    async fn relay_from_sidecar(&self, frame: probefleet_proto::DataFrame) {
        let Some(route) = self.channels.get(frame.channel).await else {
            return;
        };
        let Some(node) = self.nodes.get(&route.node).await else {
            return;
        };
        if let Err(e) = relay::forward_to_agent(&self.channels, &node, frame).await {
            debug!(error = %e, "relay to node failed");
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
        token: &probefleet_proto::token::CapabilityToken,
        kind: probefleet_proto::ChannelKind,
        sidecar_tx: mpsc::Sender<CoordToSidecar>,
    ) -> Result<CoordToSidecar> {
        let refused = || CoordToSidecar::Error {
            message: AuthzError::lease_message(),
        };

        let now = self.now();
        let (holder, board, node_id, expires) = {
            let sched = self.scheduler.lock().await;
            let Some(holder) = sched.lease_holder(token.lease).cloned() else {
                return Ok(refused());
            };
            let Some((board, node_id)) = sched.lease_target(token.lease) else {
                return Ok(refused());
            };
            let (board, node_id) = (board.clone(), node_id.clone());
            let expires = sched
                .board(&board)
                .and_then(|b| match &b.state {
                    BoardState::Leased { expires, .. } => Some(*expires),
                    _ => None,
                })
                .unwrap_or(now);
            (holder, board, node_id, expires)
        };

        // The lease must still be on the board the token names. Boards can be
        // removed and lease ids reused across restarts; a token must not
        // silently follow.
        if board != token.board {
            return Ok(refused());
        }

        // Attenuate to the intersection: never more than the token says, and
        // never more than the delegator currently holds.
        let holder_access = authz::access_of(&self.db, &holder, now).await;
        let ops: Vec<probefleet_proto::token::AllowedOp> = {
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

        let Some(node) = self.nodes.get(&node_id).await else {
            return Ok(CoordToSidecar::Error {
                message: format!("node {node_id} not connected"),
            });
        };

        let fresh = probefleet_proto::token::CapabilityToken {
            lease: token.lease,
            board: board.clone(),
            allowed_ops: ops,
            expires,
        };
        let wire = self.signer.sign_to_wire(&fresh)?;
        // Same lease and board as the delegator's own channels, so the sandbox
        // lands on the *same* `probe-rs serve` process rather than racing a
        // second one onto the probe.
        let serve = self.serve_token(token.lease, &board);

        let channel = relay::open_channel(
            &self.channels,
            &node,
            node_id,
            sidecar_tx,
            relay::OpenRequest {
                lease: token.lease,
                board: board.clone(),
                token: wire.clone(),
                serve_token: serve.clone(),
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
            Some(&format!("{channel:?}; delegated by {holder}")),
        )
        .await?;

        Ok(CoordToSidecar::ChannelOpened {
            channel,
            token: wire,
            serve_token: serve,
        })
    }

    /// Relay a data frame from a delegated connection, refusing any channel not
    /// belonging to the token's lease.
    pub(crate) async fn relay_delegated(&self, lease: LeaseId, frame: probefleet_proto::DataFrame) {
        match self.channels.get(frame.channel).await {
            Some(route) if route.lease == lease => {}
            _ => return,
        }
        self.relay_from_sidecar(frame).await;
    }

    /// Close a channel from a delegated connection, refusing any channel not
    /// belonging to the token's lease.
    pub(crate) async fn close_delegated_channel(
        &self,
        lease: LeaseId,
        channel: probefleet_proto::ChannelId,
    ) {
        let Some(route) = self.channels.get(channel).await else {
            return;
        };
        if route.lease != lease {
            return;
        }
        let node = self.nodes.get(&route.node).await;
        relay::close_channel(&self.channels, node.as_ref(), channel).await;
    }

    /// Forward a node data frame to the owning sidecar.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::error::CoordinatorError`] if the sidecar's connection
    /// has closed.
    pub async fn relay_from_agent(&self, frame: probefleet_proto::DataFrame) -> Result<bool> {
        relay::forward_to_sidecar(&self.channels, frame).await
    }

    /// Close all relay channels tied to a lease.
    async fn teardown_lease_channels(&self, lease: LeaseId) {
        for channel in self.channels.channels_for_lease(lease).await {
            let route = self.channels.get(channel).await;
            let node = match route {
                Some(r) => self.nodes.get(&r.node).await,
                None => None,
            };
            relay::close_channel(&self.channels, node.as_ref(), channel).await;
        }
    }

    /// Handle a sidecar/ctl connection going away.
    ///
    /// A disconnect drops that connection's **queued requests** but not its
    /// **held leases**, and the split is deliberate:
    ///
    /// * a queued request has nobody left to hand a board to. Promoting it
    ///   would mark a board `Leased` to a caller that has exited, held by
    ///   nobody until TTL, and skipped over every waiter that is still there
    ///   (#381). So the waiters tagged with this `requester` are dropped.
    /// * a lease outlives a single connection: a sidecar may reconnect, `ctl`
    ///   opens one connection per command, and a `probe-rs` run legitimately
    ///   holds hardware across reconnects. Leases are reclaimed by the expiry
    ///   sweep, not by a socket closing (architecture §6).
    ///
    /// This is also the **only** cleanup for a sidecar that gave up waiting:
    /// there is no cancel message on the wire, so a client whose bounded queue
    /// wait expires simply closes its connection and *this* method removes its
    /// waiter. That indirection is load-bearing — if this is ever refactored,
    /// the wait-deadline path in `probefleet-sidecar`'s `CoordSession::lease` loses
    /// its cleanup with it.
    ///
    /// It also closes every relay channel this **connection** had open, which
    /// is the third rule and sits deliberately between the two above: a channel
    /// belongs to one invocation, so it dies with the socket, while the lease
    /// it ran under survives. Nothing else would close it — the node reports
    /// `SessionClosed` only in *reply* to a `KillSession`, so waiting for the
    /// node here would wait forever, and a surviving channel keeps the node's
    /// `probe-rs serve` holding its `ProbeLease`, so the next invocation's
    /// `attach` would be refused with `ProbeInUse`. Keyed on the connection's
    /// handle rather than on the lease ([`ChannelTable::channels_for_sidecar`]),
    /// so a second connection's channels on the same lease are untouched.
    pub async fn drop_sidecar(&self, subject: &Subject, requester: RequesterId) {
        let dropped = {
            let mut sched = self.scheduler.lock().await;
            sched.remove_waiters(requester)
        };
        let handle = self.sidecars.get(requester).await;
        self.sidecars.remove(requester).await;
        let closed = match handle {
            Some(handle) => self.close_sidecar_channels(&handle).await,
            None => 0,
        };
        debug!(
            %subject,
            dropped_waiters = dropped,
            closed_channels = closed,
            "sidecar disconnected"
        );
    }

    /// Close every relay channel routed to one sidecar connection, returning
    /// how many were closed.
    ///
    /// Shared by [`Coordinator::drop_sidecar`] and the `/delegate` route's
    /// teardown, which has no [`RequesterId`] to be found by and hands its own
    /// `out_tx` in directly.
    pub async fn close_sidecar_channels(&self, handle: &SidecarHandle) -> usize {
        let channels = self.channels.channels_for_sidecar(handle).await;
        for channel in &channels {
            let node = match self.channels.get(*channel).await {
                Some(route) => self.nodes.get(&route.node).await,
                None => None,
            };
            relay::close_channel(&self.channels, node.as_ref(), *channel).await;
        }
        channels.len()
    }

    /// Push a promoted grant to the connection that queued for it.
    ///
    /// Returns whether the holder was actually reached. `false` means the
    /// promotion is undeliverable and the lease must not be left standing —
    /// see [`Coordinator::settle_promotion`], which is the only caller.
    ///
    /// Two ways to fail, and both are real:
    ///
    /// * the connection is gone (it disconnected between being queued and being
    ///   promoted, or in the window between a client's wait deadline firing and
    ///   its socket closing), or its writer task has stopped draining;
    /// * the holder's effective ops on the promoted board are empty — its
    ///   access evaporated between queueing and promotion. No token is minted
    ///   in that case, mirroring the identical check in
    ///   [`Coordinator::open_channel`]: a capability token conferring nothing
    ///   is worse than an error, because the holder cannot tell it apart from
    ///   a working one until it tries to use it.
    async fn notify_promotion(
        &self,
        requester: RequesterId,
        granted: &probefleet_core::scheduler::GrantedLease,
    ) -> bool {
        let Some(handle) = self.sidecars.get(requester).await else {
            debug!(
                lease = ?granted.lease,
                board = %granted.board,
                "promoted holder is not connected"
            );
            return false;
        };
        let now = self.now();
        let access = authz::access_of(&self.db, &granted.holder, now).await;
        let ops = {
            let sched = self.scheduler.lock().await;
            match sched.board(&granted.board) {
                Some(board) => access.effective_ops(board, now),
                None => Vec::new(),
            }
        };
        if ops.is_empty() {
            debug!(
                lease = ?granted.lease,
                board = %granted.board,
                "promoted holder may no longer use the board; not minting a token"
            );
            return false;
        }
        let Ok(grant) = self.signer.grant_to_wire(granted, ops) else {
            warn!(lease = ?granted.lease, "failed to mint a promoted lease token");
            return false;
        };
        handle.send(CoordToSidecar::Lease(grant)).await.is_ok()
    }

    /// Persist, audit and deliver a promotion — and, when it cannot be
    /// delivered, release the board again and repeat for the next waiter.
    ///
    /// The whole tail of "a board came free and the scheduler handed it to
    /// somebody", shared by [`Coordinator::tear_down_lease`] and the expiry
    /// sweep so the two cannot drift.
    ///
    /// Each iteration writes the database **before** notifying anyone: the
    /// lease row and the `lease.promote` audit must be right whether or not the
    /// holder is listening. Only then is the push attempted, and its outcome
    /// recorded in the audit detail — a stranded promotion and a live one look
    /// identical in the lease table otherwise.
    ///
    /// An undeliverable promotion is **closed out**, not left standing. Leaving
    /// it would move the very defect this exists to fix ("a board held by
    /// nobody until TTL") out of the queue and into the lease table. The
    /// precedent is `delegate`'s "undo the lease rather than hand back a token
    /// that does nothing".
    ///
    /// # Why a loop and not recursion
    ///
    /// Releasing again may itself promote the next waiter, so this is a cycle:
    /// notify → fail → release → promote → notify. It is written iteratively,
    /// and it terminates for the same reason `delete_node_core`'s loop does:
    /// each round consumes at least one waiter (`promote_one` removes it from
    /// the queue), so it runs at most `queue.len()` times. A defensive bound
    /// with a `warn!` guards against a future change breaking that argument
    /// silently.
    ///
    /// Note what this path deliberately **skips**: it does not tear down relay
    /// channels. A just-promoted lease has never had a channel opened on it —
    /// the holder was never told the lease exists — so
    /// `teardown_lease_channels` would be a no-op. Calling
    /// [`Coordinator::tear_down_lease`] here to "be safe" would re-enter the
    /// cycle above; don't.
    pub(crate) async fn settle_promotion(
        &self,
        promoted: Option<Promotion>,
        detail: Option<&str>,
    ) -> Result<()> {
        /// At most this many undeliverable promotions are chased in one
        /// release. The queue length bounds it in theory; this catches a future
        /// change that breaks that argument.
        const MAX_ROUNDS: usize = 64;

        let mut promoted = promoted;
        for _ in 0..MAX_ROUNDS {
            let Some(promotion) = promoted.take() else {
                return Ok(());
            };
            let granted = promotion.grant;
            let org = granted.board.org.clone();
            self.db
                .scoped(org.clone())
                .record_lease(
                    granted.lease,
                    &granted.board,
                    &granted.holder,
                    self.now_i64(),
                    i64::try_from(granted.expires).unwrap_or(i64::MAX),
                )
                .await?;
            let notified = self.notify_promotion(promotion.requester, &granted).await;
            let notified_detail = match (detail, notified) {
                (Some(d), true) => format!("{d}; holder notified"),
                (Some(d), false) => format!("{d}; holder unreachable"),
                (None, true) => "holder notified".to_owned(),
                (None, false) => "holder unreachable".to_owned(),
            };
            self.audit(
                &org,
                "lease.promote",
                Some(&granted.holder.to_string()),
                Some(&granted.board.node.0),
                Some(&granted.board.name),
                Some(granted.lease),
                Some(&notified_detail),
            )
            .await?;
            if notified {
                return Ok(());
            }

            // Undeliverable: give the board back and try the next waiter.
            let now = self.now();
            let next = {
                let mut sched = self.scheduler.lock().await;
                match sched.release_lease(granted.lease, &granted.holder, now) {
                    Ok(next) => next,
                    // The lease vanished under us (a sweep, a node deletion).
                    // Nothing left to undo, and nothing was promoted here.
                    Err(_) => return Ok(()),
                }
            };
            self.db
                .scoped(org.clone())
                .close_lease(granted.lease, self.now_i64(), "promotion undeliverable")
                .await?;
            self.audit(
                &org,
                "lease.release",
                Some(&granted.holder.to_string()),
                Some(&granted.board.node.0),
                Some(&granted.board.name),
                Some(granted.lease),
                Some("promotion undeliverable"),
            )
            .await?;
            promoted = next;
        }
        warn!("gave up chasing undeliverable promotions after {MAX_ROUNDS} rounds");
        Ok(())
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

/// Project a [`NodeStatus`] onto its wire shape for `ctl nodes`.
///
/// A free function rather than a `From` impl on a foreign type pair's own
/// module: the row is the *database* shape (it carries columns the wire
/// projection need not), and this is the one place the two are joined.
/// `api.rs`'s `NodeView` is the parallel projection for the browser, kept
/// separate on purpose — see [`Coordinator::list_nodes`].
fn node_summary(status: NodeStatus) -> probefleet_proto::admin::NodeSummary {
    probefleet_proto::admin::NodeSummary {
        node: status.row.id,
        name: status.row.name,
        tags: status.row.tags,
        adopt: status.row.adopt,
        owner: status.row.owner_user_id.map(|u| u.to_string()),
        last_seen: status.row.last_seen,
        created_at: status.row.created_at,
        online: status.online,
        boards: status.row.boards,
    }
}

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
    Ambiguous(Vec<NodeId>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::Clock;
    use crate::config::SigningKeySource;
    use crate::subject::testkit;

    /// The name of the fixtures' main org.
    const DEFAULT_ORG_ID: &str = "default";
    use ed25519_dalek::{Verifier, VerifyingKey};
    use probefleet_core::policy::Policy;
    use probefleet_proto::board::PowerKind;
    use probefleet_proto::ids::{NodeId, SubjectKind};
    use probefleet_proto::lease::{Constraint, Priority};
    use probefleet_proto::node_api::BoardPresence;
    use probefleet_proto::token::SignedToken;
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
            ..CoordinatorConfig::default()
        }
    }

    /// Fixture org `name`'s (deterministic) id; `coordinator_with` seeds it.
    fn org(name: &str) -> OrgId {
        testkit::org_id(name)
    }

    fn user(org_name: &str, id: &str) -> Subject {
        Subject::user(testkit::user_id(id), org(org_name))
    }

    /// A board's fleet key, with a **production-shaped** node id.
    ///
    /// `state.rs::node_id_for` namespaces node ids by org, so a real `NodeId`
    /// is `"{org}/{name}"` and a real `BoardRef` therefore has four
    /// slash-separated segments. This helper used to build bare ids
    /// (`"node-a"`), which is exactly why the qualified-name resolution tests
    /// below passed while the parse they exercised could not address a single
    /// production board. A fixture that cannot produce production-shaped data
    /// cannot fail on production-shaped bugs — so it produces it.
    fn board_ref(org_name: &str, node: &str, name: &str) -> BoardRef {
        BoardRef::new(org(org_name), node_id(org_name, node), name)
    }

    /// The org-namespaced node id `state.rs::node_id_for` mints — by calling
    /// it, not by re-spelling its format string.
    fn node_id(org_name: &str, node: &str) -> NodeId {
        crate::state::node_id_for(&org(org_name), node)
    }

    fn board(org_name: &str, id: &str, node: &str) -> Board {
        Board {
            id: board_ref(org_name, node, id),
            node: node_id(org_name, node),
            chip: "nRF52840_xxAA".to_owned(),
            model: None,
            tags: vec!["nrf52".to_owned()],
            exclusive: true,
            power: PowerKind::None,
            state: BoardState::Idle,
            serial_ports: Vec::new(),
        }
    }

    /// A coordinator with one board in the default org and the given
    /// memberships already provisioned.
    async fn coordinator_with(
        clock: Arc<TestClock>,
        boards: &[Board],
        members: &[(&str, &str, FleetRole)],
    ) -> Coordinator {
        let mut sched = Scheduler::new(Policy::default());
        for b in boards {
            sched.upsert_board(b.clone());
        }
        let db = Db::connect_in_memory().await.unwrap();
        for (org_name, id, role) in members {
            testkit::seed_member(&db, org_name, id, *role).await;
            // Boards/leases reference their node row.
            for b in boards {
                if b.id.org == org(org_name) {
                    db.scoped(org(org_name))
                        .ensure_node(&b.node, 1000)
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
            &[board(DEFAULT_ORG_ID, "b1", "node-a")],
            &[
                (DEFAULT_ORG_ID, "alice", FleetRole::Member),
                (DEFAULT_ORG_ID, "bob", FleetRole::Member),
                (DEFAULT_ORG_ID, "op", FleetRole::Admin),
            ],
        )
        .await
    }

    fn lease_req(board: &str) -> LeaseRequest {
        LeaseRequest {
            select: Constraint::Id(BoardName(board.to_owned())),
            duration_secs: 600,
            priority: Priority::Interactive,
        }
    }

    /// Ask for a lease as `subject` and return the grant.
    async fn grant_lease(
        coord: &Coordinator,
        subject: &Subject,
        board: &str,
    ) -> probefleet_proto::lease::LeaseGrant {
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                subject,
                SidecarToCoord::Lease(lease_req(board)),
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::Lease(g) => g,
            other => panic!("expected Lease, got {other:?}"),
        }
    }

    /// The token in `ChannelOpened` must be **exactly** the bytes the node was
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
        use crate::registry::{NodeHandle, NodeMessage};

        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock.clone()).await;
        let (atx, mut arx) = mpsc::channel::<NodeMessage>(16);
        coord
            .nodes()
            .insert(node_id(DEFAULT_ORG_ID, "node-a"), NodeHandle::new(atx))
            .await;

        let alice = user(DEFAULT_ORG_ID, "alice");
        let grant = grant_lease(&coord, &alice, "b1").await;
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);

        // Extend, which rewrites the lease expiry the channel mint reads.
        clock.0.store(1_200, Ordering::SeqCst);
        coord
            .handle_sidecar_message(
                &alice,
                SidecarToCoord::Extend { lease: grant.lease },
                &tx,
                RequesterId::DETACHED,
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
                    kind: probefleet_proto::ChannelKind::Data,
                },
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        let CoordToSidecar::ChannelOpened {
            token: to_sidecar, ..
        } = rx.recv().await.unwrap()
        else {
            panic!("expected ChannelOpened");
        };
        let NodeMessage::Command(probefleet_proto::CoordinatorCommand::OpenSession {
            token: to_agent,
            ..
        }) = arx.recv().await.unwrap()
        else {
            panic!("expected OpenSession");
        };

        assert_eq!(
            to_sidecar, to_agent,
            "the sidecar must get the very bytes the node will check"
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
            .handle_sidecar_message(
                &alice,
                SidecarToCoord::Lease(lease_req("b1")),
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        let grant = match rx.recv().await.unwrap() {
            CoordToSidecar::Lease(g) => g,
            other => panic!("expected Lease, got {other:?}"),
        };
        assert_eq!(grant.board, board_ref(DEFAULT_ORG_ID, "node-a", "b1"));
        assert_eq!(grant.expires, 1000 + 600);

        // The minted token verifies under the node's public key.
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
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::Extended { lease, expires } => {
                assert_eq!(lease, grant.lease);
                // The renewal re-applies the lease's own granted duration
                // (600s here), not the 4h Interactive cap.
                assert_eq!(expires, 1000 + 600);
            }
            other => panic!("expected Extended, got {other:?}"),
        }

        // Release.
        coord
            .handle_sidecar_message(
                &alice,
                SidecarToCoord::Release { lease: grant.lease },
                &tx,
                RequesterId::DETACHED,
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
                RequesterId::DETACHED,
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
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::Queued { position } => assert_eq!(position, 0),
            other => panic!("expected Queued, got {other:?}"),
        }
        assert_eq!(coord.scheduler().lock().await.queued_len(), 1);
    }

    /// A selector matching nothing reaches the wire as its own variant, with
    /// the count of boards the caller *can* see — and queues nothing.
    #[tokio::test]
    async fn a_selector_matching_nothing_is_no_candidate_on_the_wire() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &user(DEFAULT_ORG_ID, "alice"),
                SidecarToCoord::Lease(lease_req("no-such-board")),
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::NoCandidate {
                selector,
                reachable,
            } => {
                assert_eq!(selector, "id=no-such-board");
                assert_eq!(reachable, 1, "alice can reach the org's one board");
            }
            other => panic!("expected NoCandidate, got {other:?}"),
        }
        assert_eq!(coord.scheduler().lock().await.queued_len(), 0);
    }

    /// At the cap, the caller is told so — not that the board is contended —
    /// and nothing is queued.
    #[tokio::test]
    async fn an_at_cap_request_is_at_cap_on_the_wire() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[
                board(DEFAULT_ORG_ID, "b1", "node-a"),
                board(DEFAULT_ORG_ID, "b2", "node-a"),
                board(DEFAULT_ORG_ID, "b3", "node-a"),
            ],
            &[(DEFAULT_ORG_ID, "alice", FleetRole::Member)],
        )
        .await;
        let alice = user(DEFAULT_ORG_ID, "alice");
        // The default cap is 2.
        let cap = Policy::default().max_concurrent_per_subject;
        for i in 1..=cap {
            let _ = grant_lease(&coord, &alice, &format!("b{i}")).await;
        }
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &alice,
                // b3 is idle, so "contended" would have been a lie too.
                SidecarToCoord::Lease(lease_req("b3")),
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::AtCap { held, cap: got } => {
                assert_eq!(held, cap);
                assert_eq!(got, cap);
            }
            other => panic!("expected AtCap, got {other:?}"),
        }
        assert_eq!(coord.scheduler().lock().await.queued_len(), 0);
    }

    /// #452: `ctl delegate` on a contended board reports the slip and leaves
    /// the queue **exactly** as it found it. Asserting on the scheduler's queue
    /// rather than only on the reply is the point — the reply was already
    /// right before the fix.
    #[tokio::test]
    async fn delegate_on_a_contended_board_leaves_no_waiter() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let alice = user(DEFAULT_ORG_ID, "alice");
        let _ = grant_lease(&coord, &alice, "b1").await;

        let before = coord.scheduler().lock().await.queued_len();
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &user(DEFAULT_ORG_ID, "bob"),
                SidecarToCoord::Delegate {
                    select: Constraint::Id(BoardName("b1".to_owned())),
                    duration_secs: 600,
                    ops: vec![probefleet_proto::token::AllowedOp::Flash],
                },
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            CoordToSidecar::Queued { .. }
        ));
        assert_eq!(
            coord.scheduler().lock().await.queued_len(),
            before,
            "delegate must not enqueue: a waiter it leaves behind can be promoted \
             onto a board nobody is holding"
        );
    }

    /// #384: a queued sidecar is *pushed* its grant when the board frees up,
    /// instead of learning about it the next time it happens to ask.
    #[tokio::test]
    async fn a_queued_sidecar_is_pushed_its_grant_on_promotion() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let alice = user(DEFAULT_ORG_ID, "alice");
        let bob = user(DEFAULT_ORG_ID, "bob");
        let grant = grant_lease(&coord, &alice, "b1").await;

        // bob queues on a *registered* connection, so a promotion can reach him.
        let (bob_tx, mut bob_rx) = mpsc::channel::<CoordToSidecar>(16);
        let bob_id = coord.sidecars().mint();
        coord.sidecars().insert(bob_id, bob_tx.clone()).await;
        coord
            .handle_sidecar_message(
                &bob,
                SidecarToCoord::Lease(lease_req("b1")),
                &bob_tx,
                bob_id,
            )
            .await
            .unwrap();
        assert!(matches!(
            bob_rx.recv().await.unwrap(),
            CoordToSidecar::Queued { .. }
        ));

        // alice releases; bob is promoted and told so on his own connection.
        let (tx, _rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &alice,
                SidecarToCoord::Release { lease: grant.lease },
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        match bob_rx.recv().await.unwrap() {
            CoordToSidecar::Lease(g) => {
                assert_eq!(g.board, grant.board);
                assert_ne!(g.lease, grant.lease, "a promotion is a new lease");
            }
            other => panic!("expected a promotion push, got {other:?}"),
        }
        assert_eq!(
            coord
                .db()
                .scoped(org(DEFAULT_ORG_ID))
                .open_lease_count()
                .await
                .unwrap(),
            1,
            "the promoted lease is persisted"
        );
    }

    /// #381: a queued waiter whose sidecar disconnects is gone, and the board
    /// goes to the next waiter rather than to the ghost.
    #[tokio::test]
    async fn a_disconnected_sidecars_waiter_is_dropped_and_the_next_one_wins() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[board(DEFAULT_ORG_ID, "b1", "node-a")],
            &[
                (DEFAULT_ORG_ID, "alice", FleetRole::Member),
                (DEFAULT_ORG_ID, "bob", FleetRole::Member),
                (DEFAULT_ORG_ID, "carol", FleetRole::Member),
            ],
        )
        .await;
        let alice = user(DEFAULT_ORG_ID, "alice");
        let bob = user(DEFAULT_ORG_ID, "bob");
        let carol = user(DEFAULT_ORG_ID, "carol");
        let grant = grant_lease(&coord, &alice, "b1").await;

        // bob queues first, then carol.
        let (bob_tx, _bob_rx) = mpsc::channel::<CoordToSidecar>(16);
        let bob_id = coord.sidecars().mint();
        coord.sidecars().insert(bob_id, bob_tx.clone()).await;
        coord
            .handle_sidecar_message(
                &bob,
                SidecarToCoord::Lease(lease_req("b1")),
                &bob_tx,
                bob_id,
            )
            .await
            .unwrap();

        let (carol_tx, mut carol_rx) = mpsc::channel::<CoordToSidecar>(16);
        let carol_id = coord.sidecars().mint();
        coord.sidecars().insert(carol_id, carol_tx.clone()).await;
        coord
            .handle_sidecar_message(
                &carol,
                SidecarToCoord::Lease(lease_req("b1")),
                &carol_tx,
                carol_id,
            )
            .await
            .unwrap();
        let _ = carol_rx.recv().await.unwrap();
        assert_eq!(coord.scheduler().lock().await.queued_len(), 2);

        // bob's sidecar goes away.
        coord.drop_sidecar(&bob, bob_id).await;
        assert_eq!(coord.scheduler().lock().await.queued_len(), 1);

        // The board goes to carol, who is still there.
        let (tx, _rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &alice,
                SidecarToCoord::Release { lease: grant.lease },
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        match carol_rx.recv().await.unwrap() {
            CoordToSidecar::Lease(g) => assert_eq!(&g.holder, carol.key()),
            other => panic!("expected carol's promotion, got {other:?}"),
        }
    }

    /// The guard on the above not over-reaching: a **held** lease survives its
    /// sidecar disconnecting, and goes away at TTL like any other.
    #[tokio::test]
    async fn a_disconnected_sidecars_held_lease_survives_to_ttl() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let alice = user(DEFAULT_ORG_ID, "alice");
        let grant = grant_lease(&coord, &alice, "b1").await;
        let requester = coord.sidecars().mint();

        coord.drop_sidecar(&alice, requester).await;

        assert_eq!(
            coord.scheduler().lock().await.lease_holder(grant.lease),
            Some(alice.key()),
            "a lease outlives the connection that requested it"
        );
        assert_eq!(
            coord
                .db()
                .scoped(org(DEFAULT_ORG_ID))
                .open_lease_count()
                .await
                .unwrap(),
            1
        );
    }

    /// The D2 regression: two connections, one subject. Closing one must not
    /// cancel the other's queued request — the `ctl list` while `probe-rs run`
    /// waits scenario, which a `SubjectKey`-keyed drop would break.
    #[tokio::test]
    async fn closing_one_connection_leaves_the_same_subjects_other_waiter() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let alice = user(DEFAULT_ORG_ID, "alice");
        let bob = user(DEFAULT_ORG_ID, "bob");
        let _ = grant_lease(&coord, &alice, "b1").await;

        let mut ids = Vec::new();
        for _ in 0..2 {
            let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
            let id = coord.sidecars().mint();
            coord.sidecars().insert(id, tx.clone()).await;
            coord
                .handle_sidecar_message(&bob, SidecarToCoord::Lease(lease_req("b1")), &tx, id)
                .await
                .unwrap();
            let _ = rx.recv().await.unwrap();
            ids.push(id);
        }
        assert_eq!(coord.scheduler().lock().await.queued_len(), 2);

        coord.drop_sidecar(&bob, ids[0]).await;
        assert_eq!(
            coord.scheduler().lock().await.queued_len(),
            1,
            "only the closed connection's waiter goes"
        );
    }

    /// An undeliverable promotion must not leave a board leased to nobody: it
    /// is released again and handed to the next waiter, with both the
    /// `record_lease` and the `close_lease` landing so the lease count returns
    /// to where it started.
    #[tokio::test]
    async fn an_undeliverable_promotion_is_torn_down_and_the_next_waiter_wins() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[board(DEFAULT_ORG_ID, "b1", "node-a")],
            &[
                (DEFAULT_ORG_ID, "alice", FleetRole::Member),
                (DEFAULT_ORG_ID, "bob", FleetRole::Member),
                (DEFAULT_ORG_ID, "carol", FleetRole::Member),
            ],
        )
        .await;
        let alice = user(DEFAULT_ORG_ID, "alice");
        let bob = user(DEFAULT_ORG_ID, "bob");
        let carol = user(DEFAULT_ORG_ID, "carol");
        let grant = grant_lease(&coord, &alice, "b1").await;

        // bob queues on an id that is never registered: he is the ghost whose
        // deadline fired between queueing and promotion.
        let ghost = RequesterId(9_999);
        let (bob_tx, _bob_rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(&bob, SidecarToCoord::Lease(lease_req("b1")), &bob_tx, ghost)
            .await
            .unwrap();

        let (carol_tx, mut carol_rx) = mpsc::channel::<CoordToSidecar>(16);
        let carol_id = coord.sidecars().mint();
        coord.sidecars().insert(carol_id, carol_tx.clone()).await;
        coord
            .handle_sidecar_message(
                &carol,
                SidecarToCoord::Lease(lease_req("b1")),
                &carol_tx,
                carol_id,
            )
            .await
            .unwrap();
        let _ = carol_rx.recv().await.unwrap();

        // alice releases: bob wins the promotion, cannot be reached, and the
        // board is passed to carol in the same call.
        let (tx, _rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &alice,
                SidecarToCoord::Release { lease: grant.lease },
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();

        match carol_rx.recv().await.unwrap() {
            CoordToSidecar::Lease(g) => assert_eq!(&g.holder, carol.key()),
            other => panic!("expected carol's promotion, got {other:?}"),
        }
        assert_eq!(
            coord
                .db()
                .scoped(org(DEFAULT_ORG_ID))
                .open_lease_count()
                .await
                .unwrap(),
            1,
            "bob's stillborn lease was recorded and then closed; only carol's is open"
        );
        assert_eq!(coord.scheduler().lock().await.queued_len(), 0);
    }

    /// The chain terminates: two undeliverable waiters ahead of a live one.
    #[tokio::test]
    async fn a_chain_of_undeliverable_promotions_terminates_on_a_live_one() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[board(DEFAULT_ORG_ID, "b1", "node-a")],
            &[
                (DEFAULT_ORG_ID, "alice", FleetRole::Member),
                (DEFAULT_ORG_ID, "bob", FleetRole::Member),
                (DEFAULT_ORG_ID, "carol", FleetRole::Member),
                (DEFAULT_ORG_ID, "dave", FleetRole::Member),
            ],
        )
        .await;
        let alice = user(DEFAULT_ORG_ID, "alice");
        let grant = grant_lease(&coord, &alice, "b1").await;

        let (ghost_tx, _ghost_rx) = mpsc::channel::<CoordToSidecar>(16);
        for (i, name) in ["bob", "carol"].iter().enumerate() {
            coord
                .handle_sidecar_message(
                    &user(DEFAULT_ORG_ID, name),
                    SidecarToCoord::Lease(lease_req("b1")),
                    &ghost_tx,
                    RequesterId(5_000 + i as u64),
                )
                .await
                .unwrap();
        }
        let dave = user(DEFAULT_ORG_ID, "dave");
        let (dave_tx, mut dave_rx) = mpsc::channel::<CoordToSidecar>(16);
        let dave_id = coord.sidecars().mint();
        coord.sidecars().insert(dave_id, dave_tx.clone()).await;
        coord
            .handle_sidecar_message(
                &dave,
                SidecarToCoord::Lease(lease_req("b1")),
                &dave_tx,
                dave_id,
            )
            .await
            .unwrap();
        let _ = dave_rx.recv().await.unwrap();

        let (tx, _rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &alice,
                SidecarToCoord::Release { lease: grant.lease },
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        match dave_rx.recv().await.unwrap() {
            CoordToSidecar::Lease(g) => assert_eq!(&g.holder, dave.key()),
            other => panic!("expected dave's promotion, got {other:?}"),
        }
        assert_eq!(
            coord
                .db()
                .scoped(org(DEFAULT_ORG_ID))
                .open_lease_count()
                .await
                .unwrap(),
            1
        );
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
                RequesterId::DETACHED,
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
    /// the node was never commanded to open a session.
    #[tokio::test]
    async fn other_subject_cannot_open_channel_and_no_token_is_minted() {
        use crate::registry::{NodeHandle, NodeMessage};

        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let (atx, mut arx) = mpsc::channel::<NodeMessage>(16);
        coord
            .nodes()
            .insert(node_id(DEFAULT_ORG_ID, "node-a"), NodeHandle::new(atx))
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
                    kind: probefleet_proto::ChannelKind::Data,
                },
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::Error { message } => assert_eq!(message, "no such lease"),
            other => panic!("expected Error, got {other:?}"),
        }
        // No OpenSession reached the node => no capability token exists.
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
                    kind: probefleet_proto::ChannelKind::Data,
                },
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            CoordToSidecar::ChannelOpened { .. }
        ));
        assert!(matches!(
            arx.recv().await.unwrap(),
            NodeMessage::Command(probefleet_proto::CoordinatorCommand::OpenSession { .. })
        ));
    }

    /// An org admin may open a channel on a member's lease (§6.5's "or an org
    /// admin"), and the audit line records the override.
    #[tokio::test]
    async fn org_admin_may_open_channel_on_members_lease() {
        use crate::registry::{NodeHandle, NodeMessage};

        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let (atx, mut arx) = mpsc::channel::<NodeMessage>(16);
        coord
            .nodes()
            .insert(node_id(DEFAULT_ORG_ID, "node-a"), NodeHandle::new(atx))
            .await;

        let grant = grant_lease(&coord, &user(DEFAULT_ORG_ID, "alice"), "b1").await;
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &user(DEFAULT_ORG_ID, "op"),
                SidecarToCoord::OpenChannel {
                    lease: grant.lease,
                    kind: probefleet_proto::ChannelKind::Data,
                },
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            CoordToSidecar::ChannelOpened { .. }
        ));
        assert!(matches!(
            arx.recv().await.unwrap(),
            NodeMessage::Command(probefleet_proto::CoordinatorCommand::OpenSession { .. })
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
            coord
                .handle_sidecar_message(&bob, msg, &tx, RequesterId::DETACHED)
                .await
                .unwrap();
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
        assert_eq!(sched.lease_holder(grant.lease), Some(alice.key()));
        let BoardState::Leased { expires, .. } = &sched
            .board(&board_ref(DEFAULT_ORG_ID, "node-a", "b1"))
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
            &[
                ("org-a", "alice", FleetRole::Member),
                ("org-b", "mallory", FleetRole::Admin),
            ],
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
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            // `NoCandidate`, not `Queued`: org-B's subject can reach none of the
            // fleet, so no release will ever satisfy this. The board count it
            // reports is 0 for the same reason — the tenancy fence stated as a
            // number, and it leaks nothing about org-A's hardware.
            CoordToSidecar::NoCandidate { reachable, .. } => assert_eq!(reachable, 0),
            CoordToSidecar::Lease(g) => {
                panic!("cross-org lease granted on {} — tenancy breach", g.board)
            }
            other => panic!("expected NoCandidate, got {other:?}"),
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
                sched
                    .board(&board_ref("org-a", "node-a", "b1"))
                    .unwrap()
                    .state,
                BoardState::Idle
            );
        }
        let grant = grant_lease(&coord, &user("org-a", "alice"), "b1").await;
        assert_eq!(grant.board.org, org("org-a"));
    }

    /// `ctl list` / `ctl who` carry the org path and the holder's username
    /// for display; the keys stay the identities.
    #[tokio::test]
    async fn board_list_and_who_carry_display_names() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[board("org-a", "b1", "node-a")],
            &[("org-a", "alice", FleetRole::Admin)],
        )
        .await;
        let alice = user("org-a", "alice");
        grant_lease(&coord, &alice, "b1").await;
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);

        coord
            .handle_sidecar_message(
                &alice,
                SidecarToCoord::ListBoards,
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::BoardList(boards) => {
                assert_eq!(boards.len(), 1);
                assert_eq!(boards[0].org_name.as_deref(), Some("org-a"));
                assert_eq!(boards[0].holder_display.as_deref(), Some("alice"));
            }
            other => panic!("expected BoardList, got {other:?}"),
        }

        coord
            .handle_sidecar_message(&alice, SidecarToCoord::Who, &tx, RequesterId::DETACHED)
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::LeaseTable(rows) => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].holder_display.as_deref(), Some("alice"));
            }
            other => panic!("expected LeaseTable, got {other:?}"),
        }
    }

    /// Cross-org: a member of another org sees nothing and can do nothing.
    /// (A user who is a member of *both* orgs reaches both: access is the
    /// union of memberships, not the org a request names.)
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
                ("org-a", "alice", FleetRole::Admin),
                ("org-b", "bob", FleetRole::Admin),
            ],
        )
        .await;
        let alice_a = user("org-a", "alice");
        let alice_b = user("org-b", "bob");
        let grant = grant_lease(&coord, &alice_a, "b1").await;
        assert_eq!(grant.board.org, org("org-a"));

        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);

        // `ctl list` shows only org B's board to org B's alice.
        coord
            .handle_sidecar_message(
                &alice_b,
                SidecarToCoord::ListBoards,
                &tx,
                RequesterId::DETACHED,
            )
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
            .handle_sidecar_message(&alice_b, SidecarToCoord::Who, &tx, RequesterId::DETACHED)
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::LeaseTable(rows) => assert!(rows.is_empty()),
            other => panic!("expected LeaseTable, got {other:?}"),
        }
        coord
            .handle_sidecar_message(&alice_a, SidecarToCoord::Who, &tx, RequesterId::DETACHED)
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::LeaseTable(rows) => {
                assert_eq!(rows.len(), 1);
            }
            other => panic!("expected LeaseTable, got {other:?}"),
        }

        // Lease verbs on the other org's lease are indistinguishable from
        // "no such lease".
        for msg in [
            SidecarToCoord::Extend { lease: grant.lease },
            SidecarToCoord::Release { lease: grant.lease },
            SidecarToCoord::OpenChannel {
                lease: grant.lease,
                kind: probefleet_proto::ChannelKind::Data,
            },
        ] {
            coord
                .handle_sidecar_message(&alice_b, msg, &tx, RequesterId::DETACHED)
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
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::LogLines(lines) => assert!(lines.is_empty()),
            other => panic!("expected LogLines, got {other:?}"),
        }
    }

    /// `ctl nodes` renders the org's machines with their tags, adopt policy
    /// and live state — **including a machine that has reported no boards**,
    /// which is the whole reason this listing is not board-shaped.
    #[tokio::test]
    async fn list_nodes_renders_tags_and_includes_a_boardless_node() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator(clock).await;
        let scoped = coord.db().scoped(org(DEFAULT_ORG_ID));

        // A second node that has never reported a probe. `coordinator_with`
        // only ensures node rows for orgs that have boards, so seed it here.
        let empty = node_id(DEFAULT_ORG_ID, "boardless");
        scoped.ensure_node(&empty, 1000).await.unwrap();
        scoped
            .update_node(
                "boardless",
                Some(&["desk".to_owned(), "nrf52".to_owned()]),
                Some(AdoptPolicy::Auto),
            )
            .await
            .unwrap();

        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &user(DEFAULT_ORG_ID, "alice"),
                SidecarToCoord::ListNodes,
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();

        let nodes = match rx.recv().await.unwrap() {
            CoordToSidecar::NodeList(nodes) => nodes,
            other => panic!("expected NodeList, got {other:?}"),
        };
        let boardless = nodes
            .iter()
            .find(|n| n.name == "boardless")
            .expect("a node with no boards must still be listed");
        assert_eq!(boardless.tags, ["desk", "nrf52"]);
        assert_eq!(boardless.adopt, AdoptPolicy::Auto);
        assert!(boardless.boards.is_empty());
        // Never connected: the registry has no session for it.
        assert!(!boardless.online);

        let with_board = nodes
            .iter()
            .find(|n| n.name == "node-a")
            .expect("the board-carrying node is listed too");
        assert_eq!(with_board.node, node_id(DEFAULT_ORG_ID, "node-a"));
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
                RequesterId::DETACHED,
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
                RequesterId::DETACHED,
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
            Subject::new(SubjectKey::parse("gha/workload:o/ci").unwrap(), None),
            Subject::node(org(DEFAULT_ORG_ID), &node_id(DEFAULT_ORG_ID, "rpi-1")).unwrap(),
        ];
        for s in strangers {
            for msg in [
                SidecarToCoord::ListBoards,
                SidecarToCoord::ListNodes,
                SidecarToCoord::Who,
                SidecarToCoord::Lease(lease_req("b1")),
                SidecarToCoord::PowerCycle {
                    board: BoardName("b1".to_owned()),
                },
            ] {
                coord
                    .handle_sidecar_message(&s, msg, &tx, RequesterId::DETACHED)
                    .await
                    .unwrap();
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
        assert_eq!(key.kind(), SubjectKind::Workload);

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
        assert_eq!(key.kind(), SubjectKind::Workload);
        // A username resolves to the user's immutable id; an unknown one to
        // nothing rather than a guess.
        let key = coord.resolve_grantee("alice").await.unwrap().unwrap();
        assert_eq!(key, *user(DEFAULT_ORG_ID, "alice").key());
        assert!(coord
            .resolve_grantee("nobody-here")
            .await
            .unwrap()
            .is_none());
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
            &[("org-a", "alice", FleetRole::Member)],
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
                RequesterId::DETACHED,
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
        use crate::registry::{NodeHandle, NodeMessage};

        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[board("org-a", "b1", "node-a")],
            &[
                ("org-a", "alice", FleetRole::Member),
                ("org-b", "bob", FleetRole::Admin),
            ],
        )
        .await;
        let (atx, mut arx) = mpsc::channel::<NodeMessage>(16);
        coord
            .nodes()
            .insert(node_id("org-a", "node-a"), NodeHandle::new(atx))
            .await;

        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &user("org-b", "bob"),
                SidecarToCoord::PowerCycle {
                    board: BoardName("b1".to_owned()),
                },
                &tx,
                RequesterId::DETACHED,
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
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            CoordToSidecar::PowerCycled { .. }
        ));
        assert!(matches!(
            arx.recv().await.unwrap(),
            NodeMessage::Command(probefleet_proto::CoordinatorCommand::PowerCycle { .. })
        ));
    }

    /// Inventory reconciliation: a registered node's online board enters the
    /// scheduler (becomes leasable + appears in `list`), an offline board is
    /// dropped, and the board row is **actually persisted** — asserting on the
    /// warn-swallowed persistence path is exactly where a foreign-key bug would
    /// otherwise hide.
    #[tokio::test]
    async fn inventory_populates_scheduler_db_and_list() {
        use probefleet_proto::node_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        // Fresh coordinator with NO pre-seeded boards.
        let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", FleetRole::Admin)]).await;
        let node_id = node_id(DEFAULT_ORG_ID, "node-a");
        // The node row is what resolves the report's org: there is no default-org
        // fallback any more (see `org_and_policy_of_node`).
        coord
            .db()
            .scoped(org(DEFAULT_ORG_ID))
            .ensure_node(&node_id, 1000)
            .await
            .unwrap();

        let inv = ProbeInventory {
            boards: vec![
                status(
                    "online-1",
                    "S-ON",
                    BoardPresence::Online,
                    "nRF52840_xxAA",
                    false,
                ),
                status(
                    "offline-1",
                    "S-OFF",
                    BoardPresence::Offline,
                    "STM32F4",
                    false,
                ),
            ],
            unknown: vec![],
        };
        coord
            .handle_node_report(&node_id, NodeReport::Inventory(inv))
            .await
            .unwrap();

        // The online board is in the scheduler, owned by the node and keyed
        // into the default org; the offline one is not.
        {
            let sched = coord.scheduler().lock().await;
            let key = board_ref(DEFAULT_ORG_ID, "node-a", "online-1");
            let board = sched.board(&key).unwrap();
            assert_eq!(board.node, node_id);
            assert_eq!(board.chip, "nRF52840_xxAA");
            assert!(sched
                .board(&board_ref(DEFAULT_ORG_ID, "node-a", "offline-1"))
                .is_none());
        }

        // …and it reached the database, node row and all.
        let scoped = coord.db().scoped(org(DEFAULT_ORG_ID));
        assert!(
            scoped
                .has_board(&board_ref(DEFAULT_ORG_ID, "node-a", "online-1"))
                .await
                .unwrap(),
            "the board row must be persisted, not silently dropped by a FK failure"
        );
        assert_eq!(
            coord.db().org_of_node(&node_id).await.unwrap(),
            Some(org(DEFAULT_ORG_ID))
        );

        // `ctl list` (ListBoards) returns the online board as available.
        let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(16);
        coord
            .handle_sidecar_message(
                &user(DEFAULT_ORG_ID, "op"),
                SidecarToCoord::ListBoards,
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        match rx.recv().await.unwrap() {
            CoordToSidecar::BoardList(boards) => {
                assert_eq!(boards.len(), 1);
                assert_eq!(
                    boards[0].board,
                    board_ref(DEFAULT_ORG_ID, "node-a", "online-1")
                );
                assert_eq!(
                    boards[0].availability,
                    probefleet_proto::admin::BoardAvailability::Available
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
    ) -> probefleet_proto::BoardStatus {
        probefleet_proto::BoardStatus {
            board: BoardName(name.to_owned()),
            serial: serial.to_owned(),
            presence,
            chip: chip.to_owned(),
            model: None,
            tags: vec![],
            exclusive: true,
            power: PowerKind::None,
            adopted,
            serial_ports: Vec::new(),
        }
    }

    /// The direct regression test for the deleted `default_org` fallback.
    ///
    /// A node with no row used to have its inventory silently filed under
    /// `config.default_org` — harmless with one org, a cross-tenant board
    /// injection the moment there are two. The report must now be dropped.
    #[tokio::test]
    async fn a_report_from_a_node_with_no_row_is_dropped_not_defaulted() {
        use probefleet_proto::node_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", FleetRole::Admin)]).await;
        // Deliberately NOT calling `ensure_node`: this node is unknown. Its
        // id is still production-shaped — the report being dropped must be
        // because no row exists, not because the id could not name one.
        let ghost = node_id(DEFAULT_ORG_ID, "ghost");

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
            .handle_node_report(&ghost, NodeReport::Inventory(inv))
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
        use probefleet_proto::node_api::ProbeInventory;
        for (policy, expect_scheduled) in
            [(AdoptPolicy::Auto, true), (AdoptPolicy::Declared, false)]
        {
            let clock = Arc::new(TestClock(AtomicU64::new(1000)));
            let coord =
                coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", FleetRole::Admin)]).await;
            let node = node_id(DEFAULT_ORG_ID, "laptop");
            coord
                .db()
                .register_node_full(
                    &org(DEFAULT_ORG_ID),
                    "laptop",
                    "hash",
                    &[],
                    Some(testkit::user_id("op")),
                    policy,
                    1000,
                )
                .await
                .unwrap();

            let inv = ProbeInventory {
                boards: vec![status("j-link-abc", "ABC", BoardPresence::Online, "", true)],
                unknown: vec![],
            };
            coord
                .handle_node_report(&node, NodeReport::Inventory(inv))
                .await
                .unwrap();

            let scheduled = coord
                .scheduler()
                .lock()
                .await
                .board(&BoardRef::new(
                    org(DEFAULT_ORG_ID),
                    node.clone(),
                    "j-link-abc",
                ))
                .is_some();
            assert_eq!(
                scheduled,
                expect_scheduled,
                "policy {policy} should {}have scheduled the adopted board",
                if expect_scheduled { "" } else { "not " }
            );
        }
    }

    /// **The phantom-board regression.** An adopted board whose probe was
    /// unplugged arrives as an `Offline` status, and the coordinator must drop
    /// it from the scheduler.
    ///
    /// Note which code path delivers that today. `reconcile_inventory` excludes
    /// an `adopted && Offline` status from the keep-set — it is a tombstone,
    /// not a declared-but-unplugged board — so the removal happens in the
    /// **stale-board prune**, not in the offline branch this test was written
    /// against. The assertion is unchanged and still load-bearing; only the
    /// mechanism moved. `an_unplugged_adopted_board_leaves_the_db_too` pins the
    /// other half, which the prune added: the row goes as well.
    ///
    /// Historically this was the *only* thing that retired such a board:
    /// nothing pruned a board a report failed to mention, so without the
    /// node's tombstone it stayed `Idle` forever, `ctl list` showed it, and a
    /// lease against it was *granted* and then failed at the node with
    /// `UnknownBoard`. The set difference now catches that case too, but the
    /// tombstone still carries the meaning — see `adopt_unknown`'s doc comment.
    /// On a laptop, where probes are unplugged daily, this is the common case.
    #[tokio::test]
    async fn an_unplugged_adopted_board_leaves_the_scheduler() {
        use probefleet_proto::node_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", FleetRole::Admin)]).await;
        coord
            .db()
            .register_node_full(
                &org(DEFAULT_ORG_ID),
                "laptop",
                "hash",
                &[],
                Some(testkit::user_id("op")),
                AdoptPolicy::Auto,
                1000,
            )
            .await
            .unwrap();
        let node = node_id(DEFAULT_ORG_ID, "laptop");
        let key = BoardRef::new(org(DEFAULT_ORG_ID), node.clone(), "j-link-zzz");

        // Plugged in.
        coord
            .handle_node_report(
                &node,
                NodeReport::Inventory(ProbeInventory {
                    boards: vec![status("j-link-zzz", "ZZZ", BoardPresence::Online, "", true)],
                    unknown: vec![],
                }),
            )
            .await
            .unwrap();
        assert!(coord.scheduler().lock().await.board(&key).is_some());

        // Unplugged: the node tombstones it.
        coord
            .handle_node_report(
                &node,
                NodeReport::Inventory(ProbeInventory {
                    boards: vec![status(
                        "j-link-zzz",
                        "ZZZ",
                        BoardPresence::Offline,
                        "",
                        true,
                    )],
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

    /// The regression test for this whole change: a **renamed** board leaves
    /// nothing behind in either store.
    ///
    /// A rename produces no tombstone — the node reports only what is still in
    /// `boards.toml`, so `b1` simply stops appearing. Before the set-difference
    /// pass it survived in the scheduler (a leasable phantom: `ctl list` showed
    /// it, a lease was granted and tokenised, and the node refused it at the
    /// last hop with `UnknownBoard`) *and* in the `board` table, which is what
    /// made the Nodes page count two boards for a node that has one.
    ///
    /// Both assertions matter. Without the scheduler half the phantom lease
    /// comes back; without the DB half the page count does.
    #[tokio::test]
    async fn a_renamed_board_leaves_no_stale_row() {
        use probefleet_proto::node_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", FleetRole::Admin)]).await;
        let node = node_id(DEFAULT_ORG_ID, "node-a");
        coord
            .db()
            .scoped(org(DEFAULT_ORG_ID))
            .ensure_node(&node, 1000)
            .await
            .unwrap();

        for name in ["b1", "b2"] {
            coord
                .handle_node_report(
                    &node,
                    NodeReport::Inventory(ProbeInventory {
                        boards: vec![status(name, "S1", BoardPresence::Online, "chip", false)],
                        unknown: vec![],
                    }),
                )
                .await
                .unwrap();
        }

        let sched_names: Vec<String> = coord
            .scheduler()
            .lock()
            .await
            .boards()
            .map(|b| b.id.name.clone())
            .collect();
        assert_eq!(
            sched_names,
            vec!["b2".to_owned()],
            "the old name must not stay leasable"
        );

        let nodes = coord
            .db()
            .scoped(org(DEFAULT_ORG_ID))
            .list_nodes()
            .await
            .unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(
            nodes[0].boards,
            vec!["b2".to_owned()],
            "the renamed-away row must be pruned, or Nodes disagrees with Devices"
        );
    }

    /// A **declared** board reported `Offline` is unplugged, not undeclared: the
    /// row stays (Nodes keeps showing it) while the scheduler drops it (it
    /// cannot be leased). Re-reporting must not churn the row — the node
    /// re-reports every `discovery_secs`.
    #[tokio::test]
    async fn an_offline_board_is_retained_in_the_db_but_not_in_the_scheduler() {
        use probefleet_proto::node_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", FleetRole::Admin)]).await;
        let node = node_id(DEFAULT_ORG_ID, "node-a");
        let key = board_ref(DEFAULT_ORG_ID, "node-a", "b1");
        coord
            .db()
            .scoped(org(DEFAULT_ORG_ID))
            .ensure_node(&node, 1000)
            .await
            .unwrap();

        for _ in 0..3 {
            coord
                .handle_node_report(
                    &node,
                    NodeReport::Inventory(ProbeInventory {
                        boards: vec![status("b1", "S1", BoardPresence::Offline, "chip", false)],
                        unknown: vec![],
                    }),
                )
                .await
                .unwrap();
            assert!(
                coord
                    .db()
                    .scoped(org(DEFAULT_ORG_ID))
                    .has_board(&key)
                    .await
                    .unwrap(),
                "a declared board must not vanish from the UI while its probe is unplugged"
            );
            assert!(
                coord.scheduler().lock().await.board(&key).is_none(),
                "…but it is not leasable either"
            );
        }
    }

    /// The DB half of `an_unplugged_adopted_board_leaves_the_scheduler`.
    ///
    /// An adopted board reported `Offline` is a *tombstone* synthesised from
    /// `previously_adopted`, not a declaration — so unlike a declared offline
    /// board it must lose its row too. A laptop with `adopt = "auto"` is where
    /// probes get unplugged several times a day; retaining these rows would
    /// inflate the Nodes count for the most common case, which is the very
    /// symptom this change exists to fix.
    #[tokio::test]
    async fn an_unplugged_adopted_board_leaves_the_db_too() {
        use probefleet_proto::node_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", FleetRole::Admin)]).await;
        coord
            .db()
            .register_node_full(
                &org(DEFAULT_ORG_ID),
                "laptop",
                "hash",
                &[],
                Some(testkit::user_id("op")),
                AdoptPolicy::Auto,
                1000,
            )
            .await
            .unwrap();
        let node = node_id(DEFAULT_ORG_ID, "laptop");
        let key = BoardRef::new(org(DEFAULT_ORG_ID), node.clone(), "j-link-zzz");
        let scoped = coord.db().scoped(org(DEFAULT_ORG_ID));

        coord
            .handle_node_report(
                &node,
                NodeReport::Inventory(ProbeInventory {
                    boards: vec![status("j-link-zzz", "ZZZ", BoardPresence::Online, "", true)],
                    unknown: vec![],
                }),
            )
            .await
            .unwrap();
        assert!(scoped.has_board(&key).await.unwrap());

        coord
            .handle_node_report(
                &node,
                NodeReport::Inventory(ProbeInventory {
                    boards: vec![status(
                        "j-link-zzz",
                        "ZZZ",
                        BoardPresence::Offline,
                        "",
                        true,
                    )],
                    unknown: vec![],
                }),
            )
            .await
            .unwrap();
        assert!(
            !scoped.has_board(&key).await.unwrap(),
            "an adopted tombstone must clear the row, not just the scheduler entry"
        );
        assert!(coord.scheduler().lock().await.board(&key).is_none());
    }

    /// A `declared` node's adopted board is refused by policy — and refusing it
    /// means leaving no row behind, including one written while the node's
    /// policy was still `auto`.
    #[tokio::test]
    async fn a_policy_violating_adopted_board_gets_no_row() {
        use probefleet_proto::node_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", FleetRole::Admin)]).await;
        let o = org(DEFAULT_ORG_ID);
        coord
            .db()
            .register_node_full(
                &o,
                "laptop",
                "hash",
                &[],
                Some(testkit::user_id("op")),
                AdoptPolicy::Auto,
                1000,
            )
            .await
            .unwrap();
        let node = node_id(DEFAULT_ORG_ID, "laptop");
        let key = BoardRef::new(o.clone(), node.clone(), "j-link-zzz");
        let inv = || ProbeInventory {
            boards: vec![status("j-link-zzz", "ZZZ", BoardPresence::Online, "", true)],
            unknown: vec![],
        };

        // While `auto`, the adopted board is admitted and gets a row.
        coord
            .handle_node_report(&node, NodeReport::Inventory(inv()))
            .await
            .unwrap();
        assert!(coord.db().scoped(o.clone()).has_board(&key).await.unwrap());

        // The owner tightens the policy; the next report must retire the row.
        coord
            .db()
            .register_node_full(
                &o,
                "laptop",
                "hash",
                &[],
                Some(testkit::user_id("op")),
                AdoptPolicy::Declared,
                1001,
            )
            .await
            .unwrap();
        coord
            .handle_node_report(&node, NodeReport::Inventory(inv()))
            .await
            .unwrap();
        assert!(
            !coord.db().scoped(o).has_board(&key).await.unwrap(),
            "a board the coordinator refuses to know about must not keep a row"
        );
        assert!(coord.scheduler().lock().await.board(&key).is_none());
    }

    /// A live lease pins the board in **both** stores even when the report stops
    /// declaring it: dropping the scheduler entry would strand an open lease
    /// nothing can release, and dropping the row would make Nodes contradict a
    /// lease that is in active use.
    #[tokio::test]
    async fn a_leased_board_that_vanishes_from_a_report_is_not_deleted() {
        use probefleet_proto::node_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord =
            coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "alice", FleetRole::Member)]).await;
        let node = node_id(DEFAULT_ORG_ID, "node-a");
        let key = board_ref(DEFAULT_ORG_ID, "node-a", "b1");
        coord
            .db()
            .scoped(org(DEFAULT_ORG_ID))
            .ensure_node(&node, 1000)
            .await
            .unwrap();
        coord
            .handle_node_report(
                &node,
                NodeReport::Inventory(ProbeInventory {
                    boards: vec![status("b1", "S1", BoardPresence::Online, "chip", false)],
                    unknown: vec![],
                }),
            )
            .await
            .unwrap();
        grant_lease(&coord, &user(DEFAULT_ORG_ID, "alice"), "b1").await;

        // A rename while the lease is live.
        coord
            .handle_node_report(
                &node,
                NodeReport::Inventory(ProbeInventory {
                    boards: vec![status("b2", "S1", BoardPresence::Online, "chip", false)],
                    unknown: vec![],
                }),
            )
            .await
            .unwrap();

        assert!(
            matches!(
                coord.scheduler().lock().await.board(&key).map(|b| &b.state),
                Some(BoardState::Leased { .. })
            ),
            "a live lease pins the board"
        );
        assert!(
            coord
                .db()
                .scoped(org(DEFAULT_ORG_ID))
                .has_board(&key)
                .await
                .unwrap(),
            "the DB delete guard must match the scheduler's"
        );
    }

    /// An **empty** inventory is a real statement — "I declare nothing" — so it
    /// clears that node's rows and scheduler entries. Deliberately, and only
    /// that node's: a sibling node in the same org, and another tenant
    /// entirely, are untouched.
    #[tokio::test]
    async fn an_empty_inventory_clears_only_that_nodes_rows() {
        use probefleet_proto::node_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[],
            &[
                (DEFAULT_ORG_ID, "op", FleetRole::Admin),
                ("other", "op", FleetRole::Admin),
            ],
        )
        .await;
        let nodes = [
            (org(DEFAULT_ORG_ID), node_id(DEFAULT_ORG_ID, "node-a")),
            (org(DEFAULT_ORG_ID), node_id(DEFAULT_ORG_ID, "node-b")),
            (org("other"), node_id("other", "node-c")),
        ];
        for (o, node) in &nodes {
            coord
                .db()
                .scoped(o.clone())
                .ensure_node(node, 1000)
                .await
                .unwrap();
            coord
                .handle_node_report(
                    node,
                    NodeReport::Inventory(ProbeInventory {
                        boards: vec![status("b1", "S1", BoardPresence::Online, "chip", false)],
                        unknown: vec![],
                    }),
                )
                .await
                .unwrap();
        }
        assert_eq!(
            coord
                .db()
                .scoped(org(DEFAULT_ORG_ID))
                .board_count()
                .await
                .unwrap(),
            2
        );

        // Node A's `boards.toml` was emptied.
        coord
            .handle_node_report(
                &nodes[0].1,
                NodeReport::Inventory(ProbeInventory {
                    boards: vec![],
                    unknown: vec![],
                }),
            )
            .await
            .unwrap();

        assert!(!coord
            .db()
            .scoped(org(DEFAULT_ORG_ID))
            .has_board(&board_ref(DEFAULT_ORG_ID, "node-a", "b1"))
            .await
            .unwrap());
        assert!(coord
            .db()
            .scoped(org(DEFAULT_ORG_ID))
            .has_board(&board_ref(DEFAULT_ORG_ID, "node-b", "b1"))
            .await
            .unwrap());
        assert_eq!(
            coord
                .db()
                .scoped(org(DEFAULT_ORG_ID))
                .board_count()
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            coord.db().scoped(org("other")).board_count().await.unwrap(),
            1
        );

        let sched = coord.scheduler().lock().await;
        assert!(sched
            .board(&board_ref(DEFAULT_ORG_ID, "node-a", "b1"))
            .is_none());
        assert!(sched
            .board(&board_ref(DEFAULT_ORG_ID, "node-b", "b1"))
            .is_some());
        assert!(sched.board(&board_ref("other", "node-c", "b1")).is_some());
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
        use probefleet_proto::node_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", FleetRole::Admin)]).await;
        let o = org(DEFAULT_ORG_ID);
        coord
            .db()
            .register_node_full(
                &o,
                "laptop",
                "hash",
                &[],
                Some(testkit::user_id("op")),
                AdoptPolicy::Auto,
                1000,
            )
            .await
            .unwrap();
        let node = node_id(DEFAULT_ORG_ID, "laptop");
        let key = BoardRef::new(org(DEFAULT_ORG_ID), node.clone(), "j-link-zzz");

        coord
            .handle_node_report(
                &node,
                NodeReport::Inventory(ProbeInventory {
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
                Some(testkit::user_id("op")),
                AdoptPolicy::Declared,
                1001,
            )
            .await
            .unwrap();

        coord
            .handle_node_report(
                &node,
                NodeReport::Inventory(ProbeInventory {
                    boards: vec![status(
                        "j-link-zzz",
                        "ZZZ",
                        BoardPresence::Offline,
                        "",
                        true,
                    )],
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
        use probefleet_proto::node_api::ProbeInventory;
        for policy in [AdoptPolicy::Auto, AdoptPolicy::Declared] {
            let clock = Arc::new(TestClock(AtomicU64::new(1000)));
            let coord =
                coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", FleetRole::Admin)]).await;
            coord
                .db()
                .register_node_full(&org(DEFAULT_ORG_ID), "pi", "hash", &[], None, policy, 1000)
                .await
                .unwrap();
            let node = node_id(DEFAULT_ORG_ID, "pi");

            let inv = ProbeInventory {
                boards: vec![status("b1", "S1", BoardPresence::Online, "chip", false)],
                unknown: vec![],
            };
            coord
                .handle_node_report(&node, NodeReport::Inventory(inv))
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
        use probefleet_proto::node_api::ProbeInventory;
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(clock, &[], &[(DEFAULT_ORG_ID, "op", FleetRole::Admin)]).await;
        coord
            .db()
            .register_node_full(
                &org(DEFAULT_ORG_ID),
                "laptop",
                "hash",
                &[],
                Some(testkit::user_id("op")),
                AdoptPolicy::Auto,
                1000,
            )
            .await
            .unwrap();
        let node = node_id(DEFAULT_ORG_ID, "laptop");

        for _ in 0..3 {
            coord
                .handle_node_report(
                    &node,
                    NodeReport::Inventory(ProbeInventory {
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
            member_of: vec![org(own_org)],
            grants: vec![probefleet_core::access::GrantScope {
                id: "g1".to_owned(),
                org: org(granted_org),
                selector: Constraint::Tags(vec!["nrf52".to_owned()]),
                ops: vec![probefleet_proto::token::AllowedOp::Attach],
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
            &[
                board("org-b", "dk", "node-b"),
                board("org-a", "dk", "node-a"),
            ],
            &[
                ("org-a", "alice", FleetRole::Member),
                ("org-b", "bob", FleetRole::Member),
            ],
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
            &[
                board("org-b", "dk", "node-b"),
                board("org-a", "dk", "node-a"),
            ],
            &[
                ("org-a", "alice", FleetRole::Member),
                ("org-b", "bob", FleetRole::Member),
            ],
        )
        .await;
        let access = shared_access("org-b", "org-a");

        // Every qualified spelling, against a production-shaped node id
        // (`org-a/node-a`) — including the BoardRef's own Display, which is
        // what a user copies out of `ctl list`.
        let full_node = format!("{}/dk", node_id("org-a", "node-a").0);
        let display = board_ref("org-a", "node-a", "dk").to_string();
        for spelling in ["node-a/dk", "org-a/node-a/dk", &full_node, &display] {
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
            &[
                ("org-a", "alice", FleetRole::Member),
                ("org-b", "bob", FleetRole::Member),
            ],
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
            &[("org-b", "bob", FleetRole::Member)],
        )
        .await;
        assert_eq!(
            coord
                .resolve_board(
                    &Access::own_org(org("org-b")),
                    &BoardName("dk".to_owned()),
                    1000
                )
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
    /// Note the waiter is refreshed, not dropped — `probefleet-core` pins the
    /// difference (a request for the grantee's *own* org must survive); this
    /// asserts the coordinator actually pushes the new access in.
    #[tokio::test]
    async fn revocation_refreshes_the_grantees_queued_requests() {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let coord = coordinator_with(
            clock,
            &[board("org-a", "dk", "node-a")],
            &[
                ("org-a", "alice", FleetRole::Admin),
                ("org-b", "bob", FleetRole::Member),
            ],
        )
        .await;
        let alice = user("org-a", "alice");
        let bob = user("org-b", "bob");

        // Alice holds the board; bob queues behind her by grant.
        let _ = grant_lease(&coord, &alice, "dk").await;
        let id = coord
            .db()
            .forgs()
            .scoped(crate::subject::ns_of(&org("org-a")).unwrap())
            .insert_grant(
                &forgs_store::NewGrant {
                    subject: bob.forgs_key().unwrap(),
                    selector: "tag=nrf52".to_owned(),
                    ops: crate::state::join_ops(&[probefleet_proto::token::AllowedOp::Attach]),
                    expires: None,
                    created_by: Some(testkit::user_id("alice")),
                },
                1000,
            )
            .await
            .unwrap()
            .to_string();

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
                RequesterId::DETACHED,
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
                SidecarToCoord::GrantRevoke {
                    id: id[..8].to_owned(),
                },
                &tx,
                RequesterId::DETACHED,
            )
            .await
            .unwrap();
        assert!(matches!(
            rx.recv().await.unwrap(),
            CoordToSidecar::GrantRevoked { .. }
        ));

        let promoted = {
            let mut sched = coord.scheduler().lock().await;
            let held = sched.leases_held_by(alice.key());
            sched
                .release_lease(held[0].0, alice.key(), 2000)
                .expect("holder may release")
        };
        assert!(
            promoted.is_none(),
            "a revoked grantee must not be promoted onto the board it lost"
        );
    }

    // -- node move ---------------------------------------------------------

    /// org-a hosts `node-a` with boards `dk-1`/`dk-2` (scheduled and
    /// recorded). alice: admin of org-a, member of org-b. bob: member of
    /// org-a. carol: admin of org-a only. org-c exists with no alice.
    async fn move_fixture() -> Coordinator {
        let clock = Arc::new(TestClock(AtomicU64::new(1000)));
        let boards = [
            board("org-a", "dk-1", "node-a"),
            board("org-a", "dk-2", "node-a"),
        ];
        let coord = coordinator_with(
            clock,
            &boards,
            &[
                ("org-a", "alice", FleetRole::Admin),
                ("org-b", "alice", FleetRole::Member),
                ("org-a", "bob", FleetRole::Member),
                ("org-a", "carol", FleetRole::Admin),
                ("org-c", "carol", FleetRole::Member),
            ],
        )
        .await;
        for b in &boards {
            coord
                .db()
                .scoped(org("org-a"))
                .record_board(b, BoardPresence::Online, 1000)
                .await
                .unwrap();
        }
        coord
    }

    async fn audit_actions(coord: &Coordinator, org_name: &str) -> Vec<String> {
        coord
            .db()
            .scoped(org(org_name))
            .recent_audit(None, 100)
            .await
            .unwrap()
            .into_iter()
            .map(|l| l.action)
            .collect()
    }

    async fn add_grant(
        coord: &Coordinator,
        org_name: &str,
        grantee: &Subject,
        selector: &str,
    ) -> String {
        coord
            .db()
            .forgs()
            .scoped(crate::subject::ns_of(&org(org_name)).unwrap())
            .insert_grant(
                &forgs_store::NewGrant {
                    subject: grantee.forgs_key().unwrap(),
                    selector: selector.to_owned(),
                    ops: crate::state::join_ops(&[probefleet_proto::token::AllowedOp::Attach]),
                    expires: None,
                    created_by: None,
                },
                1000,
            )
            .await
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn moving_a_node_rekeys_it_and_its_boards() {
        let coord = move_fixture().await;
        let alice = user("org-a", "alice");
        let outsider = user("org-c", "carol");
        let lost = add_grant(&coord, "org-a", &outsider, "tag=nrf52").await;
        let _unrelated = add_grant(&coord, "org-a", &outsider, "chip=other").await;
        let gained = add_grant(&coord, "org-b", &outsider, "id=dk-1").await;

        let out = coord
            .move_node_core(&alice, "node-a", "org-b", false)
            .await
            .unwrap();
        assert_eq!(out.from, org("org-a"));
        assert_eq!(out.to, org("org-b"));
        assert_eq!(out.old_id, node_id("org-a", "node-a"));
        assert_eq!(out.node.row.id, node_id("org-b", "node-a"));
        assert_eq!(out.node.row.boards, ["dk-1", "dk-2"]);
        assert_eq!(out.revoked_leases, 0);
        let ids = |g: &[probefleet_proto::GrantSummary]| {
            g.iter().map(|g| g.id.clone()).collect::<Vec<_>>()
        };
        assert_eq!(ids(&out.grants_lost), [lost]);
        assert_eq!(ids(&out.grants_gained), [gained]);

        assert!(coord
            .db()
            .scoped(org("org-a"))
            .list_nodes()
            .await
            .unwrap()
            .is_empty());
        let in_b = coord.db().scoped(org("org-b")).list_nodes().await.unwrap();
        assert_eq!(in_b.len(), 1);
        assert_eq!(in_b[0].boards, ["dk-1", "dk-2"]);
        // The old keys left the scheduler; the agent's re-report re-adds them.
        assert!(coord.scheduler.lock().await.boards().next().is_none());
        assert!(audit_actions(&coord, "org-a")
            .await
            .contains(&"node.move.out".to_owned()));
        assert!(audit_actions(&coord, "org-b")
            .await
            .contains(&"node.move.in".to_owned()));
    }

    #[tokio::test]
    async fn a_non_admin_of_the_source_may_not_move_a_node() {
        let coord = move_fixture().await;
        let bob = user("org-a", "bob");
        assert!(matches!(
            coord.move_node_core(&bob, "node-a", "org-b", false).await,
            Err(NodeMoveError::Denied)
        ));
        assert!(audit_actions(&coord, "org-a")
            .await
            .contains(&"node.move.denied".to_owned()));
        assert_eq!(
            coord
                .db()
                .scoped(org("org-a"))
                .list_nodes()
                .await
                .unwrap()
                .len(),
            1
        );
        // A non-member of the source is denied too.
        let stranger = user("org-b", "alice");
        let stranger = Subject::user(stranger.user_id().unwrap(), org("org-c"));
        assert!(matches!(
            coord
                .move_node_core(&stranger, "node-a", "org-b", false)
                .await,
            Err(NodeMoveError::Denied)
        ));
    }

    #[tokio::test]
    async fn a_target_the_caller_is_not_in_looks_like_no_target() {
        let coord = move_fixture().await;
        let alice = user("org-a", "alice");
        assert!(matches!(
            coord.move_node_core(&alice, "node-a", "org-c", false).await,
            Err(NodeMoveError::Denied)
        ));
        assert!(matches!(
            coord
                .move_node_core(&alice, "node-a", "no-such-org", false)
                .await,
            Err(NodeMoveError::Denied)
        ));
        assert!(matches!(
            coord.move_node_core(&alice, "node-a", "org-a", false).await,
            Err(NodeMoveError::SameOrg)
        ));
        assert!(matches!(
            coord.move_node_core(&alice, "ghost", "org-b", false).await,
            Err(NodeMoveError::NotFound)
        ));
        // Nothing moved, nothing drained.
        assert_eq!(coord.scheduler.lock().await.boards().count(), 2);
    }

    #[tokio::test]
    async fn a_name_taken_in_the_target_is_refused() {
        let coord = move_fixture().await;
        coord
            .db()
            .scoped(org("org-b"))
            .ensure_node(&node_id("org-b", "node-a"), 1000)
            .await
            .unwrap();
        let alice = user("org-a", "alice");
        assert!(matches!(
            coord.move_node_core(&alice, "node-a", "org-b", false).await,
            Err(NodeMoveError::NameTaken)
        ));
        assert_eq!(coord.scheduler.lock().await.boards().count(), 2);
    }

    #[tokio::test]
    async fn a_leased_node_moves_only_with_force() {
        let coord = move_fixture().await;
        let alice = user("org-a", "alice");
        let bob = user("org-a", "bob");
        let grant = grant_lease(&coord, &bob, "dk-1").await;

        assert!(matches!(
            coord.move_node_core(&alice, "node-a", "org-b", false).await,
            Err(NodeMoveError::Leased(1))
        ));
        assert_eq!(coord.scheduler.lock().await.boards().count(), 2);

        let out = coord
            .move_node_core(&alice, "node-a", "org-b", true)
            .await
            .unwrap();
        assert_eq!(out.revoked_leases, 1);
        assert!(coord.scheduler.lock().await.boards().next().is_none());
        assert_eq!(
            coord
                .db()
                .scoped(org("org-a"))
                .open_lease_count()
                .await
                .unwrap(),
            0
        );
        assert!(audit_actions(&coord, "org-a")
            .await
            .contains(&"lease.revoke".to_owned()));
        let _ = grant;
    }
}
