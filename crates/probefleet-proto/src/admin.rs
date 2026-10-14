//! Operator / admin control-plane payloads (`ctl list` / `who` / `logs`).
//!
//! These ride the same sidecar-direction transport as the lease envelopes (a
//! `ctl` connects to `/client` with a user session token), but describe the
//! fleet-wide *operator* surface rather than a single subject's lease. They
//! are pure data so both the coordinator (which produces them) and `probefleet`'s
//! `ctl` role (which renders them) share one definition.

use serde::{Deserialize, Serialize};

use crate::adopt::AdoptPolicy;
use crate::board::PowerKind;
use crate::ids::{BoardRef, LeaseId, NodeId, OrgId, SubjectKey};
use crate::serial::SerialPortInfo;
use crate::token::AllowedOp;

/// A coarse, operator-facing lifecycle label for a board in `ctl list`.
///
/// Mirrors [`crate::board::BoardState`] without the inline lease detail (which,
/// when present, is reported separately via the optional `holder` fields on
/// [`BoardSummary`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoardAvailability {
    /// Idle and leasable.
    Available,
    /// Currently leased.
    Leased,
    /// Quarantined after a fault.
    Faulted,
    /// Administratively disabled.
    Disabled,
}

/// One row of the `ctl list` fleet inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardSummary {
    /// The board's fleet-unique key.
    pub board: BoardRef,
    /// The node that owns the board.
    ///
    /// Redundant with `board.node`, but kept so `ctl list` rendering and any
    /// consumer that only wants the node do not have to reach into the key.
    pub node: NodeId,
    /// probe-rs target/chip name.
    pub chip: String,
    /// Board *model* (board type), e.g. `nrf52840dk` — what `board=<model>`
    /// matches. `None` when the board did not declare one (every adopted
    /// board), in which case no `board=` selector can ever reach it.
    pub model: Option<String>,
    /// Free-form selection tags.
    pub tags: Vec<String>,
    /// Whether the board admits only one lease at a time.
    pub exclusive: bool,
    /// USB power-control capability.
    pub power: PowerKind,
    /// Coarse availability.
    pub availability: BoardAvailability,
    /// If leased, the current holder.
    pub holder: Option<SubjectKey>,
    /// If leased, the lease id.
    pub lease: Option<LeaseId>,
    /// If leased, the expiry (epoch seconds).
    pub expires: Option<u64>,
    /// USB serial ports the lease holder can open with `ctl serial`.
    pub serial_ports: Vec<SerialPortInfo>,
    /// The board's org path (display name), if the coordinator resolved one.
    /// Display only: `board.org` is the identity.
    pub org_name: Option<String>,
    /// A human rendering of `holder` (a user's username rather than
    /// `user:<ulid>`), if the coordinator resolved one. Display only.
    pub holder_display: Option<String>,
}

/// One row of the `ctl nodes` machine inventory.
///
/// The wire projection of the coordinator's node row (`OrgDb::list_nodes`,
/// joined with live connection state), so a CLI caller can answer "what
/// machines exist, and which tags do they carry?" — a question `ctl list`
/// cannot answer, because it is board-shaped and a machine that has plugged in
/// no probes has no row there.
///
/// Deliberately **not** the same struct as the coordinator's `NodeView` (the
/// body of `GET /api/v1/nodes`): that one is the web UI's contract and is free
/// to evolve on the browser's schedule, while this one is the wire's and moves
/// with [`crate::PROTOCOL_VERSION`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSummary {
    /// The node's fleet id (`{org}/{name}`).
    pub node: NodeId,
    /// The node-local name — what `ctl` and the node-patch API address it by.
    pub name: String,
    /// Free-form node tags. The point of the verb: these are what a `tag=`
    /// selector can match on every board the node offers.
    pub tags: Vec<String>,
    /// What the node does with a probe `boards.toml` does not declare.
    pub adopt: AdoptPolicy,
    /// The owning user id, if the node was enrolled by a logged-in human.
    /// `None` for an auth-key enrollment, which has no owning human by
    /// construction.
    pub owner: Option<String>,
    /// Epoch seconds of the last inventory report; `None` if the node has
    /// never connected.
    pub last_seen: Option<i64>,
    /// Epoch seconds the node row was created.
    pub created_at: i64,
    /// Whether the node holds its control-plane `WebSocket` right now.
    /// Composed from the live registry, never a stored column.
    pub online: bool,
    /// The node-local names of the boards recorded for this node. Empty for a
    /// machine that has reported no probes — which is exactly why this listing
    /// is not board-shaped.
    pub boards: Vec<String>,
}

/// One row of the `ctl who` lease table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseHolderSummary {
    /// The lease id.
    pub lease: LeaseId,
    /// The board held.
    pub board: BoardRef,
    /// The subject holding it.
    pub holder: SubjectKey,
    /// Expiry as epoch seconds.
    pub expires: u64,
    /// A human rendering of `holder` (a user's username rather than
    /// `user:<ulid>`), if the coordinator resolved one. Display only.
    pub holder_display: Option<String>,
}

/// One audit/log line returned by `ctl logs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogLine {
    /// Timestamp (epoch seconds).
    pub ts: i64,
    /// The action / event name.
    pub action: String,
    /// The board this line concerns, if any.
    pub board: Option<String>,
    /// Free-form detail.
    pub detail: Option<String>,
}

/// One row of the `grant list` table (architecture §6.5).
///
/// `selector` is the **canonical rendered** [`crate::lease::Constraint`] (see
/// its `Display`), which is exactly what is stored; evaluation re-parses it.
/// Keeping it a string on the wire means a row that fails to re-parse is a
/// visible, listable artefact rather than a decode failure that hides the whole
/// table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantSummary {
    /// Opaque grant id (32 hex chars). Revoked by id prefix.
    pub id: String,
    /// The org whose hardware is being shared (its namespace id).
    pub org: OrgId,
    /// The org's current path (display name), if the coordinator resolved
    /// one. Display only: `org` is the identity.
    pub org_name: Option<String>,
    /// Who the hardware is shared with.
    pub subject: SubjectKey,
    /// A human rendering of `subject` (a user's username rather than
    /// `user:<ulid>`), if the coordinator resolved one. Display only.
    pub subject_display: Option<String>,
    /// The canonical selector string.
    pub selector: String,
    /// The operations granted.
    pub ops: Vec<AllowedOp>,
    /// Expiry as epoch seconds. `None` means no expiry, which the `/client`
    /// path refuses to create.
    pub expires: Option<u64>,
    /// The user who created the grant, if recorded. `None` for rows created
    /// outside the API; an org admin can still revoke those.
    pub created_by: Option<String>,
    /// When the grant was created (epoch seconds).
    pub created_at: u64,
}
