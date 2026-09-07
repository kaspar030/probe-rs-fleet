//! Operator / admin control-plane payloads (`ctl list` / `who` / `logs`).
//!
//! These ride the same sidecar-direction transport as the lease envelopes (a
//! `ctl` connects to `/client` with a user session token), but describe the
//! fleet-wide *operator* surface rather than a single subject's lease. They
//! are pure data so both the coordinator (which produces them) and `fleet-bin`'s
//! `ctl` role (which renders them) share one definition.

use serde::{Deserialize, Serialize};

use crate::board::PowerKind;
use crate::ids::{BoardRef, LeaseId, NodeId, OrgId, Subject, SubjectKey};
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
    pub holder: Option<Subject>,
    /// If leased, the lease id.
    pub lease: Option<LeaseId>,
    /// If leased, the expiry (epoch seconds).
    pub expires: Option<u64>,
}

/// One row of the `ctl who` lease table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseHolderSummary {
    /// The lease id.
    pub lease: LeaseId,
    /// The board held.
    pub board: BoardRef,
    /// The subject holding it.
    pub holder: Subject,
    /// Expiry as epoch seconds.
    pub expires: u64,
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
    /// The org whose hardware is being shared.
    pub org: OrgId,
    /// Who the hardware is shared with.
    pub subject: SubjectKey,
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
