//! Lease request/grant types and selection constraints.
//!
//! A lease is *not* tied to a single `probe-rs run`: a principal claims a board
//! and holds it (with an extendable timeout) across many probe-rs invocations,
//! so remote DX feels local. See `docs/architecture.md` §6.

use serde::{Deserialize, Serialize};

use crate::ids::{AgentId, BoardId, LeaseId, Principal};

/// A request to lease a board, by id or by constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRequest {
    pub select: Constraint,
    /// Requested hold duration in seconds; the coordinator may cap it by
    /// policy. The lease is extendable via heartbeat/activity.
    pub duration_secs: u64,
    /// Priority class; higher wins when boards are scarce.
    pub priority: Priority,
}

/// How a caller picks a board.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Constraint {
    /// Exactly this board.
    Board(BoardId),
    /// Any idle board matching all of these tags.
    Tags(Vec<String>),
    /// Any idle board with this probe-rs chip name.
    Chip(String),
}

/// Priority classes for fairness when boards are contended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Priority {
    Soak = 0,
    Ci = 1,
    Interactive = 2,
}

/// Outcome of a [`LeaseRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LeaseOutcome {
    Granted(LeaseGrant),
    /// No board free; position in the queue (0-based).
    Queued { position: u32 },
}

/// A granted lease. The capability `token` is verified locally by the agent;
/// it does not require a coordinator round-trip per operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseGrant {
    pub lease: LeaseId,
    pub board: BoardId,
    pub agent: AgentId,
    pub holder: Principal,
    /// Expiry as epoch seconds; extend via heartbeat before this.
    pub expires: u64,
    /// Opaque signed capability token (see `fleet-coordinator` auth).
    pub token: Vec<u8>,
}
