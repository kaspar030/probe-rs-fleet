//! Board inventory types reported by agents and tracked by the coordinator.

use serde::{Deserialize, Serialize};

use crate::ids::{AgentId, BoardId, LeaseId, Principal};

/// A leasable board, as known to the coordinator (reconciled from an agent's
/// `boards.toml` plus live probe discovery).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Board {
    pub id: BoardId,
    pub agent: AgentId,
    /// probe-rs target name (informational; the `--chip` the caller passes
    /// still flows through untouched).
    pub chip: String,
    /// Free-form selection tags, e.g. `["nrf52", "bluetooth"]`.
    pub tags: Vec<String>,
    /// Most boards are exclusive (one lease at a time).
    pub exclusive: bool,
    /// How the agent can cut/restore USB power to this board.
    pub power: PowerKind,
    pub state: BoardState,
}

/// USB power-control capability for a board, as wired on the agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerKind {
    /// Per-port USB hub control via `uhubctl`.
    Uhubctl { hub: String, port: u8 },
    /// A GPIO-driven relay on the agent.
    Gpio { chip: String, line: u32 },
    /// No external power control; best-effort reset via the probe only.
    None,
}

/// Lifecycle state of a board in the fleet view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoardState {
    /// Available to be leased.
    Idle,
    /// Held by a principal until `expires` (epoch seconds). Extendable.
    Leased {
        lease: LeaseId,
        by: Principal,
        expires: u64,
    },
    /// Quarantined after a fault; not leasable until cleared.
    Faulted { reason: String },
    /// Administratively disabled.
    Disabled,
}
