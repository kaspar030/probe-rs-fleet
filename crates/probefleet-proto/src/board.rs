//! Board inventory types reported by nodes and tracked by the coordinator.

use serde::{Deserialize, Serialize};

use crate::ids::{BoardRef, LeaseId, NodeId, SubjectKey};
use crate::serial::SerialPortInfo;

/// A leasable board, as known to the coordinator (reconciled from a node's
/// `boards.toml` plus live probe discovery).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Board {
    pub id: BoardRef,
    pub node: NodeId,
    /// probe-rs target name (informational; the `--chip` the caller passes
    /// still flows through untouched).
    pub chip: String,
    /// Board *model* (board type), e.g. `nrf52840dk` — what `board=<model>`
    /// matches. Declared by the operator in `boards.toml`; `None` for a board
    /// that did not declare one (in particular every auto-adopted board), and
    /// a board with no model is never matched by `board=`.
    pub model: Option<String>,
    /// Free-form selection tags, e.g. `["nrf52", "bluetooth"]`.
    pub tags: Vec<String>,
    /// Most boards are exclusive (one lease at a time).
    pub exclusive: bool,
    /// How the node can cut/restore USB power to this board.
    pub power: PowerKind,
    pub state: BoardState,
    /// USB serial ports the node associates with the board.
    pub serial_ports: Vec<SerialPortInfo>,
}

/// USB power-control capability for a board, as wired on the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerKind {
    /// Per-port USB hub control via `uhubctl`.
    Uhubctl { hub: String, port: u8 },
    /// A GPIO-driven relay on the node.
    Gpio { chip: String, line: u32 },
    /// No external power control; best-effort reset via the probe only.
    None,
}

/// Lifecycle state of a board in the fleet view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoardState {
    /// Available to be leased.
    Idle,
    /// Held by a subject until `expires` (epoch seconds). Extendable.
    Leased {
        lease: LeaseId,
        by: SubjectKey,
        expires: u64,
    },
    /// Quarantined after a fault; not leasable until cleared.
    Faulted { reason: String },
    /// Administratively disabled.
    Disabled,
}
