//! Control-plane message set exchanged between an agent and the coordinator.
//!
//! These are the *payload* types for the dial-out control plane (architecture
//! §5): the agent reports upward ([`AgentReport`]) and the coordinator commands
//! downward ([`CoordinatorCommand`]) over the agent's single persistent mTLS
//! connection. The decided transport is **postcard-rpc for both planes** (§3):
//! agent→coordinator messages map to `ToServer` topics/endpoints and
//! coordinator→agent commands to `ToClient` topics. The concrete topic/endpoint
//! binding is wired by whichever of the coordinator (task 1711) / agent (task
//! 1712) crates owns the postcard-rpc service; this module defines only the
//! shared serde payloads so the two ends cannot drift.
//!
//! The opaque data plane (probe-rs frames) is *not* modeled here — it rides
//! [`crate::DataFrame`] on a leased [`crate::ChannelId`].

use serde::{Deserialize, Serialize};

use crate::board::PowerKind;
use crate::ids::{AgentId, BoardId, LeaseId};
use crate::ChannelId;

/// A probe physically discovered on an agent host (via `probe-rs` enumeration).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredProbe {
    /// Physical probe serial (matched against `boards.toml`).
    pub serial: String,
    /// USB vendor id, if known.
    pub vid: u16,
    /// USB product id, if known.
    pub pid: u16,
    /// Human-readable product string, if the probe reports one.
    pub product: Option<String>,
}

/// How a declared board reconciles against live probe discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BoardPresence {
    /// Declared in `boards.toml` and its probe is physically present.
    Online,
    /// Declared in `boards.toml` but its probe is not currently attached.
    Offline,
}

/// Per-board reconciliation status reported to the coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardStatus {
    /// The board id from `boards.toml`.
    pub board: BoardId,
    /// The probe serial bound to this board.
    pub serial: String,
    /// Whether the probe is currently present.
    pub presence: BoardPresence,
}

/// A full inventory snapshot: which declared boards are present, plus any
/// probes that were discovered but not declared (reported, not leasable — see
/// architecture §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeInventory {
    /// Reconciled status for every declared board.
    pub boards: Vec<BoardStatus>,
    /// Probes physically present but absent from `boards.toml`.
    pub unknown: Vec<DiscoveredProbe>,
}

/// Severity of an agent log line forwarded to the coordinator's audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    /// Diagnostic detail.
    Debug,
    /// Normal operational information.
    Info,
    /// A recoverable anomaly.
    Warn,
    /// A failure.
    Error,
}

/// A USB-power transition the agent performed on a board.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerAction {
    /// Power was cut.
    Off,
    /// Power was restored.
    On,
    /// Power was cycled (off then on).
    Cycle,
}

/// Messages an agent sends *up* to the coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentReport {
    /// First message after the dial-out connection is established.
    Register {
        /// This agent's id (matches the pinned cert fingerprint).
        agent: AgentId,
        /// Wire protocol version this agent speaks.
        protocol_version: u32,
    },
    /// A fresh inventory snapshot (sent on register and on change).
    Inventory(ProbeInventory),
    /// Periodic liveness ping.
    Heartbeat {
        /// Agent monotonic uptime in seconds (for drift detection).
        uptime_secs: u64,
    },
    /// A board fault that should quarantine the board.
    Fault {
        /// The affected board.
        board: BoardId,
        /// Human-readable reason.
        reason: String,
    },
    /// A forwarded log line.
    Log {
        /// Severity.
        level: LogLevel,
        /// Optionally, the board this log line concerns.
        board: Option<BoardId>,
        /// The message text.
        message: String,
    },
    /// A power transition the agent performed.
    PowerEvent {
        /// The affected board.
        board: BoardId,
        /// What happened.
        action: PowerAction,
    },
    /// A data-plane session ended (process exited or was killed).
    SessionClosed {
        /// The channel that closed.
        channel: ChannelId,
        /// The probe-rs server process exit code, if it exited on its own.
        exit_code: Option<i32>,
    },
}

/// Commands the coordinator sends *down* to an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoordinatorCommand {
    /// Open a probe-rs session for `lease` on `board`, splicing its byte
    /// stream onto `channel`. The agent verifies `token` locally before acting.
    OpenSession {
        /// The authorising lease.
        lease: LeaseId,
        /// The target board.
        board: BoardId,
        /// The signed capability token (wire framing: see [`crate::token`]).
        token: Vec<u8>,
        /// The data-plane channel to splice the session onto.
        channel: ChannelId,
    },
    /// Tear down a session by its channel.
    KillSession {
        /// The channel to kill.
        channel: ChannelId,
    },
    /// Release a lease: kill any session and run cleanup (power-cycle, optional
    /// erase) on the board.
    ReleaseLease {
        /// The lease being released.
        lease: LeaseId,
        /// The board to clean up.
        board: BoardId,
        /// Whether to erase the target's flash as part of cleanup.
        erase: bool,
    },
    /// Explicitly cut/restore/cycle power to a board (operator action).
    PowerCycle {
        /// The board to power-cycle.
        board: BoardId,
    },
    /// Ask the agent to re-report its current state and inventory.
    QueryState,
}

/// The power kind a board declares, re-exported for control-plane consumers.
///
/// (Alias so coordinator code can refer to `agent_api::BoardPower` without
/// reaching into [`crate::board`].)
pub type BoardPower = PowerKind;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_roundtrips_through_postcard() {
        let report = AgentReport::Inventory(ProbeInventory {
            boards: vec![BoardStatus {
                board: BoardId("b1".to_owned()),
                serial: "001050257890".to_owned(),
                presence: BoardPresence::Online,
            }],
            unknown: vec![DiscoveredProbe {
                serial: "deadbeef".to_owned(),
                vid: 0x1366,
                pid: 0x1015,
                product: Some("J-Link".to_owned()),
            }],
        });
        let bytes = postcard::to_allocvec(&report).unwrap();
        let back: AgentReport = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn command_roundtrips_through_postcard() {
        let cmd = CoordinatorCommand::OpenSession {
            lease: LeaseId(42),
            board: BoardId("b1".to_owned()),
            token: vec![1, 2, 3, 4],
            channel: ChannelId(9),
        };
        let bytes = postcard::to_allocvec(&cmd).unwrap();
        let back: CoordinatorCommand = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(cmd, back);
    }
}
