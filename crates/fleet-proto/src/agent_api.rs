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
    /// The probe is present but `probe-rs` cannot open it: probe-rs 0.32's
    /// `probe-rs list` appends `" (inaccessible)"` to such a probe's line
    /// (`Accessibility::PermissionDenied` — an `access(2)` check on the probe's
    /// USB device node, so in practice a udev/permissions problem, **not** a
    /// busy probe).
    ///
    /// Such a probe is still reported (so the condition is diagnosable) but is
    /// never advertised as an online, leasable board.
    pub inaccessible: bool,
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
///
/// Carries the full leasable-board metadata declared in the agent's
/// `boards.toml` (chip / tags / exclusivity / power capability) in addition to
/// the live presence, so the coordinator can reconstruct a
/// [`fleet_proto::board::Board`] for its scheduler without a second message.
/// The board's owning [`AgentId`] is known from the authenticated connection
/// (it is not repeated on the wire) and its lease state defaults to available.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardStatus {
    /// The board id from `boards.toml`.
    pub board: BoardId,
    /// The probe serial bound to this board.
    pub serial: String,
    /// Whether the probe is currently present.
    pub presence: BoardPresence,
    /// probe-rs target/chip name (informational; the caller still passes
    /// `--chip` in-band).
    pub chip: String,
    /// Free-form selection tags, e.g. `["nrf52", "bluetooth"]`.
    pub tags: Vec<String>,
    /// Whether the board admits only one lease at a time.
    pub exclusive: bool,
    /// How the agent can cut/restore power to this board.
    pub power: BoardPower,
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

/// What an opaque relay channel carries, and therefore how the agent sources /
/// sinks its bytes.
///
/// Both kinds ride the *same* relay machinery: once open, a channel is a pure
/// [`crate::DataFrame`] byte pump and the coordinator never inspects it. The
/// kind only matters at channel-open time, where it tells the agent what to
/// splice the channel onto:
///
/// * [`ChannelKind::Data`] — the board's `probe-rs serve` postcard-rpc stream
///   (the regular data plane; architecture §4.2).
/// * [`ChannelKind::Gdb`] — a freshly-spawned, board-local `probe-rs gdb` TCP
///   stub. `probe-rs gdb` is not remote-capable in 0.32, so the agent runs it
///   locally and tunnels its raw gdbremote TCP as a second opaque channel
///   (architecture §4.2 gap note, §10 Q3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ChannelKind {
    /// Opaque probe-rs `serve` postcard-rpc data plane (the default).
    #[default]
    Data,
    /// Raw gdbremote TCP from a board-local `probe-rs gdb` stub.
    Gdb,
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
    ///
    /// `kind` selects what the agent splices onto the channel: the board's
    /// `probe-rs serve` data plane ([`ChannelKind::Data`]) or a board-local
    /// `probe-rs gdb` TCP stub ([`ChannelKind::Gdb`]). Both relay identically
    /// once open.
    OpenSession {
        /// The authorising lease.
        lease: LeaseId,
        /// The target board.
        board: BoardId,
        /// The signed capability token (wire framing: see [`crate::token`]).
        token: Vec<u8>,
        /// The relay channel to splice the session onto.
        channel: ChannelId,
        /// What the channel carries (data plane vs. gdb tunnel).
        #[serde(default)]
        kind: ChannelKind,
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
                chip: "nRF52840_xxAA".to_owned(),
                tags: vec!["nrf52".to_owned()],
                exclusive: true,
                power: PowerKind::None,
            }],
            unknown: vec![
                DiscoveredProbe {
                    serial: "deadbeef".to_owned(),
                    vid: 0x1366,
                    pid: 0x1015,
                    product: Some("J-Link".to_owned()),
                    inaccessible: false,
                },
                DiscoveredProbe {
                    serial: "cafebabe".to_owned(),
                    vid: 0x0d28,
                    pid: 0x0204,
                    product: Some("CMSIS-DAP".to_owned()),
                    inaccessible: true,
                },
            ],
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
            kind: ChannelKind::Data,
        };
        let bytes = postcard::to_allocvec(&cmd).unwrap();
        let back: CoordinatorCommand = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(cmd, back);
    }

    #[test]
    fn gdb_open_session_roundtrips_through_postcard() {
        let cmd = CoordinatorCommand::OpenSession {
            lease: LeaseId(7),
            board: BoardId("b1".to_owned()),
            token: vec![9, 9],
            channel: ChannelId(3),
            kind: ChannelKind::Gdb,
        };
        let bytes = postcard::to_allocvec(&cmd).unwrap();
        let back: CoordinatorCommand = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(cmd, back);
        let CoordinatorCommand::OpenSession { kind, .. } = back else {
            panic!("expected OpenSession");
        };
        assert_eq!(kind, ChannelKind::Gdb);
    }
}
