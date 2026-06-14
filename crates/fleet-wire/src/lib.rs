//! Length-delimited postcard framing + the control-plane envelopes.
//!
//! This crate is the shared **wire substrate** between the coordinator, agents,
//! and sidecars. It holds two things:
//!
//! 1. A **length-delimited postcard codec** ([`read_frame`] / [`write_frame`])
//!    over any `AsyncRead`/`AsyncWrite`. Each frame is a `u32` little-endian
//!    length prefix followed by that many postcard bytes. This carries the
//!    control-plane messages of either plane plus opaque [`DataFrame`]s, and is
//!    structured to be swappable for a postcard-rpc `WireTx`/`WireRx` later
//!    without disturbing the scheduler/relay/auth core (architecture §3).
//! 2. The **control-plane envelopes** for both planes: the agent direction
//!    ([`AgentToCoord`] / [`CoordToAgent`]) and the sidecar direction
//!    ([`SidecarToCoord`] / [`CoordToSidecar`]). The payload types they wrap
//!    live in [`fleet_proto`]; the envelopes add an unambiguous discriminator
//!    so control and data frames demultiplex over one stream.
//!
//! It depends only on [`fleet_proto`] + a minimal `tokio` (io-util) so the
//! agent and sidecar can speak the wire without pulling the coordinator's
//! storage/TLS stack — important for cross-compiling the agent to ARM/musl.

use fleet_proto::admin::{BoardSummary, LeaseHolderSummary, LogLine};
use fleet_proto::agent_api::{AgentReport, CoordinatorCommand};
use fleet_proto::ids::BoardId;
use fleet_proto::lease::{LeaseGrant, LeaseRequest};
use fleet_proto::{ChannelId, ChannelKind, DataFrame, LeaseId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum frame body length the codec will accept, to bound memory on a
/// hostile or corrupt peer. Data-plane frames are small probe-rs chunks; 16 MiB
/// is far above any legitimate control or data frame.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Errors from the framing codec.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// An I/O failure (including a clean EOF, surfaced as `UnexpectedEof`).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A frame could not be encoded/decoded, or violated a size bound.
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// A framed message from an agent up to the coordinator.
///
/// The agent control plane multiplexes shared `fleet-proto` control payloads
/// ([`AgentReport`]) and opaque data-plane bytes ([`DataFrame`]) over one
/// length-delimited stream. Wrapping them in this envelope gives the reader an
/// unambiguous discriminator (the proto types themselves carry no tag
/// distinguishing a report from a data frame), mirroring the symmetric sidecar
/// plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentToCoord {
    /// A control-plane report.
    Report(AgentReport),
    /// Opaque data-plane bytes from a probe-rs session.
    Data(DataFrame),
}

/// A framed message from the coordinator down to an agent.
///
/// The down-stream counterpart of [`AgentToCoord`]: it wraps a control command
/// ([`CoordinatorCommand`]) or an opaque [`DataFrame`] with a discriminator so
/// the agent can demultiplex the two unambiguously.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoordToAgent {
    /// A control-plane command.
    Command(CoordinatorCommand),
    /// Opaque data-plane bytes to splice onto an open session.
    Data(DataFrame),
}

/// A message from a sidecar up to the coordinator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SidecarToCoord {
    /// First message; announces the wire protocol version.
    Hello {
        /// The protocol version the sidecar speaks.
        protocol_version: u32,
    },
    /// Request a lease on a board.
    Lease(LeaseRequest),
    /// Extend an existing lease's expiry.
    Extend {
        /// The lease to extend.
        lease: LeaseId,
    },
    /// Release a held lease.
    Release {
        /// The lease to release.
        lease: LeaseId,
    },
    /// Open a relay channel (probe-rs session) for a held lease.
    ///
    /// `kind` selects the channel plane: the regular data plane
    /// ([`ChannelKind::Data`], the default) or a gdb tunnel
    /// ([`ChannelKind::Gdb`], for `probe-rs gdb`). A lease may hold both kinds
    /// concurrently.
    OpenChannel {
        /// The authorising lease.
        lease: LeaseId,
        /// Which plane the channel carries.
        #[serde(default)]
        kind: ChannelKind,
    },
    /// Opaque data-plane bytes destined for the owning agent.
    Data(DataFrame),
    /// Close a previously opened channel.
    CloseChannel {
        /// The channel to close.
        channel: ChannelId,
    },
    /// Operator: list the fleet inventory (`ctl list`).
    ListBoards,
    /// Operator: list current lease holders (`ctl who`).
    Who,
    /// Operator: fetch recent audit/log lines (`ctl logs`).
    Logs {
        /// Restrict to a single board, if set.
        board: Option<BoardId>,
        /// Follow mode (advisory; v1 returns the current tail either way).
        #[serde(default)]
        follow: bool,
    },
    /// Operator: power-cycle a board (`ctl power-cycle`).
    PowerCycle {
        /// The board to power-cycle.
        board: BoardId,
    },
}

/// A message from the coordinator down to a sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoordToSidecar {
    /// Welcome reply; echoes the coordinator's protocol version.
    Welcome {
        /// The protocol version the coordinator speaks.
        protocol_version: u32,
    },
    /// The outcome of a [`SidecarToCoord::Lease`] request.
    Lease(LeaseGrant),
    /// The request was queued; position is 0-based.
    Queued {
        /// 0-based position among waiters for the same constraint.
        position: u32,
    },
    /// A lease was extended; carries the new expiry (epoch seconds).
    Extended {
        /// The lease that was extended.
        lease: LeaseId,
        /// The new expiry, epoch seconds.
        expires: u64,
    },
    /// A lease was released.
    Released {
        /// The lease that was released.
        lease: LeaseId,
    },
    /// A channel was opened and is ready for data.
    ChannelOpened {
        /// The allocated channel id.
        channel: ChannelId,
    },
    /// A channel was closed (by request, agent, or lease expiry).
    ChannelClosed {
        /// The channel that closed.
        channel: ChannelId,
    },
    /// Opaque data-plane bytes relayed from the owning agent.
    Data(DataFrame),
    /// Operator: the fleet inventory (reply to [`SidecarToCoord::ListBoards`]).
    BoardList(Vec<BoardSummary>),
    /// Operator: the current lease table (reply to [`SidecarToCoord::Who`]).
    LeaseTable(Vec<LeaseHolderSummary>),
    /// Operator: recent audit/log lines (reply to [`SidecarToCoord::Logs`]).
    LogLines(Vec<LogLine>),
    /// Operator: acknowledgement of a power-cycle request.
    PowerCycled {
        /// The board that was power-cycled.
        board: BoardId,
    },
    /// An error in response to a sidecar request.
    Error {
        /// Human-readable error description.
        message: String,
    },
}

/// Encode `value` as a single length-delimited postcard frame.
///
/// # Errors
///
/// Returns [`WireError::Protocol`] if encoding fails or the encoded body
/// exceeds [`MAX_FRAME_LEN`], and [`WireError::Io`] on a write failure.
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), WireError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = postcard::to_allocvec(value)
        .map_err(|e| WireError::Protocol(format!("encode: {e}")))?;
    if body.len() > MAX_FRAME_LEN {
        return Err(WireError::Protocol(format!(
            "frame too large: {} > {MAX_FRAME_LEN}",
            body.len()
        )));
    }
    // `body.len() <= MAX_FRAME_LEN` (16 MiB) so the cast cannot truncate.
    let len = u32::try_from(body.len())
        .map_err(|_| WireError::Protocol("frame length overflow".to_owned()))?;
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a single length-delimited postcard frame and decode it as `T`.
///
/// # Errors
///
/// Returns [`WireError::Io`] on a read failure (including a clean EOF, surfaced
/// as `UnexpectedEof`), and [`WireError::Protocol`] if the announced length
/// exceeds [`MAX_FRAME_LEN`] or the body fails to decode.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, WireError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(WireError::Protocol(format!(
            "frame too large: {len} > {MAX_FRAME_LEN}"
        )));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    postcard::from_bytes(&body).map_err(|e| WireError::Protocol(format!("decode: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::agent_api::{AgentReport, CoordinatorCommand};
    use fleet_proto::ids::BoardId;
    use fleet_proto::lease::{Constraint, Priority};

    #[tokio::test]
    async fn sidecar_envelope_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let msg = SidecarToCoord::Lease(LeaseRequest {
            select: Constraint::Board(BoardId("b1".to_owned())),
            duration_secs: 600,
            priority: Priority::Interactive,
        });
        write_frame(&mut a, &msg).await.unwrap();
        let back: SidecarToCoord = read_frame(&mut b).await.unwrap();
        assert_eq!(back, msg);
    }

    #[tokio::test]
    async fn dataframe_roundtrip_both_directions() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let frame = DataFrame {
            channel: ChannelId(5),
            bytes: vec![1, 2, 3, 4, 5],
        };
        write_frame(&mut a, &CoordToSidecar::Data(frame.clone()))
            .await
            .unwrap();
        let back: CoordToSidecar = read_frame(&mut b).await.unwrap();
        assert_eq!(back, CoordToSidecar::Data(frame));
    }

    #[tokio::test]
    async fn agent_envelopes_roundtrip_and_demux() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let cmd = CoordToAgent::Command(CoordinatorCommand::OpenSession {
            lease: LeaseId(1),
            board: BoardId("b1".to_owned()),
            token: vec![9, 9, 9],
            channel: ChannelId(2),
            kind: ChannelKind::Data,
        });
        let data = CoordToAgent::Data(DataFrame {
            channel: ChannelId(2),
            bytes: vec![7, 7, 7],
        });
        write_frame(&mut a, &cmd).await.unwrap();
        write_frame(&mut a, &data).await.unwrap();
        assert_eq!(read_frame::<_, CoordToAgent>(&mut b).await.unwrap(), cmd);
        assert_eq!(read_frame::<_, CoordToAgent>(&mut b).await.unwrap(), data);

        let report = AgentToCoord::Report(AgentReport::Heartbeat { uptime_secs: 123 });
        let up = AgentToCoord::Data(DataFrame {
            channel: ChannelId(2),
            bytes: vec![1, 2],
        });
        write_frame(&mut a, &report).await.unwrap();
        write_frame(&mut a, &up).await.unwrap();
        assert_eq!(read_frame::<_, AgentToCoord>(&mut b).await.unwrap(), report);
        assert_eq!(read_frame::<_, AgentToCoord>(&mut b).await.unwrap(), up);
    }

    #[tokio::test]
    async fn multiple_frames_in_sequence() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        for i in 0..5u64 {
            write_frame(&mut a, &SidecarToCoord::Extend { lease: LeaseId(i) })
                .await
                .unwrap();
        }
        for i in 0..5u64 {
            let back: SidecarToCoord = read_frame(&mut b).await.unwrap();
            assert_eq!(back, SidecarToCoord::Extend { lease: LeaseId(i) });
        }
    }

    #[tokio::test]
    async fn eof_surfaces_as_io_error() {
        let (a, mut b) = tokio::io::duplex(4096);
        drop(a);
        let err = read_frame::<_, SidecarToCoord>(&mut b).await.unwrap_err();
        assert!(matches!(err, WireError::Io(_)));
    }

    #[tokio::test]
    async fn oversized_announced_length_rejected() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // Announce a body larger than MAX_FRAME_LEN without sending it.
        let len = u32::try_from(MAX_FRAME_LEN + 1).unwrap();
        a.write_all(&len.to_le_bytes()).await.unwrap();
        a.flush().await.unwrap();
        let err = read_frame::<_, SidecarToCoord>(&mut b).await.unwrap_err();
        assert!(matches!(err, WireError::Protocol(_)));
    }
}
