//! Wire framing for the coordinator's TLS streams.
//!
//! The length-delimited postcard codec and the control-plane envelopes now live
//! in the shared [`fleet_wire`] crate (so agents and sidecars can speak the wire
//! without depending on the coordinator's storage/TLS stack). This module
//! re-exports them and provides thin [`read_frame`] / [`write_frame`] wrappers
//! that surface the coordinator's own [`CoordinatorError`] for ergonomic use in
//! the server/relay code, preserving the historical `fleet_coordinator::proto`
//! API (e.g. used by the bootstrap-enrollment client).

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};

pub use fleet_wire::{
    AgentToCoord, CoordToAgent, CoordToSidecar, SidecarToCoord, WireError, MAX_FRAME_LEN,
};

use crate::error::{CoordinatorError, Result};

impl From<WireError> for CoordinatorError {
    fn from(e: WireError) -> Self {
        match e {
            WireError::Io(io) => CoordinatorError::Io(io),
            WireError::Protocol(m) => CoordinatorError::Protocol(m),
        }
    }
}

/// Encode `value` as a single length-delimited postcard frame.
///
/// # Errors
///
/// Returns [`CoordinatorError::Protocol`] if encoding fails or the encoded body
/// exceeds [`MAX_FRAME_LEN`], and [`CoordinatorError::Io`] on a write failure.
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    fleet_wire::write_frame(writer, value).await?;
    Ok(())
}

/// Read a single length-delimited postcard frame and decode it as `T`.
///
/// # Errors
///
/// Returns [`CoordinatorError::Io`] on a read failure (including a clean EOF,
/// surfaced as `UnexpectedEof`), and [`CoordinatorError::Protocol`] if the
/// announced length exceeds [`MAX_FRAME_LEN`] or the body fails to decode.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    Ok(fleet_wire::read_frame(reader).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::agent_api::{AgentReport, CoordinatorCommand};
    use fleet_proto::ids::BoardId;
    use fleet_proto::lease::{Constraint, LeaseRequest, Priority};
    use fleet_proto::{ChannelId, DataFrame, LeaseId};
    use tokio::io::AsyncWriteExt;

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
        // Both directions wrap the shared proto types with a discriminator so
        // control and data frames demultiplex unambiguously over one stream.
        let (mut a, mut b) = tokio::io::duplex(4096);
        let cmd = CoordToAgent::Command(CoordinatorCommand::OpenSession {
            lease: LeaseId(1),
            board: BoardId("b1".to_owned()),
            token: vec![9, 9, 9],
            channel: ChannelId(2),
            kind: fleet_proto::ChannelKind::Data,
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
        assert!(matches!(err, CoordinatorError::Io(_)));
    }

    #[tokio::test]
    async fn oversized_announced_length_rejected() {
        let (mut a, mut b) = tokio::io::duplex(64);
        // Announce a body larger than MAX_FRAME_LEN without sending it.
        let len = u32::try_from(MAX_FRAME_LEN + 1).unwrap();
        a.write_all(&len.to_le_bytes()).await.unwrap();
        a.flush().await.unwrap();
        let err = read_frame::<_, SidecarToCoord>(&mut b).await.unwrap_err();
        assert!(matches!(err, CoordinatorError::Protocol(_)));
    }
}
