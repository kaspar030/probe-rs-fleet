//! Relay: opaque [`DataFrame`] forwarding between a sidecar and the owning
//! agent (architecture §4.1, §6).
//!
//! The same machinery carries **both** planes — the probe-rs `serve` data plane
//! and the gdb tunnel — distinguished only by the [`fleet_proto::ChannelKind`]
//! recorded at open time (the coordinator relays the bytes identically either
//! way). Channels are keyed purely by [`ChannelId`], so a single lease may hold
//! several concurrent channels (e.g. a data channel and a gdb channel at once).
//!
//! The coordinator never parses probe-rs traffic. A relay channel is opened by
//! an explicit control RPC (sidecar `OpenChannel` → coordinator allocates a
//! [`ChannelId`], commands the agent to `OpenSession`, replies `ChannelOpened`),
//! after which [`DataFrame`]s are forwarded **verbatim** in both directions:
//!
//! ```text
//! sidecar  --Data-->  coordinator  --Data-->  agent      (forward_to_agent)
//! agent    --Data-->  coordinator  --Data-->  sidecar    (forward_to_sidecar)
//! ```
//!
//! This module holds the routing primitives and their teardown logic; the
//! connection tasks in [`crate::server`] call into it. The functions are kept
//! transport-agnostic (they move frames between in-memory channels) so they can
//! be exercised over `tokio::io::duplex` in tests without any TLS or sockets.

use fleet_proto::agent_api::CoordinatorCommand;
use fleet_proto::ids::{BoardRef, LeaseId};
use fleet_proto::{ChannelId, DataFrame};

use crate::error::{CoordinatorError, Result};
use crate::proto::CoordToSidecar;
use crate::registry::{AgentHandle, ChannelRoute, ChannelTable, SidecarHandle};

/// The parameters of a channel-open request that vary per lease/session.
///
/// Grouped into one struct so [`open_channel`] stays within a reasonable
/// argument count and the lease/board/token/kind always travel together.
pub struct OpenRequest {
    /// The authorising lease.
    pub lease: LeaseId,
    /// The target board, as the fleet-unique key the capability token is
    /// scoped to.
    pub board: BoardRef,
    /// The signed capability token (wire framing: see `fleet_proto::token`).
    pub token: Vec<u8>,
    /// Which plane the channel carries (data vs. gdb tunnel).
    pub kind: fleet_proto::ChannelKind,
}

/// Open a relay channel: allocate an id, register the route, and command the
/// owning agent to open its side.
///
/// The caller is responsible for sending [`CoordToSidecar::ChannelOpened`] back
/// to the sidecar once the agent acknowledges (or it may do so optimistically;
/// see [`crate::server`]). Returns the allocated channel id.
///
/// # Errors
///
/// Returns [`CoordinatorError::AgentUnavailable`]-style failures via the agent
/// handle if the command cannot be delivered.
pub async fn open_channel(
    table: &ChannelTable,
    agent: &AgentHandle,
    agent_id: fleet_proto::ids::AgentId,
    sidecar: SidecarHandle,
    request: OpenRequest,
) -> Result<ChannelId> {
    let OpenRequest {
        lease,
        board,
        token,
        kind,
    } = request;
    let channel = table.allocate().await;
    table
        .insert(
            channel,
            ChannelRoute {
                lease,
                agent: agent_id,
                sidecar,
                kind,
            },
        )
        .await;
    agent
        .send_command(CoordinatorCommand::OpenSession {
            lease,
            board,
            token,
            channel,
            kind,
        })
        .await
        .map_err(|_| {
            CoordinatorError::Protocol("agent connection closed during open".to_owned())
        })?;
    Ok(channel)
}

/// Forward a [`DataFrame`] arriving from a sidecar to the owning agent.
///
/// Looks up the channel route and pushes the frame to the agent's writer task.
/// A frame for an unknown channel is dropped (returns `Ok(false)`).
///
/// # Errors
///
/// Returns [`CoordinatorError::Protocol`] if the agent's connection has closed.
pub async fn forward_to_agent(
    table: &ChannelTable,
    agent: &AgentHandle,
    frame: DataFrame,
) -> Result<bool> {
    if table.get(frame.channel).await.is_none() {
        return Ok(false);
    }
    agent.send_data(frame).await.map_err(|_| {
        CoordinatorError::Protocol("agent connection closed during relay".to_owned())
    })?;
    Ok(true)
}

/// Forward a [`DataFrame`] arriving from an agent to the sidecar that owns the
/// channel.
///
/// A frame for an unknown channel is dropped (returns `Ok(false)`).
///
/// # Errors
///
/// Returns [`CoordinatorError::Protocol`] if the sidecar's connection has
/// closed.
pub async fn forward_to_sidecar(table: &ChannelTable, frame: DataFrame) -> Result<bool> {
    let Some(route) = table.get(frame.channel).await else {
        return Ok(false);
    };
    route
        .sidecar
        .send(CoordToSidecar::Data(frame))
        .await
        .map_err(|_| {
            CoordinatorError::Protocol("sidecar connection closed during relay".to_owned())
        })?;
    Ok(true)
}

/// Tear down a channel: remove its route, command the agent to kill its session,
/// and notify the sidecar.
///
/// Best-effort on each leg — a closed connection on one side does not prevent
/// notifying the other. Returns `true` if the channel existed.
pub async fn close_channel(
    table: &ChannelTable,
    agent: Option<&AgentHandle>,
    channel: ChannelId,
) -> bool {
    let Some(route) = table.remove(channel).await else {
        return false;
    };
    if let Some(agent) = agent {
        let _ = agent
            .send_command(CoordinatorCommand::KillSession { channel })
            .await;
    }
    let _ = route.sidecar.send(CoordToSidecar::ChannelClosed { channel }).await;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::AgentMessage;
    use fleet_proto::ids::{AgentId, OrgId};
    use tokio::sync::mpsc;

    /// The org this fixture's node and boards live in.
    fn test_org() -> OrgId {
        OrgId(crate::state::DEFAULT_ORG_ID.to_owned())
    }

    /// The node id the coordinator would mint for this fixture's agent.
    ///
    /// The relay itself treats an `AgentId` as an opaque routing key, but the
    /// key it routes on in production is an org-namespaced one, so that is
    /// what the fixture routes on — built by the production constructor.
    fn test_agent_id() -> AgentId {
        crate::state::node_id_for(&test_org(), "agent-a")
    }

    fn test_board_ref() -> BoardRef {
        BoardRef::new(test_org(), test_agent_id(), "b1")
    }

    /// Build an agent handle and a receiver standing in for the agent's writer
    /// task draining its connection.
    fn agent_pair() -> (AgentHandle, mpsc::Receiver<AgentMessage>) {
        let (tx, rx) = mpsc::channel(16);
        (AgentHandle::new(tx), rx)
    }

    #[tokio::test]
    async fn relay_smoke_bidirectional() {
        // The relay routes opaque bytes both directions on a channel without
        // interpreting them.
        let table = ChannelTable::new();
        let (agent, mut agent_rx) = agent_pair();
        let (sidecar_tx, mut sidecar_rx) = mpsc::channel::<CoordToSidecar>(16);

        // Open a channel (commands the agent to open its session).
        let channel = open_channel(
            &table,
            &agent,
            test_agent_id(),
            sidecar_tx.clone(),
            OpenRequest {
                lease: LeaseId(1),
                board: test_board_ref(),
                token: vec![0xde, 0xad],
                kind: fleet_proto::ChannelKind::Data,
            },
        )
        .await
        .unwrap();
        assert_eq!(channel, ChannelId(0));

        // Agent received the OpenSession command verbatim.
        match agent_rx.recv().await.unwrap() {
            AgentMessage::Command(CoordinatorCommand::OpenSession {
                lease,
                board,
                token,
                channel: ch,
                kind,
            }) => {
                assert_eq!(lease, LeaseId(1));
                assert_eq!(board, test_board_ref());
                assert_eq!(token, vec![0xde, 0xad]);
                assert_eq!(ch, channel);
                assert_eq!(kind, fleet_proto::ChannelKind::Data);
            }
            other => panic!("expected OpenSession, got {other:?}"),
        }

        // Sidecar -> agent: opaque bytes arrive verbatim at the agent end.
        let up = DataFrame {
            channel,
            bytes: vec![1, 2, 3, 4, 5],
        };
        assert!(forward_to_agent(&table, &agent, up.clone()).await.unwrap());
        match agent_rx.recv().await.unwrap() {
            AgentMessage::Data(f) => assert_eq!(f, up),
            other @ AgentMessage::Command(_) => panic!("expected Data, got {other:?}"),
        }

        // Agent -> sidecar: opaque bytes arrive verbatim at the sidecar end.
        let down = DataFrame {
            channel,
            bytes: vec![9, 8, 7],
        };
        assert!(forward_to_sidecar(&table, down.clone()).await.unwrap());
        match sidecar_rx.recv().await.unwrap() {
            CoordToSidecar::Data(f) => assert_eq!(f, down),
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn frames_for_unknown_channel_are_dropped() {
        let table = ChannelTable::new();
        let (agent, _agent_rx) = agent_pair();
        let frame = DataFrame {
            channel: ChannelId(99),
            bytes: vec![1],
        };
        assert!(!forward_to_agent(&table, &agent, frame.clone())
            .await
            .unwrap());
        assert!(!forward_to_sidecar(&table, frame).await.unwrap());
    }

    #[tokio::test]
    async fn close_tears_down_both_ends() {
        let table = ChannelTable::new();
        let (agent, mut agent_rx) = agent_pair();
        let (sidecar_tx, mut sidecar_rx) = mpsc::channel::<CoordToSidecar>(16);
        let channel = open_channel(
            &table,
            &agent,
            test_agent_id(),
            sidecar_tx,
            OpenRequest {
                lease: LeaseId(1),
                board: test_board_ref(),
                token: vec![],
                kind: fleet_proto::ChannelKind::Data,
            },
        )
        .await
        .unwrap();
        // Drain the OpenSession command.
        let _ = agent_rx.recv().await.unwrap();

        assert!(close_channel(&table, Some(&agent), channel).await);
        assert!(table.get(channel).await.is_none());

        match agent_rx.recv().await.unwrap() {
            AgentMessage::Command(CoordinatorCommand::KillSession { channel: ch }) => {
                assert_eq!(ch, channel);
            }
            other => panic!("expected KillSession, got {other:?}"),
        }
        match sidecar_rx.recv().await.unwrap() {
            CoordToSidecar::ChannelClosed { channel: ch } => assert_eq!(ch, channel),
            other => panic!("expected ChannelClosed, got {other:?}"),
        }

        // Closing again is a no-op.
        assert!(!close_channel(&table, Some(&agent), channel).await);
    }

    /// Relay smoke test over a real wire pair: bytes forwarded to a "sidecar"
    /// travel through the codec + relay and arrive verbatim at the "agent"
    /// reader. The relay itself is transport-agnostic — it moves frames between
    /// two mpsc handles and never touches a socket — so this exercises the
    /// codec boundary either side of it.
    #[tokio::test]
    async fn relay_over_a_wire_pair() {
        let table = ChannelTable::new();
        let channel = table.allocate().await;

        // Agent side: a wire pair whose far half stands in for the node.
        let (mut agent_wire_tx, _agent_wire_rx, _peer_tx, mut agent_remote) =
            fleet_wire::mock::pair();
        let (agent_tx, mut agent_msg_rx) = mpsc::channel::<AgentMessage>(16);
        // Writer task: drains AgentMessage -> writes DataFrame onto the wire.
        let writer = tokio::spawn(async move {
            while let Some(msg) = agent_msg_rx.recv().await {
                if let AgentMessage::Data(frame) = msg {
                    fleet_wire::send(&mut agent_wire_tx, &frame).await.unwrap();
                }
            }
        });
        let agent = AgentHandle::new(agent_tx);

        let (sidecar_tx, _sidecar_rx) = mpsc::channel::<CoordToSidecar>(16);
        table
            .insert(
                channel,
                ChannelRoute {
                    lease: LeaseId(1),
                    agent: test_agent_id(),
                    sidecar: sidecar_tx,
                    kind: fleet_proto::ChannelKind::Data,
                },
            )
            .await;

        // Forward an opaque frame to the agent and read it back off the stream.
        let payload = DataFrame {
            channel,
            bytes: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };
        assert!(forward_to_agent(&table, &agent, payload.clone())
            .await
            .unwrap());
        let received: DataFrame = fleet_wire::recv(&mut agent_remote).await.unwrap();
        assert_eq!(received, payload);

        drop(agent);
        writer.await.unwrap();
    }
}
