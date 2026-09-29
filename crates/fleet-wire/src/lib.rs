//! `WebSocket` framing + the control-plane envelopes.
//!
//! This crate is the shared **wire substrate** between the coordinator, nodes,
//! and sidecars. It holds two things:
//!
//! 1. A **codec over `WebSocket` binary messages** ([`encode`] / [`decode`])
//!    plus the [`WireTx`] / [`WireRx`] traits every role speaks. Each
//!    control-plane message is one postcard-encoded binary `WebSocket` message.
//!    Revision 2 (architecture §3.5) moved the transport to WSS so it can sit
//!    behind an ordinary HTTPS reverse proxy; the old `u32`-LE length prefix is
//!    gone because `WebSocket` already delimits messages.
//! 2. The **control-plane envelopes** for both planes: the node direction
//!    ([`NodeToCoord`] / [`CoordToNode`]) and the sidecar direction
//!    ([`SidecarToCoord`] / [`CoordToSidecar`]). The payload types they wrap
//!    live in [`fleet_proto`]; the envelopes add an unambiguous discriminator
//!    so control and data frames demultiplex over one connection. **These are
//!    unchanged by the transport move** — that is the point of the seam.
//!
//! # Why traits rather than a concrete `WebSocket` type
//!
//! The coordinator serves `axum`'s `WebSocket`; the node, sidecar and ctl dial
//! with `tokio-tungstenite`. Abstracting over "a stream of binary messages"
//! rather than over one library's type is what lets `fleet-wire` — and
//! therefore `fleet-agent` and `fleet-sidecar` — stay free of `axum`. Those
//! crates are libraries that move probe bytes; requiring an HTTP *server*
//! framework to link them would be the dependency direction backwards. The
//! `axum` adapter lives in `fleet-coordinator`; the `tokio-tungstenite` one
//! lives here behind the `tungstenite` feature.

use fleet_proto::admin::{BoardSummary, GrantSummary, LeaseHolderSummary, LogLine, NodeSummary};
use fleet_proto::ids::BoardName;
use fleet_proto::lease::{Constraint, LeaseGrant, LeaseRequest};
use fleet_proto::node_api::{CoordinatorCommand, NodeReport};
use fleet_proto::token::AllowedOp;
use fleet_proto::{ChannelId, ChannelKind, DataFrame, LeaseId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[cfg(feature = "tungstenite")]
pub mod client;
#[cfg(feature = "tungstenite")]
pub mod tungstenite;

/// Maximum encoded message length either end will accept, to bound memory on a
/// hostile or corrupt peer.
///
/// Data-plane frames are small probe-rs chunks; 16 MiB is far above any
/// legitimate control or data message but below a flash image someone might one
/// day push in one go. **Both ends must configure their `WebSocket` stack with
/// this same limit** (`WebSocketConfig::max_message_size`): tungstenite and axum
/// carry their own defaults, and letting them diverge from this constant means a
/// large-but-legal message fails only in production.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Errors from the wire codec and transport.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// An I/O failure (including a clean EOF, surfaced as `UnexpectedEof`).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A message could not be encoded/decoded, or violated a size bound.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The peer closed the connection.
    ///
    /// Distinguished from [`WireError::Io`] because short-lived clients (ctl,
    /// one-shot sidecar invocations) exit immediately after their RPC: a close
    /// is the *expected* end of such a connection, not a transport fault. See
    /// [`is_benign_close`].
    #[error("connection closed by peer")]
    Closed,
}

/// Whether an error is a benign, peer-initiated end of connection.
///
/// The `WebSocket` replacement for the old `close_notify`/`UnexpectedEof`
/// heuristic. `ctl` runs one request and exits, so every single `ctl list` would
/// otherwise log a transport warning on the coordinator.
#[must_use]
pub fn is_benign_close(e: &WireError) -> bool {
    match e {
        WireError::Closed => true,
        WireError::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::BrokenPipe
        ),
        WireError::Protocol(_) => false,
    }
}

/// Encode `value` as the payload of one binary `WebSocket` message.
///
/// # Errors
///
/// Returns [`WireError::Protocol`] if encoding fails or the encoded body
/// exceeds [`MAX_FRAME_LEN`].
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, WireError> {
    let body =
        postcard::to_allocvec(value).map_err(|e| WireError::Protocol(format!("encode: {e}")))?;
    if body.len() > MAX_FRAME_LEN {
        return Err(WireError::Protocol(format!(
            "frame too large: {} > {MAX_FRAME_LEN}",
            body.len()
        )));
    }
    Ok(body)
}

/// Decode the payload of one binary `WebSocket` message as `T`.
///
/// # Errors
///
/// Returns [`WireError::Protocol`] if the payload exceeds [`MAX_FRAME_LEN`] or
/// fails to decode.
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WireError> {
    if bytes.len() > MAX_FRAME_LEN {
        return Err(WireError::Protocol(format!(
            "frame too large: {} > {MAX_FRAME_LEN}",
            bytes.len()
        )));
    }
    postcard::from_bytes(bytes).map_err(|e| WireError::Protocol(format!("decode: {e}")))
}

/// The send half of a `WebSocket` control-plane connection.
///
/// Object-safe on purpose: the coordinator hands `Box<dyn WireTx>` to its
/// per-connection tasks so one code path serves both the axum and the
/// tungstenite adapter.
#[async_trait::async_trait]
pub trait WireTx: Send {
    /// Send one binary message.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if the connection is closed or the write fails.
    async fn send_bytes(&mut self, bytes: Vec<u8>) -> Result<(), WireError>;

    /// Send a `WebSocket` ping.
    ///
    /// Keepalive is load-bearing in the hosted deployment: a reverse proxy in
    /// front reaps idle `WebSocket`s on a timeout we do not control, and the
    /// node's connection is idle most of the time.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if the connection is closed or the write fails.
    async fn send_ping(&mut self) -> Result<(), WireError>;

    /// Close the connection gracefully.
    ///
    /// # Errors
    ///
    /// Returns [`WireError`] if the close frame cannot be written.
    async fn close(&mut self) -> Result<(), WireError>;
}

/// One inbound `WebSocket` event, after text and control frames are classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireEvent {
    /// A binary message payload (a postcard-encoded envelope).
    Binary(Vec<u8>),
    /// A pong, in reply to one of our pings. Surfaced so the caller can track
    /// liveness rather than merely hoping.
    Pong,
    /// The peer closed the connection.
    Closed,
}

/// The receive half of a `WebSocket` control-plane connection.
#[async_trait::async_trait]
pub trait WireRx: Send {
    /// Await the next inbound event.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Protocol`] for a text or oversized message (this
    /// protocol is binary-only) and [`WireError::Io`] on a transport failure.
    async fn recv(&mut self) -> Result<WireEvent, WireError>;
}

/// Encode and send one control-plane message.
///
/// # Errors
///
/// Returns [`WireError`] if encoding or the write fails.
pub async fn send<T: Serialize + Sync>(
    tx: &mut (impl WireTx + ?Sized),
    value: &T,
) -> Result<(), WireError> {
    let bytes = encode(value)?;
    tx.send_bytes(bytes).await
}

/// Await the next *binary* message and decode it as `T`.
///
/// Pongs are skipped (they are liveness, not content); a close is reported as
/// [`WireError::Closed`]. Callers that need to observe pongs — the keepalive
/// loops — drive [`WireRx::recv`] directly.
///
/// # Errors
///
/// Returns [`WireError::Closed`] if the peer closed, and [`WireError::Protocol`]
/// on a malformed message.
pub async fn recv<T: DeserializeOwned>(rx: &mut (impl WireRx + ?Sized)) -> Result<T, WireError> {
    loop {
        match rx.recv().await? {
            WireEvent::Binary(bytes) => return decode(&bytes),
            WireEvent::Pong => {}
            WireEvent::Closed => return Err(WireError::Closed),
        }
    }
}

/// A framed message from a node up to the coordinator.
///
/// The node control plane multiplexes shared `fleet-proto` control payloads
/// ([`NodeReport`]) and opaque data-plane bytes ([`DataFrame`]) over one
/// length-delimited stream. Wrapping them in this envelope gives the reader an
/// unambiguous discriminator (the proto types themselves carry no tag
/// distinguishing a report from a data frame), mirroring the symmetric sidecar
/// plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeToCoord {
    /// A control-plane report.
    Report(NodeReport),
    /// Opaque data-plane bytes from a probe-rs session.
    Data(DataFrame),
}

/// A framed message from the coordinator down to a node.
///
/// The down-stream counterpart of [`NodeToCoord`]: it wraps a control command
/// ([`CoordinatorCommand`]) or an opaque [`DataFrame`] with a discriminator so
/// the node can demultiplex the two unambiguously.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoordToNode {
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
    /// Opaque data-plane bytes destined for the owning node.
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
        /// Restrict to a single board by its node-local name, if set. The
        /// coordinator resolves it within the caller's org.
        board: Option<BoardName>,
        /// Follow mode (advisory; v1 returns the current tail either way).
        #[serde(default)]
        follow: bool,
    },
    /// Operator: power-cycle a board (`ctl power-cycle`).
    PowerCycle {
        /// The board to power-cycle, by node-local name. The coordinator
        /// resolves it to a fleet key **among the boards the caller may
        /// reach** — their own org's first, then any a grant covers — so an
        /// unreachable board is reported exactly as an absent one.
        board: BoardName,
    },
    /// Share a subset of this org's boards with another subject
    /// (`grant <subject> --select … --ops …`). Admin-gated.
    GrantCreate {
        /// The grantee: a username, `repo:owner/name`, or a rendered
        /// `SubjectKey`. Resolved to an immutable subject coordinator-side.
        subject: String,
        /// The canonical selector string (see `Constraint`'s `Display`).
        selector: String,
        /// The operations conferred.
        ops: Vec<AllowedOp>,
        /// Expiry, epoch seconds. The `/client` path refuses `None`: an
        /// unbounded grant of someone else's hardware outlives its reason.
        expires: Option<u64>,
    },
    /// List this org's outbound grants (`grant list`). Membership suffices.
    GrantList,
    /// Revoke a grant by id prefix (`grant revoke <id>`). Creator or admin.
    GrantRevoke {
        /// The grant id, or a prefix of at least 8 hex characters (or `ci-`
        /// followed by 8, for the grant a CI auth key synthesised).
        id: String,
    },
    /// Lease a board as yourself and hand back only its capability token, for
    /// a sandboxed client (`ctl delegate`).
    ///
    /// Deliberately **not** a grant: it creates no principal and no fleet
    /// identity. Replies with the ordinary [`CoordToSidecar::Lease`] /
    /// [`CoordToSidecar::Queued`] / [`CoordToSidecar::NoCandidate`] /
    /// [`CoordToSidecar::AtCap`] / [`CoordToSidecar::Error`].
    ///
    /// A `Queued` reply here means "the board is busy", and **nothing was
    /// enqueued**: this verb hands a token to a sandbox and returns, so a
    /// waiter it left behind could be promoted onto a board nobody is holding.
    Delegate {
        /// Which board to lease.
        select: Constraint,
        /// Requested hold duration in seconds.
        duration_secs: u64,
        /// Ops to attenuate the handed-out token to, intersected with what the
        /// delegator may actually do.
        ops: Vec<AllowedOp>,
    },
    /// Operator: list the org's machines and their tags (`ctl nodes`).
    ///
    /// Authorized by the same `require_role(Member)` check the browser API's
    /// `GET /api/v1/nodes` goes through, because it dispatches to the same
    /// `list_nodes_core`: the CLI and the web UI cannot drift on who may see a
    /// node.
    ///
    /// Appended at the **end** of the enum rather than placed next to
    /// [`SidecarToCoord::ListBoards`] where it belongs semantically: postcard
    /// is positional, so inserting a variant renumbers every later one.
    ListNodes,
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
    /// Matching boards exist in the caller's reach but all are busy: the
    /// request was queued, and the caller will be sent a
    /// [`CoordToSidecar::Lease`] if it is promoted before it gives up.
    ///
    /// Position is 0-based, among waiters for the same constraint.
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
        /// The **exact wire bytes** of the capability token the coordinator
        /// sent the owning node in its `OpenSession` command.
        ///
        /// This is the per-channel **authorization** credential the node
        /// verifies (`fleet-agent`'s `token::verify_wire`), and it is what the
        /// sidecar cross-checks the board of on a reused lease. It is minted
        /// afresh per channel and re-attenuated to the holder's current
        /// effective ops, so it changes across an `Extend` or a narrowed
        /// grant. It is **not** [`fleet_proto::LeaseGrant::token`], and since
        /// protocol 11 it is no longer what `probe-rs serve` accepts either —
        /// that is `serve_token`.
        ///
        /// Before this field existed the two mints matched only by
        /// coincidence: both produced `{lease, board, <all ops>, expires}` and
        /// ed25519 signing is deterministic. That coincidence already broke
        /// after an `Extend` (which rewrites the expiry `open_channel` reads)
        /// and breaks by construction once grants attenuate `allowed_ops`.
        /// Carrying the bytes removes the whole class of "two mints must be
        /// byte-identical" bugs.
        token: Vec<u8>,
        /// The `probe-rs serve` user token, lowercase hex.
        ///
        /// The data-plane credential proper: the sidecar exports exactly this
        /// string as `PROBE_RS_REMOTE_TOKEN`, and the node writes exactly this
        /// string into the board's `.probe-rs.toml`. Scoped to the **lease**,
        /// not the channel, because the node reuses one `probe-rs serve`
        /// process across a holder's many invocations and Figment reads that
        /// config once at startup.
        ///
        /// Never hex-encode it again — it is already the exact string both
        /// ends must agree on.
        serve_token: String,
    },
    /// A channel was closed (by request, node, or lease expiry).
    ChannelClosed {
        /// The channel that closed.
        channel: ChannelId,
    },
    /// Opaque data-plane bytes relayed from the owning node.
    Data(DataFrame),
    /// Operator: the fleet inventory (reply to [`SidecarToCoord::ListBoards`]).
    BoardList(Vec<BoardSummary>),
    /// Operator: the current lease table (reply to [`SidecarToCoord::Who`]).
    LeaseTable(Vec<LeaseHolderSummary>),
    /// Operator: recent audit/log lines (reply to [`SidecarToCoord::Logs`]).
    LogLines(Vec<LogLine>),
    /// Operator: acknowledgement of a power-cycle request.
    PowerCycled {
        /// The board that was power-cycled (node-local name, as requested).
        board: BoardName,
    },
    /// An error in response to a sidecar request.
    Error {
        /// Human-readable error description.
        message: String,
    },
    /// A grant was created (reply to [`SidecarToCoord::GrantCreate`]).
    GrantCreated(GrantSummary),
    /// This org's outbound grants (reply to [`SidecarToCoord::GrantList`]).
    Grants(Vec<GrantSummary>),
    /// Grants were revoked (reply to [`SidecarToCoord::GrantRevoke`]).
    GrantRevoked {
        /// The ids deleted.
        ids: Vec<String>,
    },
    /// Nothing the caller may reach matches the selector at all — whatever its
    /// state. Distinct from [`CoordToSidecar::Queued`]: waiting cannot help,
    /// and nothing was queued.
    ///
    /// Appended at the **end** of the enum rather than placed next to `Queued`
    /// where it belongs semantically: postcard is positional, so inserting a
    /// variant renumbers every later one. Appending is the cheap edit; the
    /// protocol bump this pair costs is the same either way.
    NoCandidate {
        /// The selector as the coordinator parsed it, in `Constraint`'s
        /// canonical `Display` form, so the client can echo back exactly what
        /// was asked for.
        selector: String,
        /// How many boards the caller can reach at all.
        reachable: u32,
    },
    /// The caller is already at its `max_concurrent_per_subject` budget, so
    /// the selector was never evaluated. Nothing was queued.
    AtCap {
        /// Leases the caller currently holds.
        held: u32,
        /// The configured cap.
        cap: u32,
    },
    /// Operator: the org's machines (reply to [`SidecarToCoord::ListNodes`]).
    ///
    /// Appended at the end for the same reason [`CoordToSidecar::NoCandidate`]
    /// is, rather than sitting next to [`CoordToSidecar::BoardList`]: postcard
    /// is positional, so inserting renumbers every later variant.
    NodeList(Vec<NodeSummary>),
}

/// An in-memory [`WireTx`] / [`WireRx`] pair, for tests.
///
/// Exposed (behind `cfg(any(test, feature = "test-util"))`) because every crate
/// that speaks the wire wants to drive its own read/write loops without a real
/// socket — which is how `serve_connection` and `handle_node` stay testable now
/// that the transport is a `WebSocket` rather than a duplex stream.
#[cfg(any(test, feature = "test-util"))]
pub mod mock {
    use super::{WireError, WireEvent, WireRx, WireTx};
    use tokio::sync::mpsc;

    /// The send half of a mock connection.
    pub struct MockTx {
        tx: mpsc::Sender<WireEvent>,
        /// Where our pings become the peer's pongs.
        pong_to: mpsc::Sender<WireEvent>,
    }

    /// The receive half of a mock connection.
    pub struct MockRx {
        rx: mpsc::Receiver<WireEvent>,
    }

    /// Build a connected pair of mock endpoints: `(a_tx, a_rx, b_tx, b_rx)`.
    ///
    /// Bytes sent on `a_tx` arrive on `b_rx` and vice versa. A ping sent on one
    /// side is answered with a pong to the *sender's* own receiver, mirroring
    /// tungstenite's automatic pong.
    #[must_use]
    pub fn pair() -> (MockTx, MockRx, MockTx, MockRx) {
        let (a_out, b_in) = mpsc::channel(64);
        let (b_out, a_in) = mpsc::channel(64);
        (
            MockTx {
                tx: a_out.clone(),
                pong_to: b_out.clone(),
            },
            MockRx { rx: a_in },
            MockTx {
                tx: b_out,
                pong_to: a_out,
            },
            MockRx { rx: b_in },
        )
    }

    #[async_trait::async_trait]
    impl WireTx for MockTx {
        async fn send_bytes(&mut self, bytes: Vec<u8>) -> Result<(), WireError> {
            self.tx
                .send(WireEvent::Binary(bytes))
                .await
                .map_err(|_| WireError::Closed)
        }

        async fn send_ping(&mut self) -> Result<(), WireError> {
            self.pong_to
                .send(WireEvent::Pong)
                .await
                .map_err(|_| WireError::Closed)
        }

        async fn close(&mut self) -> Result<(), WireError> {
            let _ = self.tx.send(WireEvent::Closed).await;
            Ok(())
        }
    }

    #[async_trait::async_trait]
    impl WireRx for MockRx {
        async fn recv(&mut self) -> Result<WireEvent, WireError> {
            Ok(self.rx.recv().await.unwrap_or(WireEvent::Closed))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::admin::NodeSummary;
    use fleet_proto::ids::{BoardRef, NodeId, OrgId};
    use fleet_proto::lease::Priority;
    use fleet_proto::node_api::{CoordinatorCommand, NodeReport};

    fn test_board_ref() -> BoardRef {
        BoardRef::new(
            OrgId("default".to_owned()),
            NodeId("node-a".to_owned()),
            "b1",
        )
    }

    /// The `ctl nodes` request verb round-trips, in the style of the
    /// `ListBoards` assertion below.
    #[tokio::test]
    async fn list_nodes_request_roundtrip() {
        let (mut a_tx, _a_rx, _b_tx, mut b_rx) = mock::pair();
        send(&mut a_tx, &SidecarToCoord::ListNodes).await.unwrap();
        assert_eq!(
            recv::<SidecarToCoord>(&mut b_rx).await.unwrap(),
            SidecarToCoord::ListNodes
        );
    }

    /// The reply carries the fields `ctl nodes` renders: tags, adopt policy,
    /// a never-connected `last_seen`, and the node's board names.
    #[tokio::test]
    async fn node_list_reply_roundtrip() {
        let (mut a_tx, _a_rx, _b_tx, mut b_rx) = mock::pair();
        let msg = CoordToSidecar::NodeList(vec![NodeSummary {
            node: NodeId("default/beast".to_owned()),
            name: "beast".to_owned(),
            tags: vec!["desk".to_owned(), "nrf52".to_owned()],
            adopt: fleet_proto::AdoptPolicy::Auto,
            owner: Some("gh-1".to_owned()),
            last_seen: None,
            created_at: 1_700_000_000,
            online: true,
            boards: vec!["dk-1".to_owned(), "dk-2".to_owned()],
        }]);
        send(&mut a_tx, &msg).await.unwrap();
        assert_eq!(recv::<CoordToSidecar>(&mut b_rx).await.unwrap(), msg);
    }

    #[tokio::test]
    async fn sidecar_envelope_roundtrip() {
        let (mut a_tx, _a_rx, _b_tx, mut b_rx) = mock::pair();
        let msg = SidecarToCoord::Lease(LeaseRequest {
            select: Constraint::Id(BoardName("b1".to_owned())),
            duration_secs: 600,
            priority: Priority::Interactive,
        });
        send(&mut a_tx, &msg).await.unwrap();
        let back: SidecarToCoord = recv(&mut b_rx).await.unwrap();
        assert_eq!(back, msg);
    }

    #[tokio::test]
    async fn dataframe_roundtrip_both_directions() {
        let (mut a_tx, mut a_rx, mut b_tx, mut b_rx) = mock::pair();
        let frame = DataFrame {
            channel: ChannelId(5),
            bytes: vec![1, 2, 3, 4, 5],
        };
        send(&mut a_tx, &CoordToSidecar::Data(frame.clone()))
            .await
            .unwrap();
        let back: CoordToSidecar = recv(&mut b_rx).await.unwrap();
        assert_eq!(back, CoordToSidecar::Data(frame.clone()));

        send(&mut b_tx, &SidecarToCoord::Data(frame.clone()))
            .await
            .unwrap();
        let back: SidecarToCoord = recv(&mut a_rx).await.unwrap();
        assert_eq!(back, SidecarToCoord::Data(frame));
    }

    #[tokio::test]
    async fn node_envelopes_roundtrip_and_demux() {
        let (mut a_tx, _a_rx, _b_tx, mut b_rx) = mock::pair();
        let cmd = CoordToNode::Command(CoordinatorCommand::OpenSession {
            lease: LeaseId(1),
            board: test_board_ref(),
            token: vec![9, 9, 9],
            serve_token: "abc123".to_owned(),
            channel: ChannelId(2),
            kind: ChannelKind::Data,
        });
        let data = CoordToNode::Data(DataFrame {
            channel: ChannelId(2),
            bytes: vec![7, 7, 7],
        });
        send(&mut a_tx, &cmd).await.unwrap();
        send(&mut a_tx, &data).await.unwrap();
        assert_eq!(recv::<CoordToNode>(&mut b_rx).await.unwrap(), cmd);
        assert_eq!(recv::<CoordToNode>(&mut b_rx).await.unwrap(), data);

        let report = NodeToCoord::Report(NodeReport::Heartbeat { uptime_secs: 123 });
        send(&mut a_tx, &report).await.unwrap();
        assert_eq!(recv::<NodeToCoord>(&mut b_rx).await.unwrap(), report);
    }

    #[tokio::test]
    async fn multiple_messages_in_sequence() {
        let (mut a_tx, _a_rx, _b_tx, mut b_rx) = mock::pair();
        for i in 0..5u64 {
            send(&mut a_tx, &SidecarToCoord::Extend { lease: LeaseId(i) })
                .await
                .unwrap();
        }
        for i in 0..5u64 {
            let back: SidecarToCoord = recv(&mut b_rx).await.unwrap();
            assert_eq!(back, SidecarToCoord::Extend { lease: LeaseId(i) });
        }
    }

    /// A closed peer must surface as `Closed`, not as an opaque decode failure:
    /// this is what `is_benign_close` keys off so `ctl` exiting after one RPC is
    /// not logged as a fault.
    #[tokio::test]
    async fn peer_close_surfaces_as_closed_and_is_benign() {
        let (a_tx, _a_rx, b_tx, mut b_rx) = mock::pair();
        drop(a_tx);
        drop(b_tx);
        let err = recv::<SidecarToCoord>(&mut b_rx).await.unwrap_err();
        assert!(matches!(err, WireError::Closed));
        assert!(is_benign_close(&err));
        assert!(!is_benign_close(&WireError::Protocol("bad".to_owned())));
    }

    /// Pongs are liveness, not content: `recv` skips them so a keepalive reply
    /// arriving mid-conversation cannot be mistaken for a truncated envelope.
    #[tokio::test]
    async fn pongs_are_skipped_by_the_typed_receiver() {
        let (mut a_tx, mut a_rx, _b_tx, mut b_rx) = mock::pair();
        a_tx.send_ping().await.unwrap();
        send(&mut a_tx, &SidecarToCoord::ListBoards).await.unwrap();
        // The pong went back to the sender's own receiver, as tungstenite would.
        assert_eq!(a_rx.recv().await.unwrap(), WireEvent::Pong);
        assert_eq!(
            recv::<SidecarToCoord>(&mut b_rx).await.unwrap(),
            SidecarToCoord::ListBoards
        );
    }

    #[test]
    fn oversize_payloads_are_rejected_in_both_directions() {
        let too_big = vec![0u8; MAX_FRAME_LEN + 1];
        let err = decode::<SidecarToCoord>(&too_big).unwrap_err();
        assert!(matches!(err, WireError::Protocol(_)));

        // Encoding a legitimately oversized envelope is refused too, so an
        // over-large flash chunk fails here rather than at the WebSocket layer
        // with a less useful message.
        let huge = SidecarToCoord::Data(DataFrame {
            channel: ChannelId(1),
            bytes: vec![0u8; MAX_FRAME_LEN + 1],
        });
        assert!(matches!(encode(&huge), Err(WireError::Protocol(_))));
    }

    #[test]
    fn garbage_payload_is_a_protocol_error() {
        let err = decode::<CoordToNode>(&[0xFF, 0xFF, 0xFF]).unwrap_err();
        assert!(matches!(err, WireError::Protocol(_)));
    }
}
