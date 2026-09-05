//! The live `WebSocket` + byte-opaque relay transport for the sidecar's fleet
//! path.
//!
//! This is the concrete implementation of the relay seam described in
//! [`crate::proxy`]: it dials the coordinator's `/client` route (presenting a
//! bearer token on the upgrade), leases a board, opens a relay data (or gdb)
//! channel, exposes a local endpoint the genuine probe-rs client connects to,
//! and byte-splices the two verbatim. The sidecar never parses the relayed
//! frames — it is a pure byte pipe.
//!
//! The control plane and the data plane share one `WebSocket`, multiplexed by
//! the [`fleet_wire`] envelopes. A single reader task demultiplexes coordinator
//! replies (control) from relayed [`fleet_proto::DataFrame`]s (data), routing
//! the latter to the active channel's splice.

use std::path::Path;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

use fleet_proto::lease::{LeaseGrant, LeaseRequest};
use fleet_proto::{ChannelId, ChannelKind, DataFrame, PROTOCOL_VERSION};
use fleet_wire::client::{dial, DialOpts};
use fleet_wire::{CoordToSidecar, SidecarToCoord, WireEvent, WireRx, WireTx};

use crate::selector::FleetConfig;

/// Errors from the live relay transport.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// A TLS material / config failure.
    #[error("tls error: {0}")]
    Tls(String),
    /// A connection / handshake failure.
    #[error("connection error: {0}")]
    Connect(String),
    /// A wire framing failure.
    #[error("wire error: {0}")]
    Wire(String),
    /// The coordinator declined a request.
    #[error("coordinator declined: {0}")]
    Declined(String),
    /// A local endpoint / splice I/O failure.
    #[error("io error: {0}")]
    Io(String),
}

/// The active relay channel's data sink: when set, the reader routes inbound
/// `Data` frames for that channel to the splice.
type DataSink = Arc<Mutex<Option<(ChannelId, mpsc::Sender<DataFrame>)>>>;

/// A connected, post-handshake coordinator session for the sidecar.
///
/// Owns the single writer half plus a router that demultiplexes control replies
/// from relayed data frames. Drop it to tear the connection down.
pub struct CoordSession {
    /// Funnels outbound `SidecarToCoord` frames to the writer task.
    out_tx: mpsc::Sender<SidecarToCoord>,
    /// Control replies (everything that is not a `Data` frame).
    ctrl_rx: Mutex<mpsc::Receiver<CoordToSidecar>>,
    /// Set the active channel's data sink so the reader routes `Data` frames.
    data_sink: DataSink,
}

impl CoordSession {
    /// Dial the coordinator's `/client` route and complete the Hello handshake.
    ///
    /// The bearer token rides the `WebSocket` upgrade; there is no client
    /// certificate. Trust configuration (`WebPKI` roots, or the optional pinned
    /// server-cert hash) is shared with every other outbound connection in the
    /// tree via `fleet_tls::client_trust_config`.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] on a TLS, connection, or version mismatch.
    pub async fn connect(cfg: &FleetConfig) -> Result<Self, TransportError> {
        let (tx, rx) = dial(DialOpts {
            url: cfg.coordinator.clone(),
            path: "/client",
            bearer: cfg.token.clone(),
            pin: cfg.server_pin(),
        })
        .await
        .map_err(|e| TransportError::Connect(format!("dialing {}: {e}", cfg.coordinator)))?;
        Self::start(Box::new(tx), Box::new(rx)).await
    }

    /// Start the reader/writer tasks over established wire halves and complete
    /// the Hello/Welcome exchange. Generic so it is testable over an in-memory
    /// pair.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] on a framing failure or version mismatch.
    pub async fn start(
        tx: Box<dyn WireTx + Send>,
        rx: Box<dyn WireRx + Send>,
    ) -> Result<Self, TransportError> {
        let mut rx = rx;
        let (out_tx, mut out_rx) = mpsc::channel::<SidecarToCoord>(256);
        tokio::spawn(async move {
            let mut tx = tx;
            while let Some(msg) = out_rx.recv().await {
                if fleet_wire::send(&mut *tx, &msg).await.is_err() {
                    break;
                }
            }
            let _ = tx.close().await;
        });

        // Hello / Welcome handshake.
        out_tx
            .send(SidecarToCoord::Hello {
                protocol_version: PROTOCOL_VERSION,
            })
            .await
            .map_err(|_| TransportError::Connect("writer closed".to_owned()))?;
        match fleet_wire::recv::<CoordToSidecar>(&mut *rx).await {
            Ok(CoordToSidecar::Welcome { protocol_version }) => {
                if protocol_version != PROTOCOL_VERSION {
                    return Err(TransportError::Connect(format!(
                        "protocol mismatch: coordinator={protocol_version} sidecar={PROTOCOL_VERSION}"
                    )));
                }
            }
            Ok(CoordToSidecar::Error { message }) => return Err(TransportError::Declined(message)),
            Ok(other) => {
                return Err(TransportError::Wire(format!("expected Welcome, got {other:?}")))
            }
            Err(e) => return Err(TransportError::Wire(format!("reading Welcome: {e}"))),
        }

        let (ctrl_tx, ctrl_rx) = mpsc::channel::<CoordToSidecar>(256);
        let data_sink: DataSink = Arc::new(Mutex::new(None));
        let sink = Arc::clone(&data_sink);
        tokio::spawn(async move {
            loop {
                let Ok(event) = rx.recv().await else { break };
                let bytes = match event {
                    WireEvent::Binary(bytes) => bytes,
                    // Liveness only; the coordinator pings an idle connection so
                    // a proxy does not reap it mid-flash.
                    WireEvent::Pong => continue,
                    WireEvent::Closed => break,
                };
                match fleet_wire::decode::<CoordToSidecar>(&bytes) {
                    Ok(CoordToSidecar::Data(frame)) => {
                        let route = {
                            let guard = sink.lock().await;
                            match &*guard {
                                Some((ch, tx)) if *ch == frame.channel => Some(tx.clone()),
                                _ => None,
                            }
                        };
                        if let Some(tx) = route {
                            let _ = tx.send(frame).await;
                        }
                    }
                    Ok(other) => {
                        if ctrl_tx.send(other).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            out_tx,
            ctrl_rx: Mutex::new(ctrl_rx),
            data_sink,
        })
    }

    /// Send a control message to the coordinator.
    async fn send(&self, msg: SidecarToCoord) -> Result<(), TransportError> {
        self.out_tx
            .send(msg)
            .await
            .map_err(|_| TransportError::Connect("connection closed".to_owned()))
    }

    /// Await the next control reply from the coordinator.
    async fn next_ctrl(&self) -> Result<CoordToSidecar, TransportError> {
        self.ctrl_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| TransportError::Connect("connection closed".to_owned()))
    }

    /// Send one operator request and await its reply.
    ///
    /// The door `ctl` uses. Before revision 2 `ctl` hand-rolled a second
    /// coordinator client — its own TLS config, its own `server_name`, its own
    /// Hello handshake — which is how three near-identical dial paths drifted
    /// apart. There is now one client, and `ctl` is a caller of it.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`] if the connection fails.
    pub async fn request(
        &self,
        msg: SidecarToCoord,
    ) -> Result<CoordToSidecar, TransportError> {
        self.send(msg).await?;
        self.next_ctrl().await
    }

    /// Request a lease for `request`, returning the grant.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Declined`] if the request is queued or refused.
    pub async fn lease(&self, request: &LeaseRequest) -> Result<LeaseGrant, TransportError> {
        self.send(SidecarToCoord::Lease(request.clone())).await?;
        match self.next_ctrl().await? {
            CoordToSidecar::Lease(grant) => Ok(grant),
            CoordToSidecar::Queued { position } => Err(TransportError::Declined(format!(
                "board contended; queued at position {position}"
            ))),
            CoordToSidecar::Error { message } => Err(TransportError::Declined(message)),
            other => Err(TransportError::Wire(format!("expected Lease, got {other:?}"))),
        }
    }

    /// Release a held lease (best-effort).
    pub async fn release(&self, lease: fleet_proto::LeaseId) {
        let _ = self.send(SidecarToCoord::Release { lease }).await;
        // Drain the Released ack if it arrives promptly; ignore failures.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), self.next_ctrl()).await;
    }

    /// Open a relay channel of `kind` for `lease`, returning the channel id
    /// **and the data-plane capability token** the coordinator handed the
    /// owning agent.
    ///
    /// The token is the credential the genuine probe-rs client must present to
    /// `probe-rs serve` (`PROBE_RS_REMOTE_TOKEN`). It is deliberately *not*
    /// `LeaseGrant::token`: the two are different mints and diverge after an
    /// `Extend`, or whenever a grant attenuates the allowed ops.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Declined`] if the coordinator refuses.
    pub async fn open_channel(
        &self,
        lease: fleet_proto::LeaseId,
        kind: ChannelKind,
    ) -> Result<(ChannelId, Vec<u8>), TransportError> {
        self.send(SidecarToCoord::OpenChannel { lease, kind }).await?;
        match self.next_ctrl().await? {
            CoordToSidecar::ChannelOpened { channel, token } => Ok((channel, token)),
            CoordToSidecar::Error { message } => Err(TransportError::Declined(message)),
            other => Err(TransportError::Wire(format!(
                "expected ChannelOpened, got {other:?}"
            ))),
        }
    }

    /// Route relayed data frames for `channel` to `sink` (replacing any prior
    /// active channel sink).
    async fn set_data_sink(&self, channel: ChannelId, sink: mpsc::Sender<DataFrame>) {
        *self.data_sink.lock().await = Some((channel, sink));
    }

    /// Send opaque data bytes to the owning agent over `channel`.
    async fn send_data(&self, frame: DataFrame) -> Result<(), TransportError> {
        self.send(SidecarToCoord::Data(frame)).await
    }
}

/// Splice a local client stream onto an opened relay `channel`: copy bytes
/// verbatim in both directions until either side closes.
///
/// The caller must have already called [`CoordSession::open_channel`] and is
/// responsible for the lease lifecycle. Returns when the client closes, the
/// relay closes, or an I/O error occurs.
///
/// # Errors
///
/// Returns [`TransportError::Io`] on a local stream read/write failure.
pub async fn splice_client<S>(
    session: &CoordSession,
    channel: ChannelId,
    mut client: S,
) -> Result<(), TransportError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (data_tx, mut data_rx) = mpsc::channel::<DataFrame>(256);
    session.set_data_sink(channel, data_tx).await;

    let mut buf = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            read = client.read(&mut buf) => {
                let n = read.map_err(|e| TransportError::Io(format!("client read failed: {e}")))?;
                if n == 0 {
                    return Ok(());
                }
                let frame = DataFrame { channel, bytes: buf[..n].to_vec() };
                if session.send_data(frame).await.is_err() {
                    return Ok(());
                }
            }
            inbound = data_rx.recv() => {
                let Some(frame) = inbound else { return Ok(()); };
                client
                    .write_all(&frame.bytes)
                    .await
                    .map_err(|e| TransportError::Io(format!("client write failed: {e}")))?;
                client
                    .flush()
                    .await
                    .map_err(|e| TransportError::Io(format!("client flush failed: {e}")))?;
            }
        }
    }
}

/// Hex-encode bytes (for the lease token presented to the local probe-rs
/// client via `PROBE_RS_REMOTE_TOKEN`).
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Locate the real `probe-rs` binary, skipping our own shim (delegates to the
/// existing local resolver).
///
/// # Errors
///
/// Returns [`TransportError::Io`] if no real probe-rs is found.
pub fn find_real_probe_rs() -> Result<std::path::PathBuf, TransportError> {
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    let path_var = path_var.to_string_lossy();
    let self_exe = std::env::current_exe().ok();
    crate::local::find_real_probe_rs(&path_var, self_exe.as_deref())
        .map_err(|e| TransportError::Io(format!("locating probe-rs: {e}")))
}

/// Run the genuine probe-rs (async) pointed at `remote_host` (a `ws://` base
/// URL like `ws://127.0.0.1:<port>`) with the lease `token`, propagating its
/// exit code.
///
/// # Errors
///
/// Returns [`TransportError::Io`] if the child cannot be spawned / awaited.
pub async fn exec_remote_probe_rs(
    real: &Path,
    args: &[String],
    remote_host: &str,
    token: &str,
) -> Result<i32, TransportError> {
    let mut cmd = tokio::process::Command::new(real);
    cmd.args(args);
    cmd.env(crate::local::remote_env::HOST, remote_host);
    cmd.env(crate::local::remote_env::TOKEN, token);
    let status = cmd
        .status()
        .await
        .map_err(|e| TransportError::Io(format!("spawning probe-rs: {e}")))?;
    Ok(status.code().unwrap_or_else(|| {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            status.signal().map_or(1, |sig| 128 + sig)
        }
        #[cfg(not(unix))]
        {
            1
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_roundtrips() {
        assert_eq!(hex_encode(&[0x00, 0xde, 0xad, 0xff]), "00deadff");
    }

    /// The pin is decoded from the resolved config, so a self-hosted
    /// deployment's `--server-cert-sha256` reaches the dialer as bytes.
    #[test]
    fn fleet_config_decodes_its_pin() {
        let cfg = FleetConfig {
            coordinator: "https://c:1".to_owned(),
            token: "prfs1_t".to_owned(),
            select: fleet_proto::lease::Constraint::Board(fleet_proto::ids::BoardName(
                "b".to_owned(),
            )),
            server_cert_sha256: Some("cd".repeat(32)),
        };
        assert_eq!(cfg.server_pin(), Some([0xcdu8; 32]));

        let unpinned = FleetConfig {
            server_cert_sha256: None,
            ..cfg
        };
        assert!(unpinned.server_pin().is_none());
    }

    /// End-to-end sidecar transport over an in-memory duplex against a
    /// hand-rolled coordinator peer: Hello/Welcome, `Lease`, `OpenChannel`, then
    /// a client byte-splice round-trip in both directions.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[allow(clippy::too_many_lines)]
    async fn session_leases_opens_channel_and_splices() {
        use fleet_proto::ids::{AgentId, BoardName, BoardRef, OrgId, Subject, SubjectKind};
        use fleet_proto::lease::{Constraint, LeaseGrant, LeaseRequest, Priority};
        use fleet_proto::LeaseId;

        // The coordinator answers with a fleet-unique board key; the request
        // side stays node-local.
        let board_ref = BoardRef::new(
            OrgId("default".to_owned()),
            AgentId("a".to_owned()),
            "b1",
        );

        let (sc_tx, sc_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();

        // Coordinator peer task: Welcome -> Lease grant -> ChannelOpened ->
        // echo any Data frame back on the same channel.
        let board_ref_for_peer = board_ref.clone();
        let coord = tokio::spawn(async move {
            // Hello -> Welcome.
            match fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await.unwrap() {
                SidecarToCoord::Hello { protocol_version } => {
                    assert_eq!(protocol_version, PROTOCOL_VERSION);
                }
                other => panic!("expected Hello, got {other:?}"),
            }
            fleet_wire::send(
                &mut coord_tx,
                &CoordToSidecar::Welcome {
                    protocol_version: PROTOCOL_VERSION,
                },
            )
            .await
            .unwrap();

            // Lease.
            match fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await.unwrap() {
                SidecarToCoord::Lease(_) => {}
                other => panic!("expected Lease, got {other:?}"),
            }
            fleet_wire::send(
                &mut coord_tx,
                &CoordToSidecar::Lease(LeaseGrant {
                    lease: LeaseId(1),
                    board: board_ref_for_peer.clone(),
                    agent: AgentId("a".to_owned()),
                    holder: Subject::new(
                        OrgId("default".to_owned()),
                        SubjectKind::User,
                        "p",
                    ),
                    expires: 9999,
                    token: vec![0xab, 0xcd],
                }),
            )
            .await
            .unwrap();

            // OpenChannel -> ChannelOpened(7).
            match fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await.unwrap() {
                SidecarToCoord::OpenChannel { lease, kind } => {
                    assert_eq!(lease, LeaseId(1));
                    assert_eq!(kind, ChannelKind::Data);
                }
                other => panic!("expected OpenChannel, got {other:?}"),
            }
            fleet_wire::send(
                &mut coord_tx,
                &CoordToSidecar::ChannelOpened {
                    channel: ChannelId(7),
                    token: vec![0x11, 0x22],
                },
            )
            .await
            .unwrap();

            // Echo the next Data frame back (relay agent stand-in).
            match fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await.unwrap() {
                SidecarToCoord::Data(frame) => {
                    assert_eq!(frame.channel, ChannelId(7));
                    fleet_wire::send(&mut coord_tx, &CoordToSidecar::Data(frame))
                        .await
                        .unwrap();
                }
                other => panic!("expected Data, got {other:?}"),
            }
            // Keep the connection open until the test drops it.
            let _ = fleet_wire::recv::<SidecarToCoord>(&mut coord_rx).await;
        });

        let session = CoordSession::start(Box::new(sc_tx), Box::new(sc_rx))
            .await
            .unwrap();
        let grant = session
            .lease(&LeaseRequest {
                select: Constraint::Board(BoardName("b1".to_owned())),
                duration_secs: 600,
                priority: Priority::Interactive,
            })
            .await
            .unwrap();
        assert_eq!(grant.board, board_ref);
        let (channel, channel_token) = session
            .open_channel(grant.lease, ChannelKind::Data)
            .await
            .unwrap();
        assert_eq!(channel, ChannelId(7));
        // The channel token is the coordinator's own, not the lease grant's.
        assert_eq!(channel_token, vec![0x11, 0x22]);
        assert_ne!(channel_token, grant.token);

        // A local "probe-rs client" over a duplex; the splice copies bytes to
        // the relay and the coordinator echoes them back.
        let (mut client, client_peer) = tokio::io::duplex(4096);
        let splice = tokio::spawn(async move {
            let _ = splice_client(&session, channel, client_peer).await;
        });
        client.write_all(b"hello-board").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0u8; 11];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello-board");

        drop(client);
        let _ = splice.await;
        coord.abort();
    }
}
