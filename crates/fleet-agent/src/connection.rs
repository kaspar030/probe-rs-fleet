//! The dial-out control-plane connection (architecture §5).
//!
//! The agent opens **one** persistent mTLS connection *out* to the coordinator
//! and holds it; all coordinator→agent commands travel back down it, so the Pi
//! needs no inbound ports. Over the connection the agent registers, reports
//! inventory, heartbeats, and dispatches [`CoordinatorCommand`]s to the
//! [`Agent`]; the opaque data plane is multiplexed alongside.
//!
//! What ships here: the reconnect-with-backoff policy, the mTLS dial via
//! `fleet_tls::client_config`, and the live control + data multiplex — register,
//! inventory, heartbeat, command dispatch through the [`Agent`] handlers, and
//! per-channel `DataFrame` splicing onto each session's `probe-rs serve` socket
//! (or gdb stub). The shared length-delimited postcard framing + envelopes live
//! in [`fleet_wire`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsConnector;

use crate::agent::Agent;
use crate::config::AgentConfig;
use crate::error::{AgentError, Result};
use crate::probers::ProbeRsBackend;

use fleet_wire::{read_frame, write_frame, AgentToCoord, CoordToAgent};
use fleet_proto::agent_api::AgentReport;
use fleet_proto::{ChannelId, ChannelKind, CoordinatorCommand, DataFrame, PROTOCOL_VERSION};

/// Exponential-backoff schedule for reconnect attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    current: Duration,
    max: Duration,
    factor: u32,
}

impl Backoff {
    /// A backoff starting at `initial`, doubling up to `max`.
    #[must_use]
    pub fn new(initial: Duration, max: Duration) -> Self {
        Self {
            current: initial,
            max,
            factor: 2,
        }
    }

    /// The current delay.
    #[must_use]
    pub fn current(&self) -> Duration {
        self.current
    }

    /// Advance the backoff and return the delay to wait before the next try.
    pub fn next_delay(&mut self) -> Duration {
        let delay = self.current;
        self.current = (self.current * self.factor).min(self.max);
        delay
    }

    /// Reset to the initial delay (call after a successful connection).
    pub fn reset(&mut self, initial: Duration) {
        self.current = initial;
    }
}

impl Default for Backoff {
    fn default() -> Self {
        Self::new(Duration::from_millis(500), Duration::from_secs(30))
    }
}

/// Build the mTLS [`rustls::ClientConfig`] the agent dials out with.
///
/// Loads the agent's client cert/key and the coordinator-CA trust anchor from
/// the paths in `config`, then delegates to [`fleet_tls::client_config`].
///
/// # Errors
///
/// Returns [`AgentError::Connection`] if any PEM material fails to load or the
/// rustls config is rejected.
pub fn build_client_config(config: &AgentConfig) -> Result<rustls::ClientConfig> {
    let certs = fleet_tls::load_cert_chain(&config.tls_cert)
        .map_err(|e| AgentError::Connection(format!("loading agent cert: {e}")))?;
    let key = fleet_tls::load_private_key(&config.tls_key)
        .map_err(|e| AgentError::Connection(format!("loading agent key: {e}")))?;
    let ca = fleet_tls::load_root_store(&config.tls_ca)
        .map_err(|e| AgentError::Connection(format!("loading coordinator CA: {e}")))?;
    fleet_tls::client_config(certs, key, ca)
        .map_err(|e| AgentError::Connection(format!("building TLS client config: {e}")))
}

/// Routes a decoded [`CoordinatorCommand`] to the agent's handlers.
///
/// Extracted so command dispatch is unit-tested independently of the transport.
///
/// # Errors
///
/// Propagates the agent handler's error.
pub async fn dispatch_command<B: ProbeRsBackend>(
    agent: &Agent<B>,
    cmd: CoordinatorCommand,
) -> Result<()> {
    agent.handle_command(cmd).await
}

/// Run the persistent dial-out connection loop: connect, serve, reconnect with
/// backoff on failure.
///
/// This is the agent's main runtime entrypoint. It owns the lifecycle of one
/// logical connection to the coordinator and restarts it forever (until the
/// process is asked to stop).
///
/// # Errors
///
/// Returns an error only on a non-retryable setup failure (e.g. the TLS config
/// cannot be built). Transient connection failures are retried internally.
pub async fn run<B: ProbeRsBackend + 'static>(
    agent: Arc<Agent<B>>,
    config: AgentConfig,
) -> Result<()> {
    // Validate TLS material up front (non-retryable if misconfigured).
    let _tls = build_client_config(&config)?;
    let mut backoff = Backoff::default();

    loop {
        match connect_and_serve(&agent, &config).await {
            Ok(()) => {
                // Clean disconnect: reset backoff and immediately retry.
                backoff.reset(Duration::from_millis(500));
            }
            Err(e) => {
                let delay = backoff.next_delay();
                tracing::warn!(error = %e, retry_in = ?delay, "connection lost; backing off");
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// One connection lifetime: dial, register, then serve commands + heartbeats
/// until the connection drops.
///
/// # Errors
///
/// Returns [`AgentError::Connection`] when the connection cannot be established
/// or drops.
async fn connect_and_serve<B: ProbeRsBackend + 'static>(
    agent: &Arc<Agent<B>>,
    config: &AgentConfig,
) -> Result<()> {
    let tls = build_client_config(config)?;
    let connector = TlsConnector::from(Arc::new(tls));

    let tcp = tokio::net::TcpStream::connect(&config.coordinator_endpoint)
        .await
        .map_err(|e| {
            AgentError::Connection(format!(
                "connecting to coordinator {}: {e}",
                config.coordinator_endpoint
            ))
        })?;
    let _ = tcp.set_nodelay(true);

    let server_name = server_name(&config.coordinator_endpoint)?;
    let stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| AgentError::Connection(format!("TLS handshake failed: {e}")))?;

    let (reader, writer) = tokio::io::split(stream);
    serve_connection(agent, config, reader, writer).await
}

/// Derive a TLS `ServerName` from a `host:port` address (IP or DNS).
fn server_name(addr: &str) -> Result<rustls::pki_types::ServerName<'static>> {
    use rustls::pki_types::ServerName;
    let host = addr.rsplit_once(':').map_or(addr, |(h, _)| h);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }
    ServerName::try_from(host.to_owned())
        .map_err(|e| AgentError::Connection(format!("invalid server name '{host}': {e}")))
}

/// Drive one established connection: register, report inventory, then run the
/// control + data multiplex loop until the connection drops.
///
/// Generic over the stream halves so it is exercised over an in-memory duplex
/// in tests, without any TLS.
///
/// # Errors
///
/// Returns [`AgentError::Connection`] when a frame cannot be read/written (the
/// caller reconnects with backoff).
#[doc(hidden)]
pub async fn serve_connection<B, R, W>(
    agent: &Arc<Agent<B>>,
    config: &AgentConfig,
    mut reader: R,
    writer: W,
) -> Result<()>
where
    B: ProbeRsBackend + 'static,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // Single writer task: every producer (register/inventory/heartbeat, drained
    // reports, and per-channel splice tasks) funnels `AgentToCoord` frames
    // through this mpsc so only one task owns the write half.
    let (out_tx, mut out_rx) = mpsc::channel::<AgentToCoord>(256);
    let writer_task = tokio::spawn(async move {
        let mut writer = writer;
        while let Some(msg) = out_rx.recv().await {
            if write_frame(&mut writer, &msg).await.is_err() {
                break;
            }
        }
    });

    // 1. Register.
    let agent_id = fleet_proto::ids::AgentId(config.agent_id.clone());
    send_report(
        &out_tx,
        AgentReport::Register {
            agent: agent_id,
            protocol_version: PROTOCOL_VERSION,
        },
    )
    .await?;

    // 2. Report the current inventory snapshot so the coordinator populates its
    //    scheduler and the boards become leasable.
    let inventory = agent.current_inventory().await;
    send_report(&out_tx, AgentReport::Inventory(inventory)).await?;

    // Per-channel routing for inbound data frames: each open session's splice
    // task drains its own receiver.
    let routes: Arc<Mutex<HashMap<ChannelId, mpsc::Sender<DataFrame>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let mut heartbeat = tokio::time::interval(config.heartbeat_interval());
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The first tick fires immediately; skip it so we don't double-report.
    heartbeat.tick().await;
    let started = std::time::Instant::now();

    let result = loop {
        tokio::select! {
            // Inbound control / data frames from the coordinator.
            frame = read_frame::<_, CoordToAgent>(&mut reader) => {
                match frame {
                    Ok(CoordToAgent::Command(cmd)) => {
                        handle_inbound_command(agent, config, &out_tx, &routes, cmd).await;
                    }
                    Ok(CoordToAgent::Data(data)) => {
                        route_inbound_data(&routes, data).await;
                    }
                    Err(e) => break Err(AgentError::Connection(format!("read failed: {e}"))),
                }
            }
            // Heartbeat tick.
            _ = heartbeat.tick() => {
                let uptime_secs = started.elapsed().as_secs();
                if send_report(&out_tx, AgentReport::Heartbeat { uptime_secs }).await.is_err() {
                    break Err(AgentError::Connection("writer closed".to_owned()));
                }
            }
        }

        // After any handled message, drain queued reports the handlers emitted.
        if drain_reports(agent, &out_tx).await.is_err() {
            break Err(AgentError::Connection("writer closed".to_owned()));
        }
    };

    writer_task.abort();
    result
}

/// Send one report upward, mapping a closed writer to a connection error.
async fn send_report(out_tx: &mpsc::Sender<AgentToCoord>, report: AgentReport) -> Result<()> {
    out_tx
        .send(AgentToCoord::Report(report))
        .await
        .map_err(|_| AgentError::Connection("writer closed".to_owned()))
}

/// Drain any reports the agent queued and forward them upward.
async fn drain_reports<B: ProbeRsBackend>(
    agent: &Arc<Agent<B>>,
    out_tx: &mpsc::Sender<AgentToCoord>,
) -> Result<()> {
    for report in agent.take_reports().await {
        send_report(out_tx, report).await?;
    }
    Ok(())
}

/// Route an inbound data frame to the splice task owning its channel. A frame
/// for an unknown / closed channel is dropped.
async fn route_inbound_data(
    routes: &Arc<Mutex<HashMap<ChannelId, mpsc::Sender<DataFrame>>>>,
    frame: DataFrame,
) {
    let sender = routes.lock().await.get(&frame.channel).cloned();
    if let Some(sender) = sender {
        let _ = sender.send(frame).await;
    }
}

/// Handle one inbound coordinator command. `OpenSession` additionally wires the
/// new session's byte stream into a per-channel splice task; everything else is
/// dispatched through the (tested) command handlers.
async fn handle_inbound_command<B: ProbeRsBackend + 'static>(
    agent: &Arc<Agent<B>>,
    config: &AgentConfig,
    out_tx: &mpsc::Sender<AgentToCoord>,
    routes: &Arc<Mutex<HashMap<ChannelId, mpsc::Sender<DataFrame>>>>,
    cmd: CoordinatorCommand,
) {
    // Capture the channel/kind before dispatch so we can splice afterwards.
    let open = if let CoordinatorCommand::OpenSession { channel, kind, .. } = &cmd {
        Some((*channel, *kind))
    } else {
        None
    };
    let killed = if let CoordinatorCommand::KillSession { channel } = &cmd {
        Some(*channel)
    } else {
        None
    };

    if let Err(e) = dispatch_command(agent, cmd).await {
        tracing::warn!(error = %e, "command dispatch failed");
        // Surface the failure as a log report; the coordinator decides policy.
        let _ = out_tx
            .send(AgentToCoord::Report(AgentReport::Log {
                level: fleet_proto::LogLevel::Error,
                board: None,
                message: format!("command failed: {e}"),
            }))
            .await;
        return;
    }

    if let Some((channel, kind)) = open {
        spawn_splice(agent, config, out_tx, routes, channel, kind).await;
    }
    if let Some(channel) = killed {
        routes.lock().await.remove(&channel);
    }
}

/// Spawn the per-channel splice task for a freshly opened session, wiring its
/// byte stream to a relay channel. The data plane splices the `probe-rs serve`
/// socket; the gdb plane splices the board-local `probe-rs gdb` TCP stub.
async fn spawn_splice<B: ProbeRsBackend + 'static>(
    agent: &Arc<Agent<B>>,
    _config: &AgentConfig,
    out_tx: &mpsc::Sender<AgentToCoord>,
    routes: &Arc<Mutex<HashMap<ChannelId, mpsc::Sender<DataFrame>>>>,
    channel: ChannelId,
    kind: ChannelKind,
) {
    let (to_session_tx, to_session_rx) = mpsc::channel::<DataFrame>(256);
    routes.lock().await.insert(channel, to_session_tx);

    let out_tx = out_tx.clone();
    let routes = Arc::clone(routes);
    let io: Option<Box<dyn crate::probers::SpliceIo>> = match kind {
        ChannelKind::Data => agent.take_data_io(channel).await,
        ChannelKind::Gdb => agent
            .take_gdb_io(channel)
            .await
            .map(|s| Box::new(s) as Box<dyn crate::probers::SpliceIo>),
    };
    let Some(io) = io else {
        routes.lock().await.remove(&channel);
        return;
    };
    tokio::spawn(async move {
        let _ = splice_io(channel, io, out_tx, to_session_rx).await;
        routes.lock().await.remove(&channel);
    });
}

/// Bidirectionally splice a session's byte stream with the relay data channel.
///
/// * Bytes read from `io` (← `probe-rs serve`) are wrapped as `DataFrame` and
///   sent up as `AgentToCoord::Data` (→ coordinator → sidecar → probe-rs
///   client).
/// * `DataFrame`s arriving on `from_relay` (← the client) are written to `io`.
///
/// Returns when either side closes or an I/O error occurs.
async fn splice_io(
    channel: ChannelId,
    io: Box<dyn crate::probers::SpliceIo>,
    out_tx: mpsc::Sender<AgentToCoord>,
    mut from_relay: mpsc::Receiver<DataFrame>,
) -> std::result::Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut io = io;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            read = io.read(&mut buf) => {
                let n = read.map_err(|e| format!("serve socket read failed: {e}"))?;
                if n == 0 {
                    return Ok(());
                }
                let frame = DataFrame { channel, bytes: buf[..n].to_vec() };
                if out_tx.send(AgentToCoord::Data(frame)).await.is_err() {
                    return Ok(());
                }
            }
            inbound = from_relay.recv() => {
                let Some(frame) = inbound else {
                    return Ok(());
                };
                io.write_all(&frame.bytes)
                    .await
                    .map_err(|e| format!("serve socket write failed: {e}"))?;
                io.flush()
                    .await
                    .map_err(|e| format!("serve socket flush failed: {e}"))?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_caps() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_millis(800));
        assert_eq!(b.next_delay(), Duration::from_millis(100));
        assert_eq!(b.next_delay(), Duration::from_millis(200));
        assert_eq!(b.next_delay(), Duration::from_millis(400));
        assert_eq!(b.next_delay(), Duration::from_millis(800));
        // Capped.
        assert_eq!(b.next_delay(), Duration::from_millis(800));
    }

    #[test]
    fn backoff_reset_returns_to_initial() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(10));
        b.next_delay();
        b.next_delay();
        b.reset(Duration::from_millis(100));
        assert_eq!(b.current(), Duration::from_millis(100));
    }

    #[test]
    fn default_backoff_starts_at_500ms() {
        let b = Backoff::default();
        assert_eq!(b.current(), Duration::from_millis(500));
    }

    // --- Live wire integration: drive `serve_connection` (the real agent
    // dial-out multiplex) against a hand-rolled coordinator peer over an
    // in-memory duplex. Exercises register, inventory, OpenSession -> splice,
    // and a DataFrame round-trip through the mock serve socket. ---

    use crate::agent::Agent;
    use crate::probers::mock::MockSession;
    use crate::probers::{ProbeRsBackend, Session};
    use ed25519_dalek::{Signer, SigningKey};
    use fleet_proto::token::{AllowedOp, CapabilityToken, SignedToken};
    use fleet_proto::{BoardId, ChannelId, LeaseId};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SEED: [u8; 32] = [3u8; 32];

    fn hex_encode(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    fn agent_config() -> AgentConfig {
        let pubkey_hex = hex_encode(&SigningKey::from_bytes(&SEED).verifying_key().to_bytes());
        let toml = format!(
            r#"
agent_id = "pi-1"
coordinator_endpoint = "c:1"
tls_cert = "/c.pem"
tls_key = "/k.pem"
tls_ca = "/ca.pem"
coordinator_token_pubkey = "{pubkey_hex}"
boards_path = "/boards.toml"
heartbeat_secs = 1
"#
        );
        AgentConfig::from_str(&toml).unwrap()
    }

    fn boards() -> crate::config::BoardsConfig {
        crate::config::BoardsConfig::from_str(
            r#"
[[board]]
id = "b1"
serial = "S1"
chip = "nRF52840_xxAA"
tags = ["nrf52"]
[board.power]
kind = "none"
"#,
        )
        .unwrap()
    }

    fn signed_token(lease: u64, board: &str, ops: Vec<AllowedOp>, expires: u64) -> Vec<u8> {
        let token = CapabilityToken {
            lease: LeaseId(lease),
            board: BoardId(board.to_owned()),
            allowed_ops: ops,
            expires,
        };
        let key = SigningKey::from_bytes(&SEED);
        let bytes = token.serialize_for_signing().unwrap();
        let sig = key.sign(&bytes);
        SignedToken {
            token_bytes: bytes,
            signature: sig.to_bytes(),
        }
        .to_wire()
    }

    /// A backend that hands out a [`MockSession`] pre-wired with an in-memory
    /// duplex, exposing the peer half so the test can drive the "serve socket".
    struct DuplexBackend {
        peer: Arc<tokio::sync::Mutex<Option<tokio::io::DuplexStream>>>,
    }

    #[async_trait::async_trait]
    impl ProbeRsBackend for DuplexBackend {
        async fn open(
            &self,
            board: &crate::config::BoardSpec,
            _serve_token: &str,
        ) -> std::result::Result<Box<dyn Session>, String> {
            let (session, peer) = MockSession::with_io(board.id.clone());
            *self.peer.lock().await = Some(peer);
            Ok(Box::new(session) as Box<dyn Session>)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_connection_registers_reports_inventory_and_splices_data() {
        let peer_slot = Arc::new(tokio::sync::Mutex::new(None));
        let backend = Arc::new(DuplexBackend {
            peer: Arc::clone(&peer_slot),
        });
        let agent = Arc::new(Agent::new(agent_config(), boards(), backend).unwrap());
        agent.seed_inventory_from_boards().await;

        // The agent's dial-out connection speaks over `agent_side`; the test
        // plays the coordinator on `coord_side`.
        let (agent_side, coord_side) = tokio::io::duplex(8192);
        let (agent_reader, agent_writer) = tokio::io::split(agent_side);
        let config = agent_config();
        let agent_task = {
            let agent = Arc::clone(&agent);
            tokio::spawn(async move {
                let _ = serve_connection(&agent, &config, agent_reader, agent_writer).await;
            })
        };

        let (mut coord_reader, mut coord_writer) = tokio::io::split(coord_side);

        // 1. Register.
        match read_frame::<_, AgentToCoord>(&mut coord_reader).await.unwrap() {
            AgentToCoord::Report(AgentReport::Register { agent, protocol_version }) => {
                assert_eq!(agent.0, "pi-1");
                assert_eq!(protocol_version, PROTOCOL_VERSION);
            }
            other => panic!("expected Register, got {other:?}"),
        }
        // 2. Inventory (one online board with full metadata).
        match read_frame::<_, AgentToCoord>(&mut coord_reader).await.unwrap() {
            AgentToCoord::Report(AgentReport::Inventory(inv)) => {
                assert_eq!(inv.boards.len(), 1);
                assert_eq!(inv.boards[0].board.0, "b1");
                assert_eq!(inv.boards[0].chip, "nRF52840_xxAA");
            }
            other => panic!("expected Inventory, got {other:?}"),
        }

        // 3. Command the agent to open a data session on channel 1.
        let token = signed_token(7, "b1", vec![AllowedOp::Attach], u64::MAX);
        write_frame(
            &mut coord_writer,
            &CoordToAgent::Command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: BoardId("b1".to_owned()),
                token,
                channel: ChannelId(1),
                kind: ChannelKind::Data,
            }),
        )
        .await
        .unwrap();

        // The agent emits a Log report acknowledging the open; drain reports
        // until the splice peer is wired.
        let peer = loop {
            if let Some(p) = peer_slot.lock().await.take() {
                break p;
            }
            tokio::task::yield_now().await;
        };
        let mut peer = peer;

        // 4. Data round-trip: coordinator -> agent -> serve socket.
        write_frame(
            &mut coord_writer,
            &CoordToAgent::Data(DataFrame {
                channel: ChannelId(1),
                bytes: b"ping".to_vec(),
            }),
        )
        .await
        .unwrap();
        let mut buf = [0u8; 4];
        peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        // 5. Data round-trip: serve socket -> agent -> coordinator.
        peer.write_all(b"pong").await.unwrap();
        peer.flush().await.unwrap();
        // Skip any interleaved Log reports; assert the data frame arrives.
        let data = loop {
            match read_frame::<_, AgentToCoord>(&mut coord_reader).await.unwrap() {
                AgentToCoord::Data(f) => break f,
                AgentToCoord::Report(_) => {}
            }
        };
        assert_eq!(data.channel, ChannelId(1));
        assert_eq!(data.bytes, b"pong");

        drop(coord_writer);
        drop(coord_reader);
        agent_task.abort();
    }
}
