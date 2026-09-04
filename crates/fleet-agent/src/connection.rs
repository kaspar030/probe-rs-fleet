//! The dial-out control-plane connection (architecture §5).
//!
//! The agent opens **one** persistent `WebSocket` connection *out* to the
//! coordinator (`wss://…/agent`) and holds it; all coordinator→agent commands
//! travel back down it, so the Pi needs no inbound ports. Over the connection
//! the agent registers, reports inventory, heartbeats, and dispatches
//! [`CoordinatorCommand`]s to the [`Agent`]; the opaque data plane is
//! multiplexed alongside.
//!
//! What ships here: the reconnect-with-backoff policy, the dial via
//! `fleet_wire::client::dial` (which presents the node's bearer token on the
//! upgrade), ping/pong keepalive, node-token rotation, and the live control +
//! data multiplex — register, inventory, heartbeat, command dispatch through the
//! [`Agent`] handlers, and per-channel `DataFrame` splicing onto each session's
//! `probe-rs serve` socket (or gdb stub).
//!
//! # Why keepalive and backoff stopped being niceties
//!
//! The hosted deployment puts an HTTPS reverse proxy in front of the
//! coordinator, and a proxy reaps idle `WebSocket`s on a timeout nobody here
//! controls. A lab node is idle most of the time, so without ping/pong the
//! control plane would evaporate every few minutes; and when a connection does
//! drop, the whole fleet drops together, so the backoff carries **jitter** to
//! avoid a synchronised reconnect stampede against a coordinator that has just
//! restarted.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Mutex};

use crate::agent::Agent;
use crate::config::{AgentConfig, NodeTokenStore};
use crate::error::{AgentError, Result};
use crate::probers::ProbeRsBackend;

use fleet_proto::agent_api::AgentReport;
use fleet_proto::{ChannelId, ChannelKind, CoordinatorCommand, DataFrame, PROTOCOL_VERSION};
use fleet_wire::client::{dial, DialOpts};
use fleet_wire::{AgentToCoord, CoordToAgent, WireError, WireEvent, WireRx, WireTx};

/// How often the agent pings an otherwise idle connection.
///
/// Shorter than any plausible proxy idle timeout, and shorter than the
/// coordinator's own interval, so the connection stays warm even if the
/// coordinator's pings are the ones being dropped.
const PING_INTERVAL: Duration = Duration::from_secs(20);

/// How long the agent tolerates silence before declaring the connection dead.
const SILENCE_TIMEOUT: Duration = Duration::from_secs(90);

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

/// Apply ±20% jitter to a backoff delay.
///
/// Every node in a fleet loses its connection at the same instant when the
/// coordinator restarts. Without jitter they all come back at the same instant
/// too, and keep doing so on every doubling — turning a restart into a
/// self-inflicted thundering herd. Jitter is cheap and there is no reason for
/// the retries to be synchronised.
fn jittered(delay: Duration) -> Duration {
    // A coarse, dependency-free source of variation: nanosecond-resolution
    // wall-clock noise is plenty for spreading retries and needs no RNG.
    let noise = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::from(d.subsec_nanos()));
    let millis = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
    if millis == 0 {
        return delay;
    }
    let spread = millis / 5; // 20%
    if spread == 0 {
        return delay;
    }
    let offset = noise % (spread * 2 + 1);
    Duration::from_millis(millis + offset - spread)
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

/// Whether a failed connection should be retried immediately with the node's
/// *previous* token instead of backing off.
///
/// This exists to close exactly one window: the agent persisted a rotated token
/// and acked it, but the ack was lost, so the coordinator still holds the old
/// hash while this node holds the new one. Retrying once with the previous token
/// recovers without any server state.
///
/// `already_tried` is what makes it *once*. Without it the retry is unbounded:
/// [`AgentConfig::fall_back_to_previous_token`] merely swaps the two tokens and
/// keeps returning `true`, and `previous_node_token` is only cleared after a
/// **successful** dial — so when both tokens are rejected (a genuine revocation,
/// which is precisely the case an operator most needs to see) the loop would
/// alternate them forever at TCP-connect rate, never reaching the backoff and
/// emitting a warning per iteration.
fn should_fall_back(e: &AgentError, already_tried: bool) -> bool {
    matches!(e, AgentError::CredentialRejected(_)) && !already_tried
}

/// Run the persistent dial-out connection loop: connect, serve, reconnect with
/// backoff on failure.
///
/// This is the agent's main runtime entrypoint. It owns the lifecycle of one
/// logical connection to the coordinator and restarts it forever (until the
/// process is asked to stop).
///
/// The `config` is owned and mutable because a node token can be **rotated**
/// mid-connection: the coordinator pushes a replacement, the agent writes it
/// down through `store` and acks, and the next dial uses the new one. Where the
/// token is written is `fleet-bin`'s business (see [`NodeTokenStore`]); this
/// crate only knows it must be durable before the ack.
///
/// # Errors
///
/// Returns an error only on a non-retryable setup failure. Transient connection
/// failures are retried internally.
pub async fn run<B: ProbeRsBackend + 'static>(
    agent: Arc<Agent<B>>,
    config: AgentConfig,
    store: Arc<dyn NodeTokenStore>,
) -> Result<()> {
    let mut config = config;
    let mut backoff = Backoff::default();
    // Reset on every successful dial, so the one-shot fallback is once *per
    // connection*, not once for the lifetime of the process.
    let mut fallback_used = false;

    loop {
        let mut connected = false;
        match connect_and_serve(&agent, &mut config, &store, &mut connected).await {
            Ok(()) => {
                // Clean disconnect: reset backoff and immediately retry.
                backoff.reset(Duration::from_millis(500));
                fallback_used = false;
            }
            Err(e) => {
                if connected {
                    fallback_used = false;
                }
                if should_fall_back(&e, fallback_used) && config.fall_back_to_previous_token() {
                    // The coordinator refused our current token but we hold a
                    // previous one — the signature of a rotation whose *ack*
                    // was lost, leaving the coordinator on the old hash. Retry
                    // immediately with it rather than backing off into a state
                    // that only a physical visit can fix.
                    fallback_used = true;
                    tracing::warn!(
                        "node token rejected; retrying once with the pre-rotation token"
                    );
                    continue;
                }
                let delay = jittered(backoff.next_delay());
                tracing::warn!(error = %e, retry_in = ?delay, "connection lost; backing off");
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// One connection lifetime: dial, register, then serve commands + heartbeats
/// until the connection drops.
///
/// `connected` is set once the dial succeeds, so the caller can tell a
/// credential rejection (we never got in) from a connection that worked and then
/// dropped — which is what makes the one-shot fallback *per connection* rather
/// than once per process lifetime.
///
/// # Errors
///
/// Returns [`AgentError::Connection`] when the connection cannot be established
/// or drops, and [`AgentError::CredentialRejected`] when the coordinator refused
/// the node token.
async fn connect_and_serve<B: ProbeRsBackend + 'static>(
    agent: &Arc<Agent<B>>,
    config: &mut AgentConfig,
    store: &Arc<dyn NodeTokenStore>,
    connected: &mut bool,
) -> Result<()> {
    let (tx, rx) = dial(DialOpts {
        url: config.fleet_url.clone(),
        path: "/agent",
        bearer: config.node_token.clone(),
        pin: config.server_pin(),
    })
    .await
    .map_err(|e| classify_dial_error(&e))?;
    *connected = true;

    // The dial succeeded, so this token works: the previous one is dead weight
    // and keeping it would widen the window in which a stale credential is on
    // disk.
    if config.previous_node_token.take().is_some() {
        if let Err(e) = store.clear_previous() {
            tracing::debug!(error = %e, "could not clear the superseded node token");
        }
    }

    serve_connection(agent, config, store, Box::new(tx), Box::new(rx)).await
}

/// Distinguish "the coordinator refused our credential" from "the network
/// failed", because the remediation is completely different and a bare 401 in a
/// log is exactly the thing an operator cannot act on.
///
/// **This matches on substrings of tungstenite's `Display` output**, because its
/// `Error::Http` variant carries the response but the dial helper has already
/// collapsed it to a `WireError::Protocol(String)` — deliberately, so callers
/// cannot branch on a status they should not be reasoning about. The cost is a
/// dependency on an upstream error's *format*: if a tungstenite bump changes how
/// `Http` renders, this silently degrades to classifying every rejection as a
/// network failure, and a revoked node then retries forever with a generic
/// "connection lost" instead of the re-enroll remediation. Check it when bumping
/// tungstenite; `classify_dial_error_recognises_auth_rejections` pins the shapes
/// we rely on.
fn classify_dial_error(e: &WireError) -> AgentError {
    let text = e.to_string();
    if text.contains("401") || text.contains("403") || text.contains("Unauthorized") {
        return AgentError::CredentialRejected(text);
    }
    AgentError::Connection(format!("dialing coordinator: {text}"))
}

/// Drive one established connection: register, report inventory, then run the
/// control + data multiplex loop until the connection drops.
///
/// Generic over the wire halves so it is exercised over an in-memory pair in
/// tests, without any HTTP or TLS.
///
/// # Errors
///
/// Returns [`AgentError::Connection`] when a message cannot be read/written (the
/// caller reconnects with backoff).
#[doc(hidden)]
pub async fn serve_connection<B>(
    agent: &Arc<Agent<B>>,
    config: &mut AgentConfig,
    store: &Arc<dyn NodeTokenStore>,
    tx: Box<dyn WireTx + Send>,
    rx: Box<dyn WireRx + Send>,
) -> Result<()>
where
    B: ProbeRsBackend + 'static,
{
    let mut rx = rx;
    // Single writer task: every producer (register/inventory/heartbeat, drained
    // reports, and per-channel splice tasks) funnels `AgentToCoord` messages
    // through this mpsc so only one task owns the write half. Pings ride their
    // own channel so a backlog of data frames cannot starve the keepalive.
    let (out_tx, mut out_rx) = mpsc::channel::<AgentToCoord>(256);
    let (ping_tx, mut ping_rx) = mpsc::channel::<()>(1);
    let writer_task = tokio::spawn(async move {
        let mut tx = tx;
        loop {
            tokio::select! {
                msg = out_rx.recv() => {
                    let Some(msg) = msg else { break };
                    if fleet_wire::send(&mut *tx, &msg).await.is_err() {
                        break;
                    }
                }
                ping = ping_rx.recv() => {
                    if ping.is_none() || tx.send_ping().await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = tx.close().await;
    });

    // 1. Register. The id is advisory — the coordinator authenticates us by our
    //    token and will close the connection if this contradicts it.
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
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await;
    let started = std::time::Instant::now();
    let mut last_seen = tokio::time::Instant::now();

    let result = loop {
        tokio::select! {
            // Inbound control / data messages from the coordinator.
            event = rx.recv() => {
                last_seen = tokio::time::Instant::now();
                match event {
                    Ok(WireEvent::Binary(bytes)) => {
                        match fleet_wire::decode::<CoordToAgent>(&bytes) {
                            Ok(CoordToAgent::Command(cmd)) => {
                                handle_inbound_command(agent, config, store, &out_tx, &routes, cmd).await;
                            }
                            Ok(CoordToAgent::Data(data)) => {
                                route_inbound_data(&routes, data).await;
                            }
                            Err(e) => {
                                break Err(AgentError::Connection(format!("decode failed: {e}")));
                            }
                        }
                    }
                    // Liveness only; the timestamp above is the point.
                    Ok(WireEvent::Pong) => {}
                    Ok(WireEvent::Closed) => {
                        break Err(AgentError::Connection("coordinator closed the connection".to_owned()));
                    }
                    Err(e) => break Err(AgentError::Connection(format!("read failed: {e}"))),
                }
            }
            // Heartbeat tick (an application-level report, distinct from the
            // transport-level ping below: this one tells the coordinator the
            // *agent* is healthy, not merely that the socket is open).
            _ = heartbeat.tick() => {
                let uptime_secs = started.elapsed().as_secs();
                if send_report(&out_tx, AgentReport::Heartbeat { uptime_secs }).await.is_err() {
                    break Err(AgentError::Connection("writer closed".to_owned()));
                }
            }
            // Keepalive tick.
            _ = ping.tick() => {
                if last_seen.elapsed() > SILENCE_TIMEOUT {
                    break Err(AgentError::Connection(
                        "no traffic from the coordinator within the liveness deadline".to_owned(),
                    ));
                }
                if ping_tx.send(()).await.is_err() {
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
    config: &mut AgentConfig,
    store: &Arc<dyn NodeTokenStore>,
    out_tx: &mpsc::Sender<AgentToCoord>,
    routes: &Arc<Mutex<HashMap<ChannelId, mpsc::Sender<DataFrame>>>>,
    cmd: CoordinatorCommand,
) {
    // Token rotation is handled here rather than in the agent's command
    // handlers because it touches the *connection's* configuration, not the
    // board state the handlers own.
    if let CoordinatorCommand::RotateNodeToken {
        token,
        rotation_id,
    } = &cmd
    {
        rotate_token(config, store, out_tx, token, *rotation_id).await;
        return;
    }

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

/// Persist a pushed replacement node token, then acknowledge it.
///
/// **Persist before acking, always.** The coordinator keeps the old token
/// authoritative until this ack arrives, so the only divergence this ordering
/// can produce is "node has the new token, coordinator still has the old" —
/// which the retained previous token recovers from on the next dial. Acking
/// first would allow the opposite, where the coordinator retires a token the
/// node never managed to write, and that one needs a person with a keyboard
/// standing next to the Pi.
async fn rotate_token(
    config: &mut AgentConfig,
    store: &Arc<dyn NodeTokenStore>,
    out_tx: &mpsc::Sender<AgentToCoord>,
    token: &str,
    rotation_id: u64,
) {
    // Write first, then adopt in memory: if the store fails we must still be
    // holding the token the coordinator considers current.
    if let Err(e) = store.persist(token, Some(config.node_token.as_str())) {
        // Not acked: the coordinator keeps the old token, which we also still
        // hold in memory, so the connection survives and rotation is retried.
        tracing::warn!(error = %e, "failed to persist a rotated node token; not acking");
        return;
    }
    let previous = std::mem::replace(&mut config.node_token, token.to_owned());
    config.previous_node_token = Some(previous);
    if send_report(out_tx, AgentReport::TokenRotated { rotation_id })
        .await
        .is_err()
    {
        tracing::warn!("could not acknowledge the token rotation; will retry on reconnect");
    } else {
        tracing::info!(rotation_id, "node token rotated");
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
    use fleet_proto::{ChannelId, LeaseId};
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
        AgentConfig {
            agent_id: "pi-1".to_owned(),
            fleet_url: "https://coordinator.example:7000".to_owned(),
            node_token: "prfn1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            previous_node_token: None,
            server_cert_sha256: None,
            coordinator_token_pubkey: pubkey_hex,
            boards_path: std::path::PathBuf::from("/boards.toml"),
            heartbeat_secs: 1,
            erase_on_release: false,
        }
    }

    /// An in-memory [`NodeTokenStore`], standing in for the fleet file that
    /// `fleet-bin` supplies in production. It records what was written so a test
    /// can assert the persist-before-ack ordering the real store exists for.
    #[derive(Debug, Default)]
    struct MemoryStore {
        current: std::sync::Mutex<Option<String>>,
        previous: std::sync::Mutex<Option<String>>,
    }

    impl NodeTokenStore for MemoryStore {
        fn persist(&self, new_token: &str, previous: Option<&str>) -> std::result::Result<(), String> {
            *self.current.lock().unwrap() = Some(new_token.to_owned());
            *self.previous.lock().unwrap() = previous.map(ToOwned::to_owned);
            Ok(())
        }

        fn clear_previous(&self) -> std::result::Result<(), String> {
            *self.previous.lock().unwrap() = None;
            Ok(())
        }
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

    /// The fleet-unique key the coordinator mints for one of this node's
    /// boards; the token is scoped to it and the agent matches it verbatim.
    fn board_ref(name: &str) -> fleet_proto::BoardRef {
        fleet_proto::BoardRef::new(
            fleet_proto::OrgId("default".to_owned()),
            fleet_proto::AgentId("pi-1".to_owned()),
            name,
        )
    }

    fn signed_token(lease: u64, board: &str, ops: Vec<AllowedOp>, expires: u64) -> Vec<u8> {
        let token = CapabilityToken {
            lease: LeaseId(lease),
            board: board_ref(board),
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

        // The agent's dial-out connection speaks over one half of an in-memory
        // wire pair; the test plays the coordinator on the other.
        let (agent_tx, agent_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();
        let mut config = agent_config();
        let store: Arc<dyn NodeTokenStore> = Arc::new(MemoryStore::default());
        let agent_task = {
            let agent = Arc::clone(&agent);
            tokio::spawn(async move {
                let _ = serve_connection(
                    &agent,
                    &mut config,
                    &store,
                    Box::new(agent_tx),
                    Box::new(agent_rx),
                )
                .await;
            })
        };

        // 1. Register.
        match fleet_wire::recv::<AgentToCoord>(&mut coord_rx).await.unwrap() {
            AgentToCoord::Report(AgentReport::Register { agent, protocol_version }) => {
                assert_eq!(agent.0, "pi-1");
                assert_eq!(protocol_version, PROTOCOL_VERSION);
            }
            other => panic!("expected Register, got {other:?}"),
        }
        // 2. Inventory (one online board with full metadata).
        match fleet_wire::recv::<AgentToCoord>(&mut coord_rx).await.unwrap() {
            AgentToCoord::Report(AgentReport::Inventory(inv)) => {
                assert_eq!(inv.boards.len(), 1);
                assert_eq!(inv.boards[0].board.0, "b1");
                assert_eq!(inv.boards[0].chip, "nRF52840_xxAA");
            }
            other => panic!("expected Inventory, got {other:?}"),
        }

        // 3. Command the agent to open a data session on channel 1.
        let token = signed_token(7, "b1", vec![AllowedOp::Attach], u64::MAX);
        fleet_wire::send(
            &mut coord_tx,
            &CoordToAgent::Command(CoordinatorCommand::OpenSession {
                lease: LeaseId(7),
                board: board_ref("b1"),
                token,
                channel: ChannelId(1),
                kind: ChannelKind::Data,
            }),
        )
        .await
        .unwrap();

        // The agent emits a Log report acknowledging the open; wait until the
        // splice peer is wired.
        let peer = loop {
            if let Some(p) = peer_slot.lock().await.take() {
                break p;
            }
            tokio::task::yield_now().await;
        };
        let mut peer = peer;

        // 4. Data round-trip: coordinator -> agent -> serve socket.
        fleet_wire::send(
            &mut coord_tx,
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
            match fleet_wire::recv::<AgentToCoord>(&mut coord_rx).await.unwrap() {
                AgentToCoord::Data(f) => break f,
                AgentToCoord::Report(_) => {}
            }
        };
        assert_eq!(data.channel, ChannelId(1));
        assert_eq!(data.bytes, b"pong");

        agent_task.abort();
    }

    /// A pushed rotation is persisted to disk **before** it is acknowledged, so
    /// the only reachable divergence is the one the retained previous token
    /// recovers from. Acking a token that was never written is what would strand
    /// a headless node.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rotation_persists_before_acking() {
        let memory = Arc::new(MemoryStore::default());
        let store: Arc<dyn NodeTokenStore> = Arc::clone(&memory) as Arc<dyn NodeTokenStore>;
        let mut config = agent_config();
        let original = config.node_token.clone();

        let backend = Arc::new(DuplexBackend {
            peer: Arc::new(tokio::sync::Mutex::new(None)),
        });
        let agent = Arc::new(Agent::new(agent_config(), boards(), backend).unwrap());
        agent.seed_inventory_from_boards().await;

        let (agent_tx, agent_rx, mut coord_tx, mut coord_rx) = fleet_wire::mock::pair();
        let task = {
            let agent = Arc::clone(&agent);
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                let _ = serve_connection(
                    &agent,
                    &mut config,
                    &store,
                    Box::new(agent_tx),
                    Box::new(agent_rx),
                )
                .await;
            })
        };

        // Drain Register + Inventory.
        let _ = fleet_wire::recv::<AgentToCoord>(&mut coord_rx).await.unwrap();
        let _ = fleet_wire::recv::<AgentToCoord>(&mut coord_rx).await.unwrap();

        let new_token = "prfn1_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        fleet_wire::send(
            &mut coord_tx,
            &CoordToAgent::Command(CoordinatorCommand::RotateNodeToken {
                token: new_token.to_owned(),
                rotation_id: 7,
            }),
        )
        .await
        .unwrap();

        // The ack arrives ...
        let ack = loop {
            if let AgentToCoord::Report(AgentReport::TokenRotated { rotation_id }) =
                fleet_wire::recv::<AgentToCoord>(&mut coord_rx).await.unwrap()
            {
                break rotation_id;
            }
        };
        assert_eq!(ack, 7);

        // ... and by the time it did, the new token was already persisted, with
        // the old one retained for the lost-ack retry.
        assert_eq!(
            memory.current.lock().unwrap().as_deref(),
            Some(new_token)
        );
        assert_eq!(
            memory.previous.lock().unwrap().as_deref(),
            Some(original.as_str())
        );

        task.abort();
    }

    /// Jitter must stay within ±20% of the requested delay: it exists to
    /// desynchronise a fleet's reconnects, not to change the backoff schedule.
    #[test]
    fn jitter_stays_within_twenty_percent() {
        for base_ms in [100u64, 500, 1_000, 30_000] {
            let base = Duration::from_millis(base_ms);
            for _ in 0..50 {
                let j = jittered(base);
                let spread = base_ms / 5;
                assert!(
                    j >= Duration::from_millis(base_ms - spread)
                        && j <= Duration::from_millis(base_ms + spread),
                    "{j:?} outside ±20% of {base:?}"
                );
            }
        }
        // Degenerate inputs must not panic or produce nonsense.
        assert_eq!(jittered(Duration::ZERO), Duration::ZERO);
        assert_eq!(jittered(Duration::from_millis(1)), Duration::from_millis(1));
    }

    /// **Regression: the "one-shot" fallback must actually be once.**
    ///
    /// `fall_back_to_previous_token` only swaps the two tokens and keeps
    /// returning `true`, and `previous_node_token` is cleared only after a
    /// *successful* dial. So without the `already_tried` gate, a node whose
    /// credential was genuinely revoked — both tokens rejected — would alternate
    /// them forever at TCP-connect rate, never reaching the backoff, emitting a
    /// warning per iteration. That is the case an operator most needs to see, so
    /// it must fall through to the jittered backoff instead.
    #[test]
    fn credential_fallback_is_attempted_at_most_once() {
        let rejected = AgentError::CredentialRejected("401".to_owned());

        // First rejection after a connection: try the previous token.
        assert!(should_fall_back(&rejected, false));
        // Second in a row: back off instead of hot-looping.
        assert!(!should_fall_back(&rejected, true));
    }

    /// A network failure is never a reason to swap credentials: the token is
    /// fine, the network is not, and rotating through tokens would only muddy
    /// which one the coordinator last accepted.
    #[test]
    fn a_network_failure_does_not_trigger_the_credential_fallback() {
        let network = AgentError::Connection("connection refused".to_owned());
        assert!(!should_fall_back(&network, false));
        assert!(!should_fall_back(&network, true));
    }

    /// Simulates the loop's bookkeeping across a revocation: two rejections must
    /// produce exactly one fallback, then backoff. Before the fix this ran
    /// forever.
    #[test]
    fn a_revoked_node_stops_falling_back_and_reaches_the_backoff() {
        let mut cfg = agent_config();
        cfg.previous_node_token = Some("prfn1_old".to_owned());

        let rejected = AgentError::CredentialRejected("401 Unauthorized".to_owned());
        let mut fallback_used = false;
        let mut fallbacks = 0;

        // Ten consecutive rejections, as a revoked node would see.
        for _ in 0..10 {
            if should_fall_back(&rejected, fallback_used) && cfg.fall_back_to_previous_token() {
                fallback_used = true;
                fallbacks += 1;
                continue;
            }
            // Reached the backoff arm.
            break;
        }
        assert_eq!(fallbacks, 1, "exactly one fallback, then back off");
    }

    /// The counter is per *connection*, not per process: a node that connects,
    /// serves, drops, and is later rejected must still get its one retry.
    #[test]
    fn a_successful_connection_re_arms_the_fallback() {
        let rejected = AgentError::CredentialRejected("401".to_owned());
        let mut fallback_used = false;

        assert!(should_fall_back(&rejected, fallback_used));
        fallback_used = true;
        assert!(!should_fall_back(&rejected, fallback_used));

        // A dial succeeded (the loop clears the flag on `connected`).
        fallback_used = false;
        assert!(should_fall_back(&rejected, fallback_used));
    }

    /// The substring classification this relies on. If a tungstenite bump breaks
    /// these shapes, a revoked node degrades to "connection lost" forever and
    /// the operator never sees the re-enroll remediation.
    #[test]
    fn classify_dial_error_recognises_auth_rejections() {
        for text in [
            "HTTP error: 401 Unauthorized",
            "HTTP error: 403 Forbidden",
            "Unauthorized",
        ] {
            assert!(
                matches!(
                    classify_dial_error(&fleet_wire::WireError::Protocol(text.to_owned())),
                    AgentError::CredentialRejected(_)
                ),
                "`{text}` must classify as a credential rejection"
            );
        }

        // ... and a genuine network failure must not.
        assert!(matches!(
            classify_dial_error(&fleet_wire::WireError::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "connection refused"
            ))),
            AgentError::Connection(_)
        ));
    }

    /// The remediation text is the whole point of the distinct variant: a bare
    /// 401 is what an operator cannot act on.
    #[test]
    fn credential_rejection_names_the_remedy() {
        let rendered = AgentError::CredentialRejected("401".to_owned()).to_string();
        assert!(rendered.contains("agent init"), "got: {rendered}");
        assert!(rendered.contains("--auth-key"), "got: {rendered}");
    }
}
