//! Per-connection handling for both `WebSocket` planes.
//!
//! Since revision 2 (architecture §3.5) the coordinator is an HTTP server:
//! [`crate::http`] owns the routes, authenticates the bearer credential, and
//! upgrades. This module is what runs *after* the upgrade — the reader/writer
//! pumps, the keepalive, and node-token rotation — and it is generic over
//! [`WireTx`] / [`WireRx`] so the same code serves an axum socket in production
//! and a `tokio-tungstenite` one in tests.
//!
//! The lease/relay decision logic is factored into [`crate::core::Coordinator`],
//! which is unaffected by the transport: that is what the `Subject` seam bought.
//!
//! # Keepalive
//!
//! Both planes ping. A reverse proxy in front reaps idle `WebSocket`s on a
//! timeout we do not control, and a node's connection is idle most of the time,
//! so keepalive is not a nicety here: without it the fleet's control plane
//! disappears every few minutes and the agent's reconnect backoff becomes the
//! primary mechanism rather than the fallback.
//!
//! # Node-token rotation (ack-then-retire)
//!
//! When a node's token is older than the policy allows, the coordinator mints a
//! replacement, **holds it in memory**, and pushes it. The database keeps the
//! *old* hash until the node acks with
//! [`AgentReport::TokenRotated`]. See `fleet_auth::rotation` for why eagerly
//! retiring the old token is the wrong trade on hardware nobody can walk up to.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

use fleet_auth::{OpaqueToken, TokenKind};
use fleet_proto::agent_api::AgentReport;
use fleet_proto::ids::{AgentId, Subject};
use fleet_proto::PROTOCOL_VERSION;
use fleet_wire::{WireError, WireEvent, WireRx, WireTx};

use crate::core::Coordinator;
use crate::error::{CoordinatorError, Result};
use crate::proto::{AgentToCoord, CoordToAgent, CoordToSidecar, SidecarToCoord};
use crate::registry::{AgentHandle, AgentMessage};
use crate::state::AuditEntry;

/// A boxed send half.
pub type BoxTx = Box<dyn WireTx + Send>;
/// A boxed receive half.
pub type BoxRx = Box<dyn WireRx + Send>;

/// A rotation that has been pushed but not yet acknowledged.
///
/// Lives only for the lifetime of the connection: if the connection dies before
/// the ack, the pending rotation dies with it and the node's existing token —
/// which the database still holds — keeps working. That is the entire point.
struct PendingRotation {
    rotation_id: u64,
    token_hash: String,
    sent_at: Instant,
}

/// Drive an agent connection: register a writer task, then pump inbound
/// envelopes into the coordinator, pinging and rotating along the way.
///
/// # Errors
///
/// Returns a [`CoordinatorError`] when the connection ends. A benign peer close
/// is reported as such (see [`fleet_wire::is_benign_close`]) so a node that
/// simply went away is not logged as a fault.
pub async fn handle_agent(
    coord: Arc<Coordinator>,
    tx: BoxTx,
    rx: BoxRx,
    agent_id: AgentId,
    auth: fleet_auth::Authenticated,
) -> Result<()> {
    let (out_tx, mut out_rx) = mpsc::channel::<AgentMessage>(64);
    coord
        .agents()
        .insert(agent_id.clone(), AgentHandle::new(out_tx.clone()))
        .await;

    // One task owns the write half; every producer (the relay, the sweep, the
    // keepalive, rotation) funnels through the mpsc.
    let (ping_tx, mut ping_rx) = mpsc::channel::<()>(1);
    let writer_task = tokio::spawn(async move {
        let mut tx = tx;
        loop {
            tokio::select! {
                msg = out_rx.recv() => {
                    let Some(msg) = msg else { break };
                    let envelope = match msg {
                        AgentMessage::Command(cmd) => CoordToAgent::Command(cmd),
                        AgentMessage::Data(frame) => CoordToAgent::Data(frame),
                    };
                    if fleet_wire::send(&mut *tx, &envelope).await.is_err() {
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

    let result = agent_read_loop(&coord, rx, &agent_id, &auth, &out_tx, &ping_tx).await;

    coord.agents().remove(&agent_id).await;
    writer_task.abort();
    result
}

/// The agent plane's read loop, with keepalive and rotation folded in.
async fn agent_read_loop(
    coord: &Coordinator,
    mut rx: BoxRx,
    agent_id: &AgentId,
    auth: &fleet_auth::Authenticated,
    out_tx: &mpsc::Sender<AgentMessage>,
    ping_tx: &mpsc::Sender<()>,
) -> Result<()> {
    let policy = coord.config().rotation_policy();
    let mut ping = tokio::time::interval(coord.config().ping_interval());
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await; // the first tick fires immediately
    let pong_timeout = coord.config().pong_timeout();
    let mut last_seen = Instant::now();
    let mut pending: Option<PendingRotation> = None;
    let mut next_rotation_id: u64 = 1;

    // The age of the token this connection is currently authenticated by.
    //
    // **Connection state, not a re-read of `auth`.** `auth` is captured once at
    // authentication and never updated, so evaluating `should_rotate` against
    // `auth.token_issued_at` would keep reporting the *pre-rotation* age after a
    // completed cycle — re-firing a rotation every ping tick for the life of the
    // connection, each one rewriting the Pi's SD card and appending an audit
    // row. `complete_rotation` advances this on a successful promotion.
    let mut token_issued_at = auth.token_issued_at.unwrap_or(0);

    // Rotate on connect if the token is already old enough: a node that
    // reconnects after a long outage should not have to wait a full interval.
    let mut rotation_due = fleet_auth::should_rotate(token_issued_at, coord.now(), policy);

    loop {
        if rotation_due && pending.is_none() {
            rotation_due = false;
            match push_rotation(agent_id, out_tx, next_rotation_id).await {
                Some(p) => {
                    pending = Some(p);
                    next_rotation_id = next_rotation_id.wrapping_add(1);
                }
                None => break Err(CoordinatorError::Protocol(
                    "agent writer closed during rotation".to_owned(),
                )),
            }
        }

        tokio::select! {
            event = rx.recv() => {
                let event = event?;
                last_seen = Instant::now();
                match event {
                    WireEvent::Pong => {}
                    WireEvent::Closed => break Err(CoordinatorError::Wire(WireError::Closed)),
                    WireEvent::Binary(bytes) => {
                        match fleet_wire::decode::<AgentToCoord>(&bytes)? {
                            AgentToCoord::Report(report) => {
                                if let Some(outcome) = handle_agent_report(
                                    coord,
                                    agent_id,
                                    auth,
                                    &mut pending,
                                    &mut token_issued_at,
                                    report,
                                )
                                .await?
                                {
                                    break Err(outcome);
                                }
                            }
                            AgentToCoord::Data(frame) => {
                                // Return-path relay: forward opaque bytes from
                                // the agent to the sidecar owning the channel.
                                // An unknown channel is dropped.
                                if let Err(e) = coord.relay_from_agent(frame).await {
                                    debug!(error = %e, "relay to sidecar failed");
                                }
                            }
                        }
                    }
                }
            }
            _ = ping.tick() => {
                if last_seen.elapsed() > pong_timeout {
                    warn!(%agent_id, "no pong within the liveness deadline; dropping connection");
                    break Err(CoordinatorError::Protocol(
                        "keepalive timeout".to_owned(),
                    ));
                }
                if ping_tx.send(()).await.is_err() {
                    break Err(CoordinatorError::Wire(WireError::Closed));
                }
                // A pushed rotation the node never acked is abandoned and
                // retried later, rather than pinning the replacement forever.
                if let Some(p) = &pending {
                    if p.sent_at.elapsed() > policy.ack_timeout() {
                        debug!(%agent_id, rotation_id = p.rotation_id, "rotation ack timed out; will retry");
                        pending = None;
                    }
                }
                if pending.is_none()
                    && fleet_auth::should_rotate(token_issued_at, coord.now(), policy)
                {
                    rotation_due = true;
                }
            }
        }
    }
}

/// Handle one report on the agent plane.
///
/// Returns `Ok(Some(error))` when the connection must be closed (currently only
/// a self-declared id that contradicts the token).
async fn handle_agent_report(
    coord: &Coordinator,
    agent_id: &AgentId,
    auth: &fleet_auth::Authenticated,
    pending: &mut Option<PendingRotation>,
    token_issued_at: &mut u64,
    report: AgentReport,
) -> Result<Option<CoordinatorError>> {
    match report {
        AgentReport::Register { ref agent, .. } if agent.0 != auth.id => {
            // Under bearer auth the self-declared id is attacker-controlled
            // text. Routing already uses the token-derived id, so ignoring the
            // field would be safe — but a node claiming another node's id is
            // not a benign typo, and letting it sit in the audit log as
            // ambiguous provenance is worse than refusing the connection.
            let now = i64::try_from(coord.now()).unwrap_or(i64::MAX);
            let detail = format!("claimed `{}`, token says `{}`", agent.0, auth.id);
            let _ = coord
                .db()
                .scoped(fleet_proto::ids::OrgId(auth.org_id.clone()))
                .append_audit(&AuditEntry {
                    ts: now,
                    subject: Some(auth.id.as_str()),
                    action: "agent.register.id_mismatch",
                    node: Some(auth.id.as_str()),
                    board: None,
                    lease: None,
                    detail: Some(&detail),
                })
                .await;
            warn!(%agent_id, claimed = %agent.0, "node declared an id its token does not grant");
            Ok(Some(CoordinatorError::Protocol(format!(
                "node declared id `{}` but its token authenticates `{}`",
                agent.0, auth.id
            ))))
        }
        AgentReport::TokenRotated { rotation_id } => {
            complete_rotation(coord, agent_id, auth, pending, token_issued_at, rotation_id).await;
            Ok(None)
        }
        other => {
            coord.handle_agent_report(agent_id, other).await?;
            Ok(None)
        }
    }
}

/// Mint a replacement token and push it, without touching the database.
async fn push_rotation(
    agent_id: &AgentId,
    out_tx: &mpsc::Sender<AgentMessage>,
    rotation_id: u64,
) -> Option<PendingRotation> {
    let token = OpaqueToken::mint(TokenKind::Node);
    let hash = token.hash();
    let cmd = fleet_proto::agent_api::CoordinatorCommand::RotateNodeToken {
        token: token.to_secret_string(),
        rotation_id,
    };
    if out_tx.send(AgentMessage::Command(cmd)).await.is_err() {
        return None;
    }
    debug!(%agent_id, rotation_id, "pushed a replacement node token; awaiting ack");
    Some(PendingRotation {
        rotation_id,
        token_hash: hash.as_str().to_owned(),
        sent_at: Instant::now(),
    })
}

/// Promote a pending rotation once the node has acked it.
///
/// On success this advances `token_issued_at`, the connection's own record of
/// how old its credential is. Without that the read loop would keep evaluating
/// the rotation policy against the pre-rotation age and re-fire on every ping.
async fn complete_rotation(
    coord: &Coordinator,
    agent_id: &AgentId,
    auth: &fleet_auth::Authenticated,
    pending: &mut Option<PendingRotation>,
    token_issued_at: &mut u64,
    rotation_id: u64,
) {
    let now = i64::try_from(coord.now()).unwrap_or(i64::MAX);
    let org = fleet_proto::ids::OrgId(auth.org_id.clone());
    let matches = pending.as_ref().is_some_and(|p| p.rotation_id == rotation_id);
    if !matches {
        // A late ack for a rotation we already abandoned, or one we never sent.
        // Ignored — promoting an unknown hash would lock the node out.
        let _ = coord
            .db()
            .scoped(org)
            .append_audit(&AuditEntry {
                ts: now,
                subject: Some(auth.id.as_str()),
                action: "node.token.rotate_stale",
                node: Some(auth.id.as_str()),
                board: None,
                lease: None,
                detail: None,
            })
            .await;
        debug!(%agent_id, rotation_id, "ignored a stale rotation ack");
        return;
    }
    let p = pending.take().expect("checked above");
    if let Err(e) = coord
        .db()
        .set_node_token_hash(agent_id, &p.token_hash, now)
        .await
    {
        // The node has already persisted the new token, and the database still
        // has the old one. The node's one-shot retry with its previous token
        // covers this; log it loudly because it means a write failed.
        warn!(%agent_id, error = %e, "failed to promote a rotated node token");
        return;
    }
    // The promotion is committed: this connection's credential is now `now` old,
    // so the next policy evaluation sees a fresh token rather than the stale one
    // it authenticated with.
    *token_issued_at = coord.now();
    let _ = coord
        .db()
        .scoped(org)
        .append_audit(&AuditEntry {
            ts: now,
            subject: Some(auth.id.as_str()),
            action: "node.token.rotated",
            node: Some(auth.id.as_str()),
            board: None,
            lease: None,
            detail: None,
        })
        .await;
    info!(%agent_id, rotation_id, "node token rotated");
}

/// Drive a sidecar/ctl connection: handshake, then service lease/relay requests.
///
/// # Errors
///
/// Returns a [`CoordinatorError`] when the connection ends.
pub async fn handle_sidecar(coord: Arc<Coordinator>, tx: BoxTx, rx: BoxRx, subject: Subject) -> Result<()> {
    let (out_tx, ping_tx, writer_task) = spawn_sidecar_writer(tx);

    let result = sidecar_pump(&coord, rx, &out_tx, &ping_tx, |msg| {
        let coord = &coord;
        let subject = &subject;
        let out_tx = &out_tx;
        async move { coord.handle_sidecar_message(subject, msg, out_tx).await }
    })
    .await;

    // Release any leases this sidecar still held, then drop its channels.
    coord.drop_sidecar(&subject);
    writer_task.abort();
    result
}

/// Drive a **delegated** connection: a sandboxed agent presenting nothing but a
/// capability token (architecture §6.5).
///
/// This route is deliberately crippled. It shares the writer task, the
/// handshake and the keepalive with [`handle_sidecar`] — factored, not copied,
/// because a loop without ping/pong either leaks connections or dies at the
/// first pong timeout — but its message handling is a flat **allowlist**:
///
/// * `OpenChannel`, only for the token's own lease;
/// * `Data` and `CloseChannel`, on channels that lease owns;
///
/// and nothing else. In particular there is no `Lease`, no `Extend`, no
/// `Release` (the delegator owns the lease lifecycle; the sandbox's only
/// lease-affecting power is letting it expire), no `ListBoards`/`Who`/`Logs`
/// (the sandbox cannot enumerate the fleet) and no grant verbs.
///
/// **No [`Subject`] is constructed anywhere on this path.** That is the design
/// point, not an implementation detail: delegation creates no principal, so
/// there is no identity to escalate, to enumerate with, or to leave behind when
/// the lease ends.
///
/// # Errors
///
/// Returns a [`CoordinatorError`] when the connection ends.
pub async fn handle_delegate(
    coord: Arc<Coordinator>,
    tx: BoxTx,
    rx: BoxRx,
    token: fleet_proto::token::CapabilityToken,
) -> Result<()> {
    let (out_tx, ping_tx, writer_task) = spawn_sidecar_writer(tx);

    let result = sidecar_pump(&coord, rx, &out_tx, &ping_tx, |msg| {
        let coord = &coord;
        let token = &token;
        let out_tx = &out_tx;
        async move { handle_delegate_message(coord, token, msg, out_tx).await }
    })
    .await;

    writer_task.abort();
    result
}

/// The `/delegate` allowlist. Anything not named here is a flat error.
async fn handle_delegate_message(
    coord: &Coordinator,
    token: &fleet_proto::token::CapabilityToken,
    msg: SidecarToCoord,
    out_tx: &mpsc::Sender<CoordToSidecar>,
) -> Result<()> {
    match msg {
        SidecarToCoord::OpenChannel { lease, kind } => {
            // The token authorises exactly one lease. Checked here rather than
            // trusted from the request, so a sandbox cannot walk lease ids.
            if lease != token.lease {
                let _ = out_tx
                    .send(CoordToSidecar::Error {
                        message: "this token does not authorise that lease".to_owned(),
                    })
                    .await;
                return Ok(());
            }
            let reply = coord
                .open_delegated_channel(token, kind, out_tx.clone())
                .await?;
            let _ = out_tx.send(reply).await;
        }
        SidecarToCoord::Data(frame) => {
            coord.relay_delegated(token.lease, frame).await;
        }
        SidecarToCoord::CloseChannel { channel } => {
            coord.close_delegated_channel(token.lease, channel).await;
        }
        other => {
            debug!(?other, lease = ?token.lease, "refused on the delegate route");
            let _ = out_tx
                .send(CoordToSidecar::Error {
                    message: "not permitted on a delegated connection".to_owned(),
                })
                .await;
        }
    }
    Ok(())
}

/// Spawn the writer task both sidecar-direction routes share.
///
/// Returns the message sender, the ping trigger, and the task handle.
fn spawn_sidecar_writer(
    tx: BoxTx,
) -> (
    mpsc::Sender<CoordToSidecar>,
    mpsc::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let (out_tx, mut out_rx) = mpsc::channel::<CoordToSidecar>(64);
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

    (out_tx, ping_tx, writer_task)
}

/// Handshake, then read messages until the connection ends, handing each to
/// `handle` — with the keepalive contract every sidecar-direction route must
/// honour.
///
/// Shared rather than copied precisely because of that keepalive: a reverse
/// proxy in front reaps idle `WebSocket`s on a timeout we do not control, so a
/// route that forgets to ping (or to notice a missing pong) either leaks
/// connections or dies mid-session.
async fn sidecar_pump<F, Fut>(
    coord: &Coordinator,
    mut rx: BoxRx,
    out_tx: &mpsc::Sender<CoordToSidecar>,
    ping_tx: &mpsc::Sender<()>,
    mut handle: F,
) -> Result<()>
where
    F: FnMut(SidecarToCoord) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    // Expect a Hello first.
    let hello: SidecarToCoord = fleet_wire::recv(&mut *rx).await?;
    match hello {
        SidecarToCoord::Hello { protocol_version } => {
            if protocol_version != PROTOCOL_VERSION {
                let _ = out_tx
                    .send(CoordToSidecar::Error {
                        message: format!(
                            "protocol mismatch: sidecar={protocol_version} coordinator={PROTOCOL_VERSION}"
                        ),
                    })
                    .await;
                return Err(CoordinatorError::VersionMismatch {
                    peer: protocol_version,
                    ours: PROTOCOL_VERSION,
                });
            }
            let _ = out_tx
                .send(CoordToSidecar::Welcome {
                    protocol_version: PROTOCOL_VERSION,
                })
                .await;
        }
        other => {
            return Err(CoordinatorError::Protocol(format!(
                "expected Hello, got {other:?}"
            )));
        }
    }

    let mut ping = tokio::time::interval(coord.config().ping_interval());
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping.tick().await;
    let pong_timeout = coord.config().pong_timeout();
    let mut last_seen = Instant::now();

    loop {
        tokio::select! {
            event = rx.recv() => {
                last_seen = Instant::now();
                match event? {
                    WireEvent::Pong => {}
                    WireEvent::Closed => return Err(CoordinatorError::Wire(WireError::Closed)),
                    WireEvent::Binary(bytes) => {
                        let msg: SidecarToCoord = fleet_wire::decode(&bytes)?;
                        handle(msg).await?;
                    }
                }
            }
            _ = ping.tick() => {
                if last_seen.elapsed() > pong_timeout {
                    return Err(CoordinatorError::Protocol("keepalive timeout".to_owned()));
                }
                if ping_tx.send(()).await.is_err() {
                    return Err(CoordinatorError::Wire(WireError::Closed));
                }
            }
        }
    }
}

/// Test-only door: drive the agent-side pumps over arbitrary wire halves.
///
/// Exposed so integration tests can wire an agent and a coordinator over an
/// in-memory pair, or over a real `WebSocket` with no HTTP layer in between.
///
/// # Errors
///
/// Propagates any per-connection error.
#[doc(hidden)]
pub async fn handle_agent_for_test(
    coord: Arc<Coordinator>,
    tx: BoxTx,
    rx: BoxRx,
    agent_id: AgentId,
) -> Result<()> {
    let auth = fleet_auth::Authenticated {
        kind: TokenKind::Node,
        org_id: coord.config().default_org.0.clone(),
        id: agent_id.0.clone(),
        expires: None,
        hash: fleet_auth::TokenHash::from_hex(String::new()),
        // Freshly issued: no rotation is due, so a test that is not about
        // rotation does not accidentally exercise it.
        token_issued_at: Some(coord.now()),
    };
    handle_agent(coord, tx, rx, agent_id, auth).await
}

/// Test-only door: drive the sidecar-side handshake + pumps as `subject`.
///
/// # Errors
///
/// Propagates any per-connection error.
#[doc(hidden)]
pub async fn handle_sidecar_for_test(
    coord: Arc<Coordinator>,
    tx: BoxTx,
    rx: BoxRx,
    subject: Subject,
) -> Result<()> {
    handle_sidecar(coord, tx, rx, subject).await
}

/// How long the writer task waits for a queued message before giving up.
///
/// Only used by tests that need a bounded wait; production paths are driven by
/// the connection itself.
#[doc(hidden)]
pub const TEST_SETTLE: Duration = Duration::from_millis(50);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Ed25519Signer;
    use crate::clock::SystemClock;
    use crate::config::CoordinatorConfig;
    use crate::registry::{ChannelRoute, SidecarHandle};
    use fleet_core::policy::Policy;
    use fleet_core::scheduler::Scheduler;
    use fleet_proto::agent_api::{AgentReport, CoordinatorCommand};
    use fleet_proto::ids::LeaseId;
    use fleet_proto::DataFrame;

    const SEED: [u8; 32] = [5u8; 32];

    fn config() -> CoordinatorConfig {
        CoordinatorConfig {
            sqlite_path: ":memory:".into(),
            signing_key: crate::config::SigningKeySource::Seed(SEED),
            ..CoordinatorConfig::default()
        }
    }

    async fn coordinator() -> Arc<Coordinator> {
        let sched = Scheduler::new(Policy::default());
        let db = crate::state::Db::connect_in_memory().await.unwrap();
        Arc::new(Coordinator::new(
            config(),
            sched,
            db,
            Ed25519Signer::from_seed(&SEED),
            Arc::new(SystemClock),
        ))
    }

    /// End-to-end return-path relay: a `DataFrame` written by the agent peer
    /// travels through the *real* `handle_agent` read loop and is relayed to
    /// the owning sidecar's channel. Covers the agent→sidecar direction the
    /// production server actually uses.
    #[tokio::test]
    async fn agent_to_sidecar_relay_end_to_end() {
        let coord = coordinator().await;
        let agent_id = AgentId("agent-a".to_owned());

        // Pre-register an open channel routed to a sidecar receiver.
        let channel = coord.channels().allocate().await;
        let (sidecar_tx, mut sidecar_rx) = mpsc::channel::<CoordToSidecar>(16);
        let route_tx: SidecarHandle = sidecar_tx;
        coord
            .channels()
            .insert(
                channel,
                ChannelRoute {
                    lease: LeaseId(1),
                    agent: agent_id.clone(),
                    sidecar: route_tx,
                    kind: fleet_proto::ChannelKind::Data,
                },
            )
            .await;

        let (server_tx, server_rx, mut peer_tx, _peer_rx) = fleet_wire::mock::pair();
        let coord_clone = Arc::clone(&coord);
        let id = agent_id.clone();
        let agent_task = tokio::spawn(async move {
            let _ = handle_agent_for_test(
                coord_clone,
                Box::new(server_tx),
                Box::new(server_rx),
                id,
            )
            .await;
        });

        // A control report (exercising the demux path) ...
        fleet_wire::send(
            &mut peer_tx,
            &AgentToCoord::Report(AgentReport::Heartbeat { uptime_secs: 1 }),
        )
        .await
        .unwrap();
        // ... then opaque data-plane bytes for the open channel.
        let payload = DataFrame {
            channel,
            bytes: vec![0xCA, 0xFE, 0xBA, 0xBE],
        };
        fleet_wire::send(&mut peer_tx, &AgentToCoord::Data(payload.clone()))
            .await
            .unwrap();

        // The bytes arrive verbatim at the sidecar end.
        match sidecar_rx.recv().await.unwrap() {
            CoordToSidecar::Data(f) => assert_eq!(f, payload),
            other => panic!("expected Data, got {other:?}"),
        }

        drop(peer_tx);
        agent_task.abort();
    }

    /// End-to-end command path: a `CoordinatorCommand` pushed through the agent
    /// registry is framed as a `CoordToAgent` envelope and read back off the
    /// agent's wire.
    #[tokio::test]
    async fn coordinator_to_agent_command_end_to_end() {
        let coord = coordinator().await;
        let agent_id = AgentId("agent-a".to_owned());

        let (server_tx, server_rx, _peer_tx, mut peer_rx) = fleet_wire::mock::pair();
        let coord_clone = Arc::clone(&coord);
        let id = agent_id.clone();
        let agent_task = tokio::spawn(async move {
            let _ = handle_agent_for_test(
                coord_clone,
                Box::new(server_tx),
                Box::new(server_rx),
                id,
            )
            .await;
        });

        // Wait for handle_agent to register the connection, then push a command.
        let handle = loop {
            if let Some(h) = coord.agents().get(&agent_id).await {
                break h;
            }
            tokio::task::yield_now().await;
        };
        handle
            .send_command(CoordinatorCommand::QueryState)
            .await
            .unwrap();

        match fleet_wire::recv::<CoordToAgent>(&mut peer_rx).await.unwrap() {
            CoordToAgent::Command(CoordinatorCommand::QueryState) => {}
            other => panic!("expected QueryState command, got {other:?}"),
        }

        agent_task.abort();
    }

    /// A node whose `Register` claims an id its token does not grant is
    /// disconnected, not merely audited: that is not a typo.
    #[tokio::test]
    async fn register_with_a_foreign_id_closes_the_connection() {
        let coord = coordinator().await;
        let agent_id = AgentId("agent-a".to_owned());

        let (server_tx, server_rx, mut peer_tx, _peer_rx) = fleet_wire::mock::pair();
        let coord_clone = Arc::clone(&coord);
        let id = agent_id.clone();
        let task = tokio::spawn(async move {
            handle_agent_for_test(coord_clone, Box::new(server_tx), Box::new(server_rx), id).await
        });

        fleet_wire::send(
            &mut peer_tx,
            &AgentToCoord::Report(AgentReport::Register {
                agent: AgentId("someone-else".to_owned()),
                protocol_version: PROTOCOL_VERSION,
            }),
        )
        .await
        .unwrap();

        let err = task.await.unwrap().unwrap_err();
        assert!(
            matches!(err, CoordinatorError::Protocol(ref m) if m.contains("someone-else")),
            "expected an id-mismatch protocol error, got {err:?}"
        );
        // ... and the connection is deregistered, so nothing can route to it.
        assert!(coord.agents().get(&agent_id).await.is_none());
    }

    /// The matching id is accepted, so the check above is not simply refusing
    /// every `Register`.
    #[tokio::test]
    async fn register_with_the_token_id_is_accepted() {
        let coord = coordinator().await;
        let agent_id = AgentId("agent-a".to_owned());

        let (server_tx, server_rx, mut peer_tx, _peer_rx) = fleet_wire::mock::pair();
        let coord_clone = Arc::clone(&coord);
        let id = agent_id.clone();
        let task = tokio::spawn(async move {
            handle_agent_for_test(coord_clone, Box::new(server_tx), Box::new(server_rx), id).await
        });

        fleet_wire::send(
            &mut peer_tx,
            &AgentToCoord::Report(AgentReport::Register {
                agent: agent_id.clone(),
                protocol_version: PROTOCOL_VERSION,
            }),
        )
        .await
        .unwrap();
        fleet_wire::send(
            &mut peer_tx,
            &AgentToCoord::Report(AgentReport::Heartbeat { uptime_secs: 1 }),
        )
        .await
        .unwrap();

        // Still connected after both reports.
        tokio::time::sleep(TEST_SETTLE).await;
        assert!(coord.agents().get(&agent_id).await.is_some());
        task.abort();
    }
}
