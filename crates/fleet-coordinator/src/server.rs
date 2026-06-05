//! The TLS accept loop and per-connection handling.
//!
//! The coordinator is the only listening node (architecture §4.1). It binds a
//! [`tokio::net::TcpListener`], wraps each accepted socket in a
//! [`tokio_rustls::TlsAcceptor`] built from `fleet_tls::server_config`, derives
//! the peer's [`Principal`]/[`AgentId`] from its client certificate, and
//! branches on role:
//!
//! * **Agents** (cert fingerprint pinned in config) dial out and hold one
//!   persistent connection. They send [`AgentReport`]s up; the coordinator
//!   sends [`CoordinatorCommand`]s down. The connection is registered in the
//!   [`AgentRegistry`] so the relay and sweep can reach it.
//! * **Sidecars** request/extend/release leases and open relay channels
//!   ([`SidecarToCoord`] / [`CoordToSidecar`]).
//!
//! The lease/relay decision logic is factored into [`crate::core::Coordinator`]
//! so it is unit-testable without sockets; this module is the I/O shell.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use fleet_proto::ids::{AgentId, Principal};
use fleet_proto::PROTOCOL_VERSION;

use crate::core::Coordinator;
use crate::error::{CoordinatorError, Result};
use crate::proto::{
    read_frame, write_frame, AgentToCoord, CoordToAgent, CoordToSidecar, SidecarToCoord,
};
use crate::registry::{AgentHandle, AgentMessage};

/// Run the TLS accept loop until the listener errors fatally.
///
/// Each accepted connection is handled on its own task. Per-connection errors
/// are logged and do not bring down the loop.
///
/// # Errors
///
/// Returns [`CoordinatorError::Io`] if binding the listener fails.
pub async fn serve(coord: Arc<Coordinator>, acceptor: TlsAcceptor) -> Result<()> {
    let listener = TcpListener::bind(coord.config().listen_addr).await?;
    info!(addr = %coord.config().listen_addr, "coordinator listening");
    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let coord = Arc::clone(&coord);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(coord, acceptor, sock).await {
                debug!(%peer, error = %e, "connection closed");
            }
        });
    }
}

/// Accept the TLS handshake, derive the peer identity, and dispatch by role.
async fn handle_connection(
    coord: Arc<Coordinator>,
    acceptor: TlsAcceptor,
    sock: tokio::net::TcpStream,
) -> Result<()> {
    let tls = acceptor.accept(sock).await?;
    let (_, conn) = tls.get_ref();
    let peer_certs = conn
        .peer_certificates()
        .ok_or_else(|| CoordinatorError::Protocol("peer presented no certificate".to_owned()))?;
    let end_entity = peer_certs
        .first()
        .ok_or_else(|| CoordinatorError::Protocol("empty peer certificate chain".to_owned()))?;

    let fingerprint = fleet_tls::cert_fingerprint(end_entity);
    let principal = fleet_tls::principal_from_cert(end_entity)?;

    if let Some(agent_id) = coord.config().agent_for_fingerprint(&fingerprint).cloned() {
        info!(%agent_id, "agent connected");
        handle_agent(coord, tls, agent_id).await
    } else {
        debug!(%principal, "sidecar connected");
        handle_sidecar(coord, tls, principal).await
    }
}

/// Drive an agent connection: register a writer task, then pump framed
/// [`AgentToCoord`] envelopes (reports + return-path data frames) into the
/// coordinator.
async fn handle_agent<S>(coord: Arc<Coordinator>, stream: S, agent_id: AgentId) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<AgentMessage>(64);
    coord
        .agents()
        .insert(agent_id.clone(), AgentHandle::new(tx))
        .await;

    // Writer task: serialise queued commands/data onto the stream as framed
    // `CoordToAgent` envelopes so the agent can demultiplex control from data.
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let envelope = match msg {
                AgentMessage::Command(cmd) => CoordToAgent::Command(cmd),
                AgentMessage::Data(frame) => CoordToAgent::Data(frame),
            };
            if write_frame(&mut writer, &envelope).await.is_err() {
                break;
            }
        }
    });

    let result = agent_read_loop(&coord, &mut reader, &agent_id).await;

    coord.agents().remove(&agent_id).await;
    writer_task.abort();
    result
}

async fn agent_read_loop<R>(
    coord: &Coordinator,
    reader: &mut R,
    agent_id: &AgentId,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    loop {
        match read_frame::<_, AgentToCoord>(reader).await? {
            AgentToCoord::Report(report) => {
                coord.handle_agent_report(agent_id, report).await?;
            }
            AgentToCoord::Data(frame) => {
                // Return-path relay: forward opaque bytes from the agent to the
                // sidecar that owns the channel. An unknown channel is dropped.
                if let Err(e) = coord.relay_from_agent(frame).await {
                    debug!(error = %e, "relay to sidecar failed");
                }
            }
        }
    }
}

/// Drive a sidecar connection: handshake, then service lease/relay requests.
async fn handle_sidecar<S>(coord: Arc<Coordinator>, stream: S, principal: Principal) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<CoordToSidecar>(64);

    // Writer task.
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if write_frame(&mut writer, &msg).await.is_err() {
                break;
            }
        }
    });

    let result = sidecar_read_loop(&coord, &mut reader, &principal, &tx).await;

    // Release any leases this sidecar still held, then drop its channels.
    coord.drop_sidecar(&principal);
    writer_task.abort();
    result
}

async fn sidecar_read_loop<R>(
    coord: &Coordinator,
    reader: &mut R,
    principal: &Principal,
    tx: &mpsc::Sender<CoordToSidecar>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    // Expect a Hello first.
    let hello: SidecarToCoord = read_frame(reader).await?;
    match hello {
        SidecarToCoord::Hello { protocol_version } => {
            if protocol_version != PROTOCOL_VERSION {
                let _ = tx
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
            let _ = tx
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

    loop {
        let msg: SidecarToCoord = read_frame(reader).await?;
        coord.handle_sidecar_message(principal, msg, tx).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Ed25519Signer;
    use crate::clock::SystemClock;
    use crate::config::{CoordinatorConfig, SigningKeySource};
    use crate::registry::{ChannelRoute, SidecarHandle};
    use fleet_core::policy::Policy;
    use fleet_core::scheduler::Scheduler;
    use fleet_proto::agent_api::{AgentReport, CoordinatorCommand};
    use fleet_proto::ids::LeaseId;
    use fleet_proto::DataFrame;
    use std::collections::HashMap;

    const SEED: [u8; 32] = [5u8; 32];

    fn config() -> CoordinatorConfig {
        CoordinatorConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            tls_cert: "c".into(),
            tls_key: "k".into(),
            client_ca: "ca".into(),
            sqlite_path: ":memory:".into(),
            signing_key: SigningKeySource::Seed(SEED),
            policy: Policy::default(),
            pinned_agents: HashMap::new(),
            sweep_interval_secs: 5,
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
    /// production server actually uses (not just the direct unit test).
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

        // Drive handle_agent over a duplex; `peer` is the agent's end.
        let (server_side, mut peer) = tokio::io::duplex(4096);
        let coord_clone = Arc::clone(&coord);
        let agent_task = tokio::spawn(async move {
            let _ = handle_agent(coord_clone, server_side, agent_id).await;
        });

        // Agent emits a control report (exercises the demux path) ...
        write_frame(
            &mut peer,
            &AgentToCoord::Report(AgentReport::Heartbeat { uptime_secs: 1 }),
        )
        .await
        .unwrap();
        // ... then opaque data-plane bytes for the open channel.
        let payload = DataFrame {
            channel,
            bytes: vec![0xCA, 0xFE, 0xBA, 0xBE],
        };
        write_frame(&mut peer, &AgentToCoord::Data(payload.clone()))
            .await
            .unwrap();

        // The bytes arrive verbatim at the sidecar end.
        match sidecar_rx.recv().await.unwrap() {
            CoordToSidecar::Data(f) => assert_eq!(f, payload),
            other => panic!("expected Data, got {other:?}"),
        }

        drop(peer);
        let _ = agent_task.await;
    }

    /// End-to-end command path: a `CoordinatorCommand` pushed through the agent
    /// registry is framed as a `CoordToAgent` envelope and read back off the
    /// agent's wire.
    #[tokio::test]
    async fn coordinator_to_agent_command_end_to_end() {
        let coord = coordinator().await;
        let agent_id = AgentId("agent-a".to_owned());

        let (server_side, mut peer) = tokio::io::duplex(4096);
        let coord_clone = Arc::clone(&coord);
        let agent_task = tokio::spawn(async move {
            let _ = handle_agent(coord_clone, server_side, agent_id).await;
        });

        // Wait for handle_agent to register the connection, then push a command.
        let handle = loop {
            if let Some(h) = coord.agents().get(&AgentId("agent-a".to_owned())).await {
                break h;
            }
            tokio::task::yield_now().await;
        };
        handle
            .send_command(CoordinatorCommand::QueryState)
            .await
            .unwrap();

        match read_frame::<_, CoordToAgent>(&mut peer).await.unwrap() {
            CoordToAgent::Command(CoordinatorCommand::QueryState) => {}
            other => panic!("expected QueryState command, got {other:?}"),
        }

        drop(peer);
        let _ = agent_task.await;
    }
}

