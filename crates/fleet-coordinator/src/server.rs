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

use fleet_proto::agent_api::AgentReport;
use fleet_proto::ids::{AgentId, Principal};
use fleet_proto::PROTOCOL_VERSION;

use crate::core::Coordinator;
use crate::error::{CoordinatorError, Result};
use crate::proto::{read_frame, write_frame, CoordToSidecar, SidecarToCoord};
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

/// Drive an agent connection: register a writer task, then pump
/// [`AgentReport`]s into the coordinator.
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

    // Writer task: serialise queued commands/data onto the stream.
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let res = match msg {
                AgentMessage::Command(cmd) => write_frame(&mut writer, &cmd).await,
                AgentMessage::Data(frame) => write_frame(&mut writer, &frame).await,
            };
            if res.is_err() {
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
        let report: AgentReport = read_frame(reader).await?;
        coord.handle_agent_report(agent_id, report).await?;
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
