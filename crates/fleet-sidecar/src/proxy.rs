//! The relay seam: leasing a board and splicing the genuine probe-rs client's
//! byte stream to the agent through the coordinator.
//!
//! # How the sidecar proxies (resolved by investigation #1710)
//!
//! The sidecar does **not** re-implement the probe-rs client. probe-rs 0.31's
//! own client honours `PROBE_RS_REMOTE_HOST` / `PROBE_RS_REMOTE_TOKEN` (and the
//! `--host` / `--token` flags): it dials a "remote host" and speaks its normal
//! `u32-LE length-prefixed postcard` framing over that socket, doing probe + chip
//! selection in-band (`AttachRequest`) and computing the exit code itself.
//!
//! So the sidecar:
//!
//! 1. resolves the fleet selector and leases a board from the coordinator
//!    ([`LeaseClient`]);
//! 2. opens a **local** endpoint — a unix socket or `127.0.0.1:<port>` — that
//!    the genuine probe-rs client will treat as its remote host
//!    ([`LocalEndpoint`]);
//! 3. for each client connection, opens a relay channel to the coordinator
//!    (which relays to the agent's per-board `serve`) and **byte-splices** the
//!    two directions verbatim ([`RelayChannel`]). It is a pure byte pipe — the
//!    sidecar never parses the postcard frames.
//! 4. sets `PROBE_RS_REMOTE_HOST` / `PROBE_RS_REMOTE_TOKEN` in the child's
//!    environment to point at the local endpoint and the lease token, then
//!    execs the real probe-rs with the original argv (see the `local` module).
//!
//! Because the genuine client computes and returns the exit code, **exit-code
//! propagation is free**: the sidecar just propagates the child process's exit
//! status. No RPC-level exit-code plumbing is needed.
//!
//! # Status
//!
//! The concrete mTLS / postcard-rpc transport is owned by the coordinator
//! (task 1711) and TLS plumbing (task 1709), and is deferred behind the traits
//! below. [`StubLeaseClient`] / [`StubRelayChannel`] return
//! [`ProxyError::NotYetWired`] so this crate compiles and its logic is fully
//! unit-tested without a live coordinator.
//!
//! # gdb
//!
//! `probe-rs gdb` is **not** remote-capable in probe-rs 0.31 (it runs a local
//! TCP gdb stub, not over postcard-rpc). The fleet path therefore does not exec
//! the genuine client for `gdb`; instead it tunnels raw gdbremote bytes to an
//! agent that runs `probe-rs gdb` locally, as a **second relay channel**
//! ([`fleet_proto::ChannelKind::Gdb`]). The workstation-side listener + byte
//! splice live in [`crate::gdb`]; the [`GdbTunnel`] seam here is the transport
//! hook that opens the gdb-kind channel once the live relay (tasks 1709 / 1711)
//! is wired.

use fleet_proto::lease::{LeaseGrant, LeaseRequest};

/// Errors from the relay / lease seam.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProxyError {
    /// The live mTLS / postcard-rpc transport is not implemented yet (gated on
    /// tasks 1709 / 1710 / 1711).
    #[error("relay transport not yet wired (pending fleet-coordinator/fleet-tls integration)")]
    NotYetWired,
    /// The coordinator declined or could not grant the lease.
    #[error("lease request failed: {0}")]
    Lease(String),
    /// The relay channel failed mid-session.
    #[error("relay channel error: {0}")]
    Channel(String),
    /// Requested capability (e.g. gdb tunneling) is not yet supported.
    #[error("unsupported: {0}")]
    Unsupported(String),
}

/// Leases a board from the coordinator and keeps the lease alive.
///
/// Implemented over the mTLS control plane (deferred to task 1711). The session
/// driver targets this trait so the transport can be swapped without touching
/// the CLI / selector logic.
pub trait LeaseClient {
    /// Request a lease for the configured board selector.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] if the coordinator declines, queues, or is
    /// unreachable.
    fn lease(&self, request: &LeaseRequest) -> Result<LeaseGrant, ProxyError>;

    /// Extend an existing lease (heartbeat) before it expires.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] if the heartbeat is rejected or the transport
    /// fails. Returns the new expiry (epoch seconds) on success.
    fn heartbeat(&self, grant: &LeaseGrant) -> Result<u64, ProxyError>;

    /// Explicitly release a lease (best-effort).
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError`] if the release could not be delivered.
    fn release(&self, grant: &LeaseGrant) -> Result<(), ProxyError>;
}

/// A local endpoint the genuine probe-rs client connects to as its remote host.
///
/// The concrete impl binds a unix socket or `127.0.0.1:<port>` and returns the
/// address to advertise via `PROBE_RS_REMOTE_HOST`.
pub trait LocalEndpoint {
    /// The address to set as `PROBE_RS_REMOTE_HOST` (e.g. `127.0.0.1:51001`).
    fn remote_host(&self) -> String;
}

/// A bidirectional byte channel to the agent (via the coordinator) for one
/// probe-rs session.
///
/// The sidecar copies bytes verbatim between the local client connection and
/// this channel; it never interprets the postcard frames.
pub trait RelayChannel {
    /// Read up to `buf.len()` bytes from the agent side. Returns the number of
    /// bytes read (`0` on clean EOF).
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Channel`] on transport failure.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ProxyError>;

    /// Write all of `buf` to the agent side.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Channel`] on transport failure.
    fn write_all(&mut self, buf: &[u8]) -> Result<(), ProxyError>;
}

/// Seam for the gdb raw-TCP tunnel transport.
///
/// `probe-rs gdb` is not remote-capable in probe-rs 0.31, so the gdb path opens
/// a [`fleet_proto::ChannelKind::Gdb`] relay channel and byte-splices the
/// workstation listener (see [`crate::gdb`]) to the agent's local stub. This
/// trait abstracts opening that channel over the live transport; until the
/// mTLS relay (tasks 1709 / 1711) is wired it returns
/// [`ProxyError::NotYetWired`].
///
/// [`Gdb`]: crate::cli::ProbeRsInvocation::Gdb
pub trait GdbTunnel {
    /// Open a gdb-kind relay channel for the leased board.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::NotYetWired`] until the live relay transport
    /// lands; thereafter, a [`ProxyError`] on a transport failure.
    fn tunnel(&self) -> Result<(), ProxyError>;
}

/// A [`LeaseClient`] that always reports the transport is not yet wired.
///
/// Used until the coordinator (1711) / TLS (1709) integration lands, so the
/// crate compiles and the non-transport logic is fully testable.
#[derive(Debug, Clone, Copy, Default)]
pub struct StubLeaseClient;

impl LeaseClient for StubLeaseClient {
    fn lease(&self, _request: &LeaseRequest) -> Result<LeaseGrant, ProxyError> {
        Err(ProxyError::NotYetWired)
    }

    fn heartbeat(&self, _grant: &LeaseGrant) -> Result<u64, ProxyError> {
        Err(ProxyError::NotYetWired)
    }

    fn release(&self, _grant: &LeaseGrant) -> Result<(), ProxyError> {
        Err(ProxyError::NotYetWired)
    }
}

/// A [`RelayChannel`] that always reports the transport is not yet wired.
#[derive(Debug, Clone, Copy, Default)]
pub struct StubRelayChannel;

impl RelayChannel for StubRelayChannel {
    fn read(&mut self, _buf: &mut [u8]) -> Result<usize, ProxyError> {
        Err(ProxyError::NotYetWired)
    }

    fn write_all(&mut self, _buf: &[u8]) -> Result<(), ProxyError> {
        Err(ProxyError::NotYetWired)
    }
}

/// A [`GdbTunnel`] that reports the gdb relay transport is not yet wired.
#[derive(Debug, Clone, Copy, Default)]
pub struct StubGdbTunnel;

impl GdbTunnel for StubGdbTunnel {
    fn tunnel(&self) -> Result<(), ProxyError> {
        Err(ProxyError::NotYetWired)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fleet_proto::ids::{AgentId, BoardId, LeaseId, Principal};
    use fleet_proto::lease::{Constraint, Priority};

    fn request() -> LeaseRequest {
        LeaseRequest {
            select: Constraint::Board(BoardId("b".to_owned())),
            duration_secs: 600,
            priority: Priority::Interactive,
        }
    }

    fn grant() -> LeaseGrant {
        LeaseGrant {
            lease: LeaseId(1),
            board: BoardId("b".to_owned()),
            agent: AgentId("a".to_owned()),
            holder: Principal("p".to_owned()),
            expires: 1000,
            token: vec![],
        }
    }

    #[test]
    fn stub_lease_client_reports_not_wired() {
        let c = StubLeaseClient;
        assert_eq!(c.lease(&request()), Err(ProxyError::NotYetWired));
        assert_eq!(c.heartbeat(&grant()), Err(ProxyError::NotYetWired));
        assert_eq!(c.release(&grant()), Err(ProxyError::NotYetWired));
    }

    #[test]
    fn stub_relay_channel_reports_not_wired() {
        let mut ch = StubRelayChannel;
        let mut buf = [0u8; 8];
        assert_eq!(ch.read(&mut buf), Err(ProxyError::NotYetWired));
        assert_eq!(ch.write_all(&buf), Err(ProxyError::NotYetWired));
    }

    #[test]
    fn stub_gdb_tunnel_reports_not_wired() {
        let g = StubGdbTunnel;
        assert_eq!(g.tunnel(), Err(ProxyError::NotYetWired));
    }
}
