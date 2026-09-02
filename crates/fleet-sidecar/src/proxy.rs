//! The relay seam: leasing a board and splicing the genuine probe-rs client's
//! byte stream to the agent through the coordinator.
//!
//! # How the sidecar proxies
//!
//! The sidecar does **not** re-implement the probe-rs client. probe-rs 0.32's
//! own client honours `PROBE_RS_REMOTE_HOST` / `PROBE_RS_REMOTE_TOKEN` (and the
//! `--host` / `--token` flags): it builds `{host}/worker` and dials it as a
//! **WebSocket** (so `host` must be a `ws://` base URL), doing probe + chip
//! selection in-band and computing the exit code itself.
//!
//! So the sidecar:
//!
//! 1. resolves the fleet selector and leases a board from the coordinator;
//! 2. opens a **local** TCP endpoint — `127.0.0.1:<port>`, advertised to the
//!    client as `ws://127.0.0.1:<port>` — that the genuine probe-rs client will
//!    treat as its remote host;
//! 3. for each client connection, opens a relay channel to the coordinator
//!    (which relays to the agent's per-board `serve`) and **byte-splices** the
//!    two directions verbatim. It is a pure byte pipe carrying the bytes of a
//!    WebSocket-over-TCP connection — the sidecar never parses WebSocket or
//!    probe-rs frames.
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
//! The concrete mTLS + byte-opaque relay transport that implements all of the
//! [`crate::transport`] ([`crate::transport::CoordSession`] +
//! [`crate::transport::splice_client`]), driven from the fleet arm of
//! [`crate::run`]. This module retains the error type and the trait *seam*
//! definitions that document the contract; the live driver supersedes the old
//! synchronous stub implementations.
//!
//! # gdb
//!
//! `probe-rs gdb` is **not** remote-capable in probe-rs 0.32 (it runs a local
//! TCP gdb stub, not over the remote WebSocket). The fleet path therefore does not exec
//! the genuine client for `gdb`; instead it tunnels raw gdbremote bytes to an
//! agent that runs `probe-rs gdb` locally, as a **second relay channel**
//! ([`fleet_proto::ChannelKind::Gdb`]). The workstation-side listener + byte
//! splice live in [`crate::gdb`]; the gdb channel is opened over the same live
//! transport.

use fleet_proto::lease::{LeaseGrant, LeaseRequest};

/// Errors from the relay / lease seam.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProxyError {
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
/// The contract the live [`crate::transport`] driver fulfils; retained as a
/// documented seam.
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
pub trait LocalEndpoint {
    /// The `ws://` base URL to set as `PROBE_RS_REMOTE_HOST` (e.g.
    /// `ws://127.0.0.1:51001`); the client appends `/worker` and dials it as a
    /// WebSocket.
    fn remote_host(&self) -> String;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_error_displays() {
        assert_eq!(
            ProxyError::Lease("denied".to_owned()).to_string(),
            "lease request failed: denied"
        );
        assert_eq!(
            ProxyError::Unsupported("gdb".to_owned()).to_string(),
            "unsupported: gdb"
        );
    }
}
