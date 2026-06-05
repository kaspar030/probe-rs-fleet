//! Shared wire types for probe-rs-fleet.
//!
//! This crate is pure data: no I/O, no async, no transport. It defines the
//! identifiers, requests, and responses exchanged across the control plane
//! (sidecar ⇄ coordinator ⇄ agent). The data plane carries *opaque* probe-rs
//! postcard-rpc frames and is intentionally not modeled here — see
//! [`DataFrame`].
//!
//! See `docs/architecture.md` for how these types map onto the topology.

use serde::{Deserialize, Serialize};

pub mod ids;
pub mod board;
pub mod lease;

pub use board::{Board, BoardState, PowerKind};
pub use ids::{AgentId, BoardId, LeaseId, Principal};
pub use lease::{Constraint, LeaseGrant, LeaseRequest};

/// An opaque chunk of data-plane bytes (probe-rs postcard-rpc frames).
///
/// The coordinator relays these between a sidecar and the owning agent without
/// interpreting them. The `channel` ties the bytes to an open session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFrame {
    pub channel: ChannelId,
    pub bytes: Vec<u8>,
}

/// Identifies one open data-plane session multiplexed over an agent's
/// dial-out connection. Allocated by the coordinator when a lease opens a
/// probe-rs session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId(pub u64);

/// Wire protocol version. Bumped on any incompatible change to the control
/// plane message set. Peers exchange this at connection setup and refuse
/// mismatches.
pub const PROTOCOL_VERSION: u32 = 1;
