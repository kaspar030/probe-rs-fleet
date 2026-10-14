//! Wire types for the coordinator's `WebSocket` planes.
//!
//! The codec and the control-plane envelopes live in the shared [`fleet_wire`]
//! crate (so nodes and sidecars can speak the wire without depending on the
//! coordinator's storage stack). This module re-exports them and carries the
//! `WireError → CoordinatorError` conversion, preserving the historical
//! `fleet_coordinator::proto` API.
//!
//! The `read_frame` / `write_frame` wrappers that used to live here are gone
//! with the length-prefixed framing they wrapped: `WebSocket` messages are
//! delimited by the transport, and the [`fleet_wire::WireTx`] /
//! [`fleet_wire::WireRx`] traits are what the server speaks now.

pub use fleet_wire::{
    CoordToNode, CoordToSidecar, NodeToCoord, SidecarToCoord, WireError, MAX_FRAME_LEN,
};

use crate::error::CoordinatorError;

impl From<WireError> for CoordinatorError {
    fn from(e: WireError) -> Self {
        match e {
            WireError::Io(io) => CoordinatorError::Io(io),
            WireError::Protocol(m) => CoordinatorError::Protocol(m),
            WireError::Closed => CoordinatorError::Wire(WireError::Closed),
        }
    }
}
