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

pub mod adopt;
pub mod admin;
pub mod agent_api;
pub mod board;
pub mod ids;
pub mod lease;
pub mod token;

pub use adopt::AdoptPolicy;
pub use admin::{BoardAvailability, BoardSummary, GrantSummary, LeaseHolderSummary, LogLine};
pub use agent_api::{
    AgentReport, BoardPresence, BoardStatus, ChannelKind, CoordinatorCommand, DiscoveredProbe,
    LogLevel, PowerAction, ProbeInventory,
};
pub use board::{Board, BoardState, PowerKind};
pub use ids::{
    normalise_repo, workload_subject_key, AgentId, BoardName, BoardRef, Group, LeaseId, NodeId,
    OrgId, Role, Subject, SubjectKey, SubjectKind, UserId, WORKLOAD_NS_GHA,
};
pub use lease::{
    parse_constraint, Constraint, ConstraintParseError, LeaseGrant, LeaseRequest,
};
pub use token::{
    normalize_ops, parse_ops, AllowedOp, CapabilityToken, SignedToken, TokenError, TokenSigner,
    TokenVerifier, SIGNATURE_LEN,
};

/// An opaque chunk of data-plane bytes (probe-rs postcard-rpc frames).
///
/// The coordinator relays these between a sidecar and the owning agent without
/// interpreting them. The `channel` ties the bytes to an open session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFrame {
    pub channel: ChannelId,
    pub bytes: Vec<u8>,
}

/// Identifies one open relay session (data plane *or* gdb plane) multiplexed
/// over an agent's dial-out connection. Allocated by the coordinator when a
/// lease opens a probe-rs session. The byte stream a channel carries is opaque
/// to the coordinator; what the bytes *mean* (and how the agent/sidecar source
/// and sink them) is determined by the [`ChannelKind`] recorded at open time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId(pub u64);

/// Wire protocol version. Bumped on any incompatible change to the control
/// plane message set. Peers exchange this at connection setup and refuse
/// mismatches.
///
/// A bump forces a **lockstep** upgrade of agent + coordinator + sidecar + ctl.
/// All four roles ship from the single `fleet-bin` binary, so that is cheap in
/// practice, but a half-upgraded fleet will refuse to connect (by design).
///
/// * 2 → 3: [`DiscoveredProbe`] gained `inaccessible` (probe-rs 0.32 `probe-rs
///   list` reports probes it cannot open). postcard is positional, so adding a
///   field changes the encoding of every `AgentReport::Inventory`; `#[serde(default)]`
///   would not have saved it.
/// * 3 → 4: revision-2 identity. `Principal` is replaced by [`ids::Subject`]
///   (org + kind + id + groups) and the flat `BoardId` is split into a
///   fleet-unique [`ids::BoardRef`] (`(org, node, name)`) and a node-local
///   [`ids::BoardName`]. postcard is positional, so every envelope carrying
///   either re-encodes.
/// * 4 → 5: revision-2 transport and credentials. The control plane moved from
///   a bespoke `u32`-length-prefixed TCP stream to **binary `WebSocket`
///   messages over HTTPS** (architecture §3.5): the length prefix is gone, the
///   envelopes are unchanged. Node-token rotation added
///   [`agent_api::CoordinatorCommand::RotateNodeToken`] and its ack
///   [`agent_api::AgentReport::TokenRotated`]; adding variants to a postcard
///   enum shifts later discriminants, so this is not wire-compatible either
///   way.
/// * 5 → 6: per-node probe adoption ([`adopt::AdoptPolicy`]).
///   [`agent_api::BoardStatus`] gained `adopted`, distinguishing a board the
///   node synthesised from an undeclared probe under `adopt = "auto"` from one
///   declared in `boards.toml`. postcard is positional, so the added field
///   re-encodes every `AgentReport::Inventory`; `#[serde(default)]` would not
///   have saved it.
/// * 6 → 7: sharing (architecture §6.5) and the data-plane token fix.
///   `CoordToSidecar::ChannelOpened` gained `token`, the exact capability-token
///   bytes the coordinator sent the agent — previously the sidecar re-used
///   [`LeaseGrant::token`] and the two matched only by coincidence, which an
///   `Extend` (or an attenuating grant) breaks. The sidecar plane also gained
///   the grant verbs (`GrantCreate`/`GrantList`/`GrantRevoke`) and `Delegate`,
///   with their replies; adding variants to a postcard enum shifts every later
///   discriminant, so this is not wire-compatible either way.
/// * 7 → 8: board **models** (`board=<model>`). The old `Constraint::Board`
///   is renamed [`Constraint::Id`] and a new [`Constraint::Model`] variant is
///   inserted after it, so `board=` now selects any board of a model and the
///   instance selector is `id=`. [`agent_api::BoardStatus`] and
///   [`admin::BoardSummary`] gained `model`. postcard is positional in both
///   respects — variant order and field order — so every envelope carrying a
///   `Constraint` or an inventory report re-encodes. Agent and coordinator
///   must be deployed together, and a coordinator DB whose stored grant
///   selectors say `board=<instance>` must be wiped: those rows now parse as
///   a *model* selector and match nothing.
/// * 8 → 9: the lease decision split. `CoordToSidecar` gained `NoCandidate`
///   and `AtCap`, so "queued" now means only what it says — matching boards
///   exist but are busy — instead of also covering "no such board for you" and
///   "you are at your own concurrency cap". Both variants are **appended** to
///   the enum, which leaves every existing discriminant where it was, but
///   postcard peers still reject an unknown one, so an old sidecar cannot
///   decode either. A `Queued` reply now also implies a promotion push may
///   follow on the same connection.
pub const PROTOCOL_VERSION: u32 = 9;
