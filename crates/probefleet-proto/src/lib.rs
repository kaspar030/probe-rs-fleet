//! Shared wire types for probe-rs-fleet.
//!
//! This crate is pure data: no I/O, no async, no transport. It defines the
//! identifiers, requests, and responses exchanged across the control plane
//! (sidecar ⇄ coordinator ⇄ node). The data plane carries *opaque* probe-rs
//! postcard-rpc frames and is intentionally not modeled here — see
//! [`DataFrame`].
//!
//! See `docs/architecture.md` for how these types map onto the topology.

use serde::{Deserialize, Serialize};

pub mod admin;
pub mod adopt;
pub mod auth_api;
pub mod board;
pub mod ids;
pub mod lease;
pub mod node_api;
pub mod token;

pub use admin::{
    BoardAvailability, BoardSummary, GrantSummary, LeaseHolderSummary, LogLine, NodeSummary,
};
pub use adopt::AdoptPolicy;
pub use board::{Board, BoardState, PowerKind};
pub use ids::{BoardName, BoardRef, LeaseId, NodeId, OrgId, SubjectKey, SubjectKind};
pub use lease::{parse_constraint, Constraint, ConstraintParseError, LeaseGrant, LeaseRequest};
pub use node_api::{
    BoardPresence, BoardStatus, ChannelKind, CoordinatorCommand, DiscoveredProbe, LogLevel,
    NodeReport, PowerAction, ProbeInventory,
};
pub use token::{
    normalize_ops, parse_ops, AllowedOp, CapabilityToken, SignedToken, TokenError, TokenSigner,
    TokenVerifier, SIGNATURE_LEN,
};

/// An opaque chunk of data-plane bytes (probe-rs postcard-rpc frames).
///
/// The coordinator relays these between a sidecar and the owning node without
/// interpreting them. The `channel` ties the bytes to an open session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataFrame {
    pub channel: ChannelId,
    pub bytes: Vec<u8>,
}

/// Identifies one open relay session (data plane *or* gdb plane) multiplexed
/// over a node's dial-out connection. Allocated by the coordinator when a
/// lease opens a probe-rs session. The byte stream a channel carries is opaque
/// to the coordinator; what the bytes *mean* (and how the node/sidecar source
/// and sink them) is determined by the [`ChannelKind`] recorded at open time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId(pub u64);

/// Wire protocol version. Bumped on any incompatible change to the control
/// plane message set. Peers exchange this at connection setup and refuse
/// mismatches.
///
/// A bump forces a **lockstep** upgrade of node + coordinator + sidecar + ctl.
/// All four roles ship from the single `probefleet` binary, so that is cheap in
/// practice, but a half-upgraded fleet will refuse to connect (by design).
///
/// * 2 → 3: [`DiscoveredProbe`] gained `inaccessible` (probe-rs 0.32 `probe-rs
///   list` reports probes it cannot open). postcard is positional, so adding a
///   field changes the encoding of every `NodeReport::Inventory`; `#[serde(default)]`
///   would not have saved it.
/// * 3 → 4: revision-2 identity. `Principal` is replaced by `ids::Subject`
///   (org + kind + id + groups) and the flat `BoardId` is split into a
///   fleet-unique [`ids::BoardRef`] (`(org, node, name)`) and a node-local
///   [`ids::BoardName`]. postcard is positional, so every envelope carrying
///   either re-encodes.
/// * 4 → 5: revision-2 transport and credentials. The control plane moved from
///   a bespoke `u32`-length-prefixed TCP stream to **binary `WebSocket`
///   messages over HTTPS** (architecture §3.5): the length prefix is gone, the
///   envelopes are unchanged. Node-token rotation added
///   [`node_api::CoordinatorCommand::RotateNodeToken`] and its ack
///   [`node_api::NodeReport::TokenRotated`]; adding variants to a postcard
///   enum shifts later discriminants, so this is not wire-compatible either
///   way.
/// * 5 → 6: per-node probe adoption ([`adopt::AdoptPolicy`]).
///   [`node_api::BoardStatus`] gained `adopted`, distinguishing a board the
///   node synthesised from an undeclared probe under `adopt = "auto"` from one
///   declared in `boards.toml`. postcard is positional, so the added field
///   re-encodes every `NodeReport::Inventory`; `#[serde(default)]` would not
///   have saved it.
/// * 6 → 7: sharing (architecture §6.5) and the data-plane token fix.
///   `CoordToSidecar::ChannelOpened` gained `token`, the exact capability-token
///   bytes the coordinator sent the node — previously the sidecar re-used
///   [`LeaseGrant::token`] and the two matched only by coincidence, which an
///   `Extend` (or an attenuating grant) breaks. The sidecar plane also gained
///   the grant verbs (`GrantCreate`/`GrantList`/`GrantRevoke`) and `Delegate`,
///   with their replies; adding variants to a postcard enum shifts every later
///   discriminant, so this is not wire-compatible either way.
/// * 7 → 8: board **models** (`board=<model>`). The old `Constraint::Board`
///   is renamed [`Constraint::Id`] and a new [`Constraint::Model`] variant is
///   inserted after it, so `board=` now selects any board of a model and the
///   instance selector is `id=`. [`node_api::BoardStatus`] and
///   [`admin::BoardSummary`] gained `model`. postcard is positional in both
///   respects — variant order and field order — so every envelope carrying a
///   `Constraint` or an inventory report re-encodes. Node and coordinator
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
/// * 9 → 10: node visibility. `SidecarToCoord` gained `ListNodes` and
///   `CoordToSidecar` gained `NodeList(Vec<`[`admin::NodeSummary`]`>)`, which
///   is what `ctl nodes` speaks: node tags (and machines that offer no boards
///   at all) were previously reachable only through the browser API. Both
///   variants are **appended**, so every existing discriminant stays where it
///   was, but a postcard peer still refuses an unknown one — so an old sidecar
///   cannot decode the reply and an old coordinator cannot decode the request.
///   No stored data is affected (contrast 7 → 8, which invalidated
///   `board=`-shaped grant selectors).
/// * 10 → 11: the data-plane token split, so one `probe-rs serve` can be reused
///   across a holder's invocations. [`node_api::CoordinatorCommand::OpenSession`]
///   and `CoordToSidecar::ChannelOpened` each gained a `serve_token: String`:
///   the lowercase-hex `probe-rs serve` user token, minted by the coordinator
///   per **lease** and carried to both ends, which the node writes into the
///   board's `.probe-rs.toml` and the sidecar exports as
///   `PROBE_RS_REMOTE_TOKEN`. `token` keeps its exact meaning — the per-channel
///   capability the node verifies — but stops being what `serve` accepts: a
///   reused serve reads its Figment config once at startup, so a per-channel
///   token would force a respawn for every invocation (which is the `errno 16`
///   bug this split fixes). postcard is positional, so the inserted field
///   re-encodes every `OpenSession` and every `ChannelOpened`; neither end can
///   decode the other's frames across the bump.
/// * 11 → 12: identity moved to **forgs**. `ids::Subject` (org + kind + id +
///   groups), `Group`, `Role` and `UserId` are gone; every holder on the wire
///   ([`LeaseGrant::holder`], `BoardState::Leased::by`, the admin summaries) is
///   now an [`ids::SubjectKey`] — the mirror of `forgs::SubjectKey`, rendering
///   `[<ns>/]<kind>:<id>` with an *optional* namespace (a user is `user:<ulid>`,
///   not addressed in an org). [`ids::OrgId`] now carries a forgs namespace id
///   (a ULID) instead of `gh-<n>`, and [`admin::GrantSummary`] gained display
///   fields. postcard is positional, so every envelope carrying a holder
///   re-encodes, and every stored org id / subject from a v11 coordinator is
///   meaningless to a v12 one (its database starts fresh).
pub const PROTOCOL_VERSION: u32 = 12;
