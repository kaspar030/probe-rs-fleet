//! Agent role implementation for probe-rs-fleet (the Raspberry Pi side).
//!
//! The agent owns the locally attached probes. It reconciles discovered probes
//! against an agent-local `boards.toml` (architecture §8), dials **out** to the
//! coordinator over mTLS and holds a persistent connection (§5), and on command
//! drives the lifecycle of per-board `probe-rs serve` processes whose byte
//! streams it splices onto coordinator-relayed data channels (§4.2, per the
//! task #1710 protocol findings). It also owns USB power control for cleanup
//! and fault recovery.
//!
//! Module map:
//! * [`config`] — `boards.toml` + agent-config parsing/validation.
//! * [`discovery`] — probe enumeration and reconciliation.
//! * [`power`] — the [`PowerControl`] trait and uhubctl/gpio/none impls.
//! * [`token`] — local ed25519 capability-token verification.
//! * [`probers`] — `probe-rs serve` lifecycle + byte-proxy.
//! * [`agent`] — the orchestrator and command handlers.
//! * [`connection`] — the dial-out control-plane loop.
//!
//! No `unsafe` code is used (enforced by the workspace lint).

pub mod agent;
pub mod config;
pub mod connection;
pub mod discovery;
pub mod error;
pub mod gdb;
pub mod power;
pub mod probers;
pub mod token;

pub use agent::Agent;
pub use config::{AgentConfig, BoardSpec, BoardsConfig, ConfigError, PowerSpec};
pub use connection::Backoff;
pub use discovery::{reconcile, ProbeLister};
pub use error::{AgentError, Result};
pub use power::{CommandRunner, PowerControl, PowerError};
pub use probers::{ProbeRsBackend, ProcessBackend, Session, SpliceIo};
pub use token::Ed25519Verifier;
