//! Identifier newtypes used across the fleet wire protocol.

use serde::{Deserialize, Serialize};

/// Stable, human-meaningful board identifier (e.g. `"nrf52840-dk-3"`).
///
/// Declared in an agent's `boards.toml` and unique across the fleet. This is
/// the unit of leasing — *not* a probe serial (the agent maps it to a real
/// `--probe <serial>` locally).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BoardId(pub String);

/// Identifies an agent (Raspberry Pi). Pinned to a TLS client-cert
/// fingerprint in coordinator config.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AgentId(pub String);

/// Identifies an active lease. Allocated by the coordinator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LeaseId(pub u64);

/// An authenticated caller: a developer or a CI service account. Derived from
/// the TLS client-cert principal at connection time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Principal(pub String);

impl std::fmt::Display for BoardId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for Principal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
