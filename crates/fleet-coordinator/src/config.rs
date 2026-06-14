//! Coordinator configuration.
//!
//! This is the in-process configuration struct plus light validation. Loading
//! it from a file (TOML) and wiring the CLI is the job of `fleet-bin` (task
//! 1714); here we only model the shape so the rest of the crate can depend on
//! it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use fleet_core::policy::Policy;
use fleet_proto::ids::AgentId;

use crate::error::{CoordinatorError, Result};

/// Where the coordinator's ed25519 signing key comes from.
#[derive(Debug, Clone)]
pub enum SigningKeySource {
    /// A raw 32-byte ed25519 seed (e.g. loaded from a key file by `fleet-bin`).
    Seed([u8; 32]),
}

/// Full coordinator configuration.
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// The TCP address to listen on for inbound mTLS connections.
    pub listen_addr: SocketAddr,
    /// The address (`host:port`) that clients/agents should dial to reach this
    /// coordinator, embedded into enrollment tokens.
    ///
    /// This is distinct from [`listen_addr`](Self::listen_addr): the listen
    /// address is frequently a wildcard (`0.0.0.0` / `::`) which is not
    /// routable from another host. When unset, `coordinator enroll` falls back
    /// to `listen_addr` but errors if that is a wildcard.
    pub advertise_addr: Option<String>,
    /// PEM file holding the coordinator's server certificate chain.
    pub tls_cert: PathBuf,
    /// PEM file holding the coordinator's server private key.
    pub tls_key: PathBuf,
    /// PEM file holding the CA used to verify client (agent/sidecar) certs.
    pub client_ca: PathBuf,
    /// PEM file holding the client CA's private key, used to sign CSRs during
    /// bootstrap enrollment.
    pub client_ca_key: PathBuf,
    /// Path to the `SQLite` database file.
    pub sqlite_path: PathBuf,
    /// The capability-token signing key.
    pub signing_key: SigningKeySource,
    /// Lease scheduling policy.
    pub policy: Policy,
    /// Pinned agents: maps a cert SHA-256 fingerprint to the expected
    /// [`AgentId`]. A connection whose principal/fingerprint is in this map is
    /// treated as an agent; everything else is a sidecar.
    pub pinned_agents: HashMap<String, AgentId>,
    /// How often (seconds) the expiry sweep runs.
    pub sweep_interval_secs: u64,
}

impl CoordinatorConfig {
    /// Validate the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::Config`] if a required path is empty or the
    /// sweep interval is zero.
    pub fn validate(&self) -> Result<()> {
        for (label, path) in [
            ("tls_cert", &self.tls_cert),
            ("tls_key", &self.tls_key),
            ("client_ca", &self.client_ca),
            ("client_ca_key", &self.client_ca_key),
            ("sqlite_path", &self.sqlite_path),
        ] {
            if path.as_os_str().is_empty() {
                return Err(CoordinatorError::Config(format!("{label} path is empty")));
            }
        }
        if self.sweep_interval_secs == 0 {
            return Err(CoordinatorError::Config(
                "sweep_interval_secs must be non-zero".to_owned(),
            ));
        }
        Ok(())
    }

    /// Whether the given cert fingerprint identifies a pinned agent.
    #[must_use]
    pub fn agent_for_fingerprint(&self, fingerprint: &str) -> Option<&AgentId> {
        self.pinned_agents.get(fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> CoordinatorConfig {
        CoordinatorConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            advertise_addr: None,
            tls_cert: "cert.pem".into(),
            tls_key: "key.pem".into(),
            client_ca: "ca.pem".into(),
            client_ca_key: "ca-key.pem".into(),
            sqlite_path: "coord.sqlite".into(),
            signing_key: SigningKeySource::Seed([0u8; 32]),
            policy: Policy::default(),
            pinned_agents: HashMap::new(),
            sweep_interval_secs: 5,
        }
    }

    #[test]
    fn valid_config_passes() {
        assert!(cfg().validate().is_ok());
    }

    #[test]
    fn empty_path_rejected() {
        let mut c = cfg();
        c.tls_cert = PathBuf::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn zero_sweep_interval_rejected() {
        let mut c = cfg();
        c.sweep_interval_secs = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn agent_pinning_lookup() {
        let mut c = cfg();
        c.pinned_agents
            .insert("abcd".to_owned(), AgentId("agent-a".to_owned()));
        assert_eq!(
            c.agent_for_fingerprint("abcd"),
            Some(&AgentId("agent-a".to_owned()))
        );
        assert!(c.agent_for_fingerprint("zzzz").is_none());
    }
}
