//! Shared configuration loading for fleet roles.
//!
//! The sibling crates each own their *runtime* config struct:
//! [`fleet_coordinator::config::CoordinatorConfig`] and
//! [`fleet_agent::config::AgentConfig`] / `BoardsConfig`. The agent's config
//! already derives `serde::Deserialize`, so it is loaded directly via its own
//! `from_path`. The coordinator's struct intentionally does *not* derive
//! `Deserialize` (it carries non-serialisable runtime types), so this module
//! owns the on-disk TOML shape and the conversion into the runtime struct —
//! that mapping is precisely "the job of `fleet-bin`" called out in the
//! coordinator config docs.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use fleet_coordinator::config::{CoordinatorConfig, SigningKeySource};
use fleet_core::policy::Policy;
use fleet_proto::ids::AgentId;

/// Where the coordinator's ed25519 signing seed comes from in the TOML file.
///
/// Exactly one of `signing_key_hex` / `signing_key_path` must be provided.
#[derive(Debug, Clone, Deserialize)]
struct CoordinatorConfigToml {
    /// TCP address to listen on for inbound mTLS connections.
    listen_addr: SocketAddr,
    /// PEM file holding the coordinator's server certificate chain.
    tls_cert: PathBuf,
    /// PEM file holding the coordinator's server private key.
    tls_key: PathBuf,
    /// PEM file holding the CA used to verify client (agent/sidecar) certs.
    client_ca: PathBuf,
    /// Path to the `SQLite` database file.
    sqlite_path: PathBuf,
    /// 64-hex-char (32-byte) ed25519 signing seed, inline.
    #[serde(default)]
    signing_key_hex: Option<String>,
    /// Path to a file holding the 64-hex-char ed25519 signing seed.
    #[serde(default)]
    signing_key_path: Option<PathBuf>,
    /// Lease scheduling policy (defaults applied when omitted).
    #[serde(default)]
    policy: Policy,
    /// Pinned agents: cert SHA-256 fingerprint → expected agent id.
    #[serde(default)]
    pinned_agents: HashMap<String, String>,
    /// How often (seconds) the expiry sweep runs.
    #[serde(default = "default_sweep_interval_secs")]
    sweep_interval_secs: u64,
}

fn default_sweep_interval_secs() -> u64 {
    5
}

/// Load and parse a coordinator config TOML file, converting it into the
/// runtime [`CoordinatorConfig`].
///
/// # Errors
///
/// Returns an error if the file cannot be read, the TOML is malformed, or the
/// signing-key material is missing / invalid.
pub fn load_coordinator_config(path: &Path) -> Result<CoordinatorConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read coordinator config {}", path.display()))?;
    let raw: CoordinatorConfigToml = toml::from_str(&text)
        .with_context(|| format!("failed to parse coordinator config {}", path.display()))?;

    let seed = load_signing_seed(raw.signing_key_hex.as_deref(), raw.signing_key_path.as_deref())?;

    let pinned_agents = raw
        .pinned_agents
        .into_iter()
        .map(|(fp, id)| (fp, AgentId(id)))
        .collect();

    Ok(CoordinatorConfig {
        listen_addr: raw.listen_addr,
        tls_cert: raw.tls_cert,
        tls_key: raw.tls_key,
        client_ca: raw.client_ca,
        sqlite_path: raw.sqlite_path,
        signing_key: SigningKeySource::Seed(seed),
        policy: raw.policy,
        pinned_agents,
        sweep_interval_secs: raw.sweep_interval_secs,
    })
}

/// Resolve the 32-byte ed25519 signing seed from the configured source.
fn load_signing_seed(hex: Option<&str>, path: Option<&Path>) -> Result<[u8; 32]> {
    let hex = match (hex, path) {
        (Some(_), Some(_)) => {
            anyhow::bail!("set only one of `signing_key_hex` or `signing_key_path`")
        }
        (Some(h), None) => h.trim().to_owned(),
        (None, Some(p)) => std::fs::read_to_string(p)
            .with_context(|| format!("failed to read signing key {}", p.display()))?
            .trim()
            .to_owned(),
        (None, None) => {
            anyhow::bail!("coordinator config must set `signing_key_hex` or `signing_key_path`")
        }
    };
    decode_seed_hex(&hex)
}

/// Decode a 64-hex-char string into a 32-byte ed25519 seed.
fn decode_seed_hex(hex: &str) -> Result<[u8; 32]> {
    let hex = hex.trim();
    anyhow::ensure!(
        hex.len() == 64,
        "signing key must be 64 hex chars (32 bytes), got {}",
        hex.len()
    );
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let s = &hex[i * 2..i * 2 + 2];
        *byte = u8::from_str_radix(s, 16)
            .with_context(|| "signing key contains non-hex characters")?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn decode_seed_roundtrip() {
        let hex = "00".repeat(32);
        assert_eq!(decode_seed_hex(&hex).unwrap(), [0u8; 32]);
        let hex = "ff".repeat(32);
        assert_eq!(decode_seed_hex(&hex).unwrap(), [0xffu8; 32]);
    }

    #[test]
    fn decode_seed_rejects_wrong_length() {
        assert!(decode_seed_hex("00").is_err());
    }

    #[test]
    fn decode_seed_rejects_non_hex() {
        assert!(decode_seed_hex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn signing_seed_requires_a_source() {
        assert!(load_signing_seed(None, None).is_err());
    }

    #[test]
    fn signing_seed_rejects_both_sources() {
        let seed = "00".repeat(32);
        assert!(load_signing_seed(Some(&seed), Some(Path::new("/tmp/x"))).is_err());
    }

    #[test]
    fn loads_full_coordinator_config() {
        let seed = "ab".repeat(32);
        let toml = format!(
            r#"
listen_addr = "127.0.0.1:7000"
tls_cert = "cert.pem"
tls_key = "key.pem"
client_ca = "ca.pem"
sqlite_path = "coord.sqlite"
signing_key_hex = "{seed}"
sweep_interval_secs = 9

[pinned_agents]
"sha256:abc" = "agent-1"
"#
        );
        let f = write_tmp(&toml);
        let cfg = load_coordinator_config(f.path()).unwrap();
        assert_eq!(cfg.listen_addr.port(), 7000);
        assert_eq!(cfg.sweep_interval_secs, 9);
        assert_eq!(
            cfg.agent_for_fingerprint("sha256:abc"),
            Some(&AgentId("agent-1".to_owned()))
        );
        cfg.validate().unwrap();
    }

    #[test]
    fn coordinator_config_applies_defaults() {
        let seed = "01".repeat(32);
        let toml = format!(
            r#"
listen_addr = "0.0.0.0:443"
tls_cert = "c.pem"
tls_key = "k.pem"
client_ca = "ca.pem"
sqlite_path = "db.sqlite"
signing_key_hex = "{seed}"
"#
        );
        let f = write_tmp(&toml);
        let cfg = load_coordinator_config(f.path()).unwrap();
        assert_eq!(cfg.sweep_interval_secs, default_sweep_interval_secs());
        assert!(cfg.pinned_agents.is_empty());
        assert_eq!(cfg.policy, Policy::default());
    }

    #[test]
    fn coordinator_config_missing_key_errors() {
        let toml = r#"
listen_addr = "127.0.0.1:1"
tls_cert = "c.pem"
tls_key = "k.pem"
client_ca = "ca.pem"
sqlite_path = "db.sqlite"
"#;
        let f = write_tmp(toml);
        assert!(load_coordinator_config(f.path()).is_err());
    }
}
