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
    /// Address (`host:port`) clients/agents should dial to reach this
    /// coordinator, embedded into enrollment tokens. Defaults to `listen_addr`
    /// (with a wildcard rejected at enroll time).
    #[serde(default)]
    advertise_addr: Option<String>,
    /// PEM file holding the coordinator's server certificate chain.
    tls_cert: PathBuf,
    /// PEM file holding the coordinator's server private key.
    tls_key: PathBuf,
    /// PEM file holding the CA used to verify client (agent/sidecar) certs.
    client_ca: PathBuf,
    /// PEM file holding the client CA's private key (used to sign CSRs during
    /// bootstrap enrollment).
    client_ca_key: PathBuf,
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
    load_coordinator_config_from_str(&text)
}

/// Parse a coordinator config from TOML text, converting it into the runtime
/// [`CoordinatorConfig`].
///
/// # Errors
///
/// Returns an error if the TOML is malformed or the signing-key material is
/// missing / invalid.
pub fn load_coordinator_config_from_str(text: &str) -> Result<CoordinatorConfig> {
    let raw: CoordinatorConfigToml =
        toml::from_str(text).context("failed to parse coordinator config")?;

    let seed = load_signing_seed(raw.signing_key_hex.as_deref(), raw.signing_key_path.as_deref())?;

    let pinned_agents = raw
        .pinned_agents
        .into_iter()
        .map(|(fp, id)| (fp, AgentId(id)))
        .collect();

    Ok(CoordinatorConfig {
        listen_addr: raw.listen_addr,
        advertise_addr: raw.advertise_addr,
        tls_cert: raw.tls_cert,
        tls_key: raw.tls_key,
        client_ca: raw.client_ca,
        client_ca_key: raw.client_ca_key,
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
/// Resolved client (ctl / sidecar) connection configuration loaded from
/// `client.toml`.
///
/// A single `ctl init` writes this file so that both `ctl` and the `probe-rs`
/// sidecar shim discover the coordinator endpoint and client credentials from
/// one place (in addition to the explicit flags / env vars, which take
/// precedence).
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// `host:port` of the coordinator to connect to.
    pub coordinator: String,
    /// Client certificate chain (PEM).
    pub cert: PathBuf,
    /// Client private key (PEM).
    pub key: PathBuf,
    /// CA used to verify the coordinator's server cert (PEM).
    pub ca: PathBuf,
}

/// Load and parse a client config TOML file (`client.toml`).
///
/// # Errors
///
/// Returns an error if the file cannot be read or the TOML is malformed /
/// missing required keys.
pub fn load_client_config(path: &Path) -> Result<ClientConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read client config {}", path.display()))?;
    let cfg: ClientConfig = toml::from_str(&text)
        .with_context(|| format!("failed to parse client config {}", path.display()))?;
    Ok(cfg)
}

/// Render a populated `client.toml` referencing the imported credential files.
#[must_use]
pub fn render_client_config(coordinator: &str, cert: &Path, key: &Path, ca: &Path) -> String {
    format!(
        r"# probe-rs-fleet client config
#
# Generated by `probe-rs-fleet ctl init`. Used by BOTH `ctl` and the `probe-rs`
# sidecar shim to discover the coordinator endpoint and client credentials when
# the explicit flags / env vars are absent. Discovered at the XDG path
#   $XDG_CONFIG_HOME/probe-rs-fleet/client.toml
#   (i.e. ~/.config/probe-rs-fleet/client.toml).
#
# Precedence: explicit flag / env var > this file.

# `host:port` of the coordinator to connect to.
coordinator = {coordinator}

# Client certificate chain (PEM), issued by `coordinator enroll`.
cert = {cert}

# Client private key (PEM). Keep this 0600.
key = {key}

# CA used to verify the coordinator's server certificate (PEM).
ca = {ca}
",
        coordinator = toml::Value::String(coordinator.to_owned()),
        cert = toml::Value::String(cert.display().to_string()),
        key = toml::Value::String(key.display().to_string()),
        ca = toml::Value::String(ca.display().to_string()),
    )
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
client_ca_key = "ca-key.pem"
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
client_ca_key = "ca-key.pem"
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
client_ca_key = "ca-key.pem"
sqlite_path = "db.sqlite"
"#;
        let f = write_tmp(toml);
        assert!(load_coordinator_config(f.path()).is_err());
    }

    #[test]
    fn coordinator_config_parses_advertise_addr() {
        let seed = "cd".repeat(32);
        let toml = format!(
            r#"
listen_addr = "0.0.0.0:7000"
advertise_addr = "192.168.1.10:7000"
tls_cert = "c.pem"
tls_key = "k.pem"
client_ca = "ca.pem"
client_ca_key = "ca-key.pem"
sqlite_path = "db.sqlite"
signing_key_hex = "{seed}"
"#
        );
        let f = write_tmp(&toml);
        let cfg = load_coordinator_config(f.path()).unwrap();
        assert_eq!(cfg.advertise_addr.as_deref(), Some("192.168.1.10:7000"));
    }

    #[test]
    fn coordinator_config_advertise_addr_defaults_none() {
        let seed = "01".repeat(32);
        let toml = format!(
            r#"
listen_addr = "0.0.0.0:443"
tls_cert = "c.pem"
tls_key = "k.pem"
client_ca = "ca.pem"
client_ca_key = "ca-key.pem"
sqlite_path = "db.sqlite"
signing_key_hex = "{seed}"
"#
        );
        let f = write_tmp(&toml);
        let cfg = load_coordinator_config(f.path()).unwrap();
        assert!(cfg.advertise_addr.is_none());
    }

    #[test]
    fn client_config_round_trips() {
        let rendered = render_client_config(
            "coord.example:7000",
            Path::new("/data/client-cert.pem"),
            Path::new("/data/client-key.pem"),
            Path::new("/data/client-ca.pem"),
        );
        let f = write_tmp(&rendered);
        let cfg = load_client_config(f.path()).unwrap();
        assert_eq!(cfg.coordinator, "coord.example:7000");
        assert_eq!(cfg.cert, PathBuf::from("/data/client-cert.pem"));
        assert_eq!(cfg.key, PathBuf::from("/data/client-key.pem"));
        assert_eq!(cfg.ca, PathBuf::from("/data/client-ca.pem"));
    }

    #[test]
    fn client_config_missing_key_errors() {
        let toml = r#"
coordinator = "c:1"
cert = "c.pem"
key = "k.pem"
"#;
        let f = write_tmp(toml);
        assert!(load_client_config(f.path()).is_err());
    }

}
