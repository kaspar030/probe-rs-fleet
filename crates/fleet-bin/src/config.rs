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

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use fleet_coordinator::config::{CoordinatorConfig, SigningKeySource, TlsConfig};
use fleet_core::policy::Policy;

/// Optional coordinator-terminated TLS, as a `[tls]` table.
#[derive(Debug, Clone, Deserialize)]
struct TlsToml {
    /// PEM file holding the coordinator's server certificate chain.
    cert: PathBuf,
    /// PEM file holding the coordinator's server private key.
    key: PathBuf,
}

/// The on-disk shape of `coordinator.toml`.
///
/// Exactly one of `signing_key_hex` / `signing_key_path` must be provided.
#[derive(Debug, Clone, Deserialize)]
struct CoordinatorConfigToml {
    /// TCP address to listen on. Loopback by default: the expected deployment
    /// is behind a reverse proxy on the same host.
    listen_addr: SocketAddr,
    /// The externally reachable base URL operators hand to `agent init` /
    /// `ctl init`. Not derivable from `listen_addr` behind a proxy.
    public_url: String,
    /// Coordinator-terminated TLS. Omit it when a proxy terminates TLS (the
    /// hosted deployment) and the coordinator serves plain HTTP on loopback.
    #[serde(default)]
    tls: Option<TlsToml>,
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
    /// How often (seconds) the expiry sweep runs.
    #[serde(default = "default_sweep_interval_secs")]
    sweep_interval_secs: u64,
    /// How often (seconds) to ping an idle connection.
    #[serde(default = "default_ping_interval_secs")]
    ping_interval_secs: u64,
    /// How long (seconds) a connection may be silent before it is dropped.
    #[serde(default = "default_pong_timeout_secs")]
    pong_timeout_secs: u64,
    /// User session token lifetime, seconds.
    #[serde(default = "default_session_ttl_secs")]
    session_ttl_secs: u64,
    /// Node-token rotation age, seconds.
    #[serde(default = "default_node_token_rotate_secs")]
    node_token_rotate_secs: u64,
    /// The org the interim admin verbs default to.
    #[serde(default = "default_org")]
    default_org: String,
}

fn default_sweep_interval_secs() -> u64 {
    5
}

fn default_ping_interval_secs() -> u64 {
    20
}

fn default_pong_timeout_secs() -> u64 {
    60
}

fn default_session_ttl_secs() -> u64 {
    12 * 60 * 60
}

fn default_node_token_rotate_secs() -> u64 {
    fleet_auth::RotationPolicy::DEFAULT.max_age_secs
}

fn default_org() -> String {
    "default".to_owned()
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

    Ok(CoordinatorConfig {
        listen_addr: raw.listen_addr,
        public_url: raw.public_url,
        tls: raw.tls.map(|t| TlsConfig {
            cert: t.cert,
            key: t.key,
        }),
        sqlite_path: raw.sqlite_path,
        signing_key: SigningKeySource::Seed(seed),
        policy: raw.policy,
        sweep_interval_secs: raw.sweep_interval_secs,
        ping_interval_secs: raw.ping_interval_secs,
        pong_timeout_secs: raw.pong_timeout_secs,
        session_ttl_secs: raw.session_ttl_secs,
        node_token_rotate_secs: raw.node_token_rotate_secs,
        default_org: fleet_proto::ids::OrgId(raw.default_org),
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
        *byte =
            u8::from_str_radix(s, 16).with_context(|| "signing key contains non-hex characters")?;
    }
    Ok(out)
}

/// Resolved client (ctl / sidecar) connection configuration loaded from
/// `client.toml`.
///
/// A single `ctl init` writes this file so that both `ctl` and the `probe-rs`
/// sidecar shim discover the coordinator URL and the session token from one
/// place (in addition to the explicit flags / env vars, which take precedence).
///
/// It holds a bearer credential, so it is written 0600. There are no certificate
/// paths any more: one token is the whole credential.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientConfig {
    /// Base URL of the coordinator (`https://fleet.example`), or a bare
    /// `host:port`.
    pub fleet_url: String,
    /// The user's bearer session token.
    pub token: String,
    /// Optional pinned coordinator server-certificate SHA-256, for a
    /// self-hosted deployment with no publicly trusted certificate.
    #[serde(default)]
    pub server_cert_sha256: Option<String>,
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

/// Render a populated `client.toml`.
#[must_use]
pub fn render_client_config(fleet_url: &str, token: &str, pin: Option<&str>) -> String {
    let pin_block = pin.map_or_else(
        || {
            "\n# Optional: pin the coordinator's server certificate by its SHA-256, for a\n\
             # self-hosted deployment with no publicly trusted certificate. Without it the\n\
             # coordinator is verified against the usual public web PKI roots.\n\
             # server_cert_sha256 = \"<64 hex chars>\"\n"
                .to_owned()
        },
        |p| {
            format!(
                "\n# Pinned coordinator server certificate (self-hosted deployment).\n\
                 server_cert_sha256 = {}\n",
                toml::Value::String(p.to_owned())
            )
        },
    );
    format!(
        r"# probe-rs-fleet client config
#
# Generated by `probe-rs-fleet ctl init`. Used by BOTH `ctl` and the `probe-rs`
# sidecar shim to discover the coordinator and the session token when the
# explicit flags / env vars are absent. Discovered at the XDG path
#   $XDG_CONFIG_HOME/probe-rs-fleet/client.toml
#   (i.e. ~/.config/probe-rs-fleet/client.toml).
#
# Precedence: explicit flag / env var > this file.
#
# THIS FILE HOLDS A BEARER CREDENTIAL. It is written 0600; anyone who can read
# `token` can act as you until it expires.

# Base URL of the coordinator (a bare `host:port` is accepted and assumes https).
fleet_url = {fleet_url}

# Your session token. Short-lived and refreshable.
token = {token}
{pin_block}",
        fleet_url = toml::Value::String(fleet_url.to_owned()),
        token = toml::Value::String(token.to_owned()),
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
public_url = "https://fleet.example"
sqlite_path = "coord.sqlite"
signing_key_hex = "{seed}"
sweep_interval_secs = 9
ping_interval_secs = 15
pong_timeout_secs = 45
session_ttl_secs = 3600
node_token_rotate_secs = 86400

[tls]
cert = "cert.pem"
key = "key.pem"
"#
        );
        let f = write_tmp(&toml);
        let cfg = load_coordinator_config(f.path()).unwrap();
        assert_eq!(cfg.listen_addr.port(), 7000);
        assert_eq!(cfg.public_url, "https://fleet.example");
        assert_eq!(cfg.sweep_interval_secs, 9);
        assert_eq!(cfg.ping_interval_secs, 15);
        assert_eq!(cfg.session_ttl_secs, 3600);
        let tls = cfg.tls.as_ref().expect("[tls] table parsed");
        assert_eq!(tls.cert, PathBuf::from("cert.pem"));
        assert_eq!(tls.key, PathBuf::from("key.pem"));
        cfg.validate().unwrap();
    }

    /// Omitting `[tls]` is the *expected* hosted configuration, not an
    /// oversight: a reverse proxy terminates TLS and the coordinator serves
    /// plain HTTP on loopback.
    #[test]
    fn coordinator_config_applies_defaults_and_tls_is_optional() {
        let seed = "01".repeat(32);
        let toml = format!(
            r#"
listen_addr = "127.0.0.1:7000"
public_url = "https://fleet.example"
sqlite_path = "db.sqlite"
signing_key_hex = "{seed}"
"#
        );
        let f = write_tmp(&toml);
        let cfg = load_coordinator_config(f.path()).unwrap();
        assert!(cfg.tls.is_none());
        assert_eq!(cfg.sweep_interval_secs, default_sweep_interval_secs());
        assert_eq!(cfg.ping_interval_secs, default_ping_interval_secs());
        assert_eq!(cfg.pong_timeout_secs, default_pong_timeout_secs());
        assert_eq!(cfg.session_ttl_secs, default_session_ttl_secs());
        assert_eq!(
            cfg.node_token_rotate_secs,
            default_node_token_rotate_secs()
        );
        assert_eq!(cfg.policy, Policy::default());
        cfg.validate().unwrap();
    }

    #[test]
    fn coordinator_config_missing_key_errors() {
        let toml = r#"
listen_addr = "127.0.0.1:1"
public_url = "https://fleet.example"
sqlite_path = "db.sqlite"
"#;
        let f = write_tmp(toml);
        assert!(load_coordinator_config(f.path()).is_err());
    }

    #[test]
    fn coordinator_config_requires_public_url() {
        let seed = "01".repeat(32);
        let toml = format!(
            r#"
listen_addr = "127.0.0.1:7000"
sqlite_path = "db.sqlite"
signing_key_hex = "{seed}"
"#
        );
        let f = write_tmp(&toml);
        assert!(load_coordinator_config(f.path()).is_err());
    }

    #[test]
    fn client_config_round_trips() {
        let rendered = render_client_config("https://fleet.example", "prfs1_secret", None);
        let f = write_tmp(&rendered);
        let cfg = load_client_config(f.path()).unwrap();
        assert_eq!(cfg.fleet_url, "https://fleet.example");
        assert_eq!(cfg.token, "prfs1_secret");
        assert!(cfg.server_cert_sha256.is_none());
    }

    #[test]
    fn client_config_round_trips_with_a_pin() {
        let pin = "ab".repeat(32);
        let rendered = render_client_config("https://fleet.example", "prfs1_s", Some(&pin));
        let f = write_tmp(&rendered);
        let cfg = load_client_config(f.path()).unwrap();
        assert_eq!(cfg.server_cert_sha256.as_deref(), Some(pin.as_str()));
    }

    #[test]
    fn client_config_missing_key_errors() {
        let toml = r#"
fleet_url = "https://fleet.example"
"#;
        let f = write_tmp(toml);
        assert!(load_client_config(f.path()).is_err());
    }
}
