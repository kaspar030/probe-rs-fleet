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
//!
//! Client-side configuration is **not** here: since revision 2 it is one file
//! per fleet, owned by [`crate::fleet_config`]. `fleet_agent::AgentConfig` is
//! likewise no longer a file format — the agent role assembles it from the
//! fleet file plus `node/node.toml`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use fleet_coordinator::config::{
    AuthConfig, CoordinatorConfig, GithubActionsConfig, GithubEndpoints, ProviderConfig,
    ProviderKind, SigningKeySource, TlsConfig,
};
use fleet_core::policy::Policy;

/// Optional coordinator-terminated TLS, as a `[tls]` table.
#[derive(Debug, Clone, Deserialize)]
struct TlsToml {
    /// PEM file holding the coordinator's server certificate chain.
    cert: PathBuf,
    /// PEM file holding the coordinator's server private key.
    key: PathBuf,
}

/// One `[[auth.providers]]` entry: a login provider for `probe-rs-fleet
/// login` and the web UI.
///
/// A provider **proves who you are; it does not name you**: the username is
/// chosen on first login. Omit every provider for an air-gapped or
/// development fleet; `coordinator user-token` is then the bootstrap path.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderToml {
    /// `github` | `oidc` | `codeberg` | `gitlab`.
    kind: String,
    /// Instance name, used in URLs (`/auth/{name}/start`). Defaults to `kind`.
    #[serde(default)]
    name: Option<String>,
    /// OAuth client id.
    client_id: String,
    /// OAuth client secret, inline.
    #[serde(default)]
    client_secret: Option<String>,
    /// A file holding the client secret (preferred: keeps it out of the
    /// config).
    #[serde(default)]
    client_secret_path: Option<PathBuf>,
    /// OIDC issuer (required for `oidc`; overrides the `codeberg`/`gitlab`
    /// preset; a GitHub Enterprise origin for `github`).
    #[serde(default)]
    issuer: Option<String>,
    /// GitHub only: explicit endpoints, all three or none (tests, GHES).
    #[serde(default)]
    authorize_url: Option<String>,
    /// See [`ProviderToml::authorize_url`].
    #[serde(default)]
    access_token_url: Option<String>,
    /// See [`ProviderToml::authorize_url`].
    #[serde(default)]
    api_base: Option<String>,
}

/// The `[auth]` table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthToml {
    /// Login providers.
    #[serde(default)]
    providers: Vec<ProviderToml>,
}

impl ProviderToml {
    fn into_config(self) -> Result<ProviderConfig> {
        let kind = ProviderKind::from_label(&self.kind).with_context(|| {
            format!(
                "auth.providers: unknown kind `{}` (expected github, oidc, codeberg or gitlab)",
                self.kind
            )
        })?;
        let name = self.name.unwrap_or_else(|| self.kind.clone());
        let client_secret = match (self.client_secret, self.client_secret_path) {
            (Some(_), Some(_)) => anyhow::bail!(
                "auth.providers `{name}`: set only one of `client_secret` or `client_secret_path`"
            ),
            (Some(s), None) => s,
            (None, Some(p)) => std::fs::read_to_string(&p)
                .with_context(|| {
                    format!(
                        "auth.providers `{name}`: reading client_secret_path {}",
                        p.display()
                    )
                })?
                .trim()
                .to_owned(),
            (None, None) => String::new(),
        };
        let github_endpoints = match (self.authorize_url, self.access_token_url, self.api_base) {
            (Some(authorize_url), Some(access_token_url), Some(api_base)) => {
                Some(GithubEndpoints {
                    authorize_url,
                    access_token_url,
                    api_base,
                })
            }
            (None, None, None) => None,
            _ => anyhow::bail!(
                "auth.providers `{name}`: set all of authorize_url, access_token_url and \
                 api_base, or none"
            ),
        };
        Ok(ProviderConfig {
            kind,
            name,
            client_id: self.client_id,
            client_secret,
            issuer: self.issuer,
            github_endpoints,
        })
    }
}

/// The `[github_actions]` table: the OIDC issuer backing `probe-rs-fleet ci
/// login` (architecture §6.7).
///
/// Independent of the login providers: a fleet may have CI without user
/// login, or the reverse. `audience` has **no default** — see [`GithubActionsToml::audience`].
#[derive(Debug, Clone, Deserialize)]
struct GithubActionsToml {
    /// The `aud` claim a workload token must carry.
    ///
    /// Required, deliberately. GitHub's default audience is
    /// `https://github.com/<owner>`, which is not fleet-specific, so a token
    /// minted for another service under the same owner would be replayable
    /// here. Set it to this coordinator's `public_url`.
    audience: String,
    /// The expected `iss` claim. Overridable for GitHub Enterprise.
    #[serde(default = "default_gha_issuer")]
    issuer: String,
    /// Where the issuer publishes its signing keys. Overridable so a test can
    /// point it at a loopback stub.
    #[serde(default = "default_gha_jwks_url")]
    jwks_url: String,
    /// JWKS cache staleness horizon, seconds.
    #[serde(default = "default_jwks_refresh_secs")]
    jwks_refresh_secs: u64,
    /// Floor between refetches forced by an unknown `kid`, seconds.
    #[serde(default = "default_jwks_min_refetch_secs")]
    jwks_min_refetch_secs: u64,
    /// Minted workload-token lifetime, seconds.
    #[serde(default = "default_workload_token_ttl_secs")]
    workload_token_ttl_secs: u64,
}

fn default_gha_issuer() -> String {
    fleet_coordinator::config::DEFAULT_GHA_ISSUER.to_owned()
}

fn default_gha_jwks_url() -> String {
    fleet_coordinator::config::DEFAULT_GHA_JWKS_URL.to_owned()
}

fn default_jwks_refresh_secs() -> u64 {
    3600
}

fn default_jwks_min_refetch_secs() -> u64 {
    60
}

fn default_workload_token_ttl_secs() -> u64 {
    3600
}

/// The on-disk shape of `coordinator.toml`.
///
/// Exactly one of `signing_key_hex` / `signing_key_path` must be provided.
#[derive(Debug, Clone, Deserialize)]
struct CoordinatorConfigToml {
    /// TCP address to listen on. Loopback by default: the expected deployment
    /// is behind a reverse proxy on the same host.
    listen_addr: SocketAddr,
    /// The externally reachable base URL operators hand to `node up` /
    /// `login`. Not derivable from `listen_addr` behind a proxy.
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
    /// Refresh token lifetime, seconds.
    #[serde(default = "default_refresh_token_ttl_secs")]
    refresh_token_ttl_secs: u64,
    /// Node-token rotation age, seconds.
    #[serde(default = "default_node_token_rotate_secs")]
    node_token_rotate_secs: u64,
    /// How long an approval-pending node registration lives, seconds.
    #[serde(default = "default_pending_node_ttl_secs")]
    pending_node_ttl_secs: u64,
    /// Ceiling on live pending node registrations.
    #[serde(default = "default_max_pending_nodes")]
    max_pending_nodes: i64,
    /// The **name** of the deployment's shared org (created at startup); the
    /// org the shell admin verbs default to.
    #[serde(default = "default_org")]
    default_org: String,
    /// The cookie/CSRF secret file (≥ 32 bytes, hex or raw). Required to run
    /// the daemon; `coordinator init` writes one.
    #[serde(default)]
    csrf_secret_path: Option<PathBuf>,
    /// Login providers (`[[auth.providers]]`).
    #[serde(default)]
    auth: AuthToml,
    /// The GitHub Actions OIDC issuer backing `probe-rs-fleet ci login`.
    #[serde(default)]
    github_actions: Option<GithubActionsToml>,
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

/// 30 days — the same bound `http::MAX_API_AUTH_KEY_TTL_SECS` already places on
/// a durable bearer credential a member may hold. A refresh token is strictly
/// weaker than an auth key, so it does not deserve a longer one.
fn default_refresh_token_ttl_secs() -> u64 {
    30 * 24 * 3600
}

fn default_node_token_rotate_secs() -> u64 {
    forgs::RotationPolicy::DEFAULT.max_age_secs
}

fn default_org() -> String {
    fleet_coordinator::config::DEFAULT_ORG_NAME.to_owned()
}

fn default_pending_node_ttl_secs() -> u64 {
    15 * 60
}

fn default_max_pending_nodes() -> i64 {
    256
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

    let seed = load_signing_seed(
        raw.signing_key_hex.as_deref(),
        raw.signing_key_path.as_deref(),
    )?;

    let csrf_secret = raw
        .csrf_secret_path
        .as_deref()
        .map(load_csrf_secret)
        .transpose()?;
    let providers = raw
        .auth
        .providers
        .into_iter()
        .map(ProviderToml::into_config)
        .collect::<Result<Vec<_>>>()?;

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
        refresh_token_ttl_secs: raw.refresh_token_ttl_secs,
        node_token_rotate_secs: raw.node_token_rotate_secs,
        pending_node_ttl_secs: raw.pending_node_ttl_secs,
        max_pending_nodes: raw.max_pending_nodes,
        default_org: raw.default_org,
        auth: AuthConfig { providers },
        csrf_secret,
        github_actions: raw.github_actions.map(|g| GithubActionsConfig {
            issuer: g.issuer,
            jwks_url: g.jwks_url,
            audience: g.audience,
            jwks_refresh_secs: g.jwks_refresh_secs,
            jwks_min_refetch_secs: g.jwks_min_refetch_secs,
            workload_token_ttl_secs: g.workload_token_ttl_secs,
        }),
    })
}

/// Read the CSRF secret file: 64+ hex characters (decoded), or raw bytes.
/// At least 32 bytes either way.
fn load_csrf_secret(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("failed to read csrf secret {}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    let trimmed = text.trim();
    let secret = if trimmed.len() >= 64
        && trimmed.len() % 2 == 0
        && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
    {
        (0..trimmed.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&trimmed[i..i + 2], 16))
            .collect::<std::result::Result<Vec<u8>, _>>()
            .context("csrf secret contains non-hex characters")?
    } else {
        bytes
    };
    anyhow::ensure!(
        secret.len() >= 32,
        "the csrf secret in {} must be at least 32 bytes",
        path.display()
    );
    Ok(secret)
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
        assert_eq!(cfg.node_token_rotate_secs, default_node_token_rotate_secs());
        assert_eq!(cfg.policy, Policy::default());
        cfg.validate().unwrap();
    }

    #[test]
    fn providers_and_csrf_secret_are_loaded() {
        let seed = "01".repeat(32);
        let dir = tempfile::tempdir().unwrap();
        let csrf = dir.path().join("csrf.secret");
        std::fs::write(&csrf, "cd".repeat(32)).unwrap();
        let secret = dir.path().join("gh.secret");
        std::fs::write(&secret, "s3cret\n").unwrap();
        let toml = format!(
            r#"
listen_addr = "127.0.0.1:7000"
public_url = "https://fleet.example"
sqlite_path = "db.sqlite"
signing_key_hex = "{seed}"
csrf_secret_path = "{}"

[[auth.providers]]
kind = "github"
client_id = "Iv1.x"
client_secret_path = "{}"

[[auth.providers]]
kind = "oidc"
name = "sso"
client_id = "c"
client_secret = "s"
issuer = "https://sso.example"
"#,
            csrf.display(),
            secret.display()
        );
        let cfg = load_coordinator_config_from_str(&toml).unwrap();
        assert_eq!(cfg.csrf_secret.as_deref(), Some(&[0xcd_u8; 32][..]));
        assert_eq!(cfg.auth.providers.len(), 2);
        assert_eq!(cfg.auth.providers[0].name, "github");
        assert_eq!(cfg.auth.providers[0].client_secret, "s3cret");
        assert_eq!(cfg.auth.providers[1].kind, ProviderKind::Oidc);
        cfg.validate().unwrap();

        std::fs::write(&csrf, "short").unwrap();
        assert!(load_coordinator_config_from_str(&toml).is_err());
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
}
