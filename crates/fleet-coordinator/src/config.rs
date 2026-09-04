//! Coordinator configuration.
//!
//! This is the in-process configuration struct plus light validation. Loading
//! it from a file (TOML) and wiring the CLI is the job of `fleet-bin`; here we
//! only model the shape so the rest of the crate can depend on it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use fleet_core::policy::Policy;
use fleet_proto::ids::OrgId;

use crate::error::{CoordinatorError, Result};

/// Where the coordinator's ed25519 signing key comes from.
#[derive(Debug, Clone)]
pub enum SigningKeySource {
    /// A raw 32-byte ed25519 seed (e.g. loaded from a key file by `fleet-bin`).
    Seed([u8; 32]),
}

/// Optional coordinator-terminated TLS.
///
/// The hosted deployment (architecture §3.5) puts an HTTPS reverse proxy in
/// front and the coordinator speaks plain HTTP on loopback — a proxy terminates
/// TLS and routes `/agent`, `/client`, `/auth/*` and `/healthz` by path, which
/// is the whole reason the transport moved to `WebSocket`s. This table exists
/// for the self-hosted and development case, where there is no proxy.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// PEM file holding the coordinator's server certificate chain.
    pub cert: PathBuf,
    /// PEM file holding the coordinator's server private key.
    pub key: PathBuf,
}

/// The GitHub OAuth app the coordinator brokers the device flow with.
///
/// **OAuth2, not OIDC.** GitHub user login has no discovery document, no ID
/// token and no JWKS; the device flow yields an *access token* and identity
/// comes from `GET /user`. (GitHub Actions workload identity *is* real OIDC —
/// a different verifier, a different task.)
///
/// There is deliberately **no callback origin here**: the device flow has no
/// `redirect_uri` at all (RFC 8628), so §10's unresolved "where does the hosted
/// control plane run" question does not block login. The only hostname involved
/// is this coordinator's own [`CoordinatorConfig::public_url`].
///
/// The three endpoint URLs are configurable so the integration tests can point
/// the flow at a loopback stub — the only way to exercise it without GitHub.
#[derive(Debug, Clone)]
pub struct GithubConfig {
    /// The OAuth app's client id. Not a secret (it appears in the device-flow
    /// request), but without it there is no flow.
    pub client_id: String,
    /// The OAuth app's client secret, when the app requires one.
    ///
    /// OAuth Apps do not need it for the device flow; some GitHub App
    /// configurations do. It never leaves this process.
    pub client_secret: Option<String>,
    /// The OAuth scope requested. Empty is correct for identity-only login:
    /// `GET /user` needs no scope, and asking for more than we use is a
    /// permission the user cannot get back.
    pub scope: String,
    /// `POST` endpoint that starts a device flow.
    pub device_code_url: String,
    /// `POST` endpoint that redeems a device code for an access token.
    pub access_token_url: String,
    /// Base URL of the GitHub REST API (`GET {api_base}/user`).
    pub api_base: String,
}

/// Full coordinator configuration.
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// The TCP address to listen on.
    ///
    /// Defaults to loopback: the expected deployment is behind a proxy on the
    /// same host, and binding a public interface should be a deliberate act.
    pub listen_addr: SocketAddr,
    /// The externally reachable base URL of this coordinator
    /// (`https://fleet.example`), as handed to operators for
    /// `agent init --fleet-url` / `ctl init --fleet-url`.
    ///
    /// This is not derivable from [`listen_addr`](Self::listen_addr): behind a
    /// proxy the coordinator listens on `127.0.0.1:7000` and the world reaches
    /// it at a name it never sees.
    pub public_url: String,
    /// Coordinator-terminated TLS, or `None` to serve plain HTTP (behind a
    /// proxy).
    pub tls: Option<TlsConfig>,
    /// Path to the `SQLite` database file.
    pub sqlite_path: PathBuf,
    /// The capability-token signing key.
    pub signing_key: SigningKeySource,
    /// Lease scheduling policy.
    pub policy: Policy,
    /// How often (seconds) the expiry sweep runs.
    pub sweep_interval_secs: u64,
    /// How often (seconds) the coordinator pings an idle connection.
    ///
    /// Keepalive is load-bearing now: a reverse proxy reaps idle `WebSocket`s
    /// on a timeout we do not control, so the node's persistent connection must
    /// generate traffic even when the fleet is quiet.
    pub ping_interval_secs: u64,
    /// How long (seconds) a connection may go without any inbound frame or pong
    /// before it is dropped.
    pub pong_timeout_secs: u64,
    /// How long (seconds) a freshly minted user session token is valid.
    pub session_ttl_secs: u64,
    /// How old (seconds) a node token may get before it is rotated.
    pub node_token_rotate_secs: u64,
    /// The org an interim admin-minted subject is assigned to when none is
    /// specified.
    ///
    /// Note this is **not** consulted for node connections: a node's org comes
    /// from its own row, so a node token cannot be replayed into another tenant
    /// (see `http::authenticate_request`).
    pub default_org: OrgId,
    /// The GitHub OAuth app backing `probe-rs-fleet login`.
    ///
    /// `None` is a supported deployment, not a broken one: an air-gapped or
    /// development fleet bootstraps with `coordinator user-token` instead. The
    /// `/auth/device/*` routes then answer a named `503`
    /// (`device_flow_unconfigured`) so the CLI can say *why*.
    pub github: Option<GithubConfig>,
}

impl CoordinatorConfig {
    /// Validate the configuration.
    ///
    /// # Errors
    ///
    /// Returns [`CoordinatorError::Config`] if a required path or value is
    /// empty/zero, or a `[tls]` table is missing one of its two paths.
    pub fn validate(&self) -> Result<()> {
        if self.sqlite_path.as_os_str().is_empty() {
            return Err(CoordinatorError::Config("sqlite_path is empty".to_owned()));
        }
        if let Some(tls) = &self.tls {
            for (label, path) in [("tls.cert", &tls.cert), ("tls.key", &tls.key)] {
                if path.as_os_str().is_empty() {
                    return Err(CoordinatorError::Config(format!("{label} path is empty")));
                }
            }
        }
        if self.public_url.trim().is_empty() {
            return Err(CoordinatorError::Config(
                "public_url must be non-empty".to_owned(),
            ));
        }
        for (label, value) in [
            ("sweep_interval_secs", self.sweep_interval_secs),
            ("ping_interval_secs", self.ping_interval_secs),
            ("pong_timeout_secs", self.pong_timeout_secs),
            ("session_ttl_secs", self.session_ttl_secs),
            ("node_token_rotate_secs", self.node_token_rotate_secs),
        ] {
            if value == 0 {
                return Err(CoordinatorError::Config(format!(
                    "{label} must be non-zero"
                )));
            }
        }
        if self.pong_timeout_secs <= self.ping_interval_secs {
            return Err(CoordinatorError::Config(
                "pong_timeout_secs must exceed ping_interval_secs, or every idle \
                 connection is dropped before it can answer a ping"
                    .to_owned(),
            ));
        }
        if self.default_org.0.is_empty() {
            return Err(CoordinatorError::Config(
                "default_org must be non-empty".to_owned(),
            ));
        }
        if let Some(gh) = &self.github {
            // A `[github]` table with no client id would make `login` fail at
            // GitHub with an opaque error, far from the mistake.
            if gh.client_id.trim().is_empty() {
                return Err(CoordinatorError::Config(
                    "github.client_id must be non-empty when a [github] table is present"
                        .to_owned(),
                ));
            }
            for (label, value) in [
                ("github.device_code_url", &gh.device_code_url),
                ("github.access_token_url", &gh.access_token_url),
                ("github.api_base", &gh.api_base),
            ] {
                if value.trim().is_empty() {
                    return Err(CoordinatorError::Config(format!("{label} must be non-empty")));
                }
            }
        }
        Ok(())
    }

    /// The keepalive ping interval.
    #[must_use]
    pub fn ping_interval(&self) -> Duration {
        Duration::from_secs(self.ping_interval_secs)
    }

    /// The keepalive liveness deadline.
    #[must_use]
    pub fn pong_timeout(&self) -> Duration {
        Duration::from_secs(self.pong_timeout_secs)
    }

    /// The node-token rotation policy this configuration implies.
    #[must_use]
    pub fn rotation_policy(&self) -> fleet_auth::RotationPolicy {
        fleet_auth::RotationPolicy {
            max_age_secs: self.node_token_rotate_secs,
            ..fleet_auth::RotationPolicy::DEFAULT
        }
    }
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:7000".parse().expect("valid literal"),
            public_url: "http://127.0.0.1:7000".to_owned(),
            tls: None,
            sqlite_path: "coordinator.sqlite".into(),
            signing_key: SigningKeySource::Seed([0u8; 32]),
            policy: Policy::default(),
            sweep_interval_secs: 5,
            ping_interval_secs: 20,
            pong_timeout_secs: 60,
            session_ttl_secs: 12 * 60 * 60,
            node_token_rotate_secs: fleet_auth::RotationPolicy::DEFAULT.max_age_secs,
            default_org: OrgId(crate::state::DEFAULT_ORG_ID.to_owned()),
            github: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid_and_loopback() {
        let c = CoordinatorConfig::default();
        assert!(c.validate().is_ok());
        assert!(c.listen_addr.ip().is_loopback());
        assert!(c.tls.is_none(), "plain HTTP behind a proxy is the default");
    }

    #[test]
    fn empty_sqlite_path_rejected() {
        let c = CoordinatorConfig {
            sqlite_path: PathBuf::new(),
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn tls_table_needs_both_paths() {
        let mut c = CoordinatorConfig {
            tls: Some(TlsConfig {
                cert: "cert.pem".into(),
                key: PathBuf::new(),
            }),
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_err());
        c.tls = Some(TlsConfig {
            cert: "cert.pem".into(),
            key: "key.pem".into(),
        });
        assert!(c.validate().is_ok());
    }

    #[test]
    fn zero_intervals_rejected() {
        for mutate in [
            (|c: &mut CoordinatorConfig| c.sweep_interval_secs = 0) as fn(&mut CoordinatorConfig),
            |c| c.ping_interval_secs = 0,
            |c| c.pong_timeout_secs = 0,
            |c| c.session_ttl_secs = 0,
            |c| c.node_token_rotate_secs = 0,
        ] {
            let mut c = CoordinatorConfig::default();
            mutate(&mut c);
            assert!(c.validate().is_err());
        }
    }

    /// A pong timeout at or below the ping interval means the connection is
    /// reaped before the peer can possibly answer — a configuration that looks
    /// plausible and drops every idle node.
    #[test]
    fn pong_timeout_must_exceed_ping_interval() {
        let mut c = CoordinatorConfig {
            ping_interval_secs: 30,
            pong_timeout_secs: 30,
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_err());
        c.pong_timeout_secs = 31;
        assert!(c.validate().is_ok());
    }

    #[test]
    fn empty_public_url_or_default_org_rejected() {
        let c = CoordinatorConfig {
            public_url: "  ".to_owned(),
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_err());

        let c = CoordinatorConfig {
            default_org: OrgId(String::new()),
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn rotation_policy_follows_the_configured_age() {
        let c = CoordinatorConfig {
            node_token_rotate_secs: 3600,
            ..CoordinatorConfig::default()
        };
        assert_eq!(c.rotation_policy().max_age_secs, 3600);
    }

    /// A `[github]` table without a client id is a configuration that starts
    /// cleanly and then fails at GitHub with an opaque error, so it is rejected
    /// here instead.
    #[test]
    fn github_table_requires_a_client_id_and_endpoints() {
        let good = GithubConfig {
            client_id: "Iv1.abc".to_owned(),
            client_secret: None,
            scope: String::new(),
            device_code_url: "https://github.com/login/device/code".to_owned(),
            access_token_url: "https://github.com/login/oauth/access_token".to_owned(),
            api_base: "https://api.github.com".to_owned(),
        };
        let c = CoordinatorConfig {
            github: Some(good.clone()),
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_ok());

        let c = CoordinatorConfig {
            github: Some(GithubConfig {
                client_id: "  ".to_owned(),
                ..good.clone()
            }),
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_err());

        let c = CoordinatorConfig {
            github: Some(GithubConfig {
                api_base: String::new(),
                ..good
            }),
            ..CoordinatorConfig::default()
        };
        assert!(c.validate().is_err());
    }

    /// No `[github]` table is a supported deployment (air-gapped / dev), not an
    /// invalid one.
    #[test]
    fn github_is_optional() {
        assert!(CoordinatorConfig::default().github.is_none());
        assert!(CoordinatorConfig::default().validate().is_ok());
    }
}
